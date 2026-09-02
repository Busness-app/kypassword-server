package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// chainVersion is the version stamped on every entry this build writes.
const chainVersion = 1

// genesisHash is the PrevHash of the first entry in a chain.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry represents a single tamper-evident audit record in the chain.
type Entry struct {
	Index     int64     `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	UserID    string    `json:"userId,omitempty"`
	DeviceID  string    `json:"deviceId,omitempty"`
	IPAddress string    `json:"ipAddress,omitempty"`
	Details   string    `json:"details,omitempty"`
	PrevHash  string    `json:"prevHash"`
	Hash      string    `json:"hash"`

	// V is the chain version: 0 (absent) for records written before the chain
	// was keyed, 1 for HMAC records. See Store.chainHash.
	V int `json:"v,omitempty"`
}

// Store manages the append-only audit trail file.
type Store struct {
	mu        sync.Mutex
	filePath  string
	statePath string
	key       []byte
	state     chainState
	lastHash  string
	count     int64
}

// chainHash is the digest binding an entry to its predecessor. It is the single
// definition of the chain algorithm: Log and VerifyIntegrity both use it, so they
// cannot drift apart.
//
// Version 0 entries predate the key and are unkeyed, which is why Store.anchor
// exists: without it an attacker could downgrade a keyed entry to version 0 and
// recompute its hash with the public algorithm.
func (s *Store) chainHash(e Entry) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.Index, e.Timestamp.Format(time.RFC3339Nano), e.Action,
		e.UserID, e.DeviceID, e.IPAddress, e.Details, e.PrevHash)

	if e.V == 0 {
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:])
	}

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// chainState is what the log is expected to contain, held beside the key rather
// than beside the log. Hashes alone cannot detect a log that has had records
// removed, because what remains still chains correctly; only a record kept out of
// the attacker's reach can.
type chainState struct {
	// Anchor is the first index required to be keyed.
	Anchor int64 `json:"anchor"`
	// Count is how many entries the log had when last written, and Hash is the
	// hash of entry Count-1.
	Count int64  `json:"count"`
	Hash  string `json:"hash,omitempty"`
}

// loadState reads the chain state, creating it on first use, and reports whether
// this call is the one that created it.
func loadState(keyDir string, legacyLead int64) (chainState, bool, error) {
	statePath := filepath.Join(keyDir, "audit.state")
	if data, err := os.ReadFile(statePath); err == nil {
		var st chainState
		if err := json.Unmarshal(data, &st); err != nil {
			return chainState{}, false, fmt.Errorf("audit state file is corrupt: %w", err)
		}
		return st, false, nil
	}

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return chainState{}, false, fmt.Errorf("mkdir key dir: %w", err)
	}
	st := chainState{Anchor: legacyLead}
	if err := writeState(statePath, st); err != nil {
		return chainState{}, false, err
	}
	return st, true, nil
}

func writeState(statePath string, st chainState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	// Rename so a crash mid-write cannot leave a state file that reads as "the
	// log should be empty".
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write audit state: %w", err)
	}
	if err := os.Rename(tmp, statePath); err != nil {
		return fmt.Errorf("replace audit state: %w", err)
	}
	return nil
}

// decodeKey parses a hex-encoded audit key, refusing anything too short to be
// worth having. A weak key here is worse than a loud failure: the chain would
// still verify, against a value an attacker can search.
func decodeKey(source, value string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex: %w", source, err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("%s must be at least 32 bytes, got %d", source, len(key))
	}
	return key, nil
}

// loadKey returns the HMAC key for the audit chain, generating and persisting
// one on first use. keyDir must not be writable by anyone who can write the
// audit log, or the key protects nothing.
func loadKey(keyDir string) ([]byte, error) {
	if env := os.Getenv("AUDIT_KEY"); env != "" {
		return decodeKey("AUDIT_KEY", env)
	}

	keyFile := filepath.Join(keyDir, "audit.key")
	if data, err := os.ReadFile(keyFile); err == nil && len(data) > 0 {
		return decodeKey(keyFile, string(data))
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate audit key: %w", err)
	}
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir key dir: %w", err)
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0600); err != nil {
		return nil, fmt.Errorf("write audit key: %w", err)
	}
	return key, nil
}

// NewStore initializes an audit store in dir, keyed by material held in keyDir.
// keyDir must be outside dir: a key stored beside the log it protects is no
// protection at all.
func NewStore(dir, keyDir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}

	key, err := loadKey(keyDir)
	if err != nil {
		return nil, err
	}

	filePath := filepath.Join(dir, "audit.jsonl")
	s := &Store{
		filePath: filePath,
		key:      key,
		lastHash: genesisHash,
		count:    0,
	}

	// Read existing entries to find the last hash, the count, and how many
	// unkeyed records the chain opens with.
	var legacyLead int64
	countingLead := true
	if file, err := os.Open(filePath); err == nil {
		defer file.Close()
		dec := json.NewDecoder(file)
		for {
			var e Entry
			if err := dec.Decode(&e); err != nil {
				break
			}
			if countingLead && e.V == 0 {
				legacyLead++
			} else {
				countingLead = false
			}
			s.lastHash = e.Hash
			s.count = e.Index + 1
		}
	}

	state, firstKeying, err := loadState(keyDir, legacyLead)
	if err != nil {
		return nil, err
	}
	s.state = state
	s.statePath = filepath.Join(keyDir, "audit.state")

	// An unkeyed chain being opened for the first time since keying has just been
	// migrated. Anchor its tail with a keyed entry now, rather than leaving it
	// unprotected until the next real event. Only ever on the first keying: doing
	// it again later would paper over a log that had been rolled back to its
	// unkeyed prefix instead of reporting it.
	if firstKeying && s.count > 0 {
		if _, err := s.Log("audit.rekey", "", "", "", "audit chain keyed; earlier entries predate the key"); err != nil {
			return nil, fmt.Errorf("anchor legacy audit chain: %w", err)
		}
	}

	return s, nil
}

// Log records an audit action in the hash-chain.
func (s *Store) Log(action, userID, deviceID, ip, details string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	entry := Entry{
		Index:     s.count,
		Timestamp: now,
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IPAddress: ip,
		Details:   details,
		PrevHash:  s.lastHash,
		V:         chainVersion,
	}
	entry.Hash = s.chainHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, err
	}
	data = append(data, '\n')

	f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return Entry{}, err
	}

	s.lastHash = entry.Hash
	s.count++

	// Never lower the recorded count: if the log was rolled back and is now being
	// appended to again, the old mark is the evidence.
	if s.count > s.state.Count {
		s.state.Count = s.count
		s.state.Hash = entry.Hash
		if err := writeState(s.statePath, s.state); err != nil {
			return Entry{}, fmt.Errorf("record audit chain state: %w", err)
		}
	}

	return entry, nil
}

// List returns the latest N audit entries.
func (s *Store) List(limit int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []Entry
	dec := json.NewDecoder(file)
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
	}

	// Reverse to show latest first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}

// VerifyIntegrity walks the entire audit chain and checks each hash.
func (s *Store) VerifyIntegrity() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		if s.state.Count > 0 {
			return false, fmt.Errorf("audit log is missing, but %d entries were recorded", s.state.Count)
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	expectedPrev := genesisHash
	var expectedIndex int64 = 0
	tailHash := ""

	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			break
		}

		if e.Index != expectedIndex {
			return false, fmt.Errorf("audit chain index mismatch at index %d (expected %d)", e.Index, expectedIndex)
		}
		if e.PrevHash != expectedPrev {
			return false, fmt.Errorf("audit chain broken at index %d: prevHash mismatch", e.Index)
		}
		if e.V == 0 && e.Index >= s.state.Anchor {
			return false, fmt.Errorf("audit entry %d is unkeyed but the chain has been keyed since index %d", e.Index, s.state.Anchor)
		}

		calcHash := s.chainHash(e)
		if calcHash != e.Hash {
			return false, fmt.Errorf("audit entry %d hash modified: got %s, calculated %s", e.Index, e.Hash, calcHash)
		}

		if e.Index == s.state.Count-1 {
			tailHash = e.Hash
		}
		expectedPrev = e.Hash
		expectedIndex++
	}

	// A truncated log still chains correctly, so the tail is checked against the
	// state record the log's writer cannot reach. A log missing entries never
	// reaches the recorded index and fails here with tailHash empty. A log with
	// more entries than the mark is fine: an interrupted write can leave the mark
	// one behind, and the entries past it are still required to be keyed.
	if s.state.Count > 0 && tailHash != s.state.Hash {
		return false, fmt.Errorf("audit chain does not match the recorded state: entry %d is missing or altered", s.state.Count-1)
	}

	return true, nil
}
