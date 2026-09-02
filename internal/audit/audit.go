package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Busness-app/ky-primitives/auditchain"
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
}

// fieldsOf is the entry content the chain authenticates. The order is part of the
// chain format: changing it invalidates every stored digest.
func fieldsOf(e Entry) []string {
	return []string{
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.Action,
		e.UserID,
		e.DeviceID,
		e.IPAddress,
		e.Details,
	}
}

// recordOf reads a stored entry as a chain record. Entry indices are zero-based
// and chain sequences are one-based.
func recordOf(e Entry) auditchain.Record {
	return auditchain.Record{
		Seq:    uint64(e.Index) + 1,
		Prev:   e.PrevHash,
		Hash:   e.Hash,
		Fields: fieldsOf(e),
	}
}

// Store manages the append-only audit trail file.
type Store struct {
	mu        sync.Mutex
	filePath  string
	statePath string
	key       []byte
	chain     *auditchain.Chain
	anchor    auditchain.Anchor
}

// legacyHash is the digest this server used before the chain moved to the shared
// format: an unkeyed SHA-256 before the chain was keyed, an HMAC after.
//
// Both joined the fields with a bare "|", so content carrying the delimiter could
// be shifted into a neighbouring field without changing the digest. It is retained
// only to recognise entries written that way, never to write one.
//
// Deprecated: new entries are written by auditchain.
func (s *Store) legacyHash(e Entry, keyed bool) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.Index, e.Timestamp.Format(time.RFC3339Nano), e.Action,
		e.UserID, e.DeviceID, e.IPAddress, e.Details, e.PrevHash)

	if !keyed {
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
// chainState is the anchor persisted outside the log: how many entries it held
// and the digest of the last one. Without it a log truncated at the end verifies
// perfectly.
type chainState struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash,omitempty"`

	// LegacyAnchor is the first index that the previous format required to be
	// keyed. It is read only while converting a chain written under that format,
	// to decide which entries may still carry an unkeyed digest.
	LegacyAnchor int64 `json:"anchor,omitempty"`
}

// loadState reads the anchor, creating an empty one on first use.
func loadState(keyDir string) (chainState, error) {
	statePath := filepath.Join(keyDir, "audit.state")
	if data, err := os.ReadFile(statePath); err == nil {
		var st chainState
		if err := json.Unmarshal(data, &st); err != nil {
			return chainState{}, fmt.Errorf("audit state file is corrupt: %w", err)
		}
		return st, nil
	}

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return chainState{}, fmt.Errorf("mkdir key dir: %w", err)
	}
	st := chainState{}
	if err := writeState(statePath, st); err != nil {
		return chainState{}, err
	}
	return st, nil
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

	s := &Store{
		filePath:  filepath.Join(dir, "audit.jsonl"),
		statePath: filepath.Join(keyDir, "audit.state"),
		key:       key,
	}

	st, err := loadState(keyDir)
	if err != nil {
		return nil, err
	}
	s.anchor = auditchain.Anchor{Count: st.Count, Hash: st.Hash}

	entries, err := s.readAll()
	if err != nil {
		return nil, err
	}
	if entries, err = s.converge(entries, st); err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		s.chain, err = auditchain.New(key)
		return s, err
	}

	last := entries[len(entries)-1]
	if s.chain, err = auditchain.Resume(key, recordOf(last)); err != nil {
		return nil, err
	}

	// A tail exactly one entry past the anchor is this store's own append,
	// interrupted before the anchor was written: only a key holder can produce an
	// entry that carries its own digest. A longer overrun is left for
	// VerifyIntegrity to report.
	if uint64(last.Index)+1 == s.anchor.Count+1 && s.anchor.Count > 0 {
		s.anchor = s.chain.Anchor()
		if err := s.saveAnchor(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// readAll returns the log oldest first, or nothing if it does not exist yet.
func (s *Store) readAll() ([]Entry, error) {
	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		return nil, nil
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
	return entries, nil
}

// saveAnchor persists the anchor beside the key.
func (s *Store) saveAnchor() error {
	return writeState(s.statePath, chainState{Count: s.anchor.Count, Hash: s.anchor.Hash})
}

// converge rewrites a log written under this server's own hashing onto the shared
// package's digests. It runs once, when the log does not already carry them.
//
// Every entry must first verify under whichever digest wrote it, so a log that
// was already broken is never blessed. An unkeyed digest is accepted only below
// the index the previous format recorded as the first keyed one — otherwise an
// attacker could downgrade keyed entries and have the conversion bless them.
func (s *Store) converge(entries []Entry, st chainState) ([]Entry, error) {
	if len(entries) == 0 {
		return entries, nil
	}
	if _, err := auditchain.Resume(s.key, recordOf(entries[len(entries)-1])); err == nil {
		return entries, nil
	}

	unkeyedLimit := st.LegacyAnchor
	if st.Count == 0 {
		unkeyedLimit = int64(len(entries))
	}
	if !s.legacyChainVerifies(entries, unkeyedLimit) {
		// Leave the log exactly as it is. Refusing to open would let anyone who
		// can write it stop the server; VerifyIntegrity reports what is wrong.
		return entries, nil
	}

	chain, err := auditchain.New(s.key)
	if err != nil {
		return nil, err
	}
	converted := make([]Entry, 0, len(entries))
	for _, e := range entries {
		rec, err := chain.Append(fieldsOf(e)...)
		if err != nil {
			return nil, err
		}
		e.Index, e.PrevHash, e.Hash = int64(rec.Seq)-1, rec.Prev, rec.Hash
		converted = append(converted, e)
	}

	if err := s.rewrite(converted); err != nil {
		return nil, err
	}
	s.anchor = chain.Anchor()
	if err := s.saveAnchor(); err != nil {
		return nil, err
	}
	return converted, nil
}

// legacyChainVerifies reports whether every entry carries the digest the previous
// format would have written, with the links and indices intact. An unkeyed digest
// counts only below unkeyedLimit: otherwise an attacker could downgrade keyed
// entries and have the conversion bless them.
func (s *Store) legacyChainVerifies(entries []Entry, unkeyedLimit int64) bool {
	prev := genesisHash
	for i, e := range entries {
		if e.Index != int64(i) || e.PrevHash != prev {
			return false
		}
		switch e.Hash {
		case s.legacyHash(e, true):
		case s.legacyHash(e, false):
			if e.Index >= unkeyedLimit {
				return false
			}
		default:
			return false
		}
		prev = e.Hash
	}
	return true
}

// rewrite replaces the log atomically, so a crash cannot leave it half-converted.
func (s *Store) rewrite(entries []Entry) error {
	tmp := s.filePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

// Log records an audit action in the hash-chain.
func (s *Store) Log(action, userID, deviceID, ip, details string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	entry := Entry{
		Timestamp: now,
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IPAddress: ip,
		Details:   details,
	}

	rec, err := s.chain.Append(fieldsOf(entry)...)
	if err != nil {
		return Entry{}, fmt.Errorf("extend audit chain: %w", err)
	}
	entry.Index, entry.PrevHash, entry.Hash = int64(rec.Seq)-1, rec.Prev, rec.Hash

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

	// Only ever forward. If entries were removed and the log is being appended to
	// again, the recorded anchor is the evidence and must not be overwritten.
	// Written after the entry, so an interrupted write leaves the anchor one
	// behind rather than accusing a healthy log; NewStore adopts that case.
	if a := s.chain.Anchor(); a.Count > s.anchor.Count {
		s.anchor = a
		if err := s.saveAnchor(); err != nil {
			return Entry{}, fmt.Errorf("record audit chain anchor: %w", err)
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

// VerifyIntegrity walks the entire audit chain and checks it against the anchor.
func (s *Store) VerifyIntegrity() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		if s.anchor.Count > 0 {
			return false, fmt.Errorf("audit log is missing, but %d entries were recorded", s.anchor.Count)
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	err = auditchain.VerifyStream(s.key, func(yield func(auditchain.Record, error) bool) {
		for {
			var e Entry
			if derr := dec.Decode(&e); derr != nil {
				return
			}
			if !yield(recordOf(e), nil) {
				return
			}
		}
	}, s.anchor)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ExportChain writes the log as shared-package records, and returns the anchor to
// check them against. This is the form kyauditverify reads: the products store
// different fields, so the records as the chain sees them are the only thing one
// verifier can consume from all of them.
func (s *Store) ExportChain(w io.Writer) (auditchain.Anchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.readAll()
	if err != nil {
		return auditchain.Anchor{}, err
	}
	enc := json.NewEncoder(w)
	for _, e := range entries {
		if err := enc.Encode(recordOf(e)); err != nil {
			return auditchain.Anchor{}, err
		}
	}
	return s.anchor, nil
}
