package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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

// Store manages the append-only audit trail file.
type Store struct {
	mu       sync.Mutex
	filePath string
	lastHash string
	count    int64
}

// NewStore initializes an audit store in the specified directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}

	filePath := filepath.Join(dir, "audit.jsonl")
	s := &Store{
		filePath: filePath,
		lastHash: "0000000000000000000000000000000000000000000000000000000000000000",
		count:    0,
	}

	// Read existing entries to find the last hash and count
	if file, err := os.Open(filePath); err == nil {
		defer file.Close()
		dec := json.NewDecoder(file)
		for {
			var e Entry
			if err := dec.Decode(&e); err != nil {
				break
			}
			s.lastHash = e.Hash
			s.count = e.Index + 1
		}
	}

	return s, nil
}

// Log records an audit action in the hash-chain.
func (s *Store) Log(action, userID, deviceID, ip, details string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	index := s.count

	// Compute payload hash
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		index, now.Format(time.RFC3339Nano), action, userID, deviceID, ip, details, s.lastHash)
	h := sha256.Sum256([]byte(raw))
	hashHex := hex.EncodeToString(h[:])

	entry := Entry{
		Index:     index,
		Timestamp: now,
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IPAddress: ip,
		Details:   details,
		PrevHash:  s.lastHash,
		Hash:      hashHex,
	}

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

	s.lastHash = hashHex
	s.count++

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
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	var expectedIndex int64 = 0

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

		raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
			e.Index, e.Timestamp.Format(time.RFC3339Nano), e.Action, e.UserID, e.DeviceID, e.IPAddress, e.Details, e.PrevHash)
		h := sha256.Sum256([]byte(raw))
		calcHash := hex.EncodeToString(h[:])

		if calcHash != e.Hash {
			return false, fmt.Errorf("audit entry %d hash modified: got %s, calculated %s", e.Index, e.Hash, calcHash)
		}

		expectedPrev = e.Hash
		expectedIndex++
	}

	return true, nil
}
