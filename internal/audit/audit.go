package audit

import (
	"context"
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
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"
)

// genesisHash is the PrevHash of the first entry in a chain.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// appendTimeout bounds Append's wait for the chain lock. It does not bound persist,
// which runs with that lock held and no context reaching it, so a store that hangs
// hangs this caller for as long as it stays hung.
var appendTimeout = 5 * time.Second

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

// legacyHash is the keyed digest this server used before the chain moved to the
// shared format. It joined the fields with a bare "|", so content carrying the
// delimiter could be shifted into a neighbouring field without changing the digest.
//
// The unkeyed variant that preceded it is gone. It was chained under no secret at
// all, so anyone who could write the log could rewrite it and recompute every
// digest; the boundary that said where those entries stopped was never persisted.
//
// Deprecated: retained only to recognise entries written this way, never to write
// one. New entries are written by auditchain.
func (s *Store) legacyHash(e Entry) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.Index, e.Timestamp.Format(time.RFC3339Nano), e.Action,
		e.UserID, e.DeviceID, e.IPAddress, e.Details, e.PrevHash)

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// chainState is the anchor persisted outside the log: how many entries it held and
// the digest of the last one, held beside the key rather than beside the log.
// Hashes alone cannot detect a log that has had records removed, because what
// remains still chains correctly; only a mark out of the attacker's reach can.
type chainState struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash,omitempty"`
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

	// Before the empty-log short circuit, not after it. readAll stops at the first
	// line it cannot decode, so a log wiped to zero bytes — or one whose first line
	// is corrupt — reads as no entries at all, and used to be the one truncation that
	// opened cleanly and went on accepting appends.
	anchor, err := s.placeTail(entries)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		s.chain, err = auditchain.New(key)
		return s, err
	}

	if s.chain, err = auditchain.Resume(key, recordOf(entries[len(entries)-1]), anchor); err != nil {
		return nil, err
	}
	if anchor != s.anchor {
		s.anchor = anchor
		if err := s.saveAnchor(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// placeTail returns the anchor to resume the log against, and refuses outright when
// the mark and the log cannot be reconciled at all.
//
// It does not settle everything. When the counts agree it hands back the stored mark
// unexamined, and whether the last record is really the one that mark names is left
// to Resume's own digest check — which is what rejects a forged or downgraded log
// whose length happens to be right. TestEmptiedLogIsRejected and
// TestForgedChainIsRejected are the two ends of that division.
func (s *Store) placeTail(entries []Entry) (auditchain.Anchor, error) {
	n := uint64(len(entries))

	switch {
	case n < s.anchor.Count:
		// Fewer records than the mark counted. Resuming at this tail would mint a
		// sequence number that already exists: a fork that persists cleanly and can
		// never verify again. Refuse to start rather than append over the evidence.
		//
		// n == 0 lands here too, and must: an emptied log is the most truncated log
		// there is, not a fresh install.
		return auditchain.Anchor{}, fmt.Errorf("%w: %s holds %d records but the mark in %s counts %d. "+
			"Entries have been removed from the end of the log; appending would write over the gap, "+
			"so this server will not start. Restore the log from backup, or move both files aside to "+
			"begin a new chain and keep the old pair for the auditor",
			auditchain.ErrTruncated, s.filePath, n, s.statePath, s.anchor.Count)

	case n == 0:
		// No log and no mark: a first run.
		return auditchain.Anchor{}, nil

	case s.anchor.Count == 0:
		// A log with no mark cannot be placed. The mark is the only record of how
		// long the log is meant to be, so without it a log with entries removed and
		// one that is intact are the same file. Minting a mark here would bless
		// whatever is on disk, and one append used to do exactly that.
		return auditchain.Anchor{}, fmt.Errorf("%w: %s holds %d records but the mark in %s counts none. "+
			"It was removed and recreated empty, or never written; either way a truncated log "+
			"cannot be told from an intact one, so this server will not start. Restore the mark "+
			"from backup, or move both files aside to begin a new chain and keep the old pair "+
			"for the auditor", auditchain.ErrBrokenChain, s.filePath, n, s.statePath)

	case n > s.anchor.Count:
		// The mark is behind the log: records landed and the mark write that should
		// have followed did not. One behind is the classic interrupted write; several
		// behind is a config volume that was unwritable for a while, which is a disk
		// fault and not tampering. So walk the whole run: every record past the mark
		// must sit at its own position, carry its own digest, and follow the one
		// before it, starting from the mark's own hash. Minting any one of them still
		// requires the key, so accepting a run is no weaker than accepting one — but
		// without the predecessor check a re-minted fork would be adopted here.
		prev := s.anchor.Hash
		for i := s.anchor.Count; i < n; i++ {
			rec := recordOf(entries[i])
			if rec.Seq != i+1 {
				return auditchain.Anchor{}, fmt.Errorf("%w: %s overruns the mark in %s and record %d sits at position %d",
					auditchain.ErrBrokenChain, s.filePath, s.statePath, rec.Seq, i+1)
			}
			if err := auditchain.VerifyRecord(s.key, rec); err != nil {
				return auditchain.Anchor{}, fmt.Errorf("audit: %s overruns the mark in %s and record %d does not verify: %w",
					s.filePath, s.statePath, rec.Seq, err)
			}
			if rec.Prev != prev {
				return auditchain.Anchor{}, fmt.Errorf("%w: %s overruns the mark in %s and record %d does not follow its predecessor",
					auditchain.ErrBrokenChain, s.filePath, s.statePath, rec.Seq)
			}
			prev = rec.Hash
		}
		return auditchain.Anchor{Count: n, Hash: entries[n-1].Hash}, nil
	}
	return s.anchor, nil
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

// converge rewrites a log written under this server's own keyed hashing onto the
// shared package's digests. It runs once, when the log does not already carry them.
//
// Every entry must first verify under the digest that wrote it, so a log that was
// already broken is never blessed, and the mark must not already count more entries
// than the log holds: converting then would save a fresh mark over the evidence of
// a truncation. When conversion is refused the log is left exactly as it is: if the
// mark counts more than the log holds placeTail refuses, and otherwise the entries
// are still in the old format, so Resume's digest check is what rejects them.
func (s *Store) converge(entries []Entry, st chainState) ([]Entry, error) {
	if len(entries) == 0 {
		return entries, nil
	}
	// Is this log already in the shared digest format? That is all this asks.
	// Resume would also assert that the record is the tail, which is a different
	// question and not the one converge needs answered.
	if auditchain.VerifyRecord(s.key, recordOf(entries[len(entries)-1])) == nil {
		return entries, nil
	}
	if st.Count > uint64(len(entries)) || !s.legacyChainVerifies(entries) {
		return entries, nil
	}

	// Replay, not a per-record Append: the log is written once after the loop and
	// the mark saved once after that, so a persist callback per record would have
	// nothing to persist.
	tuples := make([][]string, 0, len(entries))
	for _, e := range entries {
		tuples = append(tuples, fieldsOf(e))
	}
	records, anchor, err := auditchain.Replay(s.key, tuples)
	if err != nil {
		return nil, err
	}
	converted := make([]Entry, 0, len(entries))
	for i, e := range entries {
		e.Index, e.PrevHash, e.Hash = int64(records[i].Seq)-1, records[i].Prev, records[i].Hash
		converted = append(converted, e)
	}

	if err := s.rewrite(converted); err != nil {
		return nil, err
	}
	s.anchor = anchor
	if err := s.saveAnchor(); err != nil {
		return nil, err
	}
	return converted, nil
}

// legacyChainVerifies reports whether every entry carries the keyed digest the
// previous format would have written, with the links and indices intact.
func (s *Store) legacyChainVerifies(entries []Entry) bool {
	prev := genesisHash
	for i, e := range entries {
		if e.Index != int64(i) || e.PrevHash != prev {
			return false
		}
		if !hmac.Equal([]byte(e.Hash), []byte(s.legacyHash(e))) {
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
//
// ctx is accepted for its values; its cancellation is deliberately dropped. Handlers
// pass r.Context(), which dies the instant the client hangs up, and every call site
// discards Log's error — so honouring it would let a client suppress the record of
// what it just did by aborting the connection after the handler had already acted.
// The records an attacking client most wants gone, device.pairing_failed and
// sync.rejected, are exactly the ones written that way. The audit write is not the
// caller's to cancel; TestAbortedRequestStillRecordsTheAudit pins it.
func (s *Store) Log(ctx context.Context, action, userID, deviceID, ip, details string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Derived after the mutex, not before. s.mu is a plain sync.Mutex that no context
	// can interrupt, so a deadline started above this line is spent waiting on it: a
	// caller queued behind a slow store would reach Append with an already-dead
	// context and throw its record away. That is the same suppression reached by load
	// instead of by a dropped connection. Every waiter gets its budget measured from
	// the moment it can make progress; TestQueuedLogSpendsItsBudgetOnTheChain pins it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)
	defer cancel()

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IPAddress: ip,
		Details:   details,
	}

	var anchorErr error
	_, err := s.chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
		entry.Index, entry.PrevHash, entry.Hash = int64(r.Seq)-1, r.Prev, r.Hash
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		data = append(data, '\n')

		f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.Write(data); err != nil {
			return err
		}

		// Entry first, mark second, and the mark's failure is reported from Log
		// rather than to the chain. The record is already on disk, so failing the
		// append here would leave the chain a step behind the log and the next Log
		// would reuse this sequence number — forking it permanently, and silently,
		// because the mark would already have been advanced. A mark left behind is
		// just the interrupted write placeTail reconciles.
		//
		// Only ever forward: if entries were removed and the log is being appended
		// to again, the recorded mark is the evidence and must not be overwritten.
		if a.Count > s.anchor.Count {
			s.anchor = a
			anchorErr = s.saveAnchor()
		}
		return nil
	}, fieldsOf(entry)...)
	if err != nil {
		return Entry{}, fmt.Errorf("extend audit chain: %w", err)
	}
	if anchorErr != nil {
		return entry, fmt.Errorf("record audit chain anchor: %w", anchorErr)
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
