package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"
)

func TestAuditLogAndVerify(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// 1. Log multiple events
	_, err = store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", "successful login")
	if err != nil {
		t.Fatalf("Log 1 failed: %v", err)
	}
	_, err = store.Log(t.Context(), "vault.upload", "user1", "dev1", "127.0.0.1", "version 2 uploaded")
	if err != nil {
		t.Fatalf("Log 2 failed: %v", err)
	}
	_, err = store.Log(t.Context(), "vault.download", "user1", "dev1", "127.0.0.1", "version 2 downloaded")
	if err != nil {
		t.Fatalf("Log 3 failed: %v", err)
	}

	// 2. Verify integrity
	ok, err := store.VerifyIntegrity()
	if err != nil || !ok {
		t.Fatalf("VerifyIntegrity failed: %v, ok=%v", err, ok)
	}

	// 3. List
	entries, err := store.List(10)
	if err != nil || len(entries) != 3 {
		t.Fatalf("List returned %d entries, want 3 (err: %v)", len(entries), err)
	}

	// 4. Test tampering detection
	auditFile := filepath.Join(dir, "audit.jsonl")
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	tamperedData := []byte(string(data) + "\n{\"index\":99,\"hash\":\"fake\"}\n")
	_ = os.WriteFile(auditFile, tamperedData, 0600)

	assertTamperDetected(t, dir, keyDir, "appended junk entry")
}

// An attacker who can write the audit file rewrites a record and recomputes
// every hash after it. An unkeyed chain accepts this; a keyed one must not.
func TestForgedChainIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload", "vault.download"} {
		if _, err := store.Log(t.Context(), action, "user1", "dev1", "127.0.0.1", action+" ok"); err != nil {
			t.Fatalf("Log %s failed: %v", action, err)
		}
	}

	auditFile := filepath.Join(dir, "audit.jsonl")
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var entries []Entry
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d entries, want 3", len(entries))
	}

	// Hide the second event, then re-chain the tail with the public algorithm.
	entries[1].Action = "vault.download"
	entries[1].Details = "nothing to see here"
	prev := entries[0].Hash
	for i := 1; i < len(entries); i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = unkeyedHash(entries[i])
		prev = entries[i].Hash
	}

	var forged bytes.Buffer
	enc := json.NewEncoder(&forged)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("Encode failed: %v", err)
		}
	}
	if err := os.WriteFile(auditFile, forged.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	assertTamperDetected(t, dir, keyDir, "forged chain")
}

// assertTamperDetected fails only if a tampered log both opens and verifies.
// Opening is the earlier of the two: the shared package refuses to resume a chain
// whose tail does not carry its own digest, so a forged log is usually rejected
// before anything reaches VerifyIntegrity.
func assertTamperDetected(t *testing.T, dir, keyDir, what string) {
	t.Helper()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		return
	}
	ok, err := store.VerifyIntegrity()
	if ok && err == nil {
		t.Fatalf("%s accepted: ok=%v, err=%v", what, ok, err)
	}
}

// unkeyedHash is the digest the pre-HMAC chain used, and the only one an attacker
// without the key can compute. No code under test writes or accepts it any more.
func unkeyedHash(e Entry) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.Index, e.Timestamp.Format(time.RFC3339Nano), e.Action,
		e.UserID, e.DeviceID, e.IPAddress, e.Details, e.PrevHash)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func readChain(t *testing.T, dir string) []Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var entries []Entry
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
	}
	return entries
}

func writeChain(t *testing.T, dir string, entries []Entry) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("Encode failed: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
}

// writeUnkeyedChain lays down an audit file as the pre-HMAC implementation wrote
// it: chained under no secret at all.
func writeUnkeyedChain(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	prev := genesisHash
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e := Entry{
			Index:     int64(i),
			Timestamp: time.Now().UTC(),
			Action:    "legacy.event",
			UserID:    "user1",
			PrevHash:  prev,
		}
		e.Hash = unkeyedHash(e)
		prev = e.Hash
		entries = append(entries, e)
	}
	writeChain(t, dir, entries)
}

// writeKeyedLegacyChain lays down an audit file in the keyed bare-pipe format this
// server wrote before it moved onto the shared package, with the mark that format
// saved beside it. This is the only shape converge still accepts.
func writeKeyedLegacyChain(t *testing.T, dir, keyDir string, n int) []Entry {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	key, err := loadKey(keyDir)
	if err != nil {
		t.Fatalf("loadKey failed: %v", err)
	}
	s := &Store{key: key}

	prev := genesisHash
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e := Entry{
			Index:     int64(i),
			Timestamp: time.Now().UTC(),
			Action:    "legacy.event",
			UserID:    "user1",
			PrevHash:  prev,
		}
		e.Hash = s.legacyHash(e)
		prev = e.Hash
		entries = append(entries, e)
	}
	writeChain(t, dir, entries)
	writeMark(t, keyDir, chainState{Count: uint64(n), Hash: prev})
	return entries
}

// writeMark replaces the anchor beside the key.
func writeMark(t *testing.T, keyDir string, st chainState) {
	t.Helper()
	if err := writeState(filepath.Join(keyDir, "audit.state"), st); err != nil {
		t.Fatalf("writeState failed: %v", err)
	}
}

func TestKeyedLegacyChainConvergesAndContinues(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeKeyedLegacyChain(t, dir, keyDir, 3)

	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("keyed legacy chain rejected after conversion: ok=%v, err=%v", ok, err)
	}

	if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", "after conversion"); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("converted chain rejected after an append: ok=%v, err=%v", ok, err)
	}

	// Conversion rewrites the legacy entries in place: no marker entry, and the
	// original events are all still there.
	entries := readChain(t, dir)
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 3 converted + 1 new", len(entries))
	}
	for i, e := range entries[:3] {
		if e.Action != "legacy.event" {
			t.Fatalf("entry %d = %q, want the original legacy event preserved", i, e.Action)
		}
	}

	// Reopening must not convert or append a second time.
	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store2.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("reopened chain rejected: ok=%v, err=%v", ok, err)
	}
	if got := len(readChain(t, dir)); got != 4 {
		t.Fatalf("reopen appended entries: got %d, want 4", got)
	}
}

// The unkeyed format is abandoned, not migrated. It was chained under no secret, so
// converting it would bless whatever an attacker who could write the file had put
// there — and the boundary marking where those entries stopped was never persisted.
func TestUnkeyedLegacyChainIsRefused(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeUnkeyedChain(t, dir, 3)

	if _, err := NewStore(dir, keyDir); err == nil {
		t.Fatal("NewStore adopted an unkeyed legacy chain")
	}
	// And it is left exactly as it was, for the auditor.
	entries := readChain(t, dir)
	if len(entries) != 3 || entries[0].Hash != unkeyedHash(entries[0]) {
		t.Fatal("the refused log was rewritten")
	}
}

func TestForgedKeyedLegacyEntryIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeKeyedLegacyChain(t, dir, keyDir, 3)
	if _, err := NewStore(dir, keyDir); err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// Rewrite a converted record and re-chain forward with the only digest an
	// attacker without the key can compute.
	entries := readChain(t, dir)
	entries[1].Details = "nothing to see here"
	prev := entries[0].Hash
	for i := 1; i < 3; i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = unkeyedHash(entries[i])
		prev = entries[i].Hash
	}
	writeChain(t, dir, entries)

	assertTamperDetected(t, dir, keyDir, "forged legacy entry")
}

// A legacy log rolled back before it is ever converted must not be converted: doing
// so would save a fresh mark over the count that proves entries were removed.
func TestTruncatedLegacyChainIsNotConverged(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	entries := writeKeyedLegacyChain(t, dir, keyDir, 3)
	writeChain(t, dir, entries[:2])

	_, err := NewStore(dir, keyDir)
	if !errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("NewStore err = %v, want ErrTruncated", err)
	}
	if got := readChain(t, dir)[1].Hash; got != entries[1].Hash {
		t.Fatal("the truncated legacy log was converted anyway")
	}
}

func TestDowngradedChainIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload"} {
		if _, err := store.Log(t.Context(), action, "user1", "dev1", "127.0.0.1", action); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}

	// An attacker without the key rewrites the whole file as unkeyed entries,
	// hoping the legacy verification path accepts them.
	entries := readChain(t, dir)
	prev := genesisHash
	for i := range entries {
		entries[i].Details = "forged"
		entries[i].PrevHash = prev
		entries[i].Hash = unkeyedHash(entries[i])
		prev = entries[i].Hash
	}
	writeChain(t, dir, entries)

	assertTamperDetected(t, dir, keyDir, "downgraded chain")
}

func TestShortKeyFileIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "audit.key"), []byte("abcd"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := NewStore(dir, keyDir); err == nil {
		t.Fatal("NewStore accepted a 2-byte audit key")
	}
}

func TestTruncationAfterConversionIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeKeyedLegacyChain(t, dir, keyDir, 3)
	if _, err := NewStore(dir, keyDir); err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// Roll the log back, dropping converted entries the mark still counts.
	entries := readChain(t, dir)
	writeChain(t, dir, entries[:2])

	if _, err := NewStore(dir, keyDir); !errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("NewStore err = %v, want ErrTruncated", err)
	}
}

func TestTruncatedKeyedChainIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload", "vault.download"} {
		if _, err := store.Log(t.Context(), action, "user1", "dev1", "127.0.0.1", action); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}

	// Drop the most recent record. Every surviving entry still hashes correctly.
	entries := readChain(t, dir)
	writeChain(t, dir, entries[:len(entries)-1])

	if _, err := NewStore(dir, keyDir); !errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("NewStore err = %v, want ErrTruncated", err)
	}
}

func TestDeletedLogIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", "login"); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store2.VerifyIntegrity(); ok || err == nil {
		t.Fatalf("deleted log accepted: ok=%v, err=%v", ok, err)
	}
}

// Appending after a truncation must not quietly rewrite the record of what the log
// used to hold. Resuming at a tail the mark does not name would mint a sequence
// number that already exists, so the store refuses to open at all.
func TestTruncationSurvivesFurtherLogging(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload", "vault.download"} {
		if _, err := store.Log(t.Context(), action, "user1", "dev1", "127.0.0.1", action); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}
	entries := readChain(t, dir)
	writeChain(t, dir, entries[:1])

	if _, err := NewStore(dir, keyDir); !errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("NewStore err = %v, want ErrTruncated", err)
	}
	if got := len(readChain(t, dir)); got != 1 {
		t.Fatalf("the truncated log was appended to: %d entries", got)
	}
}

// loggedStore returns a store with n records and its key.
func loggedStore(t *testing.T, dir, keyDir string, n int) *Store {
	t.Helper()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", fmt.Sprintf("event %d", i)); err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}
	return store
}

// A mark several writes behind the log is a config volume that was unwritable for a
// while, not tampering: minting any one of those records still needs the key. The
// whole run is adopted, not just the last of it.
func TestMarkSeveralWritesBehindIsAdopted(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 4)

	entries := readChain(t, dir)
	writeMark(t, keyDir, chainState{Count: 1, Hash: entries[0].Hash})

	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore refused a mark three writes behind: %v", err)
	}
	if store.anchor.Count != 4 || store.anchor.Hash != entries[3].Hash {
		t.Fatalf("adopted anchor = %+v, want 4/%s", store.anchor, entries[3].Hash)
	}
	if ok, err := store.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("adopted chain does not verify: ok=%v, err=%v", ok, err)
	}
	// The adoption is persisted, so a restart does not have to redo it.
	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if store2.anchor.Count != 4 {
		t.Fatalf("adopted mark was not saved: %+v", store2.anchor)
	}
}

// Every record past the mark carries its own digest, so VerifyRecord alone accepts a
// run re-minted on another branch. Only chaining them onto the mark's own hash
// catches it.
func TestReMintedForkPastTheMarkIsRefused(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 4)
	entries := readChain(t, dir)

	key, err := loadKey(keyDir)
	if err != nil {
		t.Fatalf("loadKey failed: %v", err)
	}

	// A whole chain minted from genesis with different content. Its records 2..4 are
	// spliced in after the real record 1.
	fork := make([]Entry, 4)
	tuples := make([][]string, 4)
	for i := range fork {
		fork[i] = Entry{
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Action:    "fork.event",
			UserID:    "attacker",
		}
		tuples[i] = fieldsOf(fork[i])
	}
	recs, _, err := auditchain.Replay(key, tuples)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}
	for i := range fork {
		fork[i].Index, fork[i].PrevHash, fork[i].Hash = int64(recs[i].Seq)-1, recs[i].Prev, recs[i].Hash
	}

	// The premise: each spliced record does carry its own digest at its own position.
	for _, e := range fork[1:] {
		if err := auditchain.VerifyRecord(key, recordOf(e)); err != nil {
			t.Fatalf("test setup: fork record %d should verify on its own: %v", e.Index, err)
		}
	}

	writeChain(t, dir, append([]Entry{entries[0]}, fork[1:]...))
	writeMark(t, keyDir, chainState{Count: 1, Hash: entries[0].Hash})

	if _, err := NewStore(dir, keyDir); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("NewStore err = %v, want ErrBrokenChain for a re-minted fork", err)
	}
}

// Without the mark a log with entries removed and an intact one are the same file,
// so there is nothing to place the tail against. One append used to mint a mark over
// whatever was on disk.
func TestLogWithNoMarkIsRefused(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 3)
	if err := os.Remove(filepath.Join(keyDir, "audit.state")); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	if _, err := NewStore(dir, keyDir); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("NewStore err = %v, want ErrBrokenChain for a log with no mark", err)
	}
	if got := len(readChain(t, dir)); got != 3 {
		t.Fatalf("the log was rewritten: %d entries", got)
	}
}

// A mark that cannot be written is reported from Log, never to the chain. Failing the
// append instead would leave the chain a step behind a record already on disk, and
// the next Log would reuse that sequence number — a fork, minted silently, because
// the mark it compares against has already moved.
func TestFailedMarkWriteDoesNotForkTheLog(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store := loggedStore(t, dir, keyDir, 0)
	store.statePath = filepath.Join(keyDir, "no-such-dir", "audit.state")

	for i := 0; i < 2; i++ {
		if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", fmt.Sprintf("event %d", i)); err == nil {
			t.Fatalf("Log %d hid a failed mark write", i)
		}
	}

	entries := readChain(t, dir)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Index != 0 || entries[1].Index != 1 {
		t.Fatalf("sequence forked: indices %d and %d", entries[0].Index, entries[1].Index)
	}
	key, err := loadKey(keyDir)
	if err != nil {
		t.Fatalf("loadKey failed: %v", err)
	}
	recs := []auditchain.Record{recordOf(entries[0]), recordOf(entries[1])}
	if err := auditchain.Verify(key, recs, store.anchor); err != nil {
		t.Fatalf("chain does not verify after two failed mark writes: %v", err)
	}
}

// Log's deadline is measured from where the caller can make progress, not from where
// it starts queueing. Derived above s.mu it would be spent waiting on a mutex no
// context can interrupt, and a queued record would be dropped on arrival.
func TestQueuedLogSpendsItsBudgetOnTheChain(t *testing.T) {
	restore := appendTimeout
	appendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { appendTimeout = restore })

	dir, keyDir := t.TempDir(), t.TempDir()
	store := loggedStore(t, dir, keyDir, 0)

	var wg sync.WaitGroup
	store.mu.Lock()
	wg.Add(1)
	var logErr error
	go func() {
		defer wg.Done()
		_, logErr = store.Log(context.Background(), "auth.login", "user1", "", "127.0.0.1", "queued")
	}()
	time.Sleep(4 * appendTimeout)
	store.mu.Unlock()
	wg.Wait()

	if logErr != nil {
		t.Fatalf("a record queued for longer than the deadline was dropped: %v", logErr)
	}
	if got := len(readChain(t, dir)); got != 1 {
		t.Fatalf("got %d entries, want the queued record", got)
	}
}
