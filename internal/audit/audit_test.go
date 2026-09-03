package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// Deleting the log, wiping it to zero bytes and corrupting its first line are one
// attack with one effect: readAll returns no entries and the mark still counts some.
// All three get the same answer, and it is the same one a log missing its last record
// gets — refuse to start. Opening instead meant every record written during that
// uptime landed in a chain that could never verify, with no signal at boot.
func TestEmptiedLogIsRejected(t *testing.T) {
	for name, wipe := range map[string]func(*testing.T, string){
		"deleted": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatalf("Remove failed: %v", err)
			}
		},
		"truncated to zero bytes": func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}
		},
		"first line corrupt": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("not json at all\n"), 0600); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, keyDir := t.TempDir(), t.TempDir()
			loggedStore(t, dir, keyDir, 3)
			wipe(t, filepath.Join(dir, "audit.jsonl"))

			if _, err := NewStore(dir, keyDir); !errors.Is(err, auditchain.ErrTruncated) {
				t.Fatalf("NewStore err = %v, want ErrTruncated", err)
			}
		})
	}
}

// The counterpart: no log and no mark is a first run, not a truncation.
func TestFirstRunOpensCleanly(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if _, err := store.Log(t.Context(), "auth.login", "user1", "", "127.0.0.1", "first"); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("first-run chain does not verify: ok=%v, err=%v", ok, err)
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

// Resume verifies only the last record, and the predecessor walk only checks that the
// links join up. Content altered past the mark without touching any digest passes
// both: only VerifyRecord on every record in the run catches it. Deleting that call
// from placeTail must fail this test.
func TestTamperedRecordPastTheMarkIsRefused(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 4)

	entries := readChain(t, dir)
	writeMark(t, keyDir, chainState{Count: 1, Hash: entries[0].Hash})

	// An intermediate record past the mark, rewritten in place. Its own hash and its
	// link to either neighbour are left exactly as they were, and the last record --
	// the only one Resume looks at -- is untouched.
	entries[2].Details = "nothing to see here"
	writeChain(t, dir, entries)

	if _, err := NewStore(dir, keyDir); err == nil {
		t.Fatal("NewStore adopted a run holding a record that no longer carries its own digest")
	}
}

// appendTimeout is a real bound only because acquire never contends: Log holds s.mu
// across the whole Append, and s.chain is used from exactly one place in the package.
// A second call site would put a waiter behind a hung store with no way to shed, and
// the deadline would start firing on a queue instead of on a fault.
func TestChainIsDrivenFromOneCallSite(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	var sites []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, ".chain.") {
				sites = append(sites, fmt.Sprintf("%s:%d", f, i+1))
			}
		}
	}
	if len(sites) != 1 {
		t.Fatalf("the chain is driven from %d places %v; appendTimeout is only a bound while there is one", len(sites), sites)
	}
}

// A comment naming a test it is not backed by is worse than no comment: it reads as
// evidence. Every Test... identifier mentioned in this package's non-test source must
// name a test that exists somewhere in the repository.
func TestCommentsNameRealTests(t *testing.T) {
	defined := definedTests(t)
	var cited []string
	name := regexp.MustCompile(`\bTest[A-Z]\w*`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, n := range name.FindAllString(line, -1) {
				if !defined[n] {
					cited = append(cited, fmt.Sprintf("%s:%d cites %s", f, i+1, n))
				}
			}
		}
	}
	if len(cited) > 0 {
		t.Fatalf("comments name tests that do not exist: %v", cited)
	}
}

// An empty audit.key must never be replaced. The old loadKey read the file and treated
// both a read error and a zero-length result as "no key yet", so it minted a fresh one and
// wrote it over the original — after which every record ever written was unverifiable,
// with nothing to restore from. keyfile.LoadOrCreate creates only when the file is absent.
func TestEmptyKeyFileIsNotRegenerated(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 2)

	keyPath := filepath.Join(keyDir, "audit.key")
	original, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) == 0 {
		t.Fatal("setup did not persist a key")
	}

	// The file is emptied — a truncated write, an interrupted restore, a full disk.
	if err := os.WriteFile(keyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStore(dir, keyDir); err == nil {
		t.Fatal("NewStore started on an empty audit.key instead of refusing")
	}
	if data, err := os.ReadFile(keyPath); err != nil || len(data) != 0 {
		t.Fatalf("the empty key file was overwritten (err=%v, %d bytes); the original key is gone", err, len(data))
	}

	// And the refusal is recoverable: restoring the key from backup brings the log back,
	// which is only true because nothing was regenerated over it.
	if err := os.WriteFile(keyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore after restoring the key: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("records did not verify under the restored key: ok=%v err=%v", ok, err)
	}
}

// A mark that cannot be read must not be recreated empty. loadState used to treat every
// failure but success as "no mark yet" and rename an empty one into place, destroying the
// anchor — and placeTail then reported that the mark "was removed and recreated empty",
// describing what the process had just done to it.
func TestUnreadableMarkIsNotOverwritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits this test relies on")
	}
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 3)

	statePath := filepath.Join(keyDir, "audit.state")
	original, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(statePath, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(statePath, 0600) })

	if _, err := NewStore(dir, keyDir); err == nil {
		t.Fatal("NewStore started on an unreadable mark instead of reporting it")
	}

	if err := os.Chmod(statePath, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatalf("the unreadable mark was overwritten:\nbefore %s\nafter  %s", original, after)
	}
}

// converge re-mints a legacy log under the audit key. It may only do that for the log the
// mark attests to, and the mark names both a count and a tail hash. A count-only check is
// passed by any equal-length substitution.
func TestLegacyLogIsNotConvergedAgainstAMismatchedMark(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	entries := writeKeyedLegacyChain(t, dir, keyDir, 3)

	// Same count, different tail: the mark no longer names this log.
	writeMark(t, keyDir, chainState{Count: 3, Hash: entries[0].Hash})

	if _, err := NewStore(dir, keyDir); err == nil {
		t.Fatal("NewStore converged a legacy log the mark does not name")
	}
	if got := readChain(t, dir); got[2].Hash != entries[2].Hash {
		t.Fatal("the log was rewritten even though conversion was refused")
	}
}

// definedTests collects every test function the repository actually defines.
//
// The pattern is anchored to the start of a line. A Go test function can only be
// declared at column zero, and without the anchor a commented-out "// func TestX(" was
// a definition as far as this map was concerned — so a comment citing a test that had
// been written, deleted and left behind as a comment satisfied the guard that exists
// precisely to catch that. TestCommentedOutDefinitionDoesNotCount holds it.
func definedTests(t *testing.T) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func (Test[A-Z]\w*)\(`)
	defined := map[string]bool{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllStringSubmatch(string(data), -1) {
			defined[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
	return defined
}

// The fixture for the test below, and the thing the guard used to accept: a definition
// that is not one.
//
// func TestSomethingThatDoesNotExist(t *testing.T) {}
//
// It sits in a test file because TestCommentsNameRealTests only reads comments in
// non-test sources; here it is a fixture, there it would be a citation.
func TestCommentedOutDefinitionDoesNotCount(t *testing.T) {
	const commented = "TestSomethingThatDoesNotExist"
	defined := definedTests(t)
	if defined[commented] {
		t.Fatalf("a commented-out func %s( counted as a definition, so a comment citing it would pass the guard", commented)
	}

	// The other half: the guard flags a cited name it cannot find, and this is the
	// name it would flag.
	name := regexp.MustCompile(`\bTest[A-Z]\w*`)
	cited := name.FindAllString("// as "+commented+" shows", -1)
	if len(cited) != 1 || cited[0] != commented {
		t.Fatalf("the citation pattern read %v out of a comment naming %s", cited, commented)
	}
	if defined[cited[0]] {
		t.Fatalf("%s is cited and treated as defined; the guard would stay silent", cited[0])
	}
}

// AUDIT_KEY is the documented way to keep the audit key out of the config volume, and
// nothing in this repo exercised it: what it accepts, and at what length, was unproven
// here. keyfile.FromEnv takes hex or standard base64 and requires exactly keyBytes.
//
// The exact length is deliberate and stays. A key longer than the one asked for is a
// key half of which is being silently discarded, and two installs disagreeing about
// how much of it counts cannot read each other's chains.
func TestAuditKeyFromEnv(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, keyBytes)

	for _, tc := range []struct{ name, value string }{
		{"hex", hex.EncodeToString(key)},
		{"hex with surrounding whitespace", "  " + hex.EncodeToString(key) + "\n"},
		{"base64", base64.StdEncoding.EncodeToString(key)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, keyDir := t.TempDir(), t.TempDir()
			t.Setenv("AUDIT_KEY", tc.value)

			store, err := NewStore(dir, keyDir)
			if err != nil {
				t.Fatalf("NewStore refused AUDIT_KEY as %s: %v", tc.name, err)
			}
			if !bytes.Equal(store.key, key) {
				t.Fatalf("chain key = %x, want the value of AUDIT_KEY", store.key)
			}
			if _, err := os.Stat(filepath.Join(keyDir, "audit.key")); !os.IsNotExist(err) {
				t.Fatalf("a key file was minted while AUDIT_KEY was set (stat err %v); the operator's key is not the one in use", err)
			}
			if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", "signed in"); err != nil {
				t.Fatalf("Log under an env key failed: %v", err)
			}
			if ok, err := store.VerifyIntegrity(); err != nil || !ok {
				t.Fatalf("VerifyIntegrity under an env key: ok=%v err=%v", ok, err)
			}
		})
	}

	for _, tc := range []struct{ name, value string }{
		{"one byte short", hex.EncodeToString(key[:keyBytes-1])},
		{"twice as long", hex.EncodeToString(bytes.Repeat(key, 2))},
		{"not hex or base64", "hunter2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, keyDir := t.TempDir(), t.TempDir()
			t.Setenv("AUDIT_KEY", tc.value)

			_, err := NewStore(dir, keyDir)
			if err == nil {
				t.Fatalf("NewStore started on an AUDIT_KEY that is %s", tc.name)
			}
			if !strings.Contains(err.Error(), "AUDIT_KEY") {
				t.Fatalf("the refusal does not name the variable the operator has to fix: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(keyDir, "audit.key")); !os.IsNotExist(statErr) {
				t.Fatalf("a key was generated behind a rejected AUDIT_KEY (stat err %v)", statErr)
			}
		})
	}
}

// A crash between a record's write and its flush leaves half a line on the end. The
// reader stops there, so the next append lands behind the fragment and every record
// after it is unreadable — the log lost from that point on, with every check still
// passing and nothing said.
func TestTornTailIsRepaired(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 3)

	logPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteString(`{"index":3,"timestamp":"2026-09-0`); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore refused a log with a torn tail: %v", err)
	}
	if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", "after the tear"); err != nil {
		t.Fatalf("Log after a torn tail failed: %v", err)
	}
	entries, err := store.List(10)
	if err != nil || len(entries) != 4 {
		t.Fatalf("List returned %d entries, want 4 (err %v); the log is unreadable past the tear", len(entries), err)
	}
	if ok, err := store.VerifyIntegrity(); err != nil || !ok {
		t.Fatalf("VerifyIntegrity after a repaired tail: ok=%v err=%v", ok, err)
	}
}

// A mark that does not parse is refused, not replaced. It is one of the boot refusals
// CHANGELOG.md tells operators about, and it is also what a rename that reached the disk
// ahead of its own contents would leave — writeState flushes before the rename for that
// reason.
func TestCorruptMarkRefusesToStart(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	loggedStore(t, dir, keyDir, 2)

	statePath := filepath.Join(keyDir, "audit.state")
	if err := os.WriteFile(statePath, []byte(`{"count":2,"ha`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := NewStore(dir, keyDir)
	if err == nil {
		t.Fatal("NewStore started on a mark it could not parse")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("the refusal does not say what is wrong with the mark: %v", err)
	}
	after, readErr := os.ReadFile(statePath)
	if readErr != nil || string(after) != `{"count":2,"ha` {
		t.Fatalf("the corrupt mark was rewritten (%q, err %v)", after, readErr)
	}
}
