package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLogAndVerify(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// 1. Log multiple events
	_, err = store.Log("auth.login", "user1", "dev1", "127.0.0.1", "successful login")
	if err != nil {
		t.Fatalf("Log 1 failed: %v", err)
	}
	_, err = store.Log("vault.upload", "user1", "dev1", "127.0.0.1", "version 2 uploaded")
	if err != nil {
		t.Fatalf("Log 2 failed: %v", err)
	}
	_, err = store.Log("vault.download", "user1", "dev1", "127.0.0.1", "version 2 downloaded")
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

	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}

	ok, err = store2.VerifyIntegrity()
	if ok || err == nil {
		t.Fatalf("expected tampering detection, but got ok=%v, err=%v", ok, err)
	}
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
		if _, err := store.Log(action, "user1", "dev1", "127.0.0.1", action+" ok"); err != nil {
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
		entries[i].V = 0
		entries[i].Hash = legacyHash(entries[i])
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

	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	ok, err := store2.VerifyIntegrity()
	if ok || err == nil {
		t.Fatalf("forged chain accepted: ok=%v, err=%v", ok, err)
	}
}

// legacyHash is the unkeyed digest the pre-HMAC chain used, and the only one an
// attacker without the key can compute.
func legacyHash(e Entry) string {
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

// writeLegacyChain lays down an audit file as the unkeyed implementation wrote it.
func writeLegacyChain(t *testing.T, dir string, n int) {
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
		e.Hash = legacyHash(e)
		prev = e.Hash
		entries = append(entries, e)
	}
	writeChain(t, dir, entries)
}

func TestLegacyChainVerifiesAndContinues(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeLegacyChain(t, dir, 3)

	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	ok, err := store.VerifyIntegrity()
	if !ok || err != nil {
		t.Fatalf("legacy chain rejected after migration: ok=%v, err=%v", ok, err)
	}

	if _, err := store.Log("auth.login", "user1", "dev1", "127.0.0.1", "after migration"); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	ok, err = store.VerifyIntegrity()
	if !ok || err != nil {
		t.Fatalf("mixed chain rejected: ok=%v, err=%v", ok, err)
	}

	// Migration must anchor the legacy tail with a keyed entry immediately,
	// not wait for the next real event.
	entries := readChain(t, dir)
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 3 legacy + rekey marker + 1 new", len(entries))
	}
	if entries[3].Action != "audit.rekey" || entries[3].V == 0 {
		t.Fatalf("entry 3 = %+v, want a keyed audit.rekey marker", entries[3])
	}

	// Reopening must not append a second marker.
	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store2.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("reopened chain rejected: ok=%v, err=%v", ok, err)
	}
	if got := len(readChain(t, dir)); got != 5 {
		t.Fatalf("reopen appended entries: got %d, want 5", got)
	}
}

func TestForgedLegacyEntryIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeLegacyChain(t, dir, 3)
	if _, err := NewStore(dir, keyDir); err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// Rewrite a legacy record and re-chain the legacy region forward. The keyed
	// marker commits to the old tail, so this must not verify.
	entries := readChain(t, dir)
	entries[1].Details = "nothing to see here"
	prev := entries[0].Hash
	for i := 1; i < 3; i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = legacyHash(entries[i])
		prev = entries[i].Hash
	}
	writeChain(t, dir, entries)

	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); ok || err == nil {
		t.Fatalf("forged legacy entry accepted: ok=%v, err=%v", ok, err)
	}
}

func TestDowngradedChainIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload"} {
		if _, err := store.Log(action, "user1", "dev1", "127.0.0.1", action); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}

	// An attacker without the key rewrites the whole file as unkeyed entries,
	// hoping the legacy verification path accepts them.
	entries := readChain(t, dir)
	prev := genesisHash
	for i := range entries {
		entries[i].V = 0
		entries[i].Details = "forged"
		entries[i].PrevHash = prev
		entries[i].Hash = legacyHash(entries[i])
		prev = entries[i].Hash
	}
	writeChain(t, dir, entries)

	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store2.VerifyIntegrity(); ok || err == nil {
		t.Fatalf("downgraded chain accepted: ok=%v, err=%v", ok, err)
	}
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

func TestTruncationToLegacyPrefixIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	writeLegacyChain(t, dir, 3)
	if _, err := NewStore(dir, keyDir); err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// Drop the keyed marker, rolling the log back to the unkeyed records the
	// attacker can still forge.
	entries := readChain(t, dir)
	writeChain(t, dir, entries[:3])

	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); ok || err == nil {
		t.Fatalf("truncated chain accepted: ok=%v, err=%v", ok, err)
	}
}

func TestTruncatedKeyedChainIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload", "vault.download"} {
		if _, err := store.Log(action, "user1", "dev1", "127.0.0.1", action); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}

	// Drop the most recent record. Every surviving entry still hashes correctly.
	entries := readChain(t, dir)
	writeChain(t, dir, entries[:len(entries)-1])

	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if ok, err := store2.VerifyIntegrity(); ok || err == nil {
		t.Fatalf("truncated chain accepted: ok=%v, err=%v", ok, err)
	}
}

func TestDeletedLogIsRejected(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if _, err := store.Log("auth.login", "user1", "dev1", "127.0.0.1", "login"); err != nil {
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

// Appending after a truncation must not quietly rewrite the record of what the
// log used to hold.
func TestTruncationSurvivesFurtherLogging(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for _, action := range []string{"auth.login", "vault.upload", "vault.download"} {
		if _, err := store.Log(action, "user1", "dev1", "127.0.0.1", action); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}
	entries := readChain(t, dir)
	writeChain(t, dir, entries[:1])

	store2, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}
	if _, err := store2.Log("auth.login", "user1", "dev1", "127.0.0.1", "after truncation"); err != nil {
		t.Fatalf("Log after truncation failed: %v", err)
	}
	if ok, err := store2.VerifyIntegrity(); ok || err == nil {
		t.Fatalf("truncation erased by later logging: ok=%v, err=%v", ok, err)
	}
}
