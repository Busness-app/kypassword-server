package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogAndVerify(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
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

	store2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore 2 failed: %v", err)
	}

	ok, err = store2.VerifyIntegrity()
	if ok || err == nil {
		t.Fatalf("expected tampering detection, but got ok=%v, err=%v", ok, err)
	}
}
