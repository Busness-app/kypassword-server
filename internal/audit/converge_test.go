package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Busness-app/ky-primitives/auditchain"
)

// chainOf reads the log back, oldest first, as shared-package records.
func chainOf(t *testing.T, s *Store) []auditchain.Record {
	t.Helper()
	entries, err := s.List(0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	recs := make([]auditchain.Record, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		recs = append(recs, recordOf(entries[i]))
	}
	return recs
}

// The point of converging: an entry this server writes must verify under the
// shared package, with no KyPassword-specific hashing involved.
func TestEntriesVerifyUnderSharedPackage(t *testing.T) {
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

	key, err := loadKey(keyDir)
	if err != nil {
		t.Fatalf("loadKey failed: %v", err)
	}
	if err := auditchain.Verify(key, chainOf(t, store), store.anchor); err != nil {
		t.Fatalf("chain does not verify under the shared package: %v", err)
	}
}

// The exported form must verify with nothing but the shared package: that is what
// makes one verifier possible across products that store different fields.
func TestExportedChainVerifiesWithSharedPackageAlone(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store, err := NewStore(dir, keyDir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := store.Log(t.Context(), "auth.login", "user1", "dev1", "127.0.0.1", "x"); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}

	var buf bytes.Buffer
	anchor, err := store.ExportChain(&buf)
	if err != nil {
		t.Fatalf("ExportChain failed: %v", err)
	}

	var recs []auditchain.Record
	dec := json.NewDecoder(&buf)
	for {
		var r auditchain.Record
		if err := dec.Decode(&r); err != nil {
			break
		}
		recs = append(recs, r)
	}

	key, err := loadKey(keyDir)
	if err != nil {
		t.Fatalf("loadKey failed: %v", err)
	}
	if err := auditchain.Verify(key, recs, anchor); err != nil {
		t.Fatalf("exported chain does not verify: %v", err)
	}
}
