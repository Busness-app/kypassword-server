package users

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// retiredCredentialFields are the JSON keys that held password- and recovery-derived
// material. The server authenticates nobody now — KySignOn does — so none of these may
// appear in a user record again.
var retiredCredentialFields = []string{"passwordHash", "authSalt", "authIterations", "recoveryHash", "mustChangePassword"}

func TestUserRecordCarriesNoAuthenticationSecret(t *testing.T) {
	// The regression guard for the whole SSO-only change: if any of these reappear, the
	// server is storing password-derived material again.
	u := User{ID: "1", Username: "alice", Role: RoleUser, Active: true, SSOSub: "sub-1"}
	blob, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range retiredCredentialFields {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("user record still carries %q: %s", forbidden, blob)
		}
	}
}

func TestPublicCarriesNoAuthenticationSecret(t *testing.T) {
	blob, err := json.Marshal(User{ID: "1", Username: "alice", Role: RoleUser, Active: true}.Public())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range retiredCredentialFields {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("public user still carries %q: %s", forbidden, blob)
		}
	}
}

func TestStoreLoadsLegacyFileAndDropsCredentialFields(t *testing.T) {
	// Existing deployments upgrade by starting the new binary. encoding/json ignores the
	// keys it no longer knows, so a legacy file loads cleanly and the verifier is erased
	// from disk on the first write. There is nothing to migrate to.
	dir := t.TempDir()
	writeUsersFile(t, dir, `[
	  {
	    "id":"u1","username":"alice","role":"admin","active":true,
	    "passwordHash":"deadbeef","authSalt":"abc123","authIterations":600000,
	    "recoveryHash":"cafebabe","mustChangePassword":true,
	    "ssoSub":"sub-1","ssoUsername":"alice","ssoEmail":"alice@example.com"
	  }
	]`)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	u, err := store.Get("u1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if u.Username != "alice" || u.Role != RoleAdmin || !u.Active || u.SSOSub != "sub-1" {
		t.Fatalf("account did not survive the upgrade intact: %+v", u)
	}

	// Any write rewrites the whole file, so one role change is enough to erase them all.
	if err := store.SetRole("u1", RoleUser); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, forbidden := range retiredCredentialFields {
		if strings.Contains(string(onDisk), forbidden) {
			t.Errorf("users.json still contains %q after a save:\n%s", forbidden, onDisk)
		}
	}

	// And the account is still usable after the rewrite.
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	if got, err := reloaded.GetBySSOSub("sub-1"); err != nil || got.Username != "alice" {
		t.Fatalf("reloaded account mismatch: %+v, err: %v", got, err)
	}
}

func TestUserStoreCRUD(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// 1. Provision from an SSO identity — the only way an account is created now.
	u, err := store.CreateSSOUser("Alice", RoleAdmin, "sso-uuid-alice", "alice_sso", "alice@urlxl.com")
	if err != nil {
		t.Fatalf("CreateSSOUser failed: %v", err)
	}
	if u.Username != "Alice" || u.Role != RoleAdmin || !u.Active {
		t.Errorf("unexpected user attributes: %+v", u)
	}

	// Duplicate username under a different subject is refused.
	if _, err := store.CreateSSOUser("alice", RoleUser, "sso-uuid-other", "other", ""); err != ErrUsernameTaken {
		t.Errorf("expected ErrUsernameTaken, got: %v", err)
	}

	// 2. Lookup by subject, username and ID.
	bySub, err := store.GetBySSOSub("sso-uuid-alice")
	if err != nil || bySub.ID != u.ID || bySub.SSOUsername != "alice_sso" {
		t.Fatalf("GetBySSOSub failed: %+v, err: %v", bySub, err)
	}
	if byName, err := store.GetByUsername("ALICE"); err != nil || byName.ID != u.ID {
		t.Fatalf("GetByUsername is not case-insensitive: %+v, err: %v", byName, err)
	}
	if _, err := store.GetBySSOSub("nobody"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	// 3. Role and activation changes.
	if err := store.SetRole(u.ID, RoleUser); err != nil {
		t.Fatalf("SetRole failed: %v", err)
	}
	if err := store.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate failed: %v", err)
	}
	if got, _ := store.Get(u.ID); got.Active || got.Role != RoleUser {
		t.Errorf("role/active change did not stick: %+v", got)
	}
	if err := store.Reactivate(u.ID); err != nil {
		t.Fatalf("Reactivate failed: %v", err)
	}

	// 4. Reload store from disk.
	store2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reload NewStore failed: %v", err)
	}
	uReloaded, err := store2.Get(u.ID)
	if err != nil || uReloaded.SSOSub != "sso-uuid-alice" || !uReloaded.Active {
		t.Errorf("reloaded user mismatch: %+v, err: %v", uReloaded, err)
	}
}

func TestLinkSSORefusesASubjectHeldByAnotherAccount(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	alice, err := store.CreateSSOUser("alice", RoleUser, "sub-alice", "alice", "")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}
	bob, err := store.CreateSSOUser("bob", RoleUser, "sub-bob", "bob", "")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}

	if err := store.LinkSSO(bob.ID, "sub-alice", "bob", ""); err == nil {
		t.Fatal("one KySignOn identity must not resolve to two accounts")
	}
	if got, _ := store.GetBySSOSub("sub-alice"); got.ID != alice.ID {
		t.Errorf("alice lost her subject: %+v", got)
	}
}

func TestDirectoryUpdateFailureKeepsPreviousRecord(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.CreateDirectoryUser("inactive", RoleUser, "subject", "inactive", "old@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if original.Active {
		t.Fatal("inactive creation was active")
	}
	if err := os.Mkdir(filepath.Join(dir, "users.json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateDirectory(original.ID, RoleAdmin, true, "changed", "new@example.com", true); err == nil {
		t.Fatal("expected write failure")
	}
	after, _ := store.Get(original.ID)
	if after != original {
		t.Fatalf("failed write changed in-memory record: %+v", after)
	}
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	after, _ = reloaded.Get(original.ID)
	if after != original {
		t.Fatal("failed write changed durable record")
	}
}
