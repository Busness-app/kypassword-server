package users

import (
	"testing"
)

func TestUserStoreCRUD(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// 1. Create user
	u, err := store.Create("Alice", "alice-secret-key-123", RoleAdmin)
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}
	if u.Username != "Alice" || u.Role != RoleAdmin {
		t.Errorf("unexpected user attributes: %+v", u)
	}

	// Duplicate username should fail
	if _, err := store.Create("alice", "another-pw", RoleUser); err != ErrUsernameTaken {
		t.Errorf("expected ErrUsernameTaken, got: %v", err)
	}

	// 2. VerifyAuth
	authed, err := store.VerifyAuth("alice", "alice-secret-key-123")
	if err != nil || authed.ID != u.ID {
		t.Fatalf("VerifyAuth failed: %v", err)
	}

	if _, err := store.VerifyAuth("alice", "wrong-pw"); err != ErrInvalidAuth {
		t.Errorf("expected ErrInvalidAuth on bad password, got: %v", err)
	}

	// 3. SSO Link and Lookup
	err = store.LinkSSO(u.ID, "sso-uuid-alice", "alice_sso", "alice@urlxl.com")
	if err != nil {
		t.Fatalf("LinkSSO failed: %v", err)
	}

	bySub, err := store.GetBySSOSub("sso-uuid-alice")
	if err != nil || bySub.ID != u.ID || bySub.SSOUsername != "alice_sso" {
		t.Fatalf("GetBySSOSub failed: %+v, err: %v", bySub, err)
	}

	// 4. Paper Recovery
	err = store.SetPaperRecovery(u.ID, "KYPASS-ABCD-1234-EFGH")
	if err != nil {
		t.Fatalf("SetPaperRecovery failed: %v", err)
	}

	recUser, err := store.VerifyPaperRecovery("alice", "KYPASS-ABCD-1234-EFGH")
	if err != nil || recUser.ID != u.ID {
		t.Fatalf("VerifyPaperRecovery failed: %v", err)
	}

	if _, err := store.VerifyPaperRecovery("alice", "KYPASS-WRONG"); err != ErrInvalidAuth {
		t.Errorf("expected ErrInvalidAuth on wrong recovery code, got: %v", err)
	}

	// 5. Reload store from disk
	store2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reload NewStore failed: %v", err)
	}

	uReloaded, err := store2.Get(u.ID)
	if err != nil || uReloaded.SSOSub != "sso-uuid-alice" {
		t.Errorf("reloaded user mismatch: %+v, err: %v", uReloaded, err)
	}
}
