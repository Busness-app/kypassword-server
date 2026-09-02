package users

import (
	"os"
	"path/filepath"
	"testing"
)

// writeUsersFile seeds a store directory with a users.json fixture. Building the file
// directly is how a real migration arrives: an existing deployment's accounts, written by
// an older binary, opened by this one.
func writeUsersFile(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestUnlinkedActiveListsOnlyActiveAccountsWithoutSSO(t *testing.T) {
	// An inactive account cannot sign in, so it does not block startup. A linked one is
	// already migrated. Only an account that is both active and unlinked would silently
	// lose access — or be duplicated by replication — once KySignOn is the only directory.
	dir := t.TempDir()
	writeUsersFile(t, dir, `[
	  {"id":"1","username":"linked-active","role":"user","active":true,"ssoSub":"sub-1"},
	  {"id":"2","username":"zoe-unlinked-active","role":"user","active":true},
	  {"id":"3","username":"unlinked-inactive","role":"user","active":false},
	  {"id":"4","username":"linked-inactive","role":"admin","active":false,"ssoSub":"sub-4"},
	  {"id":"5","username":"alice-unlinked-active","role":"admin","active":true}
	]`)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	got := UnlinkedActive(store)
	if len(got) != 2 {
		t.Fatalf("UnlinkedActive returned %d accounts, want 2: %+v", len(got), got)
	}
	// Sorted by username so an operator working through the list sees a stable order.
	if got[0].Username != "alice-unlinked-active" || got[1].Username != "zoe-unlinked-active" {
		t.Errorf("result is not sorted by username: %q, %q", got[0].Username, got[1].Username)
	}
}

func TestUnlinkedActiveIsEmptyOnAFullyMigratedStore(t *testing.T) {
	dir := t.TempDir()
	writeUsersFile(t, dir, `[
	  {"id":"1","username":"alice","role":"admin","active":true,"ssoSub":"sub-1"},
	  {"id":"2","username":"bob","role":"user","active":true,"ssoSub":"sub-2"}
	]`)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if got := UnlinkedActive(store); len(got) != 0 {
		t.Fatalf("UnlinkedActive = %+v, want none", got)
	}
}

func TestUnlinkedActiveIsEmptyOnAFreshInstall(t *testing.T) {
	// Nothing to migrate is not a migration failure; a new deployment must be able to start.
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if got := UnlinkedActive(store); len(got) != 0 {
		t.Fatalf("UnlinkedActive = %+v, want none", got)
	}
}
