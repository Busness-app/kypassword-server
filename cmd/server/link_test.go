package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kypassword-server/internal/users"
)

func seedUsers(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

func reopen(t *testing.T, dir string) *users.Store {
	t.Helper()
	store, err := users.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestLinkSSOBindsAnAccountToItsSubject(t *testing.T) {
	dir := seedUsers(t, `[{"id":"u1","username":"alice","role":"admin","active":true}]`)

	var out bytes.Buffer
	if err := runLinkSSO(dir, []string{"--username", "alice", "--sub", "kysignon-1"}, &out); err != nil {
		t.Fatalf("runLinkSSO: %v", err)
	}
	if !strings.Contains(out.String(), "kysignon-1") {
		t.Errorf("output does not say what changed: %q", out.String())
	}

	// Reopen from disk: the change has to be durable, not just in memory.
	u, err := reopen(t, dir).GetBySSOSub("kysignon-1")
	if err != nil {
		t.Fatalf("GetBySSOSub after reopen: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("linked account = %q, want alice", u.Username)
	}
	if got := users.UnlinkedActive(reopen(t, dir)); len(got) != 0 {
		t.Errorf("account should no longer block startup: %+v", got)
	}
}

func TestLinkSSORefusesASubjectAlreadyLinkedElsewhere(t *testing.T) {
	// Two accounts sharing one KySignOn identity is exactly the duplication this
	// migration exists to prevent.
	dir := seedUsers(t, `[
	  {"id":"u1","username":"alice","role":"admin","active":true,"ssoSub":"kysignon-1"},
	  {"id":"u2","username":"bob","role":"user","active":true}
	]`)

	var out bytes.Buffer
	err := runLinkSSO(dir, []string{"--username", "bob", "--sub", "kysignon-1"}, &out)
	if err == nil {
		t.Fatal("expected the duplicate subject to be refused")
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error should name the account holding the subject: %v", err)
	}

	store := reopen(t, dir)
	if bob, _ := store.GetByUsername("bob"); bob.SSOSub != "" {
		t.Errorf("bob was linked anyway: %q", bob.SSOSub)
	}
	if alice, _ := store.GetBySSOSub("kysignon-1"); alice.Username != "alice" {
		t.Errorf("alice lost her subject: %+v", alice)
	}
}

func TestLinkSSORequiresBothFlags(t *testing.T) {
	dir := seedUsers(t, `[{"id":"u1","username":"alice","role":"admin","active":true}]`)
	for _, args := range [][]string{
		{"--username", "alice"},
		{"--sub", "kysignon-1"},
		{},
	} {
		var out bytes.Buffer
		if err := runLinkSSO(dir, args, &out); err == nil {
			t.Errorf("args %v should have been refused", args)
		}
	}
}

func TestLinkSSORejectsAnUnknownUsername(t *testing.T) {
	dir := seedUsers(t, `[{"id":"u1","username":"alice","role":"admin","active":true}]`)
	var out bytes.Buffer
	if err := runLinkSSO(dir, []string{"--username", "nobody", "--sub", "kysignon-9"}, &out); err == nil {
		t.Fatal("expected an unknown username to be refused")
	}
}

func TestDeactivateRetiresAnAccountAndIsIdempotent(t *testing.T) {
	dir := seedUsers(t, `[{"id":"u1","username":"alice","role":"admin","active":true}]`)

	var out bytes.Buffer
	if err := runDeactivate(dir, []string{"--username", "alice"}, &out); err != nil {
		t.Fatalf("runDeactivate: %v", err)
	}
	if u, _ := reopen(t, dir).GetByUsername("alice"); u.Active {
		t.Fatal("alice is still active")
	}
	if got := users.UnlinkedActive(reopen(t, dir)); len(got) != 0 {
		t.Errorf("account should no longer block startup: %+v", got)
	}

	// Running it twice must not be an error: an operator re-running the migration should
	// not have to remember which accounts they already handled.
	out.Reset()
	if err := runDeactivate(dir, []string{"--username", "alice"}, &out); err != nil {
		t.Fatalf("second runDeactivate: %v", err)
	}
	if !strings.Contains(out.String(), "already inactive") {
		t.Errorf("output should say it was a no-op: %q", out.String())
	}
}

func TestDeactivateRequiresAUsername(t *testing.T) {
	dir := seedUsers(t, `[{"id":"u1","username":"alice","role":"admin","active":true}]`)
	var out bytes.Buffer
	if err := runDeactivate(dir, []string{}, &out); err == nil {
		t.Fatal("expected a missing --username to be refused")
	}
}

func TestRunMigrationCommandOnlyClaimsItsOwnSubcommands(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{nil, {}, {"--port", "8080"}, {"serve"}} {
		handled, err := runMigrationCommand(args, &out)
		if handled || err != nil {
			t.Errorf("args %v: handled = %v, err = %v; want the server to start normally", args, handled, err)
		}
	}
}
