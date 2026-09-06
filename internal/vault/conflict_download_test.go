package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConflictPathsStayWithinOwnerDirectory(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("owner", 0, []byte("current"), "", "", "web"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", ".", "..", "../vault", "../../other/vault", `..\vault`, "bad\x00id"} {
		if file, err := store.OpenConflict("owner", id); !errors.Is(err, ErrNotFound) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("accepted %q: %v", id, err)
		}
		if err := store.DiscardConflict("owner", id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("discard accepted %q: %v", id, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside.kdbx")
	if err := os.WriteFile(outside, []byte("must not be served"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store.conflictsDir("owner"), "link.kdbx")); err != nil {
		t.Fatal(err)
	}
	if file, err := store.OpenConflict("owner", "link"); err == nil {
		file.Close()
		t.Fatal("followed escaping symlink")
	}
}
