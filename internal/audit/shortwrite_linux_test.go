package audit

import (
	"bytes"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

// A full disk does not give a clean failure: the kernel writes what fits and reports a
// short write, so what lands on the end of the log is half a record. The reader stops
// there, and unless the append puts the file back the log is unreadable from that point
// while the server carries on writing into the part nobody can read.
//
// RLIMIT_FSIZE produces the short write without a full disk. It is process-wide, so it
// is lowered for one call and put straight back, and SIGXFSZ — which the kernel raises
// alongside the failure, and which would otherwise kill the test binary — is ignored
// for the duration.
func TestShortWriteLeavesNoTornLine(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store := loggedStore(t, dir, keyDir, 2)
	logPath := filepath.Join(dir, "audit.jsonl")

	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	// Room for a fraction of the next record, so the write is short rather than refused.
	capped := syscall.Rlimit{Cur: uint64(len(before)) + 20, Max: old.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &capped); err != nil {
		t.Skipf("cannot lower RLIMIT_FSIZE here: %v", err)
	}
	_, logErr := store.Log(t.Context(), "vault.saved", "user1", "dev1", "127.0.0.1", "the record that does not fit")
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("Setrlimit restore: %v", err)
	}

	if logErr == nil {
		t.Fatal("Log reported success for a record that could not be written")
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("a short write left %d bytes of a torn record on the end of the log", len(after)-len(before))
	}

	// The chain rolled back with the file, so the next record takes the sequence
	// number the failed one had and the log still reads end to end.
	if _, err := store.Log(t.Context(), "vault.saved", "user1", "dev1", "127.0.0.1", "after the disk came back"); err != nil {
		t.Fatalf("Log after a short write failed: %v", err)
	}
	if ok, err := store.VerifyIntegrity(); err != nil || !ok {
		t.Fatalf("VerifyIntegrity after a short write: ok=%v err=%v", ok, err)
	}
	entries, err := store.List(10)
	if err != nil || len(entries) != 3 {
		t.Fatalf("List returned %d entries, want 3 (err %v)", len(entries), err)
	}
}
