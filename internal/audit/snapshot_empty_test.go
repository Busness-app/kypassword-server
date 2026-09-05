package audit

import "testing"

// A never-used instance has an anchor of count 0 and no hash. Backups snapshot the chain
// before the first event exists, so the empty chain must verify.
func TestSnapshotOfEmptyChainVerifies(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("snapshot of empty chain: %v", err)
	}
	if len(snap.Log) != 0 {
		t.Fatalf("expected empty log, got %d bytes", len(snap.Log))
	}
}
