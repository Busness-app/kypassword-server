package vault

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVaultStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 90)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	userID := "user_test_123"

	// 1. Initial vault save (v1)
	v1Data := []byte("KDBX-V4-ENCRYPTED-PAYLOAD-V1")
	meta1, err := store.SaveVault(userID, 0, v1Data, "enc_pw_env_1", "enc_rec_env_1", "desktop-chrome")
	if err != nil {
		t.Fatalf("SaveVault v1 failed: %v", err)
	}
	if meta1.Version != 1 || meta1.SizeBytes != int64(len(v1Data)) {
		t.Errorf("unexpected meta1: %+v", meta1)
	}

	// 2. Open vault and verify content
	rc, readMeta, err := store.OpenVault(userID)
	if err != nil {
		t.Fatalf("OpenVault failed: %v", err)
	}
	defer rc.Close()
	readBytes, _ := io.ReadAll(rc)
	if !bytes.Equal(readBytes, v1Data) || readMeta.Version != 1 {
		t.Errorf("read bytes mismatch: got %s", string(readBytes))
	}

	// 3. Save v2 with expectedVersion = 1
	v2Data := []byte("KDBX-V4-ENCRYPTED-PAYLOAD-V2")
	meta2, err := store.SaveVault(userID, 1, v2Data, "enc_pw_env_2", "", "mobile-android")
	if err != nil {
		t.Fatalf("SaveVault v2 failed: %v", err)
	}
	if meta2.Version != 2 {
		t.Errorf("expected version 2, got %d", meta2.Version)
	}

	// 4. Test Conflict Handling: Attempt save with stale version (expectedVersion = 1 instead of 2)
	vConflictData := []byte("KDBX-V4-CONFLICT-DATA")
	_, err = store.SaveVault(userID, 1, vConflictData, "", "", "laptop-firefox")
	if err == nil {
		t.Fatalf("expected conflict error, got nil")
	}
	confErr, ok := err.(*ConflictError)
	if !ok {
		t.Fatalf("expected *ConflictError, got %T: %v", err, err)
	}
	if confErr.CurrentVersion != 2 || confErr.ExpectedVersion != 1 {
		t.Errorf("unexpected ConflictError fields: %+v", confErr)
	}

	// Check conflicts list
	conflicts, err := store.ListConflicts(userID)
	if err != nil || len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict entry, got %d (err: %v)", len(conflicts), err)
	}

	// 5. Test History List and Rollback
	history, err := store.ListHistory(userID)
	if err != nil || len(history) != 1 {
		t.Fatalf("expected 1 history entry, got %d (err: %v)", len(history), err)
	}

	meta3, err := store.RestoreHistory(userID, history[0].ID)
	if err != nil {
		t.Fatalf("RestoreHistory failed: %v", err)
	}
	if meta3.Version != 3 {
		t.Errorf("expected rollback version 3, got %d", meta3.Version)
	}

	// 6. Device Envelope management
	err = store.SetDeviceEnvelope(userID, DeviceEnvelope{
		DeviceID: "device_abc",
		Name:     "Pixel 8",
		Envelope: "dev_envelope_blob_xyz",
	})
	if err != nil {
		t.Fatalf("SetDeviceEnvelope failed: %v", err)
	}

	m, _ := store.GetMetadata(userID)
	if _, ok := m.DeviceEnvelopes["device_abc"]; !ok {
		t.Fatalf("expected device_abc in DeviceEnvelopes")
	}

	err = store.RemoveDeviceEnvelope(userID, "device_abc")
	if err != nil {
		t.Fatalf("RemoveDeviceEnvelope failed: %v", err)
	}
	m, _ = store.GetMetadata(userID)
	if _, ok := m.DeviceEnvelopes["device_abc"]; ok {
		t.Fatalf("expected device_abc removed")
	}
}

func TestHistoryCountBoundOnSaveAndRollback(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 100
	for version := int64(0); version < limit+5; version++ {
		if _, err := store.SaveVault("user", version, []byte("encrypted"), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	history, err := store.ListHistory("user")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != limit {
		t.Fatalf("history count = %d, want %d", len(history), limit)
	}
	var oldest, newest bool
	for _, entry := range history {
		oldest = oldest || entry.Version == 1
		newest = newest || entry.Version == limit+4
	}
	if !oldest || !newest {
		t.Fatal("count pruning must retain the oldest and newest snapshots")
	}
	if _, err := store.RestoreHistory("user", history[0].ID); err != nil {
		t.Fatal(err)
	}
	history, err = store.ListHistory("user")
	if err != nil || len(history) != limit {
		t.Fatalf("rollback history count = %d, err = %v", len(history), err)
	}
}

func TestHistoryAgeRetention(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	for version := int64(0); version < 2; version++ {
		if _, err := store.SaveVault("user", version, []byte("encrypted"), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	history, err := store.ListHistory("user")
	if err != nil || len(history) != 1 {
		t.Fatalf("history = %v, err = %v", history, err)
	}
	old := filepath.Join(store.historyDir("user"), history[0].ID+".kdbx")
	expired := time.Now().AddDate(0, 0, -91)
	if err := os.Chtimes(old, expired, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("user", 2, []byte("new encrypted"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expired snapshot still exists: %v", err)
	}
	history, err = store.ListHistory("user")
	if err != nil || len(history) != 1 || history[0].Version != 2 {
		t.Fatalf("recent history = %v, err = %v", history, err)
	}
}

func TestHistoryCapPreservesTimeCoverage(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("user", 0, []byte("encrypted"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 150; i++ {
		path := filepath.Join(store.historyDir("user"), fmt.Sprintf("seed_%03d.kdbx", i))
		if err := os.WriteFile(path, []byte("old encrypted"), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-time.Duration(i+1) * 60 * 24 * time.Hour / 150)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	// A burst of writes must not displace the pre-session recovery window.
	for version := int64(1); version <= 150; version++ {
		if _, err := store.SaveVault("user", version, []byte("session encrypted"), "", "", ""); err != nil {
			t.Fatal(err)
		}
		history, err := store.ListHistory("user")
		if err != nil {
			t.Fatal(err)
		}
		if len(history) > 100 || len(history) == 0 {
			t.Fatalf("history count = %d", len(history))
		}
		if !history[len(history)-1].Timestamp.Before(now.AddDate(0, 0, -30)) {
			t.Fatalf("write %d erased old history", version)
		}
		// Require more than one token old snapshot: maintain coverage in each 15-day band.
		var bands [4]bool
		for _, h := range history {
			band := int(now.Sub(h.Timestamp) / (15 * 24 * time.Hour))
			if band >= 0 && band < len(bands) {
				bands[band] = true
			}
		}
		for band, covered := range bands {
			if !covered {
				t.Fatalf("write %d erased time band %d", version, band)
			}
		}
	}
}
