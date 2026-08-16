package vault

import (
	"bytes"
	"io"
	"testing"
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
