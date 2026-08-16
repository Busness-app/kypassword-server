package devices

import (
	"testing"
	"time"
)

func TestDevicesPairingAndRevoke(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	userID := "usr_123"

	// 1. Create pairing session
	sess, err := store.CreatePairingSession(userID)
	if err != nil {
		t.Fatalf("CreatePairingSession failed: %v", err)
	}
	if len(sess.PIN) != 6 || sess.Secret == "" {
		t.Errorf("unexpected session format: %+v", sess)
	}

	// 2. Redeem using PIN
	dev, err := store.RedeemPairing(sess.PIN, "Chrome Extension", "chrome", "192.168.1.50")
	if err != nil {
		t.Fatalf("RedeemPairing PIN failed: %v", err)
	}
	if dev.UserID != userID || dev.Name != "Chrome Extension" || dev.Platform != "chrome" {
		t.Errorf("unexpected redeemed device: %+v", dev)
	}

	// Reusing same PIN should fail
	if _, err := store.RedeemPairing(sess.PIN, "Pixel 8", "android", "127.0.0.1"); err != ErrPairingExpired {
		t.Errorf("expected ErrPairingExpired on consumed PIN, got: %v", err)
	}

	// 3. Redeem using QR Secret
	sess2, _ := store.CreatePairingSession(userID)
	dev2, err := store.RedeemPairing(sess2.Secret, "Pixel 8 Pro", "android", "10.0.0.5")
	if err != nil {
		t.Fatalf("RedeemPairing Secret failed: %v", err)
	}
	if dev2.Name != "Pixel 8 Pro" {
		t.Errorf("unexpected device: %+v", dev2)
	}

	// 4. List User Devices
	list := store.ListUserDevices(userID)
	if len(list) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(list))
	}

	// 5. Touch
	store.Touch(dev.ID, "192.168.1.55")
	d1, _ := store.Get(dev.ID)
	if d1.LastIP != "192.168.1.55" {
		t.Errorf("expected updated LastIP, got: %s", d1.LastIP)
	}

	// 6. Revoke
	err = store.Revoke(dev.ID)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	if _, err := store.Get(dev.ID); err != ErrNotFound {
		t.Errorf("expected ErrNotFound for revoked device, got: %v", err)
	}
	if len(store.ListUserDevices(userID)) != 1 {
		t.Errorf("expected 1 remaining device")
	}

	// 7. Test expiration
	sess3, _ := store.CreatePairingSession(userID)
	store.mu.Lock()
	sOld := store.pairingPINs[sess3.PIN]
	sOld.ExpiresAt = time.Now().Add(-10 * time.Minute)
	store.pairingPINs[sess3.PIN] = sOld
	store.mu.Unlock()

	if _, err := store.RedeemPairing(sess3.PIN, "Old Phone", "android", "1.1.1.1"); err != ErrPairingExpired {
		t.Errorf("expected ErrPairingExpired on expired PIN, got: %v", err)
	}
}
