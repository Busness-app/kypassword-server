package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kypassword-server/internal/audit"
	"github.com/Busness-app/kypassword-server/internal/devices"
	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
	"github.com/Busness-app/kypassword-server/internal/vault"
)

func generatedKey(t *testing.T) (recoverykey.PrivateKey, RecoveryKey) {
	t.Helper()
	private, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return private, RecoveryKey{Public: private.Public(), Threshold: 2, TotalShares: 3}
}

func TestPairingSealsTokenAndPinsKey(t *testing.T) {
	dir := t.TempDir()
	store := NewStateStore(dir)
	_, key := generatedKey(t)
	const token = "do-not-store-this-token-in-cleartext"
	if err := store.StorePairing("https://recovery.example", token, key); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(token)) {
		t.Fatal("pairing state contains the plaintext token")
	}
	pairing, err := store.LoadPairing()
	if err != nil || pairing.Token != token || pairing.Key.Public.ID() != key.Public.ID() {
		t.Fatalf("LoadPairing = %+v, %v", pairing, err)
	}
	_, other := generatedKey(t)
	if err := store.StorePairing("https://recovery.example", "other", other); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("different key pairing error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPairing(); !errors.Is(err, ErrKeyPinMissing) {
		t.Fatalf("missing recovery.pub error = %v", err)
	}
}

func testCollector(t *testing.T) Collector {
	t.Helper()
	root := t.TempDir()
	configDir, dataDir := filepath.Join(root, "config"), filepath.Join(root, "data")
	u, err := users.NewStore(configDir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := devices.NewStore(configDir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewStore(filepath.Join(dataDir, "vaults"), 90)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.NewStore(filepath.Join(dataDir, "audit"), configDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Log(t.Context(), "test", "user", "", "", "seed"); err != nil {
		t.Fatal(err)
	}
	user, err := u.CreateSSOUser("alice", users.RoleAdmin, "sub-alice", "alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.SaveVault(user.ID, 0, []byte("encrypted-kdbx"), "sealed-envelope", "", "test"); err != nil {
		t.Fatal(err)
	}
	ssoStore := sso.NewStore(configDir)
	if err := ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://signon.example", ClientID: "kypassword", ClientSecret: "sealed-inside-capsule"}); err != nil {
		t.Fatal(err)
	}
	return Collector{Vault: v, Audit: a, Users: u, Devices: d, SSO: ssoStore,
		State: NewStateStore(configDir), DataDir: dataDir, PairingSecret: "replication-secret", RetentionDays: 90, AppVersion: "test"}
}

type openingDepositor struct {
	t       *testing.T
	private recoverykey.PrivateKey
}

func (d openingDepositor) Deposit(_ context.Context, _, _ string, raw []byte) (Receipt, error) {
	d.t.Helper()
	manifest, files, err := capsule.Open(raw, d.private, "")
	if err != nil {
		d.t.Fatalf("test-held private key did not open deposit: %v", err)
	}
	if len(files) < 9 {
		d.t.Fatalf("capsule has only %d files", len(files))
	}
	sum := sha256.Sum256(raw)
	return Receipt{CapsuleID: manifest.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw)), DepositedAt: time.Now()}, nil
}

func TestDepositAndRestoreDrillRoundTrip(t *testing.T) {
	collector := testCollector(t)
	private, key := generatedKey(t)
	if err := collector.State.StorePairing("https://recovery.example", "secret-token", key); err != nil {
		t.Fatal(err)
	}
	service := Service{State: collector.State, Collector: collector, Client: openingDepositor{t: t, private: private}}
	result, err := service.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.CapsuleID != result.Manifest.CapsuleID {
		t.Fatal("receipt and manifest capsule IDs differ")
	}
	drill, err := RunDrill(t.Context(), collector)
	if err != nil || !drill.Passed {
		t.Fatalf("RunDrill = %+v, %v", drill, err)
	}
}

func TestRecoveryURLPolicy(t *testing.T) {
	for _, value := range []string{
		"http://recovery.example", "https://user@recovery.example", "https://recovery.example?q=x",
		"https://recovery.example/#fragment", "https://127.0.0.1", "https://100.64.0.1",
		"https://192.0.2.1", "https://[64:ff9b::a00:1]",
	} {
		if err := ValidateURL(value, false); err == nil {
			t.Errorf("endpoint accepted %q", value)
		}
	}
	if err := ValidateURL("https://recovery.example", false); err != nil {
		t.Fatalf("public HTTPS origin rejected: %v", err)
	}
}

type mismatchedDepositor struct{}

func (mismatchedDepositor) Deposit(context.Context, string, string, []byte) (Receipt, error) {
	return Receipt{CapsuleID: "wrong", Digest: "wrong", SizeBytes: 1}, nil
}

func TestDepositRejectsMismatchedReceiptCapsule(t *testing.T) {
	collector := testCollector(t)
	_, key := generatedKey(t)
	if err := collector.State.StorePairing("https://recovery.example", "token", key); err != nil {
		t.Fatal(err)
	}
	service := Service{State: collector.State, Collector: collector, Client: mismatchedDepositor{}}
	if _, err := service.Run(t.Context()); !errors.Is(err, ErrRemote) {
		t.Fatalf("mismatched receipt error = %v", err)
	}
}

func TestDecryptGuard(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	guardtest.NoDecryptOutside(t, root, map[string][]string{"cmd/server/backup.go": {"runRestore"}})
}
