package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

func TestOutcomePreservesOperatorActions(t *testing.T) {
	for _, tc := range []struct {
		err    error
		action string
	}{{nil, "backup.deposited"}, {recoveryclient.ErrRemote, "backup.deposit_failed"}} {
		action, _ := Outcome(recoveryclient.Result{}, tc.err)
		if action != tc.action {
			t.Fatalf("action = %s, want %s", action, tc.action)
		}
	}
}
func TestConfigFromEnvRejectsOverlap(t *testing.T) {
	root := t.TempDir()
	data, config := filepath.Join(root, "data"), filepath.Join(root, "config")
	t.Setenv("DATA_DIR", data)
	t.Setenv("CONFIG_DIR", config)
	if err := os.MkdirAll(data, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, config, filepath.Join(config, "copies"), filepath.Join(data, "vaults"), filepath.Join(data, "audit", "copies"), filepath.Join(data, "drill"), filepath.Join(alias, "vaults", "copies")} {
		t.Setenv("KYPASSWORD_BACKUP_DIR", path)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("accepted overlap %s", path)
		}
	}
	t.Setenv("KYPASSWORD_BACKUP_DIR", filepath.Join(root, "copies"))
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
}
func TestPairingLifecycleRefusesBusy(t *testing.T) {
	s := NewStateStore(t.TempDir())
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	for _, fn := range []func() error{s.Unpair, func() error { return s.Pin(RecoveryKey{}) }, func() error { return s.StorePairing("", "", RecoveryKey{}) }} {
		if err := fn(); !errors.Is(err, ErrDepositInProgress) {
			t.Fatalf("busy: %v", err)
		}
	}
}

func TestRecoveryAddressPolicyDelegatesToLibrary(t *testing.T) {
	for _, host := range []string{"https://203.0.113.5", "https://[2001:db8::5]", "https://recovery.example", "https://127.0.0.1", "https://10.0.0.1"} {
		for _, private := range []bool{false, true} {
			got, want := ValidateURL(host, private), recoveryclient.ValidateURL(host, private)
			if (got == nil) != (want == nil) {
				t.Fatalf("policy diverged: %s private=%t: %v / %v", host, private, got, want)
			}
		}
	}
}

func TestOutcomePreservesConfirmedDepositWithoutLocalReceipt(t *testing.T) {
	result := recoveryclient.Result{Receipt: &recoveryclient.Receipt{CapsuleID: "c"}}
	err := fmt.Errorf("%w: c", recoveryclient.ErrReceiptUnrecorded)
	action, details := Outcome(result, err)
	if action != "backup.deposited" || !strings.Contains(details, `"receipt_unrecorded"`) {
		t.Fatalf("confirmed deposit lost: %s %s", action, details)
	}
	result.LocalError = "local destination failed"
	if action, _ := Outcome(result, err); action != "backup.deposit_failed" {
		t.Fatalf("failed destination hidden: %s", action)
	}
}
