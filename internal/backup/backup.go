package backup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kypassword-server/internal/audit"
	"github.com/Busness-app/kypassword-server/internal/devices"
	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
	"github.com/Busness-app/kypassword-server/internal/vault"
)

type Collector struct {
	Vault         *vault.Store
	Audit         *audit.Store
	Users         *users.Store
	Devices       *devices.Store
	SSO           *sso.Store
	State         *StateStore
	PairingSecret string
	RetentionDays int
	AppVersion    string
}

func (c Collector) Collect() ([]capsule.File, map[string]any, map[string]any, error) {
	if c.Vault == nil || c.Audit == nil || c.Users == nil || c.Devices == nil || c.SSO == nil || c.State == nil || c.PairingSecret == "" {
		return nil, nil, nil, errors.New("backup: collector is missing a required source")
	}
	userData, err := c.Users.Snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	deviceData, err := c.Devices.Snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	ssoData, err := c.SSO.Snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	auditData, err := c.Audit.Snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	vaultFiles, err := c.Vault.Snapshot()
	if err != nil {
		return nil, nil, nil, err
	}

	manifest, _ := json.MarshalIndent(map[string]any{
		"service": ServiceName, "appVersion": c.AppVersion, "retentionDays": c.RetentionDays,
		"vaultDecryptionKey": "not held by server; restore verifies ciphertext checksums only",
	}, "", "  ")
	files := []capsule.File{
		{Path: "config/users.json", Content: userData, Mode: 0600},
		{Path: "config/devices.json", Content: deviceData, Mode: 0600},
		{Path: "config/sso.json", Content: ssoData, Mode: 0600},
		{Path: "config/pairing.secret", Content: []byte(c.PairingSecret), Mode: 0600},
		{Path: "config/audit.key", Content: []byte(hex.EncodeToString(auditData.Key)), Mode: 0600},
		{Path: "config/audit.state", Content: auditData.State, Mode: 0600},
		{Path: "data/audit/audit.jsonl", Content: auditData.Log, Mode: 0600},
		{Path: "config/restore-manifest.json", Content: manifest, Mode: 0600},
	}
	for _, file := range vaultFiles {
		files = append(files, capsule.File{Path: "data/vaults/" + file.Path, Content: file.Data, Mode: file.Mode})
	}
	stateFiles, err := c.State.CapsuleFiles()
	if err != nil {
		return nil, nil, nil, err
	}
	files = append(files, stateFiles...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	seen := make(map[string]struct{}, len(files))
	required := make([]string, 0, len(files))
	for _, file := range files {
		if _, exists := seen[file.Path]; exists {
			return nil, nil, nil, fmt.Errorf("backup: duplicate member %s", file.Path)
		}
		seen[file.Path] = struct{}{}
		required = append(required, file.Path)
	}
	deps := map[string]any{"data_dir": "data", "config_dir": "config"}
	recipe := map[string]any{"required_files": required, "verify_audit_chain": true, "verify_vault_checksums": true}
	return files, deps, recipe, nil
}

func Seal(files []capsule.File, deps, recipe map[string]any, version string, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	if key.Public.IsZero() {
		return nil, capsule.Manifest{}, ErrNotPaired
	}
	return capsule.Seal(ServiceName, version, files, deps, recipe, key.Threshold, key.TotalShares, key.Public)
}

func FilenameSafe(value string) string {
	var out []rune
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			out = append(out, r)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

type Service struct {
	State     *StateStore
	Collector Collector
	Client    Depositor
	mu        sync.Mutex
	wg        sync.WaitGroup
}

func (s *Service) Deposit(ctx context.Context) (Receipt, capsule.Manifest, error) {
	if !s.mu.TryLock() {
		return Receipt{}, capsule.Manifest{}, ErrDepositInProgress
	}
	s.wg.Add(1)
	defer func() { s.wg.Done(); s.mu.Unlock() }()
	pairing, err := s.State.LoadPairing()
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	files, deps, recipe, err := s.Collector.Collect()
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	raw, manifest, err := Seal(files, deps, recipe, s.Collector.AppVersion, pairing.Key)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	receipt, err := s.Client.Deposit(ctx, pairing.URL, pairing.Token, raw)
	if err != nil {
		return Receipt{}, manifest, err
	}
	if receipt.CapsuleID != manifest.CapsuleID {
		return Receipt{}, manifest, fmt.Errorf("%w: receipt names capsule %s, sent %s", ErrRemote, receipt.CapsuleID, manifest.CapsuleID)
	}
	if err := s.State.SaveReceipt(receipt); err != nil {
		return receipt, manifest, fmt.Errorf("%w: %v", ErrReceiptUnrecorded, err)
	}
	return receipt, manifest, nil
}

func (s *Service) Wait() { s.wg.Wait() }

func Outcome(receipt Receipt, manifest capsule.Manifest, err error) (action, resource, details string) {
	switch {
	case err == nil:
		return "backup.deposited", receipt.CapsuleID, "digest=" + receipt.Digest
	case errors.Is(err, ErrReceiptUnrecorded):
		return "backup.deposited", receipt.CapsuleID, AuditSafe("digest=" + receipt.Digest + " receipt_unrecorded: " + err.Error())
	default:
		return "backup.deposit_failed", manifest.CapsuleID, AuditSafe(err.Error())
	}
}
