package backup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"sort"
	"sync"
	"time"

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
	DataDir       string
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

func payload(files []capsule.File, deps, recipe map[string]any, version string) recoveryclient.Payload {
	p := recoveryclient.Payload{ServiceName: ServiceName, AppVersion: version, Dependencies: deps, VerificationRecipe: recipe}
	for _, f := range files {
		p.Files = append(p.Files, recoveryclient.File{Path: f.Path, Data: f.Content, Mode: int64(f.Mode)})
	}
	return p
}
func (c Collector) Payload() (recoveryclient.Payload, error) {
	f, d, r, e := c.Collect()
	return payload(f, d, r, c.AppVersion), e
}
func Seal(files []capsule.File, deps, recipe map[string]any, version string, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	return recoveryclient.Seal(payload(files, deps, recipe, version), key)
}
func FilenameSafe(s string) string { return recoveryclient.FilenameSafe(s) }

type RunSummary struct {
	At         time.Time `json:"at"`
	CapsuleID  string    `json:"capsuleId,omitempty"`
	LocalPath  string    `json:"localPath,omitempty"`
	LocalError string    `json:"localError,omitempty"`
	Deposited  bool      `json:"deposited"`
	Error      string    `json:"error,omitempty"`
}
type Config struct {
	Directory    string
	Keep         int
	AllowPrivate bool
	Interval     time.Duration
}
type Service struct {
	State     *StateStore
	Collector Collector
	Client    Depositor
	Config    Config
	mu        sync.Mutex
}

func (s *Service) Run(ctx context.Context) (recoveryclient.Result, error) {
	if !s.mu.TryLock() {
		return recoveryclient.Result{}, ErrDepositInProgress
	}
	defer s.mu.Unlock()
	if !s.State.operationMu.TryLock() {
		return recoveryclient.Result{}, ErrDepositInProgress
	}
	defer s.State.operationMu.Unlock()
	// Stamp even degraded attempts so the scheduler does not retry every tick.
	if _, err := s.State.RecoveryKey(); err != nil && !errors.Is(err, ErrNotPaired) {
		if e := s.State.Set("backup_last_attempt", time.Now().UTC().Format(time.RFC3339)); e != nil {
			return recoveryclient.Result{}, e
		}
		return recoveryclient.Result{}, s.saveRun(recoveryclient.Result{}, err)
	}
	result, err := recoveryclient.Run(ctx, recoveryclient.RunConfig{DataDir: s.State.dir, AppName: ServiceName,
		AppVersion: s.Collector.AppVersion, BackupDir: s.Config.Directory, Keep: s.Config.Keep, Sealer: tokenSealer{s.State}}, s.State, s.Collector.Payload, s.Client)
	return result, s.saveRun(result, err)
}
func (s *Service) saveRun(r recoveryclient.Result, runErr error) error {
	summary := RunSummary{At: time.Now().UTC(), CapsuleID: AuditSafe(r.Manifest.CapsuleID), LocalPath: AuditSafe(r.LocalPath), LocalError: AuditSafe(r.LocalError), Deposited: r.Receipt != nil}
	if runErr != nil {
		summary.Error = AuditSafe(runErr.Error())
	}
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	st, err := s.State.loadLocked()
	if err == nil {
		st.LastRun = &summary
		err = s.State.saveLocked(st)
	}
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("backup result could not be recorded: %w", err))
	}
	return runErr
}
func (s *Service) Wait() { s.mu.Lock(); s.mu.Unlock() }
func Outcome(r recoveryclient.Result, err error) (string, string) {
	_, outcome, details := recoveryclient.Outcome(r, err)
	action := "backup.deposited"
	if (err != nil && !errors.Is(err, recoveryclient.ErrReceiptUnrecorded)) || r.LocalError != "" {
		action = "backup.deposit_failed"
	}
	details["outcome"] = outcome
	b, _ := json.Marshal(details)
	return action, string(b)
}
