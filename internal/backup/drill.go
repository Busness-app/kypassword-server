package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kypassword-server/internal/audit"
	"github.com/Busness-app/kypassword-server/internal/vault"
)

type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type DrillResult struct {
	Passed     bool    `json:"passed"`
	DurationMS int64   `json:"durationMs"`
	Checks     []Check `json:"checks"`
	Error      string  `json:"error,omitempty"`
}

var drillMu sync.Mutex

func RunDrill(ctx context.Context, collector Collector) (DrillResult, error) {
	drillMu.Lock()
	defer drillMu.Unlock()
	p, err := collector.Payload()
	if err != nil {
		return DrillResult{}, err
	}
	if collector.DataDir == "" {
		return DrillResult{}, recoveryclient.ErrNoScratchRoot
	}
	root := filepath.Join(collector.DataDir, "drill")
	if err := os.MkdirAll(root, 0700); err != nil {
		return DrillResult{}, err
	}
	r, err := recoveryclient.Drill(ctx, root, p, func(dir string, m capsule.Manifest) []recoveryclient.Check {
		result := validateRestore(ctx, dir, m)
		checks := make([]recoveryclient.Check, 0, len(result.Checks))
		for _, c := range result.Checks {
			checks = append(checks, recoveryclient.Check{Name: c.Name, Passed: c.Passed, Message: c.Message})
		}
		return checks
	})
	if err != nil {
		return DrillResult{}, err
	}
	result := DrillResult{Passed: r.Passed, DurationMS: r.DurationMs, Error: r.ErrorMessage}
	for _, c := range r.Checks {
		result.Checks = append(result.Checks, Check{Name: c.Name, Passed: c.Passed, Message: c.Message})
	}
	return result, nil
}

// ValidateRestored checks product invariants after the library authenticates/extracts a capsule.
func ValidateRestored(root string) error {
	r := validateRestore(context.Background(), root, capsule.Manifest{})
	for _, c := range r.Checks {
		if !c.Passed {
			return fmt.Errorf("restored capsule failed validation: %s: %s", c.Name, c.Message)
		}
	}
	return nil
}

func validateRestore(_ context.Context, root string, manifest capsule.Manifest) DrillResult {
	result := DrillResult{Passed: true}
	add := func(name string, err error) {
		check := Check{Name: name, Passed: err == nil, Message: "ok"}
		if err != nil {
			check.Message = err.Error()
			result.Passed = false
		}
		result.Checks = append(result.Checks, check)
	}
	for _, path := range []string{"config/users.json", "config/devices.json", "config/sso.json", "config/restore-manifest.json"} {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err == nil && !json.Valid(b) {
			err = errors.New("invalid JSON")
		}
		add(path, err)
	}
	for _, path := range []string{"config/pairing.secret", "config/audit.key", "config/audit.state", "data/audit/audit.jsonl"} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
		if err == nil && !info.Mode().IsRegular() {
			err = errors.New("not a regular file")
		}
		add(path, err)
	}
	err := verifyRestoredAudit(root)
	add("audit chain", err)

	err = filepath.WalkDir(filepath.Join(root, "data", "vaults"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "metadata.json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var meta vault.Metadata
		if err := json.Unmarshal(b, &meta); err != nil {
			return err
		}
		if meta.Version == 0 {
			return nil
		}
		ciphertext, err := os.ReadFile(filepath.Join(filepath.Dir(path), "vault.kdbx"))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(ciphertext)
		if hex.EncodeToString(sum[:]) != meta.Checksum || int64(len(ciphertext)) != meta.SizeBytes {
			return fmt.Errorf("vault %s checksum or size mismatch", meta.UserID)
		}
		return nil
	})
	add("encrypted vault checksums", err)
	add("zero-knowledge boundary", nil)
	result.Checks[len(result.Checks)-1].Message = "server holds no vault decryption key; ciphertext integrity verified"
	if manifest.ServiceName != "" {
		add("verification recipe", validateRecipe(root, manifest.VerificationRecipe))
	}
	return result
}

func validateRecipe(root string, raw any) error {
	recipe, ok := raw.(map[string]any)
	if !ok {
		return errors.New("invalid verification recipe")
	}
	required, ok := recipe["required_files"].([]any)
	if !ok || len(required) == 0 {
		return errors.New("missing required_files list")
	}
	for _, key := range []string{"verify_audit_chain", "verify_vault_checksums"} {
		if recipe[key] != true {
			return fmt.Errorf("%s must be true", key)
		}
	}
	seen := map[string]bool{}
	for _, item := range required {
		path, ok := item.(string)
		if !ok || !fs.ValidPath(path) || filepath.IsAbs(path) || strings.Contains(path, "\\") {
			return errors.New("invalid required file path")
		}
		if seen[path] {
			return errors.New("duplicate required file")
		}
		seen[path] = true
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("required file is not regular")
		}
	}
	for _, path := range []string{"config/users.json", "config/devices.json", "config/sso.json", "config/restore-manifest.json", "config/pairing.secret", "config/audit.key", "config/audit.state", "data/audit/audit.jsonl"} {
		if !seen[path] {
			return fmt.Errorf("recipe omits %s", path)
		}
	}
	return nil
}

func verifyRestoredAudit(root string) error {
	key, err := os.ReadFile(filepath.Join(root, "config", "audit.key"))
	if err != nil {
		return err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(key)))
	if err != nil {
		return err
	}
	state, err := os.ReadFile(filepath.Join(root, "config", "audit.state"))
	if err != nil {
		return err
	}
	log, err := os.ReadFile(filepath.Join(root, "data", "audit", "audit.jsonl"))
	if err != nil {
		return err
	}
	return audit.VerifySnapshot(audit.Snapshot{Key: decoded, State: state, Log: log})
}
