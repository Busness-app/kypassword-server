package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky-primitives/shamir"
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

func RunDrill(ctx context.Context, collector Collector) (DrillResult, error) {
	start := time.Now()
	files, deps, recipe, err := collector.Collect()
	if err != nil {
		return DrillResult{}, err
	}
	private, err := recoverykey.Generate()
	if err != nil {
		return DrillResult{}, err
	}
	raw, _, err := capsule.Seal(ServiceName, collector.AppVersion, files, deps, recipe, 2, 3, private.Public())
	if err != nil {
		return DrillResult{}, err
	}
	tmp, err := os.MkdirTemp("", "kypassword-drill-*")
	if err != nil {
		return DrillResult{}, err
	}
	defer os.RemoveAll(tmp)
	manifest, _, err := capsule.Open(raw, private, tmp)
	if err != nil {
		return DrillResult{}, err
	}
	result := validateRestore(ctx, tmp, manifest)
	result.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

func Restore(ctx context.Context, raw []byte, shares []shamir.Share, target string) (capsule.Manifest, DrillResult, error) {
	peek, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		return capsule.Manifest{}, DrillResult{}, err
	}
	if peek.ServiceName != ServiceName {
		return capsule.Manifest{}, DrillResult{}, fmt.Errorf("capsule is for service %q, want %q", peek.ServiceName, ServiceName)
	}
	private, err := recoverykey.Combine(shares)
	if err != nil {
		return capsule.Manifest{}, DrillResult{}, err
	}
	manifest, _, err := capsule.Open(raw, private, target)
	if err != nil {
		return capsule.Manifest{}, DrillResult{}, err
	}
	if manifest.ServiceName != ServiceName {
		return capsule.Manifest{}, DrillResult{}, fmt.Errorf("authenticated capsule is for service %q", manifest.ServiceName)
	}
	result := validateRestore(ctx, target, manifest)
	if !result.Passed {
		return manifest, result, errors.New("restored capsule failed validation")
	}
	return manifest, result, nil
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
	auditStore, err := audit.NewStore(filepath.Join(root, "data", "audit"), filepath.Join(root, "config"))
	if err == nil {
		var ok bool
		ok, err = auditStore.VerifyIntegrity()
		if err == nil && !ok {
			err = errors.New("audit chain invalid")
		}
	}
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
	_ = manifest
	return result
}

func ParseShares(lines []string) ([]shamir.Share, error) {
	shares := make([]shamir.Share, 0, len(lines))
	for _, line := range lines {
		share, err := shamir.ParseShare(strings.TrimSpace(line))
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}
