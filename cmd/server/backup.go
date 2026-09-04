package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kypassword-server/internal/audit"
	"github.com/Busness-app/kypassword-server/internal/backup"
	"github.com/Busness-app/kypassword-server/internal/devices"
	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
	"github.com/Busness-app/kypassword-server/internal/vault"
)

type offlineBackup struct {
	service *backup.Service
	audit   *audit.Store
	lock    *instanceLock
}

func openOfflineBackup() (*offlineBackup, error) {
	configDir := configDirFromEnv()
	lock, err := acquireInstanceLock(configDir)
	if err != nil {
		return nil, fmt.Errorf("stop the daemon or use the admin backup controls: %w", err)
	}
	fail := func(err error) (*offlineBackup, error) { lock.Close(); return nil, err }
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	retention := 90
	if raw := os.Getenv("RETENTION_DAYS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			retention = n
		}
	}
	secret := os.Getenv("PAIRING_SECRET")
	if secret == "" {
		b, err := os.ReadFile(filepath.Join(configDir, "pairing.secret"))
		if err != nil {
			return fail(fmt.Errorf("read pairing secret: %w", err))
		}
		secret = string(b)
	}
	u, err := users.NewStore(configDir)
	if err != nil {
		return fail(err)
	}
	v, err := vault.NewStore(filepath.Join(dataDir, "vaults"), retention)
	if err != nil {
		return fail(err)
	}
	d, err := devices.NewStore(configDir)
	if err != nil {
		return fail(err)
	}
	a, err := audit.NewStore(filepath.Join(dataDir, "audit"), configDir)
	if err != nil {
		return fail(err)
	}
	state := backup.NewStateStore(configDir)
	collector := backup.Collector{Vault: v, Audit: a, Users: u, Devices: d, SSO: sso.NewStore(configDir), State: state,
		PairingSecret: secret, RetentionDays: retention, AppVersion: buildVersion()}
	client := backup.NewClient()
	return &offlineBackup{service: &backup.Service{State: state, Collector: collector, Client: client}, audit: a, lock: lock}, nil
}

func (o *offlineBackup) Close() { _ = o.lock.Close() }

func runBackupCommand(command string, args []string, out io.Writer) error {
	if command == "restore" {
		return runRestore(args, os.Stdin, out)
	}
	offline, err := openOfflineBackup()
	if err != nil {
		return err
	}
	defer offline.Close()
	switch command {
	case "backup-drill":
		result, err := backup.RunDrill(context.Background(), offline.service.Collector)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Restore drill passed: %t (%d ms)\n", result.Passed, result.DurationMS)
		for _, check := range result.Checks {
			fmt.Fprintf(out, "- %s: %s\n", check.Name, check.Message)
		}
		return nil
	case "export-capsule":
		return runExport(offline, args, out)
	case "deposit":
		receipt, manifest, err := offline.service.Deposit(context.Background())
		action, _, details := backup.Outcome(receipt, manifest, err)
		_, auditErr := offline.audit.Log(context.Background(), action, "cli", "", "", details)
		if err != nil {
			return err
		}
		if auditErr != nil {
			return fmt.Errorf("deposit succeeded but audit failed: %w", auditErr)
		}
		fmt.Fprintf(out, "Deposited %s (%d bytes), digest %s\n", receipt.CapsuleID, receipt.SizeBytes, receipt.Digest)
		return nil
	}
	return errors.New("unknown backup command")
}

func runExport(offline *offlineBackup, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("export-capsule", flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("out", "", "output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := offline.service.State.RecoveryKey()
	if err != nil {
		return err
	}
	files, deps, recipe, err := offline.service.Collector.Collect()
	if err != nil {
		return err
	}
	raw, manifest, err := backup.Seal(files, deps, recipe, offline.service.Collector.AppVersion, key)
	if err != nil {
		return err
	}
	if *path == "" {
		*path = backup.FilenameSafe(manifest.CapsuleID) + ".kycap"
	}
	file, err := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := offline.audit.Log(context.Background(), "backup.exported", "cli", "", "", "capsule="+manifest.CapsuleID); err != nil {
		file.Close()
		_ = os.Remove(*path)
		return fmt.Errorf("refusing export because audit failed: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		_ = os.Remove(*path)
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Wrote %s (%d bytes)\n", *path, len(raw))
	return nil
}

func runRestore(args []string, in io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(out)
	capsulePath := flags.String("capsule", "", "path to .kycap")
	target := flags.String("to", "", "empty restore directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *capsulePath == "" || *target == "" {
		return errors.New("restore requires --capsule and --to")
	}
	raw, err := os.ReadFile(*capsulePath)
	if err != nil {
		return err
	}
	peek, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		return err
	}
	if peek.ServiceName != backup.ServiceName || peek.Threshold < 2 || peek.Threshold > 255 {
		return fmt.Errorf("capsule manifest is not a valid %s recovery capsule", backup.ServiceName)
	}
	fmt.Fprintf(out, "Enter %d custodian shares, one per line:\n", peek.Threshold)
	scanner := bufio.NewScanner(in)
	lines := make([]string, 0, peek.Threshold)
	for len(lines) < peek.Threshold && scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(lines) != peek.Threshold {
		return fmt.Errorf("received %d shares, need %d", len(lines), peek.Threshold)
	}
	shares, err := backup.ParseShares(lines)
	if err != nil {
		return err
	}
	manifest, _, err := backup.Restore(context.Background(), raw, shares, *target)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Restored %s created %s (version %s, key %s, payload %s)\n",
		manifest.CapsuleID, manifest.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), manifest.AppVersion, manifest.RecoveryKeyID, manifest.PayloadHash)
	return nil
}
