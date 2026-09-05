package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kypassword-server/internal/audit"
	"github.com/Busness-app/kypassword-server/internal/backup"
	"github.com/Busness-app/kypassword-server/internal/devices"
	"github.com/Busness-app/kypassword-server/internal/sso"
	kysync "github.com/Busness-app/kypassword-server/internal/sync"
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
	scimToken, err := kysync.LoadSCIMToken(configDir, os.Getenv("KYPASSWORD_SCIM_TOKEN"))
	if err != nil {
		return fail(err)
	}
	collector := backup.Collector{Vault: v, Audit: a, Users: u, Devices: d, SSO: sso.NewStore(configDir), State: state,
		PairingSecret: secret, SCIMToken: scimToken, RetentionDays: retention, AppVersion: buildVersion(), DataDir: dataDir}
	cfg, err := backup.ConfigFromEnv()
	if err != nil {
		return fail(err)
	}
	client := backup.NewClient(cfg.AllowPrivate)
	return &offlineBackup{service: &backup.Service{State: state, Collector: collector, Client: client, Config: cfg}, audit: a, lock: lock}, nil
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
		result, err := offline.service.Run(context.Background())
		action, details := backup.Outcome(result, err)
		_, auditErr := offline.audit.Log(context.Background(), action, "cli", "", "", details)
		if err != nil {
			return err
		}
		if auditErr != nil {
			return fmt.Errorf("deposit succeeded but audit failed: %w", auditErr)
		}
		json.NewEncoder(out).Encode(result)
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
	fmt.Fprintln(out, "Enter custodian shares, one per line; finish with EOF (Ctrl-D):")
	shares, err := recoveryclient.ReadShares(in)
	if err != nil {
		return err
	}
	var message bytes.Buffer
	if err := recoveryclient.Restore(*capsulePath, *target, backup.ServiceName, shares, &message); err != nil {
		return err
	}
	if err := backup.ValidateRestored(*target); err != nil {
		return err
	}
	_, err = io.Copy(out, &message)
	return err
}
