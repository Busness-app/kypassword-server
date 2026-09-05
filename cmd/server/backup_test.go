package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kypassword-server/internal/backup"
)

func TestExportRestoreCLIWithSyntheticShares(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONFIG_DIR", filepath.Join(root, "config"))
	t.Setenv("DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("PAIRING_SECRET", "synthetic-sync-secret")
	offline, e := openOfflineBackup()
	if e != nil {
		t.Fatal(e)
	}
	defer offline.Close()
	key, e := recoverykey.Generate()
	if e != nil {
		t.Fatal(e)
	}
	if e := offline.service.State.Pin(backup.RecoveryKey{Public: key.Public(), Threshold: 2, TotalShares: 3}); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "test.kycap")
	var out bytes.Buffer
	if e := runExport(offline, []string{"--out", path}, &out); e != nil {
		t.Fatal(e)
	}
	shares, e := recoverykey.Split(key, 2, 3)
	if e != nil {
		t.Fatal(e)
	}
	input := shares[0].String() + "\n" + shares[2].String() + "\n"
	target := filepath.Join(root, "restored")
	out.Reset()
	if e := runRestore([]string{"--capsule", path, "--to", target}, strings.NewReader(input), &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Restored") || !strings.Contains(out.String(), "kypassword") {
		t.Fatal("missing authenticated summary")
	}
	for _, name := range []string{"config/users.json", "config/devices.json", "config/sso.json", "config/recovery.pub", "config/audit.key"} {
		if _, e := os.Stat(filepath.Join(target, name)); e != nil {
			t.Fatal(e)
		}
	}
	out.Reset()
	if e := runRestore([]string{"--capsule", path, "--to", target}, strings.NewReader(input), &out); e == nil {
		t.Fatal("nonempty target accepted")
	}
	if strings.Contains(out.String(), "Restored") {
		t.Fatal("failure printed success")
	}
	out.Reset()
	if e := runRestore([]string{"--capsule", path, "--to", filepath.Join(root, "short")}, strings.NewReader(shares[0].String()+"\n"), &out); e == nil {
		t.Fatal("insufficient shares accepted")
	}
}
