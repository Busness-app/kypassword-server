package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

func TestLegacyPairingSurvivesLibraryWritesAndRestart(t *testing.T) {
	dir := t.TempDir()
	original := map[string][]byte{}
	for _, name := range []string{stateFile, publicKeyFile, tokenKeyFile} {
		b, e := os.ReadFile(filepath.Join("testdata/legacy-pairing", name))
		if e != nil {
			t.Fatal(e)
		}
		original[name] = b
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	s := NewStateStore(dir)
	before, e := s.LoadPairing()
	if e != nil || before.Token != "synthetic-legacy-token" {
		t.Fatalf("legacy load: %v", e)
	}
	st, e := s.loadLocked()
	if e != nil {
		t.Fatal(e)
	}
	token := st.SealedToken
	if e := recoveryclient.SetInterval(s, 900); e != nil {
		t.Fatal(e)
	}
	receipt := Receipt{CapsuleID: "new-receipt", Digest: "new-digest", DepositedAt: time.Now().UTC()}
	if e := s.SaveReceipt(receipt); e != nil {
		t.Fatal(e)
	}
	s = NewStateStore(dir)
	after, e := s.LoadPairing()
	if e != nil || after.Token != before.Token || after.URL != before.URL || after.Key.Public.ID() != before.Key.Public.ID() || after.Key.Threshold != 2 || after.Key.TotalShares != 3 {
		t.Fatalf("restart lost pairing: %v", e)
	}
	st, e = s.loadLocked()
	if e != nil || st.SealedToken != token || st.LastDeposit.CapsuleID != receipt.CapsuleID {
		t.Fatal("state changed unexpectedly")
	}
	for _, name := range []string{publicKeyFile, tokenKeyFile} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		if !bytes.Equal(b, original[name]) {
			t.Fatalf("%s changed", name)
		}
	}
	if e := os.Remove(s.tokenPath()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.LoadPairing(); e == nil {
		t.Fatal("missing token key accepted")
	}
	if _, e := os.Stat(s.tokenPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("open recreated token key")
	}
	status, e := s.Status()
	if e != nil || status.Error == "" {
		t.Fatal("missing token key not visible")
	}
}

type recordingDepositor struct {
	raw  []byte
	fail bool
}

func (d *recordingDepositor) Deposit(_ context.Context, _, _ string, raw []byte) (Receipt, error) {
	d.raw = bytes.Clone(raw)
	if d.fail {
		return Receipt{}, errors.New("destination unavailable")
	}
	m, e := capsule.ReadUnverifiedManifest(raw)
	if e != nil {
		return Receipt{}, e
	}
	sum := sha256.Sum256(raw)
	return Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw)), DepositedAt: time.Now()}, nil
}
func TestLocalAndRemoteDeliveryUseSameCapsuleAndRetainState(t *testing.T) {
	c := testCollector(t)
	private, key := generatedKey(t)
	if e := c.State.Pin(key); e != nil {
		t.Fatal(e)
	}
	local := t.TempDir()
	d := &recordingDepositor{}
	svc := Service{State: c.State, Collector: c, Client: d, Config: Config{Directory: local, Keep: 1, Interval: time.Hour}}
	r, e := svc.Run(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if r.LocalPath == "" || r.Receipt != nil {
		t.Fatal("bad local-only result")
	}
	if _, e := os.Stat(c.State.tokenPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("pin created a token key")
	}
	b, e := os.ReadFile(r.LocalPath)
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(t.TempDir(), "restored")
	m, _, e := capsule.Open(b, private, target)
	if e != nil {
		t.Fatal(e)
	}
	if e := ValidateRestored(target); e != nil {
		t.Fatal(e)
	}
	if e := validateRecipe(target, m.VerificationRecipe); e != nil {
		t.Fatal(e)
	}
	// The restored audit is checked using its own key even when the live environment differs.
	t.Setenv("AUDIT_KEY", strings.Repeat("09", 32))
	if e := ValidateRestored(target); e != nil {
		t.Fatal(e)
	}
	if e := c.State.StorePairing("https://recovery.example", "synthetic", key); e != nil {
		t.Fatal(e)
	}
	r, e = svc.Run(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(r.LocalPath)
	if !bytes.Equal(b, d.raw) {
		t.Fatal("destinations received different containers")
	}
	info, _ := os.Stat(r.LocalPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("local mode")
	}
	copies, e := recoveryclient.ListLocalCopies(local, ServiceName)
	if e != nil || len(copies) != 1 {
		t.Fatal("retention failed")
	}
	d.fail = true
	r, e = svc.Run(t.Context())
	if e == nil || r.LocalPath == "" {
		t.Fatal("partial success lost")
	}
	status, e := svc.Status()
	if e != nil || status.LastRun == nil || status.LastRun.LocalPath == "" || status.LastRun.Error == "" {
		t.Fatal("partial result not persisted")
	}
	next, ok, e := recoveryclient.NextRun(time.Hour, c.State)
	if e != nil || !ok || time.Until(next) < 59*time.Minute {
		t.Fatal("failure retries too soon")
	}
	if e := c.State.Unpair(); e != nil {
		t.Fatal(e)
	}
	status, e = svc.Status()
	if e != nil || status.Paired || !status.KeyHealthy || status.LastDeposit == nil {
		t.Fatal("unpair removed pin or receipt")
	}
	if _, e := svc.Run(t.Context()); e != nil {
		t.Fatal(e)
	}
}
func TestSettingsPresenceAndFailureArePreserved(t *testing.T) {
	s := NewStateStore(t.TempDir())
	if _, e := s.Get("backup_interval_sec"); !errors.Is(e, recoveryclient.ErrNotFound) {
		t.Fatal(e)
	}
	if e := s.Set("backup_interval_sec", ""); e != nil {
		t.Fatal(e)
	}
	if v, e := s.Get("backup_interval_sec"); e != nil || v != "" {
		t.Fatal("empty is missing")
	}
	if _, e := recoveryclient.Interval(time.Hour, s); e == nil {
		t.Fatal("invalid interval accepted")
	}
	if e := s.Delete("backup_interval_sec"); e != nil {
		t.Fatal(e)
	}
	if e := s.Delete("backup_interval_sec"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(s.statePath()+".tmp", 0700); e != nil {
		t.Fatal(e)
	}
	if e := recoveryclient.SetInterval(s, 900); e == nil {
		t.Fatal("write failure ignored")
	}
	if _, e := s.Get("backup_interval_sec"); !errors.Is(e, recoveryclient.ErrNotFound) {
		t.Fatal("failed write changed state")
	}
}
func TestMalformedRecipeFailsClosed(t *testing.T) {
	c := testCollector(t)
	p, e := c.Payload()
	if e != nil {
		t.Fatal(e)
	}
	for _, recipe := range []any{nil, map[string]any{}, map[string]any{"required_files": []any{42}}, map[string]any{"required_files": []any{"../secret"}, "verify_audit_chain": true, "verify_vault_checksums": true}} {
		if e := validateRecipe(t.TempDir(), recipe); e == nil {
			t.Fatalf("accepted %v", recipe)
		}
	}
	p.VerificationRecipe["verify_audit_chain"] = false
	r, e := recoveryclient.Drill(t.Context(), t.TempDir(), p, func(root string, m capsule.Manifest) []recoveryclient.Check {
		e := validateRecipe(root, m.VerificationRecipe)
		return []recoveryclient.Check{{Name: "recipe", Passed: e == nil}}
	})
	if e != nil || r.Passed {
		t.Fatal("malformed recipe passed drill")
	}
}
func TestDecryptGuardRejectsProbe(t *testing.T) {
	if root := os.Getenv("KYPASSWORD_GUARD_PROBE"); root != "" {
		guardtest.NoDecryptOutside(t, root, nil)
		return
	}
	dir := t.TempDir()
	for i := 0; i < guardtest.MinFiles; i++ {
		body := "package probe\n"
		if i == 0 {
			body += "import \"github.com/Busness-app/ky-primitives/capsule\"\nfunc bad(){capsule.Open(nil,nil,\"\")}\n"
		}
		if e := os.WriteFile(filepath.Join(dir, "probe"+strconv.Itoa(i)+".go"), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDecryptGuardRejectsProbe$")
	cmd.Env = append(os.Environ(), "KYPASSWORD_GUARD_PROBE="+dir)
	output, e := cmd.CombinedOutput()
	if e == nil || !bytes.Contains(output, []byte("capsule.Open")) {
		t.Fatalf("guard did not detect probe: %v %s", e, output)
	}
}
