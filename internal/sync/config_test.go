package sync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSCIMTokenRestoreAndOverride(t *testing.T) {
	dir := t.TempDir()
	if token, err := LoadSCIMToken(dir, ""); err != nil || token != "" {
		t.Fatal("missing token should disable provisioning")
	}
	restored := strings.Repeat("restored-token-", 3)
	if err := os.WriteFile(filepath.Join(dir, "scim.token"), []byte(restored), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := LoadSCIMToken(dir, ""); err != nil || token != restored {
		t.Fatal("restored token not loaded")
	}
	override := strings.Repeat("override-token-", 3)
	if token, err := LoadSCIMToken(dir, override); err != nil || token != override {
		t.Fatal("deployment token not preferred")
	}
	for _, invalid := range []string{"short", strings.Repeat("x", 513), strings.Repeat("x", 40) + "\n"} {
		if _, err := LoadSCIMToken(dir, invalid); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}
