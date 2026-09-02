package sso

import "testing"

func setOIDCEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{
		"KYPASSWORD_OIDC_ISSUER",
		"KYPASSWORD_OIDC_CLIENT_ID",
		"KYPASSWORD_OIDC_CLIENT_SECRET",
		"KYPASSWORD_OIDC_REDIRECT_URI",
		"KYPASSWORD_OIDC_AUTO_PROVISION",
	} {
		t.Setenv(k, kv[k])
	}
}

func TestSettingsFromEnvNeedsAllThreeRequiredValues(t *testing.T) {
	// A half-set environment is a misconfiguration, not a partial override. Falling back
	// to disk on some values and the environment on others would give an operator a
	// configuration neither file describes.
	full := map[string]string{
		"KYPASSWORD_OIDC_ISSUER":        "https://signon.example",
		"KYPASSWORD_OIDC_CLIENT_ID":     "kypassword",
		"KYPASSWORD_OIDC_CLIENT_SECRET": "s3cret",
	}
	for _, missing := range []string{"KYPASSWORD_OIDC_ISSUER", "KYPASSWORD_OIDC_CLIENT_ID", "KYPASSWORD_OIDC_CLIENT_SECRET"} {
		partial := map[string]string{}
		for k, v := range full {
			partial[k] = v
		}
		partial[missing] = ""

		setOIDCEnv(t, partial)
		if _, ok := SettingsFromEnv(); ok {
			t.Errorf("environment without %s should not configure SSO", missing)
		}
	}

	setOIDCEnv(t, map[string]string{})
	if _, ok := SettingsFromEnv(); ok {
		t.Error("an empty environment should not configure SSO")
	}
}

func TestSettingsFromEnvDefaultsAutoProvisionOn(t *testing.T) {
	// KySignOn is the directory. Someone it authenticates is entitled to a vault, and
	// with local account creation gone there is no other way to grant one interactively.
	setOIDCEnv(t, map[string]string{
		"KYPASSWORD_OIDC_ISSUER":        "https://signon.example",
		"KYPASSWORD_OIDC_CLIENT_ID":     "kypassword",
		"KYPASSWORD_OIDC_CLIENT_SECRET": "s3cret",
	})

	got, ok := SettingsFromEnv()
	if !ok {
		t.Fatal("SettingsFromEnv should have configured SSO")
	}
	if !got.Enabled {
		t.Error("env-sourced settings must be enabled")
	}
	if !got.AutoProvision {
		t.Error("AutoProvision should default to true")
	}
	if got.IssuerURL != "https://signon.example" || got.ClientID != "kypassword" || got.ClientSecret != "s3cret" {
		t.Errorf("unexpected settings: %+v", got)
	}
}

func TestSettingsFromEnvAutoProvisionCanBeTurnedOff(t *testing.T) {
	for _, off := range []string{"false", "0", "no", "off", "FALSE"} {
		setOIDCEnv(t, map[string]string{
			"KYPASSWORD_OIDC_ISSUER":         "https://signon.example",
			"KYPASSWORD_OIDC_CLIENT_ID":      "kypassword",
			"KYPASSWORD_OIDC_CLIENT_SECRET":  "s3cret",
			"KYPASSWORD_OIDC_AUTO_PROVISION": off,
		})
		got, ok := SettingsFromEnv()
		if !ok {
			t.Fatalf("%q: SettingsFromEnv should have configured SSO", off)
		}
		if got.AutoProvision {
			t.Errorf("KYPASSWORD_OIDC_AUTO_PROVISION=%q should disable auto-provisioning", off)
		}
	}
}

func TestLoadPrefersTheEnvironmentOverDisk(t *testing.T) {
	dir := t.TempDir()
	setOIDCEnv(t, map[string]string{})

	store := NewStore(dir)
	onDisk := SSOSettings{
		Enabled:      true,
		IssuerURL:    "https://stale.example",
		ClientID:     "stale-client",
		ClientSecret: "stale-secret",
		RedirectURI:  "https://stale.example/cb",
	}
	if err := store.Save(onDisk); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// With no environment, disk wins.
	if got := store.Load(); got.IssuerURL != "https://stale.example" {
		t.Fatalf("without env, Load() = %+v, want the disk settings", got)
	}

	setOIDCEnv(t, map[string]string{
		"KYPASSWORD_OIDC_ISSUER":        "https://signon.example",
		"KYPASSWORD_OIDC_CLIENT_ID":     "kypassword",
		"KYPASSWORD_OIDC_CLIENT_SECRET": "s3cret",
		"KYPASSWORD_OIDC_REDIRECT_URI":  "https://vault.example/api/auth/oidc/callback",
	})

	got := store.Load()
	if got.IssuerURL != "https://signon.example" || got.ClientID != "kypassword" || got.ClientSecret != "s3cret" {
		t.Errorf("environment did not take precedence: %+v", got)
	}
	if got.RedirectURI != "https://vault.example/api/auth/oidc/callback" {
		t.Errorf("RedirectURI = %q", got.RedirectURI)
	}

	// A store opened fresh from the same directory reads the environment too.
	if got := NewStore(dir).Load(); got.IssuerURL != "https://signon.example" {
		t.Errorf("a fresh store ignored the environment: %+v", got)
	}
}

func TestEnvSourcedReportsWhereSettingsCameFrom(t *testing.T) {
	// The admin API needs this to refuse a write it would silently discard on restart.
	dir := t.TempDir()
	setOIDCEnv(t, map[string]string{})
	store := NewStore(dir)
	if store.EnvSourced() {
		t.Error("EnvSourced should be false with no environment set")
	}

	setOIDCEnv(t, map[string]string{
		"KYPASSWORD_OIDC_ISSUER":        "https://signon.example",
		"KYPASSWORD_OIDC_CLIENT_ID":     "kypassword",
		"KYPASSWORD_OIDC_CLIENT_SECRET": "s3cret",
	})
	if !store.EnvSourced() {
		t.Error("EnvSourced should be true once the environment configures SSO")
	}
}
