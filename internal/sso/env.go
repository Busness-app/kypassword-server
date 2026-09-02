package sso

import (
	"os"
	"strings"
)

// Environment-sourced configuration exists because there is no local administrator who
// could configure SSO through the UI, and no way to become one: an admin arrives by
// signing in through KySignOn, which needs SSO configured first. Reading it from the
// environment breaks that deadlock.
const (
	EnvIssuer        = "KYPASSWORD_OIDC_ISSUER"
	EnvClientID      = "KYPASSWORD_OIDC_CLIENT_ID"
	EnvClientSecret  = "KYPASSWORD_OIDC_CLIENT_SECRET"
	EnvRedirectURI   = "KYPASSWORD_OIDC_REDIRECT_URI"
	EnvAutoProvision = "KYPASSWORD_OIDC_AUTO_PROVISION"
)

// SettingsFromEnv reads the identity provider from the environment. It reports false
// unless issuer, client ID and client secret are all present: a half-set environment is a
// misconfiguration, and merging it with the disk settings would produce a configuration
// neither source describes.
func SettingsFromEnv() (SSOSettings, bool) {
	issuer := strings.TrimSpace(os.Getenv(EnvIssuer))
	clientID := strings.TrimSpace(os.Getenv(EnvClientID))
	clientSecret := os.Getenv(EnvClientSecret)

	if issuer == "" || clientID == "" || clientSecret == "" {
		return SSOSettings{}, false
	}

	return SSOSettings{
		Enabled:      true,
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  strings.TrimSpace(os.Getenv(EnvRedirectURI)),
		// KySignOn is the directory: someone it authenticates is entitled to a vault, and
		// with local account creation gone there is no interactive way to grant one.
		AutoProvision: boolFromEnv(EnvAutoProvision, true),
	}, true
}

// EnvSourced reports whether the environment is configuring SSO, so the admin API can
// refuse a write the next restart would discard.
func (s *Store) EnvSourced() bool {
	_, ok := SettingsFromEnv()
	return ok
}

func boolFromEnv(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return fallback
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
