package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSOSettingsPersistence(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	orig := store.Load()
	if orig.Enabled {
		t.Errorf("expected default disabled SSO, got enabled")
	}

	newSettings := SSOSettings{
		Enabled:       true,
		IssuerURL:     "https://auth.urlxl.com",
		ClientID:      "kypasswords",
		ClientSecret:  "secret-xyz",
		AutoProvision: true,
	}

	if err := store.Save(newSettings); err != nil {
		t.Fatalf("store.Save failed: %v", err)
	}

	reloadedStore := NewStore(dir)
	loaded := reloadedStore.Load()
	if !loaded.Enabled || loaded.IssuerURL != "https://auth.urlxl.com" || loaded.ClientID != "kypasswords" {
		t.Errorf("loaded settings mismatch: %+v", loaded)
	}
}

func TestOIDCDiscoveryAndExchange(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "https://" + r.Host,
				"authorization_endpoint": "https://" + r.Host + "/oauth/authorize",
				"token_endpoint":         "https://" + r.Host + "/oauth/token",
				"userinfo_endpoint":      "https://" + r.Host + "/oauth/userinfo",
			})
		case "/oauth/token":
			payload := map[string]any{
				"sub":                "sso-sub-12345",
				"email":              "admin@urlxl.com",
				"preferred_username": "superadmin",
				"role":               "admin",
			}
			payloadBytes, _ := json.Marshal(payload)
			idToken := "header." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".sig"

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-access-token",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	disc, err := DiscoverEndpoints(ctx, server.URL, server.Client())
	if err != nil {
		t.Fatalf("DiscoverEndpoints failed: %v", err)
	}

	tok, err := ExchangeCode(ctx, disc.TokenEndpoint, "client123", "secret123", "auth_code_xyz", "http://callback", "verifier_xyz", server.Client())
	if err != nil {
		t.Fatalf("ExchangeCode failed: %v", err)
	}

	if tok.IDToken == "" || tok.AccessToken != "mock-access-token" {
		t.Fatal("exchange lost tokens")
	}
}
