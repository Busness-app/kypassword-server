package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SSOSettings holds the OpenID Connect configuration.
type SSOSettings struct {
	Enabled       bool   `json:"enabled"`
	IssuerURL     string `json:"issuerUrl"`
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret,omitempty"`
	RedirectURI   string `json:"redirectUri,omitempty"`
	AutoProvision bool   `json:"autoProvision"`
}

// Store manages the persistence of SSOSettings to sso.json.
type Store struct {
	mu       sync.RWMutex
	filePath string
	settings SSOSettings
}

// NewStore initializes a new Store with settings loaded from configDir/sso.json.
func NewStore(configDir string) *Store {
	filePath := filepath.Join(configDir, "sso.json")
	s := &Store{filePath: filePath}
	_ = s.loadFromDisk()
	return s
}

func (s *Store) loadFromDisk() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var settings SSOSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	s.settings = settings
	return nil
}

// Load returns the current SSOSettings.
// Load returns the active settings. The environment takes precedence over sso.json when
// it configures SSO at all — see env.go for why it has to be able to.
func (s *Store) Load() SSOSettings {
	if fromEnv, ok := SettingsFromEnv(); ok {
		return fromEnv
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// Snapshot serializes the effective settings. Environment settings take
// precedence over a stale sso.json and must be recoverable from the sealed capsule.
func (s *Store) Snapshot() ([]byte, error) {
	return json.MarshalIndent(s.Load(), "", "  ")
}

// Save persists new SSOSettings to disk atomically.
func (s *Store) Save(settings SSOSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}

	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, s.filePath); err != nil {
		return err
	}

	s.settings = settings
	return nil
}

// OIDCDiscovery represents standard OpenID Connect discovery document.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// DiscoverEndpoints queries the OpenID configuration document from issuerURL.
func DiscoverEndpoints(ctx context.Context, issuerURL string) (*OIDCDiscovery, error) {
	issuerURL = strings.TrimRight(issuerURL, "/")
	wellKnownURL := issuerURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch openid-configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("openid-configuration returned status %d: %s", resp.StatusCode, string(body))
	}

	var disc OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decode openid-configuration: %w", err)
	}

	if disc.AuthorizationEndpoint == "" {
		disc.AuthorizationEndpoint = issuerURL + "/oauth/authorize"
	}
	if disc.TokenEndpoint == "" {
		disc.TokenEndpoint = issuerURL + "/oauth/token"
	}
	if disc.UserinfoEndpoint == "" {
		disc.UserinfoEndpoint = issuerURL + "/oauth/userinfo"
	}

	return &disc, nil
}

// GeneratePKCE creates a cryptographic code verifier and S256 code challenge.
func GeneratePKCE() (verifier string, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = hex.EncodeToString(buf)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// TokenResponse represents the OAuth 2.0 / OIDC token endpoint response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code for an ID token and access token.
func ExchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<18))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tok, nil
}

// Claims represents normalized user identity claims from an ID token or Userinfo.
type Claims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Role              string   `json:"role"`
	Groups            []string `json:"groups"`
}

// IsAdmin returns true if claims designate administrator privileges.
func (c *Claims) IsAdmin() bool {
	if strings.EqualFold(c.Role, "admin") || strings.EqualFold(c.Role, "administrator") {
		return true
	}
	for _, g := range c.Groups {
		if strings.EqualFold(g, "admin") || strings.EqualFold(g, "administrators") || strings.EqualFold(g, "kysecurity-admin") {
			return true
		}
	}
	return false
}

// ParseClaims extracts Claims from the ID token JWT payload and optional userinfo endpoint.
func ParseClaims(ctx context.Context, idToken, accessToken, userinfoEndpoint string) (*Claims, error) {
	var claims Claims

	if idToken != "" {
		parts := strings.Split(idToken, ".")
		if len(parts) >= 2 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				_ = json.Unmarshal(payload, &claims)
			}
		}
	}

	if (claims.Sub == "" || claims.PreferredUsername == "") && accessToken != "" && userinfoEndpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Accept", "application/json")
			client := &http.Client{Timeout: 10 * time.Second}
			if resp, err := client.Do(req); err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				var uClaims Claims
				if err := json.NewDecoder(resp.Body).Decode(&uClaims); err == nil {
					if claims.Sub == "" {
						claims.Sub = uClaims.Sub
					}
					if claims.PreferredUsername == "" {
						claims.PreferredUsername = uClaims.PreferredUsername
					}
					if claims.Email == "" {
						claims.Email = uClaims.Email
					}
				}
			}
		}
	}

	if claims.Sub == "" {
		return nil, errors.New("missing sub claim in identity token")
	}

	if claims.PreferredUsername == "" && claims.Email != "" {
		claims.PreferredUsername = strings.Split(claims.Email, "@")[0]
	}

	return &claims, nil
}
