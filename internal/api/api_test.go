package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypassword-server/internal/sso"
	"kypassword-server/internal/users"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	srv, err := NewServer(Config{
		DataDir:       dir + "/data",
		ConfigDir:     dir + "/config",
		PairingSecret: "test-pairing-secret-123",
		RetentionDays: 90,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	return srv
}

func TestServerSetupAndAuth(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	// 1. Check Setup: should be required initially
	req := httptest.NewRequest(http.MethodGet, "/api/setup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/setup status = %d", rec.Code)
	}
	var setupResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&setupResp)
	if setupResp["setupRequired"] != true {
		t.Fatalf("expected setupRequired = true, got: %+v", setupResp)
	}

	// 2. Initialize Setup
	initBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin-super-password",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(initBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/setup status = %d", rec.Code)
	}

	// Subsequent setup should be forbidden
	req = httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(initBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("second POST /api/setup status = %d, want 403", rec.Code)
	}

	// 3. Login
	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin-super-password",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/login status = %d", rec.Code)
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypass_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected kypass_session cookie after login")
	}

	// 4. Authenticated /api/auth/me
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/me status = %d", rec.Code)
	}

	var meResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&meResp)
	if meResp["authenticated"] != true {
		t.Errorf("expected authenticated=true in /api/auth/me: %+v", meResp)
	}
}

func TestVaultOperationsAndConflicts(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	// Create user & log in
	u, _ := srv.users.Create("bob", "bob-password-123", users.RoleUser)
	rec := httptest.NewRecorder()
	_ = srv.startSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), u.ID)
	sessCookie := rec.Result().Cookies()[0]

	// 1. Initial vault upload
	v1Payload, _ := json.Marshal(VaultUploadRequest{
		ExpectedVersion:  0,
		KdbxBase64:       "ENCRYPTED-KDBX-V1",
		PasswordEnvelope: "pw-env-v1",
		RecoveryEnvelope: "rec-env-v1",
		DeviceID:         "chrome-ext",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader(v1Payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/vault/upload v1 status = %d", rec.Code)
	}

	// 2. Download vault
	req = httptest.NewRequest(http.MethodGet, "/api/vault/kdbx", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vault/kdbx status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "ENCRYPTED-KDBX-V1" {
		t.Errorf("download mismatch: %s", string(body))
	}
	if rec.Header().Get("ETag") != "\"1\"" {
		t.Errorf("expected ETag \"1\", got: %s", rec.Header().Get("ETag"))
	}

	// 3. Stale upload conflict (expectedVersion = 0 instead of 1)
	vStalePayload, _ := json.Marshal(VaultUploadRequest{
		ExpectedVersion: 0,
		KdbxBase64:      "ENCRYPTED-KDBX-STALE",
		DeviceID:        "phone-app",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader(vStalePayload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected conflict status 409, got %d", rec.Code)
	}

	// 4. List conflicts
	req = httptest.NewRequest(http.MethodGet, "/api/vault/conflicts", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vault/conflicts status = %d", rec.Code)
	}
}

func TestDevicePairingFlow(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	u, _ := srv.users.Create("carol", "carol-password-123", users.RoleUser)
	rec := httptest.NewRecorder()
	_ = srv.startSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), u.ID)
	sessCookie := rec.Result().Cookies()[0]

	// 1. User initiates pairing in UI
	req := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/start", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/pairing/start status = %d", rec.Code)
	}

	var pairInit map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&pairInit)
	pin := pairInit["pin"].(string)

	// 2. Client redeems PIN
	redeemBody, _ := json.Marshal(PairingRedeemRequest{
		CodeOrPIN:      pin,
		DeviceName:     "Carol's iPhone",
		Platform:       "ios",
		DeviceEnvelope: "ios-wrapped-key-123",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem", bytes.NewReader(redeemBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/pairing/redeem status = %d", rec.Code)
	}

	var redeemResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&redeemResp)
	if redeemResp["deviceId"] == "" || redeemResp["sessionToken"] == "" {
		t.Errorf("unexpected redeem response: %+v", redeemResp)
	}

	// 3. User lists devices
	req = httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/devices status = %d", rec.Code)
	}
}

func TestSSOCallbackAutoProvisions(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	// Mock OIDC IdP
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/oauth/authorize",
				"token_endpoint":         "http://" + r.Host + "/oauth/token",
				"userinfo_endpoint":      "http://" + r.Host + "/oauth/userinfo",
			})
		case "/oauth/token":
			payload := map[string]any{
				"sub":                "kysignon-sub-999",
				"email":              "dave@urlxl.com",
				"preferred_username": "dave",
				"role":               "admin",
			}
			payloadBytes, _ := json.Marshal(payload)
			idToken := "header." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".sig"

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-token",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()

	_ = srv.ssoStore.Save(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     idp.URL,
		ClientID:      "kypassword-app",
		AutoProvision: true,
	})

	// 1. SSO Login redirect
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /api/auth/oidc/login status = %d, want 302", rec.Code)
	}

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	state := stateCookie.Value[:32]

	// 2. SSO Callback
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/auth/oidc/callback?code=mock_code&state=%s", state), nil)
	req.AddCookie(stateCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /api/auth/oidc/callback status = %d, want 302", rec.Code)
	}

	// Verify Dave was auto-provisioned
	dave, err := srv.users.GetBySSOSub("kysignon-sub-999")
	if err != nil || dave.Username != "dave" || dave.Role != users.RoleAdmin {
		t.Errorf("dave auto-provision mismatch: %+v, err: %v", dave, err)
	}

}

func TestAuditLogIntegrity(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	admin, _ := srv.users.Create("admin", "admin-pw", users.RoleAdmin)
	rec := httptest.NewRecorder()
	_ = srv.startSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), admin.ID)
	sessCookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/audit/verify status = %d", rec.Code)
	}

	var verifyResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&verifyResp)
	if verifyResp["valid"] != true {
		t.Errorf("expected valid audit chain: %+v", verifyResp)
	}
}
