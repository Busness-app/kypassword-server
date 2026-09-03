package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithUsers(t, "")
}

// newTestServerWithUsers seeds config/users.json before the server opens it, which is the
// only way to produce an account the current code cannot create — a legacy record with no
// KySignOn identity. Pass "" for a fresh install.
func newTestServerWithUsers(t *testing.T, usersJSON string) *Server {
	t.Helper()
	dir := t.TempDir()
	if usersJSON != "" {
		if err := os.MkdirAll(dir+"/config", 0700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(dir+"/config/users.json", []byte(usersJSON), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	srv, _ := newServerIn(t, dir)
	return srv
}

// newServerIn builds a server rooted at dir and hands back its data directory, which
// the tests that have to break the audit log need in order to find it.
func newServerIn(t *testing.T, dir string) (*Server, string) {
	t.Helper()
	srv, err := NewServer(Config{
		DataDir:       dir + "/data",
		ConfigDir:     dir + "/config",
		PairingSecret: "test-pairing-secret-123",
		RetentionDays: 90,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	// Stops the background audit flush before t.TempDir removes what it writes to.
	t.Cleanup(srv.Close)
	return srv, dir + "/data"
}

// signedInUser provisions an account the way KySignOn would and returns it with a session
// cookie. Sessions are only ever issued after an SSO login now, so tests start here.
func signedInUser(t *testing.T, srv *Server, username string, role users.Role) (users.User, *http.Cookie) {
	t.Helper()
	u, err := srv.users.CreateSSOUser(username, role, "sub-"+username, username, username+"@example.com")
	if err != nil {
		t.Fatalf("CreateSSOUser(%q): %v", username, err)
	}

	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), u.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypass_session" {
			return u, c
		}
	}
	t.Fatal("no session cookie was issued")
	return users.User{}, nil
}

func TestAuthenticatedSessionAndMe(t *testing.T) {
	// There is no login endpoint to drive; a session comes from the SSO callback, which
	// TestSSOCallbackStillMatchesOnSub covers end to end. This checks that a session,
	// once held, authenticates.
	srv := newTestServer(t)
	u, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/me status = %d", rec.Code)
	}

	var meResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&meResp)
	if meResp["authenticated"] != true {
		t.Errorf("expected authenticated=true in /api/auth/me: %+v", meResp)
	}
	if user, ok := meResp["user"].(map[string]any); !ok || user["id"] != u.ID {
		t.Errorf("unexpected user in /api/auth/me: %+v", meResp)
	}

	// Without the cookie the same route must refuse.
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/auth/me = %d, want 401", rec.Code)
	}
}

func TestVaultOperationsAndConflicts(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	_, sessCookie := signedInUser(t, srv, "bob", users.RoleUser)
	var rec *httptest.ResponseRecorder

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

	_, sessCookie := signedInUser(t, srv, "carol", users.RoleUser)
	var rec *httptest.ResponseRecorder

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

	_, sessCookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.AddCookie(sessCookie)
	rec := httptest.NewRecorder()
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

// A client that hangs up after the handler has already acted must not take its audit
// record with it. r.Context() dies the instant the connection does and handlers log
// last, so honouring that cancellation meant an aborted request left no trace at all,
// with the same HTTP status and a chain that still verified clean.
func TestAbortedRequestStillRecordsTheAudit(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is already gone
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil).WithContext(ctx)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/logout status = %d, want 200", rec.Code)
	}

	entries, err := srv.audit.List(0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	logged := false
	for _, e := range entries {
		if e.Action == "auth.logout" {
			logged = true
		}
	}
	if !logged {
		t.Fatalf("the aborted request logged out but left no audit record: %+v", entries)
	}
	if ok, err := srv.audit.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("audit chain does not verify: ok=%v, err=%v", ok, err)
	}
}

// A failed audit write must not vanish. This is a password vault: an instance that
// keeps accepting privileged operations while recording none of them is the state an
// attacker wants it in, and until now every call site discarded the error, so nothing
// said a word until a later restart refused to boot.
//
// The request still succeeds. The operation it is recording has already happened, so a
// 500 would not undo it — it would ask the client to retry something the server has
// already done, and the retry would be just as unrecorded. What changes is that the
// failure is reported: on stderr, in the health body, and to an admin asking whether
// the trail is sound.
//
// Health stays 200 in both states. A sticky counter wired to 503 is a credential vault
// that takes itself out of service for one transient write failure and stays there
// until a human restarts it; both status codes are asserted here so that trade is a
// decision rather than an accident.
//
// The audit log path is made a directory rather than the directory made read-only,
// because root writes into a read-only directory whatever its mode says. O_WRONLY on a
// directory is EISDIR for every uid, so this test has no skip.
func TestFailedAuditWriteIsReportedOnlyToAnAdmin(t *testing.T) {
	srv, dataDir := newServerIn(t, t.TempDir())
	_, cookie := signedInUser(t, srv, "dana", users.RoleAdmin)
	handler := srv.Routes()

	health := func() (int, string) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
		var body struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("health body %q: %v", rec.Body.String(), err)
		}
		return rec.Code, body.Status
	}
	if code, status := health(); code != http.StatusOK || status != "ok" {
		t.Fatalf(`GET /api/health = %d %q with a working audit log, want 200 "ok"`, code, status)
	}

	// A log the append cannot open, which a full or broken volume also produces. The
	// store is already constructed, so this is a write-time failure, not a boot one.
	logPath := filepath.Join(dataDir, "audit", "audit.jsonl")
	if err := os.RemoveAll(logPath); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.Mkdir(logPath, 0700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/logout = %d; the logout happened, so the client must not be told to retry it", rec.Code)
	}
	if !strings.Contains(logs.String(), "AUDIT WRITE FAILED") || !strings.Contains(logs.String(), "auth.logout") {
		t.Fatalf("a failed audit write left no line an operator could see: %q", logs.String())
	}
	// 200 still — a full audit volume must not become a credential lockout — and the
	// body must not have moved, because an anonymous caller reading a change here is
	// reading confirmation that the disk they are filling is full.
	if code, status := health(); code != http.StatusOK || status != "ok" {
		t.Fatalf(`GET /api/health = %d %q after an audit write failed, want an unchanged 200 "ok"`, code, status)
	}

	// And the admin asking whether the trail is sound is told, which VerifyIntegrity
	// alone cannot say: it only ever sees the records that were written.
	_, adminCookie := signedInUser(t, srv, "auditor", users.RoleAdmin)
	vreq := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	vreq.AddCookie(adminCookie)
	vrec := httptest.NewRecorder()
	handler.ServeHTTP(vrec, vreq)
	var verify struct {
		WriteFailures int64 `json:"writeFailures"`
	}
	if err := json.Unmarshal(vrec.Body.Bytes(), &verify); err != nil {
		t.Fatalf("verify body %q: %v", vrec.Body.String(), err)
	}
	if verify.WriteFailures == 0 {
		t.Fatalf("GET /api/audit/verify reported no lost records after a failed write: %s", vrec.Body.String())
	}
}
