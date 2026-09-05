package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/syncauth"
	"github.com/Busness-app/kypassword-server/internal/sso"
)

func TestOIDCCallbackRejectsUnverifiedClaims(t *testing.T) {
	cases := map[string]map[string]any{
		"signature": {"__bad_signature": true}, "unsigned": {"__alg": "none"}, "HS256": {"__alg": "HS256"},
		"issuer": {"iss": "https://other.example"}, "audience": {"aud": "other-client"},
		"expired": {"exp": time.Now().Add(-time.Hour).Unix()}, "future": {"iat": time.Now().Add(time.Hour).Unix()},
		"unknown key": {"__kid": "unknown"}, "missing nonce": {"nonce": nil}, "wrong nonce": {"nonce": "wrong"},
		"missing token": {"__missing_token": true}, "invalid role shape": {"role": []string{"admin"}},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTestServer(t)
			claims := map[string]any{"sub": "forged-subject", "preferred_username": "mallory", "role": "admin"}
			for k, v := range overrides {
				claims[k] = v
			}
			idp := mockIdP(t, claims)
			srv.oidcHTTP = idp.Client()
			if e := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app", AutoProvision: true}); e != nil {
				t.Fatal(e)
			}
			rec := driveSSOCallback(t, srv)
			if rec.Code != http.StatusUnauthorized || hasSessionCookie(rec) || len(srv.users.List()) != 0 {
				t.Fatalf("unverified login mutated state: %d", rec.Code)
			}
		})
	}
}

func beginOIDCTest(t *testing.T, srv *Server) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/oidc/login", nil))
	if w.Code != 302 {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	location, e := url.Parse(w.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == ssoCookieName {
			cookie = c
		}
	}
	if cookie == nil || location.Query().Get("nonce") == "" {
		t.Fatal("missing nonce/state")
	}
	return cookie, location.Query().Get("nonce")
}
func TestOIDCStateIsSingleUseAndConfigurationBound(t *testing.T) {
	srv := newTestServer(t)
	idp := mockIdP(t, map[string]any{"sub": "x", "role": "admin"})
	srv.oidcHTTP = idp.Client()
	settings := sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app", AutoProvision: true}
	if e := srv.ssoStore.Save(settings); e != nil {
		t.Fatal(e)
	}
	cookie, nonce := beginOIDCTest(t, srv)
	call := func(state string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", fmt.Sprintf("/api/auth/oidc/callback?state=%s&code=%s", state, nonce), nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.Routes().ServeHTTP(w, r)
		return w
	}
	if w := call("mismatch"); w.Code != 400 {
		t.Fatal("mismatched state accepted")
	}
	if w := call(cookie.Value); w.Code != 302 {
		t.Fatalf("valid short-sub login failed: %d %s", w.Code, w.Body.String())
	}
	if w := call(cookie.Value); w.Code != 400 || hasSessionCookie(w) {
		t.Fatal("state replay accepted")
	}
	cookie, nonce = beginOIDCTest(t, srv)
	settings.ClientID = "changed-client"
	if e := srv.ssoStore.Save(settings); e != nil {
		t.Fatal(e)
	}
	if w := call(cookie.Value); w.Code != 400 || hasSessionCookie(w) {
		t.Fatal("configuration change not bound")
	}
}
func TestVerifiedLoginMeetsFreshBackupGate(t *testing.T) {
	srv := newTestServer(t)
	idp := mockIdP(t, map[string]any{"sub": "admin-sub", "preferred_username": "admin", "role": "admin"})
	srv.oidcHTTP = idp.Client()
	if e := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app", AutoProvision: true}); e != nil {
		t.Fatal(e)
	}
	w := driveSSOCallback(t, srv)
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "kypass_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no authenticated session")
	}
	for _, route := range destructiveBackupRoutes {
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, csrfRequest(t, srv, cookie, route.method, route.path, `{}`))
		if rec.Code == 403 {
			t.Fatalf("verified admin rejected: %s", route.path)
		}
	}
}
func TestRealKySignOnPayloadAndRetrySemantics(t *testing.T) {
	// Captured from the real sender's TestAccountSyncSCIMPayloadAndHeaders at a2d5dbc.
	body, e := os.ReadFile("testdata/kysignon-user.json")
	if e != nil {
		t.Fatal(e)
	}
	srv := newTestServer(t)
	req := signedSyncRequest(srv.pairingSecret, "user.created", body)
	headers := req.Header.Clone()
	if w := doSync(t, srv, req); w.Code != 200 {
		t.Fatalf("real sender payload: %d %s", w.Code, w.Body.String())
	}
	before, e := srv.audit.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	retry := httptest.NewRequest("POST", "/api/sync/webhook", bytes.NewReader(body))
	retry.Header = headers
	if w := doSync(t, srv, retry); w.Code != 200 || !strings.Contains(w.Body.String(), "duplicate") {
		t.Fatal("completed retry not acknowledged")
	}
	after, e := srv.audit.Snapshot()
	if e != nil || !bytes.Equal(before.Log, after.Log) {
		t.Fatal("replay reapplied the event")
	}
	// A valid signer reusing an ID with another event type is refused too.
	h, e := syncauth.Sign([]byte(srv.pairingSecret), time.Now(), "user.deleted", headers.Get(syncauth.HeaderEventID), body)
	if e != nil {
		t.Fatal(e)
	}
	reused := httptest.NewRequest("POST", "/api/sync/webhook", bytes.NewReader(body))
	h.Apply(reused)
	if w := doSync(t, srv, reused); w.Code != 401 {
		t.Fatal("ID changed meaning")
	}
}
func TestSyncFailureCanRetryAndBodyIsBounded(t *testing.T) {
	srv := newTestServer(t)
	// Invalid resource is authenticated but not a completed event. A corrected resend
	// with the same event ID must not be poisoned by the prior handler failure.
	req := signedSyncRequest(srv.pairingSecret, "user.created", []byte(`{}`))
	id := req.Header.Get(syncauth.HeaderEventID)
	if w := doSync(t, srv, req); w.Code != 400 {
		t.Fatalf("bad resource = %d", w.Code)
	}
	body := scimUserResource("retry-sub", "retry", "r@example.com", "user", true)
	h, e := syncauth.Sign([]byte(srv.pairingSecret), time.Now(), "user.created", id, body)
	if e != nil {
		t.Fatal(e)
	}
	req = httptest.NewRequest("POST", "/api/sync/webhook", bytes.NewReader(body))
	h.Apply(req)
	if w := doSync(t, srv, req); w.Code != 200 {
		t.Fatalf("retry failed = %d %s", w.Code, w.Body.String())
	}
	req = signedSyncRequest(srv.pairingSecret, "user.created", bytes.Repeat([]byte("x"), syncBodyLimit+1))
	if w := doSync(t, srv, req); w.Code != 401 {
		t.Fatal("oversized body accepted")
	}
	req = signedSyncRequest(srv.pairingSecret, "user.created", body)
	req.Body = io.NopCloser(strings.NewReader(`{}`))
	if w := doSync(t, srv, req); w.Code != 401 {
		t.Fatal("modified body accepted")
	}
}
func TestSyncStillAcceptsConfiguredClientSecret(t *testing.T) {
	srv := newTestServer(t)
	secret := "synthetic-client-secret-long-enough"
	if e := srv.ssoStore.Save(sso.SSOSettings{ClientSecret: secret}); e != nil {
		t.Fatal(e)
	}
	if w := doSync(t, srv, signedSyncRequest(secret, "user.created", scimUserResource("client-sub", "client", "c@example.com", "user", true))); w.Code != 200 {
		t.Fatalf("client secret no longer accepted: %d", w.Code)
	}
}
func TestSyncFixtureHasSCIMShape(t *testing.T) {
	b, e := os.ReadFile("testdata/kysignon-user.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if v["id"] == nil || v["userName"] == nil || v["event"] != nil {
		t.Fatal("fixture is not the sender's bare SCIM resource")
	}
}

func TestSyncRetriesSamePayloadAfterPersistenceFailure(t *testing.T) {
	root := t.TempDir()
	srv, _ := newServerIn(t, root)
	body := scimUserResource("disk-retry", "diskretry", "d@example.com", "user", true)
	req := signedSyncRequest(srv.pairingSecret, "user.created", body)
	headers := req.Header.Clone()
	tmp := filepath.Join(root, "config", "users.json.tmp")
	if e := os.Mkdir(tmp, 0700); e != nil {
		t.Fatal(e)
	}
	if w := doSync(t, srv, req); w.Code != 500 {
		t.Fatalf("wanted persistence failure: %d", w.Code)
	}
	if e := os.Remove(tmp); e != nil {
		t.Fatal(e)
	}
	retry := httptest.NewRequest("POST", "/api/sync/webhook", bytes.NewReader(body))
	retry.Header = headers
	if w := doSync(t, srv, retry); w.Code != 200 {
		t.Fatalf("failed attempt poisoned retry: %d %s", w.Code, w.Body.String())
	}
}
func TestOIDCExpiredStateAndLinkCookieCannotChangeIdentity(t *testing.T) {
	srv := newTestServer(t)
	idp := mockIdP(t, map[string]any{"sub": "new-sub", "preferred_username": "new"})
	srv.oidcHTTP = idp.Client()
	if e := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app", AutoProvision: true}); e != nil {
		t.Fatal(e)
	}
	cookie, nonce := beginOIDCTest(t, srv)
	srv.oidcMu.Lock()
	attempt := srv.oidcPending[cookie.Value]
	attempt.Expires = time.Now().Add(-time.Minute)
	srv.oidcPending[cookie.Value] = attempt
	srv.oidcMu.Unlock()
	r := httptest.NewRequest("GET", "/api/auth/oidc/callback?state="+cookie.Value+"&code="+nonce, nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, r)
	if w.Code != 400 || hasSessionCookie(w) {
		t.Fatal("expired state accepted")
	}
	forged := &http.Cookie{Name: ssoCookieName, Value: "state|verifier|victim"}
	r = httptest.NewRequest("GET", "/api/auth/oidc/callback?state=state&code="+nonce, nil)
	r.AddCookie(forged)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, r)
	if w.Code != 400 || hasSessionCookie(w) {
		t.Fatal("forged linking cookie accepted")
	}
}

func TestOIDCRefreshesRotatedSigningKey(t *testing.T) {
	srv := newTestServer(t)
	claims := map[string]any{"sub": "rotation-sub", "preferred_username": "rotate"}
	idp := mockIdP(t, claims)
	srv.oidcHTTP = idp.Client()
	if e := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app", AutoProvision: true}); e != nil {
		t.Fatal(e)
	}
	if w := driveSSOCallback(t, srv); w.Code != 302 {
		t.Fatal("initial login failed")
	}
	claims["__rotate"] = true
	srv.oidcVerifier.MinRefresh = time.Nanosecond
	if w := driveSSOCallback(t, srv); w.Code != 302 || !hasSessionCookie(w) {
		t.Fatalf("rotated-key login failed: %d %s", w.Code, w.Body.String())
	}
}
