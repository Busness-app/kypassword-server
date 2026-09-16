package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyvault-server/internal/sso"
)

// logoutFixture is a server bound to a mock issuer with one signed-in session.
type logoutFixture struct {
	srv *Server
	idp *mockIssuer
	dir string
}

func newLogoutFixture(t *testing.T, claims map[string]any) *logoutFixture {
	t.Helper()
	dir := t.TempDir()
	srv, _ := newServerIn(t, dir)
	idp := newMockIssuer(t, claims)
	srv.oidcHTTP = idp.Client()
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kyvault-app", AutoProvision: true}); err != nil {
		t.Fatal(err)
	}
	return &logoutFixture{srv: srv, idp: idp, dir: dir}
}

// login runs a full SSO login and returns the session cookie.
func (f *logoutFixture) login(t *testing.T) *http.Cookie {
	t.Helper()
	rec := driveSSOCallback(t, f.srv)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d %s, want 302", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypass_session" && c.Value != "" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func (f *logoutFixture) me(cookie *http.Cookie) int {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code
}

func (f *logoutFixture) meBearer(token string) int {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code
}

func (f *logoutFixture) logout(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return f.logoutRaw("application/x-www-form-urlencoded", url.Values{"logout_token": {token}}.Encode())
}

func (f *logoutFixture) logoutRaw(contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// pairDevice pairs a device from the browser session and returns its bearer token and ID.
func (f *logoutFixture) pairDevice(t *testing.T, cookie *http.Cookie) (string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, csrfRequest(t, f.srv, cookie, http.MethodPost, "/api/devices/pairing/start", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("pairing start = %d %s", rec.Code, rec.Body.String())
	}
	var pairing struct {
		PIN string `json:"pin"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pairing); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"codeOrPin": pairing.PIN, "deviceName": "phone", "platform": "android", "deviceEnvelope": "device-wrapped-key"})
	req := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pairing redeem = %d %s", rec.Code, rec.Body.String())
	}
	var redeemed struct {
		SessionToken string `json:"sessionToken"`
		DeviceID     string `json:"deviceId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &redeemed); err != nil {
		t.Fatal(err)
	}
	return redeemed.SessionToken, redeemed.DeviceID
}

func (f *logoutFixture) auditContains(t *testing.T, needle string) bool {
	t.Helper()
	snap, err := f.srv.audit.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Contains(snap.Log, []byte(needle))
}

func TestBackchannelLogoutEndsNamedSessionOnly(t *testing.T) {
	f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "sid": "sid-1"})
	first := f.login(t)
	deviceToken, deviceID := f.pairDevice(t, first)
	f.idp.set("sid", "sid-2")
	second := f.login(t)

	user, err := f.srv.users.GetBySSOSub("alice-sub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.vault.SaveVault(user.ID, 0, []byte("kdbx-ciphertext"), "password-envelope", "recovery-envelope", ""); err != nil {
		t.Fatal(err)
	}
	before, _ := f.srv.vault.GetMetadata(user.ID)

	rec := f.logout(t, f.idp.logoutToken(map[string]any{"sub": "alice-sub", "sid": "sid-1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d %s", rec.Code, rec.Body.String())
	}
	if got := f.me(first); got != http.StatusUnauthorized {
		t.Errorf("logged-out session answers %d, want 401", got)
	}
	if got := f.meBearer(deviceToken); got != http.StatusUnauthorized {
		t.Errorf("device paired from the logged-out session answers %d, want 401", got)
	}
	if got := f.me(second); got != http.StatusOK {
		t.Errorf("unrelated session answers %d, want 200", got)
	}

	// Authentication ended; custody did not.
	after, err := f.srv.vault.GetMetadata(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != before.Version || after.PasswordEnvelope != "password-envelope" || after.RecoveryEnvelope != "recovery-envelope" || after.DeviceEnvelopes[deviceID].Envelope != "device-wrapped-key" {
		t.Errorf("vault state changed by logout: %+v", after)
	}
	if u, err := f.srv.users.Get(user.ID); err != nil || !u.Active {
		t.Errorf("account changed by logout: %+v %v", u, err)
	}
	if devs := f.srv.devices.ListUserDevices(user.ID); len(devs) != 1 || devs[0].ID != deviceID || !devs[0].Active {
		t.Errorf("device registration changed by logout: %+v", devs)
	}
	if !f.auditContains(t, "auth.sso_logout") {
		t.Error("no auth.sso_logout audit record")
	}
}

func TestBackchannelLogoutSubjectWide(t *testing.T) {
	f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "sid": "sid-1", "iat": time.Now().Add(-2 * time.Second).Unix()})
	first := f.login(t)
	f.idp.set("sid", "sid-2")
	second := f.login(t)

	rec := f.logout(t, f.idp.logoutToken(map[string]any{"sub": "alice-sub"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d %s", rec.Code, rec.Body.String())
	}
	for name, c := range map[string]*http.Cookie{"first": first, "second": second} {
		if got := f.me(c); got != http.StatusUnauthorized {
			t.Errorf("%s session answers %d after subject logout, want 401", name, got)
		}
	}

	// A login after the logout is a new authentication and must succeed. A token from
	// the same second as the logout is still fenced, so this one is issued a second on.
	f.idp.set("iat", time.Now().Add(time.Second).Unix())
	f.idp.set("sid", "sid-3")
	if got := f.me(f.login(t)); got != http.StatusOK {
		t.Errorf("post-logout login answers %d, want 200", got)
	}
}

func TestBackchannelLogoutReplayRefusedAcrossRestart(t *testing.T) {
	f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "sid": "sid-1"})
	f.login(t)
	token := f.idp.logoutToken(map[string]any{"sub": "alice-sub", "sid": "sid-1"})
	if rec := f.logout(t, token); rec.Code != http.StatusOK {
		t.Fatalf("first delivery = %d", rec.Code)
	}
	if rec := f.logout(t, token); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay = %d, want 400", rec.Code)
	}

	f.srv.Close()
	restarted, _ := newServerIn(t, f.dir)
	restarted.oidcHTTP = f.idp.Client()
	f.srv = restarted
	if rec := f.logout(t, token); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay after restart = %d, want 400: the receipt did not survive", rec.Code)
	}
	// And a fresh token still works after restart, with no login having primed discovery.
	if rec := f.logout(t, f.idp.logoutToken(map[string]any{"sub": "alice-sub", "sid": "sid-1"})); rec.Code != http.StatusOK {
		t.Fatalf("fresh token after restart = %d %s", rec.Code, rec.Body.String())
	}
}

func TestBackchannelLogoutFencesInFlightLogin(t *testing.T) {
	for _, scope := range []string{"session", "subject"} {
		t.Run(scope, func(t *testing.T) {
			f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "sid": "sid-1", "iat": time.Now().Add(-2 * time.Second).Unix()})
			stateCookie, nonce := beginOIDCTest(t, f.srv)
			overrides := map[string]any{"sub": "alice-sub", "sid": "sid-1"}
			if scope == "subject" {
				delete(overrides, "sid")
			}
			if rec := f.logout(t, f.idp.logoutToken(overrides)); rec.Code != http.StatusOK {
				t.Fatalf("logout = %d", rec.Code)
			}

			req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code="+url.QueryEscape(nonce)+"&state="+stateCookie.Value, nil)
			req.AddCookie(stateCookie)
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || hasSessionCookie(rec) {
				t.Fatalf("callback after logout = %d, cookie=%v; want 403 and no session", rec.Code, hasSessionCookie(rec))
			}
			if !f.auditContains(t, "auth.sso_login_fenced") {
				t.Error("fenced login not audited")
			}

			// Pairing started before the logout cannot mint a device session after it.
			f.idp.set("iat", time.Now().Add(time.Second).Unix())
			f.idp.set("sid", "sid-2")
			cookie := f.login(t)
			if got := f.me(cookie); got != http.StatusOK {
				t.Fatalf("later login answers %d", got)
			}
			rec = httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, csrfRequest(t, f.srv, cookie, http.MethodPost, "/api/devices/pairing/start", ""))
			var pairing struct {
				PIN string `json:"pin"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &pairing)
			if rec := f.logout(t, f.idp.logoutToken(map[string]any{"sub": "alice-sub", "sid": "sid-2"})); rec.Code != http.StatusOK {
				t.Fatalf("second logout = %d", rec.Code)
			}
			body, _ := json.Marshal(map[string]string{"codeOrPin": pairing.PIN, "deviceName": "phone", "platform": "android"})
			rec = httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem", bytes.NewReader(body)))
			if rec.Code == http.StatusOK {
				t.Fatal("pairing redeemed a device session for a logged-out browser session")
			}
		})
	}
}

func TestBackchannelLogoutRejectsInvalidRequests(t *testing.T) {
	f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "sid": "sid-1"})
	cookie := f.login(t)
	logout := func(over map[string]any) *httptest.ResponseRecorder { return f.logout(t, f.idp.logoutToken(over)) }
	cases := map[string]func() *httptest.ResponseRecorder{
		"id token as logout": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"__typ": "JWT", "events": nil, "sub": "alice-sub", "sid": "sid-1", "nonce": "n"})
		},
		"wrong type": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"__typ": "JWT", "sub": "alice-sub", "sid": "sid-1"})
		},
		"no events": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"events": nil, "sub": "alice-sub", "sid": "sid-1"})
		},
		"nonce present": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"nonce": "n", "sub": "alice-sub", "sid": "sid-1"})
		},
		"no sub or sid": func() *httptest.ResponseRecorder { return logout(nil) },
		"no jti":        func() *httptest.ResponseRecorder { return logout(map[string]any{"jti": nil, "sub": "alice-sub"}) },
		"wrong audience": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"aud": "other-app", "sub": "alice-sub"})
		},
		"wrong issuer": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"iss": "https://other.example", "sub": "alice-sub"})
		},
		"unknown key": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"__key": f.idp.rotated, "sub": "alice-sub"})
		},
		"expired": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"exp": time.Now().Add(-5 * time.Minute).Unix(), "sub": "alice-sub"})
		},
		"stale": func() *httptest.ResponseRecorder {
			return logout(map[string]any{"iat": time.Now().Add(-10 * time.Minute).Unix(), "sub": "alice-sub"})
		},
		"json body":     func() *httptest.ResponseRecorder { return f.logoutRaw("application/json", `{"logout_token":"x"}`) },
		"missing token": func() *httptest.ResponseRecorder { return f.logoutRaw("application/x-www-form-urlencoded", "other=1") },
		"duplicate token": func() *httptest.ResponseRecorder {
			return f.logoutRaw("application/x-www-form-urlencoded", "logout_token=a&logout_token=b")
		},
		"oversized": func() *httptest.ResponseRecorder {
			return f.logoutRaw("application/x-www-form-urlencoded", "logout_token="+strings.Repeat("a", logoutBodyLimit+1))
		},
		"query string": func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout?logout_token="+url.QueryEscape(f.idp.logoutToken(map[string]any{"sub": "alice-sub", "sid": "sid-1"})), strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)
			return rec
		},
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			rec := send()
			if rec.Code < 400 {
				t.Fatalf("status = %d, want a rejection", rec.Code)
			}
			if got := f.me(cookie); got != http.StatusOK {
				t.Fatalf("session answers %d after a rejected logout, want 200", got)
			}
		})
	}
	if !f.auditContains(t, "auth.logout_rejected") {
		t.Error("rejections not audited")
	}
}

func TestBackchannelLogoutRouteTakesNoCookie(t *testing.T) {
	// The route is issuer-facing: an unauthenticated POST is answered by the token
	// checks, never by a session lookup, and never with 401.
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
}

func TestSSOLoginRequiresSidWhenIssuerSupportsSessionLogout(t *testing.T) {
	f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "__sid_supported": true})
	rec := driveSSOCallback(t, f.srv)
	if rec.Code != http.StatusUnauthorized || hasSessionCookie(rec) || len(f.srv.users.List()) != 0 {
		t.Fatalf("login without sid = %d, cookie=%v, users=%d; want 401 and nothing provisioned", rec.Code, hasSessionCookie(rec), len(f.srv.users.List()))
	}
	f.idp.set("sid", "sid-1")
	cookie := f.login(t)
	f.srv.sessMu.RLock()
	sess := f.srv.sessions[cookie.Value]
	f.srv.sessMu.RUnlock()
	if sess.SSO.SessionID != "sid-1" || sess.SSO.Subject != "alice-sub" || sess.SSO.Issuer != f.idp.URL || sess.SSO.ClientID != "kyvault-app" || sess.SSO.IssuedAt.IsZero() {
		t.Errorf("session identity not recorded: %+v", sess.SSO)
	}
}

func TestSSOLoginRecordsIssuerAuthTime(t *testing.T) {
	// auth_time is when the person authenticated. A token minted now for an hour-old
	// KySignOn session is not a fresh sign-in and must not satisfy the fresh-admin gate.
	f := newLogoutFixture(t, map[string]any{"sub": "admin-sub", "preferred_username": "admin", "role": "admin", "sid": "sid-1", "auth_time": time.Now().Add(-time.Hour).Unix()})
	cookie := f.login(t)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, csrfRequest(t, f.srv, cookie, destructiveBackupRoutes[0].method, destructiveBackupRoutes[0].path, `{}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale auth_time passed the fresh-admin gate: %d", rec.Code)
	}

	for name, value := range map[string]any{"string": "yesterday", "milliseconds": time.Now().UnixMilli(), "future": time.Now().Add(2 * time.Minute).Unix()} {
		f.idp.set("auth_time", value)
		if rec := driveSSOCallback(t, f.srv); rec.Code != http.StatusUnauthorized || hasSessionCookie(rec) {
			t.Fatalf("%s auth_time accepted: %d", name, rec.Code)
		}
	}
}

func TestSessionMintingRequiresRevocableIdentity(t *testing.T) {
	// A session no logout token could name would outlive every logout.
	f := newLogoutFixture(t, map[string]any{"sub": "alice-sub", "preferred_username": "alice", "sid": "sid-1"})
	cookie := f.login(t)
	user, _ := f.srv.users.GetBySSOSub("alice-sub")
	for name, id := range map[string]sso.Identity{"empty": {}, "no subject": {Issuer: f.idp.URL, ClientID: "kyvault-app"}, "no issuer": {ClientID: "kyvault-app", Subject: "alice-sub"}} {
		if _, err := f.srv.startSessionWithToken(user.ID, id); err == nil {
			t.Errorf("%s identity minted an unrevocable device session", name)
		}
		if err := f.srv.startSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), user.ID, id, time.Now()); err == nil {
			t.Errorf("%s identity minted an unrevocable browser session", name)
		}
	}

	// A pairing started by a session that is gone by the time the handler runs is refused,
	// not recorded with an empty identity.
	f.srv.sessMu.Lock()
	delete(f.srv.sessions, cookie.Value)
	f.srv.sessMu.Unlock()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/start", nil)
	req.AddCookie(cookie)
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pairing start with a removed session = %d, want 401", rec.Code)
	}
}

func TestFreshAdminGateIsSatisfiableByReauthentication(t *testing.T) {
	// A stale auth_time locks the backup routes; the way back in must ask the issuer to
	// authenticate again, or it hands back the same stale time forever.
	f := newLogoutFixture(t, map[string]any{"sub": "admin-sub", "preferred_username": "admin", "role": "admin", "sid": "sid-1", "auth_time": time.Now().Add(-time.Hour).Unix()})
	cookie := f.login(t)
	route := destructiveBackupRoutes[0]
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, csrfRequest(t, f.srv, cookie, route.method, route.path, `{}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale session passed the gate: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil))
	plain, _ := url.Parse(rec.Header().Get("Location"))
	if plain.Query().Has("max_age") {
		t.Error("an ordinary login must not force re-authentication")
	}
	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login?reauth=true", nil))
	reauth, _ := url.Parse(rec.Header().Get("Location"))
	if reauth.Query().Get("max_age") != "600" {
		t.Fatalf("reauth login max_age = %q, want 600", reauth.Query().Get("max_age"))
	}

	// The issuer honours max_age with a fresh auth_time; the gate opens on that alone.
	f.idp.set("auth_time", time.Now().Unix())
	fresh := f.login(t)
	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, csrfRequest(t, f.srv, fresh, route.method, route.path, `{}`))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("fresh auth_time still gated: %d", rec.Code)
	}
}
