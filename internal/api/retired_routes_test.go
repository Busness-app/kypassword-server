package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
)

func TestRetiredAuthEndpointsAreGone(t *testing.T) {
	// Every path below was a way to authenticate, change a credential, or provision an
	// account without KySignOn. Each must now 404 — not 401, not 405. A 401 would mean
	// the route still exists behind auth, and the point is that it exists nowhere.
	srv := newTestServer(t)
	handler := srv.Routes()

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/login"},
		{http.MethodGet, "/api/auth/login-params?username=alice"},
		{http.MethodPost, "/api/auth/recovery"},
		{http.MethodPost, "/api/auth/password"},
		{http.MethodPost, "/api/auth/paper-recovery"},
		{http.MethodPost, "/api/settings/sso/unlink"},
		{http.MethodGet, "/api/setup"},
		{http.MethodPost, "/api/setup"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}

func TestAdminCannotCreateAccounts(t *testing.T) {
	// POST /api/admin/users cannot 404: GET on that path is still registered, so
	// net/http's mux answers 405 for the method it does not have. That is the honest
	// answer, but it is weaker evidence than a 404 — so this drives it as a real admin
	// with a real payload and checks that no account appears.
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	before := len(srv.users.List())

	body := strings.NewReader(`{"username":"smuggled","password":"hunter2","role":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/admin/users = %d, want 405", rec.Code)
	}
	if _, err := srv.users.GetByUsername("smuggled"); err == nil {
		t.Error("an account was created through a retired endpoint")
	}
	if after := len(srv.users.List()); after != before {
		t.Errorf("account count went from %d to %d", before, after)
	}
}

func TestSurvivingRoutesStillExist(t *testing.T) {
	// The deletion must not take the remaining surface with it. These answer without a
	// session, so an unauthenticated request proves the route is registered.
	srv := newTestServer(t)
	handler := srv.Routes()

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/health"},
		{http.MethodGet, "/api/auth/sso-config"},
		{http.MethodGet, "/api/auth/oidc/login"},
		{http.MethodGet, "/api/auth/oidc/callback"},
		{http.MethodGet, "/auth/sso/login"},
		{http.MethodGet, "/auth/sso/callback"},
		{http.MethodPost, "/api/sync/webhook"},
		{http.MethodPost, "/api/devices/pairing/redeem"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s = 404; the route was removed by mistake", tc.method, tc.path)
		}
	}

	// Authenticated routes should answer 401, which likewise proves they are registered.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/auth/me"},
		{http.MethodPost, "/api/auth/logout"},
		{http.MethodGet, "/api/vault/metadata"},
		{http.MethodGet, "/api/vault/kdbx"},
		{http.MethodPut, "/api/vault/envelopes"},
		{http.MethodGet, "/api/devices"},
		{http.MethodGet, "/api/admin/users"},
		{http.MethodGet, "/api/admin/sso"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestAdminSSOPutRefusesEnvironmentSourcedSettings(t *testing.T) {
	// Accepting a write the next restart discards is worse than refusing it: the operator
	// would be looking at a saved configuration that is not the one in force.
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	t.Setenv(sso.EnvIssuer, "https://signon.example")
	t.Setenv(sso.EnvClientID, "kypassword")
	t.Setenv(sso.EnvClientSecret, "s3cret")

	body := strings.NewReader(`{"enabled":true,"issuerUrl":"https://attacker.example","clientId":"evil","clientSecret":"x"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/admin/sso", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT /api/admin/sso = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), sso.EnvIssuer) {
		t.Errorf("the refusal should name the environment as the source: %s", rec.Body)
	}
	if got := srv.ssoStore.Load(); got.IssuerURL != "https://signon.example" {
		t.Errorf("settings changed anyway: %+v", got)
	}
}

func TestAdminSSOPutStillWorksWithoutTheEnvironment(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	for _, k := range []string{sso.EnvIssuer, sso.EnvClientID, sso.EnvClientSecret} {
		t.Setenv(k, "")
	}

	body := strings.NewReader(`{"enabled":true,"issuerUrl":"https://signon.example","clientId":"kypassword","clientSecret":"s3cret","autoProvision":true}`)
	req := httptest.NewRequest(http.MethodPut, "/api/admin/sso", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/admin/sso = %d, want 200", rec.Code)
	}
	if got := srv.ssoStore.Load(); got.IssuerURL != "https://signon.example" {
		t.Errorf("settings were not saved: %+v", got)
	}
}
