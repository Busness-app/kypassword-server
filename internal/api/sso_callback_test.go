package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypassword-server/internal/sso"
	"kypassword-server/internal/users"
)

// mockIdP stands in for KySignOn, returning an id_token carrying exactly the claims given.
func mockIdP(t *testing.T, claims map[string]any) *httptest.Server {
	t.Helper()
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
			payload, _ := json.Marshal(claims)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-token",
				"id_token":     "header." + base64.RawURLEncoding.EncodeToString(payload) + ".sig",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	return idp
}

// driveSSOCallback runs a full login: request the redirect, keep the state cookie, then
// return the callback's response.
func driveSSOCallback(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	handler := srv.Routes()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /api/auth/oidc/login status = %d, want 302", rec.Code)
	}

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no SSO state cookie was issued")
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/auth/oidc/callback?code=mock_code&state=%s", stateCookie.Value[:32]), nil)
	req.AddCookie(stateCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func hasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypass_session" && c.Value != "" {
			return true
		}
	}
	return false
}

func TestSSOCallbackDoesNotLinkByUsername(t *testing.T) {
	// A KySignOn identity whose preferred_username happens to match an existing local
	// account must not inherit that account or its vault. Username collision is not
	// identity; only the OIDC sub is.
	t.Run("unlinked local account", func(t *testing.T) {
		// A legacy account carried over from before KySignOn was the directory. Nothing
		// in the current code can create one, so it is seeded on disk.
		srv := newTestServerWithUsers(t, `[{"id":"u1","username":"alice","role":"user","active":true}]`)
		alice, err := srv.users.Get("u1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		idp := mockIdP(t, map[string]any{
			"sub":                "attacker-sub",
			"preferred_username": "alice",
			"email":              "attacker@evil.example",
		})
		if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app"}); err != nil {
			t.Fatalf("Save: %v", err)
		}

		rec := driveSSOCallback(t, srv)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("callback status = %d, want 403", rec.Code)
		}
		if hasSessionCookie(rec) {
			t.Error("no session may be issued for an unlinked identity")
		}

		after, err := srv.users.Get(alice.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if after.SSOSub != "" {
			t.Errorf("alice was linked to %q by username alone", after.SSOSub)
		}
	})

	t.Run("account already linked to a different subject", func(t *testing.T) {
		// Worse than the unlinked case: the fallback's LinkSSO drops the account's real
		// subject and installs the attacker's, so the legitimate owner is evicted too.
		srv := newTestServer(t)
		alice, err := srv.users.CreateSSOUser("alice", users.RoleUser, "alice-real-sub", "alice", "alice@example.com")
		if err != nil {
			t.Fatalf("CreateSSOUser: %v", err)
		}

		idp := mockIdP(t, map[string]any{
			"sub":                "attacker-sub",
			"preferred_username": "alice",
			"email":              "attacker@evil.example",
		})
		if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app"}); err != nil {
			t.Fatalf("Save: %v", err)
		}

		rec := driveSSOCallback(t, srv)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("callback status = %d, want 403", rec.Code)
		}
		if hasSessionCookie(rec) {
			t.Error("no session may be issued for an unlinked identity")
		}

		after, err := srv.users.Get(alice.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if after.SSOSub != "alice-real-sub" {
			t.Errorf("SSOSub = %q, want alice's own subject to be untouched", after.SSOSub)
		}
		if _, err := srv.users.GetBySSOSub("attacker-sub"); err == nil {
			t.Error("the attacker's subject must not resolve to any account")
		}
	})
}

func TestSSOCallbackStillMatchesOnSub(t *testing.T) {
	// The deletion must not break the only legitimate match.
	srv := newTestServer(t)
	alice, err := srv.users.CreateSSOUser("alice", users.RoleUser, "alice-real-sub", "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}

	idp := mockIdP(t, map[string]any{
		"sub":                "alice-real-sub",
		"preferred_username": "alice",
		"email":              "alice@example.com",
	})
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kypassword-app"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rec := driveSSOCallback(t, srv)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", rec.Code)
	}
	if !hasSessionCookie(rec) {
		t.Fatal("a matching subject must start a session")
	}
	if got, _ := srv.users.GetBySSOSub("alice-real-sub"); got.ID != alice.ID {
		t.Errorf("resolved account = %q, want alice", got.ID)
	}
}
