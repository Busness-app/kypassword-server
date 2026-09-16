package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kyvault-server/internal/sso"
	"github.com/Busness-app/kyvault-server/internal/users"
)

// mockIssuer stands in for KySignOn: discovery, JWKS, the token endpoint, and a
// logout-token minter signed by the same key.
type mockIssuer struct {
	*httptest.Server
	key, rotated *rsa.PrivateKey
	mu           sync.Mutex
	claims       map[string]any
}

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// mockIdP returns an issuer whose id_token carries exactly the claims given.
func mockIdP(t *testing.T, claims map[string]any) *httptest.Server {
	return newMockIssuer(t, claims).Server
}

func newMockIssuer(t *testing.T, claims map[string]any) *mockIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &mockIssuer{key: key, rotated: rotated, claims: claims}
	is.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		issuer := "https://" + r.Host
		claims := is.snapshot()
		signingKey := key
		publishedKid := "test-key"
		if claims["__rotate"] == true {
			signingKey = rotated
			publishedKid = "rotated-key"
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "jwks_uri": issuer + "/jwks",
				"backchannel_logout_session_supported": claims["__sid_supported"] == true})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS256", "kid": publishedKid, "n": base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes())}}})
		case "/oauth/token":
			r.ParseForm()
			values := map[string]any{"iss": issuer, "aud": "kyvault-app", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": r.Form.Get("code")}
			for k, v := range claims {
				values[k] = v
			}
			if claims["__missing_token"] == true {
				json.NewEncoder(w).Encode(map[string]string{"access_token": "untrusted-access"})
				return
			}
			alg := "RS256"
			if a, ok := claims["__alg"].(string); ok {
				alg = a
			}
			kid := publishedKid
			if k, ok := claims["__kid"].(string); ok {
				kid = k
			}
			token := signJWT(signingKey, map[string]any{"alg": alg, "kid": kid}, values)
			if claims["__bad_signature"] == true {
				token = token[:len(token)-2] + "AA"
			}
			json.NewEncoder(w).Encode(map[string]any{"id_token": token, "access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(is.Close)
	return is
}

func (is *mockIssuer) snapshot() map[string]any {
	is.mu.Lock()
	defer is.mu.Unlock()
	out := make(map[string]any, len(is.claims))
	for k, v := range is.claims {
		out[k] = v
	}
	return out
}

// set changes a claim for later tokens; a nil value removes it.
func (is *mockIssuer) set(k string, v any) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if v == nil {
		delete(is.claims, k)
		return
	}
	is.claims[k] = v
}

// logoutToken mints a logout+jwt for this issuer. overrides replace or, when nil,
// remove claims; "__typ" and "__key" override the header type and signing key.
func (is *mockIssuer) logoutToken(overrides map[string]any) string {
	now := time.Now()
	values := map[string]any{"iss": is.URL, "aud": "kyvault-app", "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": randomHex(8),
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}}}
	header := map[string]any{"alg": "RS256", "kid": "test-key", "typ": "logout+jwt"}
	key := is.key
	for k, v := range overrides {
		switch {
		case k == "__typ":
			header["typ"] = v
		case k == "__key":
			key = v.(*rsa.PrivateKey)
		case v == nil:
			delete(values, k)
		default:
			values[k] = v
		}
	}
	return signJWT(key, header, values)
}

func signJWT(key *rsa.PrivateKey, header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	b, _ := json.Marshal(payload)
	raw := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return raw + "." + base64.RawURLEncoding.EncodeToString(sig)
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

	location, _ := url.Parse(rec.Header().Get("Location"))
	nonce := location.Query().Get("nonce")
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", url.QueryEscape(nonce), stateCookie.Value), nil)
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
		srv.oidcHTTP = idp.Client()
		if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kyvault-app"}); err != nil {
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
		srv.oidcHTTP = idp.Client()
		if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kyvault-app"}); err != nil {
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
	srv.oidcHTTP = idp.Client()
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kyvault-app"}); err != nil {
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
