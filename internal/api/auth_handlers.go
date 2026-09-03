package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
)

const ssoCookieName = "kypass_sso_state"

// There is no local authentication here, by design. KySignOn is the only authenticator:
// no login endpoint, no login parameters, no recovery-as-site-access, no first-run setup.
// The master password is never sent, not even as a derived verifier — it unwraps the
// vault key envelope in the browser and nowhere else.

func (s *Server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   settings.Enabled,
		"issuerUrl": settings.IssuerURL,
	})
}

func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "SSO is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	linkUserID := ""
	if r.URL.Query().Get("link") == "true" {
		if auth, ok := s.currentUser(r); ok {
			linkUserID = auth.ID
		}
	}

	verifier, challenge, err := sso.GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}

	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	cookieVal := fmt.Sprintf("%s|%s|%s", state, verifier, linkUserID)
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
	if err != nil {
		http.Error(w, "failed to discover OIDC endpoints: "+err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}
	redirectURI := settings.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, requestHost(r))
	}

	authURL, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, "invalid authorization endpoint", http.StatusInternalServerError)
		return
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", settings.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" {
		http.Error(w, "SSO is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	cookie, err := r.Cookie(ssoCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing or expired SSO session state", http.StatusBadRequest)
		return
	}

	// Clear cookie
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   -1,
	})

	parts := strings.Split(cookie.Value, "|")
	if len(parts) < 2 {
		http.Error(w, "corrupted SSO state cookie", http.StatusBadRequest)
		return
	}
	expectedState := parts[0]
	codeVerifier := parts[1]
	linkUserID := ""
	if len(parts) >= 3 {
		linkUserID = parts[2]
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or authorization code", http.StatusBadRequest)
		return
	}

	if state != expectedState {
		http.Error(w, "invalid or mismatched SSO state parameter", http.StatusBadRequest)
		return
	}

	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
	if err != nil {
		http.Error(w, "failed to discover OIDC endpoints: "+err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}
	redirectURI := settings.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, requestHost(r))
	}

	tok, err := sso.ExchangeCode(r.Context(), disc.TokenEndpoint, settings.ClientID, settings.ClientSecret, code, redirectURI, codeVerifier)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusBadGateway)
		return
	}

	claims, err := sso.ParseClaims(r.Context(), tok.IDToken, tok.AccessToken, disc.UserinfoEndpoint)
	if err != nil {
		http.Error(w, "failed to parse claims: "+err.Error(), http.StatusBadGateway)
		return
	}

	// 1. Account linking mode
	if linkUserID != "" {
		if err := s.users.LinkSSO(linkUserID, claims.Sub, claims.PreferredUsername, claims.Email); err != nil {
			http.Error(w, "failed to link account: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.record(r, "auth.sso_linked", linkUserID, "", clientIP(r), "linked SSO subject "+claims.Sub)
		http.Redirect(w, r, "/#sso=linked", http.StatusFound)
		return
	}

	// 2. Login mode.
	//
	// The subject is the only key an identity is ever matched on. Matching on
	// preferred_username as well — which this used to do on a subject miss — hands any
	// KySignOn identity the local account that happens to share its name, and that
	// account's vault with it. A name is an attribute of an identity, not the identity.
	user, _ := s.users.GetBySSOSub(claims.Sub)

	if user.ID == "" {
		if !settings.AutoProvision {
			http.Error(w, "Access denied: SSO identity not linked to any KyPassword account.", http.StatusForbidden)
			return
		}

		role := users.RoleUser
		if claims.IsAdmin() {
			role = users.RoleAdmin
		}

		username := claims.PreferredUsername
		if username == "" {
			username = "user_" + claims.Sub[:8]
		}

		createdUser, errCreate := s.users.CreateSSOUser(username, role, claims.Sub, claims.PreferredUsername, claims.Email)
		if errCreate != nil {
			if errors.Is(errCreate, users.ErrUsernameTaken) {
				username = fmt.Sprintf("%s_%s", username, claims.Sub[:6])
				createdUser, errCreate = s.users.CreateSSOUser(username, role, claims.Sub, claims.PreferredUsername, claims.Email)
			}
			if errCreate != nil {
				http.Error(w, "failed to auto-provision user: "+errCreate.Error(), http.StatusInternalServerError)
				return
			}
		}
		user = createdUser
		s.record(r, "auth.sso_provisioned", user.ID, "", clientIP(r), "auto-provisioned user via SSO")
	}

	if !user.Active {
		http.Error(w, "Account deactivated", http.StatusForbidden)
		return
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}

	s.record(r, "auth.sso_login", user.ID, "", clientIP(r), "signed in via SSO")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u users.User) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          u.Public(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, u users.User) {
	if cookie, err := r.Cookie("kypass_session"); err == nil && cookie.Value != "" {
		s.sessMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessMu.Unlock()
	}

	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "kypass_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   -1,
	})

	s.record(r, "auth.logout", u.ID, "", clientIP(r), "logged out")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleHealth is what the container healthcheck polls. It reports unhealthy once an
// audit write has failed: the vault still works, but it is no longer recording what it
// does, and that is a state to be pulled out of rotation rather than served from.
//
// Why the reason is not in the body: this endpoint is unauthenticated, and "the audit
// log is broken" is not something to hand an attacker. The reason is in the server log.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status, code := "ok", http.StatusOK
	if s.auditFailures.Load() > 0 {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"status":  status,
		"service": "kypassword-server",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}
