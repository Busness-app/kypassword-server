package api

import (
	"crypto/rand"

	"errors"
	"fmt"
	"net/http"
	"net/url"

	"time"

	"github.com/Busness-app/ky-primitives/oidcverify"
	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
)

const ssoCookieName = "kypass_sso_state"

type oidcAttempt struct {
	Settings                     sso.SSOSettings
	Discovery                    sso.OIDCDiscovery
	Verifier, Nonce, RedirectURI string
	LinkUserID                   string
	Expires                      time.Time
}

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
		} else {
			http.Error(w, "sign in before linking", http.StatusUnauthorized)
			return
		}
	}

	verifier, challenge, err := sso.GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}

	state := rand.Text()
	nonce := rand.Text()
	secure := isRequestSecure(r)
	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL, s.oidcHTTP)
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
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	s.oidcMu.Lock()
	for id, attempt := range s.oidcPending {
		if time.Now().After(attempt.Expires) {
			delete(s.oidcPending, id)
		}
	}
	if len(s.oidcPending) >= 1024 {
		s.oidcMu.Unlock()
		http.Error(w, "too many pending logins", http.StatusServiceUnavailable)
		return
	}
	s.oidcPending[state] = oidcAttempt{Settings: settings, Discovery: *disc, Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, LinkUserID: linkUserID, Expires: time.Now().Add(5 * time.Minute)}
	s.oidcMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: ssoCookieName, Value: state, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 300})
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

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" || state != cookie.Value {
		http.Error(w, "invalid SSO state", http.StatusBadRequest)
		return
	}
	s.oidcMu.Lock()
	attempt, ok := s.oidcPending[state]
	delete(s.oidcPending, state)
	s.oidcMu.Unlock()
	if !ok || time.Now().After(attempt.Expires) || settings != attempt.Settings {
		http.Error(w, "expired or changed SSO login", http.StatusBadRequest)
		return
	}
	tok, err := sso.ExchangeCode(r.Context(), attempt.Discovery.TokenEndpoint, settings.ClientID, settings.ClientSecret, code, attempt.RedirectURI, attempt.Verifier, s.oidcHTTP)
	if err != nil {
		http.Error(w, "identity token exchange failed", http.StatusBadGateway)
		return
	}
	s.oidcMu.Lock()
	v := s.oidcVerifier
	if v == nil || v.Issuer != settings.IssuerURL || v.Audience != settings.ClientID || v.JWKSURL != attempt.Discovery.JWKSURI {
		v = &oidcverify.Verifier{Issuer: settings.IssuerURL, Audience: settings.ClientID, JWKSURL: attempt.Discovery.JWKSURI, HTTPClient: s.oidcHTTP}
		s.oidcVerifier = v
	}
	s.oidcMu.Unlock()
	verified, err := v.VerifyWithNonce(r.Context(), tok.IDToken, attempt.Nonce)
	if err != nil {
		s.recordAnonymousRejection(r, "auth.oidc_rejected", clientIP(r), "identity token verification failed")
		http.Error(w, "identity token verification failed", http.StatusUnauthorized)
		return
	}
	claims, err := sso.VerifiedClaims(verified)
	if err != nil {
		http.Error(w, "invalid identity claims", http.StatusUnauthorized)
		return
	}
	if s.ssoStore.Load() != attempt.Settings {
		http.Error(w, "SSO configuration changed; sign in again", http.StatusBadRequest)
		return
	}
	linkUserID := attempt.LinkUserID
	// 1. Account linking mode
	if linkUserID != "" {
		current, ok := s.currentUser(r)
		if !ok || current.ID != linkUserID || (current.SSOSub != "" && current.SSOSub != claims.Sub) {
			http.Error(w, "linking identity does not match the initiating account", http.StatusForbidden)
			return
		}
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
			username = "user_" + truncate(claims.Sub, 8)
		}

		createdUser, errCreate := s.users.CreateSSOUser(username, role, claims.Sub, claims.PreferredUsername, claims.Email)
		if errCreate != nil {
			if errors.Is(errCreate, users.ErrUsernameTaken) {
				username = fmt.Sprintf("%s_%s", username, truncate(claims.Sub, 6))
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

// handleHealth is what the container healthcheck polls. It takes no credential, so it
// answers one thing: the process is up.
//
// Still 200 once an audit write has failed, and still not 503. There is nothing here to
// shed an instance to — docker-compose.yml runs one container with
// `restart: unless-stopped` and no orchestrator, and plain Compose does not act on an
// unhealthy container at all. The audit-failure counter is sticky, so 503 turned one
// transient audit-write failure into a vault that stays out of service until a human
// restarts it; behind Traefik or Kubernetes that is a full DATA_DIR becoming a credential
// lockout, which is worse than the record that was lost.
//
// It no longer says "degraded" either, and that is secrecy rather than tidiness:
// "degraded" has one cause in this server, so the string let an anonymous caller watch
// for the moment audit writes began failing — confirmation that a disk they were filling
// was full. The operator signal is the "AUDIT WRITE FAILED" line on stderr with its count
// and cause; the machine-readable one is GET /api/audit/verify, which is admin-only and
// carries writeFailures. TestFailedAuditWriteIsReportedOnlyToAnAdmin pins the status
// code, the body that does not change, and the count behind auth.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "kypassword-server",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}
