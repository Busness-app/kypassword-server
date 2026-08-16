package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kypassword-server/internal/sso"
	"kypassword-server/internal/users"
)

const ssoCookieName = "kypass_sso_state"

type LoginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthSecret string `json:"authSecret"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	secret := req.AuthSecret
	if secret == "" {
		secret = req.Password
	}

	u, err := s.users.VerifyAuth(req.Username, secret)
	if err != nil {
		_, _ = s.audit.Log("auth.login_failed", "", "", clientIP(r), "failed login for "+req.Username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.login", u.ID, "", clientIP(r), "user signed in")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": u.Public(),
	})
}

func (s *Server) handlePaperRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username       string `json:"username"`
		RecoverySecret string `json:"recoverySecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	u, err := s.users.VerifyPaperRecovery(req.Username, req.RecoverySecret)
	if err != nil {
		_, _ = s.audit.Log("auth.recovery_failed", "", "", clientIP(r), "failed paper recovery for "+req.Username)
		http.Error(w, "invalid recovery code", http.StatusUnauthorized)
		return
	}

	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.recovery_success", u.ID, "", clientIP(r), "unlocked via paper recovery code")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"mustChangePassword": true,
		"user":               u.Public(),
	})
}

func (s *Server) handleLoginParams(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}

	u, err := s.users.GetByUsername(username)
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"salt":       u.AuthSalt,
			"iterations": u.AuthIterations,
		})
		return
	}

	// Account not found: return deterministic synthetic salt so response timing/shape does not leak existence
	h := sha256.Sum256([]byte("kypass-synth:" + strings.ToLower(username)))
	writeJSON(w, http.StatusOK, map[string]any{
		"salt":       hex.EncodeToString(h[:16]),
		"iterations": 600000,
	})
}

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
	redirectURI := fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, r.Host)

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
	redirectURI := fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, r.Host)

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
		_, _ = s.audit.Log("auth.sso_linked", linkUserID, "", clientIP(r), "linked SSO subject "+claims.Sub)
		http.Redirect(w, r, "/#sso=linked", http.StatusFound)
		return
	}

	// 2. Login mode
	user, err := s.users.GetBySSOSub(claims.Sub)
	if err != nil && errors.Is(err, users.ErrNotFound) {
		if claims.PreferredUsername != "" {
			if u, errU := s.users.GetByUsername(claims.PreferredUsername); errU == nil {
				user = u
				_ = s.users.LinkSSO(u.ID, claims.Sub, claims.PreferredUsername, claims.Email)
			}
		}
	}

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
		_, _ = s.audit.Log("auth.sso_provisioned", user.ID, "", clientIP(r), "auto-provisioned user via SSO")
	}

	if !user.Active {
		http.Error(w, "Account deactivated", http.StatusForbidden)
		return
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.sso_login", user.ID, "", clientIP(r), "signed in via SSO")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleSSOUnlink(w http.ResponseWriter, r *http.Request, u users.User) {
	if err := s.users.UnlinkSSO(u.ID); err != nil {
		http.Error(w, "failed to unlink SSO: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = s.audit.Log("auth.sso_unlinked", u.ID, "", clientIP(r), "unlinked SSO identity")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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

	_, _ = s.audit.Log("auth.logout", u.ID, "", clientIP(r), "logged out")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, u users.User) {
	var req struct {
		NewPassword   string `json:"newPassword"`
		RequireChange bool   `json:"requireChange"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewPassword == "" {
		http.Error(w, "invalid password payload", http.StatusBadRequest)
		return
	}

	if err := s.users.SetPassword(u.ID, req.NewPassword, req.RequireChange); err != nil {
		http.Error(w, "failed to update password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.password_changed", u.ID, "", clientIP(r), "user changed password")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetPaperRecovery(w http.ResponseWriter, r *http.Request, u users.User) {
	var req struct {
		RecoverySecret string `json:"recoverySecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RecoverySecret == "" {
		http.Error(w, "invalid recovery payload", http.StatusBadRequest)
		return
	}

	if err := s.users.SetPaperRecovery(u.ID, req.RecoverySecret); err != nil {
		http.Error(w, "failed to save recovery secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.paper_recovery_set", u.ID, "", clientIP(r), "paper recovery code updated")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "kypassword-server",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleSetupCheck(w http.ResponseWriter, r *http.Request) {
	userList := s.users.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"setupRequired": len(userList) == 0,
	})
}

func (s *Server) handleSetupInit(w http.ResponseWriter, r *http.Request) {
	userList := s.users.List()
	if len(userList) > 0 {
		http.Error(w, "setup has already been completed", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	u, err := s.users.Create(req.Username, req.Password, users.RoleAdmin)
	if err != nil {
		http.Error(w, "failed to create initial admin: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = s.startSession(w, r, u.ID)
	_, _ = s.audit.Log("setup.initialized", u.ID, "", clientIP(r), "initial admin account created")

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": u.Public(),
	})
}
