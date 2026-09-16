package api

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/oidcverify"
	"github.com/Busness-app/kyvault-server/internal/sso"
)

// logoutBodyLimit bounds a back-channel logout request; a logout token is a few hundred bytes.
const logoutBodyLimit = 64 << 10

// logoutDiscoveryInterval bounds how often a failing token may make this receiver re-read
// the issuer's discovery document, so junk tokens cannot turn into issuer traffic.
const logoutDiscoveryInterval = time.Minute

// handleBackchannelLogout receives OpenID Connect Back-Channel Logout 1.0 tokens from
// KySignOn. The token is the only credential: no cookie, no CSRF token, and nothing in
// the query string is read. A logout naming no live session is still a success, so a
// delivery retried after a lost response converges instead of failing.
func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	reject := func(status int, why string) {
		s.recordAnonymousRejection(r, "auth.logout_rejected", clientIP(r), why)
		http.Error(w, why, status)
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != "application/x-www-form-urlencoded" {
		reject(http.StatusBadRequest, "form-encoded logout token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, logoutBodyLimit)
	if err := r.ParseForm(); err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			reject(http.StatusRequestEntityTooLarge, "logout request too large")
			return
		}
		reject(http.StatusBadRequest, "invalid logout request")
		return
	}
	tokens := r.PostForm["logout_token"]
	if len(tokens) != 1 || tokens[0] == "" {
		reject(http.StatusBadRequest, "one logout token required")
		return
	}
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" {
		reject(http.StatusBadRequest, "SSO is not configured")
		return
	}
	claims, err := s.verifyLogoutToken(r.Context(), settings, tokens[0])
	if err != nil {
		reject(http.StatusBadRequest, "logout token verification failed")
		return
	}
	n, err := s.applySSOLogout(claims, settings.ClientID)
	switch {
	case errors.Is(err, sso.ErrLogoutReplayed):
		reject(http.StatusBadRequest, "logout token already applied")
		return
	case errors.Is(err, sso.ErrLogoutCapacity):
		http.Error(w, "logout receipt capacity reached; retry later", http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, "logout was not recorded", http.StatusInternalServerError)
		return
	}
	userID := ""
	if u, err := s.users.GetBySSOSub(claims.Subject); err == nil {
		userID = u.ID
	}
	s.record(r, "auth.sso_logout", userID, "", clientIP(r), fmt.Sprintf("jti=%s sid=%s sessions=%d", claims.JWTID, claims.SessionID, n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// verifyLogoutToken shares the login verifier and its JWKS cache. A logout can arrive
// before any login has run discovery, and after the issuer rotates its JWKS location,
// so an unknown key re-runs discovery once, no more than once a minute.
func (s *Server) verifyLogoutToken(ctx context.Context, settings sso.SSOSettings, token string) (oidcverify.LogoutClaims, error) {
	s.oidcMu.Lock()
	v := s.oidcVerifier
	s.oidcMu.Unlock()
	if v != nil && v.Issuer == settings.IssuerURL && v.Audience == settings.ClientID {
		claims, err := v.VerifyLogout(ctx, token)
		if err == nil || !(errors.Is(err, oidcverify.ErrUnknownKey) || errors.Is(err, oidcverify.ErrJWKS) || errors.Is(err, oidcverify.ErrSignature)) {
			return claims, err
		}
	}
	s.oidcMu.Lock()
	if time.Since(s.oidcDiscoveredAt) < logoutDiscoveryInterval {
		s.oidcMu.Unlock()
		return oidcverify.LogoutClaims{}, errors.New("logout discovery cooldown")
	}
	s.oidcDiscoveredAt = time.Now()
	s.oidcMu.Unlock()
	discovery, err := sso.DiscoverEndpoints(ctx, settings.IssuerURL, s.oidcHTTP)
	if err != nil {
		return oidcverify.LogoutClaims{}, err
	}
	v = &oidcverify.Verifier{Issuer: settings.IssuerURL, Audience: settings.ClientID, JWKSURL: discovery.JWKSURI, HTTPClient: s.oidcHTTP}
	s.oidcMu.Lock()
	s.oidcVerifier = v
	s.oidcMu.Unlock()
	return v.VerifyLogout(ctx, token)
}

// applySSOLogout records the token and ends the sessions it names under the session
// lock, so a login racing it either lands first and is revoked here, or lands second
// and is fenced by the recorded event. Vault ciphertext, envelopes and registered
// devices are untouched: this ends authentication, not custody.
func (s *Server) applySSOLogout(c oidcverify.LogoutClaims, clientID string) (int, error) {
	now := time.Now().UTC()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	event, err := s.logouts.Admit(c, clientID, now)
	if err != nil {
		return 0, err
	}
	n := 0
	for token, session := range s.sessions {
		if event.Matches(session.SSO) {
			delete(s.sessions, token)
			s.devices.CancelUserPairings(session.UserID)
			n++
		}
	}
	return n, nil
}
