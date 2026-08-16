package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"kypassword-server/internal/audit"
	"kypassword-server/internal/devices"
	"kypassword-server/internal/sso"
	"kypassword-server/internal/users"
	"kypassword-server/internal/vault"
)

type Session struct {
	UserID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	CSRFToken string
}

type Server struct {
	users         *users.Store
	vault         *vault.Store
	devices       *devices.Store
	audit         *audit.Store
	ssoStore      *sso.Store
	pairingSecret string

	sessMu   sync.RWMutex
	sessions map[string]Session // token -> Session
}

// Config holds initialization paths and secrets for Server.
type Config struct {
	DataDir       string
	ConfigDir     string
	PairingSecret string
	RetentionDays int
}

// NewServer constructs the KyPassword Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = "./config"
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 90
	}

	uStore, err := users.NewStore(cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("init users store: %w", err)
	}

	vStore, err := vault.NewStore(cfg.DataDir+"/vaults", cfg.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("init vault store: %w", err)
	}

	dStore, err := devices.NewStore(cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("init devices store: %w", err)
	}

	aStore, err := audit.NewStore(cfg.DataDir + "/audit")
	if err != nil {
		return nil, fmt.Errorf("init audit store: %w", err)
	}

	ssoSt := sso.NewStore(cfg.ConfigDir)

	s := &Server{
		users:         uStore,
		vault:         vStore,
		devices:       dStore,
		audit:         aStore,
		ssoStore:      ssoSt,
		pairingSecret: cfg.PairingSecret,
		sessions:      make(map[string]Session),
	}

	return s, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public Auth & Setup
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/recovery", s.handlePaperRecovery)
	mux.HandleFunc("GET /api/auth/login-params", s.handleLoginParams)
	mux.HandleFunc("GET /api/auth/sso-config", s.handleSSOConfig)
	mux.HandleFunc("GET /api/auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/sso/login", s.handleSSOLogin)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/sso/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/setup", s.handleSetupCheck)
	mux.HandleFunc("POST /api/setup", s.handleSetupInit)

	// Self & Session
	mux.HandleFunc("GET /api/auth/me", s.withAuth(s.handleMe))
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("POST /api/auth/password", s.withAuth(s.handleChangePassword))
	mux.HandleFunc("POST /api/auth/paper-recovery", s.withAuth(s.handleSetPaperRecovery))
	mux.HandleFunc("POST /api/settings/sso/unlink", s.withAuth(s.handleSSOUnlink))

	// Vault Operations
	mux.HandleFunc("GET /api/vault/metadata", s.withAuth(s.handleVaultMetadata))
	mux.HandleFunc("GET /api/vault/kdbx", s.withAuth(s.handleVaultDownload))
	mux.HandleFunc("POST /api/vault/upload", s.withAuth(s.handleVaultUpload))
	mux.HandleFunc("PUT /api/vault/envelopes", s.withAuth(s.handleVaultEnvelopes))
	mux.HandleFunc("GET /api/vault/history", s.withAuth(s.handleVaultHistory))
	mux.HandleFunc("POST /api/vault/history/{id}/restore", s.withAuth(s.handleVaultHistoryRestore))
	mux.HandleFunc("GET /api/vault/conflicts", s.withAuth(s.handleVaultConflicts))
	mux.HandleFunc("DELETE /api/vault/conflicts/{id}", s.withAuth(s.handleVaultConflictDiscard))

	// Devices & Extension Pairing
	mux.HandleFunc("POST /api/devices/pairing/start", s.withAuth(s.handlePairingStart))
	mux.HandleFunc("POST /api/devices/pairing/redeem", s.handlePairingRedeem) // device-facing
	mux.HandleFunc("GET /api/devices", s.withAuth(s.handleDevicesList))
	mux.HandleFunc("DELETE /api/devices/{id}", s.withAuth(s.handleDeviceRevoke))

	// Directory Sync Webhook
	mux.HandleFunc("POST /api/sync/webhook", s.handleSyncWebhook)

	// Admin Operations
	mux.HandleFunc("GET /api/admin/users", s.withAdmin(s.handleAdminUsersList))
	mux.HandleFunc("POST /api/admin/users", s.withAdmin(s.handleAdminUsersCreate))
	mux.HandleFunc("PUT /api/admin/users/{id}/role", s.withAdmin(s.handleAdminUserRole))
	mux.HandleFunc("POST /api/admin/users/{id}/deactivate", s.withAdmin(s.handleAdminUserDeactivate))
	mux.HandleFunc("POST /api/admin/users/{id}/reactivate", s.withAdmin(s.handleAdminUserReactivate))
	mux.HandleFunc("GET /api/admin/sso", s.withAdmin(s.handleAdminSSOGet))
	mux.HandleFunc("PUT /api/admin/sso", s.withAdmin(s.handleAdminSSOPut))
	mux.HandleFunc("GET /api/audit", s.withAdmin(s.handleAuditList))
	mux.HandleFunc("GET /api/audit/verify", s.withAdmin(s.handleAuditVerify))

	return s.corsMiddleware(mux)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, If-Match")
		w.Header().Set("Access-Control-Expose-Headers", "ETag")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeJSON formats and sends a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// clientIP extracts the client's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// startSession issues session token & CSRF token cookies.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID string) error {
	tokBytes := make([]byte, 24)
	if _, err := rand.Read(tokBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokBytes)

	csrfBytes := make([]byte, 24)
	if _, err := rand.Read(csrfBytes); err != nil {
		return err
	}
	csrfToken := hex.EncodeToString(csrfBytes)

	now := time.Now().UTC()
	s.sessMu.Lock()
	s.sessions[token] = Session{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
		CSRFToken: csrfToken,
	}
	s.sessMu.Unlock()

	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "kypass_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	return nil
}

func isRequestSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// currentUser extracts the user from the session cookie or Bearer token.
func (s *Server) currentUser(r *http.Request) (users.User, bool) {
	token := ""
	if cookie, err := r.Cookie("kypass_session"); err == nil && cookie.Value != "" {
		token = cookie.Value
	} else if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimPrefix(authHdr, "Bearer ")
	}

	if token == "" {
		return users.User{}, false
	}

	s.sessMu.RLock()
	sess, ok := s.sessions[token]
	s.sessMu.RUnlock()

	if !ok || time.Now().UTC().After(sess.ExpiresAt) {
		return users.User{}, false
	}

	u, err := s.users.Get(sess.UserID)
	if err != nil || !u.Active {
		return users.User{}, false
	}

	return u, true
}

// withAuth enforces authenticated session.
func (s *Server) withAuth(next func(http.ResponseWriter, *http.Request, users.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.currentUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, u)
	}
}

// withAdmin enforces admin role.
func (s *Server) withAdmin(next func(http.ResponseWriter, *http.Request, users.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.currentUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if u.Role != users.RoleAdmin {
			http.Error(w, "forbidden: admin privileges required", http.StatusForbidden)
			return
		}
		next(w, r, u)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
