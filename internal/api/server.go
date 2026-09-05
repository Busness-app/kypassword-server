package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Busness-app/kypassword-server/internal/audit"
	"github.com/Busness-app/kypassword-server/internal/backup"
	"github.com/Busness-app/kypassword-server/internal/devices"
	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
	"github.com/Busness-app/kypassword-server/internal/vault"
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
	backupState   *backup.StateStore
	backupService *backup.Service
	recovery      backup.RecoveryClient
	pairingSecret string

	// auditFailures counts audit writes that did not reach the log. Sticky: the
	// missing record never comes back, so only a restart — after someone has
	// looked — clears it. It is reported, never acted on: see handleHealth for why
	// a sticky counter must not be allowed to take a credential vault out of service.
	auditFailures atomic.Int64

	// rejects bounds the audit writes an unauthenticated caller can cause, and
	// flushStop/flushDone run the periodic flush that keeps the folded ones from
	// being lost. See audit_budget.go.
	rejects   *auditBudget
	flushStop chan struct{}
	flushDone chan struct{}
	closeOnce sync.Once

	sessMu   sync.RWMutex
	sessions map[string]Session // token -> Session
}

// Config holds initialization paths and secrets for Server.
type Config struct {
	DataDir       string
	ConfigDir     string
	PairingSecret string
	RetentionDays int
	AppVersion    string
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
	if cfg.AppVersion == "" {
		cfg.AppVersion = "dev"
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

	aStore, err := audit.NewStore(cfg.DataDir+"/audit", cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("init audit store: %w", err)
	}

	ssoSt := sso.NewStore(cfg.ConfigDir)
	backupState := backup.NewStateStore(cfg.ConfigDir)
	recovery := backup.NewClient()
	collector := backup.Collector{
		Vault: vStore, Audit: aStore, Users: uStore, Devices: dStore, SSO: ssoSt,
		State: backupState, PairingSecret: cfg.PairingSecret, RetentionDays: cfg.RetentionDays,
		AppVersion: cfg.AppVersion,
	}

	s := &Server{
		users:         uStore,
		vault:         vStore,
		devices:       dStore,
		audit:         aStore,
		ssoStore:      ssoSt,
		backupState:   backupState,
		recovery:      recovery,
		pairingSecret: cfg.PairingSecret,
		sessions:      make(map[string]Session),
		rejects:       newAuditBudget(auditBudgetWindow, auditBudgetBurst),
		flushStop:     make(chan struct{}),
		flushDone:     make(chan struct{}),
	}
	s.backupService = &backup.Service{State: backupState, Collector: collector, Client: recovery}
	go s.flushSuppressed()

	return s, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public auth. KySignOn is the only way in: there is no local login, no login
	// parameters to fetch, no recovery-as-site-access and no first-run setup. Paper
	// recovery still works, client-side, against the vault key envelope.
	mux.HandleFunc("GET /api/auth/sso-config", s.handleSSOConfig)
	mux.HandleFunc("GET /api/auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/sso/login", s.handleSSOLogin)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/sso/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// Self & Session. Changing the master password is a client-side re-wrap of the vault
	// key envelope against PUT /api/vault/envelopes; the server has no password to change.
	// Unlinking SSO is gone too — it would only be a way to lock yourself out for good.
	mux.HandleFunc("GET /api/auth/me", s.withAuth(s.handleMe))
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))

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
	mux.HandleFunc("PUT /api/admin/users/{id}/role", s.withAdmin(s.handleAdminUserRole))
	mux.HandleFunc("POST /api/admin/users/{id}/deactivate", s.withAdmin(s.handleAdminUserDeactivate))
	mux.HandleFunc("POST /api/admin/users/{id}/reactivate", s.withAdmin(s.handleAdminUserReactivate))
	mux.HandleFunc("GET /api/admin/sso", s.withAdmin(s.handleAdminSSOGet))
	mux.HandleFunc("PUT /api/admin/sso", s.withAdmin(s.handleAdminSSOPut))
	mux.HandleFunc("GET /api/audit", s.withAdmin(s.handleAuditList))
	mux.HandleFunc("GET /api/audit/verify", s.withAdmin(s.handleAuditVerify))
	mux.HandleFunc("POST /api/backup/drill", s.withAdmin(s.handleBackupDrill))
	mux.HandleFunc("GET /api/backup/export-capsule", s.withFreshAdmin(s.handleExportCapsule))
	mux.HandleFunc("POST /api/backup/pair-remote", s.withFreshAdmin(s.handlePairRemoteRecovery))
	mux.HandleFunc("POST /api/backup/deposit", s.withFreshAdmin(s.handleDepositBackup))
	mux.HandleFunc("GET /api/backup/status", s.withAdmin(s.handleBackupStatus))

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

// record writes an audit entry and makes a failed write impossible to miss.
//
// It does not fail the request. Every call site records an operation the server has
// already carried out, so a 500 would not undo it — it would ask the client to retry
// something that already happened, and the retry would be just as unrecorded. Several
// call sites record a rejection — sync.rejected, device.pairing_failed — where a 500
// would turn "you are not authorised" into "the server is broken" and tell an attacker
// the log is down.
//
// What a lost record does change is what the operator and the auditor are told. The
// failure goes to stderr with its cause and the running count, and GET /api/audit/verify
// — which is admin-only, and the one place someone asks whether the trail is sound —
// carries the count, because VerifyIntegrity cannot see a record that never reached the
// log. GET /api/health does not carry it: it takes no credential, and a caller filling
// the disk must not be able to watch the filling work.
// TestFailedAuditWriteIsReportedOnlyToAnAdmin pins all three.
//
// Rejections recorded before any credential is checked go through
// recordAnonymousRejection instead, which bounds what they cost.
func (s *Server) record(r *http.Request, action, userID, deviceID, ip, details string) {
	s.recordCtx(r.Context(), action, userID, deviceID, ip, details)
}

// recordCtx is record for a call site that has no request — the periodic flush.
func (s *Server) recordCtx(ctx context.Context, action, userID, deviceID, ip, details string) {
	if _, err := s.audit.Log(ctx, action, userID, deviceID, ip, details); err != nil {
		n := s.auditFailures.Add(1)
		// details is left out on purpose: it carries operation content, and both the
		// audit records and these logs are content-blind.
		log.Printf("AUDIT WRITE FAILED (%d since start) action=%s user=%s device=%s ip=%s: %v",
			n, action, userID, deviceID, ip, err)
	}
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

func requestHost(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.Host
}

// currentUser extracts the user from the session cookie or Bearer token.
// currentSession resolves the request's unexpired session from the cookie or bearer token.
func (s *Server) currentSession(r *http.Request) (Session, bool) {
	token := ""
	if cookie, err := r.Cookie("kypass_session"); err == nil && cookie.Value != "" {
		token = cookie.Value
	} else if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimPrefix(authHdr, "Bearer ")
	}
	if token == "" {
		return Session{}, false
	}

	s.sessMu.RLock()
	sess, ok := s.sessions[token]
	s.sessMu.RUnlock()

	if !ok || time.Now().UTC().After(sess.ExpiresAt) {
		return Session{}, false
	}
	return sess, true
}

func (s *Server) currentUser(r *http.Request) (users.User, bool) {
	sess, ok := s.currentSession(r)
	if !ok {
		return users.User{}, false
	}

	u, err := s.users.Get(sess.UserID)
	if err != nil || !u.Active {
		return users.User{}, false
	}

	return u, true
}

// validCSRF protects cookie-authenticated state changes. Bearer callers are not
// vulnerable to ambient-cookie CSRF and do not need the browser token.
func (s *Server) validCSRF(r *http.Request) bool {
	sessionCookie, err := r.Cookie("kypass_session")
	if err != nil || sessionCookie.Value == "" {
		return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	csrfCookie, err := r.Cookie("csrf_token")
	if err != nil || csrfCookie.Value == "" {
		return false
	}
	s.sessMu.RLock()
	session, ok := s.sessions[sessionCookie.Value]
	s.sessMu.RUnlock()
	header := r.Header.Get("X-CSRF-Token")
	return ok && subtle.ConstantTimeCompare([]byte(header), []byte(csrfCookie.Value)) == 1 &&
		subtle.ConstantTimeCompare([]byte(header), []byte(session.CSRFToken)) == 1
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

// freshSessionWindow is how recently an admin must have signed in to move or expose backup
// material. KyPassword has no password of its own to re-prompt for, so a stale admin is sent
// back through KySignOn instead.
const freshSessionWindow = 10 * time.Minute

// withFreshAdmin is withAdmin for destructive backup routes.
func (s *Server) withFreshAdmin(next func(http.ResponseWriter, *http.Request, users.User)) http.HandlerFunc {
	return s.withAdmin(func(w http.ResponseWriter, r *http.Request, u users.User) {
		sess, _ := s.currentSession(r)
		if time.Since(sess.IssuedAt) > freshSessionWindow {
			http.Error(w, "re-authenticate to continue: sign in again through KySignOn", http.StatusForbidden)
			return
		}
		next(w, r, u)
	})
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
