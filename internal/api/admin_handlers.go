package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"kypassword-server/internal/sso"
	"kypassword-server/internal/users"
)

func (s *Server) handleAdminUsersList(w http.ResponseWriter, r *http.Request, admin users.User) {
	list := s.users.List()
	res := make([]users.Public, len(list))
	for i, u := range list {
		res[i] = u.Public()
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleAdminUsersCreate(w http.ResponseWriter, r *http.Request, admin users.User) {
	var req struct {
		Username string     `json:"username"`
		Password string     `json:"password"`
		Role     users.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "invalid user payload", http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		req.Role = users.RoleUser
	}

	u, err := s.users.Create(req.Username, req.Password, req.Role)
	if err != nil {
		http.Error(w, "failed to create user: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, _ = s.audit.Log("admin.user_created", admin.ID, "", clientIP(r), "created user "+u.Username)
	writeJSON(w, http.StatusOK, u.Public())
}

func (s *Server) handleAdminUserRole(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	var req struct {
		Role users.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Role != users.RoleAdmin && req.Role != users.RoleUser) {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}

	if err := s.users.SetRole(id, req.Role); err != nil {
		http.Error(w, "failed to update role: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("admin.user_role_updated", admin.ID, "", clientIP(r), "updated role for user "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminUserDeactivate(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	if err := s.users.Deactivate(id); err != nil {
		http.Error(w, "failed to deactivate user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = s.audit.Log("admin.user_deactivated", admin.ID, "", clientIP(r), "deactivated user "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminUserReactivate(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	if err := s.users.Reactivate(id); err != nil {
		http.Error(w, "failed to reactivate user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = s.audit.Log("admin.user_reactivated", admin.ID, "", clientIP(r), "reactivated user "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminSSOGet(w http.ResponseWriter, r *http.Request, admin users.User) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleAdminSSOPut(w http.ResponseWriter, r *http.Request, admin users.User) {
	var req sso.SSOSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := s.ssoStore.Save(req); err != nil {
		http.Error(w, "failed to save SSO settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("admin.sso_configured", admin.ID, "", clientIP(r), "updated SSO configuration")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": req})
}

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request, admin users.User) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	entries, err := s.audit.List(limit)
	if err != nil {
		http.Error(w, "failed to read audit logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request, admin users.User) {
	ok, err := s.audit.VerifyIntegrity()
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": ok,
		"error": func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})
}

type SyncUserPayload struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
	Email    string `json:"email"`
}

type SyncWebhookEvent struct {
	Event string          `json:"event"`
	User  SyncUserPayload `json:"user"`
}

func (s *Server) handleSyncWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<18))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	authHeader := r.Header.Get("Authorization")
	sigHeader := r.Header.Get("X-Sync-Signature")

	authorized := false
	if s.pairingSecret != "" {
		if authHeader == "Bearer "+s.pairingSecret {
			authorized = true
		} else if sigHeader != "" {
			mac := hmac.New(sha256.New, []byte(s.pairingSecret))
			mac.Write(body)
			expectedSig := hex.EncodeToString(mac.Sum(nil))
			if hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
				authorized = true
			}
		}
	}

	if !authorized {
		ssoSettings := s.ssoStore.Load()
		if ssoSettings.ClientSecret != "" {
			if authHeader == "Bearer "+ssoSettings.ClientSecret {
				authorized = true
			} else if sigHeader != "" {
				mac := hmac.New(sha256.New, []byte(ssoSettings.ClientSecret))
				mac.Write(body)
				expectedSig := hex.EncodeToString(mac.Sum(nil))
				if hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
					authorized = true
				}
			}
		}
	}

	if !authorized {
		http.Error(w, "unauthorized sync request", http.StatusUnauthorized)
		return
	}

	var ev SyncWebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	switch ev.Event {
	case "user.created":
		if _, err := s.users.GetBySSOSub(ev.User.ID); err != nil {
			role := users.RoleUser
			if strings.EqualFold(ev.User.Role, "admin") {
				role = users.RoleAdmin
			}
			_, _ = s.users.CreateSSOUser(ev.User.Username, role, ev.User.ID, ev.User.Username, ev.User.Email)
		}
	case "user.updated":
		if u, err := s.users.GetBySSOSub(ev.User.ID); err == nil {
			role := users.RoleUser
			if strings.EqualFold(ev.User.Role, "admin") {
				role = users.RoleAdmin
			}
			if u.Role != role {
				_ = s.users.SetRole(u.ID, role)
			}
			if ev.User.Active && !u.Active {
				_ = s.users.Reactivate(u.ID)
			} else if !ev.User.Active && u.Active {
				_ = s.users.Deactivate(u.ID)
			}
		}
	case "user.deleted":
		if u, err := s.users.GetBySSOSub(ev.User.ID); err == nil {
			_ = s.users.Deactivate(u.ID)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
