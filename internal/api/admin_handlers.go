package api

import (
	"encoding/json"
	"net/http"
	"strconv"

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
