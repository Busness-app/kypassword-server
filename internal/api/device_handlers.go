package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Busness-app/kyvault-server/internal/sso"
	"github.com/Busness-app/kyvault-server/internal/users"
	"github.com/Busness-app/kyvault-server/internal/vault"
)

func (s *Server) handlePairingStart(w http.ResponseWriter, r *http.Request, u users.User) {
	// withAuth resolved the session under its own lock; a logout can land between
	// that read and this one, and a pairing must not outlive the session it came from.
	current, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	origin, err := json.Marshal(current.SSO)
	if err != nil {
		http.Error(w, "failed to create pairing session", http.StatusInternalServerError)
		return
	}
	session, err := s.devices.CreatePairingSession(u.ID, string(origin))
	if err != nil {
		http.Error(w, "failed to create pairing session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "device.pairing_initiated", u.ID, "", clientIP(r), "pairing code issued")
	writeJSON(w, http.StatusOK, map[string]any{
		"pin":       session.PIN,
		"secret":    session.Secret,
		"expiresAt": session.ExpiresAt,
	})
}

type PairingRedeemRequest struct {
	CodeOrPIN      string `json:"codeOrPin"`
	DeviceName     string `json:"deviceName"`
	Platform       string `json:"platform"`
	DeviceEnvelope string `json:"deviceEnvelope,omitempty"`
}

func (s *Server) handlePairingRedeem(w http.ResponseWriter, r *http.Request) {
	var req PairingRedeemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CodeOrPIN == "" {
		http.Error(w, "invalid pairing request", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	dev, origin, err := s.devices.RedeemPairing(req.CodeOrPIN, req.DeviceName, req.Platform, ip)
	if err != nil {
		// Within the source's audit budget: redeem takes no credential, and a wrong
		// code costs the store nothing until this record. See audit_budget.go.
		s.recordAnonymousRejection(r, "device.pairing_failed", ip, "failed pairing redeem: "+err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Mint only while the directory account is still active and the browser session
	// that started the pairing has not been logged out by KySignOn meanwhile.
	var id sso.Identity
	if err := json.Unmarshal([]byte(origin), &id); err != nil {
		_ = s.devices.Revoke(dev.ID)
		http.Error(w, "invalid pairing origin", http.StatusBadRequest)
		return
	}
	tokBytes, err := s.startSessionWithToken(dev.UserID, id)
	if err != nil {
		_ = s.devices.Revoke(dev.ID)
		http.Error(w, "account is inactive or signed out", http.StatusUnauthorized)
		return
	}

	// If device envelope provided, save it to vault metadata
	if req.DeviceEnvelope != "" {
		_ = s.vault.SetDeviceEnvelope(dev.UserID, vault.DeviceEnvelope{
			DeviceID: dev.ID,
			Name:     dev.Name,
			Envelope: req.DeviceEnvelope,
		})
	}

	s.record(r, "device.paired", dev.UserID, dev.ID, ip, fmt.Sprintf("paired device %s (%s)", dev.Name, dev.Platform))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"deviceId":     dev.ID,
		"sessionToken": tokBytes,
		"user": map[string]any{
			"id": dev.UserID,
		},
	})
}

func (s *Server) startSessionWithToken(userID string, id sso.Identity) (string, error) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if u, err := s.users.Get(userID); err != nil || !u.Active {
		return "", fmt.Errorf("account is inactive")
	}
	if !id.Revocable() {
		return "", errors.New("device session needs a revocable identity")
	}
	if s.logouts.Fenced(id, time.Now().UTC()) {
		return "", errLoginFenced
	}

	tokBytes := randomHex(24)
	csrfBytes := randomHex(24)

	now := time.Now().UTC()
	s.sessions[tokBytes] = Session{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(90 * 24 * time.Hour), // 90-day device session
		CSRFToken: csrfBytes,
		SSO:       id,
	}
	return tokBytes, nil
}

func (s *Server) handleDevicesList(w http.ResponseWriter, r *http.Request, u users.User) {
	devs := s.devices.ListUserDevices(u.ID)
	writeJSON(w, http.StatusOK, devs)
}

func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request, u users.User) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		http.Error(w, "missing device id", http.StatusBadRequest)
		return
	}

	dev, err := s.devices.Get(deviceID)
	if err != nil || dev.UserID != u.ID {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	_ = s.devices.Revoke(deviceID)
	_ = s.vault.RemoveDeviceEnvelope(u.ID, deviceID)

	s.record(r, "device.revoked", u.ID, deviceID, clientIP(r), "revoked device "+dev.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
