package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Busness-app/kypassword-server/internal/users"
	"github.com/Busness-app/kypassword-server/internal/vault"
)

func (s *Server) handlePairingStart(w http.ResponseWriter, r *http.Request, u users.User) {
	session, err := s.devices.CreatePairingSession(u.ID)
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
	dev, err := s.devices.RedeemPairing(req.CodeOrPIN, req.DeviceName, req.Platform, ip)
	if err != nil {
		// Within the source's audit budget: redeem takes no credential, and a wrong
		// code costs the store nothing until this record. See audit_budget.go.
		s.recordAnonymousRejection(r, "device.pairing_failed", ip, "failed pairing redeem: "+err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	// Mint initial session for device
	tokBytes, _ := s.startSessionWithToken(dev.UserID)

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

func (s *Server) startSessionWithToken(userID string) (string, error) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	tokBytes := randomHex(24)
	csrfBytes := randomHex(24)

	now := time.Now().UTC()
	s.sessions[tokBytes] = Session{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(90 * 24 * time.Hour), // 90-day device session
		CSRFToken: csrfBytes,
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
