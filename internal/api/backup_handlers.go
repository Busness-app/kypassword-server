package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kypassword-server/internal/backup"
	"github.com/Busness-app/kypassword-server/internal/users"
)

const depositWriteBudget = 16 * time.Minute

func (s *Server) requireBackupCSRF(w http.ResponseWriter, r *http.Request) bool {
	if s.validCSRF(r) {
		return true
	}
	http.Error(w, "invalid CSRF token", http.StatusForbidden)
	return false
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, _ *http.Request, _ users.User) {
	status, err := s.backupState.Status()
	if err != nil {
		http.Error(w, "failed to read backup status", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleBackupDrill(w http.ResponseWriter, r *http.Request, u users.User) {
	if !s.requireBackupCSRF(w, r) {
		return
	}
	result, err := backup.RunDrill(r.Context(), s.backupService.Collector)
	details := "passed"
	if err != nil {
		details = backup.AuditSafe(err.Error())
	}
	s.record(r, "backup.drill", u.ID, "", clientIP(r), details)
	if err != nil {
		http.Error(w, "restore drill failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExportCapsule(w http.ResponseWriter, r *http.Request, u users.User) {
	if !s.requireBackupCSRF(w, r) {
		return
	}
	key, err := s.backupState.RecoveryKey()
	if err != nil {
		s.writeBackupError(w, err)
		return
	}
	files, deps, recipe, err := s.backupService.Collector.Collect()
	if err != nil {
		http.Error(w, "failed to collect backup", http.StatusInternalServerError)
		return
	}
	raw, manifest, err := backup.Seal(files, deps, recipe, s.backupService.Collector.AppVersion, key)
	if err != nil {
		s.writeBackupError(w, err)
		return
	}
	if _, err := s.audit.Log(r.Context(), "backup.exported", u.ID, "", clientIP(r), "capsule="+backup.AuditSafe(manifest.CapsuleID)); err != nil {
		http.Error(w, "capsule export refused because audit recording failed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.kycap"`, backup.FilenameSafe(manifest.CapsuleID)))
	w.Header().Set("X-Recovery-Key-ID", manifest.RecoveryKeyID)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

type pairRemoteRequest struct {
	RecoveryURL string `json:"recoveryUrl"`
	PairingCode string `json:"pairingCode"`
}

func (s *Server) handlePairRemoteRecovery(w http.ResponseWriter, r *http.Request, u users.User) {
	if !s.requireBackupCSRF(w, r) {
		return
	}
	var request pairRemoteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil || dec.Decode(&struct{}{}) != io.EOF || request.RecoveryURL == "" || len(request.PairingCode) != 6 ||
		strings.IndexFunc(request.PairingCode, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		http.Error(w, "invalid pairing request", http.StatusBadRequest)
		return
	}
	result, err := s.recovery.Claim(r.Context(), request.RecoveryURL, request.PairingCode)
	if err == nil {
		err = s.backupState.StorePairing(request.RecoveryURL, result.Token, result.Key)
	}
	if err != nil {
		s.record(r, "backup.pair_failed", u.ID, "", clientIP(r), backup.AuditSafe(err.Error()))
		if errors.Is(err, fs.ErrExist) {
			http.Error(w, "already paired to a different recovery key", http.StatusConflict)
		} else if errors.Is(err, backup.ErrInvalidURL) || strings.Contains(err.Error(), "pairing code must") {
			http.Error(w, "invalid KyRecovery URL or pairing code", http.StatusBadRequest)
		} else if errors.Is(err, backup.ErrRemote) {
			http.Error(w, "KyRecovery pairing failed", http.StatusBadGateway)
		} else {
			http.Error(w, "failed to persist recovery pairing", http.StatusInternalServerError)
		}
		return
	}
	s.record(r, "backup.paired", u.ID, "", clientIP(r), "recovery_key_id="+result.Key.Public.ID())
	status, _ := s.backupState.Status()
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleDepositBackup(w http.ResponseWriter, r *http.Request, u users.User) {
	if !s.requireBackupCSRF(w, r) {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(depositWriteBudget))
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), depositWriteBudget)
	defer cancel()
	receipt, manifest, err := s.backupService.Deposit(ctx)
	action, resource, details := backup.Outcome(receipt, manifest, err)
	s.recordCtx(ctx, action, u.ID, "", clientIP(r), backup.AuditSafe("capsule="+resource+" "+details))
	if err != nil {
		if errors.Is(err, backup.ErrReceiptUnrecorded) {
			log.Printf("[BACKUP] capsule %s deposited but receipt was not recorded", receipt.CapsuleID)
			http.Error(w, fmt.Sprintf("capsule %s was deposited but its receipt was not recorded", receipt.CapsuleID), http.StatusInternalServerError)
			return
		}
		s.writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) writeBackupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, backup.ErrNotPaired):
		http.Error(w, "not paired with KyRecovery", http.StatusPreconditionFailed)
	case errors.Is(err, backup.ErrKeyPinMissing), errors.Is(err, backup.ErrKeyMismatch), errors.Is(err, backup.ErrDepositInProgress):
		http.Error(w, "backup pairing is degraded or busy", http.StatusConflict)
	case errors.Is(err, capsule.ErrCapsuleTooLarge):
		http.Error(w, "backup exceeds capsule size limits", http.StatusRequestEntityTooLarge)
	case errors.Is(err, backup.ErrRemote):
		http.Error(w, "KyRecovery did not accept the operation", http.StatusBadGateway)
	default:
		http.Error(w, "backup operation failed", http.StatusInternalServerError)
	}
}

// RunScheduledDeposit performs one timer-driven deposit. Only a never-paired
// instance is silent; degraded pairing and remote failures remain visible.
func (s *Server) RunScheduledDeposit(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), depositWriteBudget)
	defer cancel()
	receipt, manifest, err := s.backupService.Deposit(ctx)
	if errors.Is(err, backup.ErrNotPaired) {
		return
	}
	action, resource, details := backup.Outcome(receipt, manifest, err)
	s.recordCtx(ctx, action, "system", "", "", backup.AuditSafe("capsule="+resource+" "+details))
	if err != nil {
		log.Printf("[BACKUP] scheduled deposit failed: %s", backup.AuditSafe(err.Error()))
		return
	}
	log.Printf("[BACKUP] deposited capsule %s (%d bytes)", receipt.CapsuleID, receipt.SizeBytes)
}

func (s *Server) WaitForBackups() { s.backupService.Wait() }
