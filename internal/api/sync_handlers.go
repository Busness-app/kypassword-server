package api

import (
	"errors"
	"github.com/Busness-app/ky-primitives/syncauth"
	"io"
	"net/http"
	"strconv"
	"strings"

	kysync "github.com/Busness-app/kypassword-server/internal/sync"
	"github.com/Busness-app/kypassword-server/internal/users"
)

// syncSecrets lists the secrets a replication request may be authenticated with, in
// preference order: the pairing secret, then the KySignOn client secret.
func (s *Server) syncSecrets() []string {
	var out []string
	if s.pairingSecret != "" {
		out = append(out, s.pairingSecret)
	}
	if cs := s.ssoStore.Load().ClientSecret; cs != "" {
		out = append(out, cs)
	}
	return out
}

// scimRole maps a KySignOn role onto a KyPassword role. Anything that is not literally
// "admin" is an ordinary user; an unrecognised role must never widen access.
func scimRole(role string) users.Role {
	if strings.EqualFold(role, "admin") {
		return users.RoleAdmin
	}
	return users.RoleUser
}

func truncate(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

// provisionFromSCIM creates the local account for a replicated KySignOn identity. The
// username is advisory — the sub is the identity — so a collision is resolved by
// suffixing, never by adopting the account that already holds the name.
func (s *Server) provisionFromSCIM(u kysync.SCIMUser) (users.User, error) {
	username := u.Username
	if username == "" {
		username = "user_" + truncate(u.ID, 8)
	}

	created, err := s.users.CreateDirectoryUser(username, scimRole(u.Role), u.ID, u.Username, u.Email, u.Active)
	if errors.Is(err, users.ErrUsernameTaken) {
		created, err = s.users.CreateDirectoryUser(username+"_"+truncate(u.ID, 6), scimRole(u.Role), u.ID, u.Username, u.Email, u.Active)
	}
	if err != nil {
		return users.User{}, err
	}

	return created, nil
}

// handleSyncWebhook applies a bare SCIM resource only after syncauth verified the event.
func (s *Server) handleSyncWebhook(w http.ResponseWriter, r *http.Request) {
	verified, ok := syncauth.EventFromContext(r)
	if !ok {
		http.Error(w, "unverified sync event", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	event := verified.Type
	switch event {
	case "user.created", "user.updated", "user.deleted":
	default:
		s.record(r, "sync.bad_event", "", "", clientIP(r), "unrecognised replication event "+strconv.Quote(event))
		http.Error(w, "unrecognised replication event", http.StatusBadRequest)
		return
	}

	u, err := kysync.ParseSCIMUser(body)
	if err != nil {
		http.Error(w, "invalid SCIM user resource: "+err.Error(), http.StatusBadRequest)
		return
	}

	switch event {
	case "user.created":
		if existing, errGet := s.users.GetBySSOSub(u.ID); errGet == nil {
			if existing.SCIMDeleted {
				if err := s.applySCIMUpdate(existing, u); err != nil {
					http.Error(w, "failed to restore directory account", http.StatusInternalServerError)
					return
				}
				s.record(r, "sync.user_created", existing.ID, "", clientIP(r), "restored retained directory account")
				break
			}
			// KySignOn treats 409 on a create as success, so a retried event settles here
			// instead of provisioning a second account.
			s.record(r, "sync.create_duplicate", existing.ID, "", clientIP(r), "replication re-sent create for subject "+u.ID)
			http.Error(w, "an account already exists for this subject", http.StatusConflict)
			return
		}
		created, errCreate := s.provisionFromSCIM(u)
		if errCreate != nil {
			http.Error(w, "failed to provision account: "+errCreate.Error(), http.StatusInternalServerError)
			return
		}
		s.record(r, "sync.user_created", created.ID, "", clientIP(r), "provisioned "+created.Username+" from KySignOn")

	case "user.updated":
		existing, errGet := s.users.GetBySSOSub(u.ID)
		if errors.Is(errGet, users.ErrNotFound) {
			// An update for a subject we never saw created. Provisioning it heals a create
			// that never arrived — but only where first-login provisioning is allowed at
			// all, or replication would be a way around that setting. A 404 here is not an
			// option: KySignOn forgives 404 only on a delete, so it would retry forever.
			if !s.ssoStore.Load().AutoProvision {
				s.record(r, "sync.update_ignored", "", "", clientIP(r), "update for unknown subject "+u.ID+" ignored; auto-provisioning is off")
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provisioned": false})
				return
			}
			created, errCreate := s.provisionFromSCIM(u)
			if errCreate != nil {
				http.Error(w, "failed to provision account: "+errCreate.Error(), http.StatusInternalServerError)
				return
			}
			s.record(r, "sync.user_created", created.ID, "", clientIP(r), "provisioned "+created.Username+" from a KySignOn update")
			break
		}
		if errGet != nil {
			http.Error(w, "failed to look up account: "+errGet.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.applySCIMUpdate(existing, u); err != nil {
			http.Error(w, "failed to apply update: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.record(r, "sync.user_updated", existing.ID, "", clientIP(r), "applied KySignOn update for "+existing.Username)

	case "user.deleted":
		existing, errGet := s.users.GetBySSOSub(u.ID)
		if errGet != nil {
			// KySignOn treats 404 on a delete as success, so this ends the event rather
			// than leaving it to retry.
			http.Error(w, "no account for this subject", http.StatusNotFound)
			return
		}
		// Deactivate, never delete. A replication event must never destroy vault data: the
		// vault is the user's, not the directory's, and a deletion in KySignOn is not
		// consent to erase it.
		if err := s.users.UpdateDirectory(existing.ID, existing.Role, false, existing.SSOUsername, existing.SSOEmail, true); err != nil {
			http.Error(w, "failed to deactivate account: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.revokeDirectorySessions(existing.ID)
		s.record(r, "sync.user_deleted", existing.ID, "", clientIP(r), "deactivated "+existing.Username+" on KySignOn deletion; vault retained")
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// applySCIMUpdate brings a local account in line with the replicated resource. It matches
// on the sub alone; username and email are attributes of the identity, never keys for it.
func (s *Server) applySCIMUpdate(existing users.User, u kysync.SCIMUser) error {
	if err := s.users.UpdateDirectory(existing.ID, scimRole(u.Role), u.Active, u.Username, u.Email, false); err != nil {
		return err
	}
	if !u.Active {
		s.revokeDirectorySessions(existing.ID)
	}
	return nil
}
