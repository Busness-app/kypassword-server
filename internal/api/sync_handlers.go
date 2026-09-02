package api

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	kysync "kypassword-server/internal/sync"
	"kypassword-server/internal/users"
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

	created, err := s.users.CreateSSOUser(username, scimRole(u.Role), u.ID, u.Username, u.Email)
	if errors.Is(err, users.ErrUsernameTaken) {
		created, err = s.users.CreateSSOUser(username+"_"+truncate(u.ID, 6), scimRole(u.Role), u.ID, u.Username, u.Email)
	}
	if err != nil {
		return users.User{}, err
	}

	if !u.Active {
		if err := s.users.Deactivate(created.ID); err != nil {
			return users.User{}, err
		}
		created.Active = false
	}
	return created, nil
}

// handleSyncWebhook receives account replication from KySignOn.
//
// The wire format is KySignOn's, not ours: a bare SCIM 2.0 User resource, the event in
// X-KySignOn-Event-Type, and an HMAC over `timestamp + "." + body` in X-KySignOn-Signature.
// See AGENTS.md. This handler previously expected a format nobody sent, so it matched no
// event and returned 200 while doing nothing. An unrecognised event is now a 400.
func (s *Server) handleSyncWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<18))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	secrets := s.syncSecrets()
	signature := kysync.Signature(r)

	authorized, unsigned := false, false
	if signature != "" {
		timestamp := kysync.Timestamp(r)
		for _, secret := range secrets {
			if kysync.VerifySignature(secret, timestamp, body, signature) == nil {
				authorized = true
				break
			}
		}
	} else {
		// No signature header at all means a paired system from before signing. Accept the
		// bearer token so an existing deployment keeps replicating, and record that it
		// arrived unsigned. A signature that is present but wrong is always a rejection.
		auth := []byte(r.Header.Get("Authorization"))
		for _, secret := range secrets {
			if subtle.ConstantTimeCompare(auth, []byte("Bearer "+secret)) == 1 {
				authorized, unsigned = true, true
				break
			}
		}
	}

	if !authorized {
		_, _ = s.audit.Log("sync.rejected", "", "", clientIP(r), "replication request failed authentication")
		http.Error(w, "unauthorized sync request", http.StatusUnauthorized)
		return
	}
	if unsigned {
		_, _ = s.audit.Log("sync.unsigned", "", "", clientIP(r), "replication request accepted on bearer token with no signature")
	}

	event := kysync.EventType(r)
	switch event {
	case "user.created", "user.updated", "user.deleted":
	default:
		_, _ = s.audit.Log("sync.bad_event", "", "", clientIP(r), "unrecognised replication event "+strconv.Quote(event))
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
			// KySignOn treats 409 on a create as success, so a retried event settles here
			// instead of provisioning a second account.
			_, _ = s.audit.Log("sync.create_duplicate", existing.ID, "", clientIP(r), "replication re-sent create for subject "+u.ID)
			http.Error(w, "an account already exists for this subject", http.StatusConflict)
			return
		}
		created, errCreate := s.provisionFromSCIM(u)
		if errCreate != nil {
			http.Error(w, "failed to provision account: "+errCreate.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = s.audit.Log("sync.user_created", created.ID, "", clientIP(r), "provisioned "+created.Username+" from KySignOn")

	case "user.updated":
		existing, errGet := s.users.GetBySSOSub(u.ID)
		if errors.Is(errGet, users.ErrNotFound) {
			// An update for a subject we never saw created. Provisioning it heals a create
			// that never arrived — but only where first-login provisioning is allowed at
			// all, or replication would be a way around that setting. A 404 here is not an
			// option: KySignOn forgives 404 only on a delete, so it would retry forever.
			if !s.ssoStore.Load().AutoProvision {
				_, _ = s.audit.Log("sync.update_ignored", "", "", clientIP(r), "update for unknown subject "+u.ID+" ignored; auto-provisioning is off")
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provisioned": false})
				return
			}
			created, errCreate := s.provisionFromSCIM(u)
			if errCreate != nil {
				http.Error(w, "failed to provision account: "+errCreate.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = s.audit.Log("sync.user_created", created.ID, "", clientIP(r), "provisioned "+created.Username+" from a KySignOn update")
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
		_, _ = s.audit.Log("sync.user_updated", existing.ID, "", clientIP(r), "applied KySignOn update for "+existing.Username)

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
		if err := s.users.Deactivate(existing.ID); err != nil {
			http.Error(w, "failed to deactivate account: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = s.audit.Log("sync.user_deleted", existing.ID, "", clientIP(r), "deactivated "+existing.Username+" on KySignOn deletion; vault retained")
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// applySCIMUpdate brings a local account in line with the replicated resource. It matches
// on the sub alone; username and email are attributes of the identity, never keys for it.
func (s *Server) applySCIMUpdate(existing users.User, u kysync.SCIMUser) error {
	if role := scimRole(u.Role); existing.Role != role {
		if err := s.users.SetRole(existing.ID, role); err != nil {
			return err
		}
	}
	if u.Active && !existing.Active {
		if err := s.users.Reactivate(existing.ID); err != nil {
			return err
		}
	} else if !u.Active && existing.Active {
		if err := s.users.Deactivate(existing.ID); err != nil {
			return err
		}
	}
	if existing.SSOUsername != u.Username || existing.SSOEmail != u.Email {
		return s.users.LinkSSO(existing.ID, existing.SSOSub, u.Username, u.Email)
	}
	return nil
}
