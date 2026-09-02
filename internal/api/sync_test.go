package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
)

// scimUserResource builds the exact payload kysignon-server's UserToSCIMResource emits.
func scimUserResource(id, username, email, role string, active bool) []byte {
	return []byte(fmt.Sprintf(`{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": %q,
  "externalId": %q,
  "userName": %q,
  "displayName": %q,
  "name": {"formatted": %q},
  "emails": [{"value": %q, "type": "work", "primary": true}],
  "roles": [{"value": %q, "primary": true}],
  "active": %t,
  "meta": {"resourceType": "User"}
}`, id, id, username, username, username, email, role, active))
}

// signedSyncRequest builds a replication request the way KySignOn's deliver() does:
// bearer token, event type header, and an HMAC over `timestamp + "." + body`.
func signedSyncRequest(secret, event string, body []byte) *http.Request {
	ts := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sync/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-KySignOn-Event-Type", event)
	req.Header.Set("X-KySignOn-Timestamp", ts)
	req.Header.Set("X-KySignOn-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-KySignOn-Event-Id", "evt-"+event)
	req.Header.Set("Idempotency-Key", "evt-"+event)
	return req
}

func doSync(t *testing.T, srv *Server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestSyncWebhookProvisionsFromKySignOnSCIMResource(t *testing.T) {
	srv := newTestServer(t)

	body := scimUserResource("kysignon-sub-alice", "alice", "alice@example.com", "admin", true)
	rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("user.created status = %d, body = %s", rec.Code, rec.Body)
	}

	u, err := srv.users.GetBySSOSub("kysignon-sub-alice")
	if err != nil {
		t.Fatalf("account was not provisioned: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("Username = %q, want alice", u.Username)
	}
	if u.Role != users.RoleAdmin {
		t.Errorf("Role = %q, want admin", u.Role)
	}
	if u.SSOEmail != "alice@example.com" {
		t.Errorf("SSOEmail = %q", u.SSOEmail)
	}
	if !u.Active {
		t.Error("account should be active")
	}
}

func TestSyncWebhookRejectsUnknownEventType(t *testing.T) {
	// The old handler let an unrecognised event fall out of its switch and answered 200,
	// which is how replication broke silently. Anything we do not act on must say so.
	srv := newTestServer(t)

	body := scimUserResource("kysignon-sub-bob", "bob", "bob@example.com", "user", true)
	for _, event := range []string{"", "user.renamed", "group.created"} {
		rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, event, body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("event %q status = %d, want 400", event, rec.Code)
		}
	}

	if _, err := srv.users.GetBySSOSub("kysignon-sub-bob"); err == nil {
		t.Error("an unrecognised event must not provision an account")
	}
}

func TestSyncWebhookRejectsBadSignatureDespiteValidBearer(t *testing.T) {
	srv := newTestServer(t)
	body := scimUserResource("kysignon-sub-mallory", "mallory", "m@example.com", "admin", true)

	cases := map[string]func(*http.Request){
		"signature from the wrong secret": func(r *http.Request) {
			ts := r.Header.Get("X-KySignOn-Timestamp")
			mac := hmac.New(sha256.New, []byte("not-the-secret"))
			mac.Write([]byte(ts))
			mac.Write([]byte("."))
			mac.Write(body)
			r.Header.Set("X-KySignOn-Signature", hex.EncodeToString(mac.Sum(nil)))
		},
		"signature over a different body": func(r *http.Request) {
			r.Header.Set("X-KySignOn-Signature", "00"+r.Header.Get("X-KySignOn-Signature")[2:])
		},
		"replayed outside the skew window": func(r *http.Request) {
			old := time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339)
			mac := hmac.New(sha256.New, []byte(srv.pairingSecret))
			mac.Write([]byte(old))
			mac.Write([]byte("."))
			mac.Write(body)
			r.Header.Set("X-KySignOn-Timestamp", old)
			r.Header.Set("X-KySignOn-Signature", hex.EncodeToString(mac.Sum(nil)))
		},
	}

	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			req := signedSyncRequest(srv.pairingSecret, "user.created", body)
			tamper(req) // the Authorization bearer stays valid throughout
			rec := doSync(t, srv, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if _, err := srv.users.GetBySSOSub("kysignon-sub-mallory"); err == nil {
				t.Fatal("a rejected request must not provision an account")
			}
		})
	}
}

func TestSyncWebhookAcceptsUnsignedLegacyBearer(t *testing.T) {
	// A system paired before signing sends no X-KySignOn-Signature at all. It keeps
	// working on its bearer token so an upgrade does not sever replication.
	srv := newTestServer(t)
	body := scimUserResource("kysignon-sub-legacy", "legacy", "l@example.com", "user", true)

	req := httptest.NewRequest(http.MethodPost, "/api/sync/webhook", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+srv.pairingSecret)
	req.Header.Set("X-KySignOn-Event-Type", "user.created")

	if rec := doSync(t, srv, req); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if _, err := srv.users.GetBySSOSub("kysignon-sub-legacy"); err != nil {
		t.Fatalf("account was not provisioned: %v", err)
	}
}

func TestSyncWebhookDuplicateCreateIsConflict(t *testing.T) {
	// KySignOn retries with the same Idempotency-Key and reads 409 on a create as success.
	srv := newTestServer(t)
	body := scimUserResource("kysignon-sub-dup", "dup", "d@example.com", "user", true)

	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", body)); rec.Code != http.StatusOK {
		t.Fatalf("first create status = %d", rec.Code)
	}
	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", body)); rec.Code != http.StatusConflict {
		t.Fatalf("second create status = %d, want 409", rec.Code)
	}
	if n := len(srv.users.List()); n != 1 {
		t.Fatalf("account count = %d, want 1", n)
	}
}

func TestSyncWebhookUpdateAppliesRoleAndActive(t *testing.T) {
	srv := newTestServer(t)
	created := scimUserResource("kysignon-sub-eve", "eve", "eve@example.com", "user", true)
	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", created)); rec.Code != http.StatusOK {
		t.Fatalf("create status = %d", rec.Code)
	}

	updated := scimUserResource("kysignon-sub-eve", "eve", "eve@corp.example", "admin", false)
	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.updated", updated)); rec.Code != http.StatusOK {
		t.Fatalf("update status = %d", rec.Code)
	}

	u, err := srv.users.GetBySSOSub("kysignon-sub-eve")
	if err != nil {
		t.Fatalf("GetBySSOSub: %v", err)
	}
	if u.Role != users.RoleAdmin {
		t.Errorf("Role = %q, want admin", u.Role)
	}
	if u.Active {
		t.Error("account should have been deactivated")
	}
	if u.SSOEmail != "eve@corp.example" {
		t.Errorf("SSOEmail = %q, want the updated address", u.SSOEmail)
	}
}

func TestSyncWebhookUpdateForUnknownSubjectHonoursAutoProvision(t *testing.T) {
	// A 404 here is not an option: KySignOn forgives 404 only on a delete, so an update
	// that 404s retries forever. Provisioning heals a lost create, but only where first
	// -login provisioning is allowed at all.
	t.Run("provisions when auto-provision is on", func(t *testing.T) {
		srv := newTestServer(t)
		if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, AutoProvision: true}); err != nil {
			t.Fatalf("Save: %v", err)
		}

		body := scimUserResource("kysignon-sub-heal", "heal", "h@example.com", "user", true)
		if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.updated", body)); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
		}
		if _, err := srv.users.GetBySSOSub("kysignon-sub-heal"); err != nil {
			t.Fatalf("account should have been provisioned: %v", err)
		}
	})

	t.Run("no-ops when auto-provision is off", func(t *testing.T) {
		srv := newTestServer(t)
		if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, AutoProvision: false}); err != nil {
			t.Fatalf("Save: %v", err)
		}

		body := scimUserResource("kysignon-sub-noheal", "noheal", "n@example.com", "user", true)
		rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.updated", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 so KySignOn stops retrying", rec.Code)
		}
		if _, err := srv.users.GetBySSOSub("kysignon-sub-noheal"); err == nil {
			t.Fatal("account must not be provisioned when auto-provisioning is off")
		}
	})
}

func TestSyncWebhookDeleteDeactivatesAndKeepsTheVault(t *testing.T) {
	srv := newTestServer(t)
	body := scimUserResource("kysignon-sub-frank", "frank", "f@example.com", "user", true)
	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", body)); rec.Code != http.StatusOK {
		t.Fatalf("create status = %d", rec.Code)
	}

	u, err := srv.users.GetBySSOSub("kysignon-sub-frank")
	if err != nil {
		t.Fatalf("GetBySSOSub: %v", err)
	}
	if _, err := srv.vault.SaveVault(u.ID, 0, []byte("ENCRYPTED-KDBX"), "pw-env", "rec-env", "test-device"); err != nil {
		t.Fatalf("SaveVault: %v", err)
	}

	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.deleted", body)); rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", rec.Code)
	}

	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("the account record must survive a directory deletion: %v", err)
	}
	if after.Active {
		t.Error("account should be deactivated")
	}

	// The vault is the user's, not the directory's. Replication may never destroy it.
	rc, _, err := srv.vault.OpenVault(u.ID)
	if err != nil {
		t.Fatalf("vault was destroyed by a replication event: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "ENCRYPTED-KDBX" {
		t.Errorf("vault contents = %q", data)
	}
}

func TestSyncWebhookDeleteForUnknownSubjectIs404(t *testing.T) {
	// KySignOn reads 404 on a delete as success, so this ends the event instead of
	// leaving it to retry.
	srv := newTestServer(t)
	body := scimUserResource("kysignon-sub-ghost", "ghost", "g@example.com", "user", true)

	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.deleted", body)); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestSyncWebhookRejectsResourceWithoutID(t *testing.T) {
	srv := newTestServer(t)
	if rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", []byte(`{"userName":"nobody","active":true}`))); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if n := len(srv.users.List()); n != 0 {
		t.Fatalf("account count = %d, want 0", n)
	}
}
