package sync

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

const kySignOnPayload = `{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "3f9a1c22-0000-4000-8000-000000000001",
  "userName": "alice",
  "displayName": "Alice Example",
  "active": true,
  "name": {"formatted": "Alice Example"},
  "emails": [{"value": "alice@example.com", "type": "work", "primary": true}],
  "roles": [{"value": "admin", "primary": true}],
  "meta": {"resourceType": "User"}
}`

func TestParseSCIMUserReadsKySignOnResource(t *testing.T) {
	u, err := ParseSCIMUser([]byte(kySignOnPayload))
	if err != nil {
		t.Fatalf("ParseSCIMUser: %v", err)
	}
	if u.ID != "3f9a1c22-0000-4000-8000-000000000001" {
		t.Fatalf("ID = %q", u.ID)
	}
	if u.Username != "alice" {
		t.Fatalf("Username = %q, want the SCIM userName", u.Username)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want the primary email value", u.Email)
	}
	if u.Role != "admin" {
		t.Fatalf("Role = %q, want the primary role value", u.Role)
	}
	if !u.Active {
		t.Fatal("Active = false, want true")
	}
}

func TestParseSCIMUserRejectsResourceWithoutID(t *testing.T) {
	// The id is the OIDC sub and the only key we ever match on. A resource without one
	// must be refused rather than provisioning an account keyed on nothing.
	if _, err := ParseSCIMUser([]byte(`{"userName":"bob","active":true}`)); err == nil {
		t.Fatal("expected a resource with no id to be rejected")
	}
}

func TestParseSCIMUserToleratesMissingOptionalFields(t *testing.T) {
	u, err := ParseSCIMUser([]byte(`{"id":"abc","userName":"bob","active":false}`))
	if err != nil {
		t.Fatalf("ParseSCIMUser: %v", err)
	}
	if u.Email != "" || u.Role != "" {
		t.Fatalf("expected empty optional fields, got %+v", u)
	}
	if u.Active {
		t.Fatal("Active should be false")
	}
}

func sign(t *testing.T, secret, timestamp string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignatureMatchesKySignOnConstruction(t *testing.T) {
	body := []byte(kySignOnPayload)
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := VerifySignature("s3cret", ts, body, sign(t, "s3cret", ts, body)); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestVerifySignatureRejects(t *testing.T) {
	body := []byte(kySignOnPayload)
	ts := time.Now().UTC().Format(time.RFC3339)
	good := sign(t, "s3cret", ts, body)

	cases := map[string]func() error{
		"wrong secret": func() error { return VerifySignature("other", ts, body, good) },
		"tampered body": func() error {
			return VerifySignature("s3cret", ts, []byte(`{"id":"evil","userName":"evil","active":true}`), good)
		},
		"tampered timestamp": func() error {
			return VerifySignature("s3cret", time.Now().UTC().Add(time.Second).Format(time.RFC3339), body, good)
		},
		"empty signature":      func() error { return VerifySignature("s3cret", ts, body, "") },
		"no secret configured": func() error { return VerifySignature("", ts, body, good) },
		"stale timestamp": func() error {
			old := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
			return VerifySignature("s3cret", old, body, sign(t, "s3cret", old, body))
		},
		"future timestamp": func() error {
			future := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
			return VerifySignature("s3cret", future, body, sign(t, "s3cret", future, body))
		},
		"unparseable timestamp": func() error {
			return VerifySignature("s3cret", "not-a-time", body, sign(t, "s3cret", "not-a-time", body))
		},
	}

	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatalf("expected VerifySignature to reject %s", name)
			}
		})
	}
}

// KySignOn signs a deletion with an empty payload when it routes RESTfully. KyPassword
// only ever registers POST /api/sync/webhook, so it always receives a body — but the
// verifier must not assume one, or a protocol change becomes an authentication bypass.
func TestVerifySignatureAcceptsEmptyBody(t *testing.T) {
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := VerifySignature("s3cret", ts, []byte{}, sign(t, "s3cret", ts, []byte{})); err != nil {
		t.Fatalf("VerifySignature over an empty body: %v", err)
	}
}
