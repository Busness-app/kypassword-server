package sync

import "testing"

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
