package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/Busness-app/kypassword-server/internal/users"
)

func scimTestClient(t *testing.T) (*Server, *scim.Client) {
	t.Helper()
	srv := newTestServer(t)
	srv.scimToken = strings.Repeat("scim-token-", 4)
	server := httptest.NewTLSServer(srv.Routes())
	t.Cleanup(server.Close)
	return srv, &scim.Client{BaseURL: server.URL + "/scim/v2", Token: srv.scimToken, HTTPClient: server.Client()}
}

func TestSharedSCIMClientLifecycle(t *testing.T) {
	srv, client := scimTestClient(t)
	ctx := context.Background()
	if err := client.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	input := scim.User{ExternalID: "ky-sub-alice", UserName: "alice", Active: true, Emails: []scim.MultiValue{{Value: "alice@example.com", Primary: true}}}
	created, err := client.CreateUser(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.ID == input.ExternalID {
		t.Fatal("server must mint a local ID")
	}
	if fetched, err := client.GetUser(ctx, created.ID); err != nil || fetched.ID != created.ID {
		t.Fatalf("GET created user: %+v %v", fetched, err)
	}
	if _, err = client.CreateUser(ctx, input); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, attribute := range []string{"externalId", "userName"} {
		value := input.ExternalID
		if attribute == "userName" {
			value = "ALICE"
		}
		found, err := client.FindUser(ctx, attribute, value)
		if err != nil || found.ID != created.ID {
			t.Fatalf("lookup %s: %+v %v", attribute, found, err)
		}
	}
	if _, err = client.FindUser(ctx, "externalId", "other"); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("unknown filter: %v", err)
	}
	if _, err = srv.vault.SaveVault(created.ID, 0, []byte("encrypted vault stays here"), "envelope", "", "test"); err != nil {
		t.Fatal(err)
	}
	created.UserName = "renamed"
	created.Roles = []scim.MultiValue{{Value: "admin", Primary: true}}
	replaced, err := client.ReplaceUser(ctx, created.ID, created)
	if err != nil || replaced.UserName != "renamed" {
		t.Fatalf("replace: %+v %v", replaced, err)
	}
	tally, _ := auditTally(t, srv)
	if tally["scim.user_created"] != 1 || tally["scim.user_updated"] != 1 {
		t.Fatalf("creation and replacement must have distinct actions: %+v", tally)
	}
	local, _ := srv.users.Get(created.ID)
	if local.Role != users.RoleAdmin || local.SSOSub != input.ExternalID {
		t.Fatalf("identity/role: %+v", local)
	}
	token, err := srv.startSessionWithToken(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := srv.devices.CreatePairingSession(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	deactivated, err := client.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: false})
	if err != nil || deactivated.Active {
		t.Fatalf("deactivate: %+v %v", deactivated, err)
	}
	if _, err = srv.devices.RedeemPairing(pairing.PIN, "late device", "test", ""); err == nil {
		t.Fatal("pairing survived deactivation")
	}
	if _, err = srv.startSessionWithToken(created.ID); err == nil {
		t.Fatal("inactive account got a session")
	}
	if _, err = client.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: true}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, ok := srv.currentUser(req); ok {
		t.Fatal("old device session revived after reactivation")
	}
	if err = client.DeleteUser(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = client.GetUser(ctx, created.ID); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("deleted resource visible: %v", err)
	}
	if _, err = client.FindUser(ctx, "externalId", input.ExternalID); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("deleted resource listed: %v", err)
	}
	if err = client.DeleteUser(ctx, created.ID); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	local, err = srv.users.Get(created.ID)
	if err != nil || local.Active || !local.SCIMDeleted {
		t.Fatal("retained record is not deactivated")
	}
	file, _, err := srv.vault.OpenVault(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	if string(data) != "encrypted vault stays here" {
		t.Fatal("vault was changed")
	}
	recreated, err := client.CreateUser(ctx, input)
	if err != nil || recreated.ID != created.ID {
		t.Fatalf("same identity must recover its retained account: %+v %v", recreated, err)
	}
	tally, _ = auditTally(t, srv)
	if tally["scim.user_created"] != 1 || tally["scim.user_restored"] != 1 {
		t.Fatalf("restoration must not look like a new account: %+v", tally)
	}
}

func TestSCIMRejectsIdentityChangesAndAtomicInvalidPatch(t *testing.T) {
	srv, client := scimTestClient(t)
	ctx := context.Background()
	created, err := client.CreateUser(ctx, scim.User{ExternalID: "subject-one", UserName: "owner", Active: true, Emails: []scim.MultiValue{{Value: "keep@example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.CreateUser(ctx, scim.User{ExternalID: "subject-two", UserName: "owner", Active: true}); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("name collision: %v", err)
	}
	if _, err = client.CreateUser(ctx, scim.User{UserName: "missing-sub", Active: true}); err == nil {
		t.Fatal("missing externalId accepted")
	}
	changed := created
	changed.ExternalID = "subject-two"
	if _, err = client.ReplaceUser(ctx, created.ID, changed); err == nil {
		t.Fatal("PUT changed identity")
	}
	_, err = client.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: false}, scim.PatchOperation{Op: "replace", Path: "externalId", Value: "subject-two"})
	if err == nil {
		t.Fatal("invalid patch accepted")
	}
	local, _ := srv.users.Get(created.ID)
	if !local.Active || local.SSOSub != "subject-one" {
		t.Fatal("invalid patch partially mutated account")
	}
	if _, err := client.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "add", Path: "emails", Value: []scim.MultiValue{{Value: "extra@example.com"}}}); err == nil {
		t.Fatal("silently replaced the existing email on add")
	}
	current, err := client.GetUser(ctx, created.ID)
	if err != nil || len(current.Emails) != 1 || current.Emails[0].Value != "keep@example.com" {
		t.Fatal("rejected add changed email")
	}
	changed, err = client.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "remove", Path: "emails"})
	if err != nil || len(changed.Emails) != 0 {
		t.Fatalf("remove emails: %+v %v", changed, err)
	}
	_, err = client.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "replace", Value: map[string]any{"userName": "updated", "active": false}})
	if err != nil {
		t.Fatal(err)
	}
	local, _ = srv.users.Get(created.ID)
	if local.Active || local.SSOUsername != "updated" {
		t.Fatal("pathless patch was not applied")
	}
}

func TestSCIMTokenIsSeparateAndDisabledByDefault(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatal("SCIM should be disabled by default")
	}
	srv.scimToken = strings.Repeat("dedicated-", 4)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	for _, bearer := range []string{"", srv.pairingSecret, cookie.Value, "wrong"} {
		req = httptest.NewRequest("GET", "/scim/v2/Users", nil)
		req.AddCookie(cookie)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec = httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("non-provisioning credential accepted: %d", rec.Code)
		}
	}
	entries, err := srv.audit.List(100)
	if err != nil {
		t.Fatal(err)
	}
	rejections := 0
	for _, entry := range entries {
		if entry.Action == "scim.rejected" {
			rejections++
		}
		encoded, _ := json.Marshal(entry)
		for _, secret := range []string{srv.scimToken, srv.pairingSecret, cookie.Value, "wrong"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatal("credential leaked into audit log")
			}
		}
	}
	if rejections != 5 {
		t.Fatalf("SCIM rejection records = %d, want disabled request plus four rejected credentials", rejections)
	}
	req = httptest.NewRequest("GET", "/api/vault/metadata", nil)
	req.Header.Set("Authorization", "Bearer "+srv.scimToken)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatal("SCIM token grants vault access")
	}
}

func TestSCIMAndRealKySignOnPayloadShareIdentity(t *testing.T) {
	srv, client := scimTestClient(t)
	body, err := os.ReadFile("testdata/kysignon-user.json")
	if err != nil {
		t.Fatal(err)
	}
	response := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", body))
	if response.Code != 200 {
		t.Fatal(response.Body)
	}
	var sender scim.User
	if err = json.Unmarshal(body, &sender); err != nil {
		t.Fatal(err)
	}
	found, err := client.FindUser(context.Background(), "externalId", sender.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.CreateUser(context.Background(), scim.User{ExternalID: sender.ID, UserName: sender.UserName, Active: true}); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("duplicated signed account: %v", err)
	}
	if len(srv.users.List()) != 1 || found.ExternalID != sender.ID {
		t.Fatal("interfaces disagree on identity")
	}
}

func TestSCIMDeletionAndSignedRecreationRetainIdentity(t *testing.T) {
	srv, client := scimTestClient(t)
	body, err := os.ReadFile("testdata/kysignon-user.json")
	if err != nil {
		t.Fatal(err)
	}
	var sender scim.User
	if err := json.Unmarshal(body, &sender); err != nil {
		t.Fatal(err)
	}
	sender.ExternalID = sender.ID
	created, err := client.CreateUser(context.Background(), sender)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteUser(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if response := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.updated", body)); response.Code != 200 {
		t.Fatal(response.Body)
	}
	deleted, err := srv.users.Get(created.ID)
	if err != nil || deleted.Active || !deleted.SCIMDeleted {
		t.Fatalf("routine update restored deleted account: %+v %v", deleted, err)
	}
	tally, _ := auditTally(t, srv)
	if tally["sync.update_ignored_deleted"] != 1 {
		t.Fatal("ignored update was not identified in audit log")
	}
	if response := doSync(t, srv, signedSyncRequest(srv.pairingSecret, "user.created", body)); response.Code != 200 {
		t.Fatal(response.Body)
	}
	restored, err := client.GetUser(context.Background(), created.ID)
	if err != nil || !restored.Active || restored.ExternalID != sender.ExternalID {
		t.Fatalf("signed recreation: %+v %v", restored, err)
	}
	tally, _ = auditTally(t, srv)
	if tally["sync.user_restored"] != 1 {
		t.Fatal("explicit restoration was not identified in audit log")
	}
}

func TestSCIMFiltersAndPagination(t *testing.T) {
	_, client := scimTestClient(t)
	ctx := context.Background()
	input := scim.User{ExternalID: `subject\with"quotes`, UserName: "filter-user", Active: false}
	created, err := client.CreateUser(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	found, err := client.FindUser(ctx, "externalId", input.ExternalID)
	if err != nil || found.ID != created.ID {
		t.Fatalf("escaped filter: %+v %v", found, err)
	}
	for _, query := range []string{"?count=0", "?startIndex=999&count=1", "?filter=userName+co+%22filter%22", "?count=-1"} {
		req := httptest.NewRequest("GET", client.BaseURL+"/Users"+query, nil)
		req.Header.Set("Authorization", "Bearer "+client.Token)
		// Use the HTTP client against the TLS receiver, including actual query encoding.
		req.RequestURI = ""
		response, err := client.HTTPClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			TotalResults int         `json:"totalResults"`
			Resources    []scim.User `json:"Resources"`
		}
		_ = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if strings.Contains(query, "co+") || strings.Contains(query, "-1") {
			if response.StatusCode != 400 {
				t.Fatalf("unsupported query accepted: %s", query)
			}
		} else if response.StatusCode != 200 || len(body.Resources) != 0 || body.TotalResults != 1 {
			t.Fatalf("pagination %s: %+v", query, body)
		}
	}
}

func TestSCIMShowsLocallyReactivatedAccount(t *testing.T) {
	srv, client := scimTestClient(t)
	ctx := context.Background()
	input := scim.User{ExternalID: "local-reactivation-sub", UserName: "local-reactivation-user", Active: true}
	created, err := client.CreateUser(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteUser(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetUser(ctx, created.ID); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("inactive deletion visible: %v", err)
	}
	if err := srv.users.Reactivate(created.ID); err != nil {
		t.Fatal(err)
	}
	visible, err := client.GetUser(ctx, created.ID)
	if err != nil || !visible.Active {
		t.Fatalf("active account hidden: %+v %v", visible, err)
	}
	found, err := client.FindUser(ctx, "externalId", input.ExternalID)
	if err != nil || found.ID != created.ID {
		t.Fatalf("active account missing from reconciliation: %+v %v", found, err)
	}
	if _, err := client.CreateUser(ctx, input); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("active account treated as deleted on creation: %v", err)
	}
}
