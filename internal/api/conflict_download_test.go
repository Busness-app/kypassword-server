package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Busness-app/kypassword-server/internal/users"
	"github.com/Busness-app/kypassword-server/internal/vault"
)

func TestConflictDownloadIsOwnerOnlyAndReadOnly(t *testing.T) {
	srv := newTestServer(t)
	owner, cookie := signedInUser(t, srv, "owner", users.RoleUser)
	_, other := signedInUser(t, srv, "other", users.RoleAdmin)
	if _, err := srv.vault.SaveVault(owner.ID, 0, []byte("current"), "", "", "web"); err != nil {
		t.Fatal(err)
	}
	_, err := srv.vault.SaveVault(owner.ID, 0, []byte("encrypted conflict"), "", "", "phone")
	var conflict *vault.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		id     string
		status int
	}{
		{"owner", cookie, conflict.ConflictID, 200},
		{"other account even admin", other, conflict.ConflictID, 404},
		{"anonymous", nil, conflict.ConflictID, 401},
		{"missing", cookie, "missing", 404},
		{"path traversal", cookie, "../vault", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/vault/conflicts/"+url.PathEscape(tc.id), nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if tc.status == 200 && (rec.Body.String() != "encrypted conflict" || rec.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("wrong ciphertext or cache policy")
			}
		})
	}
	metadata, err := srv.vault.GetMetadata(owner.ID)
	if err != nil || metadata.Version != 1 {
		t.Fatalf("download changed version: %+v %v", metadata, err)
	}
	conflicts, err := srv.vault.ListConflicts(owner.ID)
	if err != nil || len(conflicts) != 1 {
		t.Fatalf("download removed conflict: %v %v", conflicts, err)
	}
}
