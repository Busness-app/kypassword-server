package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypassword-server/internal/users"
)

// destructiveBackupRoutes move or expose backup material. Each needs a session issued within
// freshSessionWindow; adding a route to the backup API without the gate fails this test.
var destructiveBackupRoutes = []struct{ method, path string }{
	{http.MethodPost, "/api/backup/deposit"},
	{http.MethodGet, "/api/backup/export-capsule"},
	{http.MethodPost, "/api/backup/pair-remote"},
}

func TestDestructiveBackupRoutesRequireAFreshSession(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	for _, tc := range destructiveBackupRoutes {
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, csrfRequest(t, srv, cookie, tc.method, tc.path, `{}`))
		if rec.Code == http.StatusForbidden {
			t.Errorf("fresh session: %s %s = 403", tc.method, tc.path)
		}
	}

	srv.sessMu.Lock()
	sess := srv.sessions[cookie.Value]
	sess.IssuedAt = sess.IssuedAt.Add(-freshSessionWindow - time.Second)
	srv.sessions[cookie.Value] = sess
	srv.sessMu.Unlock()

	for _, tc := range destructiveBackupRoutes {
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, csrfRequest(t, srv, cookie, tc.method, tc.path, `{}`))
		if rec.Code != http.StatusForbidden {
			t.Errorf("stale session: %s %s = %d, want 403", tc.method, tc.path, rec.Code)
		}
	}

	// Reading is not destructive: status and the drill stay available to a stale admin.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/backup/status"},
		{http.MethodPost, "/api/backup/drill"},
	} {
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, csrfRequest(t, srv, cookie, tc.method, tc.path, `{}`))
		if rec.Code == http.StatusForbidden {
			t.Errorf("stale session: %s %s = 403, want the route to run", tc.method, tc.path)
		}
	}
}
