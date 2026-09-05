package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kypassword-server/internal/users"
)

// destructiveBackupRoutes move or expose backup material. Each needs a KySignOn
// authentication within freshSessionWindow; adding a route without the gate fails this test.
var destructiveBackupRoutes = []struct{ method, path string }{
	{http.MethodPost, "/api/backup/deposit"},
	{http.MethodPost, "/api/backup/export-capsule"},
	{http.MethodPost, "/api/backup/pair-remote"},
}

// A stale admin can mint a 90-day device token through the ordinary pairing flow, but that
// token is not a fresh KySignOn authentication and must not pass the destructive-action gate.
func TestDevicePairingCannotRefreshAnAdminSession(t *testing.T) {
	srv := newTestServer(t)
	admin, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	srv.sessMu.Lock()
	sess := srv.sessions[cookie.Value]
	sess.AuthenticatedAt = sess.AuthenticatedAt.Add(-freshSessionWindow - time.Second)
	srv.sessions[cookie.Value] = sess
	srv.sessMu.Unlock()

	start := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/start", nil)
	start.AddCookie(cookie)
	startRec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(startRec, start)
	if startRec.Code != http.StatusOK {
		t.Fatalf("pairing start = %d: %s", startRec.Code, startRec.Body.String())
	}
	var started struct {
		PIN string `json:"pin"`
	}
	if err := json.NewDecoder(startRec.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(PairingRedeemRequest{CodeOrPIN: started.PIN, DeviceName: "attacker", Platform: "test"})
	redeemRec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(redeemRec, httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem", bytes.NewReader(body)))
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("pairing redeem = %d: %s", redeemRec.Code, redeemRec.Body.String())
	}
	var redeemed struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.NewDecoder(redeemRec.Body).Decode(&redeemed); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/backup/deposit", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+redeemed.SessionToken)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("paired device token for admin %s reached backup: %d", admin.ID, rec.Code)
	}
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
	sess.AuthenticatedAt = sess.AuthenticatedAt.Add(-freshSessionWindow - time.Second)
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
