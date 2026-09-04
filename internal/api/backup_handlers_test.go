package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kypassword-server/internal/backup"
	"github.com/Busness-app/kypassword-server/internal/users"
)

type fakeRecovery struct {
	result backup.PairingResult
	claims int
}

func (f *fakeRecovery) Claim(context.Context, string, string) (backup.PairingResult, error) {
	f.claims++
	return f.result, nil
}

func (f *fakeRecovery) Deposit(context.Context, string, string, []byte) (backup.Receipt, error) {
	return backup.Receipt{}, nil
}

func csrfRequest(t *testing.T, srv *Server, session *http.Cookie, method, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(session)
	srv.sessMu.RLock()
	token := srv.sessions[session.Value].CSRFToken
	srv.sessMu.RUnlock()
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	return req
}

func TestBackupRoutesRequireAdminAndCSRF(t *testing.T) {
	srv := newTestServer(t)
	_, userCookie := signedInUser(t, srv, "ordinary", users.RoleUser)
	req := httptest.NewRequest(http.MethodGet, "/api/backup/status", nil)
	req.AddCookie(userCookie)
	if rec := httptest.NewRecorder(); func() int { srv.Routes().ServeHTTP(rec, req); return rec.Code }() != http.StatusForbidden {
		t.Fatal("ordinary user reached backup status")
	}

	_, adminCookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	request := httptest.NewRequest(http.MethodPost, "/api/backup/pair-remote", strings.NewReader(`{"recoveryUrl":"https://recovery.example","pairingCode":"123456"}`))
	request.AddCookie(adminCookie)
	recorder := httptest.NewRecorder()
	srv.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", recorder.Code)
	}
}

func TestPairStatusRedactsTokenAndUnpairedExportFailsClosed(t *testing.T) {
	srv := newTestServer(t)
	_, adminCookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	export := httptest.NewRequest(http.MethodGet, "/api/backup/export-capsule", nil)
	export.AddCookie(adminCookie)
	exportRec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(exportRec, export)
	if exportRec.Code != http.StatusPreconditionFailed {
		t.Fatalf("unpaired export status = %d", exportRec.Code)
	}

	private, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRecovery{result: backup.PairingResult{Token: "never-return-this-token", Key: backup.RecoveryKey{Public: private.Public(), Threshold: 2, TotalShares: 3}}}
	srv.recovery = fake
	srv.backupService.Client = fake
	pair := csrfRequest(t, srv, adminCookie, http.MethodPost, "/api/backup/pair-remote", `{"recoveryUrl":"https://recovery.example","pairingCode":"123456"}`)
	pairRec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(pairRec, pair)
	if pairRec.Code != http.StatusOK {
		t.Fatalf("pair status = %d: %s", pairRec.Code, pairRec.Body.String())
	}
	if fake.claims != 1 || bytes.Contains(pairRec.Body.Bytes(), []byte("never-return-this-token")) || bytes.Contains(pairRec.Body.Bytes(), []byte("sealedToken")) {
		t.Fatalf("pair response leaked token or did not claim: %s", pairRec.Body.String())
	}
	status := httptest.NewRequest(http.MethodGet, "/api/backup/status", nil)
	status.AddCookie(adminCookie)
	statusRec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(statusRec, status)
	if statusRec.Code != http.StatusOK || bytes.Contains(statusRec.Body.Bytes(), []byte("never-return-this-token")) || !bytes.Contains(statusRec.Body.Bytes(), []byte(`"keyHealthy":true`)) {
		t.Fatalf("unsafe or unhealthy status: %d %s", statusRec.Code, statusRec.Body.String())
	}
}
