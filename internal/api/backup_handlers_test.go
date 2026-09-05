package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	export := csrfRequest(t, srv, adminCookie, http.MethodPost, "/api/backup/export-capsule", `{}`)
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

func TestExportCapsuleRequiresCSRF(t *testing.T) {
	srv := newTestServer(t)
	_, adminCookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	request := httptest.NewRequest(http.MethodPost, "/api/backup/export-capsule", nil)
	request.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("export without CSRF = %d, want 403", rec.Code)
	}
}

func TestEveryBackupMutationRequiresCSRFAndAdmin(t *testing.T) {
	srv := newTestServer(t)
	_, admin := signedInUser(t, srv, "admin", users.RoleAdmin)
	_, user := signedInUser(t, srv, "user", users.RoleUser)
	routes := append(append([]struct{ method, path string }{}, destructiveBackupRoutes...), struct{ method, path string }{http.MethodPost, "/api/backup/drill"})
	for _, route := range routes {
		r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		r.AddCookie(admin)
		w := httptest.NewRecorder()
		srv.Routes().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s without CSRF: %d", route.path, w.Code)
		}
		w = httptest.NewRecorder()
		srv.Routes().ServeHTTP(w, csrfRequest(t, srv, user, route.method, route.path, `{}`))
		if w.Code != 403 {
			t.Errorf("%s nonadmin: %d", route.path, w.Code)
		}
	}
}
func TestPinScheduleAndLocalBackupRoutes(t *testing.T) {
	srv := newTestServer(t)
	_, admin := signedInUser(t, srv, "admin", users.RoleAdmin)
	srv.backupService.Config.Directory = t.TempDir()
	srv.backupService.Config.Keep = 2
	key, e := recoverykey.Generate()
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"publicKey": base64.StdEncoding.EncodeToString(key.Public().Bytes()), "threshold": 2, "totalShares": 3})
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.Routes().ServeHTTP(w, csrfRequest(t, srv, admin, method, path, body))
		return w
	}
	if w := call("POST", "/api/backup/pin-key", string(body)); w.Code != 200 {
		t.Fatalf("pin: %d %s", w.Code, w.Body.String())
	}
	if w := call("PUT", "/api/backup/schedule", `{"intervalSec":900}`); w.Code != 200 {
		t.Fatalf("schedule: %d %s", w.Code, w.Body.String())
	}
	if w := call("PUT", "/api/backup/schedule", `{"intervalSec":899}`); w.Code != 400 {
		t.Fatalf("bad interval: %d", w.Code)
	}
	if w := call("POST", "/api/backup/deposit", `{}`); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("local_path")) {
		t.Fatalf("local backup: %d %s", w.Code, w.Body.String())
	}
}

type blockedRecovery struct{ started, release chan struct{} }

func (f *blockedRecovery) Deposit(ctx context.Context, _, _ string, _ []byte) (backup.Receipt, error) {
	close(f.started)
	select {
	case <-f.release:
	case <-ctx.Done():
	}
	return backup.Receipt{}, backup.ErrRemote
}
func TestPartialBackupAndBusyUnpair(t *testing.T) {
	srv := newTestServer(t)
	_, admin := signedInUser(t, srv, "admin", users.RoleAdmin)
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.backupState.StorePairing("https://recovery.example", "synthetic", backup.RecoveryKey{Public: key.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	srv.backupService.Config.Directory = t.TempDir()
	srv.backupService.Config.Keep = 2
	fake := &blockedRecovery{make(chan struct{}), make(chan struct{})}
	srv.backupService.Client = fake
	deposit := httptest.NewRecorder()
	req := csrfRequest(t, srv, admin, "POST", "/api/backup/deposit", `{}`)
	done := make(chan struct{})
	go func() { defer close(done); srv.Routes().ServeHTTP(deposit, req) }()
	var unpaired chan struct{}
	defer func() {
		close(fake.release)
		<-done
		if unpaired != nil {
			<-unpaired
		}
	}()
	select {
	case <-fake.started:
	case <-time.After(3 * time.Second):
		t.Fatal("deposit did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	unpair := httptest.NewRecorder()
	unpaired = make(chan struct{})
	go func() {
		defer close(unpaired)
		srv.Routes().ServeHTTP(unpair, csrfRequest(t, srv, admin, "DELETE", "/api/backup/pairing", `{}`).WithContext(ctx))
	}()
	select {
	case <-unpaired:
	case <-ctx.Done():
		t.Fatal("unpair blocked behind deposit")
	}
	if unpair.Code != http.StatusConflict {
		t.Fatalf("unpair: %d %s", unpair.Code, unpair.Body.String())
	}
	claimant := &fakeRecovery{}
	srv.recovery = claimant
	pair := httptest.NewRecorder()
	srv.Routes().ServeHTTP(pair, csrfRequest(t, srv, admin, "POST", "/api/backup/pair-remote", `{"recoveryUrl":"https://recovery.example","pairingCode":"123456"}`))
	if pair.Code != http.StatusConflict || claimant.claims != 0 {
		t.Fatalf("busy pairing consumed code: status=%d claims=%d", pair.Code, claimant.claims)
	}

	// Release without closing so the deferred cleanup can close it once.
	fake.release <- struct{}{}
	<-done
	if deposit.Code != http.StatusMultiStatus || !bytes.Contains(deposit.Body.Bytes(), []byte("local_path")) || !bytes.Contains(deposit.Body.Bytes(), []byte("warning")) {
		t.Fatalf("partial: %d %s", deposit.Code, deposit.Body.String())
	}
}
