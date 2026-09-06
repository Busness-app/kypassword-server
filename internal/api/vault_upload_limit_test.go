package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kypassword-server/internal/users"
)

func TestOversizedVaultUploadPreservesCurrentVault(t *testing.T) {
	srv := newTestServer(t)
	user, cookie := signedInUser(t, srv, "attachment-owner", users.RoleUser)
	if _, err := srv.vault.SaveVault(user.ID, 0, []byte("current encrypted vault"), "", "", "web"); err != nil {
		t.Fatal(err)
	}
	handler := srv.Routes()
	payload := bytes.Repeat([]byte("x"), 50<<20)
	for _, contentType := range []string{"application/octet-stream", "application/json"} {
		t.Run(contentType, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/vault/upload", io.MultiReader(bytes.NewReader(payload), strings.NewReader("x")))
			request.ContentLength = -1 // Exercise streaming requests too.
			request.Header.Set("Content-Type", contentType)
			request.Header.Set("If-Match", `"1"`)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized upload = %d, want 413", response.Code)
			}
			request = httptest.NewRequest(http.MethodGet, "/api/vault/kdbx", nil)
			request.AddCookie(cookie)
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || response.Body.String() != "current encrypted vault" {
				t.Fatal("oversized upload changed the stored vault")
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader(payload))
	request.Header.Set("If-Match", `"1"`)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("upload exactly at limit = %d, want 200", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/vault/kdbx", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), payload) {
		t.Fatal("upload at the limit did not round-trip intact")
	}
}
