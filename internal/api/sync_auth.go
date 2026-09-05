package api

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/syncauth"
)

const syncBodyLimit = 1 << 18

type syncReceipt struct {
	digest  [32]byte
	event   string
	expires time.Time
}

func (s *Server) signedSyncHandler() http.Handler {
	// Both historically accepted secrets remain supported. Verify to select the key,
	// then Middleware establishes the authenticated event and exact body for the handler.
	keyFn := func(r *http.Request) ([]byte, error) {
		h := syncauth.FromRequest(r)
		if len(h.EventID) > 200 || len(h.EventType) > 64 {
			return nil, syncauth.ErrMissingFields
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, syncBodyLimit+1))
		if err != nil {
			return nil, err
		}
		if len(body) > syncBodyLimit {
			return nil, syncauth.ErrBodyTooLarge
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		for _, secret := range s.syncSecrets() {
			if _, err := syncauth.Verify([]byte(secret), syncauth.FromRequest(r), body, syncauth.Options{}); err == nil {
				return []byte(secret), nil
			}
		}
		return nil, errors.New("no configured sync key verified the request")
	}
	rejected := func(r *http.Request, _ error) {
		s.recordAnonymousRejection(r, "sync.rejected", clientIP(r), "replication signature rejected")
	}
	return syncauth.Middleware(keyFn, syncauth.Options{}, syncBodyLimit, rejected)(http.HandlerFunc(s.applySignedSync))
}

func (s *Server) applySignedSync(w http.ResponseWriter, r *http.Request) {
	event, ok := syncauth.EventFromContext(r)
	if !ok {
		http.Error(w, "unverified sync event", 401)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid sync body", 400)
		return
	}
	digest := sha256.Sum256(body)
	// ponytail: serialize file-backed directory mutations and completion receipts. Move
	// receipts into transactional storage if multi-process sync or restart durability is needed.
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	now := time.Now()
	for id, receipt := range s.syncReceipts {
		if now.After(receipt.expires) {
			delete(s.syncReceipts, id)
		}
	}
	if receipt, seen := s.syncReceipts[event.ID]; seen {
		if receipt.digest != digest || receipt.event != event.Type {
			http.Error(w, "event ID reused for different content", 401)
			return
		}
		// A valid retransmission after a lost response is acknowledged, never applied again.
		writeJSON(w, 200, map[string]any{"ok": true, "duplicate": true})
		return
	}
	if len(s.syncReceipts) >= 4096 {
		http.Error(w, "sync receipt capacity reached; retry later", 503)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	recorded := &syncResponse{ResponseWriter: w}
	s.handleSyncWebhook(recorded, r)
	code := recorded.status
	if code == 0 || code >= 200 && code < 300 || code == 404 && event.Type == "user.deleted" || code == 409 && event.Type == "user.created" {
		expires := now.Add(syncauth.DefaultWindow)
		if later := event.At.Add(syncauth.DefaultWindow); later.After(expires) {
			expires = later
		}
		s.syncReceipts[event.ID] = syncReceipt{digest: digest, event: event.Type, expires: expires}
	}
	// Failed attempts are not remembered: the sender signs the same event ID again on retry.
}

type syncResponse struct {
	http.ResponseWriter
	status int
}

func (w *syncResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *syncResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
