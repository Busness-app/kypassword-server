// Package sync receives account replication from KySignOn.
//
// KySignOn's sync engine POSTs a bare SCIM 2.0 User resource and carries the event type,
// timestamp and signature in headers. This package parses exactly that, and nothing else:
// the wire format is dictated by the sender, which is already deployed.
package sync

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// clockSkew bounds how far a signed timestamp may be from now. It exists so a captured
// request cannot be replayed indefinitely; the sender re-signs on every retry.
const clockSkew = 5 * time.Minute

// SCIMUser is the subset of a SCIM User resource KyPassword acts on.
type SCIMUser struct {
	// ID is the KySignOn user ID, which is also the OIDC `sub`. It is the only key an
	// account is ever matched on.
	ID       string
	Username string
	Email    string
	Role     string
	Active   bool
}

type scimResource struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
	Emails   []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Roles []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"roles"`
}

// ParseSCIMUser reads a KySignOn SCIM User resource.
func ParseSCIMUser(body []byte) (SCIMUser, error) {
	var res scimResource
	if err := json.Unmarshal(body, &res); err != nil {
		return SCIMUser{}, fmt.Errorf("body is not a SCIM user resource: %w", err)
	}
	if res.ID == "" {
		return SCIMUser{}, errors.New("SCIM resource has no id, so it identifies no account")
	}

	u := SCIMUser{ID: res.ID, Username: res.UserName, Active: res.Active}
	for _, e := range res.Emails {
		if e.Primary || u.Email == "" {
			u.Email = e.Value
		}
	}
	for _, r := range res.Roles {
		if r.Primary || u.Role == "" {
			u.Role = r.Value
		}
	}
	return u, nil
}

// VerifySignature checks the HMAC KySignOn computes over `timestamp + "." + body`, and
// that the timestamp is recent. Both halves matter: without the freshness bound a captured
// request stays replayable for as long as the secret lives.
func VerifySignature(secret, timestamp string, body []byte, signature string) error {
	if secret == "" {
		return errors.New("no sync secret is configured")
	}
	if signature == "" {
		return errors.New("request carries no signature")
	}

	sent, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("signature timestamp is not RFC3339: %w", err)
	}
	if delta := time.Since(sent); delta > clockSkew || delta < -clockSkew {
		return fmt.Errorf("signature timestamp is %s away from now", delta.Round(time.Second))
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) != 1 {
		return errors.New("signature does not match")
	}
	return nil
}

// EventType reads the replication event from the header KySignOn sets.
func EventType(r *http.Request) string {
	return r.Header.Get("X-KySignOn-Event-Type")
}

// Signature and Timestamp read the headers KySignOn signs a request with. Callers use
// their presence to tell a signed request from an unsigned legacy one.
func Signature(r *http.Request) string { return r.Header.Get("X-KySignOn-Signature") }
func Timestamp(r *http.Request) string { return r.Header.Get("X-KySignOn-Timestamp") }
