# KyPassword SSO-Only Directory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make KySignOn the sole directory and sole authenticator for KyPassword, so the master password never reaches the server in any form and there is exactly one account record per person across the suite.

**Architecture:** KyPassword keeps its vault, device and audit subsystems untouched — the vault store is already keyed by user ID alone and has no dependency on the auth verifier. What goes is the local password directory: the `PasswordHash`/`AuthSalt` verifier, the login and setup endpoints, paper-recovery-as-site-access, and admin user creation. Accounts arrive by KySignOn replication or first SSO login, keyed on the OIDC `sub`. The master password becomes purely client-side key material that unwraps the vault envelope after an SSO session already exists.

**Tech Stack:** Go 1.26 stdlib plus `golang.org/x/crypto` (the only direct dependency), JSON file store, React + TypeScript + Vite frontend.

**Spec:** `PROMPT.md` (security model), `AGENTS.md` (subsystem contracts), and the decisions recorded under "Design decisions" below. Where this plan and `PROMPT.md` conflict, `PROMPT.md`'s zero-knowledge requirements win and the conflict is called out explicitly.

## Global Constraints

- Go 1.26 (`go.mod`). **No new Go dependencies.** The single direct dependency stays `golang.org/x/crypto`.
- **No new npm dependencies.**
- Backend gates: `gofmt -l .` must print nothing, `go vet ./...`, `go test -race ./...`, `govulncheck ./...`.
- Frontend gates: `npm test && npm run build` in `frontend/` (`build` is `tsc && vite build`, so it is the typecheck gate).
- Docker build must still succeed: `docker build -t kypassword-server:latest .`
- **The server must never receive an unhashed master password, a plaintext vault key, or decrypted KeePass data** (`PROMPT.md:9`). This plan strengthens that guarantee; no step may weaken it.
- All KeePass decryption, editing, encryption and key handling stay in the client (`PROMPT.md`, "Vault and file behavior").
- Audit records stay tamper-evident; every new state-changing path writes one.
- User-visible copy calls the identity provider "KySignOn".

---

## Two findings that shaped this plan

Both were verified against the code, not inferred. Read them before starting — they change what "make KyPassword OIDC-only" means.

### Finding A: the KySignOn → KyPassword replication does not work today

Both products' docs advertise account replication. It is wired at both ends and it silently does nothing.

**What KySignOn actually sends** (`kysignon-server/internal/sync/sync.go`, `deliver()` and `resolveSCIMURL()`):
- Method/URL: for a paired system whose type is not `scim` and whose callback URL contains no SCIM markers, `POST <callbackURL>` verbatim.
- Body: a **bare SCIM 2.0 User resource** — `json.Marshal(scimRes)` of `SCIMUserResource`, i.e. `{"schemas":[...],"id":...,"userName":...,"name":{...},"emails":[{"value":...}],"roles":[{"value":...}],"active":...}`.
- Event type: in the **`X-KySignOn-Event-Type` header**, values `user.created`, `user.updated`, `user.deleted`.
- Auth: `Authorization: Bearer <secret>` **and** `X-KySignOn-Signature`, an HMAC-SHA256 over `timestamp + "." + body`, with the timestamp in `X-KySignOn-Timestamp`.
- Replay key: `X-KySignOn-Event-Id` and `Idempotency-Key`.

**What KyPassword expects** (`internal/api/admin_handlers.go:140-151`, `handleSyncWebhook`):
- Body `{"event": "...", "user": {"id","username","role","active","email"}}`.
- Signature header `X-Sync-Signature`, HMAC over the **body only**, no timestamp.

So `ev.Event` is always `""`, `ev.User` is the zero value, the `switch` matches no case, and the handler returns success having done nothing. Because KySignOn also sends `Authorization: Bearer <secret>`, the request *authorises* — so KySignOn records the event as delivered and both sides look healthy while no account is ever provisioned.

`SyncWebhookPayload` at `kysignon-server/internal/sync/sync.go:298` is dead code: `grep -rn 'SyncWebhookPayload{'` finds no construction anywhere.

**Ruling: fix the receiver, not the sender.** KySignOn's format is SCIM-shaped by design, is already deployed, and carries replay protection (signed timestamp + idempotency key) that KyPassword's format lacks. Task 1 makes KyPassword speak what KySignOn actually sends.

### Finding B: two live account-takeover paths in the code being deleted

1. **The SSO callback silently links by username.** `internal/api/auth_handlers.go:280-283`: when `GetBySSOSub` misses, it falls back to `GetByUsername(claims.PreferredUsername)` and links that account to the incoming `sub`. Any KySignOn identity whose `preferred_username` matches a local KyPassword account takes over that account and its vault. Task 2 deletes it. This is the same collision hazard rejected for the migration path, and it is live today.

2. **The login endpoint accepts the raw master password.** `internal/api/auth_handlers.go:38-42` tries the client-derived `authSecret`, then falls back to `req.Password` against the same `VerifyAuth`. Because the fallback fires on *failure* of the derived path, a client bug or version skew downgrades silently to transmitting the real master password — directly contrary to `PROMPT.md:9`. Task 5 deletes the endpoint, which removes the path by construction rather than patching it.

---

## Design decisions

Locked. If one turns out wrong, stop and raise it rather than working around it.

**1. SSO-only. No local password login survives, not even break-glass.** There is no `handleLogin`, no `handleLoginParams`, no local verifier. Site access is exclusively an OIDC session from KySignOn. The consequence is real and accepted: if KySignOn is down, nobody reaches the web vault. Users are not locked out of their data — `GET /api/vault/kdbx` gives them a standard KDBX v4 file that opens in any KeePass client, and that remains the documented outage path.

**2. The master password stops being an authentication credential.** It is only ever the secret that unwraps the password-wrapped vault key envelope, client-side. It is never sent, not even as a derived verifier, so `PasswordHash`, `AuthSalt` and `AuthIterations` leave the user record entirely.

**3. Paper recovery becomes vault-unlock only.** Today `POST /api/auth/recovery` verifies a server-side `RecoveryHash` and *starts a session*. Under decision 1 that is a second authentication path, so it goes. The recovery capability itself is unharmed: the recovery-wrapped envelope lives in vault metadata and is unwrapped client-side after an SSO session exists. `RecoveryHash`, `SetPaperRecovery` and `VerifyPaperRecovery` are deleted from the server.

**4. Accounts are keyed on the OIDC `sub`, which is the KySignOn user ID.** Verified: `kysignon-server/internal/oauth/oauth.go:310` and `:326` set `"sub": user.ID`, and the SCIM resource the sync engine sends uses the same `u.ID` as its `id`. So a webhook-provisioned account and a first-login-provisioned account converge on the same key. Nothing else — username, email — is ever used to match an identity.

**5. Migration is a hard preflight gate, not a guess.** The server refuses to start while any *active* user lacks an `ssoSub`, naming them. The operator links or deactivates each one first, using an offline CLI that edits `users.json` without needing a session. No automatic matching, by username or anything else.

**6. SSO configuration comes from the environment.** Under decision 1 there is no local admin who could configure SSO through the UI, and no way to become one — a bootstrap deadlock. Issuer, client ID and client secret are read from environment variables at startup and take precedence over the on-disk settings. The first person to sign in whose token carries an admin role claim becomes an admin.

---

## File structure

**Create:**
- `internal/sync/scim.go` — parsing a KySignOn SCIM User resource and verifying its signature. Pure: no HTTP, no store.
- `internal/sync/scim_test.go`
- `internal/users/preflight.go` — the unlinked-active-user gate.
- `cmd/server/link.go` — the offline `link-sso` / `deactivate` subcommands.

**Modify:**
- `internal/api/admin_handlers.go` — `handleSyncWebhook` rewritten against the real contract; `handleAdminUsersCreate` deleted.
- `internal/api/auth_handlers.go` — delete `handleLogin`, `handleLoginParams`, `handlePaperRecovery`, `handleChangePassword`, `handleSetPaperRecovery`, `handleSSOUnlink`, `handleSetupCheck`, `handleSetupInit`; delete the username-link fallback in `handleSSOCallback`.
- `internal/api/server.go` — routes.
- `internal/users/users.go` — delete the local-auth fields and methods.
- `internal/sso/sso.go` — environment-sourced settings.
- `cmd/server/main.go` — preflight, subcommand dispatch.
- `frontend/src/pages/LoginPage.tsx`, `SecuritySettings.tsx`, `AdminPanel.tsx`.
- `README.md`, `PROMPT.md`, `AGENTS.md`, `.env.example` if present.

**Untouched, deliberately:** `internal/vault/`, `internal/devices/`, `internal/audit/`, and all vault crypto in `frontend/src/lib/`. If a task seems to require changing those, stop and report — it means this plan mis-read the coupling.

---

## Task 1: Speak KySignOn's actual replication protocol

**Files:**
- Create: `internal/sync/scim.go`, `internal/sync/scim_test.go`
- Modify: `internal/api/admin_handlers.go` (`handleSyncWebhook`, lines 140-240)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `sync.SCIMUser` with fields `ID, Username, Email, Role string` and `Active bool`; `sync.ParseSCIMUser([]byte) (SCIMUser, error)`; `sync.VerifySignature(secret, timestamp string, body []byte, signature string) error`; `sync.EventType(r *http.Request) string`.

- [ ] **Step 1: Write the failing test**

Create `internal/sync/scim_test.go`. The payload below is the exact shape `kysignon-server/internal/sync/sync.go`'s `UserToSCIMResource` produces — do not simplify it.

```go
package sync

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

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

func sign(t *testing.T, secret, timestamp string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignatureMatchesKySignOnConstruction(t *testing.T) {
	body := []byte(kySignOnPayload)
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := VerifySignature("s3cret", ts, body, sign(t, "s3cret", ts, body)); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestVerifySignatureRejects(t *testing.T) {
	body := []byte(kySignOnPayload)
	ts := time.Now().UTC().Format(time.RFC3339)
	good := sign(t, "s3cret", ts, body)

	cases := map[string]func() error{
		"wrong secret": func() error { return VerifySignature("other", ts, body, good) },
		"tampered body": func() error {
			return VerifySignature("s3cret", ts, []byte(`{"id":"evil","userName":"evil","active":true}`), good)
		},
		"tampered timestamp": func() error {
			return VerifySignature("s3cret", time.Now().UTC().Add(time.Second).Format(time.RFC3339), body, good)
		},
		"empty signature": func() error { return VerifySignature("s3cret", ts, body, "") },
		"stale timestamp": func() error {
			old := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
			return VerifySignature("s3cret", old, body, sign(t, "s3cret", old, body))
		},
		"future timestamp": func() error {
			future := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
			return VerifySignature("s3cret", future, body, sign(t, "s3cret", future, body))
		},
		"unparseable timestamp": func() error {
			return VerifySignature("s3cret", "not-a-time", body, sign(t, "s3cret", "not-a-time", body))
		},
	}

	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatalf("expected VerifySignature to reject %s", name)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/sync/...`
Expected: FAIL — the package does not exist (`no Go files`).

- [ ] **Step 3: Write the parser and verifier**

Create `internal/sync/scim.go`:

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/sync/...`
Expected: PASS.

- [ ] **Step 5: Rewrite `handleSyncWebhook` against this contract**

In `internal/api/admin_handlers.go`, replace the body of `handleSyncWebhook` and delete the now-unused `SyncWebhookEvent` and `SyncUserPayload` types. Requirements, in order:

1. Read the body under the existing `io.LimitReader(r.Body, 1<<18)` cap.
2. Resolve the secret exactly as today — `s.pairingSecret` first, then the SSO client secret — but **require `sync.VerifySignature` to pass**. Keep bearer-only acceptance *only* when no `X-KySignOn-Signature` header is present at all, so an existing paired system does not break the moment this deploys; log an audit event recording that the request was accepted unsigned. Signature-present-but-invalid is always a rejection.
3. `switch sync.EventType(r)` on `user.created`, `user.updated`, `user.deleted`. An unrecognised or empty event type is a `400`, **not** a silent success — the silent-success behaviour is the bug this task exists to fix.
4. `user.created`: if `GetBySSOSub(u.ID)` misses, `CreateSSOUser(u.Username, role, u.ID, u.Username, u.Email)`. If it hits, treat as idempotent success (KySignOn retries with the same `Idempotency-Key`).
5. `user.updated`: update role, active flag and email on the matched account. Match on `ssoSub` only, never username.
6. `user.deleted`: deactivate the account. **Do not delete the vault** — a replication event must never destroy user data. Add a comment saying so.
7. Every branch writes an audit record.
8. Return `200` on success, `409` on a duplicate create (KySignOn treats `409` on create as success), `404` on an update or delete for an unknown subject.

- [ ] **Step 6: Test the endpoint end to end**

Add tests to `internal/api/api_test.go` following the harness already there. Cover, at minimum: a correctly signed `user.created` provisions an account with the right `ssoSub`; a valid signature with an unknown event type returns `400`; an invalid signature is rejected even with a valid bearer token; a `user.deleted` deactivates the account and leaves the vault directory on disk.

Run: `go test -race ./internal/api/... ./internal/sync/...`

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/sync internal/api
go vet ./...
git add internal/sync internal/api
git commit -m "fix(sync): accept the SCIM replication KySignOn actually sends"
```

---

## Task 2: Delete the username auto-link fallback

**Files:**
- Modify: `internal/api/auth_handlers.go:278-284`
- Test: `internal/api/api_test.go`

**Interfaces:** consumes nothing; produces no new symbols. Behaviour change only.

- [ ] **Step 1: Write the failing test**

```go
func TestSSOCallbackDoesNotLinkByUsername(t *testing.T) {
	// A KySignOn identity whose preferred_username happens to match an unlinked local
	// account must not inherit that account or its vault. Username collision is not
	// identity; only the OIDC sub is.
	//
	// Build a server with one local account named "alice" and no ssoSub, then drive the
	// SSO callback with claims for sub="attacker-sub", preferred_username="alice".
	// Assert: the response is 403, no session cookie is issued, and the stored "alice"
	// record still has an empty SSOSub.
}
```

Implement that body against the existing test harness in `internal/api/api_test.go`. If the harness cannot drive `handleSSOCallback` without a live IdP, factor the post-token-exchange decision — "given these claims, which account, or none?" — into a small testable function on `*Server` and test that instead. Say in your report which route you took.

- [ ] **Step 2: Run it and watch it fail**

Expected: FAIL — the account is linked and a session is issued.

- [ ] **Step 3: Delete the fallback**

In `handleSSOCallback`, remove this block entirely:

```go
	user, err := s.users.GetBySSOSub(claims.Sub)
	if err != nil && errors.Is(err, users.ErrNotFound) {
		if claims.PreferredUsername != "" {
			if u, errU := s.users.GetByUsername(claims.PreferredUsername); errU == nil {
				user = u
				_ = s.users.LinkSSO(u.ID, claims.Sub, claims.PreferredUsername, claims.Email)
			}
		}
	}
```

leaving the lookup as `GetBySSOSub` alone. Add a comment stating that username is deliberately not a matching key, and why.

Check whether `errors` and `users.ErrNotFound` are still used elsewhere in the file before removing imports.

- [ ] **Step 4: Verify and commit**

Run: `go test -race ./internal/api/...`

```bash
gofmt -w internal/api
git add internal/api
git commit -m "fix(sso): never link an SSO identity to an account by username"
```

---

## Task 3: Migration preflight and the offline linking CLI

**Files:**
- Create: `internal/users/preflight.go`, `cmd/server/link.go`
- Modify: `cmd/server/main.go`
- Test: `internal/users/users_test.go`

**Interfaces:**
- Produces: `users.UnlinkedActive(s *Store) []User`; `users.ErrUnlinkedAccounts`; subcommands `link-sso` and `deactivate`.

- [ ] **Step 1: Write the failing test**

```go
func TestUnlinkedActiveListsOnlyActiveAccountsWithoutSSO(t *testing.T) {
	// Fixture: four accounts — linked+active, unlinked+active, unlinked+inactive,
	// linked+inactive. Only the unlinked+active one may be returned: an inactive account
	// cannot log in, so it does not block startup, and a linked one is already migrated.
}
```

Implement against the helpers `internal/users/users_test.go` already uses.

- [ ] **Step 2: Implement the gate**

`internal/users/preflight.go`:

```go
package users

// UnlinkedActive returns every active account with no KySignOn identity. These are the
// accounts that would silently lose access — or, worse, be duplicated by replication —
// when KySignOn becomes the only directory, so the server refuses to start while any exist.
func UnlinkedActive(s *Store) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []User
	for _, u := range s.users {
		if u.Active && u.SSOSub == "" {
			out = append(out, u)
		}
	}
	return out
}
```

Sort the result by username so the operator sees a stable list.

In `cmd/server/main.go`, before the server starts listening:

```go
	if unlinked := users.UnlinkedActive(userStore); len(unlinked) > 0 {
		log.Printf("KyPassword now authenticates only through KySignOn, and %d active account(s) have no KySignOn identity:", len(unlinked))
		for _, u := range unlinked {
			log.Printf("  - %s (id %s)", u.Username, u.ID)
		}
		log.Printf("Link each one:      kypassword-server link-sso --username <name> --sub <kysignon-user-id>")
		log.Printf("Or retire it:       kypassword-server deactivate --username <name>")
		log.Printf("The KySignOn user ID is the value shown in its admin user list, and is the same value it puts in the OIDC 'sub' claim.")
		os.Exit(1)
	}
```

Fail before opening the listener, so a misconfigured upgrade never serves a single request.

- [ ] **Step 3: Implement the subcommands**

`cmd/server/link.go` provides `link-sso` and `deactivate`, dispatched from `main` on `os.Args[1]` before any server setup. Both operate on `users.json` through the existing `users.Store` and exit non-zero on failure. They must work with no session, no network and no SSO configured — that is the whole point, since the operator cannot log in until the migration is done.

`link-sso` requires `--username` and `--sub`; it must refuse to link a `sub` that is already bound to a different account, and print what it changed.

Add a test per subcommand covering the success path and the duplicate-`sub` refusal.

- [ ] **Step 4: Verify and commit**

Run: `go test -race ./internal/users/... ./cmd/...`

```bash
gofmt -w internal/users cmd
git add internal/users cmd
git commit -m "feat(migration): gate startup on unlinked accounts and add offline linking"
```

---

## Task 4: Remove local authentication from the users package

**Files:**
- Modify: `internal/users/users.go`
- Test: `internal/users/users_test.go`

**Interfaces:**
- Removes: `User.PasswordHash`, `.AuthSalt`, `.AuthIterations`, `.RecoveryHash`, `.MustChangePassword`; `Public.MustChangePassword`; `HashPassword`, `Create`, `VerifyAuth`, `SetPassword`, `SetPaperRecovery`, `VerifyPaperRecovery`, `UnlinkSSO`; `ErrInvalidAuth` if nothing else uses it.
- Keeps: `CreateSSOUser`, `Get`, `GetByUsername`, `GetBySSOSub`, `List`, `LinkSSO`, `SetRole`, `Deactivate`, `Reactivate`.

- [ ] **Step 1: Write the failing test**

```go
func TestUserRecordCarriesNoAuthenticationSecret(t *testing.T) {
	// Marshal a user and assert the JSON contains none of the retired credential fields.
	// This is the regression guard for the whole plan: if any of these reappear, the
	// server is storing password-derived material again.
	u := User{ID: "1", Username: "alice", Role: RoleUser, Active: true, SSOSub: "sub-1"}
	blob, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"passwordHash", "authSalt", "authIterations", "recoveryHash", "mustChangePassword"} {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("user record still carries %q: %s", forbidden, blob)
		}
	}
}

func TestStoreLoadsLegacyFileAndDropsCredentialFields(t *testing.T) {
	// Write a users.json in the OLD format (with passwordHash/authSalt/recoveryHash),
	// open a Store over it, then save. Assert the account survives with its id, username,
	// role, active flag and ssoSub intact, and that the file on disk no longer contains
	// any credential field. Existing deployments upgrade by starting the new binary; the
	// verifier is erased from disk on the first write.
}
```

- [ ] **Step 2: Run and watch them fail**

Expected: the first test fails on the present fields; the second does not compile or fails on the retained fields.

- [ ] **Step 3: Delete the fields and methods**

Removing struct fields is backward compatible on read — `encoding/json` ignores unknown keys — so a legacy `users.json` loads cleanly and the retired fields disappear on the next save. Do not write a migration routine; there is nothing to migrate to.

Delete `golang.org/x/crypto/scrypt` from the imports if `HashPassword` was its only user, and check whether `crypto/rand`, `crypto/subtle`, `encoding/hex` are still needed.

**`golang.org/x/crypto` must stay in `go.mod`** if anything else imports it. Run `go mod tidy` and report what changed; if it becomes an unused dependency, that is a legitimate removal, but say so explicitly rather than letting it pass unremarked.

- [ ] **Step 4: Verify and commit**

Run: `go build ./... && go test -race ./internal/users/...`

Compilation will fail in `internal/api` until Task 5. That is expected and correct — the two tasks are one change split for review, so commit this only if the package's own tests pass, and note the broken build in your report.

```bash
gofmt -w internal/users
git add internal/users go.mod go.sum
git commit -m "refactor(users): remove local password and recovery verifiers"
```

---

## Task 5: Remove the local-auth HTTP surface

**Files:**
- Modify: `internal/api/auth_handlers.go`, `internal/api/admin_handlers.go`, `internal/api/server.go`
- Test: `internal/api/api_test.go`

**Interfaces:** removes the routes `POST /api/auth/login`, `GET /api/auth/login-params`, `POST /api/auth/recovery`, `POST /api/auth/password`, `POST /api/auth/paper-recovery`, `POST /api/settings/sso/unlink`, `GET /api/setup`, `POST /api/setup`, `POST /api/admin/users`, and their handlers.

- [ ] **Step 1: Write the failing test**

```go
func TestRetiredAuthEndpointsAreGone(t *testing.T) {
	// Every path below was a way to authenticate or provision without KySignOn. Each must
	// now 404 — not 401, not 405. A 401 would mean the route still exists behind auth.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/login"},
		{http.MethodGet, "/api/auth/login-params?username=alice"},
		{http.MethodPost, "/api/auth/recovery"},
		{http.MethodPost, "/api/auth/password"},
		{http.MethodPost, "/api/auth/paper-recovery"},
		{http.MethodPost, "/api/settings/sso/unlink"},
		{http.MethodGet, "/api/setup"},
		{http.MethodPost, "/api/setup"},
		{http.MethodPost, "/api/admin/users"},
	} {
		// assert 404
	}
}
```

- [ ] **Step 2: Delete handlers and routes**

Remove the handlers named in Interfaces and their route registrations. Keep `GET /api/auth/me`, `POST /api/auth/logout`, the whole `/api/auth/oidc/*` and `/auth/sso/*` family, and every vault, device, audit and admin route not listed above.

`handleSetupCheck` is referenced by the frontend to decide whether to show a setup screen. It is deleted here; Task 7 removes the caller. Sequence matters — do not leave the frontend calling a dead endpoint across a release.

- [ ] **Step 3: Verify and commit**

Run: `go build ./... && go test -race ./...` — the whole tree must build again now that Task 4's callers are gone.

```bash
gofmt -w internal/api
git add internal/api
git commit -m "feat(auth): remove every authentication path except KySignOn"
```

---

## Task 6: Bootstrap SSO configuration from the environment

**Files:**
- Modify: `internal/sso/sso.go`, `cmd/server/main.go`, `internal/api/admin_handlers.go`
- Test: `internal/sso/sso_test.go`

**Interfaces:**
- Produces: `sso.SettingsFromEnv() (SSOSettings, bool)`; `(*Store).Load()` returns environment settings when present.

- [ ] **Step 1: Write the failing test**

```go
func TestSettingsFromEnvOverrideDisk(t *testing.T) {
	// With KYPASSWORD_OIDC_ISSUER, _CLIENT_ID and _CLIENT_SECRET set, Load() must return
	// them regardless of what is on disk. Without them, Load() must return the disk
	// settings unchanged. There is no local admin who could configure SSO through the UI,
	// so the environment has to be able to bootstrap it.
}
```

- [ ] **Step 2: Implement**

Read `KYPASSWORD_OIDC_ISSUER`, `KYPASSWORD_OIDC_CLIENT_ID`, `KYPASSWORD_OIDC_CLIENT_SECRET`, and optionally `KYPASSWORD_OIDC_REDIRECT_URI` and `KYPASSWORD_OIDC_AUTO_PROVISION`. When issuer, client ID and client secret are all set, `Load()` returns environment-sourced settings with `Enabled: true`.

At startup, if SSO resolves to disabled or has no issuer, log a clear fatal error — under this plan a server with no IdP can authenticate nobody, so starting would only serve 503s.

`PUT /api/admin/sso` must refuse to overwrite environment-sourced settings, returning `409` with a message naming the environment as the source. Silently accepting a write that the next restart discards is worse than refusing it.

Admin role on first login comes from the token's role claim via the existing `Claims.IsAdmin()`; no change needed, but confirm it reads KySignOn's `role` claim (`kysignon-server/internal/oauth/oauth.go:75` lists `role` in `claims_supported`) and report what you find.

- [ ] **Step 3: Verify and commit**

Run: `go test -race ./internal/sso/... ./internal/api/...`

```bash
gofmt -w internal/sso internal/api cmd
git add internal/sso internal/api cmd
git commit -m "feat(sso): bootstrap identity provider configuration from the environment"
```

---

## Task 7: Frontend — one way in

**Files:**
- Modify: `frontend/src/pages/LoginPage.tsx`, `frontend/src/pages/SecuritySettings.tsx`, `frontend/src/pages/AdminPanel.tsx`

**Read before writing:** all three pages, plus `frontend/src/lib/api.ts`, `frontend/src/lib/vaultCrypto.ts` and `frontend/src/lib/storage.ts`. The master password's role changes here and the crypto must not.

- [ ] **Step 1: Rebuild the login page**

`LoginPage.tsx` currently does four things: a setup check (`GET /api/setup`), local login (`/api/auth/login-params` then `/api/auth/login`), paper recovery (`/api/auth/recovery`), and first-admin setup (`POST /api/setup`). All four endpoints are gone.

What replaces them is a single "Sign in with KySignOn" action pointing at the existing `/api/auth/oidc/login`, and — **after** the SSO session exists — a separate vault-unlock step where the user enters their master password.

That separation is the point of the whole plan, and the UI must make it legible: signing in proves who you are to KySignOn; unlocking decrypts your vault with a secret this server never receives. Say that in the interface, briefly, where the user enters the master password.

The master password must never be sent anywhere. Verify by reading the network calls you leave behind: after this task, no request body may contain the master password or any value derived from it.

- [ ] **Step 2: Strip the retired settings**

`SecuritySettings.tsx` loses the change-password form (`POST /api/auth/password`, line 61) and the SSO unlink button (`POST /api/settings/sso/unlink`, line 129). Under SSO-only, unlinking is a way to lock yourself out permanently and nothing else.

Keep anything that re-wraps the vault key envelope — that is client-side crypto against `PUT /api/vault/envelopes`, and it is how a user changes their master password now. If changing the master password currently routes through `/api/auth/password` *as well as* the envelope re-wrap, the envelope path is the one that survives; make sure the flow still works end to end with the server call removed.

`AdminPanel.tsx` loses user creation (`POST /api/admin/users`). Replace it with a line saying accounts are managed in KySignOn, and leave role, deactivate and reactivate alone — those remain local overrides.

- [ ] **Step 3: Verify**

Run: `cd frontend && npm test && npm run build`

Then exercise it against a real server with SSO configured, and report what you saw: sign in through KySignOn, unlock the vault with the master password, edit an entry, sync, sign out, sign back in.

- [ ] **Step 4: Commit**

```bash
git add frontend/src
git commit -m "feat(web): sign in with KySignOn, unlock with the master password"
```

---

## Task 8: Documentation

**Files:** `README.md`, `PROMPT.md`, `AGENTS.md`, `.env.example` (create if absent)

- [ ] **Step 1: Correct the security model**

`PROMPT.md`'s "Security model" section says to reuse KyPost's client-derived authentication protocol and that the server stores a salted hash of the client-derived auth value. That is no longer true and must not be left as an instruction to a future agent — the server now stores no authentication material at all. Rewrite that bullet and the recovery bullet (paper recovery grants vault access, not site access).

- [ ] **Step 2: Document the operator-facing reality**

In `README.md`, state plainly:
- KySignOn is required. There is no local login. If KySignOn is unavailable, sign-in is unavailable; the documented fallback is downloading the KDBX and opening it in any KeePass client.
- The environment variables that configure SSO, and that they take precedence over the admin UI.
- The upgrade procedure: the server refuses to start while active accounts lack a KySignOn identity, and the two commands that resolve it.
- That replication is keyed on the KySignOn user ID, which is the OIDC `sub`.

- [ ] **Step 3: Record the contract for future agents**

In `AGENTS.md`, add a `## Replication` section giving the exact wire format KySignOn sends — bare SCIM User resource, `X-KySignOn-Event-Type` header, HMAC over `timestamp + "." + body` in `X-KySignOn-Signature` — and note that this was previously mismatched and silently no-oped, so any change to it needs a round-trip test against a real KySignOn payload rather than a unit test against our own encoder.

- [ ] **Step 4: Full gate and commit**

```bash
gofmt -l .
go build ./... && go vet ./... && go test -race ./...
govulncheck ./...
cd frontend && npm test && npm run build
docker build -t kypassword-server:latest .
```

```bash
git add README.md PROMPT.md AGENTS.md .env.example
git commit -m "docs: KySignOn is the only directory"
```

---

## Self-review notes

- **Spec coverage.** `PROMPT.md`'s zero-knowledge requirements are strengthened, not merely preserved: after Task 5 there is no endpoint that accepts a password or a password-derived value. The vault, sharing, encrypted-file and audit requirements are untouched. The "reuse KyPost's client-derived authentication protocol" instruction is deliberately contradicted and rewritten in Task 8 — that is the one place this plan overrides the spec, and it does so because decision 1 removes the thing that protocol authenticated.
- **Ordering.** Task 4 breaks the build for `internal/api` until Task 5 lands. That is deliberate: splitting the deletion into "remove the capability" and "remove its HTTP surface" gives each a reviewable diff. Do not reorder them, and do not merge the branch between them.
- **Not covered here, by choice:** rate limiting on the SSO callback, and the `X-Sync-Signature`-era compatibility shim's eventual removal. Both are follow-ups, not blockers.
- **Deliberate non-goal:** nothing in this plan changes `internal/vault`. If an implementer finds themselves editing it, the plan mis-read the coupling and they should stop and report.

---

## What this does not do

This makes KySignOn the directory. It does not merge the products, and the reasons remain: KyPassword is zero-knowledge by contract while KySignOn is a knowing server, they have opposite failure modes, and the master password must stay client-derived because it is the vault's key-wrapping secret. After this plan those two properties are cleaner, not weaker — KyPassword ends up holding *less* about its users than before, not more.

The remaining consolidation opportunity is the duplicated pairing and audit code (`zero_code_pairing_handoff_spec.md` is byte-identical across both repos, md5 `24899bae8d11ac740c58dcc5c3581e32`). That belongs in `ky_server_base` and is a separate plan, to be done after this one settles.
