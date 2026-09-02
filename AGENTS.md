# KyPassword Server

KyPassword Server is a zero-knowledge KeePass v4 management and synchronization server with web interface, mobile clients, and browser plugins.

## Core Capabilities & Architecture

1. **Zero-Knowledge KeePass v4 Vault Storage**: Server stores encrypted KDBX v4 vaults and wrapped key envelopes. The server never receives raw master passwords, plaintext vault keys, or unencrypted credential data.
2. **Key Custody & Envelopes**: Vault master key (256-bit) is wrapped client-side into password-wrapped, paper-recovery-wrapped, and device-wrapped envelopes using PBKDF2/Argon2 + AES-GCM. Changing passwords re-wraps the envelope without re-encrypting the full KDBX.
   KyAuth may upload its local KDBX and password envelope when the server vault is empty; the web client opens both raw-key and KyAuth hex-key KDBX credentials.
3. **Atomic Sync & Conflict Preservation**: Optimistic concurrency via ETag / version check (`If-Match: "{version}"`). Conflicting uploads are rejected and preserved in `conflicts/` for client deconfliction.
4. **90-Day Version History & Rollback**: Automatic version snapshots with 90-day retention policy and one-click rollback.
5. **KySignOn SSO & Directory Replication**: KySignOn is the sole authenticator and sole directory (`/api/auth/oidc/login`, `/api/sync/webhook`). There is no local login, no local account creation and no server-side credential of any kind. See "Replication" and "Authentication" below.
6. **Native Device Pairing**: 90-second PIN and QR code protocol (`/api/devices/pairing/*`) for mobile apps and browser extensions.
7. **Tamper-Evident Audit Logging**: Cryptographic hash-chained audit trail (`/api/audit/*`).
8. **KySecurity Patina Interface**: React + TypeScript frontend using Space Grotesk, IBM Plex Mono, and Patina dark theme.

## Authentication

KySignOn is the only way in. The user record holds **no** authentication material —
no password hash, no salt, no client-derived verifier, no recovery hash. A test in
`internal/users/users_test.go` asserts those JSON keys never reappear; if you find
yourself adding one, the design has been misread.

- Accounts are matched on the OIDC `sub` alone, which is the KySignOn user ID
  (`kysignon-server/internal/oauth/oauth.go:310,326`). Never match on username: doing
  so hands any KySignOn identity the local account that shares its name, and its vault.
- The master password is not a credential. It unwraps the vault key envelope in the
  browser and is never transmitted. Changing it is a client-side re-wrap against
  `PUT /api/vault/envelopes`.
- Paper recovery unlocks the vault, not the site.
- SSO settings come from `KYPASSWORD_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`
  (optional `_REDIRECT_URI`, `_AUTO_PROVISION`) and take precedence over
  `config/sso.json`. `PUT /api/admin/sso` answers 409 while they are set. Without an
  identity provider, or with an active account that has no `ssoSub`, the server
  refuses to start.

## Replication

KySignOn's sync engine dictates the wire format; KyPassword is the receiver and has no
say in it. `POST /api/sync/webhook` receives:

- a **bare SCIM 2.0 User resource** as the body — not an envelope with an `event` key
- the event in the **`X-KySignOn-Event-Type`** header: `user.created`, `user.updated`,
  `user.deleted`
- **`X-KySignOn-Signature`**: HMAC-SHA256 over `timestamp + "." + body`, with the
  timestamp in `X-KySignOn-Timestamp` — not over the body alone
- `Authorization: Bearer <secret>`, plus `X-KySignOn-Event-Id` / `Idempotency-Key`

This was previously mismatched: KyPassword expected `{"event","user"}` and an
`X-Sync-Signature` over the body only, so every event fell out of the switch and
returned 200 having done nothing, while the bearer token made KySignOn record it as
delivered. **Both sides looked healthy and no account was ever provisioned.** Any change
here needs a round-trip test against a real KySignOn payload, not a unit test against our
own encoder — the bug was that our encoder and theirs disagreed.

Status codes matter to the sender (`kysignon-server/internal/sync/sync.go`, `deliver()`):
it treats 2xx as success, plus 404 on `user.deleted` and 409 on `user.created`. A 404 on
`user.updated` is a delivery *failure* it will retry, so an update naming an unknown
subject provisions the account when auto-provisioning is on and otherwise returns 200.

Keep the configured callback URL free of `/scim`, and do not let it end in `/Users` or
`/v2`: `resolveSCIMURL()` switches to RESTful SCIM on those, sending PUT and DELETE to
paths KyPassword does not serve.

A `user.deleted` deactivates the account and **never** deletes the vault. The vault is
the user's, not the directory's.

## Verification

- Backend: `gofmt -l .` (must be empty), `go vet ./...`, `go test -race ./...`
- Frontend: `npm test && npm run build` in `frontend/` (`build` is `tsc && vite build`, so it is the typecheck gate)
- Daemon build: `go build -o ./kypassword-server ./cmd/server`
- Docker build: `docker build -t kypassword-server:latest .`
- Dependency vulns: `govulncheck ./...` and `npm audit --audit-level=high` in `frontend/`

All of the above run in CI on every push to `master` and every pull request, split
across four jobs in `.github/workflows/ci.yml`: `backend`, `frontend`, `docker`,
`security`. Keep the workflow and this list in sync when either changes.

`.github/dependabot.yml` opens weekly grouped dependency PRs for Go modules, npm,
the Dockerfile base images, and the actions themselves. `kdbxweb` and
`argon2-browser` are grouped separately from the rest of npm: a bump to either
touches vault encryption, so it needs a vault round-trip review, not a rubber stamp.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Child DOX Index

- `frontend/src/lib/storage.ts`: manages the persistent IndexedDB `keys` vault on trusted devices
  to allow 1-click SSO access without typing a password; explicit "Forget This Device" controls
  clear stored secrets from browser storage.
- `frontend/src/lib/kdbx.ts`: client-side KDBX v4 vault, written to be byte-compatible with
  KyAuth so either client opens the other's file and so a downloaded vault opens in KeePassXC.
  Two properties carry that, and both are load-bearing:
  - **The credential is the vault key as hexadecimal text**, never the raw bytes. That is what
    KyAuth uses (`KdbxPasswordVault.kt`: `Credentials.from(EncryptedValue.fromString(
    bytesToHex(vaultKey)))`), and it is the only form a human can type into KeePassXC. A
    binary-keyed vault has no offline recovery path at all — the file opens with nothing a
    person can enter.
  - **Argon2d with kotpass's `Ver4x.create()` parameters**: m=32 MiB, t=8, p=2, set explicitly
    because kdbxweb's Argon2 defaults are far weaker (1 MiB, t=2, p=1).

  The Argon2 engine is hash-wasm, not argon2-browser: argon2-browser resolves its WASM by URL
  and dies outside a browser, which left every Argon2 path untestable under `node --test`.

  **Do not "convert" the memory argument in `deriveArgon2Key`.** kdbxweb passes KiB and
  hash-wasm expects KiB. Dividing by 1024 runs Argon2 on 32 KiB instead of 32 MiB — a
  thousandfold weakening that still encrypts, decrypts and round-trips, with the header still
  advertising 32 MiB because the header is written independently of what the KDF consumed. The
  pinned-key test in `kdbx.test.ts` is the only thing that catches it; keep it.

  ponytail: kdbxweb's `setVersion` takes only a major version, so we write KDBX 4.0 while
  kotpass writes 4.1. Both libraries read both. Upgrade path is kdbxweb minor-version support.
  Also untested: opening a genuine kotpass-written file. The KyAuth fixture in `kdbx.test.ts`
  is built with kdbxweb, so it proves our credential handling, not cross-library compatibility.
- `frontend/src/lib/csvImport.ts`: zero-knowledge RFC 4180 CSV parser and multi-format importer supporting
  Google Chrome, 1Password, Bitwarden, LastPass, DashPass (Dashlane), and generic CSV formats. Provider
  folder values are split on `/` and `\` into nested KeePass groups, reusing existing groups by path;
  all parsing and vault mutation happen client-side. Covered by `csvImport.test.ts`.
  ponytail: no duplicate detection against existing entries — re-importing the same CSV duplicates it.

