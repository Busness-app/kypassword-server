# KyPassword Server

KyPassword Server is a zero-knowledge KeePass v4 management and synchronization server with web interface, mobile clients, and browser plugins.

## Core Capabilities & Architecture

1. **Zero-Knowledge KeePass v4 Vault Storage**: Server stores encrypted KDBX v4 vaults and wrapped key envelopes. The server never receives raw master passwords, plaintext vault keys, or unencrypted credential data.
2. **Key Custody & Envelopes**: Vault master key (256-bit) is wrapped client-side into password-wrapped, paper-recovery-wrapped, and device-wrapped envelopes using PBKDF2/Argon2 + AES-GCM. Changing passwords re-wraps the envelope without re-encrypting the full KDBX.
   KyAuth may upload its local KDBX and password envelope when the server vault is empty; the web client opens both raw-key and KyAuth hex-key KDBX credentials.
3. **Atomic Sync & Conflict Preservation**: Optimistic concurrency via ETag / version check (`If-Match: "{version}"`). Conflicting uploads are rejected and preserved in `conflicts/` for client deconfliction.
4. **Bounded Version History & Rollback**: Keep up to 100 snapshots per user spread across a default 90-day age window, with one-click rollback. Saves and rollbacks prune synchronously under the store lock. After age expiry, preserve the oldest/newest snapshots and thin the closest-spaced interior snapshots so a burst of writes cannot erase the pre-session recovery window.
5. **KySignOn SSO & Directory Replication**: KySignOn is the sole authenticator and sole directory (`/api/auth/oidc/login`, `/api/sync/webhook`). There is no local login, no local account creation and no server-side user credential. See "Replication" and "Authentication" below.
6. **Native Device Pairing**: 90-second PIN and QR code protocol (`/api/devices/pairing/*`) for mobile apps and browser extensions.
7. **Tamper-Evident Audit Logging**: Cryptographic hash-chained audit trail (`/api/audit/*`).
8. **KySecurity Patina Interface**: React + TypeScript frontend using Space Grotesk, IBM Plex Mono, and Patina dark theme.
9. **Blind KyRecovery Deposits**: `internal/backup` snapshots encrypted vault and operational state, uses `ky-primitives/recoveryclient` to seal `kycap/3` capsules to the pinned suite recovery public key, and writes local copies and deposits them without giving KyRecovery or this server the recovery private key.

## Authentication

KySignOn is the only way in. The user record holds **no** authentication material —
no password hash, no salt, no client-derived verifier, no recovery hash. A test in
`internal/users/users_test.go` asserts those JSON keys never reappear; if you find
yourself adding one, the design has been misread.

- Pending OIDC attempts are bounded at 1024; at capacity, evict the earliest expiry
  and admit new logins. Evicted attempts must restart. Issuer configuration is normalized
  by removing trailing slashes before both discovery and token verification; discovered
  and signed issuer values must still match exactly.
- Accounts are matched on the OIDC `sub` alone, which is the KySignOn user ID
  (`kysignon-server/internal/oauth/oauth.go:310,326`). Never match on username: doing
  so hands any KySignOn identity the local account that shares its name, and its vault.
- OIDC login attempts keep settings, PKCE verifier and nonce server-side for five minutes.
  The cookie is an opaque single-use state. Discovery/token transport is HTTPS with no
  redirects; `oidcverify.VerifyWithNonce` verifies issuer/client/signature/nonce before
  claims can create/link accounts or sessions. Userinfo is not an authentication fallback.
- The master password is not a credential. It unwraps the vault key envelope in the
  browser and is never transmitted. Changing it is a client-side re-wrap against
  `PUT /api/vault/envelopes`.
- Paper recovery unlocks the vault, not the site.
- Destructive backup actions require a recent KySignOn-authenticated session. Device-pairing
  tokens carry no authentication timestamp and cannot refresh that gate. Capsule export is
  POST-only and requires the session-bound CSRF token because it snapshots the whole service.
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
- **`X-KySignOn-Signature`**: `syncauth` v1 HMAC binding the RFC3339 timestamp,
  event type, event ID and body digest. Use the shared Sign/Middleware, not a local encoder.
- `X-KySignOn-Event-ID` is stable across retries; no bearer secret is sent or accepted.
  A verified completed retransmission gets 200 without another mutation; failed handlers
  may retry. ID reuse with different content/type is rejected. Completion receipts are
  bounded and in memory for the signature window; restart durability needs persistent receipts.

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

For signed replication, configure suite type `kypassword` with callback
`/api/sync/webhook`. Deploy the signed KySignOn sender with this receiver;
legacy unsigned or timestamp-dot-body webhook requests are rejected.

Standard Users-only SCIM uses `/scim/v2` and the shared `ky-primitives/scim` v0.6.0
wire types. It is disabled unless `KYPASSWORD_SCIM_TOKEN` is set (32–512 characters).
That dedicated bearer token grants directory access only; session, pairing and OIDC
secrets are not SCIM credentials. The deployment token overrides a restored `CONFIG_DIR/scim.token`. Collect the effective
token inside sealed capsules; it grants directory access but never user sessions. To disable
SCIM after restore, remove that file and unset the environment token.

`POST /Users` requires `externalId` equal to the KySignOn OIDC subject and returns the
server-owned local `id`. Lookup supports equality on `externalId` or `userName`, with
bounded pagination. PUT preserves the subject; PATCH supports add/replace of userName,
active, emails and roles, plus removal of emails/roles. Store one email and role per user;
reject additional values rather than discard them. Validate every operation before
one atomic directory update. Groups, bulk and arbitrary filters/attribute paths are outside
this interface. `/ServiceProviderConfig` advertises supported operations.

DELETE marks the account `scimDeleted` and inactive while retaining its vault. Only inactive
tombstones are hidden from SCIM GET/list; a local admin's reactivation must remain visible.
Creating the same externalId or an explicit signed `user.created` recovers the retained account.
Signed `user.updated` acknowledges but never restores inactive tombstones, recording
`sync.update_ignored_deleted`; explicit signed recreation records `sync.user_restored`.
SCIM authentication/disabled-route failures use `recordAnonymousRejection` with action
`scim.rejected`, a fixed non-secret detail and the existing source audit budget.
Successful SCIM writes distinguish `scim.user_created`, `scim.user_restored` and
`scim.user_updated`; details record role/active state or transitions, never credentials.
Deactivation invalidates existing sessions and outstanding pairing codes. The standard
client must use its bearer token and returned server IDs; the old signed generic sender's
empty DELETE payload is not accepted by this interface. `Admin → User Directory` shows
configuration and the base URL, never the token. `internal/api/scim_handlers_test.go` drives
the real shared client over TLS and checks convergence with the captured KySignOn payload.

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

- `frontend/src/lib/autoLock.ts` and `App.tsx`: per-tab vault idle locking defaults to five
  minutes; Security offers 1/5/15/30/60 minutes saved per browser. Check both wall and
  monotonic elapsed time before accepting activity, including focus/visibility resume.
  Lock invalidates pending unlocks and discards the save queue. A session-storage lock
  marker prevents refreshing the locked tab from using its trusted key. Mirror activity and
  lock markers in localStorage so a new tab after closure/browser restart also expires the
  cached key; missing or invalid activity requires a password. Automatic lock
  also removes that cached device key. Other already-unlocked tabs keep their own timers.
- `frontend/src/lib/lockedDraft.ts`: automatic lock checkpoints applied unsaved vault changes
  and unapplied entry fields, AES-GCM encrypted with the vault key and account-bound AAD.
  A separate IndexedDB database preserves the existing key-store version for older clients.
  Each lock allocates a fresh checkpoint ID so duplicated tabs cannot overwrite each other.
  Ordinary unlock does not open recovery storage unless this account has a checkpoint reference.
  Copies belong to a tab/account, survive refresh, and are consumed after successful
  decryption on unlock. Restore uses the original server version and requires explicit retry
  for unsaved changes, preserving conflict protection. Recovery read failures open the server
  copy with a notice and retain the unread reference; cleanup failures also surface a notice.
  Cache-key write failure does not block password unlock. Storage failure retains encrypted
  memory recovery and an unload warning; encryption failure locks anyway and reports the loss.
  Manual lock/logout still ask before discarding unsaved edits. Forget removes this tab's copy.
  ponytail: closing a tab without restoring it loses the reference to its encrypted checkpoint;
  a cross-tab recovery inventory and retention policy are future work. No offline login/unlock.

- `frontend/src/lib/vaultSave.ts`: owns one automatic save queue per unlocked vault.
  Applied edits, entry/folder creation, deletion, and CSV import enqueue saves after 1.5 seconds
  of idle time. Explicit retry flushes immediately. Serialize
  KDBX exports and uploads; each success acknowledges only its starting edit revision and
  advances the version for the next upload. Failures (including 409) remain unsaved and
  require explicit retry. Uploads use the shared CSRF request helper. `App.tsx` retains
  the queue and mounted editor across tabs, warns before unloading unsaved work, and guards
  rollback. Lock/logout/forget always allow the user to confirm discarding unsaved or in-flight
  edits; saving cannot refuse those actions. Closing/replacing the queue cancels its timer,
  aborts transport and prevents later revisions uploading. An already accepted request cannot
  be undone. Logout clears the visible vault before network I/O; forgetting starts key removal
  independently of logout. Draft fields require Apply Edits; automatic locking preserves them in the encrypted local checkpoint.
  `vaultSave.test.ts` checks encrypted round trips, debounce, cancellation, failures, and retry.

- `frontend/src/styles/styles.css`: `.settings-page` provides the bounded scroll area for
  Admin and Security within the fixed-height app shell; keep long backup forms reachable.

- `internal/backup/AGENTS.md`: owns the recoveryclient settings/sealer adapter, file-store
  collection, product restore validation, and backup integration. Vault validation is ciphertext/checksum-only;
  only drills and restores may hold private recovery material.

- `frontend/src/lib/storage.ts`: manages the persistent IndexedDB `keys` vault on trusted devices
  to allow 1-click SSO access without typing a password; explicit "Forget This Device" controls
  clear stored secrets from browser storage.
- `frontend/src/lib/vaultCrypto.ts`: the vault key envelope — **the only place a
  human-chosen secret is stretched**. Everything else is keyed on a 256-bit random vault
  key, where the KDF is near-irrelevant; here it is the whole defence, and the envelope is
  stored server-side, so anyone holding a backup can attack the master password offline
  forever. Argon2id, m=64 MiB, t=3, p=1 (OWASP), AES-GCM over the vault key.

  The envelope is self-describing so parameters can be raised later without a format break:

  ```json
  {"kdf":"argon2id","salt":"…","iv":"…","ciphertext":"…",
   "memoryKiB":65536,"iterations":3,"parallelism":1}
  ```

  **`memoryKiB` is KiB.** The field is named for its unit on purpose — mixing it up runs
  Argon2 on a thousandth of the intended memory while every round-trip still succeeds and
  the recorded parameters still read correctly. `deriveEnvelopeKey` is exported and pinned
  to a known vector in `vaultCrypto.test.ts` for exactly that reason; the parameter
  assertions alone cannot catch it, because they only check what was written.

  **This is a cross-product format.** KyAuth reads *and writes* envelopes
  (`KyPasswordEnvelopeCrypto.kt`), and today it writes PBKDF2-HMAC-SHA256 at 600k
  iterations. An envelope with no `kdf` field is PBKDF2 by definition, and
  `unwrapVaultKey` still reads that shape so a vault uploaded by an un-updated KyAuth
  remains openable. Remove the PBKDF2 path only once KyAuth writes Argon2id.

  Shared vector for whoever implements the Kotlin side — Argon2id, m=65536 KiB, t=3, p=1,
  32-byte output, password `correct horse battery staple`, salt = 16 bytes of `0x03`:

  ```
  73eb74162616418d643f08dc0856539ea61400cb268f85ce8df01d8257795b8d
  ```

  Both implementations must produce that. Unit tests per repo only prove each side is
  self-consistent; agreeing on a vector is what proves they interoperate — the same lesson
  the silently-mismatched replication format taught.

- `frontend/src/lib/kdbx.ts`: client-side KDBX v4 vault, written to be byte-compatible with
  KyAuth so either client opens the other's file and so a downloaded vault opens in KeePassXC.
  Two properties carry that, and both are load-bearing:
  - **The credential is the vault key as hexadecimal text**, never the raw bytes. That is what
    KyAuth uses (`KdbxPasswordVault.kt`: `Credentials.from(EncryptedValue.fromString(
    bytesToHex(vaultKey)))`), and it is the only form a human can type into KeePassXC. A
    binary-keyed vault has no offline recovery path at all — the file opens with nothing a
    person can enter.
    Legacy web vaults still require binary-key reads: `open` tries hexadecimal first and
    falls back only on `InvalidKey`. A legacy load uses hexadecimal credentials for the next
    explicit save/export, without uploading or changing the original snapshot on unlock.
    Keep the legacy open/export regression test alongside the new-vault checks.
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
