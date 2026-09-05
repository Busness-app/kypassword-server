**Repo:** kypassword-server
**PR:** #25 — https://github.com/Busness-app/kypassword-server/pull/25
**PR:** #26 — https://github.com/Busness-app/kypassword-server/pull/26
**PR:** #24 — https://github.com/Busness-app/kypassword-server/pull/24 (Phase A merged)
**PR:** #23 — https://github.com/Busness-app/kypassword-server/pull/23 (original plan merged)
**Worktree:** /home/yoshi/busness.app/kypassword-server (branch feat/verified-directory-auth)

# Post 289 implementation plan: recoveryclient, then authentication

Updated 2026-09-05. Owner: marigold. MySlop folder: `kypassword-kyrecovery-deposit`;
claim: post 298. This document replaces the previous plan, including its completed Phase A
checklists, obsolete library gates, and proposed token re-encryption. This turn produces a
plan only; implementation, PR submission, and deployment are subsequent work.

## Verified baseline and scope

- Fetched KyPassword `origin/master` and local HEAD both resolve to
  `1259b5da623365fe076bc1d4d167a655b0fc53b3`; checkout was clean before this plan edit.
- Phase A is merged: LAN DNS override, restore runbook, fresh-admin gate, POST export and
  session-bound CSRF checks exist. Preserve them.
- `go.mod` still pins ky-primitives v0.4.1. The locally available v0.5.1 tag resolves to
  `e9bd63b44ea62b98340a90e18a35e2ffd8d21f66`; its module-cache sources include
  `recoveryclient`, `syncauth`, and `oidcverify`. Use that released version for this work.
- KySignOn's locally fetched `origin/master`, `a2d5dbc59c0724fd96dc21a861f1e6ba33b38711`,
  imports recoveryclient in `internal/backup/adapter.go`. The old first-consumer gate is
  satisfied. Re-fetch reference repositories before implementation; this is a snapshot.
- KyPassword uses file stores. Keep existing `Snapshot` methods for vaults, users, devices,
  SSO and audit. No SQL database, SQLiteSnapshot, or server-side KDBX decryption belongs here.
- Two reviewable changes: PR B completes backup adoption; a separate PR C adopts signed
  sync and verified OIDC. Preserve existing worktrees; create implementation branches from
  refreshed master, carrying this plan forward. No new framework or dependency beyond the
  existing shared module upgrade is needed.

Read parent and root AGENTS.md plus `internal/backup/AGENTS.md` before implementation.
The wire source is `../kyrecovery-server/zero_code_pairing_handoff_spec.md` v2.0.0;
use library source for exact signatures, not copied API declarations in historical plans.

## PR B: backup adoption

### 1. Pin the dependency and prove existing-state compatibility

Files: `go.mod`, `go.sum`, `internal/backup/state.go`, a small adapter file and state tests.

- [ ] Upgrade to v0.5.1 and tidy. First capture a synthetic fixture produced by the current
  StorePairing code: `kyrecovery.json`, raw `recovery.pub`, `recovery-token.key`, and receipt.
  Keep real deployment credentials out of tests and the board.
- [ ] Implement `recoveryclient.Settings` over the existing persistedState shape. Map the
  six existing library keys to recoveryUrl, sealedToken, recoveryKeyId, threshold,
  totalShares and lastDeposit. Add optional interval and last-attempt fields for
  `backup_interval_sec` and `backup_last_attempt`. Missing differs from an explicitly empty
  string or zero; use presence-aware fields for new settings. Delete of a missing key is
  harmless. Unknown keys fail explicitly rather than disappearing.
- [ ] Preserve existing AES-GCM Sealer bytes: direct 32-byte token key, nonce prefix,
  RawStdEncoding, additional data `kypassword:kyrecovery_token`. Wrap the existing functions
  to satisfy Seal/Open; do not switch to the library's HKDF sealer or rewrite old tokens.
  Opening never creates a missing token key. New pairing may create it.
- [ ] Keep mutex-protected read/modify/temp-file/rename persistence at 0600. Library lifecycle
  calls make several Settings writes: serialize competing pairing/pin/unpair operations
  and state snapshots at the product boundary, without recursively locking Settings calls.
  Verify partial failures retain the pin and expose degraded state. Do not assume each
  atomic Set makes an entire lifecycle transaction atomic.
- [ ] Tests: old fixture loads unchanged through library LoadPairing; mutate schedule and
  save a receipt, restart, and verify URL/token/key/topology/receipt survived. Missing or
  wrong token key, corrupt ciphertext/JSON, failed persistence, missing public key, and
  conflicting pin fail visibly without overwriting existing state.

Acceptance: focused state tests pass under race detection; existing pairing needs no
migration or re-pair. Record fixture provenance and byte-level token/key comparisons.

### 2. Replace lifecycle code; retain collection and validation

Files: `internal/backup/{backup,state,client,drill}.go`, adapter and focused tests;
`cmd/server/backup.go`.

- [ ] Use recoveryclient pairing, key pin, Seal, Run, Outcome, local copies, schedule, Drill,
  ReadShares and Restore. Delete superseded protocol/crypto lifecycle code and tests that
  merely duplicate the library; retain product compatibility and integration checks.
- [ ] Keep `kypassword` as Payload.ServiceName, RunConfig.AppName and restore expected service.
  `KyPassword` is only the display name sent alongside the explicit pairing service name.
  RunConfig.DataDir must be CONFIG_DIR, where recovery.pub already lives. Drill scratch is
  under DATA_DIR; these two directory roles are different.
- [ ] Convert Collector output to library Payload using the existing locked snapshots.
  Preserve paths, effective environment-sourced secrets, history/conflicts, audit key/anchor
  consistency, and encrypted KDBX metadata/checksums. Keep backup output and drill scratch
  out of collection. CapsuleFiles includes the token key when needed for stored ciphertext;
  a manually pinned, never-paired instance must work without a token key.
- [ ] Keep the daemon/offline CLI instance lock and graceful-shutdown waiting. Route manual,
  scheduled and CLI backups through one product RunBackup wrapper. Library Run seals once;
  don't add a second seal per destination. Keep detached bounded upload contexts and the
  HTTP write deadline so a disconnected browser cannot cancel a committed backup attempt.
- [ ] Adapt drill checks to `func(dir string, opened capsule.Manifest) []recoveryclient.Check`.
  Validate the opened recipe's required_files array (JSON-decoded []any), element types,
  clean relative paths, expected mandatory members and required check flags. Invalid or
  missing recipe data fails; it must not suppress audit or vault checks. Handle valid
  empty instances explicitly. Serialize drills; scratch is owner-only and removed on error.
- [ ] Preserve actual restore validation. v0.5.1 Restore extracts and prints information but
  returns only error: it does not invoke KyPassword checks or return the opened manifest.
  After successful library Restore, run retained fixed product checks against restored
  files before reporting success. Buffer success output until checks pass. Do not parse
  display output or treat an unverified manifest as authenticated. Drill remains the path
  for manifest-driven recipe validation. Keep empty-target enforcement and stdin-only shares.
- [ ] Use guardtest.NoDecryptOutside from an absolute repo root, allowing only
  `cmd/server/backup.go:runRestore` for library Restore. Prove the guard detects a forbidden
  call in an isolated fixture/subprocess with the required file-count floor; leave no probe.

Acceptance: old-format capsule restores with synthetic shares; reopened users/devices/SSO,
vault bytes/metadata and audit state match. Bad recipe, omitted required file, bad checksum,
wrong service, insufficient shares and nonempty target fail. No normal process path handles
recovery private material or plaintext vault keys.

### 3. Config, routes, schedule, status and UI

Files: `cmd/server/main.go`, `internal/api/{server,backup_handlers,backup_freshness_test}.go`,
`frontend/src/components/AdminBackup.tsx`, existing frontend API helpers if necessary,
`.env.example`, `docker-compose.yml`, README and `docs/RESTORE.md`.

- [ ] Wire KYPASSWORD_BACKUP_DIR (absolute path or disabled), BACKUP_KEEP (default 7, >=1),
  BACKUP_ALLOW_PRIVATE_RECOVERY (explicit boolean, default false), all with KYPASSWORD_
  prefix. Keep BACKUP_DEPOSIT_INTERVAL duration syntax/default 24h; validate off or whole
  seconds in [900,31622400] before using it as the library Interval default. Persisted admin
  interval overrides the environment and takes effect without restart.
- [ ] Preserve HTTPS, no redirects, and forbidden-address checks through library Options.
  Private-network opt-in is audited and names the correct product variable in errors.
  Pass new variables through compose; local backup directory must be on a mounted volume.
  Keep DNS confined to the existing optional override and KYPASSWORD_DNS.
- [ ] Add POST `/api/backup/pin-key`, DELETE `/api/backup/pairing`, PUT
  `/api/backup/schedule`; keep existing routes. Pair, pin, unpair, schedule, deposit and
  export require fresh admin plus session CSRF. Drill requires admin plus CSRF; status is
  admin read-only. Extend the real route table tests for every mutation, stale sessions,
  missing CSRF, nonadmins, and device-issued tokens with no authentication timestamp.
- [ ] Status separates pinned key health from remote pairing. Validate stored token health
  without returning the token. A stored pin with missing public key remains degraded even
  when locally pinned/unpaired; library ErrNotPaired alone cannot describe that state.
  Show topology, remote URL, receipt, local copies, effective interval, last attempt and next
  attempt. Map `fs.ErrExist` from pin conflict to 409, no destination to 412, busy to 409.
- [ ] Persist a bounded, secret-free last-run summary in the same product state store;
  the library records last attempt and receipt, not the last failed/local-only outcome.
  Preserve both destinations' results. v0.5.1 Run can return an error after a successful
  local write when remote delivery fails; don't discard that success or claim total failure.
  Report receipt-unrecorded as delivered with a persistence error. Reuse Outcome for audits.
- [ ] Poll NextRun every minute, count from last attempt on success and failure, and drain
  active work on shutdown. Never-paired/no-key may skip quietly; pinned/no-destination and
  broken keys must be explained in status and bounded audits, not hidden as unpaired.
- [ ] Extend existing AdminBackup controls: key and destination status, local copies,
  last result, next attempt, pin form, interval/off form, unpair and Back up now. Use existing
  React styles and API helpers. Unpair clears only URL/token, retaining pin/topology,
  receipt/local copies; explain separate KyRecovery-admin revocation. Preserve export and
  drill UX, reauthentication link and the zero-knowledge explanation. No secrets in status,
  errors or audit output. Keep current response fields or adapt handler and UI together.

Acceptance: one fixture verifies local-only, paired-only and dual-destination paths; both
copies are identical sealed bytes, receipts match digest/ID, local retention affects only
this service's files, and files are 0600. Test partial failures, schedule changes/restart,
second-key refusal, unpair/re-pair to same key, and interrupted persistence. Run frontend
checks and inspect the running UI with keyboard navigation and representative error states.

## PR C: signed sync and verified OIDC

Files: `internal/sync/scim.go`, `internal/sso/sso.go`,
`internal/api/{auth_handlers,sync_handlers,server}.go` and their integration tests.

- [ ] Trace KySignOn's actual sender before changing the receiver. syncauth v1 signs timestamp,
  event type, event ID and body digest, uses RFC3339 timestamps and `v1=` signatures, and
  sends no bearer secret. It is incompatible with today's timestamp-dot-body signature.
  Coordinate sender/receiver deployment; don't silently accept unsigned bearer fallback.
  Inspect current multiple-secret support (`syncSecrets`) and preserve authorized secret
  rotation using library verification, without a second custom HMAC implementation.
- [ ] Install syncauth.Middleware, consume its verified event, bound the body and rejection
  audit rate, and supply a shared bounded replay guard. Test retry-after-handler-failure and
  sender idempotency behavior: middleware remembers the ID before the handler succeeds, so
  this needs an explicit sender/receiver integration decision, not a guessed retry policy.
  Document in-memory replay protection's restart limit; persistent replay is needed if the
  accepted threat model requires protection across restarts.
- [ ] Keep real bare SCIM parsing, subject-only lookup, unknown-update provisioning policy,
  delete deactivation without vault deletion, and sender-compatible response codes.
  Test a library-signed real KySignOn payload through the mounted route, then tampered body,
  type/ID, wrong secret, replay, stale timestamp, missing signature and oversized body.
- [ ] Replace ParseClaims' unverified JWT decoding with a reusable oidcverify.Verifier for
  configured issuer/client and discovered JWKS. Add a cryptographic nonce to login state
  and the authorization request; current login has PKCE/state but no nonce. Bind callback
  state to the initiating session/configuration, consume it once, and use VerifyWithNonce
  before any account lookup/link, role assignment or AuthenticatedAt update.
- [ ] Preserve PKCE, state and subject-only identity mapping. Only verified token claims may
  grant roles. Remove userinfo as an authentication fallback; if profile enrichment remains,
  require its sub to equal the verified subject. Review the existing cookie-carried linkUserID
  branch and bind any retained linking to the authenticated initiating user.
- [ ] Test real signed tokens from a local TLS issuer/JWKS through login/callback: valid login,
  forged signature, none/wrong algorithm, issuer/audience, expiry, unknown/rotated kid,
  missing/wrong nonce, mismatched/reused state, userinfo subject mismatch and same-username
  different-subject isolation. Re-run fresh-admin tests against verified login sessions.

Acceptance: actual sender/receiver round trip and OIDC callback pass; negative cases produce
no account/session mutation. The documented rollout identifies sender compatibility and
retry behavior. These are implementation gates, not reasons to delay the backup plan.

## Verification, documentation and handoff

- [ ] After each implementation phase, run focused meaningful integration tests; at PR B/C
  completion run root `gofmt -l .` (empty), `go vet ./...`, `go test -race ./...`,
  `go build -o ./kypassword-server ./cmd/server`, frontend `npm test && npm run build`,
  `docker build -t kypassword-server:latest .`, `govulncheck ./...`, and frontend
  `npm audit --audit-level=high`. Validate base/override compose config as well.
- [ ] DOX: update root and backup AGENTS.md with actual ownership, private-recovery policy,
  validation, settings and route behavior. Update root replication/auth contracts with PR C.
  Keep README/env table/restore runbook and CI verification list aligned. Frontend dist is
  not tracked. This plan-only edit leaves AGENTS.md unchanged because runtime contracts
  and verification have not changed.
- [ ] Open each implementation PR and drive CI plus current-head autonomous reviewer to
  clearance. Report exact tested SHA, remaining external gates and mirror the handoff to
  the existing MySlop folder before stopping. Human merge and live proof are separate.

## Live proof after implementation

Preserve deployment volume, issuer, recovery key and pairing. Use the intended homelab's
explicit private-recovery switch and LAN override with KYPASSWORD_DNS=192.168.1.1;
source deployment uses `up -d --build`. Verify readiness and unchanged pinned key ID,
then deposit without re-pairing. Record deployed SHA, capsule ID, digest, receipt time and
local-copy result. KyRecovery endpoint: https://kyrecovery.urlxl.us; compare its key fingerprint
out of band. If there was no existing pairing, label the result first-pair proof.

Test local-only, schedule and conflicting key behavior on disposable state, then restore
using synthetic shares. Real custodian-card restoration is a separate operator exercise:
shares go locally through stdin, never chat, argv or shared notes. No prior KySignOn deposit
proves this product's migration or restore.

## Planning completion (historical)

Code and released library interfaces were inspected; no application implementation, tests,
PR creation or deployment was performed in this planning turn. The next task is PR B step 1.
The MySlop claim remains with marigold for continuity; claim ownership does not mean an
implementation process is running in the background.


## Implementation follow-up — 2026-09-05

The plan has now been implemented in two ready PRs:

- PR #25: https://github.com/Busness-app/kypassword-server/pull/25
  (`feat/recoveryclient`, code head `115d6048cf0fa2c5766cfd7307000731dca1d9d1`).
  recoveryclient v0.5.1 owns pairing/deposit/sealing and recovery orchestration;
  the adapter preserves the existing disk schema, direct AES-GCM token wrapping,
  key paths and explicit settings presence. Local backups, retention, schedules,
  pin/unpair UI, partial-result reporting, drill validation and the private-material
  guard are implemented. Genuine old-code pairing and v0.4.1 capsule fixtures prove
  restart and restore compatibility with synthetic data.
- PR #26: https://github.com/Busness-app/kypassword-server/pull/26
  (`feat/verified-directory-auth`, combined code head
  `29cb1de08dee737cfdb4bd538687384f4848228f`).
  Signed sync requires syncauth verification, preserves retries after failed mutations,
  and prevents completed-event reuse with changed payloads. OIDC uses PKCE, single-use
  server-side state, nonce and JWKS signature/issuer/audience verification before any
  account mutation. A real KySignOn-emitted SCIM fixture and TLS/JWKS integration tests
  cover the cross-product boundary and invalid tokens.

Full local verification passed: formatting, vet, race tests, daemon and Docker builds,
frontend tests/build, govulncheck and npm audit; compose configuration was validated.
After the final settings/capsule additions, full backend race tests, vet and daemon build
passed again on both code heads above. CI passed all four jobs before those final
additions; current-head CI and security-review clearance must be checked on GitHub.

The ready PRs have received no autonomous security-review comment after repeated ticks;
Copilot separately reported its quota exhausted. Neither is a security clearance.
The pull-request skill requires asking the operator after two ticks with no reviewer.
Operator action: restore the autonomous reviewer for this repo or designate a replacement
review process. Do not call the PRs cleared without a verdict for the current head.

Merge #25 first, then retarget #26 to master and recheck its gates. No merge or live
rollout has been performed. The live proof above remains: preserve deployment state and
pairing, verify a deposit without re-pairing, then record deployed SHA and capsule receipt.
Real recovery shares must stay out of chat, arguments and board notes.

Remaining limitations: sync completion receipts are bounded and in-memory (restart clears
them); the extra documentation-address URL restriction applies to literals, while DNS
resolution follows the library policy. Restore fixtures use disposable vault placeholder
bytes and prove ciphertext preservation, not a real client vault unlock.
