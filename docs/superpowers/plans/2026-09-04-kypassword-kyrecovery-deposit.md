# KyPassword adopts KyRecovery pairing and sealed deposits

Plan, 2026-09-04. Repo `kypassword-server`, surveyed at `db42308` on `master`.
Implementation branch: `feat/kyrecovery-deposit`; suggested worktree:
`.claude/worktrees/deposit`.

## Goal

Add the suite-standard KyRecovery lifecycle: claim a pairing code, pin the suite recovery
public key, seal a complete zero-knowledge KyPassword backup, deposit it on demand and on a
schedule, export it for an operator, prove it through a restore drill, and restore it from
custodian shares.

This work must preserve KyPassword's central security property: the server still never sees a
master password, plaintext vault key, or decrypted KDBX data. A recovery capsule protects the
server-side encrypted artifacts and operational keys; it does not bypass a user's vault
password or paper-recovery envelope.

## Sources of truth

- Wire contract: `kyrecovery-server/zero_code_pairing_handoff_spec.md` v2.0.0.
- Shared formats: `github.com/Busness-app/ky-primitives@v0.4.1`, especially `capsule` and
  `recoverykey`.
- Product-side baseline: `ky_server_base/internal/backup`.
- Hardened non-scaffold adaptation: the decisions in MySlop folder
  `kypassword-kyrecovery-deposit`, plus the URL/token hardening already implemented in
  `kydns-server/internal/backup`.
- KyPassword's local contracts and verification commands: `AGENTS.md` and
  `/home/yoshi/busness.app/AGENTS.md`.

Copy the protocol behavior, not the scaffold's database assumptions. KyPassword has no SQL
database or server-side vault decryption key.

## Findings that change the port

1. Durable state is file based, split between `DATA_DIR` and `CONFIG_DIR`:
   - `DATA_DIR/vaults/**`: encrypted KDBX files, envelopes, history, and conflicts.
   - `DATA_DIR/audit/audit.jsonl`: the append-only audit log.
   - `CONFIG_DIR/users.json`, `devices.json`, and the active SSO configuration.
   - `CONFIG_DIR/audit.key` and `audit.state` (or an `AUDIT_KEY` supplied by the
     environment).
   - `CONFIG_DIR/pairing.secret` (or `PAIRING_SECRET` supplied by the environment).
   There is no SQLite handle to snapshot and no `VACUUM INTO` path to copy.
2. Vault writes replace `vault.kdbx` and `metadata.json` separately under the vault store's
   mutex. A raw recursive directory copy can pair one generation's ciphertext with another
   generation's checksum. The collector must snapshot through the live vault store lock and
   validate every current KDBX checksum before sealing.
3. The audit log and its rollback-detection state are a pair. They must be captured with the
   audit store lock held, including the in-memory audit key when `AUDIT_KEY` supplied it.
4. `PAIRING_SECRET` authenticates KySignOn replication. A restore that loses it will reject
   future directory events, so the collector must place the effective secret in the sealed
   payload even when it originated in the environment.
5. The active OIDC client secret may also come from the environment and override `sso.json`.
   Serialize the active `sso.Store.Load()` value into the sealed payload; do not merely copy a
   possibly stale file.
6. KyPassword has admin sessions but no step-up model and no server-side CSRF verifier. Use the
   existing `withAdmin` boundary and the frontend's existing `secureFetch` behavior. Adding a
   new global step-up or CSRF system is separate security work, not part of this port.
7. `frontend/dist` is not tracked. Build it as a gate, but do not add generated assets.

## Fixed design decisions

- The KyRecovery service name is the constant `kypassword`; the display/app name is
  `KyPassword`. Do not derive the service name from operator-controlled branding: pairing pins
  it byte-for-byte and a later rename would make every deposit fail.
- Read the application version from Go build information and fall back to `dev`; pass it into
  the API config so CLI and HTTP seals record the same value.
- Store `recovery.pub`, `kyrecovery.json`, and `recovery-token.key` under `CONFIG_DIR` beside
  `audit.key`. `kyrecovery.json` holds the URL, key ID, custodian topology, AES-GCM-sealed API
  token, and last verified receipt. It never holds the token in plaintext.
- Generate the 32-byte token-encryption key with `keyfile.LoadOrCreate`. Include that key only
  inside the recovery-key-sealed capsule so a restored instance can resume deposits.
- Treat the key ID in `kyrecovery.json` as the durable pin. If it exists but `recovery.pub` is
  missing, return `ErrKeyPinMissing`, show a degraded status, and audit the failure. Never call
  this state unpaired. Re-pairing to a different public key returns `fs.ErrExist`.
- Persist the public key/pin before the URL and sealed token. If later persistence fails, keep
  and audit the pin; an operator may retry the same pairing key but may not replace it silently.
- Refuse recovery URLs with anything except a plain HTTPS origin: no userinfo, query, fragment,
  private/loopback/link-local/multicast/unspecified address, CGNAT, protocol-assignment,
  benchmark, reserved, documentation, or NAT64-wrapped private ranges. Validate every resolved
  address at dial time and refuse redirects outright.
- A file-store snapshot is valid when each store contributes a lock-consistent view and the
  collector's cross-file checks pass. Users may exist without vaults, and devices may exist
  without device envelopes, so there is no useful global transaction to invent.
- Local CLI commands that read or write live stores must not race the daemon. Hold an advisory
  instance lock for the daemon lifetime and have `backup-drill`, `export-capsule`, and `deposit`
  refuse while it is held, directing the operator to the admin UI/API. Kernel-released locking
  avoids stale PID files after a crash. `restore` targets a new directory and does not need the
  live-instance lock.
- A restore drill proves capsule opening, path/mode safety, JSON readability, audit-chain
  integrity, and every current KDBX ciphertext checksum. It explicitly reports that it cannot
  decrypt user vaults because KyPassword holds no plaintext vault key. Do not add a server-side
  key merely to make the drill claim more.

## Capsule contents

Use paths relative to a restore root so the restored service can start with
`DATA_DIR=<root>/data` and `CONFIG_DIR=<root>/config`:

- `data/vaults/**`: current encrypted KDBX files, metadata/envelopes, history, and conflicts.
- `data/audit/audit.jsonl`.
- `config/users.json` and `config/devices.json` (emit valid empty arrays if the stores are
  empty and no files exist yet).
- `config/sso.json`, synthesized from the active settings, including its client secret inside
  the sealed capsule.
- `config/pairing.secret`, synthesized from the effective runtime value.
- `config/audit.key` and `config/audit.state` from one audit-store snapshot.
- `config/recovery.pub`, `config/kyrecovery.json`, and
  `config/recovery-token.key` once pairing state exists.
- `config/restore-manifest.json`, a secret-free description of the service name, source
  version, retention setting, expected directory layout, and the explicit statement that no
  server-held vault decryption key exists.

Ephemeral login sessions and device pairing PINs stay out: they live only in memory and should
not survive a disaster. Temporary `*.tmp` files and backup scratch directories stay out.

## Task 1: Update the shared dependency and delete the stale protocol copy

Files: `go.mod`, `go.sum`, delete `zero_code_pairing_handoff_spec.md`.

1. Run `go get github.com/Busness-app/ky-primitives@v0.4.1` and `go mod tidy`; retain Go
   `1.26.6`.
2. Confirm `auditchain` and `keyfile` callers still compile unchanged.
3. Delete the repository's v1 pairing specification. Documentation added later must link to
   KyRecovery's v2 source of truth instead of copying it again.

Complete when `go test ./internal/audit` passes against v0.4.1 and no stale v1 contract remains.

## Task 2: Add lock-consistent snapshots to the existing stores

Files: `internal/vault/vault.go`, `internal/vault/vault_test.go`,
`internal/audit/audit.go`, `internal/audit/audit_test.go`, and a small instance-lock helper under
`cmd/server` with tests.

1. Add a vault snapshot method that holds `Store.mu.RLock`, walks only the vault base directory,
   rejects symlinks and escaping/duplicate paths, skips temporary files, and returns immutable
   path/content/mode records. Make history pruning take the store lock too so it cannot remove a
   file during the walk.
2. Before returning, parse every `metadata.json`; for `version > 0`, require its sibling
   `vault.kdbx` and verify checksum and size. Missing or mismatched pairs fail the collection.
3. Add an audit snapshot method that holds `Store.mu`, copies the log, anchor state, and the
   effective in-memory key as one view, and verifies the copied chain before returning it.
4. Add a daemon-lifetime advisory lock in `CONFIG_DIR`; backup CLI commands attempt the same
   nonblocking lock. Keep the implementation in the command package—this is process lifecycle,
   not backup-format behavior.
5. Test a concurrent vault save cannot produce mixed metadata/KDBX bytes, a concurrent history
   prune cannot break a snapshot, an environment-sourced audit key is included, and a second
   process/descriptor cannot acquire the instance lock.

Complete when the focused vault/audit/command tests pass under `-race`.

## Task 3: Add the hardened backup package and local pairing state

Files: new `internal/backup/AGENTS.md`, `state.go`, `client.go`, `collector.go`, `capsule.go`,
`deposit.go`, `drill.go`, and focused tests beside them.

1. Port the small reusable pieces from the scaffold (`capsule.Seal`, receipt validation,
   restore opening) and the hardened URL rules from KyDNS. Change imports and delete every SQL
   branch rather than carrying a speculative database interface.
2. Implement one concrete pairing-state store for `CONFIG_DIR`. Encrypt/decrypt the token with
   AES-GCM and domain-separated additional data `kypassword:kyrecovery_token`. Writes use
   mode `0600` and atomic rename; public and token keys use `ky-primitives/keyfile`.
3. Implement `StorePairing`, `LoadPairing`, `Status`, and `LastDeposit` with distinct errors for
   never paired, missing pinned key, mismatched key, in-progress deposit, remote failure, and
   a deposit whose receipt could not be recorded.
4. Build the capsule contents listed above from the live vault/audit stores and the small atomic
   config stores. Refuse missing required members, unsafe paths, duplicate paths, checksum
   failures, and capsule size-limit violations.
5. Implement claim and deposit clients. Send `service_name: "kypassword"` and
   `app_name: "KyPassword"`; require a nonempty token, valid public key, and valid k-of-n
   topology. Treat 200 and 201 deposits as success only after capsule ID, SHA-256 digest, and
   byte size match locally.
6. Make deposits single-flight across scheduler, HTTP, and in-process CLI callers. Use one
   `Outcome` function to bound printable audit details and classify every success/failure.
7. Implement the throwaway-key drill and local restore helper. Reject absolute/traversing paths,
   restore only into an empty/nonexistent directory, and keep custodian shares in memory only.
8. Add an absolute-root source guard with a file-count floor. Only the restore helper and drill
   may combine private recovery material; product runtime, API handlers, and collectors may hold
   only a public key.

Tests must prove at least:

- a capsule opens only with the test-held private recovery material;
- the token never appears verbatim in `kyrecovery.json` or API/status output;
- same-key pairing is idempotent and a different key is refused;
- a present pin plus missing `recovery.pub` is `ErrKeyPinMissing`;
- redirects and every reserved-range class are refused, including IPv4-mapped/NAT64 cases;
- query and fragment recovery URLs are refused;
- wrong receipt capsule ID, digest, or size is refused;
- the single-flight guard rejects a second deposit;
- a drill verifies audit integrity and KDBX checksums without calling KDBX decryption code;
- the decrypt guard actually walks this repository and cannot pass vacuously.

Complete when `go test -race ./internal/backup` passes.

## Task 4: Add backup runtime configuration and lifecycle

Files: `cmd/server/main.go`, `cmd/server/main_test.go` (create if needed), and
`internal/api/server.go`.

1. Add `KYPASSWORD_BACKUP_DEPOSIT_INTERVAL`: default `24h`, `0` disables, any other value below
   15 minutes or any invalid/negative value refuses startup.
2. Pass `DataDir`, `ConfigDir`, effective pairing secret, retention days, app version, and the
   backup interval into the server. The backup collector uses these effective values rather
   than rereading potentially different environment state.
3. Start a scheduler only for a nonzero interval and wait a full interval before its first
   attempt. A never-paired server skips silently; a missing/mismatched pinned key and every
   attempted deposit outcome are audited and logged without token data.
4. Once a deposit starts, detach it with `context.WithoutCancel` and add a 16-minute deadline.
   Track in-flight deposits so SIGTERM stops new work, shuts HTTP down, waits for a bounded
   upload to finish, then closes the stores.
5. Acquire the instance lock before opening mutable stores and hold it until shutdown.

Complete when duration parsing, disabled scheduling, unpaired skip, audit-on-error, and graceful
in-flight completion are covered without real-time sleeps.

## Task 5: Expose the admin backup API

Files: new `internal/api/backup_handlers.go`, `internal/api/server.go`,
`internal/api/api_test.go`, and focused backup API tests if that keeps the existing file readable.

Register all routes through `withAdmin`:

- `POST /api/backup/drill`
- `GET /api/backup/export-capsule`
- `POST /api/backup/pair-remote`
- `POST /api/backup/deposit`
- `GET /api/backup/status`

Behavior:

1. Resolve the acting admin and request IP before detaching a deposit. Give the response a
   16-minute write deadline, then record `backup.Outcome` on the detached context whether the
   browser stays connected or not.
2. Audit pairing success and failure. If the public-key pin succeeds but token/URL persistence
   fails, audit the partial pin explicitly.
3. Audit an export before writing capsule bytes; if that audit write fails, refuse the export.
   The current best-effort `record` helper remains correct for already-completed ordinary
   operations, so add only the narrow required-audit helper instead of changing every caller.
4. Return 412 for never-paired export/deposit, 409 for missing/mismatched pins and in-progress
   deposits, 413 for capsule limits, 502 for a refused remote claim/deposit, and 500 for local
   collection/persistence faults. Do not echo remote bodies to the browser.
5. Status returns the URL, key ID, topology, key health, and last verified receipt. It never
   returns the plaintext or sealed token.

Tests cover method/auth rejection, unpaired behavior, degraded pinned state, redaction, audit on
every pairing/deposit outcome, required audit before export, receipt-unrecorded wording, and a
request cancellation that does not cancel the upload.

## Task 6: Add operator controls to the existing admin UI

Files: new `frontend/src/components/AdminBackup.tsx`, modify
`frontend/src/pages/AdminPanel.tsx`, `frontend/src/lib/api.ts` only if an existing helper cannot
express the download, and focused tests where logic is extracted.

1. Add a `Backup & Recovery` tab rather than a second admin shell.
2. Show pairing health, pinned key ID and topology, recovery URL, and the last receipt's capsule
   ID/digest/time.
3. Provide labeled, keyboard-usable controls to claim a six-digit pairing code, deposit now,
   download a `.kycap`, run the drill, and refresh status. Use the existing API helpers and
   error/message styles.
4. Warn clearly that the drill validates encrypted vault files and their envelopes but cannot
   open user credentials. Never render or log either form of the KyRecovery token.
5. Keep generated `frontend/dist` untracked.

Complete when `npm test && npm run build` passes in `frontend/` and the narrow layout remains
usable.

## Task 7: Add the four backup CLI commands

Files: `cmd/server/link.go` (rename the dispatcher/usage to cover all maintenance commands), a
new `cmd/server/backup.go`, and command tests.

1. Add `backup-drill`, `export-capsule`, `deposit`, and `restore` without disturbing
   `link-sso` and `deactivate`.
2. The first three acquire the same instance lock as the daemon and refuse if it is running;
   the message points to the corresponding admin action. They open the existing stores, use the
   same collector/deposit/outcome code as HTTP, and record CLI audit entries.
3. `export-capsule --out PATH` defaults to a filename-safe capsule ID plus `.kycap`, writes
   mode `0600`, and refuses to overwrite an existing file.
4. `restore --capsule PATH --to DIR` peeks at the unverified manifest and requires service name
   `kypassword` before asking for shares. Read exactly the manifest threshold from stdin—never
   argv, flags, or environment—then call `capsule.Open`, validate, and write into an empty target
   with restrictive modes.
5. Print the authenticated capsule ID, creation time, app version, recovery key ID, and payload
   hash so the operator can compare them with KyRecovery's receipt.

Complete when tests cover dispatch, daemon-lock refusal, no-overwrite export, wrong-service
refusal before share input, stdin-only shares, empty-target enforcement, and restored modes.

## Task 8: Documentation and DOX pass

Files: `AGENTS.md`, `README.md`, `.env.example`, `SECURITY.md`, `LOGGING.md`, and this plan if
implementation discoveries change it.

1. Add `internal/backup` to the Child DOX Index and record ownership of pairing state, snapshot
   contents, restore validation, and the no-KDBX-decryption boundary.
2. Document pairing, deposit-now, the 24-hour schedule/disable override, capsule export, drill,
   offline CLI restriction, restore command, and post-restore receipt comparison.
3. Document every sealed member and explicitly state that recovery custodians can restore the
   server's encrypted vault material but still cannot read vault contents without each user's
   master password or paper recovery secret.
4. Add the backup audit action names and redaction rule to `LOGGING.md`; add the recovery URL
   SSRF boundary and token storage to `SECURITY.md`.
5. Ensure all links point to KyRecovery's v2 spec and no text claims that KyRecovery decrypts or
   drills user credentials.

Complete when docs name only routes, variables, files, and commands that now exist.

## Task 9: Verification and delivery

Run the repository gates from `AGENTS.md`:

```sh
gofmt -l .
go vet ./...
go test -race ./...
(cd frontend && npm test && npm run build)
go build -o ./kypassword-server ./cmd/server
docker build -t kypassword-server:latest .
govulncheck ./...
(cd frontend && npm audit --audit-level=high)
git diff --check
```

Then run two smoke checks:

1. With temporary data/config and a configured KySignOn stub, verify unpaired export and deposit
   return 412 while ordinary login/vault flows still work.
2. Pair and deposit against a real HTTPS KyRecovery instance, compare the returned receipt to
   the capsule, download it through KyRecovery, and restore it into an empty temporary root with
   test custodian shares. Start KyPassword from that root and verify the audit chain, user list,
   device list, and encrypted vault downloads. Opening a vault remains a separate client-side
   test with its real master password.

Open a PR and drive CI plus the autonomous reviewer to green. Update the MySlop folder with the
PR URL, final commit, completed gates, the real KyRecovery smoke result, and any remaining
deployment-only step.

## Hard stops

- Stop if `ky-primitives@v0.4.1` cannot open a fixture produced by the deployed KyRecovery
  version. Recovery format compatibility is suite-wide, not a local workaround.
- Stop if a required durable secret exists only in an unavailable external secret manager. The
  restore contract must name how it is recovered; silently omitting it creates a capsule that
  cannot restart the service.
- Stop if the effective OIDC or replication secret cannot be serialized without exposing it in
  an unsealed manifest or log. Secret metadata may be described; secret values belong only in
  capsule members.
- Stop if a new KDBX-decryption path appears necessary. That would violate KyPassword's
  zero-knowledge architecture; the drill must remain ciphertext- and envelope-aware instead.
