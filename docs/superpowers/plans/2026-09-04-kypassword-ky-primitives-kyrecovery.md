# KyPassword on the ky-primitives `kyrecovery` package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `kypassword-server` to the KySignOn backup spec by replacing the hand-rolled
client, key pin, pairing state, schedule and restore in `internal/backup` with the shared
`github.com/Busness-app/ky-primitives/recoveryclient` package, and adding the product-side rows
(local directory, schedule setting, unpair, pin by hand, private-recovery switch, compose
override, new screen, runbook, docs).

**Architecture:** `internal/backup` shrinks to what is KyPassword-specific: the payload
collector (`Collector`), the drill checks, and a small `Settings` adapter over the existing
`kyrecovery.json` file store. Everything else is a thin call into the lib. Handlers in
`internal/api/backup_handlers.go` and the CLI in `cmd/server/backup.go` stay, gain the new
routes and subcommands, and record through the lib's `Outcome`.

**Tech Stack:** Go (stdlib + ky-primitives), React/TypeScript frontend, Docker Compose.

**Spec:** MySlop folder `kypassword-kyrecovery-deposit` post 191 (the 14 rows), lib contract
is the code in `ky-primitives/recoveryclient` (folder `ky-primitives-kyrecovery-package`
posts 204, 211, 215 record the rename and review-round changes), suite plan
`ky_server_base/docs/superpowers/plans/2026-09-04-bring-suite-to-kysignon-spec.md`.
Reference implementation: `kysignon-server` master (`internal/backup`, `internal/api/backup_handlers.go`,
`cmd/kysignon/main.go` `backupLoop`, `web/src/components/AdminBackup.tsx`, `docs/RESTORE.md`,
`docker-compose.lan-dns.yml`).

## Where it stands (surveyed 2026-09-04, HEAD 5939a5e)

- ky-primitives `v0.4.1` in `go.mod`. Uses `auditchain`, `capsule`, `keyfile`, `recoverykey`, `shamir`.
- **The shared package landed as `recoveryclient`**, not `kyrecovery` (Yoshi's rename, post 204
  in folder `ky-primitives-kyrecovery-package`). ky-primitives PR #12 merged to master at
  `533a053` on 2026-09-05 after six security-review rounds and is tagged **`v0.5.0`**.
  `kysignon-server` adopts it in PR #21 (open, not merged as of 2026-09-05). Post 189's order
  is: tag, KySignOn first, then products. Phase B waits on #21. Do not start another copy of
  `internal/backup`.
- Own package from PR #22: `backup.go` (Collector, Seal, Service.Deposit, Outcome),
  `client.go` (Claim, Deposit, SSRF filter), `drill.go` (RunDrill, Restore, ParseShares),
  `state.go` (StateStore over `kyrecovery.json` + `recovery.pub`, sealed token). Routes
  `/api/backup/{status,drill,export-capsule,pair-remote,deposit}` behind `withAdmin`. CLI
  `backup-drill`, `export-capsule`, `restore`. Env-only interval
  `KYPASSWORD_BACKUP_DEPOSIT_INTERVAL` with a 15 min floor in `cmd/server/main.go`.
- Rows already met: 14 (stale spec deleted in 5516a6e). Row 11 exists in the local shape
  (`TestDecryptGuard`); it moves to the lib's `guardtest` in Phase B.
- No step-up in KyPassword (SSO-only, no server-side password). Row 10 uses a
  fresh-session check instead; see Task 3.
- **Phase A is done** (branch `feat/backup-phase-a`, PR #24, 2026-09-05): rows 8, 10, 12, 13.
  Only `KYPASSWORD_BACKUP_DEPOSIT_INTERVAL` is passed through compose; the Phase B env vars
  are added by Task 6 when they exist. Two findings from the runbook proof:
  - Fixed in Phase A: `audit.Snapshot` on a never-used instance (anchor count 0, empty hash)
    failed verification, so export, drill and deposit all failed before the first audit event.
  - **For Task 7:** `StateStore.CapsuleFiles` requires `recovery-token.key`, which only
    exists after a pairing. A key pinned by hand with no pairing cannot export. The lib's
    `Run` has no such requirement; make sure the new collector does not either.
  - **For Task 7:** the capsule `ServiceName` is the lowercase `"kypassword"` and `AppName`
    is `"KyPassword"`. `recoveryclient.Run` refuses a payload whose ServiceName differs from
    `RunConfig.AppName`, and `ClaimPairing` sends `serviceName` for KyRecovery to pin.
    Capsules in the wild (PR #22 deposits) say `kypassword`; keep that string for both, and
    make `Restore`'s `expectService` the same, or every existing deposit becomes unrestorable
    through the new CLI.

## Global Constraints

- Server never decrypts a user vault: no KDBX decryptor, drill verifies ciphertext
  checksums and audit chain only. Say so in the manifest and on the screen.
- `kyrecovery.json` never holds the deposit token in plaintext.
- KyRecovery URLs: HTTPS only, no redirects, no query or fragment, public addresses only
  unless `KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY=true` (private + CGNAT admitted; loopback,
  link-local, multicast, unspecified, reserved never).
- Local copies are named `KyPassword.<capsule-id>.kycap` (the lib escapes the app name and
  prunes only its own prefix). Local write failure never cancels a deposit.
- Interval bounded in whole seconds before any `time.Duration` math: 0, or [900, 31622400].
- Every external string through `AuditSafe` (printable, 200 chars) before audit or error.
- Env var prefix `KYPASSWORD_`. Never a `dns:` key in `docker-compose.yml`.
- Never HTML-escape a value inside an inline `on*=` handler; data attributes + bind after render.
- Verification: `go test -race ./...`, `cd frontend && npm test && npm run build`.

---

## Phase A: product rows that need no lib (do now)

### Task 1: Compose DNS override and backup env passthrough (row 8) — DONE (PR #24)

**Files:**
- Create: `docker-compose.lan-dns.yml`
- Modify: `docker-compose.yml` (environment block), `.env.example`

- [ ] **Step 1: Create the override file**

```yaml
# Optional override: send the container's DNS lookups to your LAN's resolver, so names that
# exist only there (a KyRecovery behind your own proxy) resolve inside the container. It
# replaces the host's resolvers for every lookup this container makes, which is why it lives
# in its own file instead of a default.
#
#   KYPASSWORD_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d
services:
  kypassword-server:
    dns:
      - ${KYPASSWORD_DNS:?set KYPASSWORD_DNS to your LAN DNS server}
```

Use the service name actually declared in `docker-compose.yml`; check it before writing.

- [ ] **Step 2: Pass the backup env vars through the base compose**

Add to the service's `environment:` list, each as `- KYPASSWORD_X=${KYPASSWORD_X:-}`:
`KYPASSWORD_BACKUP_DEPOSIT_INTERVAL`, `KYPASSWORD_BACKUP_DIR`, `KYPASSWORD_BACKUP_KEEP`,
`KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY`. When `KYPASSWORD_BACKUP_DIR` is set it must be a
path inside a mounted volume; document the volume line in `.env.example` next to it.

- [ ] **Step 3: Prove it**

```bash
docker compose -f docker-compose.yml config | grep -c 'dns:'          # expect 0
KYPASSWORD_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml config | grep -A1 'dns:'
docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml config 2>&1 | grep 'set KYPASSWORD_DNS'  # unset var must error
```

- [ ] **Step 4: Commit** `chore(compose): lan-dns override and backup env passthrough`

### Task 2: Restore runbook (row 12) — DONE (PR #24)

**Files:**
- Create: `docs/RESTORE.md`
- Modify: `README.md` (link the runbook from "KyRecovery backups")

- [ ] **Step 1: Write `docs/RESTORE.md`** with the same section order as
  `kysignon-server/docs/RESTORE.md`: What a capsule holds, Before you start, Step 1 open the
  capsule, Step 2 check what came out, Step 3 put it in service, Step 4 prove it, Step 5
  decide what to trust, Afterwards, Drill it. Adapt every fact to KyPassword:
  - Capsule holds `vaults/**` (encrypted KDBX, envelopes, history, conflicts),
    `audit/audit.jsonl`, `users.json`, `devices.json`, SSO config, `audit.key`,
    `audit.state`, `recovery.pub`, `kyrecovery.json` (sealed token), manifest.
  - Empty-target gate: `restore` refuses a non-empty `--to`. Copy the old volume out first.
  - Docker target writable as `$(id -u)`; exact `docker run --user "$(id -u)" ... restore` line.
  - Shares on stdin only, one per line; nothing secret on stdout; the printed manifest is
    authenticated, compare `capsule_id` with KyRecovery's receipt.
  - Rotation after restore: `audit.key` (new chain head, note the break in the audit log),
    OIDC client secret in KySignOn, KyRecovery token (unpair, re-pair). Vault keys are never
    rotated by the operator: they are the users' Argon2id envelopes.
  - Per-user session revocation: restart clears the in-memory session map; say so.
- [ ] **Step 2: Prove every command in a scratch run** with a capsule sealed to a freshly
  split 2-of-3 key (`recoverykey` CLI in ky-primitives `cmd/`), shares on stdin. Also run
  each failure mode: wrong service name, 1 of 3 shares, non-empty target, and confirm the
  message printed matches what the runbook says.
- [ ] **Step 3: Commit** `docs: restore runbook proven against a scratch capsule`

### Task 3: Fresh-session gate on destructive backup routes (row 10) — DONE (PR #24)

KyPassword has no step-up. Its equivalent: the admin's session must have been issued within
the last 10 minutes, otherwise `403 {"error":"re-authenticate to continue"}` and the UI sends
the admin back through KySignOn. This is an assumption to confirm with Yoshi; the alternative
is a real OIDC `prompt=login` step-up, which is a larger change.

**Files:**
- Modify: `internal/api/server.go` (`withAdmin` neighbour `withFreshAdmin`), route table
- Test: `internal/api/backup_handlers_test.go`

- [ ] **Step 1: Failing test**: a session with `IssuedAt` 11 minutes ago gets 403 on
  `POST /api/backup/deposit`; one issued 1 minute ago gets past the gate (assert not 403).
- [ ] **Step 2: Implement** `withFreshAdmin` wrapping `withAdmin` with
  `time.Since(sess.IssuedAt) <= 10*time.Minute`; `currentUser` must return the `Session`
  or a sibling `currentSession` added next to it.
- [ ] **Step 3: Apply** to `deposit`, `export-capsule`, `pair-remote`, and in Phase B to
  `pin-key`, `unpair`, `schedule`. `status` and `drill` stay `withAdmin`.
- [ ] **Step 4: Hardening test**: extend `retired_routes_test.go` or a new
  `backup_hardening_test.go` with a table of every destructive backup route asserting the
  stale-session 403 so a future route cannot be added without the gate.
- [ ] **Step 5: Commit** `api: fresh-session gate on destructive backup routes`

### Task 4: README and package AGENTS.md (row 13, part 1) — DONE (PR #24)

**Files:**
- Modify: `README.md` "KyRecovery backups" and env table; `internal/backup/AGENTS.md`

- [ ] **Step 1: README**: why TLS matters when the capsule is sealed (key received at
  pairing, bearer token, receipts travel in the clear without it); pin by hand or compare
  fingerprints before trusting a pairing; every env var
  (`KYPASSWORD_BACKUP_DEPOSIT_INTERVAL`, `_BACKUP_DIR`, `_BACKUP_KEEP`,
  `_BACKUP_ALLOW_PRIVATE_RECOVERY`, `KYPASSWORD_DNS` override); link `docs/RESTORE.md`.
  Write the rows for Phase B env vars now and mark none as "coming"; Phase B implements them
  in the same PR train, or this task waits for Task 6.
- [ ] **Step 2: Commit** `docs(readme): backup env vars, TLS rationale, key by hand`

---

## Phase B: wire the lib (gated on ky-primitives `v0.5.0` and KySignOn consuming it)

### Task 5: Gate check

- [x] `v0.5.0` is tagged on `533a053` (verified 2026-09-05); its tree has `recoveryclient/`
  and `recoveryclient/guardtest/`.
- [ ] Confirm `kysignon-server` master imports `ky-primitives/recoveryclient`
  (`git grep -l recoveryclient origin/master -- '*.go'`). As of 2026-09-05 that is
  kysignon-server PR #21 (branch `feat/recoveryclient`, worktree
  `kysignon-server/.claude/worktrees/rc`), open, not merged. Read its `internal/backup`
  adapter now: Sealer wrapper, `Settings` adapter, and
  `TestAPairingSealedBeforeTheLibStillOpens` are the pattern for Tasks 6 and 7. Start
  Task 6 once #21 merges.
- [ ] Diff the tag's exported API against the block below (read from master `533a053`); the
  lib wins, fix the plan before starting.
- [ ] `go get github.com/Busness-app/ky-primitives@v0.5.0 && go mod tidy`; `go build ./...`.

Exported API of `recoveryclient` at `533a053`:

```go
type Settings interface { Get(key string) (string, error); Set(key, value string) error; Delete(key string) error }
var ErrNotFound error                          // adapter returns this for a missing key
type Sealer interface { Seal(plain []byte) (string, error); Open(sealed string) ([]byte, error) }
func NewAESGCMSealer(key []byte, label string) (Sealer, error)   // HKDF(label) + AES-GCM, stdlib
type Options struct { AllowPrivate bool }
func NewClient(o Options) *Client
func ValidateURL(raw string, allowPrivate bool) error
type PairingResult struct { APIToken string; Key RecoveryKey }
func (c *Client) ClaimPairing(ctx, serverURL, pairingCode, serviceName, appName string) (PairingResult, error)
type Receipt struct { CapsuleID, Digest string; SizeBytes int64; DepositedAt time.Time }
func (c *Client) Deposit(ctx, serverURL, apiToken string, container []byte) (Receipt, error)
var ErrRemote error
func AuditSafe(s string) string
type RecoveryKey struct { Public recoverykey.PublicKey; Threshold, TotalShares int }
func RecoveryKeyPath(dataDir string) string  // <dataDir>/recovery.pub
func StoreRecoveryKey(dataDir string, s Settings, k RecoveryKey) error   // write-once; ErrKeyMismatch
func LoadRecoveryKey(dataDir string, s Settings) (RecoveryKey, error)    // ErrNotPaired
func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error)
type Pairing struct { URL, Token string; Key RecoveryKey }
type Depositor interface { Deposit(ctx, serverURL, apiToken string, container []byte) (Receipt, error) }
func StorePairing(s Settings, sealer Sealer, serverURL, token string) error
func LoadPairing(dataDir string, s Settings, sealer Sealer) (Pairing, error) // ErrNotPaired, ErrKeyPinMissing
func HasPairing(s Settings) bool
func ClearPairing(s Settings) error
func LastDeposit(s Settings) (Receipt, bool, error)
type LocalCopy struct { Name string; SizeBytes int64; CreatedAt time.Time }
func WriteLocalCopy(dir, appName, capsuleID string, raw []byte, keep int) (string, error) // ErrBadKeep (<1)
func ListLocalCopies(dir, appName string) ([]LocalCopy, error)
const MinInterval = 15 * time.Minute; const MaxInterval = 366 * 24 * time.Hour
var ErrBadInterval error
func Interval(defaultInterval time.Duration, s Settings) (time.Duration, error)
func SetInterval(s Settings, sec int64) error
func NextRun(defaultInterval time.Duration, s Settings) (time.Time, bool, error)
type File struct { Path string; Data []byte; Mode int64 }
type Payload struct { ServiceName, AppVersion string; Files []File; Dependencies, VerificationRecipe map[string]any }
const MaxCapsuleFileBytes, MaxCapsuleTotalBytes; var TooLargeMessage string
func Seal(p Payload, key RecoveryKey) ([]byte, capsule.Manifest, error)
func FilenameSafe(s string) string
type RunConfig struct { DataDir, AppName, AppVersion, BackupDir string; Keep int; Sealer Sealer }
type Result struct { Manifest capsule.Manifest; SizeBytes int; LocalPath, LocalError string; Receipt *Receipt }
var ErrNoDestination, ErrInProgress, ErrReceiptUnrecorded error
func Run(ctx, cfg RunConfig, s Settings, collect func() (Payload, error), client Depositor) (Result, error)
     // refuses payload.ServiceName != cfg.AppName before uploading
func Outcome(res Result, err error) (action, outcome string, details map[string]any)
type Check struct { Name string; Passed bool; Message string }
type DrillResult struct { Passed bool; Checks []Check; ErrorMessage string; DurationMs int64; SizeBytes int }
func Drill(ctx, scratchRoot string, payload Payload, checks func(dir string) []Check) (*DrillResult, error)
     // scratchRoot required, inside the data dir; ErrNoScratchRoot
func ReadShares(r io.Reader) ([]string, error)
func Restore(capsulePath, targetDir, expectService string, shareStrings []string, stdout io.Writer) error
func SQLiteSnapshot(ctx, db *sql.DB, destPath string) error   // not used: KyPassword is file-backed
guardtest.NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string)
     // needs >= guardtest.MinFiles (10) Go files, walks web/ too, also forbids recoveryclient.Restore
```

Settings keys the lib reads and writes (the adapter must persist exactly these names):
`kyrecovery_url`, `kyrecovery_token_enc`, `kyrecovery_last_deposit`, `kyrecovery_key_id`,
`kyrecovery_threshold`, `kyrecovery_total_shares`, `backup_interval_sec`, `backup_last_attempt`.

### Task 6: Settings adapter and config (rows 4, 5, 7 env)

**Files:**
- Create: `internal/backup/settings.go` (file-backed `recoveryclient.Settings` over the
  existing `kyrecovery.json` as a flat `map[string]string` with exactly the eight lib keys
  listed in Task 5; missing key returns `recoveryclient.ErrNotFound`; writes are temp+rename
  at 0600 under the existing mutex)
- Modify: `cmd/server/main.go` env loading: `KYPASSWORD_BACKUP_DIR` (absolute or off),
  `KYPASSWORD_BACKUP_KEEP` (default 7, min 1), `KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY`
  (`true` only), logged at startup when on
- Test: `internal/backup/settings_test.go`
- Migration: a `kyrecovery.json` written by PR #22 (`persistedState`) must load. Write a
  test that seeds the old shape and asserts `LoadPairing` still returns the pairing.
- [ ] Failing tests → implement → `go test -race ./internal/backup` → commit
  `backup: settings adapter over kyrecovery.json, backup dir and private-recovery env`.

### Task 7: Replace client, pin, pairing, deposit, drill, restore with the lib (rows 1, 2, 3, 6, 11)

**Files:**
- Delete: `internal/backup/client.go`, most of `state.go`, `Service` and `Seal` in
  `backup.go`, `Restore`/`ParseShares` in `drill.go`
- Keep: `Collector.Collect` (returns `recoveryclient.Payload` with `ServiceName: "KyPassword"`,
  which must equal `RunConfig.AppName` or `Run` refuses), the drill checks in `drill.go` (KDBX
  checksum, audit chain verify, users/devices JSON parse) as `func checks(dir string) []recoveryclient.Check`
- Modify: `internal/api/backup_handlers.go`, `internal/api/server.go`, `cmd/server/backup.go`,
  `cmd/server/main.go` (loop)
- Sealer: `recoveryclient.NewAESGCMSealer(<existing token key from tokenKeyFile>, "kypassword:setting:kyrecovery_token")`.
  The lib derives with HKDF over the label and seals with AES-GCM; PR #22's `sealTokenLocked`
  format will not open under it. Migration: on first load, if `kyrecovery.json` is the PR #22
  `persistedState` shape, open the token with the old code once, re-seal with the lib Sealer,
  rewrite the file as the flat key map, then delete the old code. Test with a fixture written
  by the PR #22 code path: after migration `LoadPairing` returns the same URL and token. A
  fixture that fails to open must surface as an error on the status route, never as unpaired.
- Routes (all under `withFreshAdmin` from Task 3 except status/drill):
  - `POST /api/backup/pair-remote` → `ValidateURL(url, allowPrivate)` →
    `ClaimPairing(ctx, url, code, "KyPassword", "KyPassword")` returns `PairingResult{APIToken, Key}`
    → `StoreRecoveryKey(configDir, settings, res.Key)` → `StorePairing(settings, sealer, url, res.APIToken)`;
    audit row carries `allow_private=<bool>`.
  - `POST /api/backup/pin-key` `{publicKey, threshold, totalShares}` → `ParsePinRequest` →
    `StoreRecoveryKey`; `ErrKeyMismatch` → 409.
  - `DELETE /api/backup/pairing` → `ClearPairing`; response text: "pairing rows removed;
    the credential is dead only when KyRecovery revokes it".
  - `PUT /api/backup/schedule` `{intervalSec}` → `SetInterval`, then read back with `Interval`
    for the audit row and response.
  - `POST /api/backup/deposit` → `Run`; `ErrNoDestination` → 412 with a message the screen
    shows; `ErrInProgress` → 409.
  - `GET /api/backup/status` → key (id, k-of-n, healthy via `LoadRecoveryKey`), pairing
    (`HasPairing`, url), `LastDeposit`, `ListLocalCopies(dir, "KyPassword")`, `Interval`,
    `NextRun`, `backupDir` set or not, `allowPrivate`. The drill no longer reports pin status;
    this route does.
  - `GET /api/backup/export-capsule` → `Seal(payload, key)`;
    `POST /api/backup/drill` → `Drill(ctx, filepath.Join(dataDir, "drill"), payload, checks)`
    (scratch root must be inside the data dir, `ErrNoScratchRoot` otherwise).
- Loop in `cmd/server/main.go`: tick every minute, `NextRun`, skip `ErrNotPaired` and
  `ErrNoDestination`, otherwise audit through `Outcome`. Drop `backupDepositInterval` floor
  code; the env value becomes the `Interval` default.
- CLI `cmd/server/backup.go`: `backup-drill`, `export-capsule`, `deposit` → `Run`,
  `restore --capsule --to` → `shares, err := recoveryclient.ReadShares(os.Stdin)` then
  `recoveryclient.Restore(capsulePath, target, "KyPassword", shares, os.Stdout)`. Drop the
  local manifest peek: `Restore` checks the service name before `Combine` and prints the
  authenticated manifest itself.
- Decrypt guard: replace `TestDecryptGuard` with one test calling
  `guardtest.NoDecryptOutside(t, <abs repo root>, map[string][]string{})`. The lib also
  forbids `recoveryclient.Restore` outside an allowed func, so the allow map becomes
  `{"cmd/server/backup.go": {"runRestore"}}` (whatever the CLI function is named). The repo
  has far more than `guardtest.MinFiles` (10) Go files. Prove the guard bites once by planting
  `capsule.Open` in a handler and watching the test fail, then remove it.
- [ ] Per route: failing handler test → implement → pass → commit. Suggested commits:
  `backup: pairing, pin and sealed token from kyrecovery`, `backup: Run with local copies
  and schedule setting`, `backup: drill and restore from kyrecovery`, `api: pin-key,
  unpair, schedule routes`, `test: decrypt guard via guardtest`.

### Task 8: Disaster recovery screen (row 9)

**Files:**
- Modify: `frontend/src/components/AdminBackup.tsx` (currently 151 lines, one panel)
- Reference: `kysignon-server/web/src/components/AdminBackup.tsx`
- [ ] Four fact cards: Key (id, k-of-n, healthy or missing), KyRecovery (url or not paired),
  Local copies (dir, count, newest), Schedule (interval or off, next run).
- [ ] One action row: Back up now, Download capsule, Run drill. Disabled with the reason when
  no key; 412 from deposit shown as "a key is pinned but no destination is configured".
- [ ] "What a capsule carries" list, stating plainly that vault contents stay encrypted and
  the drill cannot read them.
- [ ] Schedule form (off, or minutes ≥ 15, ≤ 366 days) → `PUT /api/backup/schedule`.
- [ ] Pairing panel with Unpair (confirm dialog quoting the rows-removed text); key-by-hand
  panel (base64 + k + n) → `POST /api/backup/pin-key`.
- [ ] Warnings: no key, no destination, schedule off. Stale-session 403 → prompt to sign in again.
- [ ] `npm test`, `npm run build`; commit `frontend: disaster recovery screen to suite spec`.

### Task 9: Package AGENTS.md and repo AGENTS.md (row 13, part 2)

- [ ] Rewrite `internal/backup/AGENTS.md` to the kysignon shape (Purpose, Ownership, Local
  Contracts, Verification) listing only what this repo still owns: collector, drill checks,
  settings adapter, file names, env vars, the fresh-session gate. Everything else: "see
  ky-primitives `kyrecovery`".
- [ ] Update repo `AGENTS.md` item 9 and the DOX line to match. Commit `docs: backup contracts`.

### Task 10: Live proof

- [ ] `go test -race ./...`, `cd frontend && npm test && npm run build`, `govulncheck ./...`.
- [ ] Screen live: throwaway `DATA_DIR`/`CONFIG_DIR`, `KYPASSWORD_BACKUP_DIR` set, log in via
  KySignOn, pin a freshly split key by hand, Back up now, confirm `KyPassword.<id>.kycap` at
  0600 in the dir, audit rows for pin and run, `ls` shows no other file touched.
- [ ] Live pairing in Yoshi's homelab: `KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY=true`,
  `KYPASSWORD_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d`,
  recreate the container, `docker inspect <c> --format '{{.HostConfig.Dns}}'` shows the
  resolver, pair, deposit, receipt on KyRecovery.
- [ ] Runbook Step 1 against the capsule from the previous step, shares on stdin, plus each
  failure mode listed in Task 2.
- [ ] Open the PR, post to MySlop folder `kypassword-kyrecovery-deposit` with status.

## Ordering and PRs

- PR 1 (now): Tasks 1–4. Task 4's env rows for `_BACKUP_DIR`, `_KEEP`,
  `_ALLOW_PRIVATE_RECOVERY` may land with PR 2 instead if describing unimplemented vars
  reads badly; decide at PR time, do not leave a "coming soon".
- PR 2 (after the lib tag and KySignOn consuming it): Tasks 5–10.
