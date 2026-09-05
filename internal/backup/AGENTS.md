# KyRecovery backup

## Purpose and ownership

KyPassword owns file-store snapshots, the settings/sealer adapter, product validation,
audit/HTTP/CLI integration and UI. `ky-primitives/recoveryclient` v0.5.1 owns pairing,
write-once pins, sealing, delivery, retention, schedule calculation, drill and restore.

## Local contracts

- Preserve `CONFIG_DIR/kyrecovery.json` fields and `recovery-token.key`. Tokens use the
  existing direct AES-GCM key, nonce prefix, RawStdEncoding and additional data
  `kypassword:kyrecovery_token`. The synthetic legacy fixture pins this contract.
- Settings writes are atomic under the state mutex; pairing/pin/unpair hold it across
  library writes. The operation mutex prevents those changes during a backup run; lifecycle operations
  and competing runs return ErrDepositInProgress immediately instead of waiting.
- `kypassword` is the capsule/service binding and RunConfig.AppName; `KyPassword` is the
  display label. RunConfig.DataDir is CONFIG_DIR; drill scratch is under DATA_DIR.
- Collect only through existing store snapshots. Include effective operational secrets
  inside the sealed capsule. Manually pinned/local-only instances need no token key.
- Vault verification is ciphertext/checksum-only. Verify audit snapshots against their
  captured key and anchor without live environment overrides or file repair. Drills check
  the opened recipe's types, required paths and mandatory audit/vault flags.
- Normal operation holds only the recovery public key. The library drill uses a throwaway
  private key; `cmd/server/backup.go:runRestore` alone may invoke library Restore, with
  shares on stdin. Product validation must pass before the CLI prints restore success.
- HTTPS and refused redirects are library policy. KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY
  explicitly admits private/CGNAT hosts, while loopback/link-local/reserved targets remain
  refused. All address policy, including resolved addresses, belongs to recoveryclient;
  v0.5.1 does not classify documentation networks as blocked.
- Local copies use KYPASSWORD_BACKUP_DIR and BACKUP_KEEP (same prefix, default 7, >=1).
  The directory must not overlap CONFIG_DIR or DATA_DIR/{vaults,audit,drill},
  including existing symlink ancestors. Interval defaults from KYPASSWORD_BACKUP_DEPOSIT_INTERVAL, overridden by admin settings:
  off or 900–31622400 whole seconds. Runs count from last attempt, including failures.
- Unpair removes URL/token only. Pins, topology, receipts and local copies stay. Remote
  revocation is a separate KyRecovery-admin action. Status never exposes a token.
- Keep partial local/remote results visible (HTTP 207 and an alert) and persist the last outcome.
  Preserve backup.deposited/backup.deposit_failed audit actions and log scheduled outcomes. Bound audit
  fields, omit remote response bodies (they can reflect credentials), and retain the
  existing session CSRF/fresh-admin route gates.

## Verification

`go test -race ./internal/backup ./internal/api ./cmd/server ./internal/audit` covers old
state, both destinations, partial failures, restore CLI, malformed recipes and the decrypt
guard. Run the root CI gates before opening a PR.
