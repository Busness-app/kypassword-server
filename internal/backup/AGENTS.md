# KyRecovery backup

- This package may hold only the suite recovery public key during normal operation. Private
  recovery material may exist only inside `RunDrill` and `Restore`.
- Capsules contain encrypted KDBX files and their key envelopes. Never add a server-side KDBX
  decryptor or claim the drill can read user credentials.
- `kyrecovery.json` must never contain the deposit token in plaintext. A paired key ID with a
  missing `recovery.pub` is a degraded error, not an unpaired state.
- Recovery URLs are an SSRF boundary: HTTPS only, no redirects, and every dial must pin a
  validated public address.
- Verify with `go test -race ./internal/backup`.
