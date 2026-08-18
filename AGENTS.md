# KyPassword Server

KyPassword Server is a zero-knowledge KeePass v4 management and synchronization server with web interface, mobile clients, and browser plugins.

## Core Capabilities & Architecture

1. **Zero-Knowledge KeePass v4 Vault Storage**: Server stores encrypted KDBX v4 vaults and wrapped key envelopes. The server never receives raw master passwords, plaintext vault keys, or unencrypted credential data.
2. **Key Custody & Envelopes**: Vault master key (256-bit) is wrapped client-side into password-wrapped, paper-recovery-wrapped, and device-wrapped envelopes using PBKDF2/Argon2 + AES-GCM. Changing passwords re-wraps the envelope without re-encrypting the full KDBX.
3. **Atomic Sync & Conflict Preservation**: Optimistic concurrency via ETag / version check (`If-Match: "{version}"`). Conflicting uploads are rejected and preserved in `conflicts/` for client deconfliction.
4. **90-Day Version History & Rollback**: Automatic version snapshots with 90-day retention policy and one-click rollback.
5. **KySignOn SSO & Directory Replication**: Interoperable with KySignOn and standard OIDC/PKCE IdPs (`/api/auth/oidc/login`, `/api/sync/webhook`).
6. **Native Device Pairing**: 90-second PIN and QR code protocol (`/api/devices/pairing/*`) for mobile apps and browser extensions.
7. **Tamper-Evident Audit Logging**: Cryptographic hash-chained audit trail (`/api/audit/*`).
8. **KySecurity Patina Interface**: React + TypeScript frontend using Space Grotesk, IBM Plex Mono, and Patina dark theme.

## Verification

- Backend: `go test ./...`
- Frontend: `npm run build` in `frontend/`
- Daemon build: `go build -o ./kypassword-server ./cmd/server/main.go`
- Docker build: `docker build -t kypassword-server:latest .`

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

