## KyPassword

KyPassword is a Docker-based, self-hosted KeePass management and synchronization
server designed to run alongside KyPost-Net behind the same reverse proxy.

### Security model

- The system is end-to-end, zero-knowledge. The server must never receive an
  unhashed master password, plaintext vault key, or decrypted KeePass data.
- Reuse KyPost's existing client-derived authentication protocol, KDF choices,
  login parameters, lockout behavior, and optional CAPTCHA behavior.
- The server stores only the salted hash of the client-derived authentication
  value. It never stores or receives the raw master password.
- The client generates a cryptographically random vault key. The KDBX is
  encrypted with that key; the login password is not used directly as the KDBX
  encryption key.
- The client stores password-wrapped, recovery-wrapped, and device-wrapped
  copies of the vault key. Password changes re-wrap the vault key client-side;
  they do not require re-encrypting the entire KDBX.
- Recovery is paper-based. The paper unlock secret is hashed and stored beside
  the authentication verifier. It provides site access and vault access by
  unlocking the recovery-wrapped vault key, after which the user must set a new
  master password. The old password and remote device keys are invalidated.
- Wrapped key envelopes are stored as encrypted, versioned server-side metadata
  beside the KDBX. Metadata must not contain plaintext keys or secrets.
- Mobile applications use KyPost's existing QR-code key-sealing method. Reuse
  its API where practical; in phase 2, extract that API into a repository shared
  by KyPost and KyPassword if its dependencies and boundaries permit it.
- Logout deletes local key files. Device loss is handled by revoking the device,
  deleting its server-side envelope, and wiping local key files when the device
  next connects. Local browser storage and memory deletion are best-effort.

### Vault and file behavior

- Create a new KDBX v4 vault or import an existing KDBX v4 file.
- KDBX v3 import support is a future TODO; server-managed files are saved as
  KDBX v4.
- All KeePass decryption, editing, encryption, and key handling occur in the
  user's browser or client application.
- The server exposes APIs for browser extensions, mobile clients, and future
  clients in other repositories.
- Sync is client-triggered after edits. Conflicting saves are rejected rather
  than merged. The rejected encrypted upload is preserved for web-based user
  deconfliction.
- Preserve versioned KDBX files and encrypted file metadata for 90 days, with
  administrator-configurable retention, deletion, restore, and quota options.
- After 90 days, unresolved conflicting uploads may be deleted.
- Users can download the latest encrypted KDBX at any time and restore it using
  any KeePass-compatible tool.

### Sharing and encrypted files

- Shared passwords are encrypted in their own vault. The recipient receives the
  unlock code out of band.
- Files saved outside the vault use PGP/MIME or the selected encrypted-file
  format. Each file uses a decryption key held inside the user's encrypted
  vault; the server never sees that key in plaintext.
- Audit records cover authentication, vault changes, downloads, restores,
  sharing, device enrollment, revocation, and administrative actions.
- Audit records should be tamper-evident.

### Clients and initial scope

- Initial scope: upload/create vault, authentication, browser editing,
  versioning, encrypted download, and the supporting APIs.
- Browser support: Chrome extensions using Manifest V3 and Firefox extensions.
- Mobile support: Android and iOS, including offline access and automatic sync.
- Linux support is phase 2.
- Browser extensions must decrypt queried credential data client-side; the
  server must never receive decrypted key data.
