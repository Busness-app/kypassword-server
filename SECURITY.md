# Security Policy

Report vulnerabilities through [GitHub Security Advisories](https://github.com/Busness-app/kypassword-server/security/advisories), not a public issue. Include the affected version, impact, and reproduction steps.

## Trust boundaries

- KySignOn is the only authenticator and directory. KyPassword stores no password verifier.
- KDBX encryption and vault-key envelopes are created and opened in clients. The server stores
  ciphertext and cannot read credentials.
- The audit log is HMAC-chained and anchored outside its data directory. Losing `audit.key` or
  `audit.state` prevents trustworthy verification.
- Session cookies are `HttpOnly` and `SameSite`; state-changing KyRecovery admin requests also
  require the session's double-submit CSRF token.

## KyRecovery

KyRecovery stores only `kycap/3` capsules sealed to the suite recovery public key. The product
never receives the private key or custodian shares during normal operation. The deposit bearer
token is AES-GCM sealed at rest and is never returned by status APIs or written to logs.

The operator-supplied KyRecovery URL is an SSRF boundary. The client accepts HTTPS only, rejects
userinfo, query, fragment, and redirects, resolves DNS itself, rejects private, loopback,
link-local, multicast, CGNAT, benchmark, documentation, reserved, and NAT64-wrapped private
addresses, and dials only an address it validated.

A recovery quorum restores the server's encrypted vault files, envelopes, configuration, and
audit material. It does not reveal credentials: each KDBX still requires its user's master
password, offline vault key, or paper-recovery path.

## Deployment

Terminate TLS before exposing KyPassword. Session cookies are marked `Secure` only when the
request arrives over TLS or the deployment edge supplies `X-Forwarded-Proto: https`. Protect
`DATA_DIR` and `CONFIG_DIR` with owner-only filesystem permissions and back them up together.
Treat `PAIRING_SECRET`, `AUDIT_KEY`, OIDC client secrets, KyRecovery state, exported capsules,
and custodian shares as secrets appropriate to their role.
