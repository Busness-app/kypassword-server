# KyPassword Server

A self-hosted, zero-knowledge KeePass v4 vault and synchronisation server, with a web
interface, mobile clients and browser extensions.

The server stores your encrypted KDBX file and your wrapped key envelopes. It cannot read
your passwords, and it holds nothing that could be used to authenticate as you.

## KySignOn is required

**There is no local login.** Signing in to KyPassword means signing in to KySignOn; the
server has no password of its own to check, and no way to create an account.

If KySignOn is unavailable, sign-in is unavailable. Your passwords are not — but the escape
hatch only works if you prepare it in advance:

1. In **Security → Offline Vault Key**, reveal your vault key and print it. It is a
   64-character hexadecimal string.
2. Keep a downloaded copy of your vault (**Download .kdbx**, or `GET /api/vault/kdbx`).

That file is a standard KDBX v4 database, and the vault key *is* its password — type or
paste it into KeePass, KeePassXC or KeePassDX and your passwords are there, with no server
involved. Both steps matter: the server cannot show you the key while it is down.

Treat the vault key like the paper recovery code. It unlocks everything, on any device,
forever, and unlike your master password it cannot be changed without re-encrypting the
vault.

Two secrets, doing different jobs:

| | proves | held by |
|---|---|---|
| Your KySignOn password | who you are | KySignOn |
| Your KyPassword master password | nothing — it decrypts your vault key | you, in your browser |

The master password is never sent to the server, not even as a derived verifier. Changing
it re-wraps the vault key envelope in your browser; the KDBX itself is not re-encrypted.
Your paper recovery code works the same way: it unlocks your vault, not the site.

## Configuration

The identity provider is configured from the environment, and those values take precedence
over anything saved in `config/sso.json`. The admin UI will refuse to overwrite them
(`409`) rather than accept a change the next restart would discard.

| Variable | Required | Meaning |
|---|---|---|
| `KYPASSWORD_OIDC_ISSUER` | yes | e.g. `https://signon.example.com` |
| `KYPASSWORD_OIDC_CLIENT_ID` | yes | client ID KySignOn issued for KyPassword |
| `KYPASSWORD_OIDC_CLIENT_SECRET` | yes | the matching client secret |
| `KYPASSWORD_OIDC_REDIRECT_URI` | no | defaults to `<scheme>://<host>/api/auth/oidc/callback` |
| `KYPASSWORD_OIDC_AUTO_PROVISION` | no | defaults to `true` |
| `PORT` | no | defaults to `5877` |
| `DATA_DIR` | no | defaults to `./data` — vaults, history, audit log |
| `CONFIG_DIR` | no | defaults to `./config` — `users.json`, `sso.json`, pairing secret, audit key and chain state |
| `RETENTION_DAYS` | no | defaults to `90` |
| `PAIRING_SECRET` | no | generated into `CONFIG_DIR/pairing.secret` if unset |
| `AUDIT_KEY` | no | exactly 32 bytes, as 64 hex characters or standard base64; generated into `CONFIG_DIR/audit.key` if unset |
| `KYPASSWORD_BACKUP_DEPOSIT_INTERVAL` | no | Backup interval default; `24h`, `0` disables, otherwise whole seconds from `15m` to `8784h`; admin setting overrides it |
| `KYPASSWORD_BACKUP_DIR` | no | Absolute local capsule directory; in Docker use `/kypassword/data/backups` inside the mounted volume |
| `KYPASSWORD_BACKUP_KEEP` | no | Local retention count, default `7`, minimum `1` |
| `KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY` | no | Explicit private/CGNAT HTTPS destination opt-in, default `false`; loopback remains blocked |
| `KYPASSWORD_DNS` | no | only with `docker-compose.lan-dns.yml`: the LAN resolver the container uses, for a KyRecovery whose name exists only on your network |

`AUDIT_KEY` is 32 bytes exactly — not a minimum. A longer value is refused at startup
rather than shortened, because a key half of which is silently discarded is a key two
installs can disagree about. It is the same length `CONFIG_DIR/audit.key` holds, so an
existing install can move its key into the environment by copying that file's contents.
Changing the value orphans the existing chain: the records were signed under the old key
and nothing can verify them under the new one.

All three OIDC values must be set together. A partially set environment is treated as
unset, so that a typo cannot silently produce a configuration that is half environment and
half disk.

With `KYPASSWORD_OIDC_AUTO_PROVISION=true` (the default), anyone KySignOn authenticates
gets a KyPassword account and an empty vault on first sign-in. Set it to `false` to accept
only accounts KySignOn has explicitly replicated — but then make sure replication is
working first, or nobody can get in.

The server will not start without an identity provider. It could authenticate nobody, and
there is no local administrator who could fix it from the UI.

## Upgrading

The audit chain also refuses to start in cases an older version started in, and the
`AUDIT_KEY` length is now exact. [CHANGELOG.md](CHANGELOG.md) lists each condition and
what to do about it; read it before upgrading, not at the failed startup.

### From a version with local accounts

The server refuses to start while any **active** account has no KySignOn identity, and
names them:

```
KyPassword now authenticates only through KySignOn, and 1 active account(s) have no KySignOn identity:
  - alice (id u1)
```

Such an account could not sign in, and replication would create a second account for the
same person alongside it. Resolve each one with an offline command — these work with no
session, no network and no SSO configured, because you cannot sign in until the migration
is done:

```sh
# Bind a local account to its KySignOn identity.
kypassword-server link-sso --username alice --sub <kysignon-user-id>

# Or retire an account that has no KySignOn identity. Its vault is kept.
kypassword-server deactivate --username alice
```

The KySignOn user ID is the value shown in the KySignOn admin user list, and is the same
value KySignOn puts in the OIDC `sub` claim. Accounts are matched on that and nothing
else — never on username, which would let a name collision hand over someone's vault.

Both commands are safe to re-run: `link-sso` refuses a subject already bound to another
account, and `deactivate` is a no-op on an account that is already inactive.

Credential fields left in an old `users.json` (`passwordHash`, `authSalt`,
`authIterations`, `recoveryHash`, `mustChangePassword`) are ignored on load and erased
from disk on the first write. There is nothing to migrate to.

## Replication from KySignOn

Pair KyPassword as a system in KySignOn with the callback URL:

```
https://<your-kypassword-host>/api/sync/webhook
```

Keep `/scim` out of that URL and do not let it end in `/Users` or `/v2` — KySignOn routes
RESTfully on those, to paths this server does not serve.

Replication is keyed on the KySignOn user ID, which is the OIDC `sub`, so an account
created by replication and one created at first sign-in converge on the same record. A
deletion in KySignOn deactivates the KyPassword account and **keeps the vault**.

## KyRecovery backups

An administrator pairs the instance from **System Administration → Backup & Recovery**
with a six-digit code generated by KyRecovery. Pairing pins the suite recovery public key;
the instance then deposits a new sealed capsule every 24 hours by default. The same page can
deposit immediately, download a `.kycap`, and run a local restore drill. Pairing, depositing
downloading, pinning, unpairing and changing the schedule need a session signed in within the last 10 minutes; a stale admin is sent
back through KySignOn first.

For local-only backups, pin the suite public key from the ceremony page and configure
`KYPASSWORD_BACKUP_DIR`. One run seals once and writes every configured destination. The
page shows local copies, the remote receipt, partial failures and the next attempt. Set the
schedule there without restarting; failed attempts wait the same interval before retrying.
Unpair removes only the remote URL/token, keeping the key, receipt and local copies. A
KyRecovery administrator must separately revoke the token on KyRecovery.

**Check the key you pinned.** Pairing takes the recovery public key from whatever answered at
the URL you typed. The page shows the pinned key ID; compare it with the key ID on the
KyRecovery ceremony page before the first deposit. A different ID means every capsule is
sealed to someone else's key, and the pin is write-once, so fix it before depositing.

**Why the URL must be HTTPS.** The capsule itself is sealed and safe on any wire. The pairing
exchange is not: the recovery public key arrives over that connection, the deposit token goes
out over it on every run, and receipts come back over it. Plain HTTP would let a man in the
middle substitute their key at pairing or take the token. The server refuses `http://`, refuses
redirects, and refuses loopback and reserved addresses. Private and CGNAT destinations require
`KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY=true` for your intended HTTPS host. A KyRecovery on
your own LAN behind a TLS proxy also needs its name to resolve inside the container: put the resolver in
`KYPASSWORD_DNS` and start with the override file, which is kept separate because it replaces
the container's resolvers for every lookup.

```sh
KYPASSWORD_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d --build
```

KyRecovery is a blind store. A capsule contains encrypted vault files and envelopes, history
and conflicts, users and devices, active SSO and replication settings, and audit material.
Only the custodian quorum can open it. Vault contents remain encrypted after recovery because
KyPassword never held users' master passwords or plaintext vault keys.

Offline maintenance commands are available while the daemon is stopped:

```sh
kypassword-server backup-drill
kypassword-server export-capsule --out kypassword.kycap
kypassword-server deposit
kypassword-server restore --capsule kypassword.kycap --to ./restored
```

`restore` reads custodian shares from standard input, never command-line arguments. The full
procedure, from picking the capsule to deciding what to trust afterwards, is
[`docs/RESTORE.md`](docs/RESTORE.md). Live local commands refuse to race the daemon; use the
admin page while it is running.

The wire protocol is documented in the KyRecovery repository; the shared formats come from
`github.com/Busness-app/ky-primitives`.

## Building and running

```sh
go build -o kypassword-server ./cmd/server   # Go backend
cd frontend && npm install && npm run build  # web interface
docker build -t kypassword-server:latest .   # or the container
```

See `AGENTS.md` for the full verification suite and subsystem contracts.

## Signed directory and identity rollout

This receiver requires KySignOn's `syncauth` v1 sender (verified in KySignOn master
`a2d5dbc59c0724fd96dc21a861f1e6ba33b38711`). Deploy compatible sender and receiver together;
legacy bearer-only and timestamp-dot-body signatures are rejected. Keep the configured
pairing/client secret; the secret is used as an HMAC key and no longer travels in a header.
Use the suite type `kypassword` and callback `/api/sync/webhook`.

Completed event retries receive an acknowledgement without reapplying the directory change.
Failed handlers may retry the same ID and payload; reused IDs with different content are
refused. The bounded receipt cache covers the signature window within one process; restarting
clears it. Captured requests still expire after the library's five-minute clock window.

Login now verifies RS256 ID tokens against the configured HTTPS issuer/client and discovered
JWKS, including a nonce tied to single-use server-side login state. In-flight logins from an
older server or changed SSO configuration must start again. Userinfo can no longer substitute
for a missing or invalid ID token. Verify real SSO login and a signed directory update after
deployment; local TLS issuer tests are separate from that live proof.
