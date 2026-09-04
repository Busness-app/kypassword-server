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
| `KYPASSWORD_BACKUP_DEPOSIT_INTERVAL` | no | KyRecovery schedule; defaults to `24h`, `0` disables, minimum nonzero value `15m` |

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
deposit immediately, download a `.kycap`, and run a local restore drill.

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

`restore` reads custodian shares from standard input, never command-line arguments. Compare
the authenticated capsule details it prints with KyRecovery's receipt before starting with
`DATA_DIR=./restored/data` and `CONFIG_DIR=./restored/config`. Live local commands refuse to
race the daemon; use the admin page while it is running.

The authoritative protocol is KyRecovery's `zero_code_pairing_handoff_spec.md` v2.0.0.

## Building and running

```sh
go build -o kypassword-server ./cmd/server   # Go backend
cd frontend && npm install && npm run build  # web interface
docker build -t kypassword-server:latest .   # or the container
```

See `AGENTS.md` for the full verification suite and subsystem contracts.
