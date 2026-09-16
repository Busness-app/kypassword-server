# Restoring KyVault from a capsule

This is the procedure for bringing a KyVault server back from a `.kycap` backup after the
original is gone. It needs three things, held by three different parties by design:

| Thing | Who has it |
|---|---|
| The capsule (`.kycap`) | KyRecovery, or a downloaded copy from **System Administration → Backup & Recovery** or `export-capsule` |
| k custodian cards | The custodians from the suite ceremony (k is usually 2 of 3) |
| A machine to restore on | You |

Nobody can do this alone. KyRecovery cannot open a capsule. One custodian cannot. The server
that made the backup never could. That is the point, and it is also why you should run this
procedure once as a drill before you ever need it.

The `docker compose` commands below use the base file alone, which runs the published
image. Source install: confirm the `COMPOSE_FILE` line in `.env` contains `docker-compose.build.yml`
before the first command; extra overlays beside it, such as `docker-compose.lan-dns.yml`, are
fine (the install step in `CONTRIBUTING.md` adds it). Check: `grep '^COMPOSE_FILE=' .env | grep -q
docker-compose.build.yml && echo ok`. Otherwise a restore silently pulls a different binary than
the one you built and are running.
Published install: never restore onto a floating `:latest`; the step before the restore
command pins and verifies a digest.

## What a capsule holds

Everything a fresh KyVault server needs to be the old one, and nothing that opens a user's
vault:

| Path in the capsule | What it is |
|---|---|
| `data/vaults/<user>/vault.kdbx`, `metadata.json`, `history/`, `conflicts/` | Every user's encrypted KDBX file with its checksum, size and version, plus history and conflict copies. Still encrypted under the user's master password |
| `data/audit/audit.jsonl` | The append-only audit log |
| `config/users.json`, `config/devices.json` | Accounts and paired devices |
| `config/sso.json` | The KySignOn (OIDC) issuer, client ID and client secret. Environment variables override it when set |
| `config/pairing.secret` | The bearer secret KySignOn uses to replicate accounts into this server |
| `config/audit.key`, `config/audit.state` | The HMAC key and anchor that make the audit chain verifiable |
| `config/recovery.pub`, `config/kyrecovery.json`, `config/recovery-token.key` | The pinned suite public key and settings; the sealed token and its key exist only when previously paired |
| `config/restore-manifest.json` | Service name, version and retention. It also states that the server holds no vault decryption key |

The server never held a master password or a vault key, so a restored server cannot read a
vault either. Users open their vaults with their own passwords, exactly as before.

The restored directory is the live directory in the clear. Treat it like the running server's
`/kypassword/config`.

## Before you start

- **Pick the capsule.** In the KyRecovery dashboard, open Capsules, find the newest one for
  service `kyvault` that is not flagged corrupt, and note its `capsule_id`, `created_at`
  and `digest`. You will compare these after the restore. Download it with an operator session
  (`GET /api/capsules/{id}/download`).
- **Gather k custodians.** Each card carries one share, a single line beginning `ky2-`. They
  type or paste it themselves; do not collect the shares in a file, a chat, or an email. Two
  shares in one place is the suite key in one place.
- **Prepare an empty directory** on a machine you trust, ideally the one that will run the
  restored server. The restore refuses a directory that is not empty. If the directory does
  not exist the binary creates it at mode 700.

## Step 1: open the capsule

With the binary (from a release, or `go build ./cmd/server`):

```bash
kyvault-server restore --capsule cap-kyvault-XXXXXXXX.kycap --to ./restored
```

For a published-image install, and always on a fresh recovery machine, pin the commit you
intend to run (normally the one that made the backup, or the current tip) to a digest you have
verified before it reads a single share (`gh` must be logged in). Name the commit yourself.
Tags are movable, `:<commit sha>` included, so the chain also checks that the attestation records
your commit as its source: the guarantee is the commit you named, not whatever the tag points at. The
chain stops at the first failure and renames a same-directory staging file over `.env` only
if the filtered copy was written in full, so your secrets are never truncated. The pin persists
in `.env` after the drill: see the README's upgrade note for moving off it.

```bash
sha=<full commit sha you intend to run, e.g. $(git rev-parse origin/master)>
d=$(docker buildx imagetools inspect ghcr.io/busness-app/kyvault-server:$sha --format '{{.Manifest.Digest}}') \
  && gh attestation verify "oci://ghcr.io/busness-app/kyvault-server@$d" --repo Busness-app/kyvault-server \
       --cert-identity https://github.com/Busness-app/kyvault-server/.github/workflows/ci.yml@refs/heads/master \
  && [ "$(gh attestation verify "oci://ghcr.io/busness-app/kyvault-server@$d" --repo Busness-app/kyvault-server \
       --cert-identity https://github.com/Busness-app/kyvault-server/.github/workflows/ci.yml@refs/heads/master \
       --format json --jq '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit')" = "$sha" ] \
  && (umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env && { grep -v '^KYVAULT_IMAGE=' .env || [ $? -eq 1 ]; } > "$t" \
      && echo "KYVAULT_IMAGE=ghcr.io/busness-app/kyvault-server@$d" >> "$t" && mv "$t" .env) \
  && grep -qxF "KYVAULT_IMAGE=ghcr.io/busness-app/kyvault-server@$d" .env
```

Then, in the same shell (the check compares against `$d`), refuse to go on unless the image in
effect is exactly that digest. A source install passes on its `kyvault-server:local` build instead,
since `docker-compose.build.yml` wins over the pin, which is what a source install wants. The
two refusal messages are distinct on purpose: a broken invocation is not an unpinned image.

```bash
imgs=$(docker compose config --images) || { echo 'refusing: compose could not resolve the image'; false; }
printf '%s\n' "$imgs" | grep -qxF "ghcr.io/busness-app/kyvault-server@$d" || printf '%s\n' "$imgs" | grep -qxF 'kyvault-server:local' \
  || { echo "refusing: image in effect is '$imgs', not the digest verified above"; false; }
```

With Docker Compose, from the repository directory, mount the capsule and an empty target
directory into a one-off container. Create the target yourself at mode 700 and run the
container as your own user, so the extraction can write into it and what comes out is owned
by you, not by root and not by the image's user. The image's entrypoint is the binary, so the
subcommand goes straight after the service name; `--no-deps` keeps the real server down:

```bash
mkdir -m 700 restored
docker compose run --rm --no-deps --user "$(id -u):$(id -g)" \
  -v "$PWD/cap-kyvault-XXXXXXXX.kycap:/in.kycap:ro" \
  -v "$PWD/restored:/restored" \
  kyvault-server restore --capsule /in.kycap --to /restored
```

The command prompts:

```
Enter custodian shares, one per line; finish with EOF (Ctrl-D):
```

Each custodian enters their share on its own line. After all k shares are entered, send EOF (Ctrl-D). Shares are read from stdin only, never from the command line, because argv is
world-readable and lands in shell history.

Only for a rehearsal with synthetic test shares, never with real cards, stdin can be a file.
Delete it afterwards; a file holding k shares is the suite key in a file.

```bash
kyvault-server restore --capsule cap-kyvault-XXXXXXXX.kycap --to ./restored < test-shares.txt
```

After extraction and product checks pass it prints authenticated capsule details:

```
Restored 12 files from capsule cap-kyvault-1788574282596580928
  service:      kyvault (v1.2.0)
  created:      2026-09-05T02:11:22Z
  recovery key: fe8af276...
  payload hash: e059a268...
```

**Check it against KyRecovery's record.** The capsule ID and `created` must match the
deposit record you noted. Opening the capsule has already proved the bytes are intact and were
sealed to the suite key; matching the ID and time against the blind store's record is what
proves this is the capsule you meant, not an older one someone substituted.

Failures you may see, and what they mean:

| Message | Meaning |
|---|---|
| `capsule is for service ... this instance is kyvault` | The file is a capsule from another suite product. Legacy `kypassword` capsules are accepted and reported explicitly; another service name is rejected |
| `not a recognised capsule container` | The file is not a `.kycap` at all: truncated download or the wrong file |
| `shamir: need at least 2 shares` | Input ended before k lines were read. Check for a missed line |
| `shamir: share is not index-hex: checksum "6fax", expected "6fa6"` | One character on a card was mistyped. The checksum tells you which share to re-enter |
| `capsule is sealed to a different recovery key` | Valid shares, but from a different ceremony than the one that sealed this capsule |
| `restore target directory is not empty` | Use an empty directory. The restore never overwrites |

Cryptographic extraction failures roll back the partial extraction. If product validation
fails after extraction, the target remains for diagnosis; it is not declared restored and
must not be put into service. Use a fresh empty target for the next attempt.

## Step 2: check what came out

```bash
find restored -type f -printf '%m %p\n'
```

Every file is mode `600`, under `restored/config` and `restored/data`. Expect the ten config
and audit files from the table above plus one directory per user under `restored/data/vaults`.
An instance that never had a user has no `vaults` entries; that is not an error.

`cat restored/config/restore-manifest.json` shows the version the old server ran and states
`vaultDecryptionKey: not held by server`.

## Step 3: put it in service

The server reads everything from `CONFIG_DIR` and `DATA_DIR`. The compose file maps them to
the `kypassword_config` and `kypassword_data` volumes. Both must be empty before the copy,
for the same reason Step 1 demands an empty directory: a vault directory for a user who is
not in the restored `users.json`, or an audit log longer than the restored anchor, is two
servers mixed into one.

```bash
docker compose down
docker compose run --rm --no-deps --entrypoint sh kyvault-server \
  -c 'ls -A /kypassword/config | wc -l; ls -A /kypassword/data | wc -l'
```

Both counts must be `0`. If they are not, the old volumes still hold data, and you keep a
copy before anything else: it holds every change made after the capsule was sealed, and it is
the only record Step 5 can walk. Create the destination yourself, mode 700, and run the copy
as root, because the image's user cannot write a directory it does not own:

```bash
mkdir -m 700 old-config old-data
docker compose run --rm --no-deps --user root \
  -v "$PWD/old-config:/outc" -v "$PWD/old-data:/outd" --entrypoint sh kyvault-server \
  -c 'cp -a /kypassword/config/. /outc/ && cp -a /kypassword/data/. /outd/ && ls -A /outc /outd | wc -l'
```

The command must exit 0. `old-config/` and `old-data/` are now the old live directories in
the clear, with the same keys the capsule holds; they are removed in "Afterwards", not before
Step 5 is done.

Only with the copy confirmed, remove the volumes. This is irreversible:

```bash
docker compose down -v
docker compose run --rm --no-deps --entrypoint sh kyvault-server \
  -c 'ls -A /kypassword/config | wc -l; ls -A /kypassword/data | wc -l'
```

With `0` and `0` confirmed, copy the restored files in and start:

```bash
docker compose run --rm --no-deps --user root --entrypoint sh \
  -v "$PWD/restored/config:/fromc:ro" -v "$PWD/restored/data:/fromd:ro" kyvault-server \
  -c 'cp -a /fromc/. /kypassword/config/ && cp -a /fromd/. /kypassword/data/ && chown -R kypassword:kypassword /kypassword/config /kypassword/data'
docker compose up -d
```

The one-off container mounts the same volumes the service uses, so the copy lands where the
server will read it, owned by the image's `kypassword` user.

Keep the KySignOn settings identical to the old deployment. `KYVAULT_OIDC_ISSUER`,
`KYVAULT_OIDC_CLIENT_ID` and `KYVAULT_OIDC_CLIENT_SECRET` in `.env` override
`config/sso.json` when set; either keep supplying the same values or unset them so the
restored file is read. The same applies to `PAIRING_SECRET` and `AUDIT_KEY` against
`config/pairing.secret` and `config/audit.key`. Never print a key to a terminal or type one on
a command line: it lands in scrollback, session recordings and shell history. If you must
produce a value for `.env`, write it there with `umask 077` and nothing else on stdout.

**Bare binary.** Point `CONFIG_DIR` at `restored/config` and `DATA_DIR` at `restored/data`,
set the OIDC variables as before, and start.

## Step 4: prove it

1. Sign in through KySignOn with an existing admin account. That proves `sso.json` and the
   client secret.
2. Open **System Administration → Backup & Recovery**. If the backup was paired, the key
   shows as pinned with the same key ID as before, and the pairing is present because the
   sealed token and its key both came across. Click **Deposit now** to prove the credential
   still works. If the screen says the key is missing, `config/recovery.pub` did not come
   across; re-pair, which is refused unless KyRecovery hands back the same key.
3. Have one user open their vault from a paired device or the web UI with their master
   password. That proves the KDBX files and their metadata are intact.
4. Check the audit log: the last events before the restore are there, followed by your
   sign-in. The chain verifies because `audit.key` and `audit.state` came across together.

## Step 5: decide what to trust

The restore proves the service works. It does not make the restored state current or safe.
Everything comes back as of the capsule's `created_at`: users, devices, vault contents,
history, and the audit log. Anything changed after that moment is undone.

1. Sessions are already gone. KyVault keeps sessions in memory only, so the restart in
   Step 3 signed everyone out; nobody holds a cookie the restored server accepts.
2. Walk the old audit log in `old-data/audit/audit.jsonl` from `created_at` to the moment the
   old server was lost (the restored log stops at `created_at`), and re-apply what happened
   after the capsule: deactivated accounts, removed devices, vault changes users will need to
   re-enter. Compare the restored user list with KySignOn; a deactivation KySignOn made after
   the capsule is undone until replication runs again or you repeat it.
3. Devices paired after the capsule are unknown to the restored server and must pair again.
   Devices removed after the capsule are back; remove them again.
4. If the reason for the restore was a suspected compromise rather than hardware loss, treat
   the restored secrets as exposed and rotate the ones that can be rotated. A restore from
   before a compromise brings the attacker's access back with the service unless you do this.

   **Never rotate `audit.key`.** The whole chain is keyed under it; a new key means nothing
   before this moment can be verified again. It is a verification key, not an access key, and
   an attacker who read it can forge history but cannot reach a vault with it.

   Rotate these, in order:

   - **The KySignOn client secret.** Issue a new secret for the KyVault client in KySignOn
     and put it in `.env` (or `config/sso.json` if the environment does not set it), then
     `docker compose up -d`.
   - **The replication secret.** Stop the server, remove `config/pairing.secret`, start; a new
     one is generated. Then give KySignOn the new value for its KyVault replication target.
     If `PAIRING_SECRET` is set in `.env`, replace it there instead.

     ```bash
     docker compose down
     docker compose run --rm --no-deps --user root --entrypoint sh kyvault-server \
       -c 'rm /kypassword/config/pairing.secret && ls -A /kypassword/config'
     docker compose up -d
     ```

     The listing must still show `audit.key`, `users.json` and `recovery.pub`.
   - **The KyRecovery credential.** On KyRecovery, revoke the old pairing
     (`POST /api/pairing/revoke`); the product token cannot do this itself. Then pair again
     from Backup & Recovery with a fresh code. Re-pairing is accepted only to the same key.

   User vault passwords are the users' own; the server cannot rotate them and never could
   read them. If a user believes their master password was exposed, they change it in their
   client, which re-encrypts and re-uploads the vault.

   Confirm with **Deposit now** so the recovered server has a capsule that reflects the
   rotation.

## Afterwards

- Delete the `restored/` directory once the server runs from its own copy, and `old-config/`
  and `old-data/` once Step 5 is done. All three are the live directories in the clear, secrets
  included. Files copied out as root are root-owned, so `sudo rm -rf old-config old-data`.
- The custodians' cards are unchanged; a restore does not consume them. If a card was
  exposed during the restore (read aloud, photographed, pasted anywhere shared), that is a
  key compromise for the whole suite, not for one server: run a new ceremony.
- Make a backup from the restored server so the newest capsule reflects the recovery.

## Drill it

Run Steps 1 and 2 against the latest capsule on a scratch machine once a quarter, with the
real custodians and their real cards, and then delete the output. The in-app drill and
`kyvault-server backup-drill` prove the capsule format restores; only this proves the
cards do.
