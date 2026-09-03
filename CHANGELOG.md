# Changelog

## Unreleased

The audit chain moved onto the shared `ky-primitives/auditchain` and `ky-primitives/keyfile`
packages. Read this before upgrading: the audit store now refuses to start in cases the
previous version started in, and the key length is now exact.

### `AUDIT_KEY` is exactly 32 bytes

The documentation used to say "hex, 32+ bytes" and the code enforced only a floor. It is
now exactly 32 bytes, as 64 hex characters or as standard base64, and a longer value is
refused at startup rather than truncated: a key longer than the one asked for is a key
half of which is being silently discarded, and two installs disagreeing about how much of
it counts cannot read each other's chains.

If you set a longer `AUDIT_KEY`, do not shorten it — the existing chain was signed under
the whole value you supplied, and the records cannot be verified under anything else.
Stay on the previous version, start a new chain and keep the old log and mark for the
auditor, or restore both from a backup taken under a 32-byte key.

`CONFIG_DIR/audit.key` is unchanged: it always held 32 bytes as hex, and its contents can
be copied into `AUDIT_KEY` as they are.

### Conditions that now refuse to start

Each of these used to be survivable, and each was survivable by writing over the evidence.
None of them is fixable from configuration; all of them want a look before a restart.

1. **The log holds fewer records than the mark counts.** `CONFIG_DIR/audit.state` records
   how many records `DATA_DIR/audit/audit.jsonl` should hold. Fewer means records were
   removed from the end, and appending would write over the gap. An emptied log counts:
   zero records against a non-zero mark is the most truncated log there is, not a fresh
   install. Restore the log from backup, or move the log and the mark aside together to
   begin a new chain and keep the old pair.
2. **The log holds records and the mark counts none.** The mark is the only record of how
   long the log is meant to be, so without it a truncated log and an intact one are the
   same file. A previous version would mint a mark here and bless whatever was on disk.
   Restore the mark from backup, or move both files aside.
3. **The key file cannot be read as a key.** `audit.key` that does not decode to exactly
   32 bytes — including a zero-length one left by an interrupted write — is refused and
   left exactly as found. A previous version treated it as "no key yet" and generated a
   replacement, after which every record ever written was permanently unverifiable. The
   file is also refused if it is readable beyond its owner (`chmod 0600 audit.key`), if
   it is a symlink, or if it is not owned by the user the server runs as.

A corrupt `audit.state` refuses too, rather than being replaced with an empty one.

Records that sit past the mark are not a refusal on their own: a mark left behind by an
interrupted write, or by a config volume that was briefly unwritable, is reconciled at
startup after every record past the mark has been checked against its position, its own
digest and its predecessor.

### Durability

Each audit record is flushed to disk before the mark that counts it is advanced, and the
mark is flushed before the rename that publishes it. That is **two `fsync` calls per
audited request**, on the request path and serialised under the store mutex: measured at
about **2.6 ms per audited request against 0.08 ms unflushed — roughly 32x** (btrfs on
NVMe, 300 appends per run, three runs; a slower disk will be worse). It buys the ordering
the refusals above depend on: without it the two files can reach stable storage in either
order, and a mark that lands first turns an ordinary power loss into condition 1 at the
next start — a tamper accusation produced by pulling the plug.

A short write is rolled back as it happens, and an incomplete record left on the *end* of
the log by a crash is dropped at startup. Only the end: bytes the reader stops at with
newline-terminated records still behind them are damage in the middle of the log, and the
server refuses to start rather than truncate to the tear. An earlier version of this fix
truncated either way, which destroyed every complete record after a single corrupted line
and booted clean.

### Failed audit writes are no longer silent

If an audit write fails — a read-only log directory, a full disk, the append timing out —
it is reported three ways: `AUDIT WRITE FAILED` on stderr with the cause and a running
count, `"status": "degraded"` from `GET /api/health`, and a `writeFailures` count from the
admin-only `GET /api/audit/verify`, which otherwise reports a log that lost a record as
perfectly valid. **Watch stderr for `AUDIT WRITE FAILED`** — that is the line with the
cause in it.

The request itself still succeeds: the operation being recorded has already happened, and
a 500 would only ask the client to retry something that would be just as unrecorded.

`GET /api/health` stays **200** in both states, and the container healthcheck therefore
stays green. That is deliberate. The counter never clears — the missing record does not
come back — so a 503 would take a credential vault out of service for one transient write
failure and keep it there until a human restarted it. Behind a load balancer that is a
full data volume turning into a lockout, which is worse than the record that was lost.
Clear the degraded state by fixing the log volume and restarting.
