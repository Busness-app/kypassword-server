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

Each audit record is flushed to disk before the mark that counts it is advanced. This
costs one `fsync` per audited request, on the request path. It buys the ordering the
refusals above depend on: without it the two files can reach stable storage in either
order, and a mark that lands first turns an ordinary power loss into condition 1 at the
next start — a tamper accusation produced by pulling the plug.

A record cut in half by a crash or a full disk is dropped at startup, and a short write is
rolled back as it happens. Before, the reader stopped at the fragment and the next append
landed behind it, so the log was unreadable from that point on while every check still
passed.

### Failed audit writes are no longer silent

If an audit write fails — a read-only log directory, a full disk, the append timing out —
the failure is logged as `AUDIT WRITE FAILED` and `GET /api/health` answers 503 from then
on, so the container healthcheck takes the instance out of rotation. The request itself
still succeeds: the operation being recorded has already happened, and a 500 would only
ask the client to retry something that would be just as unrecorded. The 503 is sticky —
the missing record does not come back — so clear it by fixing the log volume and
restarting.
