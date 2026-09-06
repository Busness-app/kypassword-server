import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "node:crypto";
import * as kdbxweb from "kdbxweb";
import { KeePassVault, MAX_ATTACHMENT_BYTES } from "./kdbx";
import { bytesToHex } from "./vaultCrypto";
const { Kdbx, Credentials, ProtectedValue } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

const login = { title: "Files", username: "", password: "secret", url: "", notes: "", groupUuid: "" };
const signal = () => new AbortController().signal;

test("aggregate attachment budget rejects before mutation and explicit removal reclaims history bytes", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(24));
  const entry = vault.createEntry(login);
  for (let i = 0; i < 4; i++) {
    await vault.addAttachment(entry.uuid, `${i}.bin`, new Uint8Array(randomBytes(MAX_ATTACHMENT_BYTES)).buffer, signal());
  }
  const before = vault.getAttachments(entry.uuid);
  const history = vault.getEntryHistory(entry.uuid);
  await assert.rejects(vault.addAttachment(entry.uuid, "over.bin", new Uint8Array(randomBytes(MAX_ATTACHMENT_BYTES)).buffer, signal()), /40 MiB/);
  assert.deepEqual(vault.getAttachments(entry.uuid), before);
  assert.deepEqual(vault.getEntryHistory(entry.uuid), history);
  vault.removeAttachment(entry.uuid, "0.bin", true);
  assert.ok((await vault.exportBinary()).byteLength < 40 * 1024 * 1024);
});

test("explicit removal frees retained attachment bytes with entry history enabled", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(25));
  const entry = vault.createEntry(login);
  for (let i = 0; i < 4; i++) await vault.addAttachment(entry.uuid, `${i}.bin`, new Uint8Array(randomBytes(MAX_ATTACHMENT_BYTES)).buffer, signal());
  vault.removeAttachment(entry.uuid, "0.bin", true);
  assert.ok((await vault.exportBinary()).byteLength < 40 * 1024 * 1024, "removal must reclaim history-pinned bytes");
});

test("clearing history reclaims removed files but preserves password history and other entries' shared copies", async () => {
  const key = new Uint8Array(32).fill(26);
  const vault = await KeePassVault.createNew(key);
  const first = vault.createEntry(login);
  const second = vault.createEntry(login);
  const bytes = new Uint8Array([1, 2, 3]).buffer;
  await vault.addAttachment(first.uuid, "file", bytes, signal());
  await vault.addAttachment(second.uuid, "shared", bytes, signal());
  assert.equal(vault.attachmentBytes, 3);
  vault.removeAttachment(first.uuid, "file", true);
  assert.equal(vault.attachmentBytes, 3, "other entry still pins the file");
  assert.deepEqual(vault.getAttachment(second.uuid, "shared"), bytes);
  vault.removeAttachment(second.uuid, "shared");
  assert.equal(vault.attachmentBytes, 3, "ordinary removal retains history");
  assert.equal(vault.clearAttachmentHistory(second.uuid), true);
  assert.equal(vault.clearAttachmentHistory(second.uuid), false);
  assert.equal(vault.attachmentBytes, 0);
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  assert.equal(reopened.getEntryHistory(second.uuid).length, 2);
  assert.equal(reopened.getEntryHistoryVersion(second.uuid, 1).fields.find(field => field.name === "Password")?.value, "secret");
  assert.deepEqual(reopened.getEntryHistoryVersion(second.uuid, 1).attachments, []);
  reopened.deleteEntry(second.uuid);
  assert.throws(() => reopened.clearAttachmentHistory(second.uuid), /live vault/);
});

test("an imported vault above the upload limit can reclaim attachments without disabling history", async () => {
  const key = new Uint8Array(32).fill(27);
  const credentials = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
  const seed = await KeePassVault.createNew(key);
  const db = await Kdbx.load(await seed.exportBinary(), credentials);
  const entry = db.createEntry(db.getDefaultGroup());
  for (let i = 0; i < 5; i++) entry.binaries.set(`${i}.bin`, await db.createBinary(new Uint8Array(randomBytes(MAX_ATTACHMENT_BYTES)).buffer));
  entry.pushHistory();
  const original = await db.save();
  assert.ok(original.byteLength > 50 * 1024 * 1024);
  const vault = await KeePassVault.open(original, key);
  assert.ok(vault.entryHistoryEnabled);
  vault.removeAttachment(entry.uuid.toString(), "0.bin", true);
  const saved = await vault.exportBinary();
  assert.ok(saved.byteLength < 50 * 1024 * 1024);
  const reopened = await KeePassVault.open(saved, key);
  assert.equal(reopened.getAttachments(entry.uuid.toString()).length, 4);
  assert.ok(reopened.getEntryHistory(entry.uuid.toString()).length > 0);
  assert.equal(reopened.getEntryHistoryVersion(entry.uuid.toString(), 0).attachments.includes("0.bin"), false);
});

test("attachments survive encrypted saves, removal history and undo without changing other entries", async () => {
  const key = new Uint8Array(32).fill(21);
  const vault = await KeePassVault.createNew(key);
  const first = vault.createEntry(login);
  const second = vault.createEntry({ ...login, title: "Other" });
  const bytes = new TextEncoder().encode("attachment-secret-1234\u0000\u00ff").buffer;
  await vault.addAttachment(first.uuid, "秘密 & <file>.bin", bytes, signal());
  await vault.addAttachment(second.uuid, "shared.bin", bytes, signal());
  assert.equal(vault.getEntryHistory(first.uuid).length, 1);
  assert.deepEqual(vault.getAttachments(first.uuid), [{ name: "秘密 & <file>.bin", sizeBytes: bytes.byteLength }]);
  const download = vault.getAttachment(first.uuid, "秘密 & <file>.bin");
  assert.deepEqual(download, bytes);
  new Uint8Array(download).fill(0);
  assert.deepEqual(vault.getAttachment(first.uuid, "秘密 & <file>.bin"), bytes, "download is an independent copy");
  await assert.rejects(vault.addAttachment(first.uuid, "秘密 & <file>.bin", new Uint8Array([99]).buffer, signal()), /already exists/);
  assert.equal(vault.getEntryHistory(first.uuid).length, 1);
  assert.equal(vault.removeAttachment(first.uuid, "missing"), false);
  assert.equal(vault.removeAttachment(first.uuid, "秘密 & <file>.bin"), true);
  assert.deepEqual(vault.getAttachments(first.uuid), []);
  const binary = await vault.exportBinary();
  assert.equal(Buffer.from(binary).includes(Buffer.from("attachment-secret-1234")), false);
  const reopened = await KeePassVault.open(binary, key);
  assert.deepEqual(reopened.getAttachments(first.uuid), []);
  assert.deepEqual(reopened.getAttachment(second.uuid, "shared.bin"), bytes);
  reopened.restoreEntryVersion(first.uuid, 1);
  const restored = await KeePassVault.open(await reopened.exportBinary(), key);
  assert.deepEqual(restored.getAttachment(first.uuid, "秘密 & <file>.bin"), bytes);
  restored.deleteEntry(first.uuid);
  assert.deepEqual(restored.getAttachment(first.uuid, "秘密 & <file>.bin"), bytes, "recycle bin retains downloadable bytes");
  await assert.rejects(restored.addAttachment(first.uuid, "no.bin", bytes, signal()), /live vault/);
  assert.throws(() => restored.removeAttachment(first.uuid, "秘密 & <file>.bin"), /live vault/);
});

test("invalid and cancelled attachment additions leave no entry, history or binary-pool mutation", async () => {
  const key = new Uint8Array(32).fill(22);
  const vault = await KeePassVault.createNew(key);
  const entry = vault.createEntry(login);
  const bytes = new Uint8Array([1, 2, 3]).buffer;
  for (const name of ["", "\t", "bad\u0000name"]) await assert.rejects(vault.addAttachment(entry.uuid, name, bytes, signal()), /valid name/);
  await assert.rejects(vault.addAttachment(entry.uuid, "too-large", new ArrayBuffer(MAX_ATTACHMENT_BYTES + 1), signal()), /10 MiB/);
  await assert.rejects(vault.addAttachment("missing", "file", bytes, signal()), /live vault/);
  const controller = new AbortController();
  const pending = vault.addAttachment(entry.uuid, "cancelled", bytes, controller.signal);
  controller.abort();
  await assert.rejects(pending, error => error instanceof Error && error.name === "AbortError");
  assert.deepEqual(vault.getAttachments(entry.uuid), []);
  assert.deepEqual(vault.getEntryHistory(entry.uuid), []);
  const credentials = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
  const db = await Kdbx.load(await vault.exportBinary(), credentials);
  assert.equal(db.binaries.getAll().length, 0);
  await vault.addAttachment(entry.uuid, "empty", new ArrayBuffer(0), signal());
  assert.equal(vault.getAttachment(entry.uuid, "empty").byteLength, 0);
});

test("native protected binaries download correctly and cleanup respects history and shared references", async () => {
  const key = new Uint8Array(32).fill(23);
  const credentials = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
  const seed = await KeePassVault.createNew(key);
  const db = await Kdbx.load(await seed.exportBinary(), credentials);
  db.meta.historyMaxItems = 0;
  const first = db.createEntry(db.getDefaultGroup());
  const second = db.createEntry(db.getDefaultGroup());
  const bytes = new Uint8Array([4, 5, 255, 0]).buffer;
  first.binaries.set("protected.bin", ProtectedValue.fromBinary(bytes.slice(0)));
  const shared = await db.createBinary(bytes);
  first.binaries.set("shared.bin", shared);
  second.binaries.set("shared.bin", shared);
  const vault = await KeePassVault.open(await db.save(), key);
  const id = first.uuid.toString();
  assert.deepEqual(vault.getAttachment(id, "protected.bin"), bytes);
  assert.equal(vault.getAttachments(id).find(file => file.name === "protected.bin")?.sizeBytes, 4);
  vault.removeAttachment(id, "shared.bin");
  let reopened = await Kdbx.load(await vault.exportBinary(), credentials);
  assert.equal(reopened.binaries.getAll().length, 1, "other entry still owns the shared binary");
  vault.removeAttachment(second.uuid.toString(), "shared.bin");
  reopened = await Kdbx.load(await vault.exportBinary(), credentials);
  assert.equal(reopened.binaries.getAll().length, 0, "unreferenced bytes are removed when history is disabled");
  assert.deepEqual(vault.getEntryHistory(id), []);
});
