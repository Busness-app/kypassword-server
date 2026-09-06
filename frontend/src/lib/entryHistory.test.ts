import assert from "node:assert/strict";
import test from "node:test";
import * as kdbxweb from "kdbxweb";
import { KeePassVault } from "./kdbx";
import { bytesToHex } from "./vaultCrypto";
import { findReusedPasswords } from "./passwordReuse";
const { Kdbx, Credentials, ProtectedValue } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

test("applied edits and restores retain independent encrypted versions with the same identity and folder", async () => {
  const key = new Uint8Array(32).fill(12);
  const vault = await KeePassVault.createNew(key);
  const login = vault.createEntry({ title: "Login", username: "me", password: "old secret", url: "", notes: "old notes", totpSeed: "old otp", groupUuid: "" });
  const other = vault.createEntry({ ...login, title: "Other" });
  const folder = vault.createGroup("Moved");
  assert.deepEqual(vault.getEntryHistory(login.uuid), []);
  assert.equal(vault.updateEntry(login), false);
  assert.deepEqual(vault.getEntryHistory(login.uuid), []);
  vault.updateEntry({ ...login, password: "new secret", notes: "new notes", totpSeed: "", groupUuid: folder.uuid });
  assert.equal(vault.getEntryHistory(login.uuid).length, 1);
  assert.equal(findReusedPasswords(vault).size, 0);
  vault.restoreEntryVersion(login.uuid, 0);
  assert.equal(vault.getEntryHistory(login.uuid).length, 2);
  assert.equal(findReusedPasswords(vault).size, 2);
  const bytes = await vault.exportBinary();
  for (const secret of ["old secret", "new secret", "old notes", "new notes"]) {
    assert.equal(Buffer.from(bytes).includes(Buffer.from(secret)), false);
  }
  const reopened = await KeePassVault.open(bytes, key);
  const restored = reopened.getLiveEntries().find(entry => entry.uuid === login.uuid);
  assert.ok(restored);
  assert.equal(restored.password, "old secret");
  assert.equal(restored.notes, "old notes");
  assert.equal(restored.totpSeed, "old otp");
  assert.equal(restored.groupUuid, folder.uuid);
  assert.equal(reopened.getLiveEntries().find(entry => entry.uuid === other.uuid)?.password, "old secret");
  reopened.restoreEntryVersion(login.uuid, 1);
  const undone = await KeePassVault.open(await reopened.exportBinary(), key);
  assert.equal(undone.getLiveEntries().find(entry => entry.uuid === login.uuid)?.password, "new secret");
  assert.equal(undone.getEntryHistoryVersion(login.uuid, 0).fields.find(field => field.name === "Password")?.value, "old secret");
  assert.equal(undone.getEntryHistory(login.uuid).length, 3);
  for (const index of [-1, 100, 0.5, NaN]) assert.throws(() => undone.restoreEntryVersion(login.uuid, index), /no longer available/);
  assert.throws(() => undone.restoreEntryVersion("missing", 0), /live vault/);
  undone.deleteEntry(login.uuid);
  assert.equal(undone.getEntryHistory(login.uuid).length, 3);
  assert.throws(() => undone.restoreEntryVersion(login.uuid, 0), /live vault/);
});

test("native imported history restores protected fields, attachments and metadata and preserves the replaced version", async () => {
  const key = new Uint8Array(32).fill(13);
  const credentials = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
  const seed = await KeePassVault.createNew(key);
  const native = await Kdbx.load(await seed.exportBinary(), credentials);
  const entry = native.createEntry(native.getDefaultGroup());
  const id = entry.uuid.toString();
  entry.fields.set("Title", ProtectedValue.fromString("Protected title"));
  entry.fields.set("Password", ProtectedValue.fromString("historic password"));
  entry.fields.set("Notes", ProtectedValue.fromString("historic notes"));
  entry.fields.set("Custom secret", ProtectedValue.fromString("historic custom"));
  entry.fields.set("TOTP", "historic totp");
  entry.binaries.set("old.bin", await native.createBinary(new Uint8Array([1, 2, 3]).buffer));
  entry.tags = ["old tag"];
  entry.autoType.defaultSequence = "old sequence";
  entry.times.expires = true;
  entry.times.expiryTime = new Date("2030-01-01T00:00:00Z");
  entry.pushHistory();
  // Simulate an imported history record with properties omitted by native copyFrom.
  entry.history[0].customData = new Map([["plugin", { value: "old metadata" }]]);
  entry.customData = new Map([["plugin", { value: "new metadata" }]]);
  entry.fields.set("Password", ProtectedValue.fromString("current password"));
  entry.fields.set("Notes", ProtectedValue.fromString("current notes"));
  entry.fields.set("Custom secret", ProtectedValue.fromString("current custom"));
  entry.fields.set("Only current", "remove on restore");
  entry.binaries.clear();
  entry.binaries.set("new.bin", await native.createBinary(new Uint8Array([4, 5]).buffer));
  entry.tags = ["new tag"];
  entry.autoType.defaultSequence = "new sequence";
  entry.times.expires = false;
  const vault = await KeePassVault.open(await native.save(), key);
  const preview = vault.getEntryHistoryVersion(id, 0);
  for (const name of ["Title", "Password", "Notes", "Custom secret", "TOTP"]) {
    assert.equal(preview.fields.find(field => field.name === name)?.protected, true, name);
  }
  assert.deepEqual(preview.attachments, ["old.bin"]);
  vault.restoreEntryVersion(id, 0);
  const db = await Kdbx.load(await vault.exportBinary(), credentials);
  const restored = [...db.getDefaultGroup().allEntries()][0];
  assert.equal(restored.uuid.toString(), id);
  assert.ok(restored.fields.get("Title") instanceof ProtectedValue);
  assert.equal(restored.fields.has("Only current"), false);
  assert.equal(restored.customData?.get("plugin")?.value, "old metadata");
  assert.equal(restored.history[1].customData?.get("plugin")?.value, "new metadata");
  assert.equal(restored.history[1].fields.get("Only current"), "remove on restore");
  assert.deepEqual(restored.tags, ["old tag"]);
  assert.equal(restored.autoType.defaultSequence, "old sequence");
  assert.equal(restored.times.expires, true);
  assert.equal(restored.times.expiryTime?.toISOString(), "2030-01-01T00:00:00.000Z");
  for (const [item, name, expected] of [[restored, "old.bin", [1, 2, 3]], [restored.history[1], "new.bin", [4, 5]]] as const) {
    const attachment = item.binaries.get(name);
    assert.ok(attachment && "hash" in attachment);
    const value = db.binaries.getValueByHash(attachment.hash);
    assert.ok(value instanceof ArrayBuffer);
    assert.deepEqual([...new Uint8Array(value)], expected);
  }
  // Ordinary edits also retain protected representations and imported metadata.
  vault.updateEntry({ ...vault.getLiveEntries()[0], notes: "edited again" });
  const edited = await Kdbx.load(await vault.exportBinary(), credentials);
  const latest = [...edited.getDefaultGroup().allEntries()][0];
  assert.ok(latest.fields.get("Title") instanceof ProtectedValue);
  assert.ok(latest.fields.get("Notes") instanceof ProtectedValue);
  assert.equal(latest.history[2].customData?.get("plugin")?.value, "old metadata");
});

test("history count limits retain the replaced version; disabled history never silently drops it on restore", async () => {
  const key = new Uint8Array(32).fill(14);
  const credentials = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
  const seed = await KeePassVault.createNew(key);
  const login = seed.createEntry({ title: "Login", username: "", password: "first", url: "", notes: "", groupUuid: "" });
  const db = await Kdbx.load(await seed.exportBinary(), credentials);
  db.meta.historyMaxItems = 1;
  const vault = await KeePassVault.open(await db.save(), key);
  vault.updateEntry({ ...login, password: "second" });
  vault.restoreEntryVersion(login.uuid, 0);
  assert.equal(vault.getEntryHistory(login.uuid).length, 1);
  assert.equal(vault.getLiveEntries()[0].password, "first");
  assert.equal(vault.getEntryHistoryVersion(login.uuid, 0).fields.find(field => field.name === "Password")?.value, "second");
  const disabledDb = await Kdbx.load(await vault.exportBinary(), credentials);
  disabledDb.meta.historyMaxItems = 0;
  const disabled = await KeePassVault.open(await disabledDb.save(), key);
  assert.equal(disabled.entryHistoryEnabled, false);
  assert.throws(() => disabled.restoreEntryVersion(login.uuid, 0), /disabled/);
  assert.equal(disabled.getLiveEntries()[0].password, "first");
  disabled.updateEntry({ ...login, password: "third" });
  assert.equal(disabled.getEntryHistory(login.uuid).length, 1, "existing imported history remains readable");
  disabledDb.meta.historyMaxItems = 10;
  disabledDb.meta.historyMaxSize = 0;
  const zeroBytes = await KeePassVault.open(await disabledDb.save(), key);
  assert.equal(zeroBytes.entryHistoryEnabled, false);
  assert.throws(() => zeroBytes.restoreEntryVersion(login.uuid, 0), /disabled/);
});
