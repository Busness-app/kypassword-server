import { test } from "node:test";
import assert from "node:assert/strict";
import * as kdbxweb from "kdbxweb";
import { KeePassVault } from "./kdbx.js";
import { compareConflictEntries } from "./conflictComparison.js";
const { Kdbx, Credentials, ProtectedValue, KdbxUuid } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

const text = (value: string | kdbxweb.ProtectedValue | undefined) => typeof value === "string" ? value : value?.getText();

test("comparison follows UUID and preserves exact field differences", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(1));
  const entry = vault.createEntry({ title: "Same title", username: "u", password: " password ", url: "", notes: "", groupUuid: "" });
  const rows = compareConflictEntries([entry], [
    { ...entry, password: "password", totpSeed: "OTP" },
    { ...entry, uuid: "another-id" },
    { ...entry, totpSeed: "" },
  ]);
  assert.deepEqual(rows[0].changedFields.map(([key]) => key), ["password", "totpSeed"]);
  assert.equal(rows[1].current, undefined);
  assert.equal(rows[2].changedFields.length, 0);
});

test("recovering a copy preserves full entry data without replacing current entries or icons", async () => {
  const key = new Uint8Array(32).fill(4);
  const credentials = new Credentials(ProtectedValue.fromString(Array.from(key, b => b.toString(16).padStart(2, "0")).join("")));
  const seed = await KeePassVault.createNew(key);
  const login = seed.createEntry({ title: "Account", username: "user", password: "new password", url: "https://example.test", notes: "notes", groupUuid: "" });
  const deleted = seed.createEntry({ ...login, title: "Deleted" });
  seed.deleteEntry(deleted.uuid);
  const iconId = KdbxUuid.random();
  const currentDb = await Kdbx.load(await seed.exportBinary(), credentials);
  const currentEntry = [...currentDb.getDefaultGroup().allEntries()].find(entry => entry.uuid.toString() === login.uuid);
  assert.ok(currentEntry);
  currentEntry.customIcon = iconId;
  currentDb.meta.customIcons.set(iconId.toString(), { data: new Uint8Array([1, 2]).buffer });
  const currentBytes = await currentDb.save();
  const conflictDb = await Kdbx.load(currentBytes, credentials);
  const conflictEntry = [...conflictDb.getDefaultGroup().allEntries()].find(entry => entry.uuid.toString() === login.uuid);
  assert.ok(conflictEntry);
  conflictDb.meta.customIcons.set(iconId.toString(), { data: new Uint8Array([3, 4]).buffer });
  conflictEntry.fields.set("Title", ProtectedValue.fromString("Account"));
  conflictEntry.fields.set("Notes", ProtectedValue.fromString("protected notes"));
  conflictEntry.fields.set("Password", ProtectedValue.fromString("old password"));
  conflictEntry.fields.set("Custom secret", ProtectedValue.fromString("keep custom field"));
  conflictEntry.fields.set("otp", "JBSWY3DPEHPK3PXP");
  const attachment = await conflictDb.createBinary(new Uint8Array([8, 9, 10]).buffer);
  conflictEntry.binaries.set("attachment.bin", attachment);
  conflictEntry.pushHistory();
  const current = await KeePassVault.open(currentBytes, key);
  const source = await KeePassVault.open(await conflictDb.save(), key);
  assert.equal(source.getLiveEntries()[0].title, "Account");
  assert.equal(source.getLiveEntries()[0].notes, "protected notes");
  const copyId = current.recoverEntryCopy(source, login.uuid);
  assert.notEqual(copyId, login.uuid);
  assert.equal(current.getLiveEntries().find(entry => entry.uuid === login.uuid)?.password, "new password");
  assert.equal(source.getLiveEntries()[0].password, "old password");
  assert.throws(() => current.recoverEntryCopy(source, deleted.uuid), /live entry/);
  assert.throws(() => current.recoverEntryCopy(source, "missing"), /live entry/);

  const reopened = await Kdbx.load(await current.exportBinary(), credentials);
  const recovered = [...reopened.getDefaultGroup().allEntries()].find(entry => entry.uuid.toString() === copyId);
  assert.ok(recovered);
  assert.ok(recovered.fields.get("Title") instanceof ProtectedValue);
  assert.equal(text(recovered.fields.get("Title")), "Account (recovered)");
  assert.equal(text(recovered.fields.get("Custom secret")), "keep custom field");
  assert.equal(text(recovered.fields.get("Password")), "old password");
  assert.equal(recovered.fields.get("otp"), "JBSWY3DPEHPK3PXP");
  assert.equal(recovered.history.length, 1);
  assert.equal(text(recovered.history[0].fields.get("Custom secret")), "keep custom field");
  const recoveredAttachment = recovered.binaries.get("attachment.bin");
  assert.ok(recoveredAttachment && "hash" in recoveredAttachment);
  const binary = reopened.binaries.getValueByHash(recoveredAttachment.hash);
  assert.ok(binary && binary instanceof ArrayBuffer);
  assert.deepEqual(new Uint8Array(binary), new Uint8Array([8, 9, 10]));
  assert.ok(recovered.customIcon);
  assert.notEqual(recovered.customIcon.toString(), iconId.toString());
  assert.deepEqual(reopened.meta.customIcons.get(iconId.toString())?.data, new Uint8Array([1, 2]).buffer);
  assert.deepEqual(reopened.meta.customIcons.get(recovered.customIcon.toString())?.data, new Uint8Array([3, 4]).buffer);
  assert.equal((await KeePassVault.open(await current.exportBinary(), key)).getRecycledEntries().length, 1);
});

test("recovering an unprotected title keeps it unprotected", async () => {
  const key = new Uint8Array(32).fill(5);
  const source = await KeePassVault.createNew(key);
  const entry = source.createEntry({title: "Plain", username: "", password: "p", url: "", notes: "", groupUuid: ""});
  const target = await KeePassVault.createNew(key);
  const id = target.recoverEntryCopy(source, entry.uuid);
  const credentials = new Credentials(ProtectedValue.fromString(Array.from(key, b => b.toString(16).padStart(2, "0")).join("")));
  const db = await Kdbx.load(await target.exportBinary(), credentials);
  const copy = [...db.getDefaultGroup().allEntries()].find(item => item.uuid.toString() === id);
  assert.ok(copy);
  assert.equal(typeof copy.fields.get("Title"), "string");
  assert.equal(copy.fields.get("Title"), "Plain (recovered)");
});
