import assert from "node:assert/strict";
import test from "node:test";
import { KeePassVault } from "./kdbx";
import { applyImportToVault } from "./csvImport";

test("nested folders and renames preserve identity, contents and history through encrypted reopening", async () => {
  const key = new Uint8Array(32).fill(31);
  const vault = await KeePassVault.createNew(key);
  const parent = vault.createGroup("  Projects  ");
  const child = vault.createGroup("秘密 <folder>", parent.uuid);
  const other = vault.createGroup("秘密 <folder>");
  const entry = vault.createEntry({ title: "Keep", username: "user", password: "secret", url: "", notes: "", groupUuid: child.uuid });
  await vault.addAttachment(entry.uuid, "file", new Uint8Array([3, 2, 1]).buffer, new AbortController().signal);
  const history = vault.getEntryHistory(entry.uuid);
  assert.equal(vault.renameGroup(parent.uuid, "Projects"), false);
  assert.equal(vault.renameGroup(parent.uuid, "Renamed"), true);
  assert.equal(vault.renameGroup(child.uuid, "Child"), true);
  assert.deepEqual(vault.getEntryHistory(entry.uuid), history);
  const exported = await vault.exportBinary();
  assert.equal(Buffer.from(exported).includes(Buffer.from("Renamed")), false);
  const reopened = await KeePassVault.open(exported, key);
  const renamed = reopened.getLiveGroups().find(group => group.uuid === child.uuid);
  assert.equal(renamed?.parentUuid, parent.uuid);
  assert.equal(renamed?.path, "KyPasswords Vault / Renamed / Child");
  assert.equal(renamed?.depth, 2);
  assert.equal(reopened.getLiveGroups().find(group => group.uuid === other.uuid)?.name, "秘密 <folder>");
  assert.equal(reopened.getLiveEntries()[0].groupUuid, child.uuid);
  assert.equal(reopened.getLiveEntries()[0].password, "secret");
  assert.equal(reopened.getEntryHistory(entry.uuid).length, history.length);
  assert.equal(reopened.getEntryHistoryVersion(entry.uuid, 0).fields.find(field => field.name === "Password")?.value, "secret");
  assert.deepEqual(reopened.getAttachment(entry.uuid, "file"), new Uint8Array([3, 2, 1]).buffer);
  assert.equal(reopened.renameGroup(reopened.getGroups()[0].uuid, "My vault"), true);
  assert.equal(reopened.getLiveGroups().find(group => group.uuid === child.uuid)?.path, "My vault / Renamed / Child");
});

test("invalid folder changes leave the tree unchanged and recycled folders cannot be renamed", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(32));
  const root = vault.getGroups()[0];
  const before = vault.getGroups();
  for (const name of ["", "   ", "bad\u0000name", "bad\nname"]) {
    assert.throws(() => vault.createGroup(name), /folder name/);
    assert.throws(() => vault.renameGroup(root.uuid, name), /folder name/);
  }
  assert.throws(() => vault.createGroup("Child", "missing"), /no longer available/);
  assert.throws(() => vault.renameGroup("missing", "Name"), /live vault/);
  assert.deepEqual(vault.getGroups(), before);
  const entry = vault.createEntry({ title: "", username: "", password: "", url: "", notes: "", groupUuid: "" });
  vault.deleteEntry(entry.uuid);
  const bin = vault.getRecycledEntries()[0].groupUuid;
  const nested = vault.createGroup("Imported child", bin);
  assert.throws(() => vault.renameGroup(bin, "Rename bin"), /live vault/);
  assert.throws(() => vault.renameGroup(nested.uuid, "Rename child"), /live vault/);
  assert.ok(!vault.getLiveGroups().some(group => group.uuid === nested.uuid));
});

test("CSV validates folder names before importing any rows", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(33));
  const before = vault.getGroups();
  const row = { id: "one", title: "One", username: "", password: "p", url: "", notes: "", totpSeed: "", folder: "Valid", selected: true };
  assert.throws(() => applyImportToVault(vault, [row, { ...row, id: "two", title: "Two", folder: "Bad\u0000name" }], { folderMode: "csv_folders" }), /folder name/);
  assert.deepEqual(vault.getGroups(), before);
  assert.deepEqual(vault.getEntries(), []);
});
