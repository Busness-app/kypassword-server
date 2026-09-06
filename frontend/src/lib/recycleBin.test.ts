import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx.js";
import { applyImportToVault } from "./csvImport.js";
import * as kdbxweb from "kdbxweb";
const { Kdbx, Credentials, ProtectedValue } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

test("recycled entries and descendants restore intact after encrypted reopening", async () => {
  const key = new Uint8Array(32).fill(9);
  const vault = await KeePassVault.createNew(key);
  const entry = vault.createEntry({ title: "Keep me", username: "user", password: " secret ",
    url: "https://example.test", notes: "notes", totpSeed: "JBSWY3DPEHPK3PXP", groupUuid: vault.getGroups()[0].uuid });
  vault.deleteEntry(entry.uuid);
  const recycled = vault.getRecycledEntries()[0];
  const nested = vault.createGroup("Nested", recycled.groupUuid);
  vault.updateEntry({ ...recycled, groupUuid: nested.uuid });
  vault.deleteEntry(entry.uuid); // Repeated deletion must never destroy it.
  assert.equal(vault.getLiveEntries().length, 0);
  assert.ok(!vault.getLiveGroups().some(group => group.uuid === nested.uuid));
  const liveNamesake = vault.createGroup("Recycle Bin");
  assert.ok(vault.getLiveGroups().some(group => group.uuid === liveNamesake.uuid));
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  assert.equal(reopened.getRecycledEntries()[0].uuid, entry.uuid);
  reopened.restoreEntry(entry.uuid);
  const restored = await KeePassVault.open(await reopened.exportBinary(), key);
  assert.equal(restored.getRecycledEntries().length, 0);
  const result = restored.getLiveEntries()[0];
  assert.deepEqual({ ...result, updatedAt: entry.updatedAt }, entry);
  assert.throws(() => restored.restoreEntry(entry.uuid), /not in the recycle bin/);
  assert.throws(() => restored.restoreEntry("missing"), /not in the recycle bin/);
});

test("delete keeps imported vaults recoverable even when recycling was disabled", async () => {
  const key = new Uint8Array(32).fill(8);
  const original = await KeePassVault.createNew(key);
  const db = await Kdbx.load(await original.exportBinary(), new Credentials(ProtectedValue.fromString(
    Array.from(key, byte => byte.toString(16).padStart(2, "0")).join(""))));
  db.meta.recycleBinEnabled = false;
  const vault = await KeePassVault.open(await db.save(), key);
  const entry = vault.createEntry({ title: "Keep", username: "", password: "p", url: "", notes: "", groupUuid: "" });
  vault.deleteEntry(entry.uuid);
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  assert.equal(reopened.getRecycledEntries()[0].uuid, entry.uuid);
  reopened.restoreEntry(entry.uuid);
  assert.equal(reopened.getLiveEntries()[0].password, "p");
});

test("CSV folders named Recycle Bin import into a live namesake", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(1));
  applyImportToVault(vault, [{id: "row", selected: true, title: "Imported", username: "", password: "p",
    url: "", notes: "", totpSeed: "", folder: "Recycle Bin/Nested"}], { folderMode: "csv_folders" });
  assert.equal(vault.getLiveEntries().length, 1);
  assert.equal(vault.getRecycledEntries().length, 0);
});
