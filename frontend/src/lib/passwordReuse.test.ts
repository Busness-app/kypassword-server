import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx.js";
import { findReusedPasswords } from "./passwordReuse.js";

test("reuse compares exact nonempty passwords across live folders and updates after edits/deletion", async () => {
  const key = new Uint8Array(32).fill(7);
  const vault = await KeePassVault.createNew(key);
  const groupUuid = vault.getGroups()[0].uuid;
  const add = (title: string, password: string, folder = groupUuid) => vault.createEntry({
    title, password, username: "", url: "", notes: "", groupUuid: folder,
  });
  const first = add("First", "shared");
  const second = add("Second", "shared", vault.createGroup("Other").uuid);
  add("Case differs", "Shared");
  add("Whitespace differs", " shared ");
  add("Empty", ""); add("Also empty", "");
  const spaces = add("Spaces", " ");
  const moreSpaces = add("More spaces", " ");
  assert.deepEqual(findReusedPasswords(vault), new Map([
    [first.uuid, 2], [second.uuid, 2], [spaces.uuid, 2], [moreSpaces.uuid, 2],
  ]));
  vault.updateEntry({ ...second, password: "unique" });
  vault.deleteEntry(moreSpaces.uuid);
  assert.equal(findReusedPasswords(vault).size, 0);
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  assert.equal(findReusedPasswords(reopened).size, 0);
  const third = reopened.createEntry({ ...first, title: "Third" });
  assert.deepEqual(findReusedPasswords(reopened), new Map([[first.uuid, 2], [third.uuid, 2]]));
});
