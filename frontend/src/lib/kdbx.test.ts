import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx.js";

const vaultKey = () => {
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = i * 7 + 3;
  return key;
};

// Outside a browser there is no global DOMParser, so save/load runs through
// kdbxweb's @xmldom/xmldom fallback. These cover both that XML path and the
// CJS interop of the kdbxweb import, neither of which the CSV tests touch.
describe("KDBX vault round-trip", () => {
  test("kdbxweb class exports resolve under Node's CJS interop", async () => {
    const vault = await KeePassVault.createNew(vaultKey(), "Interop Vault");
    assert.ok(vault.getGroups().length > 0);
  });

  test("export and reopen preserves entries, unicode and XML metacharacters", async () => {
    const key = vaultKey();
    const vault = await KeePassVault.createNew(key, "RoundTrip Vault");
    const group = vault.createGroup("Nested", vault.getGroups()[0].uuid);

    vault.createEntry({
      title: 'Acct <&> "quoted"',
      username: "user@example.com",
      password: "p@ss'w<>rdé中",
      url: "https://example.com/x?a=1&b=2",
      notes: "line1\nline2 <![CDATA[tricky]]> & more",
      totpSeed: "JBSWY3DPEHPK3PXP",
      groupUuid: group.uuid,
    });

    const reopened = await KeePassVault.open(await vault.exportBinary(), key);
    const entries = reopened.getEntries();

    assert.equal(entries.length, 1);
    assert.equal(entries[0].title, 'Acct <&> "quoted"');
    assert.equal(entries[0].username, "user@example.com");
    assert.equal(entries[0].password, "p@ss'w<>rdé中");
    assert.equal(entries[0].url, "https://example.com/x?a=1&b=2");
    assert.equal(entries[0].notes, "line1\nline2 <![CDATA[tricky]]> & more");
    assert.equal(entries[0].totpSeed, "JBSWY3DPEHPK3PXP");
    assert.ok(reopened.getGroups().some((g) => g.name === "Nested"));
  });

  test("a wrong vault key cannot open the exported vault", async () => {
    const vault = await KeePassVault.createNew(vaultKey(), "RoundTrip Vault");
    const exported = await vault.exportBinary();

    const wrong = vaultKey();
    wrong[0] ^= 0xff;

    await assert.rejects(() => KeePassVault.open(exported, wrong));
  });
});
