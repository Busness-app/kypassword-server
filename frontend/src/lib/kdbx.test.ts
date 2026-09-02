import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault, deriveArgon2Key } from "./kdbx.js";
import * as kdbxweb from "kdbxweb";

const { Consts, Credentials, ProtectedValue, Kdbx } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

const vaultKey = () => {
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = i * 7 + 3;
  return key;
};

const bytesToHex = (b: Uint8Array) =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

// KDF parameters arrive as a VarDictionary of mixed number/Int64 values.
const uuidOf = (kdf: kdbxweb.VarDictionary) => {
  const raw = kdf.get("$UUID") as ArrayBuffer;
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
};
const numberOf = (kdf: kdbxweb.VarDictionary, name: string) => {
  const v = kdf.get(name) as number | { lo: number; hi: number };
  return typeof v === "number" ? v : v.hi * 2 ** 32 + v.lo;
};

// Outside a browser there is no global DOMParser, so save/load runs through
// kdbxweb's @xmldom/xmldom fallback. The CSV tests never call exportBinary/open,
// so that path is uncovered without this file.
describe("KDBX vault round-trip", () => {
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

    // Match the code: a bare rejects() would also pass on a TypeError from a
    // broken interop binding or an xmldom failure, proving nothing about the key.
    await assert.rejects(
      () => KeePassVault.open(exported, wrong),
      (err: unknown) => (err as { code?: string }).code === Consts.ErrorCodes.InvalidKey,
    );
  });

  test("opens a KyAuth vault encrypted with the hexadecimal vault key", async () => {
    const key = vaultKey();
    const credentials = new Credentials(ProtectedValue.fromString(
      Array.from(key).map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    ));
    const database = Kdbx.create(credentials, "KyAuth Passwords");
    database.header.setKdf(Consts.KdfId.Aes);

    const reopened = await KeePassVault.open(await database.save(), key);

    assert.equal(reopened.getGroups()[0].name, "KyAuth Passwords");
  });
});

// A vault only reaches its owner during a KySignOn outage if they can actually open the
// file we hand them. That means the credential has to be something a person can type into
// KeePassXC — which raw key bytes are not.
describe("vaults are interchangeable with KyAuth", () => {
  test("a new vault opens with the hexadecimal key typed as a password", async () => {
    const key = vaultKey();
    const vault = await KeePassVault.createNew(key, "Portable Vault");

    const typed = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
    const opened = await Kdbx.load(await vault.exportBinary(), typed);

    assert.equal(opened.getDefaultGroup().name, "Portable Vault");
  });

  test("a new vault is NOT locked to raw key bytes", async () => {
    // The old behaviour. Nobody can type 32 raw bytes, so a vault locked this way has no
    // offline recovery path at all.
    const key = vaultKey();
    const vault = await KeePassVault.createNew(key, "Portable Vault");
    const exported = await vault.exportBinary();
    const raw = new Credentials(ProtectedValue.fromBinary(key.buffer.slice(0) as ArrayBuffer));

    await assert.rejects(
      () => Kdbx.load(exported, raw),
      (err: unknown) => (err as { code?: string }).code === Consts.ErrorCodes.InvalidKey,
    );
  });

  test("a new vault uses Argon2d with kotpass's parameters", async () => {
    const vault = await KeePassVault.createNew(vaultKey(), "Portable Vault");
    const reopened = await Kdbx.load(
      await vault.exportBinary(),
      new Credentials(ProtectedValue.fromString(bytesToHex(vaultKey()))),
    );

    const kdf = reopened.header.kdfParameters;
    assert.ok(kdf, "KDBX4 must carry KDF parameters");
    assert.equal(uuidOf(kdf), Consts.KdfId.Argon2d, "KyAuth writes Argon2d; we must match");

    assert.equal(numberOf(kdf, "M"), 32 * 1024 * 1024, "memory must be 32 MiB, in bytes");
    assert.equal(numberOf(kdf, "I"), 8, "iterations");
    assert.equal(numberOf(kdf, "P"), 2, "parallelism");
  });

  test("the Argon2 engine derives the pinned key for known parameters", async () => {
    // The header assertions above are NOT enough. The header records the parameters we
    // asked for; it is written independently of what the KDF actually consumed. An adapter
    // that mangles the memory unit still produces a vault that encrypts, decrypts and
    // round-trips, with a header advertising 32 MiB while Argon2 ran on 32 KiB — a
    // thousandfold weakening that every other test in this file passes straight through.
    // Only the derived bytes reveal it.
    const derived = await deriveArgon2Key(
      new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer,
      new Uint8Array(16).fill(9).buffer as ArrayBuffer,
      32768, // KiB, exactly as kdbxweb passes it for a 32 MiB header value
      8,
      32,
      2,
      0, // Argon2d
      0x13,
    );

    assert.equal(
      bytesToHex(new Uint8Array(derived)),
      "8ed939b1c25bbff96c83492009cd9eb95b7fcaec057cc0deb007c0807afd45d8",
      "wrong derived key — check the memory unit is passed through as KiB, not converted",
    );
  });
});
