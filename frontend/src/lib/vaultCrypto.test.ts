import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  wrapVaultKey,
  unwrapVaultKey,
  deriveEnvelopeKey,
  ENVELOPE_ARGON2ID,
  bytesToHex,
  hexToBytes,
  generateVaultMasterKey,
} from "./vaultCrypto.js";

const key = () => {
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i++) k[i] = (i * 11 + 5) & 0xff;
  return k;
};

describe("vault key envelope", () => {
  test("a wrapped key comes back out", async () => {
    const vaultKey = key();
    const envelope = await wrapVaultKey(vaultKey, "correct horse battery staple");
    assert.deepEqual(await unwrapVaultKey(envelope, "correct horse battery staple"), vaultKey);
  });

  test("the wrong password does not yield the key", async () => {
    const envelope = await wrapVaultKey(key(), "right");
    await assert.rejects(() => unwrapVaultKey(envelope, "wrong"));
  });

  test("each wrap uses a fresh salt and iv", async () => {
    const a = JSON.parse(await wrapVaultKey(key(), "pw"));
    const b = JSON.parse(await wrapVaultKey(key(), "pw"));
    assert.notEqual(a.salt, b.salt, "salt must not be reused across envelopes");
    assert.notEqual(a.iv, b.iv, "iv must not be reused under the same derived key");
  });

  test("the envelope carries its own KDF and parameters", async () => {
    // Self-describing, so parameters can be raised later without guessing what produced
    // an old envelope, and so KyAuth can dispatch on something explicit.
    const envelope = JSON.parse(await wrapVaultKey(key(), "pw"));
    assert.equal(envelope.kdf, "argon2id");
    assert.equal(envelope.memoryKiB, ENVELOPE_ARGON2ID.memoryKiB);
    assert.equal(envelope.iterations, ENVELOPE_ARGON2ID.iterations);
    assert.equal(envelope.parallelism, ENVELOPE_ARGON2ID.parallelism);
  });

  test("the envelope contains nothing that reveals the password or the key", async () => {
    const vaultKey = key();
    const envelope = await wrapVaultKey(vaultKey, "hunter2");
    assert.ok(!envelope.includes("hunter2"), "the password must not appear in the envelope");
    assert.ok(!envelope.includes(bytesToHex(vaultKey)), "the vault key must not appear in the envelope");
  });

  test("a tampered ciphertext is rejected rather than yielding a wrong key", async () => {
    // AES-GCM authenticates; without the tag check a flipped bit would silently produce
    // a corrupt vault key and an unopenable vault.
    const envelope = JSON.parse(await wrapVaultKey(key(), "pw"));
    const bytes = hexToBytes(envelope.ciphertext);
    bytes[0] ^= 0xff;
    envelope.ciphertext = bytesToHex(bytes);
    await assert.rejects(() => unwrapVaultKey(JSON.stringify(envelope), "pw"));
  });

  test("generateVaultMasterKey returns 32 unpredictable bytes", () => {
    const a = generateVaultMasterKey();
    const b = generateVaultMasterKey();
    assert.equal(a.length, 32);
    assert.notDeepEqual(a, b);
  });
});

describe("envelope key derivation is pinned", () => {
  test("known inputs derive the known key", async () => {
    // The parameter assertions above only prove what we WROTE into the envelope. They
    // cannot prove what Argon2 actually consumed — the same class of bug as the kdbxweb
    // memory-unit trap, where a mangled unit still round-trips perfectly and the recorded
    // parameters still look right. Only the derived bytes settle it.
    const derived = await deriveEnvelopeKey("correct horse battery staple", new Uint8Array(16).fill(3), {
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
    });

    assert.equal(
      bytesToHex(derived),
      "73eb74162616418d643f08dc0856539ea61400cb268f85ce8df01d8257795b8d",
      "wrong derived key — memoryKiB must be passed through as KiB, not converted",
    );
  });

  test("every parameter changes the derived key", async () => {
    const base = { memoryKiB: 8192, iterations: 2, parallelism: 1 };
    const salt = new Uint8Array(16).fill(3);
    const ref = bytesToHex(await deriveEnvelopeKey("pw", salt, base));

    assert.notEqual(ref, bytesToHex(await deriveEnvelopeKey("pX", salt, base)));
    assert.notEqual(ref, bytesToHex(await deriveEnvelopeKey("pw", new Uint8Array(16).fill(4), base)));
    assert.notEqual(ref, bytesToHex(await deriveEnvelopeKey("pw", salt, { ...base, memoryKiB: 16384 })));
    assert.notEqual(ref, bytesToHex(await deriveEnvelopeKey("pw", salt, { ...base, iterations: 3 })));
    assert.notEqual(ref, bytesToHex(await deriveEnvelopeKey("pw", salt, { ...base, parallelism: 2 })));
  });
});

describe("KyAuth compatibility", () => {
  test("still reads a legacy PBKDF2 envelope", async () => {
    // KyAuth's KyPasswordEnvelopeCrypto still writes PBKDF2-HMAC-SHA256 envelopes, so we
    // must keep reading them until it ships the Argon2id change. An envelope with no
    // `kdf` field is PBKDF2 by definition. Delete this path only once KyAuth no longer
    // writes them.
    const vaultKey = key();
    const legacy = await wrapLegacyPbkdf2(vaultKey, "legacy-secret");
    assert.deepEqual(await unwrapVaultKey(legacy, "legacy-secret"), vaultKey);
  });
});

// Builds a PBKDF2 envelope exactly as the previous implementation (and KyAuth) does.
async function wrapLegacyPbkdf2(vaultKey: Uint8Array, secret: string): Promise<string> {
  const salt = new Uint8Array(16).fill(2);
  const iv = new Uint8Array(12).fill(4);
  const iterations = 600000;

  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "PBKDF2" }, false, [
    "deriveKey",
  ]);
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    wrappingKey,
    vaultKey as BufferSource,
  );

  return JSON.stringify({
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(encrypted)),
    iterations,
  });
}
