// Client-side zero-knowledge key derivation and envelope wrapping.
//
// The envelope is the one place in this system where a human-chosen secret is stretched.
// Everything else is keyed on a 256-bit random vault key, where the KDF barely matters;
// here it is the whole defence. The envelope is stored server-side, so anyone who obtains
// a backup can attack the master password offline for as long as they like — which is why
// this uses a memory-hard KDF rather than a faster one.
import { argon2id } from "hash-wasm";

// OWASP's Argon2id guidance. Memory is the parameter that actually denies GPUs and ASICs:
// PBKDF2-SHA256 is tiny and parallel, so a rig sustains billions of guesses a second,
// whereas 64 MiB per guess caps a 24 GB card at a few hundred concurrent attempts.
// Parallelism is 1 because Argon2 in WASM is effectively single-threaded in a browser.
export const ENVELOPE_ARGON2ID = { memoryKiB: 65536, iterations: 3, parallelism: 1 } as const;

export type Argon2idParams = {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
};

export type WrappedEnvelope = {
  kdf: "argon2id";
  salt: string;       // Hex encoded 16 bytes
  iv: string;         // Hex encoded 12 bytes
  ciphertext: string; // Hex encoded AES-GCM ciphertext + tag
  memoryKiB: number;
  iterations: number;
  parallelism: number;
};

// An envelope written before the Argon2id change, and what KyAuth's
// KyPasswordEnvelopeCrypto still produces today. No `kdf` field means PBKDF2-HMAC-SHA256.
type LegacyPbkdf2Envelope = {
  kdf?: undefined;
  salt: string;
  iv: string;
  ciphertext: string;
  iterations: number;
};

// Generate a fresh 256-bit random vault master key.
export function generateVaultMasterKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

// Convert bytes to Hex string
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Convert Hex string to bytes
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// There is deliberately no deriveAuthSecret here any more. It produced a password-derived
// verifier for the login endpoint, and the login endpoint is gone: the master password is
// key material for the envelope below and is never transmitted in any form.

// Derive the AES-GCM wrapping key from a human secret.
//
// Exported so a test can pin it. The parameters recorded in an envelope are written
// independently of what Argon2 actually consumed, so they cannot prove the derivation was
// strong — a mangled memory unit produces a perfectly working envelope that took a
// thousandth of the intended work. Only the derived bytes reveal that, hence the pinned
// vector in vaultCrypto.test.ts.
export async function deriveEnvelopeKey(
  secret: string,
  salt: Uint8Array,
  params: Argon2idParams
): Promise<Uint8Array> {
  return argon2id({
    password: secret,
    salt,
    // hash-wasm's memorySize is KiB, and memoryKiB is KiB. Straight hand-off; do not convert.
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
}

async function aesGcmKey(raw: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, [usage]);
}

// Wrap vault master key into an encrypted envelope using password or recovery secret
export async function wrapVaultKey(vaultKey: Uint8Array, secret: string): Promise<string> {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const derived = await deriveEnvelopeKey(secret, salt, ENVELOPE_ARGON2ID);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    await aesGcmKey(derived, "encrypt"),
    vaultKey as BufferSource
  );

  const envelope: WrappedEnvelope = {
    kdf: "argon2id",
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(encrypted)),
    ...ENVELOPE_ARGON2ID,
  };

  return JSON.stringify(envelope);
}

// Unwrap vault master key from an encrypted envelope.
//
// Reads both shapes. The Argon2id envelope is what we write; the PBKDF2 one is what older
// envelopes and KyAuth's current KyPasswordEnvelopeCrypto contain. Dropping the PBKDF2
// path would mean a vault uploaded by an un-updated KyAuth could not be opened here at
// all, so it stays until KyAuth writes Argon2id too.
export async function unwrapVaultKey(envelopeJSON: string, secret: string): Promise<Uint8Array> {
  const envelope: WrappedEnvelope | LegacyPbkdf2Envelope = JSON.parse(envelopeJSON);
  const salt = hexToBytes(envelope.salt);
  const iv = hexToBytes(envelope.iv);
  const ciphertext = hexToBytes(envelope.ciphertext);

  const derived =
    envelope.kdf === "argon2id"
      ? await deriveEnvelopeKey(secret, salt, envelope)
      : await derivePbkdf2Key(secret, salt, envelope.iterations || 600000);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    await aesGcmKey(derived, "decrypt"),
    ciphertext as BufferSource
  );

  return new Uint8Array(decrypted);
}

async function derivePbkdf2Key(secret: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}
