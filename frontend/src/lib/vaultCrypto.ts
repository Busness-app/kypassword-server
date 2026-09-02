// Client-side Zero-Knowledge Key Derivation and Envelope Wrapping using Web Crypto API

export type WrappedEnvelope = {
  salt: string;       // Hex encoded 16 bytes
  iv: string;         // Hex encoded 12 bytes
  ciphertext: string; // Hex encoded AES-GCM ciphertext + tag
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

// Wrap vault master key into an encrypted envelope using password or recovery secret
export async function wrapVaultKey(vaultKey: Uint8Array, secret: string, iterations = 600000): Promise<string> {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    wrappingKey,
    vaultKey as BufferSource
  );

  const envelope: WrappedEnvelope = {
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(encrypted)),
    iterations,
  };

  return JSON.stringify(envelope);
}

// Unwrap vault master key from an encrypted envelope
export async function unwrapVaultKey(envelopeJSON: string, secret: string): Promise<Uint8Array> {
  const envelope: WrappedEnvelope = JSON.parse(envelopeJSON);
  const salt = hexToBytes(envelope.salt);
  const iv = hexToBytes(envelope.iv);
  const ciphertext = hexToBytes(envelope.ciphertext);

  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: envelope.iterations || 600000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    wrappingKey,
    ciphertext as BufferSource
  );

  return new Uint8Array(decrypted);
}
