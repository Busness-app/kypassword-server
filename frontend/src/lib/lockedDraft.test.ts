import test from "node:test";
import assert from "node:assert/strict";
import { openDraft, sealDraft } from "./lockedDraft";

test("recovery copy authenticates account, version, draft and binary with the vault key", async (t) => {
  let metadataBytes: Uint8Array | undefined;
  const encode = TextEncoder.prototype.encode;
  t.mock.method(TextEncoder.prototype, "encode", function (this: TextEncoder, input?: string) {
    const bytes = encode.call(this, input);
    if (input?.includes("secret-draft")) metadataBytes = bytes;
    return bytes;
  });
  const key = crypto.getRandomValues(new Uint8Array(32));
  const binary = new Uint8Array([1, 2, 3, 4]).buffer;
  const metadata = { version: 7, dirty: true, entry: { uuid: "entry", title: "unsaved", username: "alice", password: "secret-draft", url: "", notes: "note", totpSeed: "", groupUuid: "group" } };
  const sealed = await sealDraft(binary, metadata, key, "account-a");
  assert.ok(metadataBytes?.every(byte => byte === 0), "serialized password draft is wiped");
  assert.equal(new TextDecoder().decode(sealed.ciphertext).includes("secret-draft"), false);
  assert.deepEqual(await openDraft(sealed, key, "account-a"), { binary, metadata });
  await assert.rejects(openDraft(sealed, key, "account-b"));
  await assert.rejects(openDraft(sealed, new Uint8Array(32), "account-a"));
  new Uint8Array(sealed.ciphertext)[0] ^= 1;
  await assert.rejects(openDraft(sealed, key, "account-a"));
});

test("recovery storage outages resolve as degraded results rather than aborting unlock", async (t) => {
  const { readDraft, removeDraft } = await import("./lockedDraft");
  const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {
    open() { throw new DOMException("Site storage denied", "SecurityError"); },
  } });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "indexedDB", previous);
    else Reflect.deleteProperty(globalThis, "indexedDB");
  });
  assert.deepEqual(await readDraft("account:checkpoint"), { kind: "unavailable" });
  assert.equal(await removeDraft("account:checkpoint"), false);
  assert.deepEqual(await readDraft(undefined), { kind: "available", draft: undefined });
});
