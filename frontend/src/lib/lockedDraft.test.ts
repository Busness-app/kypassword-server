import test from "node:test";
import assert from "node:assert/strict";
import { openDraft, sealDraft } from "./lockedDraft";

test("recovery copy authenticates account, version, draft and binary with the vault key", async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const binary = new Uint8Array([1, 2, 3, 4]).buffer;
  const metadata = { version: 7, dirty: true, entry: { uuid: "entry", title: "unsaved", username: "alice", password: "secret-draft", url: "", notes: "note", totpSeed: "", groupUuid: "group" } };
  const sealed = await sealDraft(binary, metadata, key, "account-a");
  assert.equal(new TextDecoder().decode(sealed.ciphertext).includes("secret-draft"), false);
  assert.deepEqual(await openDraft(sealed, key, "account-a"), { binary, metadata });
  await assert.rejects(openDraft(sealed, key, "account-b"));
  await assert.rejects(openDraft(sealed, new Uint8Array(32), "account-a"));
  new Uint8Array(sealed.ciphertext)[0] ^= 1;
  await assert.rejects(openDraft(sealed, key, "account-a"));
});
