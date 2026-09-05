import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { VaultSaveQueue, uploadVault, type SaveState } from "./vaultSave";
import { KeePassVault } from "./kdbx";

function settled(queue: VaultSaveQueue): Promise<SaveState> {
  return new Promise((resolve) => {
    const unsubscribe = queue.subscribe(() => {
      if (queue.getSnapshot().kind !== "saving") {
        unsubscribe();
        resolve(queue.getSnapshot());
      }
    });
  });
}

// Browser cookie input only; encryption and queue execution use the real implementations.
function browserCookie(t: TestContext) {
  Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "csrf_token=test-csrf" } });
  t.after(() => { Reflect.deleteProperty(globalThis, "document"); });
}

test("edits during upload are serialized with the acknowledged version and remain encrypted", async (t) => {
  browserCookie(t);
  const key = new Uint8Array(32).fill(7);
  const vault = await KeePassVault.createNew(key);
  const queue = new VaultSaveQueue(vault, 4);
  let signalStarted = () => {};
  let releaseUpload = () => {};
  const started = new Promise<void>((resolve) => { signalStarted = resolve; });
  const release = new Promise<void>((resolve) => { releaseUpload = resolve; });
  const uploads: ArrayBuffer[] = [];
  t.mock.method(globalThis, "fetch", async (_url: string | URL | Request, options: RequestInit) => {
    const headers = new Headers(options.headers);
    assert.equal(headers.get("X-CSRF-Token"), "test-csrf");
    assert.equal(headers.get("If-Match"), `"${4 + uploads.length}"`);
    assert.ok(options.body instanceof ArrayBuffer);
    uploads.push(options.body);
    if (uploads.length === 1) { signalStarted(); await release; }
    return Response.json({ metadata: { version: 4 + uploads.length } });
  });
  vault.createEntry({ title: "first", username: "", password: "secret-one", url: "", notes: "", groupUuid: "" });
  const done = settled(queue);
  queue.changed();
  await started;
  vault.createEntry({ title: "second", username: "", password: "secret-two", url: "", notes: "", groupUuid: "" });
  queue.changed();
  assert.equal(uploads.length, 1);
  assert.equal(queue.getSnapshot().kind, "saving");
  releaseUpload();
  assert.deepEqual(await done, { kind: "saved", version: 6 });
  assert.equal(uploads.length, 2);
  assert.equal((await KeePassVault.open(uploads[0], key)).getEntries().length, 1);
  assert.equal((await KeePassVault.open(uploads[1], key)).getEntries().length, 2);
  assert.equal(Buffer.from(uploads[1]).includes(Buffer.from("secret-two")), false);
});

for (const failure of ["conflict", "server", "network", "unconfirmed"] as const) {
  test(`${failure} keeps edits unsaved until an explicit successful retry`, async (t) => {
    browserCookie(t);
    const vault = await KeePassVault.createNew(new Uint8Array(32).fill(9));
    const queue = new VaultSaveQueue(vault, 2);
    let attempts = 0;
    let fail = true;
    t.mock.method(globalThis, "fetch", async () => {
      attempts++;
      if (!fail) return Response.json({ metadata: { version: 3 } });
      if (failure === "network") throw new TypeError("Network unavailable");
      if (failure === "unconfirmed") return Response.json({ ok: true });
      return new Response("failed", { status: failure === "conflict" ? 409 : 500 });
    });
    const done = settled(queue);
    queue.changed();
    const result = await done;
    assert.equal(result.kind, "error");
    assert.equal(result.version, 2);
    queue.changed();
    assert.equal(attempts, 1, "editing after failure must not create an automatic retry loop");
    fail = false;
    await queue.save();
    assert.deepEqual(queue.getSnapshot(), { kind: "saved", version: 3 });
    assert.equal(attempts, 2);
  });
}

test("initial upload uses CSRF, version zero and the password envelope", async (t) => {
  browserCookie(t);
  t.mock.method(globalThis, "fetch", async (_url: string | URL | Request, options: RequestInit) => {
    const headers = new Headers(options.headers);
    assert.equal(headers.get("If-Match"), '"0"');
    assert.equal(headers.get("X-Password-Envelope"), "wrapped-key");
    assert.equal(headers.get("X-CSRF-Token"), "test-csrf");
    return Response.json({ metadata: { version: 1 } });
  });
  assert.equal(await uploadVault(new ArrayBuffer(8), 0, "wrapped-key"), 1);
});
