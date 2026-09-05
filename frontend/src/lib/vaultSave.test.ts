import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { VaultSaveQueue, uploadVault, canDiscardVault, type SaveState } from "./vaultSave";
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
  void queue.save();
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
    void queue.save();
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

test("a burst waits for idle and uploads only its final encrypted revision", async (t) => {
  browserCookie(t);
  const key = new Uint8Array(32).fill(3);
  const vault = await KeePassVault.createNew(key);
  const queue = new VaultSaveQueue(vault, 1);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const exporter = t.mock.method(vault, "exportBinary");
  const uploads: ArrayBuffer[] = [];
  t.mock.method(globalThis, "fetch", async (_url: unknown, options: RequestInit) => {
    assert.ok(options.body instanceof ArrayBuffer);
    uploads.push(options.body);
    return Response.json({ metadata: { version: 2 } });
  });
  const done = settled(queue);
  for (let i = 0; i < 3; i++) {
    vault.createEntry({ title: `entry ${i}`, username: "", password: "secret", url: "", notes: "", groupUuid: "" });
    queue.changed();
    t.mock.timers.tick(1000);
    await Promise.resolve();
    assert.equal(exporter.mock.callCount(), 0, "export must wait for an idle window");
  }
  t.mock.timers.tick(1500);
  assert.deepEqual(await done, { kind: "saved", version: 2 });
  assert.equal(uploads.length, 1);
  assert.equal((await KeePassVault.open(uploads[0], key)).getEntries().length, 3);
});

test("security actions proceed in every save state unless the user declines discarding edits", () => {
  for (const state of [
    { kind: "saved", version: 1 },
    { kind: "saving", version: 1 },
    { kind: "error", version: 1, message: "offline" },
  ] satisfies SaveState[]) {
    for (const hasDraft of [false, true]) {
      assert.equal(canDiscardVault(state, hasDraft, () => true), true);
      assert.equal(canDiscardVault(state, hasDraft, () => false), !hasDraft && state.kind === "saved");
    }
  }
});

test("discard cancels a pending autosave and releases the vault", async (t) => {
  browserCookie(t);
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(1));
  const queue = new VaultSaveQueue(vault, 1);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = t.mock.method(globalThis, "fetch", async () => Response.json({ metadata: { version: 2 } }));
  queue.changed();
  queue.discard();
  t.mock.timers.tick(5000);
  queue.changed();
  await queue.save();
  assert.equal(fetch.mock.callCount(), 0);
  await assert.rejects(queue.exportBinary(), /locked/);
});

test("discard aborts a stalled upload and never sends queued revisions or publishes late success", async (t) => {
  browserCookie(t);
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(2));
  const queue = new VaultSaveQueue(vault, 1);
  let started = () => {};
  let release = () => {};
  const uploadStarted = new Promise<void>((resolve) => { started = resolve; });
  const held = new Promise<void>((resolve) => { release = resolve; });
  let signal: AbortSignal | null | undefined;
  const fetch = t.mock.method(globalThis, "fetch", async (_url: unknown, options: RequestInit) => {
    signal = options.signal;
    started();
    // Simulate an accepted request whose success arrives even after client cancellation.
    await held;
    return Response.json({ metadata: { version: 2 } });
  });
  let publications = 0;
  queue.subscribe(() => { publications++; });
  queue.changed();
  const saving = queue.save();
  await uploadStarted;
  queue.changed();
  queue.discard();
  assert.equal(signal?.aborted, true);
  const before = publications;
  release();
  await saving;
  await queue.save();
  assert.equal(publications, before);
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(queue.getSnapshot().version, 1);
});

test("a checkpoint queued before locking finishes encrypted, but a locked queue cannot export or upload", async (t) => {
  const key = new Uint8Array(32).fill(9);
  const vault = await KeePassVault.createNew(key);
  vault.createEntry({ title: "recover me", username: "", password: "unsaved", url: "", notes: "", groupUuid: "" });
  const queue = new VaultSaveQueue(vault, 8);
  const fetch = t.mock.method(globalThis, "fetch", async () => { throw new Error("must not upload"); });
  queue.changed();
  const binary = queue.exportBinary();
  queue.discard();
  const recovered = await KeePassVault.open(await binary, key);
  assert.equal(recovered.getEntries()[0].password, "unsaved");
  await assert.rejects(queue.exportBinary(), /locked/);
  await queue.save();
  assert.equal(fetch.mock.callCount(), 0);
  const restored = new VaultSaveQueue(recovered, 8);
  restored.recoverUnsaved();
  assert.equal(restored.getSnapshot().kind, "error");
  assert.equal(restored.getSnapshot().version, 8);
  restored.discard();
});
