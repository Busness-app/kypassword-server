import assert from "node:assert/strict";
import test from "node:test";
import { IdleDeadline, loadAutoLockMinutes, parseAutoLockMinutes, storeAutoLockMinutes } from "./autoLock";

test("activity extends an unexpired deadline but cannot reopen an expired session", () => {
  const idle = new IdleDeadline(60_000, 100_000, 0);
  assert.equal(idle.activity(159_999, 59_999), true);
  assert.equal(idle.expired(219_998, 119_998), false);
  assert.equal(idle.activity(219_999, 119_999), false);
  assert.equal(idle.expired(219_999, 119_999), true);
});

test("sleep and clock changes cannot extend inactivity", () => {
  const idle = new IdleDeadline(60_000, 100_000, 0);
  assert.equal(idle.expired(160_000, 0), true, "wall clock catches suspension even if the monotonic clock pauses");
  assert.equal(idle.expired(90_000, 60_000), true, "monotonic clock survives a backwards wall-clock adjustment");
});

test("invalid browser preferences fall back to five minutes", () => {
  for (const value of [null, undefined, "0", "-1", "Infinity", "NaN", "3600", {}, 0]) {
    assert.equal(parseAutoLockMinutes(value), 5);
  }
  for (const value of [1, 5, 15, 30, 60]) {
    assert.equal(parseAutoLockMinutes(value), value);
    assert.equal(parseAutoLockMinutes(String(value)), value);
  }
});

test("legacy auto-lock preference survives the settings-key rename", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const values = new Map([["kypassword.autoLockMinutes", "1"]]);
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    },
  });
  try {
    assert.equal(loadAutoLockMinutes(), 1);
    storeAutoLockMinutes(15);
    assert.equal(values.get("kyvault.autoLockMinutes"), "15");
    assert.equal(values.has("kypassword.autoLockMinutes"), false);
  } finally {
    if (original) Object.defineProperty(globalThis, "localStorage", original);
    else delete (globalThis as { localStorage?: unknown }).localStorage;
  }
});

test("cached-key expiry survives a fresh tab and fails closed without a valid timestamp", async () => {
  const { cachedKeyExpired } = await import("./autoLock");
  assert.equal(cachedKeyExpired("1000", 60000, 60999), false);
  assert.equal(cachedKeyExpired("1000", 60000, 61000), true);
  assert.equal(cachedKeyExpired("1000", 60000, 999), true);
  for (const value of [null, "", "0", "-1", "NaN", "Infinity", "broken"]) {
    assert.equal(cachedKeyExpired(value, 60000, 61000), true);
  }
});
