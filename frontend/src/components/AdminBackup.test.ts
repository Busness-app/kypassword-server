import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { BackupDepositResult } from "./AdminBackup";

test("partial backup renders an alert and preserves the successful destination", () => {
  for (const reply of [
    { result: { local_path: "/copies/example.kycap" }, warning: "Remote deposit failed" },
    { result: { local_error: "Local copy failed" } },
  ]) {
    const html = renderToStaticMarkup(createElement(BackupDepositResult, { reply }));
    assert.match(html, /role="alert"/);
    assert.match(html, /var\(--danger\)/);
    assert.doesNotMatch(html, /check-circle/);
    if ("warning" in reply) assert.match(html, /\/copies\/example.kycap/);
  }
  const html = renderToStaticMarkup(createElement(BackupDepositResult, { reply: { result: { local_path: "/copies/example.kycap" } } }));
  assert.match(html, /role="status"/);
});
