import type { KeePassVault } from "./kdbx";

// Return entry IDs and counts only; passwords never leave this comparison.
export function findReusedPasswords(vault: KeePassVault): Map<string, number> {
  const byPassword = new Map<string, string[]>();
  for (const entry of vault.getLiveEntries()) {
    if (entry.password === "") continue;
    const ids = byPassword.get(entry.password);
    if (ids) ids.push(entry.uuid);
    else byPassword.set(entry.password, [entry.uuid]);
  }
  const reused = new Map<string, number>();
  for (const ids of byPassword.values()) {
    if (ids.length > 1) for (const id of ids) reused.set(id, ids.length);
  }
  return reused;
}
