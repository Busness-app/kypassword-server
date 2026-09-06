import type { VaultEntry } from "./kdbx";

export const comparisonFields = [
  ["title", "Title"], ["username", "Username"], ["password", "Password"],
  ["url", "Website"], ["notes", "Notes"], ["totpSeed", "TOTP"],
] as const;

// UUID comparison follows the shared entry identity; names and passwords are not identities.
export function compareConflictEntries(current: VaultEntry[], conflict: VaultEntry[]) {
  const byId = new Map(current.map(entry => [entry.uuid, entry]));
  return conflict.map(entry => {
    const existing = byId.get(entry.uuid);
    const changedFields = comparisonFields.filter(([key]) => (entry[key] || "") !== (existing?.[key] || ""));
    return { entry, current: existing, changedFields };
  });
}
