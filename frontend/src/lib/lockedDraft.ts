// A per-tab encrypted checkpoint. It never contains a password or a vault key.
export type EntryDraft = {
  uuid: string; title: string; username: string; password: string;
  url: string; notes: string; totpSeed: string; groupUuid: string;
};
export type DraftMetadata = { version: number; dirty: boolean; entry: EntryDraft | null };
export type LockedDraft = { iv: Uint8Array<ArrayBuffer>; ciphertext: ArrayBuffer };

export async function sealDraft(binary: ArrayBuffer, metadata: DraftMetadata, key: Uint8Array, account: string): Promise<LockedDraft> {
  const json = new TextEncoder().encode(JSON.stringify(metadata));
  const plain = new Uint8Array(4 + json.length + binary.byteLength);
  new DataView(plain.buffer).setUint32(0, json.length);
  plain.set(json, 4);
  plain.set(new Uint8Array(binary), 4 + json.length);
  const cryptoKey = await crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(account) }, cryptoKey, plain);
  plain.fill(0);
  return { iv, ciphertext };
}

export async function openDraft(draft: LockedDraft, key: Uint8Array, account: string): Promise<{ binary: ArrayBuffer; metadata: DraftMetadata }> {
  const cryptoKey = await crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: draft.iv, additionalData: new TextEncoder().encode(account) }, cryptoKey, draft.ciphertext);
  const length = new DataView(plain).getUint32(0);
  if (length > plain.byteLength - 4) throw new Error("Invalid recovery copy");
  const metadata: unknown = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + length)));
  if (typeof metadata !== "object" || metadata === null || !("version" in metadata) || typeof metadata.version !== "number" ||
      !Number.isSafeInteger(metadata.version) || metadata.version < 1 || !("dirty" in metadata) || typeof metadata.dirty !== "boolean" ||
      !("entry" in metadata) || !isEntryDraft(metadata.entry)) throw new Error("Invalid recovery copy");
  return { binary: plain.slice(4 + length), metadata: { version: metadata.version, dirty: metadata.dirty, entry: metadata.entry } };
}

function isEntryDraft(value: unknown): value is EntryDraft | null {
  if (value === null) return true;
  return typeof value === "object" && "uuid" in value && typeof value.uuid === "string" &&
    "title" in value && typeof value.title === "string" && "username" in value && typeof value.username === "string" &&
    "password" in value && typeof value.password === "string" && "url" in value && typeof value.url === "string" &&
    "notes" in value && typeof value.notes === "string" && "totpSeed" in value && typeof value.totpSeed === "string" &&
    "groupUuid" in value && typeof value.groupUuid === "string";
}

// Separate database preserves compatibility with older clients opening the device-key DB.
export async function draftStore(id: string, operation: "get" | "put" | "delete", value?: LockedDraft): Promise<LockedDraft | undefined> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("kypassword-locked-drafts", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("drafts");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction("drafts", operation === "get" ? "readonly" : "readwrite");
      const store = tx.objectStore("drafts");
      const request = operation === "get" ? store.get(id) : operation === "put" ? store.put(value, id) : store.delete(id);
      tx.oncomplete = () => resolve(operation === "get" ? request.result : undefined);
      tx.onabort = () => reject(tx.error ?? new Error("Recovery storage failed"));
      tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}
