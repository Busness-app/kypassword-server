import * as kdbxweb from "kdbxweb";
import { bytesToHex } from "./vaultCrypto";
import { argon2d, argon2i, argon2id } from "hash-wasm";
// kdbxweb's UMD bundle defeats Node's CJS export lexer; classes arrive under `default`.
const { CryptoEngine, Credentials, ProtectedValue, Kdbx, KdbxBinaries, KdbxError, KdbxUuid, Consts, VarDictionary, Int64 } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

// KyAuth's KDBX vaults are Argon2d, so opening or writing one needs an Argon2 engine.
// hash-wasm rather than argon2-browser because it runs under Node too — argon2-browser
// resolves its WASM by URL and dies outside a browser, which left every Argon2 path in
// this file untestable.
// Exported only so a test can pin it. Getting the memory unit wrong here weakens every
// vault by a factor of a thousand while leaving encryption, decryption and every
// round-trip working perfectly — the header still advertises the strong parameters,
// because the header is written independently of what the KDF actually consumed. Nothing
// short of checking the derived bytes catches that, hence the pinned-key test in kdbx.test.ts.
export async function deriveArgon2Key(
  password: ArrayBuffer,
  salt: ArrayBuffer,
  memory: number,
  iterations: number,
  length: number,
  parallelism: number,
  type: number,
  _version: number
): Promise<ArrayBuffer> {
  const options = {
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    parallelism,
    iterations,
    // kdbxweb passes memory in KiB and hash-wasm's memorySize is KiB, so this is a
    // straight hand-off. Do not "convert" it.
    memorySize: memory,
    hashLength: length,
    outputType: "binary" as const,
  };
  // KDBX header type values: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id.
  const hash =
    type === 0 ? await argon2d(options) : type === 2 ? await argon2id(options) : await argon2i(options);
  return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength) as ArrayBuffer;
}

CryptoEngine.setArgon2Impl(deriveArgon2Key);

// KyAuth writes its vaults with kotpass's Ver4x defaults. Matching them exactly is what
// lets either client open the other's vault, and lets a downloaded file open in KeePassXC.
const KOTPASS_ARGON2 = { memoryBytes: 32 * 1024 * 1024, iterations: 8, parallelism: 2 };
export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;

export type VaultEntry = {
  uuid: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpSeed?: string;
  groupUuid: string;
  updatedAt: Date;
};

export type VaultGroup = {
  uuid: string;
  name: string;
  parentUuid?: string;
  entriesCount: number;
};

function entryFieldText(entry: kdbxweb.KdbxEntry, name: string): string {
  const value = entry.fields.get(name);
  return typeof value === "string" ? value : value?.getText() ?? "";
}

export class KeePassVault {
  private db: kdbxweb.Kdbx;
  private credentials: kdbxweb.Credentials;

  private constructor(db: kdbxweb.Kdbx, credentials: kdbxweb.Credentials) {
    this.db = db;
    this.credentials = credentials;
  }

  // The credential is the vault key written as hexadecimal text, not the raw bytes.
  // Both facts matter: it is what KyAuth uses, so either client opens the other's vault,
  // and it is something a person can type into KeePassXC — which raw bytes are not, so a
  // binary-keyed vault has no offline recovery path at all.
  private static credentialFor(vaultKey: Uint8Array): kdbxweb.Credentials {
    return new Credentials(ProtectedValue.fromString(bytesToHex(vaultKey)));
  }

  // Create a new blank KDBX v4 vault encrypted with the random 256-bit vaultKey
  public static async createNew(vaultKey: Uint8Array, vaultName = "KyPasswords Vault"): Promise<KeePassVault> {
    const cred = KeePassVault.credentialFor(vaultKey);
    const db = Kdbx.create(cred, vaultName);

    // Argon2d with kotpass's Ver4x defaults, so our vaults and KyAuth's are the same kind
    // of file. The parameters are set explicitly because kdbxweb's Argon2 defaults are far
    // weaker (1 MiB, t=2, p=1) than kotpass's.
    db.header.setKdf(Consts.KdfId.Argon2d);
    const kdf = db.header.kdfParameters!;
    kdf.set("M", VarDictionary.ValueType.UInt64, Int64.from(KOTPASS_ARGON2.memoryBytes));
    kdf.set("I", VarDictionary.ValueType.UInt64, Int64.from(KOTPASS_ARGON2.iterations));
    kdf.set("P", VarDictionary.ValueType.UInt32, KOTPASS_ARGON2.parallelism);

    // Create standard default folders
    const root = db.getDefaultGroup();
    db.createGroup(root, "General");
    db.createGroup(root, "Personal");
    db.createGroup(root, "Work");
    db.createGroup(root, "Finance");

    return new KeePassVault(db, cred);
  }

  // Older web clients wrote binary-key credentials. Read those after a hex-key mismatch,
  // then use the portable hex credential on the next explicit save/export.
  public static async open(buffer: ArrayBuffer, vaultKey: Uint8Array): Promise<KeePassVault> {
    const cred = KeePassVault.credentialFor(vaultKey);
    try {
      return new KeePassVault(await Kdbx.load(buffer, cred), cred);
    } catch (err) {
      if (!(err instanceof KdbxError) || err.code !== Consts.ErrorCodes.InvalidKey) throw err;
      const legacy = new Credentials(ProtectedValue.fromBinary(vaultKey.slice().buffer));
      const db = await Kdbx.load(buffer, legacy);
      db.credentials = cred;
      return new KeePassVault(db, cred);
    }
  }

  // Copy the full native entry, including history, binaries and unknown fields.
  // A new UUID avoids replacing a newer edit or reviving a current tombstone.
  public recoverEntryCopy(source: KeePassVault, uuid: string): string {
    const entry = source.findEntry(uuid);
    if (!entry?.parentGroup || source.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Select a live entry from the conflict.");
    }
    const destination = this.db.getDefaultGroup();
    if (this.recycledGroupIds().has(destination.uuid.toString())) throw new Error("No live vault folder is available.");
    // kdbxweb imports icons by UUID. Preserve current icons when another client reused
    // the UUID with different data; give the recovered copy its own icon identity.
    const existingIcons = new Map(this.db.meta.customIcons);
    const copy = this.db.importEntry(entry, destination, source.db);
    const importedIcons = new Map<string, kdbxweb.KdbxUuid>();
    for (const item of [copy, ...copy.history]) {
      const iconId = item.customIcon?.toString();
      if (!iconId || !existingIcons.has(iconId)) continue;
      const icon = source.db.meta.customIcons.get(iconId);
      if (!icon) continue;
      let newId = importedIcons.get(iconId);
      if (!newId) {
        newId = KdbxUuid.random();
        importedIcons.set(iconId, newId);
        this.db.meta.customIcons.set(newId.toString(), icon);
      }
      item.customIcon = newId;
    }
    for (const [id, icon] of existingIcons) this.db.meta.customIcons.set(id, icon);
    const title = `${entryFieldText(entry, "Title") || "Untitled"} (recovered)`;
    copy.fields.set("Title", entry.fields.get("Title") instanceof ProtectedValue ? ProtectedValue.fromString(title) : title);
    return copy.uuid.toString();
  }

  // Export/Save the vault back into encrypted KDBX v4 ArrayBuffer
  public async exportBinary(): Promise<ArrayBuffer> {
    // Keep binaries referenced by live/recycled entries or their retained history.
    this.db.cleanup({ binaries: true });
    return this.db.save();
  }

  // List all Groups
  public getGroups(): VaultGroup[] {
    const groups: VaultGroup[] = [];
    
    const traverse = (g: kdbxweb.KdbxGroup, parentUuid?: string) => {
      const uuid = g.uuid.toString();
      groups.push({
        uuid,
        name: g.name || "Folder",
        parentUuid,
        entriesCount: g.entries.length,
      });

      for (const child of g.groups) {
        traverse(child, uuid);
      }
    };

    traverse(this.db.getDefaultGroup());
    return groups;
  }

  // List all Entries across all groups (or filter by group)
  public getEntries(groupUuid?: string): VaultEntry[] {
    const entries: VaultEntry[] = [];
    const all = this.db.getDefaultGroup().allEntries();

    for (const e of all) {
      const gUuid = e.parentGroup?.uuid.toString() || "";
      if (groupUuid && gUuid !== groupUuid && groupUuid !== "all") {
        continue;
      }

      const title = entryFieldText(e, "Title");
      const username = entryFieldText(e, "UserName");
      const password = entryFieldText(e, "Password");
      const url = entryFieldText(e, "URL");
      const notes = entryFieldText(e, "Notes");
      const otp = entryFieldText(e, "otp") || entryFieldText(e, "TOTP");

      entries.push({
        uuid: e.uuid.toString(),
        title,
        username,
        password,
        url,
        notes,
        totpSeed: otp,
        groupUuid: gUuid,
        updatedAt: e.times.lastModTime || new Date(),
      });
    }

    return entries;
  }

  private recycledGroupIds(): Set<string> {
    const recycleBin = this.db.meta.recycleBinUuid ? this.db.getGroup(this.db.meta.recycleBinUuid) : undefined;
    return new Set(recycleBin ? [...recycleBin.allGroups()].map(group => group.uuid.toString()) : []);
  }

  public getLiveEntries(): VaultEntry[] {
    const recycled = this.recycledGroupIds();
    return this.getEntries().filter(entry => !recycled.has(entry.groupUuid));
  }

  public getRecycledEntries(): VaultEntry[] {
    const recycled = this.recycledGroupIds();
    return this.getEntries().filter(entry => recycled.has(entry.groupUuid));
  }

  public getLiveGroups(): VaultGroup[] {
    const recycled = this.recycledGroupIds();
    return this.getGroups().filter(group => !recycled.has(group.uuid));
  }

  public getEntryHistory(uuid: string) {
    return (this.findEntry(uuid)?.history ?? []).map((entry, index) => ({
      index, updatedAt: entry.times.lastModTime,
    })).reverse();
  }

  public getAttachments(uuid: string) {
    return [...(this.findEntry(uuid)?.binaries ?? [])].map(([name, binary]) => {
      const value = "hash" in binary ? binary.value : binary;
      return { name, sizeBytes: value.byteLength };
    });
  }

  public getAttachment(uuid: string, name: string): ArrayBuffer {
    const binary = this.findEntry(uuid)?.binaries.get(name);
    if (!binary) throw new Error("This attachment is no longer available.");
    const value = "hash" in binary ? binary.value : binary;
    return value instanceof ProtectedValue ? value.getBinary().slice().buffer : value.slice(0);
  }

  public async addAttachment(uuid: string, name: string, data: ArrayBuffer, signal: AbortSignal): Promise<void> {
    if (!name.trim() || /[\u0000-\u001f\u007f]/.test(name)) throw new Error("Choose a file with a valid name.");
    if (data.byteLength > MAX_ATTACHMENT_BYTES) throw new Error("Attachments must be 10 MiB or smaller.");
    signal.throwIfAborted();
    // Hash outside the live database so lock/navigation cannot leave a late mutation.
    const binary = await new KdbxBinaries().add(data.slice(0));
    signal.throwIfAborted();
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Choose an entry in the live vault.");
    }
    if (entry.binaries.has(name)) throw new Error("An attachment with this name already exists. Rename the file before adding it.");
    this.pushEntryHistory(entry);
    this.db.binaries.addWithHash(binary);
    entry.binaries.set(name, binary);
    entry.times.update();
  }

  public removeAttachment(uuid: string, name: string): boolean {
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Choose an entry in the live vault.");
    }
    if (!entry.binaries.has(name)) return false;
    this.pushEntryHistory(entry);
    entry.binaries.delete(name);
    entry.times.update();
    // History and other entries may still reference these bytes.
    return true;
  }

  public getEntryHistoryVersion(uuid: string, index: number) {
    const entry = Number.isSafeInteger(index) ? this.findEntry(uuid)?.history[index] : undefined;
    if (!entry) throw new Error("This entry version is no longer available.");
    return {
      fields: [...entry.fields].map(([name, value]) => ({
        name,
        value: typeof value === "string" ? value : value.getText(),
        protected: value instanceof ProtectedValue || /^(password|otp|totp)$/i.test(name),
      })),
      attachments: [...entry.binaries.keys()],
    };
  }

  public get entryHistoryEnabled(): boolean {
    return this.db.meta.historyMaxItems !== 0 && this.db.meta.historyMaxSize !== 0;
  }

  private pushEntryHistory(entry: kdbxweb.KdbxEntry): void {
    if (!this.entryHistoryEnabled) return;
    entry.pushHistory();
    const snapshot = entry.history[entry.history.length - 1];
    // kdbxweb's copyFrom (also used by pushHistory) omits these native properties.
    if (snapshot) {
      snapshot.customData = structuredClone(entry.customData);
      snapshot.qualityCheck = entry.qualityCheck;
      snapshot.previousParentGroup = entry.previousParentGroup;
    }
    const limit = this.db.meta.historyMaxItems ?? 10;
    // ponytail: match kdbxweb's count-based history rules; byte-budget pruning needs
    // native historyMaxSize support before we can enforce it without guessing sizes.
    if (limit >= 0 && entry.history.length > limit) entry.removeHistory(0, entry.history.length - limit);
  }

  public restoreEntryVersion(uuid: string, index: number): void {
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Restore the entry to the live vault before restoring a version.");
    }
    const version = Number.isSafeInteger(index) ? entry.history[index] : undefined;
    if (!version) throw new Error("This entry version is no longer available.");
    if (!this.entryHistoryEnabled) throw new Error("Entry history is disabled for this vault; the current version cannot be preserved.");
    const identity = entry.uuid;
    const locationChanged = entry.times.locationChanged;
    const previousParentGroup = entry.previousParentGroup;
    // Capture the version before pruning; the selected version may be the oldest.
    this.pushEntryHistory(entry);
    entry.copyFrom(version);
    entry.customData = structuredClone(version.customData);
    entry.qualityCheck = version.qualityCheck;
    entry.uuid = identity;
    entry.previousParentGroup = previousParentGroup;
    entry.times.locationChanged = locationChanged;
    entry.times.update();
  }

  public restoreEntry(uuid: string): void {
    const entry = this.findEntry(uuid);
    const recycled = this.recycledGroupIds();
    if (!entry?.parentGroup || !recycled.has(entry.parentGroup.uuid.toString())) {
      throw new Error("This entry is not in the recycle bin.");
    }
    const destination = this.db.getDefaultGroup();
    if (recycled.has(destination.uuid.toString())) throw new Error("No live vault folder is available.");
    this.db.move(entry, destination);
    entry.times.update();
  }

  // Create a new entry in a group
  public createEntry(entry: Omit<VaultEntry, "uuid" | "updatedAt">): VaultEntry {
    let targetGroup = this.db.getDefaultGroup();
    if (entry.groupUuid) {
      const found = this.findGroup(entry.groupUuid);
      if (found) targetGroup = found;
    }

    const e = this.db.createEntry(targetGroup);
    e.fields.set("Title", entry.title);
    e.fields.set("UserName", entry.username);
    e.fields.set("Password", ProtectedValue.fromString(entry.password));
    e.fields.set("URL", entry.url);
    e.fields.set("Notes", entry.notes);
    if (entry.totpSeed) {
      e.fields.set("otp", entry.totpSeed);
    }

    return {
      uuid: e.uuid.toString(),
      title: entry.title,
      username: entry.username,
      password: entry.password,
      url: entry.url,
      notes: entry.notes,
      totpSeed: entry.totpSeed,
      groupUuid: targetGroup.uuid.toString(),
      updatedAt: new Date(),
    };
  }

  // Update an existing entry
  public updateEntry(entry: VaultEntry): boolean {
    const e = this.findEntry(entry.uuid);
    if (!e) return false;

    if (entryFieldText(e, "Title") === entry.title && entryFieldText(e, "UserName") === entry.username &&
        entryFieldText(e, "Password") === entry.password && entryFieldText(e, "URL") === entry.url &&
        entryFieldText(e, "Notes") === entry.notes &&
        (entryFieldText(e, "otp") || entryFieldText(e, "TOTP")) === (entry.totpSeed || "") &&
        (!entry.groupUuid || e.parentGroup?.uuid.toString() === entry.groupUuid)) return false;
    this.pushEntryHistory(e);

    const setField = (name: string, value: string) => e.fields.set(name,
      name === "Password" || e.fields.get(name) instanceof ProtectedValue ? ProtectedValue.fromString(value) : value);
    setField("Title", entry.title);
    setField("UserName", entry.username);
    setField("Password", entry.password);
    setField("URL", entry.url);
    setField("Notes", entry.notes);
    if (entry.totpSeed) {
      setField(e.fields.has("otp") || !e.fields.has("TOTP") ? "otp" : "TOTP", entry.totpSeed);
    } else {
      e.fields.delete("otp");
      e.fields.delete("TOTP");
    }

    if (entry.groupUuid && e.parentGroup?.uuid.toString() !== entry.groupUuid) {
      const targetGroup = this.findGroup(entry.groupUuid);
      if (targetGroup) {
        this.db.move(e, targetGroup);
      }
    }

    e.times.update();
    return true;
  }

  public get recyclingEnabled(): boolean {
    return this.db.meta.recycleBinEnabled !== false;
  }

  // Delete an entry
  public deleteEntry(uuid: string): void {
    const e = this.findEntry(uuid);
    if (e) {
      // Preserve the imported file’s explicit retention policy.
      if (e.parentGroup && this.recycledGroupIds().has(e.parentGroup.uuid.toString())) return;
      if (this.recyclingEnabled) this.db.createRecycleBin();
      this.db.remove(e);
    }
  }

  // Create a group
  public createGroup(name: string, parentUuid?: string): VaultGroup {
    let parent = this.db.getDefaultGroup();
    if (parentUuid) {
      const found = this.findGroup(parentUuid);
      if (found) parent = found;
    }

    const g = this.db.createGroup(parent, name);
    return {
      uuid: g.uuid.toString(),
      name: g.name || name,
      parentUuid: parent.uuid.toString(),
      entriesCount: 0,
    };
  }

  private findEntry(uuid: string): kdbxweb.KdbxEntry | undefined {
    for (const e of this.db.getDefaultGroup().allEntries()) {
      if (e.uuid.toString() === uuid) {
        return e;
      }
    }
    return undefined;
  }

  private findGroup(uuid: string): kdbxweb.KdbxGroup | undefined {
    const search = (g: kdbxweb.KdbxGroup): kdbxweb.KdbxGroup | undefined => {
      if (g.uuid.toString() === uuid) return g;
      for (const child of g.groups) {
        const res = search(child);
        if (res) return res;
      }
      return undefined;
    };
    return search(this.db.getDefaultGroup());
  }
}
