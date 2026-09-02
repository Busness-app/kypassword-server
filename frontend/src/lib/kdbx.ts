import * as kdbxweb from "kdbxweb";
import { bytesToHex } from "./vaultCrypto";
import { argon2d, argon2i, argon2id } from "hash-wasm";
// kdbxweb's UMD bundle defeats Node's CJS export lexer; classes arrive under `default`.
const { CryptoEngine, Credentials, ProtectedValue, Kdbx, Consts, VarDictionary, Int64 } =
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
  attachments?: { name: string; data: ArrayBuffer }[];
};

export type VaultGroup = {
  uuid: string;
  name: string;
  parentUuid?: string;
  entriesCount: number;
};

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

  // Open an existing encrypted KDBX v4 binary with the random vaultKey.
  //
  // One credential form, deliberately. An earlier build keyed vaults on the raw bytes and
  // fell back to the hexadecimal form, but a failed attempt is not free: it runs the full
  // KDF before reporting the wrong key, so with Argon2d at 32 MiB every unlock would pay
  // an extra derivation. Both clients write hexadecimal now, so there is nothing to fall
  // back to.
  public static async open(buffer: ArrayBuffer, vaultKey: Uint8Array): Promise<KeePassVault> {
    const cred = KeePassVault.credentialFor(vaultKey);
    return new KeePassVault(await Kdbx.load(buffer, cred), cred);
  }

  // Export/Save the vault back into encrypted KDBX v4 ArrayBuffer
  public async exportBinary(): Promise<ArrayBuffer> {
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

      const title = e.fields.get("Title")?.toString() || "";
      const username = e.fields.get("UserName")?.toString() || "";
      
      let password = "";
      const pwField = e.fields.get("Password");
      if (pwField instanceof ProtectedValue) {
        password = pwField.getText();
      } else if (typeof pwField === "string") {
        password = pwField;
      }

      const url = e.fields.get("URL")?.toString() || "";
      const notes = e.fields.get("Notes")?.toString() || "";
      const otp = e.fields.get("otp")?.toString() || e.fields.get("TOTP")?.toString() || "";

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
  public updateEntry(entry: VaultEntry): void {
    const e = this.findEntry(entry.uuid);
    if (!e) return;

    e.fields.set("Title", entry.title);
    e.fields.set("UserName", entry.username);
    e.fields.set("Password", ProtectedValue.fromString(entry.password));
    e.fields.set("URL", entry.url);
    e.fields.set("Notes", entry.notes);
    if (entry.totpSeed) {
      e.fields.set("otp", entry.totpSeed);
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
  }

  // Delete an entry
  public deleteEntry(uuid: string): void {
    const e = this.findEntry(uuid);
    if (e) {
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
