import * as kdbxweb from "kdbxweb";

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

  // Create a new blank KDBX v4 vault encrypted with the random 256-bit vaultKey
  public static async createNew(vaultKey: Uint8Array, vaultName = "KyPasswords Vault"): Promise<KeePassVault> {
    const keyBuf = vaultKey.buffer.slice(vaultKey.byteOffset, vaultKey.byteOffset + vaultKey.byteLength) as ArrayBuffer;
    const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromBinary(keyBuf));
    const db = kdbxweb.Kdbx.create(cred, vaultName);
    // ponytail: use native WebCrypto AES-KDF to avoid missing Argon2 WASM engine
    db.header.setKdf(kdbxweb.Consts.KdfId.Aes);
    
    // Create standard default folders
    const root = db.getDefaultGroup();
    db.createGroup(root, "General");
    db.createGroup(root, "Personal");
    db.createGroup(root, "Work");
    db.createGroup(root, "Finance");

    return new KeePassVault(db, cred);
  }

  // Open an existing encrypted KDBX v4 binary with the random vaultKey
  public static async open(buffer: ArrayBuffer, vaultKey: Uint8Array): Promise<KeePassVault> {
    const keyBuf = vaultKey.buffer.slice(vaultKey.byteOffset, vaultKey.byteOffset + vaultKey.byteLength) as ArrayBuffer;
    const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromBinary(keyBuf));
    const db = await kdbxweb.Kdbx.load(buffer, cred);
    return new KeePassVault(db, cred);
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
      if (pwField instanceof kdbxweb.ProtectedValue) {
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
    e.fields.set("Password", kdbxweb.ProtectedValue.fromString(entry.password));
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
    e.fields.set("Password", kdbxweb.ProtectedValue.fromString(entry.password));
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
