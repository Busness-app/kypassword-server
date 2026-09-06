import { KeePassVault, type VaultEntry } from "./kdbx";

export type CsvProvider =
  | "auto"
  | "chrome"
  | "onepassword"
  | "bitwarden"
  | "lastpass"
  | "dashlane"
  | "generic";

export interface ImportedEntryPreview {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpSeed: string;
  folder: string;
  selected: boolean;
}

export interface CsvParseSummary {
  provider: CsvProvider;
  providerName: string;
  totalRows: number;
  validEntries: ImportedEntryPreview[];
  errors: string[];
  detectedColumns: string[];
}

export const PROVIDER_LABELS: Record<CsvProvider, string> = {
  auto: "Auto-Detect Provider",
  chrome: "Google Chrome / Chromium",
  onepassword: "1Password",
  bitwarden: "Bitwarden",
  lastpass: "LastPass",
  dashlane: "DashPass / Dashlane",
  generic: "Generic CSV",
};

/**
 * Robust RFC 4180 CSV parser supporting quotes, multiline values, escaped quotes (""),
 * UTF-8 BOM, and delimiter detection (, or ; or \t).
 */
export function parseCsvRecords(csvText: string): string[][] {
  if (!csvText) return [];

  // Strip UTF-8 BOM if present
  let cleanText = csvText.charCodeAt(0) === 0xfeff ? csvText.slice(1) : csvText;
  if (!cleanText.trim()) return [];

  // Determine delimiter from first non-empty line
  const firstLine = cleanText.split(/\r\n|\n|\r/)[0] || "";
  let delimiter = ",";
  const commaCount = (firstLine.match(/,/g) || []).length;
  const semiCount = (firstLine.match(/;/g) || []).length;
  const tabCount = (firstLine.match(/\t/g) || []).length;

  if (semiCount > commaCount && semiCount > tabCount) {
    delimiter = ";";
  } else if (tabCount > commaCount && tabCount > semiCount) {
    delimiter = "\t";
  }

  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = "";
  let inQuotes = false;

  for (let i = 0; i < cleanText.length; i++) {
    const char = cleanText[i];
    const nextChar = cleanText[i + 1];

    if (inQuotes) {
      if (char === '"') {
        if (nextChar === '"') {
          // Escaped quote
          currentField += '"';
          i++; // Skip second quote
        } else {
          // End of quoted field
          inQuotes = false;
        }
      } else {
        currentField += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === delimiter) {
        currentRow.push(currentField);
        currentField = "";
      } else if (char === "\r") {
        if (nextChar === "\n") {
          i++; // Skip \n in \r\n
        }
        currentRow.push(currentField);
        currentField = "";
        if (currentRow.some((c) => c.trim().length > 0)) {
          rows.push(currentRow);
        }
        currentRow = [];
      } else if (char === "\n") {
        currentRow.push(currentField);
        currentField = "";
        if (currentRow.some((c) => c.trim().length > 0)) {
          rows.push(currentRow);
        }
        currentRow = [];
      } else {
        currentField += char;
      }
    }
  }

  // Push remainder
  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField);
    if (currentRow.some((c) => c.trim().length > 0)) {
      rows.push(currentRow);
    }
  }

  return rows;
}

/**
 * Normalize header strings by lowercasing and removing symbols
 */
function normalizeHeader(h: string): string {
  return h.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * Detect CSV provider from raw header list
 */
export function detectCsvProvider(rawHeaders: string[]): CsvProvider {
  const headers = rawHeaders.map(normalizeHeader);
  const headerSet = new Set(headers);

  // Bitwarden signature: loginuri, loginusername, loginpassword, logintotp, folder, reprompt
  if (
    headerSet.has("loginuri") ||
    headerSet.has("loginusername") ||
    headerSet.has("loginpassword") ||
    headerSet.has("logintotp")
  ) {
    return "bitwarden";
  }

  // LastPass signature: grouping, fav, extra + (url & password)
  if (
    headerSet.has("grouping") ||
    (headerSet.has("extra") && headerSet.has("url") && (headerSet.has("fav") || headerSet.has("username")))
  ) {
    return "lastpass";
  }

  // Dashlane / DashPass signature: otpsecret, secondaryotpsecret, category + username/login/title
  if (
    headerSet.has("otpsecret") ||
    headerSet.has("secondaryotpsecret") ||
    (headerSet.has("category") && (headerSet.has("username2") || headerSet.has("username3")))
  ) {
    return "dashlane";
  }

  // 1Password signature: otpauth, onetimepassword, otp, or (title & notes & (type | section | folder | otp | password))
  if (
    headerSet.has("otpauth") ||
    headerSet.has("onetimepassword") ||
    headerSet.has("authcode") ||
    (headerSet.has("title") && (headerSet.has("notes") || headerSet.has("folder") || headerSet.has("section") || headerSet.has("type")) && (headerSet.has("otp") || headerSet.has("password") || headerSet.has("username")))
  ) {
    return "onepassword";
  }

  // Chrome signature: name, url, username, password, note (or without note)
  if (
    headerSet.has("name") &&
    headerSet.has("url") &&
    headerSet.has("username") &&
    headerSet.has("password") &&
    !headerSet.has("grouping") &&
    !headerSet.has("loginpassword")
  ) {
    return "chrome";
  }

  // Fallback generic
  return "generic";
}

/**
 * Map a row to an ImportedEntryPreview given detected/selected provider
 */
function mapRowToEntry(
  row: string[],
  headers: string[],
  normalizedHeaders: string[],
  provider: CsvProvider,
  rowIndex: number
): ImportedEntryPreview | null {
  const getField = (keys: string[], trim: boolean): string => {
    for (const key of keys) {
      const normKey = normalizeHeader(key);
      const idx = normalizedHeaders.indexOf(normKey);
      if (idx !== -1 && row[idx] !== undefined) {
        const val = trim ? row[idx].trim() : row[idx];
        if (val) return val;
      }
    }
    return "";
  };

  const getVal = (...keys: string[]) => getField(keys, true);
  const getPassword = (...keys: string[]) => getField(keys, false);

  let title = "";
  let username = "";
  let password = "";
  let url = "";
  let notes = "";
  let totpSeed = "";
  let folder = "";

  switch (provider) {
    case "chrome": {
      title = getVal("name", "title", "url");
      url = getVal("url");
      username = getVal("username", "user", "login");
      password = getPassword("password", "pass");
      notes = getVal("note", "notes");
      break;
    }

    case "onepassword": {
      title = getVal("title", "name", "url", "website");
      url = getVal("url", "website", "login_url");
      username = getVal("username", "user", "login", "email");
      password = getPassword("password", "pass");
      notes = getVal("notes", "note", "description");
      totpSeed = getVal("otpauth", "onetimepassword", "otp", "authcode");
      folder = getVal("folder", "section", "vault", "category");
      break;
    }

    case "bitwarden": {
      title = getVal("name", "title");
      url = getVal("loginuri", "login_uri", "uri", "url");
      username = getVal("loginusername", "login_username", "username");
      password = getPassword("loginpassword", "login_password", "password");
      notes = getVal("notes", "note");
      totpSeed = getVal("logintotp", "login_totp", "totp", "otp");
      folder = getVal("folder", "group");
      
      const customFields = getVal("fields");
      if (customFields) {
        notes = notes ? `${notes}\n\n[Custom Fields]\n${customFields}` : `[Custom Fields]\n${customFields}`;
      }
      break;
    }

    case "lastpass": {
      title = getVal("name", "title");
      url = getVal("url");
      username = getVal("username", "login");
      password = getPassword("password");
      notes = getVal("extra", "note", "notes");
      totpSeed = getVal("totp", "otp");
      folder = getVal("grouping", "group", "folder");

      // LastPass Secure Notes often use http://sn as placeholder URL
      if (url === "http://sn" || url === "https://sn") {
        url = "";
      }
      break;
    }

    case "dashlane": {
      title = getVal("title", "name");
      url = getVal("url", "website");
      username = getVal("username", "login", "username2", "username3", "email");
      password = getPassword("password");
      notes = getVal("note", "notes");
      totpSeed = getVal("otpsecret", "secondaryotpsecret", "otp");
      folder = getVal("category", "folder", "group");
      break;
    }

    case "generic":
    default: {
      title = getVal("title", "name", "sitename", "site", "account", "label", "service", "system");
      url = getVal("url", "website", "uri", "loginuri", "link", "webpage", "host");
      username = getVal("username", "login", "user", "email", "loginusername", "accountname");
      password = getPassword("password", "pass", "loginpassword", "secret", "pwd");
      notes = getVal("notes", "note", "extra", "comments", "description", "memo");
      totpSeed = getVal("totp", "logintotp", "otp", "otpauth", "onetimepassword", "otpsecret");
      folder = getVal("folder", "group", "grouping", "category", "section", "collection");
      break;
    }
  }

  // If title is missing but URL or username exists, fallback
  if (!title) {
    if (url) {
      try {
        const parsedUrl = new URL(url.startsWith("http") ? url : `https://${url}`);
        title = parsedUrl.hostname.replace(/^www\./, "");
      } catch {
        title = url;
      }
    } else if (username) {
      title = username;
    } else if (password || notes) {
      title = `Account #${rowIndex + 1}`;
    } else {
      // Entirely empty entry
      return null;
    }
  }

  return {
    id: `import-${rowIndex}-${Math.random().toString(36).slice(2, 7)}`,
    title,
    username,
    password,
    url,
    notes,
    totpSeed,
    folder,
    selected: true,
  };
}

/**
 * Parse CSV text into a structured summary with previews and auto-detection
 */
export function parseAndPreviewCsv(
  csvText: string,
  preferredProvider: CsvProvider = "auto"
): CsvParseSummary {
  const rows = parseCsvRecords(csvText);
  if (rows.length === 0) {
    return {
      provider: preferredProvider,
      providerName: PROVIDER_LABELS[preferredProvider] || "CSV",
      totalRows: 0,
      validEntries: [],
      errors: ["The provided CSV is empty."],
      detectedColumns: [],
    };
  }

  const rawHeaders = rows[0];
  const normalizedHeaders = rawHeaders.map(normalizeHeader);

  const effectiveProvider =
    preferredProvider === "auto" ? detectCsvProvider(rawHeaders) : preferredProvider;

  const dataRows = rows.slice(1);
  const validEntries: ImportedEntryPreview[] = [];
  const errors: string[] = [];

  for (let i = 0; i < dataRows.length; i++) {
    const row = dataRows[i];
    // Skip empty lines
    if (row.length === 0 || row.every((c) => !c.trim())) {
      continue;
    }

    try {
      const entry = mapRowToEntry(row, rawHeaders, normalizedHeaders, effectiveProvider, i);
      if (entry) {
        validEntries.push(entry);
      }
    } catch (err: any) {
      errors.push(`Row ${i + 2}: ${err.message || String(err)}`);
    }
  }

  return {
    provider: effectiveProvider,
    providerName: PROVIDER_LABELS[effectiveProvider],
    totalRows: dataRows.length,
    validEntries,
    errors,
    detectedColumns: rawHeaders,
  };
}

/**
 * Split a provider folder value into path segments. Bitwarden nests with "/",
 * LastPass with a backslash; both map onto KeePass subgroups.
 */
function splitFolderPath(folder: string): string[] {
  return folder
    .split(/[/\\]/)
    .map((seg) => seg.trim())
    .filter(Boolean);
}

// Compare all CSV-supported content exactly, across folders. Never collapse changed
// passwords, notes or TOTP secrets into an older entry. These keys stay in memory only.
function importContentKey(entry: Pick<VaultEntry, "title" | "username" | "password" | "url" | "notes" | "totpSeed">): string {
  return JSON.stringify([entry.title, entry.username, entry.password, entry.url, entry.notes, entry.totpSeed || ""]);
}

export function findDuplicateImports(vault: KeePassVault, entries: ImportedEntryPreview[]): Set<string> {
  const seen = new Set(vault.getLiveEntries().map(importContentKey));
  const duplicates = new Set<string>();
  for (const entry of entries) {
    const key = importContentKey({ ...entry, title: entry.title || "Untitled" });
    if (seen.has(key)) duplicates.add(entry.id);
    if (entry.selected) seen.add(key);
  }
  return duplicates;
}

/**
 * Apply selected imported entries into a KeePassVault instance
 */
export function applyImportToVault(
  vault: KeePassVault,
  entries: ImportedEntryPreview[],
  options: {
    folderMode: "csv_folders" | "single_folder";
    targetFolderUuid?: string;
    defaultFolderName?: string;
    skipDuplicates?: boolean;
    newFolderName?: string;
  }
): { importedCount: number; skippedDuplicates: number; foldersCreated: string[] } {
  const duplicates = options.skipDuplicates !== false ? findDuplicateImports(vault, entries) : new Set<string>();
  const selected = entries.filter(item => item.selected);
  const pending = selected.filter(item => !duplicates.has(item.id));
  const skippedDuplicates = selected.length - pending.length;
  if (pending.length === 0) return { importedCount: 0, skippedDuplicates, foldersCreated: [] };
  const existingGroups = vault.getLiveGroups();
  const rootUuid = existingGroups[0]?.uuid || "";

  // Lowercase folder path ("work/projects") -> group uuid, so repeated segments
  // across rows reuse one subgroup. getLiveGroups() is pre-order, so parents land first.
  const pathByUuid = new Map<string, string>([[rootUuid, ""]]);
  const groupMap = new Map<string, string>();
  for (const g of existingGroups) {
    if (g.uuid === rootUuid) continue;
    const parentPath = pathByUuid.get(g.parentUuid || "") ?? "";
    const name = g.name.toLowerCase().trim();
    const path = parentPath ? `${parentPath}/${name}` : name;
    pathByUuid.set(g.uuid, path);
    groupMap.set(path, g.uuid);
  }

  const foldersCreated: string[] = [];

  const getOrCreateGroup = (folder: string): string => {
    let parentUuid = rootUuid;
    let path = "";
    for (const segment of splitFolderPath(folder)) {
      path = path ? `${path}/${segment.toLowerCase()}` : segment.toLowerCase();
      const existing = groupMap.get(path);
      if (existing) {
        parentUuid = existing;
        continue;
      }
      const created = vault.createGroup(segment, parentUuid);
      groupMap.set(path, created.uuid);
      foldersCreated.push(segment);
      parentUuid = created.uuid;
    }
    return parentUuid;
  };

  let importedCount = 0;
  let singleFolderUuid = options.targetFolderUuid || rootUuid;
  if (options.folderMode === "single_folder" && options.newFolderName?.trim()) {
    const name = options.newFolderName.trim();
    singleFolderUuid = vault.createGroup(name).uuid;
    foldersCreated.push(name);
  }

  for (const item of pending) {

    const targetGroupUuid =
      options.folderMode === "single_folder"
        ? singleFolderUuid
        : getOrCreateGroup(item.folder || options.defaultFolderName || "");

    vault.createEntry({
      title: item.title || "Untitled",
      username: item.username,
      password: item.password,
      url: item.url,
      notes: item.notes,
      totpSeed: item.totpSeed || undefined,
      groupUuid: targetGroupUuid,
    });

    importedCount++;
  }

  return { importedCount, skippedDuplicates, foldersCreated };
}
