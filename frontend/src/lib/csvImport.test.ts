import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  parseCsvRecords,
  detectCsvProvider,
  parseAndPreviewCsv,
  applyImportToVault,
  findDuplicateImports,
} from "./csvImport.js";
import { KeePassVault } from "./kdbx.js";

describe("CSV Import & Multi-Provider Detection", () => {
  test("RFC 4180 CSV parser handles quotes, newlines, escaped quotes and delimiters", () => {
    const raw = `name,url,username,password,note
"Google, Inc.","https://google.com","user@gmail.com","p@ss""word","Line 1
Line 2 with ""quotes"" and , commas"
"GitHub","https://github.com","octocat","token123","Simple note"`;

    const records = parseCsvRecords(raw);
    assert.equal(records.length, 3);
    assert.deepEqual(records[0], ["name", "url", "username", "password", "note"]);
    assert.equal(records[1][0], "Google, Inc.");
    assert.equal(records[1][3], 'p@ss"word');
    assert.equal(records[1][4], 'Line 1\nLine 2 with "quotes" and , commas');
    assert.equal(records[2][0], "GitHub");
  });

  test("Parser handles UTF-8 BOM and semicolon delimiters", () => {
    const raw = `\uFEFFname;url;username;password;note
Netflix;https://netflix.com;user@mail.com;secret123;Stream`;

    const records = parseCsvRecords(raw);
    assert.equal(records.length, 2);
    assert.equal(records[0][0], "name");
    assert.equal(records[1][0], "Netflix");
    assert.equal(records[1][3], "secret123");
  });

  test("Google Chrome CSV import & detection", () => {
    const chromeCsv = `name,url,username,password,note
Amazon,https://amazon.com,shopper@gmail.com,prime123,Prime account
Slack,https://slack.com,worker@company.com,slackpass,`;

    const summary = parseAndPreviewCsv(chromeCsv);
    assert.equal(summary.provider, "chrome");
    assert.equal(summary.validEntries.length, 2);
    assert.equal(summary.validEntries[0].title, "Amazon");
    assert.equal(summary.validEntries[0].username, "shopper@gmail.com");
    assert.equal(summary.validEntries[0].password, "prime123");
    assert.equal(summary.validEntries[0].notes, "Prime account");
    assert.equal(summary.validEntries[1].title, "Slack");
  });

  test("1Password CSV import & detection with OTP and sections", () => {
    const opCsv = `Title,URL,Username,Password,Notes,OTP,Folder
ProtonMail,https://proton.me,user@proton.me,proton_secret,Secure mail,otpauth://totp/Proton:user?secret=JBSWY3DPEHPK3PXP,Personal
AWS Console,https://aws.amazon.com,root,aws_master,Cloud root,JBSWY3DPEHPK3PXP,Work`;

    const summary = parseAndPreviewCsv(opCsv);
    assert.equal(summary.provider, "onepassword");
    assert.equal(summary.validEntries.length, 2);
    assert.equal(summary.validEntries[0].title, "ProtonMail");
    assert.equal(summary.validEntries[0].totpSeed, "otpauth://totp/Proton:user?secret=JBSWY3DPEHPK3PXP");
    assert.equal(summary.validEntries[0].folder, "Personal");
    assert.equal(summary.validEntries[1].folder, "Work");
  });

  test("Bitwarden CSV import & detection with custom fields and TOTP", () => {
    const bwCsv = `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Finance,1,login,Chase Bank,Banking portal,Pin: 1234,0,https://chase.com,chase_user,chase_pass,TOTPSECRET123`;

    const summary = parseAndPreviewCsv(bwCsv);
    assert.equal(summary.provider, "bitwarden");
    assert.equal(summary.validEntries.length, 1);
    const entry = summary.validEntries[0];
    assert.equal(entry.title, "Chase Bank");
    assert.equal(entry.url, "https://chase.com");
    assert.equal(entry.username, "chase_user");
    assert.equal(entry.password, "chase_pass");
    assert.equal(entry.totpSeed, "TOTPSECRET123");
    assert.equal(entry.folder, "Finance");
    assert.match(entry.notes, /Pin: 1234/);
  });

  test("LastPass CSV import & detection with secure note handling", () => {
    const lpCsv = `url,username,password,totp,extra,name,grouping,fav
https://reddit.com,redditor,redditpass,REDDIT2FA,Favorite subreddits,Reddit,Social,1
http://sn,,,,"Server SSH Key: ssh-rsa AAA...",Production SSH Key,Servers,0`;

    const summary = parseAndPreviewCsv(lpCsv);
    assert.equal(summary.provider, "lastpass");
    assert.equal(summary.validEntries.length, 2);

    const entry1 = summary.validEntries[0];
    assert.equal(entry1.title, "Reddit");
    assert.equal(entry1.url, "https://reddit.com");
    assert.equal(entry1.totpSeed, "REDDIT2FA");
    assert.equal(entry1.folder, "Social");

    const entry2 = summary.validEntries[1];
    assert.equal(entry2.title, "Production SSH Key");
    assert.equal(entry2.url, ""); // Cleared http://sn placeholder
    assert.equal(entry2.notes, "Server SSH Key: ssh-rsa AAA...");
    assert.equal(entry2.folder, "Servers");
  });

  test("DashPass / Dashlane CSV import & detection", () => {
    const dlCsv = `title,url,username,password,note,category,otpSecret
Spotify,https://spotify.com,musiclover,spotipass,Family plan,Media,DASH2FASECRET
GitHub,https://github.com,dashuser,ghpass,,Dev,GHTOTPSECRET`;

    const summary = parseAndPreviewCsv(dlCsv);
    assert.equal(summary.provider, "dashlane");
    assert.equal(summary.validEntries.length, 2);
    assert.equal(summary.validEntries[0].title, "Spotify");
    assert.equal(summary.validEntries[0].folder, "Media");
    assert.equal(summary.validEntries[0].totpSeed, "DASH2FASECRET");
    assert.equal(summary.validEntries[1].title, "GitHub");
    assert.equal(summary.validEntries[1].folder, "Dev");
  });

  test("Generic CSV format with URL hostname title derivation", () => {
    const genericCsv = `website,user,pass,description
https://sub.domain.example.com/login,admin,admin123,Internal portal`;

    const summary = parseAndPreviewCsv(genericCsv, "generic");
    assert.equal(summary.validEntries.length, 1);
    assert.equal(summary.validEntries[0].title, "sub.domain.example.com");
    assert.equal(summary.validEntries[0].username, "admin");
    assert.equal(summary.validEntries[0].password, "admin123");
  });

  test("Applying imported entries into KeePassVault creates groups and entries", async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i + 1;

    const vault = await KeePassVault.createNew(key, "Test Vault");

    const entries = [
      {
        id: "1",
        title: "Test Entry 1",
        username: "user1",
        password: "pw1",
        url: "https://site1.com",
        notes: "Notes 1",
        totpSeed: "OTP1",
        folder: "Imported Work",
        selected: true,
      },
      {
        id: "2",
        title: "Test Entry 2",
        username: "user2",
        password: "pw2",
        url: "https://site2.com",
        notes: "Notes 2",
        totpSeed: "",
        folder: "Personal", // Existing default folder
        selected: true,
      },
      {
        id: "3",
        title: "Skipped Entry",
        username: "skip",
        password: "skip",
        url: "",
        notes: "",
        totpSeed: "",
        folder: "",
        selected: false,
      },
    ];

    const res = applyImportToVault(vault, entries, { folderMode: "csv_folders" });
    assert.equal(res.importedCount, 2);
    assert.ok(res.foldersCreated.includes("Imported Work"));

    const allEntries = vault.getEntries();
    assert.equal(allEntries.length, 2);

    const imported1 = allEntries.find((e) => e.title === "Test Entry 1");
    assert.ok(imported1);
    assert.equal(imported1.username, "user1");
    assert.equal(imported1.password, "pw1");
    assert.equal(imported1.totpSeed, "OTP1");
  });

  test("Nested provider folder paths become nested KeePass groups", async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i + 1;
    const vault = await KeePassVault.createNew(key, "Test Vault");

    const make = (title: string, folder: string) => ({
      id: title,
      title,
      username: "u",
      password: "p",
      url: "",
      notes: "",
      totpSeed: "",
      folder,
      selected: true,
    });

    const res = applyImportToVault(
      vault,
      [
        make("Bitwarden style", "Work/Projects"),
        make("LastPass style", "Work\\Projects"), // same path, backslash separator
        make("Deeper", "Work/Projects/Alpha"),
        make("Under existing", "Personal/Banking"),
      ],
      { folderMode: "csv_folders" }
    );

    assert.equal(res.importedCount, 4);
    // "Work" and "Personal" ship as default groups, so only the leaves are new
    // and "Projects" is created once despite three rows referencing it.
    assert.deepEqual(res.foldersCreated, ["Projects", "Alpha", "Banking"]);

    const groups = vault.getGroups();
    const byName = (n: string) => groups.filter((g) => g.name === n);
    assert.equal(byName("Projects").length, 1);

    const work = byName("Work")[0];
    const projects = byName("Projects")[0];
    const alpha = byName("Alpha")[0];
    const personal = byName("Personal")[0];
    const banking = byName("Banking")[0];
    assert.equal(projects.parentUuid, work.uuid);
    assert.equal(alpha.parentUuid, projects.uuid);
    assert.equal(banking.parentUuid, personal.uuid);

    // Both separator styles land in the same group.
    assert.equal(vault.getEntries(projects.uuid).length, 2);
    assert.equal(vault.getEntries(alpha.uuid).length, 1);
  });

  test("Entries without a CSV folder fall back to defaultFolderName", async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i + 1;
    const vault = await KeePassVault.createNew(key, "Test Vault");

    const res = applyImportToVault(
      vault,
      [
        {
          id: "1",
          title: "Loose Entry",
          username: "u",
          password: "p",
          url: "",
          notes: "",
          totpSeed: "",
          folder: "",
          selected: true,
        },
      ],
      { folderMode: "csv_folders", defaultFolderName: "Imported Passwords" }
    );

    assert.equal(res.importedCount, 1);
    assert.deepEqual(res.foldersCreated, ["Imported Passwords"]);
    const target = vault.getGroups().find((g) => g.name === "Imported Passwords");
    assert.ok(target);
    assert.equal(vault.getEntries(target.uuid).length, 1);
  });
});


test("CSV duplicates are skipped across folders and rows, with explicit opt-out", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(7));
  const row = { id: "one", title: "Example", username: "user", password: "p", url: "https://example.test", notes: "n", totpSeed: "OTP", folder: "First", selected: true };
  const rows = [row, { ...row, id: "two", folder: "Second" }];
  assert.deepEqual([...findDuplicateImports(vault, rows)], ["two"]);
  const first = applyImportToVault(vault, rows, { folderMode: "csv_folders" });
  assert.equal(first.importedCount, 1);
  assert.equal(first.skippedDuplicates, 1);
  assert.deepEqual(first.foldersCreated, ["First"]);
  const before = vault.getGroups().length;
  assert.deepEqual(applyImportToVault(vault, rows, { folderMode: "single_folder", newFolderName: "Must not be created" }),
    { importedCount: 0, skippedDuplicates: 2, foldersCreated: [] });
  assert.equal(vault.getGroups().length, before);
  assert.equal(vault.getEntries().length, 1);
  const kept = applyImportToVault(vault, rows, { folderMode: "single_folder", newFolderName: "Intentional copies", skipDuplicates: false });
  assert.equal(kept.importedCount, 2);
  assert.equal(kept.skippedDuplicates, 0);
  assert.deepEqual(kept.foldersCreated, ["Intentional copies"]);
});

test("duplicate selection ignores unchecked rows and preserves every changed content field", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(8));
  const row = { id: "one", title: "Example", username: "user", password: "p", url: "https://example.test", notes: "n", totpSeed: "OTP", folder: "", selected: true };
  assert.deepEqual([...findDuplicateImports(vault, [{ ...row, selected: false }, { ...row, id: "two" }])], []);
  applyImportToVault(vault, [row], { folderMode: "csv_folders" });
  const changes = ["title", "username", "password", "url", "notes", "totpSeed"].map(field => ({ ...row, id: field, [field]: "changed" }));
  assert.equal(findDuplicateImports(vault, changes).size, 0);
  assert.equal(applyImportToVault(vault, changes, { folderMode: "csv_folders" }).importedCount, 6);
  const blank = { ...row, id: "blank", title: "" };
  vault.createEntry({ ...row, title: "", groupUuid: vault.getGroups()[0].uuid });
  assert.equal(findDuplicateImports(vault, [blank]).size, 0, "empty existing title is not the imported Untitled fallback");
  applyImportToVault(vault, [blank], { folderMode: "csv_folders" });
  assert.equal(findDuplicateImports(vault, [blank]).size, 1);
});


test("password whitespace stays significant during parsing and duplicate detection", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(9));
  const csv = "name,url,username,password,note\nExample,https://example.test,user,secret,n\nExample,https://example.test,user, secret ,n\nExample,https://example.test,user,   ,n";
  const rows = parseAndPreviewCsv(csv, "chrome").validEntries;
  assert.deepEqual(rows.map(row => row.password), ["secret", " secret ", "   "]);
  assert.equal(applyImportToVault(vault, rows, { folderMode: "csv_folders" }).importedCount, 3);
  assert.equal(applyImportToVault(vault, rows, { folderMode: "csv_folders" }).skippedDuplicates, 3);
});
