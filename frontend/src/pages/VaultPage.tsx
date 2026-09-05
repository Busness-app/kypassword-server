import React, { useState, useEffect, useMemo } from "react";
import { KeePassVault, VaultEntry, VaultGroup } from "../lib/kdbx";
import type { SaveState } from "../lib/vaultSave";
import { generateTOTP } from "../lib/totp";
import { PasswordGenerator } from "../components/PasswordGenerator";
import { DevicePairingModal } from "../components/DevicePairingModal";
import { HistoryModal } from "../components/HistoryModal";
import { CsvImportModal } from "../components/CsvImportModal";
import {
  Folder,
  Plus,
  Search,
  Key,
  Copy,
  Eye,
  EyeOff,
  ExternalLink,
  Trash2,
  Save,
  Download,
  History,
  QrCode,
  Check,
  Clock,
  Shield,
  RefreshCw,
  FileSpreadsheet,
  CheckCircle2,
} from "lucide-react";

type Props = {
  vault: KeePassVault;
  vaultVersion: number;
  saveState: SaveState;
  onChanged: () => void;
  onDraftChange: (dirty: boolean) => void;
  hidden: boolean;
  onSave: () => Promise<void>;
  onExport: () => void;
  onReload: () => Promise<void>;
};

export function VaultPage({ vault, vaultVersion, onSave, onExport, onReload, saveState, onChanged, onDraftChange, hidden }: Props) {
  const [groups, setGroups] = useState<VaultGroup[]>([]);
  const [selectedGroupUuid, setSelectedGroupUuid] = useState<string>("all");
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [selectedEntryUuid, setSelectedEntryUuid] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  // Editor State
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState("");
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const [editTotp, setEditTotp] = useState("");
  const [editGroupUuid, setEditGroupUuid] = useState("");

  // UI Modals & Helpers
  const [showGenerator, setShowGenerator] = useState(false);
  const [showPairing, setShowPairing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showCsvImport, setShowCsvImport] = useState(false);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const [revealPassword, setRevealPassword] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const saving = saveState.kind === "saving";

  // TOTP live state
  const [totpCode, setTotpCode] = useState<string | null>(null);
  const [totpRemaining, setTotpRemaining] = useState<number>(30);

  const refreshVaultData = () => {
    const grps = vault.getGroups();
    const ents = vault.getEntries();
    setGroups(grps);
    setEntries(ents);
    if (!selectedEntryUuid && ents.length > 0) {
      setSelectedEntryUuid(ents[0].uuid);
    }
  };

  useEffect(() => {
    refreshVaultData();
  }, [vault]);

  const selectedEntry = useMemo(() => {
    return entries.find((e) => e.uuid === selectedEntryUuid) || null;
  }, [entries, selectedEntryUuid]);

  const draftDirty = isEditing && selectedEntry !== null && (
    editTitle !== selectedEntry.title || editUsername !== selectedEntry.username ||
    editPassword !== selectedEntry.password || editUrl !== selectedEntry.url ||
    editNotes !== selectedEntry.notes || editTotp !== (selectedEntry.totpSeed || "") ||
    editGroupUuid !== selectedEntry.groupUuid
  );
  useEffect(() => { onDraftChange(draftDirty); }, [draftDirty, onDraftChange]);
  const canChangeEntry = () => !draftDirty || confirm("Discard unapplied entry edits?");

  // Load selected entry into editor
  const loadEditor = () => {
    if (selectedEntry) {
      setEditTitle(selectedEntry.title);
      setEditUsername(selectedEntry.username);
      setEditPassword(selectedEntry.password);
      setEditUrl(selectedEntry.url);
      setEditNotes(selectedEntry.notes);
      setEditTotp(selectedEntry.totpSeed || "");
      setEditGroupUuid(selectedEntry.groupUuid);
      setRevealPassword(false);
    }
  };
  useEffect(loadEditor, [vault, selectedEntry?.uuid]);

  // Live TOTP ticker
  useEffect(() => {
    if (!selectedEntry?.totpSeed) {
      setTotpCode(null);
      return;
    }

    let active = true;
    const update = async () => {
      if (!selectedEntry.totpSeed) return;
      const res = await generateTOTP(selectedEntry.totpSeed);
      if (active) {
        setTotpCode(res.code);
        setTotpRemaining(res.secondsRemaining);
      }
    };

    update();
    const interval = setInterval(update, 1000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [selectedEntry?.totpSeed]);

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleSaveEntry = () => {
    if (!selectedEntryUuid) return;
    vault.updateEntry({
      uuid: selectedEntryUuid,
      title: editTitle,
      username: editUsername,
      password: editPassword,
      url: editUrl,
      notes: editNotes,
      totpSeed: editTotp,
      groupUuid: editGroupUuid,
      updatedAt: new Date(),
    });
    onChanged();
    setIsEditing(false);
    refreshVaultData();
  };

  const handleCreateNewEntry = () => {
    if (!canChangeEntry()) return;
    const newEntry = vault.createEntry({
      title: "New Account",
      username: "",
      password: "",
      url: "",
      notes: "",
      groupUuid: selectedGroupUuid === "all" ? groups[0]?.uuid || "" : selectedGroupUuid,
    });
    onChanged();
    refreshVaultData();
    setSelectedEntryUuid(newEntry.uuid);
    setIsEditing(true);
  };

  const handleDeleteEntry = () => {
    if (!selectedEntryUuid || !confirm("Are you sure you want to delete this entry?")) return;
    vault.deleteEntry(selectedEntryUuid);
    onChanged();
    setSelectedEntryUuid(null);
    refreshVaultData();
  };

  const handleCreateGroup = () => {
    const name = prompt("Enter folder / group name:");
    if (!name) return;
    vault.createGroup(name.trim());
    onChanged();
    refreshVaultData();
  };

  const filteredEntries = useMemo(() => {
    return entries.filter((e) => {
      const matchesGroup =
        selectedGroupUuid === "all" || e.groupUuid === selectedGroupUuid;
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.url.toLowerCase().includes(q) ||
        e.notes.toLowerCase().includes(q);
      return matchesGroup && matchesSearch;
    });
  }, [entries, selectedGroupUuid, searchQuery]);

  return (
    <div className="vault-layout" style={hidden ? { display: "none" } : undefined}>
      {/* 1. Sidebar Folders */}
      <aside className="vault-sidebar">
        <div className="sidebar-header">
          <span style={{ fontWeight: 600, fontSize: "0.85rem", textTransform: "uppercase", color: "var(--ink)" }}>
            Folders
          </span>
          <button className="btn btn-quiet btn-sm" onClick={handleCreateGroup} title="Add Folder">
            <Plus size={16} />
          </button>
        </div>

        <div
          className={`group-item ${selectedGroupUuid === "all" ? "active" : ""}`}
          onClick={() => setSelectedGroupUuid("all")}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Shield size={16} />
            <span>All Items</span>
          </div>
          <span className="font-mono" style={{ fontSize: "0.75rem" }}>
            {entries.length}
          </span>
        </div>

        {groups.map((g) => (
          <div
            key={g.uuid}
            className={`group-item ${selectedGroupUuid === g.uuid ? "active" : ""}`}
            onClick={() => setSelectedGroupUuid(g.uuid)}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Folder size={16} />
              <span>{g.name}</span>
            </div>
            <span className="font-mono" style={{ fontSize: "0.75rem" }}>
              {entries.filter((e) => e.groupUuid === g.uuid).length}
            </span>
          </div>
        ))}

        <div style={{ marginTop: "auto", padding: "1rem", borderTop: "1px solid var(--line)" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <button className="btn btn-primary btn-sm" onClick={() => setShowCsvImport(true)}>
              <FileSpreadsheet size={14} /> Import CSV Passwords
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowPairing(true)}>
              <QrCode size={14} /> Pair Extension / Mobile
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowHistory(true)} disabled={saveState.kind !== "saved" || draftDirty}>
              <History size={14} /> Version History (v{vaultVersion})
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onExport} disabled={saving}>
              <Download size={14} /> Download .kdbx
            </button>
          </div>
        </div>
      </aside>

      {/* 2. Middle List Pane */}
      <section className="vault-list-pane">
        <div className="list-search-bar">
          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
            <div style={{ position: "relative", flex: 1 }}>
              <Search
                size={16}
                color="var(--ink-muted)"
                style={{ position: "absolute", left: "0.75rem", top: "50%", transform: "translateY(-50%)" }}
              />
              <input
                type="text"
                className="input"
                style={{ paddingLeft: "2.2rem" }}
                placeholder="Search passwords…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button className="btn btn-primary" onClick={handleCreateNewEntry} title="Add Entry">
              <Plus size={16} />
            </button>
          </div>

          {importMessage ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                background: "var(--success-soft)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                padding: "0.5rem 0.75rem",
                borderRadius: "6px",
                fontSize: "0.8rem",
                marginBottom: "0.5rem",
                color: "var(--success)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <CheckCircle2 size={14} />
                <span>{importMessage}</span>
              </div>
              <button
                className="btn btn-quiet btn-sm"
                style={{ padding: "0.1rem 0.3rem" }}
                onClick={() => setImportMessage(null)}
              >
                ✕
              </button>
            </div>
          ) : null}

          <div role={saveState.kind === "error" ? "alert" : "status"} style={{ padding: "0.5rem", fontSize: "0.85rem" }}>
            {saveState.kind === "error" ? (
              <>
                <p style={{ color: "var(--danger)" }}>Unsaved edits: {saveState.message}</p>
                <button className="btn btn-primary btn-sm" onClick={() => void onSave()}>Retry Save</button>
              </>
            ) : <span>{saving ? "Saving…" : draftDirty ? "Applied changes saved" : "All changes saved"}</span>}
            {draftDirty ? <p>Entry edits have not been applied.</p> : null}
          </div>
        </div>

        <ul className="entry-list">
          {filteredEntries.length === 0 ? (
            <li style={{ padding: "2.5rem 1rem", textAlign: "center", color: "var(--ink-muted)", fontSize: "0.9rem" }}>
              <p style={{ marginBottom: "1rem" }}>No entries found.</p>
              <button
                className="btn btn-secondary btn-sm"
                style={{ margin: "0 auto" }}
                onClick={() => setShowCsvImport(true)}
              >
                <FileSpreadsheet size={14} /> Import from CSV
              </button>
            </li>
          ) : (
            filteredEntries.map((e) => (
              <li
                key={e.uuid}
                className={`entry-item ${selectedEntryUuid === e.uuid ? "active" : ""}`}
                onClick={() => { if (canChangeEntry()) { setIsEditing(false); setSelectedEntryUuid(e.uuid); } }}
              >
                <div className="entry-title">
                  <span>{e.title || "Untitled"}</span>
                  {e.totpSeed ? <span className="badge badge-cyan">2FA</span> : null}
                </div>
                <div className="entry-subtitle">
                  {e.username || (e.url ? e.url.replace(/^https?:\/\//, "") : "No username")}
                </div>
              </li>
            ))
          )}
        </ul>
      </section>

      {/* 3. Detail & Editor Pane */}
      <main className="vault-detail-pane">
        {selectedEntry ? (
          <div>
            <div className="detail-header">
              <div>
                <h2>{isEditing ? "Edit Entry" : selectedEntry.title || "Untitled"}</h2>
                <span style={{ color: "var(--ink-muted)", fontSize: "0.8rem" }}>
                  Last modified: {new Date(selectedEntry.updatedAt).toLocaleString()}
                </span>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                {isEditing ? (
                  <>
                    <button className="btn btn-secondary" onClick={() => { loadEditor(); setIsEditing(false); }}>
                      Cancel
                    </button>
                    <button className="btn btn-primary" onClick={handleSaveEntry}>
                      <Save size={16} /> Apply Edits
                    </button>
                  </>
                ) : (
                  <>
                    <button className="btn btn-secondary" onClick={() => setIsEditing(true)}>
                      Edit
                    </button>
                    <button className="btn btn-danger btn-sm" onClick={handleDeleteEntry} title="Delete">
                      <Trash2 size={16} />
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Title & Group */}
            <div className="field-card">
              <div className="input-group" style={{ marginBottom: isEditing ? "1rem" : 0 }}>
                <label className="input-label">Title</label>
                {isEditing ? (
                  <input
                    type="text"
                    className="input"
                    value={editTitle}
                    onChange={(e) => setEditTitle(e.target.value)}
                  />
                ) : (
                  <div style={{ fontSize: "1.1rem", fontWeight: 600 }}>{selectedEntry.title}</div>
                )}
              </div>

              {isEditing ? (
                <div className="input-group" style={{ marginBottom: 0 }}>
                  <label className="input-label">Folder</label>
                  <select
                    className="select"
                    value={editGroupUuid}
                    onChange={(e) => setEditGroupUuid(e.target.value)}
                  >
                    {groups.map((g) => (
                      <option key={g.uuid} value={g.uuid}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </div>
              ) : null}
            </div>

            {/* Username Field */}
            <div className="field-card">
              <label className="input-label">Username / Email</label>
              {isEditing ? (
                <input
                  type="text"
                  className="input font-mono"
                  value={editUsername}
                  onChange={(e) => setEditUsername(e.target.value)}
                />
              ) : (
                <div className="field-row">
                  <span className="font-mono">{selectedEntry.username || "—"}</span>
                  {selectedEntry.username ? (
                    <button
                      className="btn btn-quiet btn-sm"
                      onClick={() => copyToClipboard(selectedEntry.username, "user")}
                      title="Copy Username"
                    >
                      {copiedField === "user" ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                    </button>
                  ) : null}
                </div>
              )}
            </div>

            {/* Password Field */}
            <div className="field-card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.4rem" }}>
                <label className="input-label" style={{ margin: 0 }}>Password</label>
                {isEditing ? (
                  <button
                    type="button"
                    className="btn btn-quiet btn-sm"
                    onClick={() => setShowGenerator(true)}
                  >
                    <Key size={14} /> Generate
                  </button>
                ) : null}
              </div>

              {isEditing ? (
                <div style={{ position: "relative" }}>
                  <input
                    type={revealPassword ? "text" : "password"}
                    className="input font-mono"
                    value={editPassword}
                    onChange={(e) => setEditPassword(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn btn-quiet btn-sm"
                    style={{ position: "absolute", right: "0.5rem", top: "50%", transform: "translateY(-50%)" }}
                    onClick={() => setRevealPassword(!revealPassword)}
                  >
                    {revealPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              ) : (
                <div className="field-row">
                  <span className="font-mono">
                    {revealPassword ? selectedEntry.password : "••••••••••••••••"}
                  </span>
                  <div style={{ display: "flex", gap: "0.4rem" }}>
                    <button
                      className="btn btn-quiet btn-sm"
                      onClick={() => setRevealPassword(!revealPassword)}
                      title="Toggle visibility"
                    >
                      {revealPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                    <button
                      className="btn btn-quiet btn-sm"
                      onClick={() => copyToClipboard(selectedEntry.password, "pass")}
                      title="Copy Password"
                    >
                      {copiedField === "pass" ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* TOTP 2FA Authenticator */}
            {(selectedEntry.totpSeed || isEditing) ? (
              <div className="field-card">
                <label className="input-label">Two-Factor Authentication (TOTP Key / URI)</label>
                {isEditing ? (
                  <input
                    type="text"
                    className="input font-mono"
                    placeholder="otpauth://totp/App:user?secret=JBSWY3DPEHPK3PXP"
                    value={editTotp}
                    onChange={(e) => setEditTotp(e.target.value)}
                  />
                ) : totpCode ? (
                  <div className="totp-box">
                    <div>
                      <div className="totp-code">{totpCode}</div>
                      <span style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                        Auto-updates every 30s
                      </span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                      <div className="totp-timer">{totpRemaining}</div>
                      <button
                        className="btn btn-quiet btn-sm"
                        onClick={() => copyToClipboard(totpCode, "totp")}
                        title="Copy OTP Code"
                      >
                        {copiedField === "totp" ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
                      </button>
                    </div>
                  </div>
                ) : (
                  <span style={{ color: "var(--ink-muted)" }}>—</span>
                )}
              </div>
            ) : null}

            {/* Website URL */}
            <div className="field-card">
              <label className="input-label">Website URL</label>
              {isEditing ? (
                <input
                  type="url"
                  className="input font-mono"
                  placeholder="https://example.com"
                  value={editUrl}
                  onChange={(e) => setEditUrl(e.target.value)}
                />
              ) : (
                <div className="field-row">
                  <span className="font-mono">{selectedEntry.url || "—"}</span>
                  {selectedEntry.url ? (
                    <div style={{ display: "flex", gap: "0.4rem" }}>
                      <a
                        href={selectedEntry.url}
                        target="_blank"
                        rel="noreferrer"
                        className="btn btn-quiet btn-sm"
                        title="Open in new tab"
                      >
                        <ExternalLink size={14} />
                      </a>
                      <button
                        className="btn btn-quiet btn-sm"
                        onClick={() => copyToClipboard(selectedEntry.url, "url")}
                      >
                        {copiedField === "url" ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                      </button>
                    </div>
                  ) : null}
                </div>
              )}
            </div>

            {/* Notes */}
            <div className="field-card">
              <label className="input-label">Notes</label>
              {isEditing ? (
                <textarea
                  className="textarea font-mono"
                  rows={5}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                />
              ) : (
                <div style={{ whiteSpace: "pre-wrap", color: "var(--ink-strong)", fontSize: "0.9rem" }}>
                  {selectedEntry.notes || <span style={{ color: "var(--ink-muted)" }}>No notes attached.</span>}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: "4rem 0", color: "var(--ink-muted)" }}>
            <Key size={48} style={{ opacity: 0.2, marginBottom: "1rem" }} />
            <p>Select an entry to view details, or create a new password.</p>
          </div>
        )}
      </main>

      {/* Modals */}
      {showGenerator ? (
        <PasswordGenerator
          onSelect={(pw) => {
            setEditPassword(pw);
            setRevealPassword(true);
          }}
          onClose={() => setShowGenerator(false)}
        />
      ) : null}

      {showPairing ? <DevicePairingModal onClose={() => setShowPairing(false)} /> : null}

      {showCsvImport ? (
        <CsvImportModal
          vault={vault}
          groups={groups}
          onClose={() => setShowCsvImport(false)}
          onImportComplete={(count, createdFolders) => {
            onChanged();
            refreshVaultData();
            const folderText =
              createdFolders.length > 0
                ? ` (${createdFolders.length} folder${createdFolders.length === 1 ? "" : "s"} created)`
                : "";
            setImportMessage(`Successfully imported ${count} password${count === 1 ? "" : "s"}${folderText}. Changes are saved automatically.`);
          }}
        />
      ) : null}

      {showHistory ? (
        <HistoryModal
          onClose={() => setShowHistory(false)}
          onRestored={async () => {
            setShowHistory(false);
            await onReload();
          }}
        />
      ) : null}
    </div>
  );
}
