import { useState, useMemo, useRef } from "react";
import { KeePassVault, VaultGroup } from "../lib/kdbx";
import {
  CsvProvider,
  ImportedEntryPreview,
  CsvParseSummary,
  PROVIDER_LABELS,
  parseAndPreviewCsv,
  applyImportToVault,
  findDuplicateImports,
} from "../lib/csvImport";
import {
  FileSpreadsheet,
  UploadCloud,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Search,
  Eye,
  EyeOff,
  FolderPlus,
  Folder,
} from "lucide-react";

type Props = {
  vault: KeePassVault;
  groups: VaultGroup[];
  onClose: () => void;
  onImportComplete: (importedCount: number, foldersCreated: string[], skippedDuplicates: number) => void;
};

export function CsvImportModal({ vault, groups, onClose, onImportComplete }: Props) {
  const [inputMode, setInputMode] = useState<"file" | "paste">("file");
  const [csvContent, setCsvContent] = useState<string>("");
  const [fileName, setFileName] = useState<string>("");
  const [provider, setProvider] = useState<CsvProvider>("auto");
  const [folderMode, setFolderMode] = useState<"csv_folders" | "single_folder">("csv_folders");
  const [selectedFolderUuid, setSelectedFolderUuid] = useState<string>(groups[0]?.uuid || "");
  const [newFolderName, setNewFolderName] = useState<string>("");
  const [useNewFolder, setUseNewFolder] = useState<boolean>(false);

  // Preview & Table State
  const [previewEntries, setPreviewEntries] = useState<ImportedEntryPreview[]>([]);
  const [parseSummary, setParseSummary] = useState<CsvParseSummary | null>(null);
  const [tableSearch, setTableSearch] = useState<string>("");
  const [revealedPasswords, setRevealedPasswords] = useState<Record<string, boolean>>({});
  const [skipDuplicates, setSkipDuplicates] = useState(true);
  const [isImporting, setIsImporting] = useState<boolean>(false);
  const [dragOver, setDragOver] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleProcessCsv = (text: string, selectedProvider: CsvProvider = provider) => {
    setCsvContent(text);
    if (!text.trim()) {
      setParseSummary(null);
      setPreviewEntries([]);
      return;
    }

    const summary = parseAndPreviewCsv(text, selectedProvider);
    setParseSummary(summary);
    setPreviewEntries(summary.validEntries);
  };

  const handleFileChange = (file: File) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      handleProcessCsv(text, provider);
    };
    reader.readAsText(file);
  };

  const handleProviderChange = (newProvider: CsvProvider) => {
    setProvider(newProvider);
    if (csvContent) {
      handleProcessCsv(csvContent, newProvider);
    }
  };

  const toggleSelectAll = (checked: boolean) => {
    setPreviewEntries((prev) => prev.map((e) => ({ ...e, selected: checked })));
  };

  const toggleSelectEntry = (id: string) => {
    setPreviewEntries((prev) =>
      prev.map((e) => (e.id === id ? { ...e, selected: !e.selected } : e))
    );
  };

  const toggleReveal = (id: string) => {
    setRevealedPasswords((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredEntries = useMemo(() => {
    if (!tableSearch.trim()) return previewEntries;
    const q = tableSearch.toLowerCase();
    return previewEntries.filter(
      (e) =>
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.url.toLowerCase().includes(q) ||
        e.folder.toLowerCase().includes(q) ||
        e.notes.toLowerCase().includes(q)
    );
  }, [previewEntries, tableSearch]);

  const selectedCount = useMemo(() => {
    return previewEntries.filter((e) => e.selected).length;
  }, [previewEntries]);

  const duplicates = useMemo(() => findDuplicateImports(vault, previewEntries), [vault, previewEntries]);
  const skippedCount = skipDuplicates ? previewEntries.filter(entry => entry.selected && duplicates.has(entry.id)).length : 0;
  const importCount = selectedCount - skippedCount;

  const handleExecuteImport = () => {
    if (importCount === 0) return;
    setIsImporting(true);

    try {
      const res = applyImportToVault(vault, previewEntries, {
        folderMode,
        targetFolderUuid: selectedFolderUuid,
        newFolderName: useNewFolder ? newFolderName : undefined,
        skipDuplicates,
        defaultFolderName: "Imported Passwords",
      });

      onImportComplete(res.importedCount, res.foldersCreated, res.skippedDuplicates);
      onClose();
    } catch (err: any) {
      alert("Failed to import entries: " + (err?.message || String(err)));
    } finally {
      setIsImporting(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-card"
        style={{ maxWidth: "860px", width: "95%" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
            <FileSpreadsheet size={22} color="var(--accent)" />
            <h3>Import Passwords from CSV</h3>
          </div>
          <button className="btn btn-quiet btn-sm" onClick={onClose}>
            ✕
          </button>
        </div>

        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          Seamlessly import your credentials from Chrome, 1Password, Bitwarden, LastPass,
          DashPass (Dashlane), or generic CSV files. All parsing and decryption occur zero-knowledge
          directly in your browser before saving to your encrypted KeePass v4 vault.
        </p>

        {/* Source Provider selector & Mode Toggle */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "1rem",
            marginBottom: "1.25rem",
          }}
        >
          <div className="input-group" style={{ marginBottom: 0 }}>
            <label className="input-label">Password Manager / CSV Format</label>
            <select
              className="select"
              value={provider}
              onChange={(e) => handleProviderChange(e.target.value as CsvProvider)}
            >
              <option value="auto">Auto-Detect Format (Recommended)</option>
              <option value="chrome">Google Chrome / Chromium</option>
              <option value="onepassword">1Password</option>
              <option value="bitwarden">Bitwarden</option>
              <option value="lastpass">LastPass</option>
              <option value="dashlane">DashPass / Dashlane</option>
              <option value="generic">Generic CSV</option>
            </select>
          </div>

          <div className="input-group" style={{ marginBottom: 0 }}>
            <label className="input-label">Input Method</label>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button
                type="button"
                className={`btn btn-sm ${inputMode === "file" ? "btn-primary" : "btn-secondary"}`}
                style={{ flex: 1 }}
                onClick={() => setInputMode("file")}
              >
                <UploadCloud size={14} /> Upload File
              </button>
              <button
                type="button"
                className={`btn btn-sm ${inputMode === "paste" ? "btn-primary" : "btn-secondary"}`}
                style={{ flex: 1 }}
                onClick={() => setInputMode("paste")}
              >
                <FileText size={14} /> Paste Text
              </button>
            </div>
          </div>
        </div>

        {/* Input Area: Dropzone or Textarea */}
        {inputMode === "file" ? (
          <div
            style={{
              border: `2px dashed ${dragOver ? "var(--accent)" : "var(--line)"}`,
              borderRadius: "8px",
              padding: "1.5rem",
              textAlign: "center",
              background: dragOver ? "var(--accent-soft)" : "rgba(0, 0, 0, 0.2)",
              cursor: "pointer",
              transition: "all 0.15s ease",
              marginBottom: "1.25rem",
            }}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const file = e.dataTransfer.files?.[0];
              if (file) handleFileChange(file);
            }}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              type="file"
              ref={fileInputRef}
              accept=".csv,.txt"
              style={{ display: "none" }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileChange(file);
                e.target.value = "";
              }}
            />
            <UploadCloud
              size={36}
              color={fileName ? "var(--accent)" : "var(--ink-muted)"}
              style={{ margin: "0 auto 0.5rem auto" }}
            />
            {fileName ? (
              <div>
                <div style={{ fontWeight: 600, color: "var(--accent)" }}>{fileName}</div>
                <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.25rem" }}>
                  Click or drag another file to replace
                </div>
              </div>
            ) : (
              <div>
                <div style={{ fontWeight: 600, color: "var(--ink-strong)" }}>
                  Click to browse or drag & drop CSV file
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.25rem" }}>
                  Supports Chrome, 1Password, Bitwarden, LastPass, DashPass CSV files
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="input-group" style={{ marginBottom: "1.25rem" }}>
            <label className="input-label">Paste Raw CSV Data</label>
            <textarea
              className="textarea font-mono"
              rows={5}
              placeholder={`name,url,username,password,note\nGitHub,https://github.com,octocat,token123,Developer keys`}
              value={csvContent}
              onChange={(e) => handleProcessCsv(e.target.value)}
            />
          </div>
        )}

        {/* Folder Destination Policy */}
        {parseSummary && parseSummary.validEntries.length > 0 ? (
          <div
            style={{
              background: "#0d0f14",
              border: "1px solid var(--line)",
              borderRadius: "8px",
              padding: "1rem",
              marginBottom: "1.25rem",
            }}
          >
            <div style={{ fontWeight: 600, fontSize: "0.85rem", marginBottom: "0.75rem", color: "var(--ink-strong)" }}>
              Destination Folder Organization
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                <input
                  type="radio"
                  name="folderMode"
                  checked={folderMode === "csv_folders"}
                  onChange={() => setFolderMode("csv_folders")}
                />
                <span>
                  Preserve CSV folder/group structure (auto-create missing categories like Personal, Work, etc.)
                </span>
              </label>

              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                <input
                  type="radio"
                  name="folderMode"
                  checked={folderMode === "single_folder"}
                  onChange={() => setFolderMode("single_folder")}
                />
                <span>Import all items into a single folder</span>
              </label>

              {folderMode === "single_folder" ? (
                <div style={{ marginLeft: "1.5rem", marginTop: "0.4rem", display: "flex", gap: "0.75rem", alignItems: "center" }}>
                  {!useNewFolder ? (
                    <select
                      className="select"
                      style={{ maxWidth: "260px" }}
                      value={selectedFolderUuid}
                      onChange={(e) => setSelectedFolderUuid(e.target.value)}
                    >
                      {groups.map((g) => (
                        <option key={g.uuid} value={g.uuid}>
                          {g.name}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      className="input"
                      style={{ maxWidth: "260px" }}
                      placeholder="Folder name (e.g. Imported)"
                      value={newFolderName}
                      onChange={(e) => setNewFolderName(e.target.value)}
                    />
                  )}

                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setUseNewFolder(!useNewFolder)}
                  >
                    {useNewFolder ? <Folder size={14} /> : <FolderPlus size={14} />}
                    {useNewFolder ? "Choose Existing" : "Create New Folder"}
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        {parseSummary ? (
          <div style={{ marginBottom: "1rem" }}>
            <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <input type="checkbox" checked={skipDuplicates} onChange={event => setSkipDuplicates(event.target.checked)} />
              Skip exact duplicates
            </label>
            <p style={{ fontSize: "0.85rem", color: "var(--ink-muted)" }}>
              Matches title, username, password, URL, notes and 2FA across all vault folders and selected CSV rows.
              Changed values are imported as separate entries.
            </p>
            <p role="status">{importCount} to import; {skippedCount} duplicate{skippedCount === 1 ? "" : "s"} to skip.</p>
          </div>
        ) : null}

        {/* Parsed summary & Preview Table */}
        {parseSummary ? (
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "0.75rem",
                flexWrap: "wrap",
                gap: "0.5rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span className="badge badge-cyan">
                  Detected: {parseSummary.providerName}
                </span>
                <span style={{ fontSize: "0.85rem", color: "var(--ink-muted)" }}>
                  {parseSummary.validEntries.length} accounts found ({selectedCount} selected)
                </span>
              </div>

              <div style={{ position: "relative", width: "220px" }}>
                <Search
                  size={14}
                  color="var(--ink-muted)"
                  style={{ position: "absolute", left: "0.6rem", top: "50%", transform: "translateY(-50%)" }}
                />
                <input
                  type="text"
                  className="input"
                  style={{ paddingLeft: "2rem", height: "30px", fontSize: "0.8rem" }}
                  placeholder="Filter preview…"
                  value={tableSearch}
                  onChange={(e) => setTableSearch(e.target.value)}
                />
              </div>
            </div>

            {/* Errors alert if any */}
            {parseSummary.errors.length > 0 ? (
              <div
                style={{
                  background: "var(--danger-soft)",
                  color: "var(--danger)",
                  padding: "0.6rem 0.8rem",
                  borderRadius: "6px",
                  fontSize: "0.8rem",
                  marginBottom: "0.75rem",
                }}
              >
                <AlertTriangle size={14} style={{ verticalAlign: "middle", marginRight: "0.3rem" }} />
                {parseSummary.errors.length} rows could not be parsed.
              </div>
            ) : null}

            {/* Table */}
            <div
              style={{
                border: "1px solid var(--line)",
                borderRadius: "6px",
                maxHeight: "260px",
                overflowY: "auto",
                background: "#0d0f14",
              }}
            >
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
                <thead>
                  <tr style={{ background: "var(--panel)", borderBottom: "1px solid var(--line)", textAlign: "left" }}>
                    <th style={{ padding: "0.5rem 0.75rem", width: "36px" }}>
                      <input
                        type="checkbox"
                        checked={previewEntries.length > 0 && previewEntries.every((e) => e.selected)}
                        onChange={(e) => toggleSelectAll(e.target.checked)}
                      />
                    </th>
                    <th style={{ padding: "0.5rem 0.75rem" }}>Title / Site</th>
                    <th style={{ padding: "0.5rem 0.75rem" }}>Username</th>
                    <th style={{ padding: "0.5rem 0.75rem" }}>Password</th>
                    <th style={{ padding: "0.5rem 0.75rem" }}>Folder</th>
                    <th style={{ padding: "0.5rem 0.75rem", textAlign: "center" }}>2FA</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEntries.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: "center", padding: "1.5rem", color: "var(--ink-muted)" }}>
                        No matching entries.
                      </td>
                    </tr>
                  ) : (
                    filteredEntries.map((item) => (
                      <tr
                        key={item.id}
                        style={{
                          borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                          background: item.selected ? "transparent" : "rgba(0,0,0,0.3)",
                          opacity: item.selected ? 1 : 0.5,
                        }}
                      >
                        <td style={{ padding: "0.5rem 0.75rem" }}>
                          <input
                            type="checkbox"
                            checked={item.selected}
                            onChange={() => toggleSelectEntry(item.id)}
                          />
                        </td>
                        <td style={{ padding: "0.5rem 0.75rem", fontWeight: 600, color: "var(--ink-strong)" }}>
                          {item.title}
                          {duplicates.has(item.id) ? <span className="badge badge-cyan" style={{ marginLeft: "0.5rem" }}>Duplicate</span> : null}
                          {item.url ? (
                            <div style={{ fontSize: "0.7rem", color: "var(--ink-muted)", fontWeight: 400 }}>
                              {item.url}
                            </div>
                          ) : null}
                        </td>
                        <td style={{ padding: "0.5rem 0.75rem", fontFamily: "var(--font-mono)", color: "var(--ink-muted)" }}>
                          {item.username || "—"}
                        </td>
                        <td style={{ padding: "0.5rem 0.75rem", fontFamily: "var(--font-mono)" }}>
                          {item.password ? (
                            <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
                              <span>
                                {revealedPasswords[item.id] ? item.password : "••••••••"}
                              </span>
                              <button
                                type="button"
                                className="btn btn-quiet btn-sm"
                                style={{ padding: "0.1rem 0.2rem" }}
                                onClick={() => toggleReveal(item.id)}
                              >
                                {revealedPasswords[item.id] ? <EyeOff size={12} /> : <Eye size={12} />}
                              </button>
                            </div>
                          ) : (
                            <span style={{ color: "var(--ink-muted)" }}>—</span>
                          )}
                        </td>
                        <td style={{ padding: "0.5rem 0.75rem", color: "var(--ink-muted)" }}>
                          {item.folder || "—"}
                        </td>
                        <td style={{ padding: "0.5rem 0.75rem", textAlign: "center" }}>
                          {item.totpSeed ? <span className="badge badge-cyan" style={{ fontSize: "0.65rem" }}>TOTP</span> : "—"}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        {/* Modal Actions */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: "1.5rem",
            borderTop: "1px solid var(--line)",
            paddingTop: "1rem",
          }}
        >
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={importCount === 0 || isImporting}
            onClick={handleExecuteImport}
          >
            <CheckCircle2 size={16} />
            {isImporting
              ? "Importing…"
              : `Import ${importCount} Password${importCount === 1 ? "" : "s"}`}
          </button>
        </div>
      </div>
    </div>
  );
}
