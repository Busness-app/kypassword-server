import { useEffect, useId, useRef, useState } from "react";
import { MAX_ATTACHMENT_BYTES, type KeePassVault } from "../lib/kdbx";

type Props = {
  vault: KeePassVault;
  entryUuid: string;
  readOnly: boolean;
  onChanged: () => void;
};

export function EntryAttachments({ vault, entryUuid, readOnly, onChanged }: Props) {
  const inputId = useId();
  const pending = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [removeFromHistory, setRemoveFromHistory] = useState(false);
  const attachments = vault.getAttachments(entryUuid);
  useEffect(() => {
    const controller = new AbortController();
    pending.current = controller;
    setBusy(false);
    setError("");
    return () => controller.abort();
  }, [vault, entryUuid, readOnly]);

  const add = async (file: File) => {
    const signal = pending.current?.signal;
    if (!signal || signal.aborted || busy || readOnly) return;
    setError("");
    if (file.size > MAX_ATTACHMENT_BYTES) { setError("Attachments must be 10 MiB or smaller."); return; }
    setBusy(true);
    try {
      const bytes = await file.arrayBuffer();
      signal.throwIfAborted();
      await vault.addAttachment(entryUuid, file.name, bytes, signal);
      onChanged();
    } catch (error) {
      if (!signal.aborted) setError(error instanceof Error ? error.message : "Unable to add this attachment.");
    } finally {
      if (!signal.aborted) setBusy(false);
    }
  };

  const download = (name: string) => {
    try {
      const url = URL.createObjectURL(new Blob([vault.getAttachment(entryUuid, name)], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = name.replace(/[\\/\u0000-\u001f\u007f]/g, "_") || "attachment";
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to download this attachment.");
    }
  };

  const remove = (name: string) => {
    if (readOnly || busy) return;
    if (!confirm(removeFromHistory
      ? "Remove this file and all copies with this name from this entry's history? Other entries, vault snapshots and backups may still contain copies."
      : vault.entryHistoryEnabled
      ? "Remove this attachment? The previous entry version is kept in Entry History. Existing snapshots and backups may also contain the file."
      : "Remove this attachment? Entry history is disabled. Existing snapshots and backups may still contain the file.")) return;
    try {
      if (vault.removeAttachment(entryUuid, name, removeFromHistory)) onChanged();
      setError("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to remove this attachment.");
    }
  };

  const clearHistory = () => {
    if (readOnly || busy || !confirm("Remove all attachment copies from this entry's history? Current attachments and historical password fields will be kept. Other entries, snapshots and backups may still contain copies.")) return;
    try {
      if (vault.clearAttachmentHistory(entryUuid)) onChanged();
      setError("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to clear attachment history.");
    }
  };

  return <section className="field-card entry-attachments" aria-label="Attachments">
    <h3>Attachments</h3>
    {attachments.length ? <ul>
      {attachments.map(file => <li key={file.name}>
        <span>{file.name} ({file.sizeBytes.toLocaleString()} bytes)</span>
        <div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => download(file.name)} aria-label={`Download ${file.name}`}>Download</button>
          {!readOnly ? <button type="button" className="btn btn-danger btn-sm" disabled={busy}
            onClick={() => remove(file.name)} aria-label={`Remove ${file.name}`}>Remove</button> : null}
        </div>
      </li>)}
    </ul> : <p>No attachments.</p>}
    {!readOnly ? <>
      <label style={{ display: "flex", gap: "0.5rem", margin: "0.75rem 0" }}>
        <input type="checkbox" checked={removeFromHistory} disabled={busy}
          onChange={event => setRemoveFromHistory(event.target.checked)} />
        Also remove saved copies from this entry’s history when removing a file
      </label>
      {vault.hasAttachmentHistory(entryUuid) ? <button type="button" className="btn btn-secondary btn-sm" disabled={busy}
        onClick={clearHistory}>Clear attachment history</button> : null}
      <p>Vault attachment budget: {(vault.attachmentBytes / 1024 / 1024).toFixed(1)} of 40 MiB used, including retained history and recycled entries.</p>
      <label className="input-label" htmlFor={inputId}>Add attachment</label>
      <input id={inputId} type="file" disabled={busy} onChange={event => {
        const file = event.target.files?.[0];
        event.target.value = "";
        if (file) void add(file);
      }} />
      <p>Up to 10 MiB per file. Files stay inside the encrypted vault and save automatically.
        The encrypted vault upload limit is 50 MiB. Downloading saves a decrypted copy to your device.</p>
    </> : null}
    {busy ? <p role="status">Adding attachment…</p> : null}
    {error ? <p role="alert">{error}</p> : null}
  </section>;
}
