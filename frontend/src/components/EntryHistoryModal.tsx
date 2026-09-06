import { useEffect, useRef, useState } from "react";
import type { KeePassVault } from "../lib/kdbx";

type Props = {
  vault: KeePassVault;
  entryUuid: string;
  allowRestore: boolean;
  onRestored: () => void;
  onClose: () => void;
};

export function EntryHistoryModal({ vault, entryUuid, allowRestore, onRestored, onClose }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const versions = vault.getEntryHistory(entryUuid);
  const [selectedIndex, setSelectedIndex] = useState(versions[0]?.index ?? -1);
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState("");
  const selected = versions.find(version => version.index === selectedIndex);
  const preview = selected ? vault.getEntryHistoryVersion(entryUuid, selected.index) : null;

  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => { element?.close(); };
  }, []);

  const restore = () => {
    if (!allowRestore || !selected) return;
    if (!confirm("Restore this entry version? The current version will be kept in entry history. The entry will stay in its current folder.")) return;
    try {
      vault.restoreEntryVersion(entryUuid, selected.index);
      onRestored();
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to restore this entry version.");
    }
  };

  return <dialog ref={dialog} className="modal-card entry-history-dialog" aria-labelledby="entry-history-title" onCancel={onClose}>
    <div className="modal-header">
      <h3 id="entry-history-title">Entry History</h3>
      <button type="button" className="btn btn-quiet btn-sm" aria-label="Close entry history" onClick={onClose}>✕</button>
    </div>
    <p>Previous versions stored inside your encrypted vault. Restoring replaces this entry’s contents, including attachments and custom fields, and saves automatically.</p>
    {!vault.entryHistoryEnabled ? <p>Entry history is disabled for this vault. Restoring is unavailable because the current version could not be kept.</p> : null}
    {versions.length === 0 ? <p>No previous versions. New versions are kept when you apply changed entry fields while entry history is enabled.</p> : <>
      <label className="input-label" htmlFor="entry-history-version">Previous version</label>
      <select id="entry-history-version" className="select" value={selectedIndex}
        onChange={event => { setSelectedIndex(Number(event.target.value)); setReveal(false); setError(""); }}>
        {versions.map(version => <option key={version.index} value={version.index}>
          Version {version.index + 1} — {version.updatedAt?.toLocaleString() ?? "Unknown date"}
        </option>)}
      </select>
      <label className="entry-history-reveal">
        <input type="checkbox" checked={reveal} onChange={event => setReveal(event.target.checked)} />
        Reveal passwords, TOTP keys and protected fields
      </label>
      {preview ? <>
        <dl className="entry-history-fields">
          {preview.fields.map(field => <div key={field.name}>
            <dt>{field.name}</dt>
            <dd>{field.protected && !reveal && field.value ? "••••••••" : field.value || "—"}</dd>
          </div>)}
        </dl>
        <p>Attachments: {preview.attachments.length ? preview.attachments.join(", ") : "None"}</p>
      </> : null}
      {!allowRestore ? <p>Restore this entry from the Recycle Bin before restoring a previous version.</p> : null}
      <button type="button" className="btn btn-primary" disabled={!allowRestore || !vault.entryHistoryEnabled || !selected}
        onClick={restore}>Restore this version</button>
    </>}
    {error ? <p role="alert">{error}</p> : null}
  </dialog>;
}
