import { useEffect, useState } from "react";
import { getBinary } from "../lib/api";
import { KeePassVault } from "../lib/kdbx";
import { compareConflictEntries, comparisonFields } from "../lib/conflictComparison";

type LoadState = { kind: "loading" } | { kind: "error" } | { kind: "ready"; vault: KeePassVault };
type Props = {
  conflictId: string;
  current: KeePassVault;
  vaultKey: Uint8Array;
  onRecovered: (uuid: string) => void;
  onBack: () => void;
};

export function ConflictComparison({ conflictId, current, vaultKey, onRecovered, onBack }: Props) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [selectedId, setSelectedId] = useState("");
  const [reveal, setReveal] = useState(false);
  const [recovered, setRecovered] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void (async () => {
      try {
        const bytes = await getBinary(`/api/vault/conflicts/${encodeURIComponent(conflictId)}`, controller.signal);
        if (!active) return;
        const vault = await KeePassVault.open(bytes, vaultKey);
        if (active) {
          setState({ kind: "ready", vault });
          setSelectedId(vault.getLiveEntries()[0]?.uuid ?? "");
        }
      } catch {
        if (active) setState({ kind: "error" });
      }
    })();
    return () => { active = false; controller.abort(); };
  }, [conflictId, vaultKey]);

  const rows = state.kind === "ready" ? compareConflictEntries(current.getLiveEntries(), state.vault.getLiveEntries()) : [];
  const selected = rows.find(row => row.entry.uuid === selectedId);
  const recover = () => {
    if (state.kind !== "ready" || !selected || recovered.has(selectedId)) return;
    try {
      const uuid = current.recoverEntryCopy(state.vault, selectedId);
      setRecovered(previous => new Set(previous).add(selectedId));
      onRecovered(uuid);
      setMessage("Recovered a copy to the top-level folder. Close this window to check autosave status. The conflict is still preserved.");
    } catch {
      setMessage("Unable to recover this entry. The preserved conflict has not been deleted.");
    }
  };

  return <section aria-label="Conflict comparison">
    <button className="btn btn-secondary btn-sm" onClick={onBack}>Back to conflicts</button>
    <p>Compare live entries by their KeePass ID with the open vault. Passwords stay in this browser.</p>
    <p style={{ fontSize: "0.85rem", color: "var(--ink-muted)" }}>
      Only the six fields below are compared. Folders, attachments, other fields and history are not compared.
      Recovery copies the complete entry with a new ID; it never replaces a current entry.
    </p>
    {state.kind === "loading" ? <p role="status">Opening encrypted conflict…</p> : null}
    {state.kind === "error" ? <p role="alert">Could not open this conflict with the current vault key. It may be unavailable, damaged or use a different key. Your vault has not changed.</p> : null}
    {state.kind === "ready" && rows.length === 0 ? <p>No live entries in this conflict.</p> : null}
    <div style={{ maxHeight: "12rem", overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
      {rows.map(row => <button key={row.entry.uuid} className={`btn ${selectedId === row.entry.uuid ? "btn-primary" : "btn-secondary"}`}
        onClick={() => { setSelectedId(row.entry.uuid); setReveal(false); }}>
        {row.entry.title || "Untitled"} — {!row.current ? "Not in live vault" : row.changedFields.length ? "Changed fields" : "Same shown fields"}
        {recovered.has(row.entry.uuid) ? " · Copy recovered" : ""}
      </button>)}
    </div>
    {selected ? <>
      <label style={{ display: "flex", gap: "0.5rem", margin: "1rem 0" }}>
        <input type="checkbox" checked={reveal} onChange={event => setReveal(event.target.checked)} /> Reveal passwords and TOTP keys
      </label>
      <table style={{ width: "100%", tableLayout: "fixed", overflowWrap: "anywhere" }}>
        <thead><tr><th scope="col">Field</th><th scope="col">Open vault</th><th scope="col">Preserved conflict</th></tr></thead>
        <tbody>{comparisonFields.map(([key, label]) => <tr key={key}>
          <th scope="row">{label}{selected.changedFields.some(([changed]) => changed === key) ? " (changed)" : ""}</th>
          {[selected.current, selected.entry].map((entry, index) => <td key={index} style={{ whiteSpace: "pre-wrap", padding: "0.5rem" }}>
            {!entry ? "Not in live vault" : (key === "password" || key === "totpSeed") && !reveal && entry[key] ? "••••••••" : entry[key] || "—"}
          </td>)}
        </tr>)}</tbody>
      </table>
      <button className="btn btn-primary" disabled={recovered.has(selectedId)} onClick={recover}>Recover as copy</button>
    </> : null}
    {message ? <p role="status">{message}</p> : null}
  </section>;
}
