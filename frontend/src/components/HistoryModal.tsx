import React, { useState, useEffect } from "react";
import { getJSON, postJSON, deleteJSON, toErrorMessage } from "../lib/api";
import { History, RotateCcw, AlertTriangle, Trash2, CheckCircle2 } from "lucide-react";

type HistoryEntry = {
  id: string;
  version: number;
  sizeBytes: number;
  checksum: string;
  timestamp: string;
};

type ConflictEntry = {
  id: string;
  expectedVersion: number;
  deviceId: string;
  sizeBytes: number;
  timestamp: string;
};

type Props = {
  onClose: () => void;
  onRestored: () => void;
};

export function HistoryModal({ onClose, onRestored }: Props) {
  const [activeTab, setActiveTab] = useState<"history" | "conflicts">("history");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [conflicts, setConflicts] = useState<ConflictEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [histData, confData] = await Promise.all([
        getJSON<HistoryEntry[]>("/api/vault/history"),
        getJSON<ConflictEntry[]>("/api/vault/conflicts"),
      ]);
      setHistory(histData || []);
      setConflicts(confData || []);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to load history"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const restoreSnapshot = async (id: string) => {
    if (!confirm(`Are you sure you want to rollback to snapshot ${id}? Current changes will be archived.`)) return;
    setBusyId(id);
    setMessage("");
    setError("");
    try {
      await postJSON(`/api/vault/history/${id}/restore`, {});
      setMessage("Vault successfully restored.");
      onRestored();
    } catch (err) {
      setError(toErrorMessage(err, "Failed to restore snapshot"));
    } finally {
      setBusyId(null);
    }
  };

  const discardConflict = async (id: string) => {
    if (!confirm("Are you sure you want to discard this conflict upload?")) return;
    setBusyId(id);
    try {
      await deleteJSON(`/api/vault/conflicts/${id}`);
      setConflicts((prev) => prev.filter((c) => c.id !== id));
      setMessage("Conflict upload removed.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to discard conflict"));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" style={{ maxWidth: "680px" }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <History size={20} color="var(--accent)" />
            <h3>Vault Version History & Rollback</h3>
          </div>
          <button className="btn btn-quiet btn-sm" onClick={onClose}>
            ✕
          </button>
        </div>

        <div style={{ display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--line)", marginBottom: "1.5rem" }}>
          <button
            className={`nav-link-btn ${activeTab === "history" ? "active" : ""}`}
            onClick={() => setActiveTab("history")}
          >
            Snapshots ({history.length})
          </button>
          <button
            className={`nav-link-btn ${activeTab === "conflicts" ? "active" : ""}`}
            onClick={() => setActiveTab("conflicts")}
          >
            Preserved Conflicts ({conflicts.length})
          </button>
        </div>

        {message ? (
          <p style={{ color: "var(--accent)", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <CheckCircle2 size={16} /> {message}
          </p>
        ) : null}
        {error ? <p style={{ color: "var(--danger)", fontSize: "0.9rem" }}>{error}</p> : null}

        {loading ? (
          <p style={{ color: "var(--ink-muted)" }}>Loading snapshots…</p>
        ) : activeTab === "history" ? (
          history.length === 0 ? (
            <p style={{ color: "var(--ink-muted)" }}>No past version snapshots found (current version is preserved for 90 days).</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {history.map((h) => (
                <div
                  key={h.id}
                  style={{
                    background: "#0d0f14",
                    border: "1px solid var(--line)",
                    borderRadius: "6px",
                    padding: "0.75rem 1rem",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                      Version {h.version || h.id}
                    </div>
                    <div style={{ color: "var(--ink-muted)", fontSize: "0.8rem", marginTop: "0.2rem" }}>
                      {new Date(h.timestamp).toLocaleString()} • {(h.sizeBytes / 1024).toFixed(1)} KB • Checksum:{" "}
                      <code className="font-mono">{h.checksum.slice(0, 8)}</code>
                    </div>
                  </div>
                  <button
                    className="btn btn-secondary btn-sm"
                    disabled={busyId === h.id}
                    onClick={() => restoreSnapshot(h.id)}
                  >
                    <RotateCcw size={14} /> Rollback
                  </button>
                </div>
              ))}
            </div>
          )
        ) : conflicts.length === 0 ? (
          <p style={{ color: "var(--ink-muted)" }}>No pending conflicting saves detected.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <p style={{ color: "var(--warning)", fontSize: "0.85rem", marginBottom: "0.5rem" }}>
              <AlertTriangle size={14} style={{ display: "inline", verticalAlign: "middle" }} /> The following uploads were rejected because another client saved changes in the meantime:
            </p>
            {conflicts.map((c) => (
              <div
                key={c.id}
                style={{
                  background: "#0d0f14",
                  border: "1px solid rgba(245, 158, 11, 0.3)",
                  borderRadius: "6px",
                  padding: "0.75rem 1rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: "0.95rem", color: "var(--warning)" }}>
                    Conflict from {c.deviceId || "Unknown Device"}
                  </div>
                  <div style={{ color: "var(--ink-muted)", fontSize: "0.8rem", marginTop: "0.2rem" }}>
                    {new Date(c.timestamp).toLocaleString()} • Target Version: {c.expectedVersion}
                  </div>
                </div>
                <button
                  className="btn btn-danger btn-sm"
                  disabled={busyId === c.id}
                  onClick={() => discardConflict(c.id)}
                >
                  <Trash2 size={14} /> Discard
                </button>
              </div>
            ))}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "1.5rem" }}>
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
