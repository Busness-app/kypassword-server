import { FormEvent, useEffect, useState } from "react";
import { ArchiveRestore, CheckCircle2, Download, RefreshCw, Send, ShieldCheck } from "lucide-react";
import { getJSON, postJSON, toErrorMessage } from "../lib/api";

type Receipt = {
  capsule_id: string;
  digest: string;
  size_bytes: number;
  deposited_at: string;
};

type BackupStatus = {
  paired: boolean;
  recoveryUrl?: string;
  recoveryKeyId?: string;
  threshold?: number;
  totalShares?: number;
  keyHealthy: boolean;
  lastDeposit?: Receipt;
};

type DrillResult = {
  passed: boolean;
  durationMs: number;
  checks: Array<{ name: string; passed: boolean; message: string }>;
};

export function AdminBackup() {
  const [status, setStatus] = useState<BackupStatus>();
  const [url, setURL] = useState("");
  const [code, setCode] = useState("");
  const [drill, setDrill] = useState<DrillResult>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = async () => {
    try {
      const next = await getJSON<BackupStatus>("/api/backup/status");
      setStatus(next);
      setURL(next.recoveryUrl ?? "");
    } catch (cause: unknown) {
      setError(toErrorMessage(cause, "Failed to load backup status"));
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const act = async (action: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await action();
      await refresh();
    } catch (cause: unknown) {
      setError(toErrorMessage(cause, "Backup operation failed"));
    } finally {
      setBusy(false);
    }
  };

  const pair = (event: FormEvent) => {
    event.preventDefault();
    void act(async () => {
      await postJSON<BackupStatus>("/api/backup/pair-remote", { recoveryUrl: url, pairingCode: code });
      setCode("");
      setMessage("KyRecovery pairing pinned successfully.");
    });
  };

  const deposit = () => void act(async () => {
    const receipt = await postJSON<Receipt>("/api/backup/deposit", {});
    setMessage(`Deposited capsule ${receipt.capsule_id}.`);
  });

  const runDrill = () => void act(async () => {
    const result = await postJSON<DrillResult>("/api/backup/drill", {});
    setDrill(result);
    setMessage(result.passed ? "Restore drill passed." : "Restore drill found a problem.");
  });

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", gap: "1rem", marginBottom: "1.5rem" }}>
        <div>
          <h3 style={{ margin: 0 }}>KyRecovery Backup</h3>
          <p style={{ color: "var(--ink-muted)", marginTop: "0.4rem" }}>
            Seal encrypted vaults and server state to the suite recovery key. KyRecovery cannot read the capsule.
          </p>
        </div>
        <button className="btn btn-secondary btn-sm" type="button" onClick={() => void refresh()} disabled={busy}>
          <RefreshCw size={15} /> Refresh
        </button>
      </div>

      {message ? <div className="field-card" style={{ color: "var(--success)", marginBottom: "1rem" }}><CheckCircle2 size={16} /> {message}</div> : null}
      {error ? <div className="field-card" style={{ color: "var(--danger)", marginBottom: "1rem" }}>{error}</div> : null}

      <div className="field-card" style={{ marginBottom: "1rem" }}>
        <h4 style={{ marginTop: 0 }}>Pairing status</h4>
        <p>
          <strong>{status?.paired ? (status.keyHealthy ? "Paired and healthy" : "Paired, key missing or mismatched") : "Not paired"}</strong>
        </p>
        {status?.recoveryKeyId ? <p className="font-mono" style={{ overflowWrap: "anywhere" }}>Key: {status.recoveryKeyId}</p> : null}
        {status?.threshold ? <p>Custodians: {status.threshold} of {status.totalShares}</p> : null}
        {status?.lastDeposit ? (
          <p className="font-mono" style={{ overflowWrap: "anywhere" }}>
            Last deposit: {status.lastDeposit.capsule_id} at {new Date(status.lastDeposit.deposited_at).toLocaleString()}
          </p>
        ) : null}
      </div>

      <form className="field-card" onSubmit={pair} style={{ marginBottom: "1rem" }}>
        <h4 style={{ marginTop: 0 }}>Claim pairing code</h4>
        <div className="input-group">
          <label className="input-label" htmlFor="recovery-url">KyRecovery HTTPS origin</label>
          <input id="recovery-url" className="input font-mono" type="url" required value={url} onChange={(event) => setURL(event.target.value)} placeholder="https://recovery.example.com" />
        </div>
        <div className="input-group">
          <label className="input-label" htmlFor="recovery-code">Six-digit pairing code</label>
          <input id="recovery-code" className="input font-mono" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={(event) => setCode(event.target.value)} placeholder="123456" />
        </div>
        <button className="btn btn-primary" disabled={busy}><ShieldCheck size={16} /> Claim pairing</button>
      </form>

      <div className="field-card">
        <h4 style={{ marginTop: 0 }}>Recovery operations</h4>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
          <button className="btn btn-primary" type="button" onClick={deposit} disabled={busy || !status?.keyHealthy}><Send size={16} /> Deposit now</button>
          {status?.keyHealthy ? (
            <a className="btn btn-secondary" href="/api/backup/export-capsule" download><Download size={16} /> Download .kycap</a>
          ) : (
            <button className="btn btn-secondary" type="button" disabled><Download size={16} /> Download .kycap</button>
          )}
          <button className="btn btn-secondary" type="button" onClick={runDrill} disabled={busy}><ArchiveRestore size={16} /> Run restore drill</button>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: 0 }}>
          The drill opens a throwaway capsule, verifies the audit chain and encrypted KDBX checksums, but cannot decrypt user credentials because the server holds no vault key.
        </p>
        {drill ? (
          <ul>
            {drill.checks.map((check) => <li key={check.name}>{check.passed ? "✓" : "✗"} {check.name}: {check.message}</li>)}
          </ul>
        ) : null}
      </div>
    </div>
  );
}
