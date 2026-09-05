import { FormEvent, useEffect, useState } from "react";
import { ArchiveRestore, CheckCircle2, Download, RefreshCw, Send, ShieldCheck } from "lucide-react";
import { getJSON, postBlob, postJSON, putJSON, deleteJSON, toErrorMessage } from "../lib/api";

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
 error?: string;
 backupDir: string;
 allowPrivate: boolean;
 intervalSec: number;
 nextAttempt?: string;
 lastAttempt?: string;
 localCopies: Array<{ name: string }>;
 lastRun?: { at: string; capsuleId?: string; localPath?: string; localError?: string; deposited: boolean; error?: string };

};

type DrillResult = {
  passed: boolean;
  durationMs: number;
  checks: Array<{ name: string; passed: boolean; message: string }>;
};

type DepositReply = { result: { local_path?: string; local_error?: string; receipt?: Receipt }; warning?: string };

export function BackupDepositResult({ reply }: { reply: DepositReply }) {
  const failed = Boolean(reply.warning || reply.result.local_error);
  const details = [reply.result.local_path ? `Local copy: ${reply.result.local_path}.` : "", reply.result.receipt ? `Deposited ${reply.result.receipt.capsule_id}.` : "", reply.result.local_error ?? "", reply.warning ?? ""].filter(Boolean).join(" ");
  return <div role={failed ? "alert" : "status"} className="field-card" style={{ color: failed ? "var(--danger)" : "var(--success)", marginBottom: "1rem" }}>
    {failed ? null : <CheckCircle2 size={16} />} {details}
  </div>;
}

export function AdminBackup() {
  const [status, setStatus] = useState<BackupStatus>();
  const [url, setURL] = useState("");
  const [code, setCode] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [threshold, setThreshold] = useState(2);
  const [totalShares, setTotalShares] = useState(3);
  const [intervalMinutes, setIntervalMinutes] = useState(1440);
  const [drill, setDrill] = useState<DrillResult>();
  const [busy, setBusy] = useState(false);
  const [depositReply, setDepositReply] = useState<DepositReply>();
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = async () => {
    try {
      const next = await getJSON<BackupStatus>("/api/backup/status");
      setStatus(next);
      setURL(next.recoveryUrl ?? "");
 setIntervalMinutes(next.intervalSec / 60);
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
    setDepositReply(undefined);
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
    setDepositReply(await postJSON<DepositReply>("/api/backup/deposit", {}));
  });

  const runDrill = () => void act(async () => {
    const result = await postJSON<DrillResult>("/api/backup/drill", {});
    setDrill(result);
    setMessage(result.passed ? "Restore drill passed." : "Restore drill found a problem.");
  });

  const download = () => void act(async () => {
    const blob = await postBlob("/api/backup/export-capsule");
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = "kypassword.kycap";
    anchor.click();
    URL.revokeObjectURL(href);
    setMessage("Downloaded sealed capsule.");
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

      {depositReply ? <BackupDepositResult reply={depositReply} /> : null}
      {message ? <div role="status" className="field-card" style={{ color: "var(--success)", marginBottom: "1rem" }}><CheckCircle2 size={16} /> {message}</div> : null}
      {error ? (
        <div role="alert" className="field-card" style={{ color: "var(--danger)", marginBottom: "1rem" }}>
          {error}
          {error.startsWith("re-authenticate") ? <> <a href="/api/auth/oidc/login">Sign in again</a></> : null}
        </div>
      ) : null}

      <div className="field-card" style={{ marginBottom: "1rem" }}>
        <h4 style={{ marginTop: 0 }}>Pairing status</h4>
        <p>
          <strong>{status?.error ? "Recovery configuration needs attention" : status?.paired ? "Paired and healthy" : status?.keyHealthy ? "Key pinned; remote not paired" : "No recovery key"}</strong>
        </p>
        {status?.recoveryKeyId ? <p className="font-mono" style={{ overflowWrap: "anywhere" }}>Key: {status.recoveryKeyId}</p> : null}
        {status?.threshold ? <p>Custodians: {status.threshold} of {status.totalShares}</p> : null}
        {status?.lastDeposit ? (
          <p className="font-mono" style={{ overflowWrap: "anywhere" }}>
            Last deposit: {status.lastDeposit.capsule_id} at {new Date(status.lastDeposit.deposited_at).toLocaleString()}
          </p>
        ) : null}
      </div>

      {status ? <div className="field-card" style={{ marginBottom: "1rem" }}>
        <h4>Backup destinations and schedule</h4>
        {status.error ? <p role="alert">{status.error}</p> : null}
        <p>Local directory: {status.backupDir || "Not configured"}. Copies: {status.localCopies?.length ?? 0}.</p>
        <p>Remote: {status.recoveryUrl || "Not paired"}. Private HTTPS destinations: {status.allowPrivate ? "enabled" : "disabled"}.</p>
        {!status.paired && !status.backupDir ? <p>A key needs a destination: pair with KyRecovery or configure a local backup directory.</p> : null}
        <p>Schedule: {status.intervalSec === 0 ? "Off" : `Every ${status.intervalSec / 60} minutes`}. Next attempt: {status.nextAttempt ? new Date(status.nextAttempt).toLocaleString() : "None"}.</p>
        {status.lastRun ? <div>
          <p>Last attempt: {new Date(status.lastRun.at).toLocaleString()}. Remote deposit: {status.lastRun.deposited ? "confirmed" : "not confirmed"}.</p>
          {status.lastRun.localPath ? <p>Local copy: {status.lastRun.localPath}</p> : null}
          {status.lastRun.localError ? <p role="alert">{status.lastRun.localError}</p> : null}
          {status.lastRun.error ? <p role="alert">{status.lastRun.error}</p> : null}
        </div> : <p>No backup attempt recorded.</p>}
        <form onSubmit={(event) => { event.preventDefault(); void act(async () => {
          await putJSON("/api/backup/schedule", { intervalSec: intervalMinutes * 60 });
          setMessage("Backup schedule saved.");
        }); }}>
          <label htmlFor="backup-interval">Interval in minutes (0 turns the schedule off; otherwise 15–527040)</label>
          <input id="backup-interval" className="input" type="number" min={0} max={527040} step={1} required value={intervalMinutes}
            onChange={(event) => setIntervalMinutes(Number(event.target.value))} />
          <button className="btn btn-secondary" disabled={busy || (intervalMinutes > 0 && intervalMinutes < 15)}>Save schedule</button>
        </form>
      </div> : null}

      <form className="field-card" style={{ marginBottom: "1rem" }} onSubmit={(event) => {
        event.preventDefault(); void act(async () => {
          await postJSON("/api/backup/pin-key", { publicKey, threshold, totalShares });
          setPublicKey(""); setMessage("Recovery public key pinned. Compare its fingerprint with the ceremony page.");
        });
      }}>
        <h4>Pin the suite public key by hand</h4>
        <p>Paste the public key from the ceremony page. Custodian shares and private keys stay with the custodians.</p>
        <label htmlFor="recovery-public-key">Public key (base64)</label>
        <textarea id="recovery-public-key" className="input font-mono" required value={publicKey} onChange={(event) => setPublicKey(event.target.value)} />
        <label htmlFor="recovery-threshold">Required custodians</label>
        <input id="recovery-threshold" className="input" type="number" min={2} max={totalShares} required value={threshold} onChange={(event) => setThreshold(Number(event.target.value))} />
        <label htmlFor="recovery-total">Total custodians</label>
        <input id="recovery-total" className="input" type="number" min={threshold} max={255} required value={totalShares} onChange={(event) => setTotalShares(Number(event.target.value))} />
        <button className="btn btn-secondary" disabled={busy}>Pin public key</button>
      </form>

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

      {status?.recoveryUrl ? <div className="field-card" style={{ marginBottom: "1rem" }}>
        <p>Unpair removes the remote URL and token. The pinned key, receipts and local copies stay. A KyRecovery administrator must separately revoke the token there.</p>
        <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => {
          if (window.confirm("Remove the remote pairing while keeping the key, receipts and local copies? Ask a KyRecovery administrator to revoke the token there.")) {
            void act(async () => { await deleteJSON("/api/backup/pairing"); setMessage("Remote pairing removed. Local backups remain available."); });
          }
        }}>Unpair KyRecovery</button>
      </div> : null}
      <div className="field-card">
        <h4 style={{ marginTop: 0 }}>Recovery operations</h4>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
          <button className="btn btn-primary" type="button" onClick={deposit} disabled={busy || !status?.keyHealthy}><Send size={16} /> Back up now</button>
          {status?.keyHealthy ? (
            <button className="btn btn-secondary" type="button" onClick={download} disabled={busy}><Download size={16} /> Download .kycap</button>
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
