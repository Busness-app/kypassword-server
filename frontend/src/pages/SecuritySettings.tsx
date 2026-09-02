import React, { useState, useEffect, FormEvent } from "react";
import { getJSON, putJSON, deleteJSON, toErrorMessage } from "../lib/api";
import { wrapVaultKey, bytesToHex } from "../lib/vaultCrypto";
import { KeyRound, Shield, FileText, Smartphone, Trash2, CheckCircle2, QrCode, Download } from "lucide-react";
import { DevicePairingModal } from "../components/DevicePairingModal";

type Device = {
  id: string;
  name: string;
  platform: string;
  lastSeenAt: string;
  lastIp: string;
};

type Props = {
  user: any;
  vaultKey: Uint8Array;
  onUserUpdated: () => void;
  onForgetDevice?: () => void;
};

export function SecuritySettings({ user, vaultKey, onUserUpdated, onForgetDevice }: Props) {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [devices, setDevices] = useState<Device[]>([]);
  const [paperCode, setPaperCode] = useState<string | null>(null);
  const [ssoConfig, setSsoConfig] = useState<{ enabled: boolean; issuerUrl: string } | null>(null);
  const [showPairing, setShowPairing] = useState(false);
  const [showVaultKey, setShowVaultKey] = useState(false);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const loadDevices = async () => {
    try {
      const list = await getJSON<Device[]>("/api/devices");
      setDevices(list || []);
    } catch {}
  };

  useEffect(() => {
    loadDevices();
    getJSON<{ enabled: boolean; issuerUrl: string }>("/api/auth/sso-config")
      .then((cfg) => setSsoConfig(cfg))
      .catch(() => {});
  }, []);

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("New passwords do not match");
      return;
    }
    setBusy(true);
    setMessage("");
    setError("");

    try {
      // Changing the master password is entirely a re-wrap of the vault key envelope.
      // There is no password on the server to update: it never had one, and the new
      // password is not sent anywhere — only the envelope it encrypts is.
      const newEnvelope = await wrapVaultKey(vaultKey, newPassword);

      await putJSON("/api/vault/envelopes", {
        passwordEnvelope: newEnvelope,
      });

      setMessage("Master password changed and vault key re-wrapped successfully.");
      setNewPassword("");
      setConfirmPassword("");
      onUserUpdated();
    } catch (err) {
      setError(toErrorMessage(err, "Failed to change password"));
    } finally {
      setBusy(false);
    }
  };

  const handleGeneratePaperRecovery = async () => {
    if (!confirm("Generating a new paper recovery code will invalidate any previous paper backup. Proceed?")) return;
    setBusy(true);
    setMessage("");
    setError("");

    try {
      // Generate 16-character alphanumeric code
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      let raw = "";
      for (let i = 0; i < 16; i++) {
        raw += chars[bytes[i] % chars.length];
      }
      const code = `KYPASS-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;

      // The recovery code wraps the vault key and nothing else. It used to also be hashed
      // onto the user record so it could start a session; that made it a second way to
      // authenticate, which SSO-only does not allow. It unlocks the vault, not the site.
      const recoveryEnv = await wrapVaultKey(vaultKey, code);

      await putJSON("/api/vault/envelopes", {
        recoveryEnvelope: recoveryEnv,
      });

      setPaperCode(code);
      setMessage("Paper recovery backup generated. Print or write this down.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to generate paper recovery code"));
    } finally {
      setBusy(false);
    }
  };

  // The vault key in the form KeePassXC will accept. A downloaded .kdbx is encrypted with
  // exactly this string, so without it the "open your vault in any KeePass client" fallback
  // is not actually available to anyone.
  const handleRevealVaultKey = () => {
    if (showVaultKey) {
      setShowVaultKey(false);
      return;
    }
    if (!confirm(
      "Your vault key unlocks everything, on any device, forever — and unlike your master " +
      "password it cannot be changed without re-encrypting the vault. Only reveal it if you " +
      "are printing it for offline recovery, and nobody can see your screen.\n\nShow it?",
    )) return;
    setShowVaultKey(true);
  };

  const handleRevokeDevice = async (id: string, name: string) => {
    if (!confirm(`Revoke access for device "${name}"?`)) return;
    try {
      await deleteJSON(`/api/devices/${id}`);
      setDevices((prev) => prev.filter((d) => d.id !== id));
      setMessage(`Device "${name}" revoked.`);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to revoke device"));
    }
  };

  return (
    <div style={{ maxWidth: "800px", margin: "2rem auto", padding: "0 1rem" }}>
      <div style={{ marginBottom: "2rem" }}>
        <h2>Security & Key Management</h2>
        <p style={{ color: "var(--ink-muted)" }}>
          Manage your zero-knowledge key custody, master password, paper recovery, and paired devices.
        </p>
      </div>

      {message ? (
        <div
          style={{
            background: "var(--success-soft)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            color: "var(--success)",
            padding: "0.75rem 1rem",
            borderRadius: "6px",
            marginBottom: "1.5rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <CheckCircle2 size={16} /> {message}
        </div>
      ) : null}

      {error ? (
        <div
          style={{
            background: "var(--danger-soft)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            color: "var(--danger)",
            padding: "0.75rem 1rem",
            borderRadius: "6px",
            marginBottom: "1.5rem",
          }}
        >
          {error}
        </div>
      ) : null}

      {/* 1. Master Password Change */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <KeyRound size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Change Master Password</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          Your master password is not a login credential — KySignOn handles signing in. It is the
          secret that decrypts your vault key, here in the browser. Changing it re-wraps that key
          envelope client-side; the password itself is never sent, and the KDBX vault is not
          re-encrypted.
        </p>

        <form onSubmit={handleChangePassword}>
          <div className="input-group">
            <label className="input-label">New Master Password</label>
            <input
              type="password"
              className="input"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>
          <div className="input-group">
            <label className="input-label">Confirm New Password</label>
            <input
              type="password"
              className="input"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={busy || !newPassword}>
            {busy ? "Updating…" : "Update Master Password"}
          </button>
        </form>
      </section>

      {/* 2. Paper Recovery Code */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <FileText size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Paper Recovery Code</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          Print or store this paper key in a safe. If you ever forget your master password, this code unlocks your vault key envelope.
        </p>

        {paperCode ? (
          <div
            style={{
              background: "#0d0f14",
              border: "1px solid var(--accent)",
              borderRadius: "8px",
              padding: "1.25rem",
              marginBottom: "1.25rem",
              textAlign: "center",
            }}
          >
            <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginBottom: "0.5rem" }}>
              YOUR EMERGENCY PAPER BACKUP KEY
            </div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700, letterSpacing: "0.1em", color: "var(--accent)" }} className="font-mono">
              {paperCode}
            </div>
          </div>
        ) : null}

        <button className="btn btn-secondary" onClick={handleGeneratePaperRecovery} disabled={busy}>
          Generate Printable Paper Key
        </button>
      </section>

      {/* Offline recovery: the key that opens a downloaded vault in any KeePass client */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <Download size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Offline Vault Key</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          If KySignOn is ever unavailable you can still reach your passwords: download your vault
          and open it in KeePass, KeePassXC or KeePassDX. The file's password is the key below —
          type or paste it exactly. Keep a printed copy somewhere safe, because this server cannot
          show it to you while it is down.
        </p>

        {showVaultKey ? (
          <div
            style={{
              background: "#0d0f14",
              border: "1px solid var(--accent)",
              borderRadius: "8px",
              padding: "1.25rem",
              marginBottom: "1.25rem",
              textAlign: "center",
            }}
          >
            <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginBottom: "0.5rem" }}>
              VAULT KEY — THE PASSWORD FOR YOUR DOWNLOADED .KDBX
            </div>
            <div
              className="font-mono"
              style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--accent)", wordBreak: "break-all" }}
            >
              {bytesToHex(vaultKey)}
            </div>
          </div>
        ) : null}

        <button className="btn btn-secondary" onClick={handleRevealVaultKey}>
          {showVaultKey ? "Hide Vault Key" : "Show Vault Key"}
        </button>
      </section>

      {/* 3. Single Sign-On */}
      {ssoConfig?.enabled ? (
        <section className="field-card" style={{ marginBottom: "2rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
            <Shield size={20} color="var(--accent)" />
            <h3 style={{ margin: 0 }}>Single Sign-On (KySignOn / OIDC)</h3>
          </div>

          <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
            KySignOn is your only way in to KyPasswords, so this identity cannot be unlinked —
            doing so would lock you out for good. Accounts are managed in KySignOn.
          </p>
          <div
            style={{
              background: "var(--accent-soft)",
              border: "1px solid rgba(77, 238, 234, 0.3)",
              borderRadius: "6px",
              padding: "0.75rem 1rem",
            }}
          >
            <strong style={{ color: "var(--accent)" }}>KySignOn Identity</strong>
            <div style={{ fontSize: "0.85rem", color: "var(--ink-muted)", marginTop: "0.25rem" }}>
              Username: <code>{user.ssoUsername || user.username}</code>{" "}
              {user.ssoEmail ? `(${user.ssoEmail})` : ""}
              <br />
              Subject: <code>{user.ssoSub || "—"}</code>
            </div>
          </div>
        </section>
      ) : null}

      {/* Local Device Vault & 1-Click SSO */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <KeyRound size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>This Device & 1-Click SSO</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
          This browser holds your local zero-knowledge encryption key in its secure storage vault to allow instant 1-click SSO access.
        </p>

        {onForgetDevice && (
          <button className="btn btn-danger btn-sm" onClick={onForgetDevice}>
            Forget This Device & Sign Out
          </button>
        )}
      </section>

      {/* 4. Paired Devices */}
      <section className="field-card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Smartphone size={20} color="var(--accent)" />
            <h3 style={{ margin: 0 }}>Paired Devices & Extensions</h3>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => setShowPairing(true)}>
            <QrCode size={14} /> Pair New Device
          </button>
        </div>

        {devices.length === 0 ? (
          <p style={{ color: "var(--ink-muted)", fontSize: "0.9rem" }}>No paired mobile apps or browser extensions.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {devices.map((d) => (
              <div
                key={d.id}
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
                  <div style={{ fontWeight: 600 }}>{d.name}</div>
                  <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.2rem" }}>
                    {d.platform} • Last active: {new Date(d.lastSeenAt).toLocaleString()} ({d.lastIp || "—"})
                  </div>
                </div>
                <button
                  className="btn btn-danger btn-sm"
                  onClick={() => handleRevokeDevice(d.id, d.name)}
                  title="Revoke device"
                >
                  <Trash2 size={14} /> Revoke
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {showPairing ? <DevicePairingModal onClose={() => { setShowPairing(false); loadDevices(); }} /> : null}
    </div>
  );
}
