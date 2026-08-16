import React, { useState, useEffect } from "react";
import { getJSON, postJSON, putJSON, toErrorMessage } from "./lib/api";
import { KeePassVault } from "./lib/kdbx";
import {
  generateVaultMasterKey,
  wrapVaultKey,
  unwrapVaultKey,
} from "./lib/vaultCrypto";
import { LoginPage } from "./pages/LoginPage";
import { VaultPage } from "./pages/VaultPage";
import { SecuritySettings } from "./pages/SecuritySettings";
import { AdminPanel } from "./pages/AdminPanel";
import { Shield, KeyRound, Settings, LogOut, Lock, CheckCircle2 } from "lucide-react";
import "./styles/styles.css";

type User = {
  id: string;
  username: string;
  role: "admin" | "user";
  active: boolean;
  ssoSub?: string;
  ssoUsername?: string;
  ssoEmail?: string;
};

type VaultMetadata = {
  version: number;
  checksum: string;
  sizeBytes: number;
  passwordEnvelope?: string;
  recoveryEnvelope?: string;
};

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [navTab, setNavTab] = useState<"vault" | "security" | "admin">("vault");

  // Vault state
  const [vault, setVault] = useState<KeePassVault | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [vaultVersion, setVaultVersion] = useState<number>(0);
  const [vaultMetadata, setVaultMetadata] = useState<VaultMetadata | null>(null);

  // SSO unlock modal state
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [unlocking, setUnlocking] = useState(false);

  // Check auth on load
  const checkAuth = async () => {
    try {
      const res = await getJSON<{ authenticated: boolean; user?: User }>("/api/auth/me");
      if (res.authenticated && res.user) {
        setUser(res.user);
        await initVault(res.user);
      } else {
        setUser(null);
        setVault(null);
        setVaultKey(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const initVault = async (u: User, masterPassword?: string) => {
    try {
      const meta = await getJSON<VaultMetadata>("/api/vault/metadata");
      setVaultMetadata(meta);
      setVaultVersion(meta.version || 0);

      // Case 1: Brand new vault (version 0)
      if (!meta.version || meta.version === 0) {
        if (!masterPassword) {
          setShowUnlockModal(true);
          return;
        }

        const key = generateVaultMasterKey();
        setVaultKey(key);

        const newVault = await KeePassVault.createNew(key, `${u.username}'s Vault`);
        setVault(newVault);

        // Export and save initial version 1
        const binary = await newVault.exportBinary();
        const pwEnvelope = await wrapVaultKey(key, masterPassword);

        const uploadRes = await fetch("/api/vault/upload", {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "If-Match": "0",
            "X-Password-Envelope": pwEnvelope,
          },
          body: binary,
        });

        if (uploadRes.ok) {
          const upMeta = (await uploadRes.json()).metadata;
          setVaultVersion(upMeta.version);
        }
        return;
      }

      // Case 2: Existing vault on server
      if (!masterPassword) {
        // Need user to enter master password or recovery code to unlock envelope
        setShowUnlockModal(true);
        return;
      }

      // We have password & envelope: unwrap key
      let key: Uint8Array;
      if (meta.passwordEnvelope) {
        key = await unwrapVaultKey(meta.passwordEnvelope, masterPassword);
      } else if (meta.recoveryEnvelope) {
        key = await unwrapVaultKey(meta.recoveryEnvelope, masterPassword);
      } else {
        throw new Error("No key envelopes found on server metadata");
      }

      setVaultKey(key);

      // Download encrypted KDBX
      const kdbxRes = await fetch("/api/vault/kdbx", { credentials: "same-origin" });
      if (!kdbxRes.ok) throw new Error("Failed to download encrypted vault");
      const kdbxBytes = await kdbxRes.arrayBuffer();

      // Open zero-knowledge vault client-side
      const loadedVault = await KeePassVault.open(kdbxBytes, key);
      setVault(loadedVault);
      setShowUnlockModal(false);
    } catch (err) {
      console.error("Vault init error:", err);
      setUnlockError(toErrorMessage(err, "Failed to unlock vault"));
      setShowUnlockModal(true);
    }
  };

  const handleLoginSuccess = async (u: User, password?: string) => {
    setUser(u);
    await initVault(u, password);
  };

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setUnlocking(true);
    setUnlockError("");

    try {
      await initVault(user, unlockPassword);
      setUnlockPassword("");
      setShowUnlockModal(false);
    } catch (err) {
      setUnlockError(toErrorMessage(err, "Incorrect password or recovery key"));
    } finally {
      setUnlocking(false);
    }
  };

  const handleSaveVault = async () => {
    if (!vault || !vaultKey) return;
    const binary = await vault.exportBinary();

    const uploadRes = await fetch("/api/vault/upload", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "If-Match": `"${vaultVersion}"`,
      },
      body: binary,
    });

    if (!uploadRes.ok) {
      if (uploadRes.status === 409) {
        alert("A newer version of your vault exists on the server. Your save has been preserved as a conflict.");
        return;
      }
      throw new Error(await uploadRes.text());
    }

    const data = await uploadRes.json();
    setVaultVersion(data.metadata.version);
  };

  const handleExportKdbx = async () => {
    if (!vault) return;
    const binary = await vault.exportBinary();
    const blob = new Blob([binary], { type: "application/x-keepass2" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${user?.username || "vault"}.kdbx`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleLogout = async () => {
    try {
      await postJSON("/api/auth/logout", {});
    } catch {}
    setUser(null);
    setVault(null);
    setVaultKey(null);
  };

  const handleLockVault = () => {
    setVault(null);
    setVaultKey(null);
    setShowUnlockModal(true);
  };

  if (loading) {
    return (
      <div className="auth-container">
        <p style={{ color: "var(--accent)" }}>Loading KyPasswords…</p>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="app-container">
      {/* Navbar */}
      <header className="app-nav">
        <a href="/" className="nav-brand">
          <img src="/logo.png" alt="KyPasswords" />
          <span>KyPasswords</span>
        </a>

        <div className="nav-links">
          <button
            className={`nav-link-btn ${navTab === "vault" ? "active" : ""}`}
            onClick={() => setNavTab("vault")}
          >
            <Shield size={16} /> Vault
          </button>
          <button
            className={`nav-link-btn ${navTab === "security" ? "active" : ""}`}
            onClick={() => setNavTab("security")}
          >
            <KeyRound size={16} /> Security
          </button>
          {user.role === "admin" ? (
            <button
              className={`nav-link-btn ${navTab === "admin" ? "active" : ""}`}
              onClick={() => setNavTab("admin")}
            >
              <Settings size={16} /> Admin
            </button>
          ) : null}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <span style={{ fontSize: "0.85rem", color: "var(--ink-muted)" }}>
            {user.username}
          </span>
          <button className="btn btn-quiet btn-sm" onClick={handleLockVault} title="Lock Vault">
            <Lock size={16} /> Lock
          </button>
          <button className="btn btn-quiet btn-sm" onClick={handleLogout} title="Log Out">
            <LogOut size={16} />
          </button>
        </div>
      </header>

      {/* Main Content View */}
      {vault ? (
        navTab === "vault" ? (
          <VaultPage
            vault={vault}
            vaultVersion={vaultVersion}
            onSave={handleSaveVault}
            onExport={handleExportKdbx}
            onReload={() => initVault(user)}
          />
        ) : navTab === "security" && vaultKey ? (
          <SecuritySettings
            user={user}
            vaultKey={vaultKey}
            onUserUpdated={checkAuth}
          />
        ) : (
          <AdminPanel />
        )
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ textAlign: "center", maxWidth: "400px", padding: "2rem" }}>
            <Lock size={48} color="var(--accent)" style={{ marginBottom: "1rem" }} />
            <h2>Vault is Locked</h2>
            <p style={{ color: "var(--ink-muted)", marginBottom: "1.5rem" }}>
              Enter your master password or paper recovery code to unlock your encrypted KeePass vault.
            </p>
            <button className="btn btn-primary" onClick={() => setShowUnlockModal(true)}>
              Unlock Vault
            </button>
          </div>
        </div>
      )}

      {/* Unlock Modal for SSO sessions or locked vaults */}
      {showUnlockModal ? (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Unlock KeePass Vault</h3>
            </div>
            <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
              Because KyPasswords enforces end-to-end zero-knowledge encryption, enter your master password or paper recovery code to unseal your vault key.
            </p>

            {unlockError ? (
              <div
                style={{
                  background: "var(--danger-soft)",
                  color: "var(--danger)",
                  padding: "0.75rem",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  marginBottom: "1rem",
                }}
              >
                {unlockError}
              </div>
            ) : null}

            <form onSubmit={handleUnlockSubmit}>
              <div className="input-group">
                <label className="input-label">Master Password or Paper Recovery Key</label>
                <input
                  type="password"
                  className="input font-mono"
                  placeholder="•••••••••••• or KYPASS-XXXX-..."
                  value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
                <button type="button" className="btn btn-secondary" onClick={handleLogout}>
                  Log Out
                </button>
                <button type="submit" className="btn btn-primary" disabled={unlocking || !unlockPassword}>
                  {unlocking ? "Unlocking…" : "Unlock"}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </div>
  );
}
