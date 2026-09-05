import React, { useState, useEffect, useSyncExternalStore } from "react";
import { getJSON, postJSON, putJSON, toErrorMessage } from "./lib/api";
import { VaultSaveQueue, uploadVault, canDiscardVault, type SaveState } from "./lib/vaultSave";
import { KeePassVault } from "./lib/kdbx";
import {
  generateVaultMasterKey,
  wrapVaultKey,
  unwrapVaultKey,
  bytesToHex,
  hexToBytes,
} from "./lib/vaultCrypto";
import { getDeviceVaultKey, storeDeviceVaultKey, clearDeviceVaultKey } from "./lib/storage";
import { LoginPage } from "./pages/LoginPage";
import { VaultPage } from "./pages/VaultPage";
import { SecuritySettings } from "./pages/SecuritySettings";
import { AdminPanel } from "./pages/AdminPanel";
import { HistoryModal } from "./components/HistoryModal";
import { Shield, KeyRound, Settings, LogOut, Lock, CheckCircle2, History, RotateCcw } from "lucide-react";
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

const idleSave: SaveState = { kind: "saved", version: 0 };
const noSubscribe = () => () => {};
const idleSnapshot = () => idleSave;

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [navTab, setNavTab] = useState<"vault" | "security" | "admin">("vault");

  // Vault state
  const [vault, setVault] = useState<KeePassVault | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [saveQueue, setSaveQueue] = useState<VaultSaveQueue | null>(null);
  const saveState = useSyncExternalStore(saveQueue?.subscribe ?? noSubscribe, saveQueue?.getSnapshot ?? idleSnapshot);
  const [hasDraft, setHasDraft] = useState(false);
  const unsaved = hasDraft || saveState.kind !== "saved";

  useEffect(() => {
    if (!unsaved) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [unsaved]);

  const confirmDiscardVault = () => canDiscardVault(saveState, hasDraft, () =>
    confirm("Some edits are unsaved or still saving. Continue and discard unsaved edits? An upload already accepted by the server cannot be undone."));

  // Replacing or closing a vault must never leave a timer/old upload able to save later.
  useEffect(() => () => { saveQueue?.discard(); }, [saveQueue]);

  // SSO unlock modal state
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
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
        setSaveQueue(null);
        setHasDraft(false);
      }
    } catch {
      setUser(null);
      setVault(null);
      setVaultKey(null);
      setSaveQueue(null);
      setHasDraft(false);
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

      // Case 1: Brand new vault (version 0)
      if (!meta.version || meta.version === 0) {
        if (!masterPassword) {
          setShowUnlockModal(true);
          return;
        }

        const key = generateVaultMasterKey();

        const newVault = await KeePassVault.createNew(key, `${u.username}'s Vault`);

        // Export and save initial version 1
        const binary = await newVault.exportBinary();
        const pwEnvelope = await wrapVaultKey(key, masterPassword);

        const version = await uploadVault(binary, 0, pwEnvelope);
        setSaveQueue(new VaultSaveQueue(newVault, version));
        setVaultKey(key);
        setVault(newVault);
        await storeDeviceVaultKey(u.username, bytesToHex(key));
        setShowUnlockModal(false);
        return;
      }

      // Case 2: Existing vault on server
      let key: Uint8Array | null = null;
      if (masterPassword) {
        if (meta.passwordEnvelope) {
          key = await unwrapVaultKey(meta.passwordEnvelope, masterPassword);
        } else if (meta.recoveryEnvelope) {
          key = await unwrapVaultKey(meta.recoveryEnvelope, masterPassword);
        } else {
          throw new Error("No key envelopes found on server metadata");
        }
        await storeDeviceVaultKey(u.username, bytesToHex(key));
      } else {
        // Check for cached key on this trusted device
        const cachedHex = await getDeviceVaultKey(u.username).catch(() => undefined);
        if (cachedHex) {
          key = hexToBytes(cachedHex);
        } else {
          setShowUnlockModal(true);
          return;
        }
      }

      setVaultKey(key);

      // Download encrypted KDBX
      const kdbxRes = await fetch("/api/vault/kdbx", { credentials: "same-origin" });
      if (!kdbxRes.ok) throw new Error("Failed to download encrypted vault");
      const kdbxBytes = await kdbxRes.arrayBuffer();

      // Open zero-knowledge vault client-side
      const loadedVault = await KeePassVault.open(kdbxBytes, key);
      setSaveQueue(new VaultSaveQueue(loadedVault, meta.version));
      setVault(loadedVault);
      setShowUnlockModal(false);
    } catch (err) {
      console.error("Vault init error:", err);
      setUnlockError(toErrorMessage(err, "Failed to unlock vault"));
      setShowUnlockModal(true);
    }
  };

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setUnlocking(true);
    setUnlockError("");

    try {
      await initVault(user, unlockPassword);
      setUnlockPassword("");
    } catch (err) {
      setUnlockError(toErrorMessage(err, "Incorrect password or recovery key"));
    } finally {
      setUnlocking(false);
    }
  };

  const handleExportKdbx = async () => {
    if (!saveQueue || saveState.kind === "saving") return;
    const binary = await saveQueue.exportBinary();
    const blob = new Blob([binary], { type: "application/x-keepass2" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${user?.username || "vault"}.kdbx`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const closeVault = () => {
    saveQueue?.discard();
    setSaveQueue(null);
    setHasDraft(false);
    setVault(null);
    setVaultKey(null);
    setUnlockPassword("");
    setShowUnlockModal(false);
    setShowHistoryModal(false);
  };

  const logout = async () => {
    closeVault();
    // Clear the visible vault before waiting on a possibly stalled network request.
    await postJSON("/api/auth/logout", {});
    setUser(null);
  };

  const handleLogout = async () => {
    if (!confirmDiscardVault()) return;
    try { await logout(); } catch { alert("Vault locked locally, but server logout failed. Retry signing out when the connection returns."); }
  };

  const handleForgetDevice = async () => {
    if (!confirmDiscardVault()) return;
    const username = user?.username;
    closeVault();
    // Neither storage failure nor a stalled logout may prevent the other action starting.
    const results = await Promise.allSettled([
      username ? clearDeviceVaultKey(username) : Promise.resolve(),
      logout(),
    ]);
    if (results[0].status === "rejected") alert("Could not forget this device. Clear this site's browser data to remove its saved vault key.");
    if (results[1].status === "rejected") alert("Vault locked locally, but server logout failed.");
  };

  const handleLockVault = () => {
    if (!confirmDiscardVault()) return;
    closeVault();
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
    return <LoginPage />;
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

      {/* Keep the editor mounted across tabs so drafts and save status survive navigation. */}
      {vault && saveQueue ? (
        <VaultPage
          vault={vault}
          vaultVersion={saveState.version}
          saveState={saveState}
          onChanged={saveQueue.changed}
          onSave={saveQueue.save}
          onDraftChange={setHasDraft}
          hidden={navTab !== "vault"}
          onExport={handleExportKdbx}
          onReload={() => initVault(user)}
        />
      ) : null}
      {navTab === "admin" && user.role === "admin" ? (
        <AdminPanel />
      ) : vault ? (
        navTab === "security" ? <SecuritySettings
          user={user}
          vaultKey={vaultKey!}
          onUserUpdated={() => { if (confirmDiscardVault()) void checkAuth(); }}
          onForgetDevice={handleForgetDevice}
        /> : null
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ textAlign: "center", maxWidth: "440px", padding: "2rem" }}>
            <Lock size={48} color="var(--accent)" style={{ marginBottom: "1rem" }} />
            <h2>Vault is Locked</h2>
            <p style={{ color: "var(--ink-muted)", marginBottom: "1.5rem" }}>
              Enter your master password or paper recovery code to unlock your encrypted KeePass vault.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <button className="btn btn-primary" onClick={() => setShowUnlockModal(true)}>
                <Lock size={16} /> Unlock Vault
              </button>
              <button className="btn btn-secondary" onClick={() => setShowHistoryModal(true)}>
                <RotateCcw size={16} /> Version History & Rollback
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Unlock Modal for SSO sessions or locked vaults */}
      {showUnlockModal ? (
        <div className="modal-overlay" onClick={() => setShowUnlockModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Unlock KeePass Vault</h3>
              <button className="btn btn-quiet btn-sm" onClick={() => setShowUnlockModal(false)}>
                ✕
              </button>
            </div>
            <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
              You are signed in — KySignOn has proved who you are. Unlocking is separate: your master
              password decrypts the vault here in your browser, and is never sent to the server.
              Enter it once to trust this device for 1-click unlock.
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

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "1rem" }}>
                <button
                  type="button"
                  className="btn btn-quiet btn-sm"
                  onClick={() => {
                    setShowUnlockModal(false);
                    setShowHistoryModal(true);
                  }}
                >
                  <RotateCcw size={14} /> Rollback / History
                </button>
                <div style={{ display: "flex", gap: "0.75rem" }}>
                  <button type="button" className="btn btn-secondary" onClick={() => setShowUnlockModal(false)}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={unlocking || !unlockPassword}>
                    {unlocking ? "Unlocking…" : "Unlock"}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {/* History & Rollback Modal */}
      {showHistoryModal ? (
        <HistoryModal
          onClose={() => setShowHistoryModal(false)}
          onRestored={async () => {
            setShowHistoryModal(false);
            if (user) {
              await initVault(user);
            }
          }}
        />
      ) : null}
    </div>
  );
}
