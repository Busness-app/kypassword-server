import React, { useState, useEffect, FormEvent } from "react";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../lib/api";
import { Users, Shield, ScrollText, CheckCircle2, AlertCircle, Plus, ShieldCheck } from "lucide-react";

type User = {
  id: string;
  username: string;
  role: "admin" | "user";
  active: boolean;
  ssoSub?: string;
};

type SSOSettings = {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  autoProvision: boolean;
};

type AuditEntry = {
  index: number;
  timestamp: string;
  action: string;
  userId: string;
  deviceId: string;
  ipAddress: string;
  details: string;
  hash: string;
};

export function AdminPanel() {
  const [activeTab, setActiveTab] = useState<"sso" | "users" | "audit">("sso");
  const [usersList, setUsersList] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);

  const [ssoSettings, setSsoSettings] = useState<SSOSettings>({
    enabled: false,
    issuerUrl: "",
    clientId: "",
    clientSecret: "",
    autoProvision: true,
  });

  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "user">("user");
  const [showAddUser, setShowAddUser] = useState(false);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const loadData = async () => {
    try {
      const [u, s, a, v] = await Promise.all([
        getJSON<User[]>("/api/admin/users"),
        getJSON<SSOSettings>("/api/admin/sso"),
        getJSON<AuditEntry[]>("/api/audit?limit=50"),
        getJSON<{ valid: boolean }>("/api/audit/verify"),
      ]);
      setUsersList(u || []);
      setSsoSettings(s);
      setAuditLogs(a || []);
      setAuditValid(v.valid);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to load admin data"));
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveSSO = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");

    try {
      await putJSON("/api/admin/sso", ssoSettings);
      setMessage("SSO settings saved successfully.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to save SSO settings"));
    } finally {
      setBusy(false);
    }
  };

  const applyKySignOnPreset = () => {
    setSsoSettings((prev) => ({
      ...prev,
      enabled: true,
      issuerUrl: "https://auth.urlxl.com",
      clientId: "kypasswords",
      autoProvision: true,
    }));
  };

  const handleCreateUser = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");

    try {
      const newUser = await postJSON<User>("/api/admin/users", {
        username: newUsername,
        password: newPassword,
        role: newRole,
      });
      setUsersList((prev) => [...prev, newUser]);
      setShowAddUser(false);
      setNewUsername("");
      setNewPassword("");
      setMessage(`User "${newUser.username}" created.`);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to create user"));
    } finally {
      setBusy(false);
    }
  };

  const handleToggleDeactivate = async (u: User) => {
    const action = u.active ? "deactivate" : "reactivate";
    if (!confirm(`${action === "deactivate" ? "Deactivate" : "Reactivate"} user "${u.username}"?`)) return;

    try {
      await postJSON(`/api/admin/users/${u.id}/${action}`, {});
      setUsersList((prev) =>
        prev.map((item) => (item.id === u.id ? { ...item, active: !u.active } : item))
      );
      setMessage(`User ${action}d.`);
    } catch (err) {
      setError(toErrorMessage(err, `Failed to ${action} user`));
    }
  };

  return (
    <div style={{ maxWidth: "1000px", margin: "2rem auto", padding: "0 1rem" }}>
      <div style={{ marginBottom: "2rem" }}>
        <h2>System Administration</h2>
        <p style={{ color: "var(--ink-muted)" }}>
          Manage instance settings, Single Sign-On, user accounts, and audit trails.
        </p>
      </div>

      <div style={{ display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--line)", marginBottom: "2rem" }}>
        <button
          className={`nav-link-btn ${activeTab === "sso" ? "active" : ""}`}
          onClick={() => setActiveTab("sso")}
        >
          <Shield size={16} /> Single Sign-On (SSO)
        </button>
        <button
          className={`nav-link-btn ${activeTab === "users" ? "active" : ""}`}
          onClick={() => setActiveTab("users")}
        >
          <Users size={16} /> User Directory ({usersList.length})
        </button>
        <button
          className={`nav-link-btn ${activeTab === "audit" ? "active" : ""}`}
          onClick={() => setActiveTab("audit")}
        >
          <ScrollText size={16} /> Tamper-Evident Audit Log
        </button>
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

      {activeTab === "sso" ? (
        <div className="field-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
            <div>
              <h3 style={{ margin: "0 0 0.25rem 0" }}>OIDC Provider Configuration</h3>
              <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", margin: 0 }}>
                Configure KySignOn, Authentik, Keycloak, or any OpenID Connect IdP.
              </p>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={applyKySignOnPreset}>
              + KySignOn Preset
            </button>
          </div>

          <form onSubmit={handleSaveSSO}>
            <div className="input-group">
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={ssoSettings.enabled}
                  onChange={(e) => setSsoSettings({ ...ssoSettings, enabled: e.target.checked })}
                />
                <strong>Enable Single Sign-On (SSO)</strong>
              </label>
            </div>

            <div className="input-group">
              <label className="input-label">Issuer URL</label>
              <input
                type="url"
                className="input font-mono"
                placeholder="https://auth.urlxl.com"
                value={ssoSettings.issuerUrl}
                onChange={(e) => setSsoSettings({ ...ssoSettings, issuerUrl: e.target.value })}
                required={ssoSettings.enabled}
              />
              <span style={{ fontSize: "0.75rem", color: "var(--ink-muted)", marginTop: "0.25rem", display: "block" }}>
                Must support standard <code>.well-known/openid-configuration</code> auto-discovery.
              </span>
            </div>

            <div className="input-group">
              <label className="input-label">Client ID</label>
              <input
                type="text"
                className="input font-mono"
                placeholder="kypasswords"
                value={ssoSettings.clientId}
                onChange={(e) => setSsoSettings({ ...ssoSettings, clientId: e.target.value })}
                required={ssoSettings.enabled}
              />
            </div>

            <div className="input-group">
              <label className="input-label">Client Secret (optional for PKCE)</label>
              <input
                type="password"
                className="input font-mono"
                placeholder="••••••••••••"
                value={ssoSettings.clientSecret || ""}
                onChange={(e) => setSsoSettings({ ...ssoSettings, clientSecret: e.target.value })}
              />
            </div>

            <div className="input-group">
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.9rem" }}>
                <input
                  type="checkbox"
                  checked={ssoSettings.autoProvision}
                  onChange={(e) => setSsoSettings({ ...ssoSettings, autoProvision: e.target.checked })}
                />
                Auto-provision new accounts upon successful SSO authentication
              </label>
            </div>

            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Saving…" : "Save SSO Settings"}
            </button>
          </form>
        </div>
      ) : activeTab === "users" ? (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
            <h3 style={{ margin: 0 }}>Registered User Accounts</h3>
            <button className="btn btn-primary btn-sm" onClick={() => setShowAddUser(true)}>
              <Plus size={14} /> Add User
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {usersList.map((u) => (
              <div
                key={u.id}
                style={{
                  background: "var(--panel)",
                  border: "1px solid var(--line)",
                  borderRadius: "6px",
                  padding: "0.75rem 1.25rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span style={{ fontWeight: 600 }}>{u.username}</span>
                    <span className={`badge ${u.role === "admin" ? "badge-cyan" : "badge-green"}`}>
                      {u.role}
                    </span>
                    {!u.active ? <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>Disabled</span> : null}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.25rem" }}>
                    ID: <code>{u.id}</code> {u.ssoSub ? `• Linked SSO: ${u.ssoSub}` : ""}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleToggleDeactivate(u)}
                  >
                    {u.active ? "Deactivate" : "Reactivate"}
                  </button>
                </div>
              </div>
            ))}
          </div>

          {showAddUser ? (
            <div className="modal-overlay" onClick={() => setShowAddUser(false)}>
              <div className="modal-card" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h3>Create New User</h3>
                  <button className="btn btn-quiet btn-sm" onClick={() => setShowAddUser(false)}>
                    ✕
                  </button>
                </div>
                <form onSubmit={handleCreateUser}>
                  <div className="input-group">
                    <label className="input-label">Username</label>
                    <input
                      type="text"
                      className="input"
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      required
                    />
                  </div>
                  <div className="input-group">
                    <label className="input-label">Initial Password</label>
                    <input
                      type="password"
                      className="input"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                    />
                  </div>
                  <div className="input-group">
                    <label className="input-label">Role</label>
                    <select
                      className="select"
                      value={newRole}
                      onChange={(e) => setNewRole(e.target.value as "admin" | "user")}
                    >
                      <option value="user">Standard User</option>
                      <option value="admin">Administrator</option>
                    </select>
                  </div>
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
                    <button type="button" className="btn btn-secondary" onClick={() => setShowAddUser(false)}>
                      Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={busy}>
                      Create User
                    </button>
                  </div>
                </form>
              </div>
            </div>
          ) : null}
        </div>
      ) : (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
              <h3 style={{ margin: 0 }}>Cryptographic Audit Chain</h3>
              {auditValid ? (
                <span className="badge badge-green" style={{ display: "flex", alignItems: "center", gap: "0.25rem" }}>
                  <ShieldCheck size={12} /> Chain Verified
                </span>
              ) : (
                <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>
                  <AlertCircle size={12} /> Integrity Warning
                </span>
              )}
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {auditLogs.map((log) => (
              <div
                key={log.index}
                style={{
                  background: "#0d0f14",
                  border: "1px solid var(--line)",
                  borderRadius: "6px",
                  padding: "0.75rem 1rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.85rem",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.3rem" }}>
                  <strong style={{ color: "var(--accent)" }}>{log.action}</strong>
                  <span style={{ color: "var(--ink-muted)", fontSize: "0.75rem" }}>
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                </div>
                <div style={{ color: "var(--ink-strong)", marginBottom: "0.3rem" }}>
                  {log.details || "—"}
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                  IP: {log.ipAddress} • User: {log.userId || "anon"} • Hash: {log.hash.slice(0, 16)}…
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
