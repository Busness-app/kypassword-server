import React, { useState, useEffect, FormEvent } from "react";
import { getJSON, postJSON, toErrorMessage } from "../lib/api";
import { deriveAuthSecret } from "../lib/vaultCrypto";
import { ShieldCheck, KeyRound, FileText, ArrowRight, Lock } from "lucide-react";

type Props = {
  onLoginSuccess: (user: any, masterPassword?: string) => void;
};

export function LoginPage({ onLoginSuccess }: Props) {
  const [mode, setMode] = useState<"login" | "recovery" | "setup">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [recoverySecret, setRecoverySecret] = useState("");
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [setupRequired, setSetupRequired] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    // Check initial setup state
    getJSON<{ setupRequired: boolean }>("/api/setup")
      .then((res) => {
        if (res.setupRequired) {
          setSetupRequired(true);
          setMode("setup");
        }
      })
      .catch(() => {});

    // Check SSO availability
    getJSON<{ enabled: boolean }>("/api/auth/sso-config")
      .then((res) => {
        if (res.enabled) setSsoEnabled(true);
      })
      .catch(() => {});
  }, []);

  const handleLoginSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");

    try {
      // 1. Fetch user's KDF params (salt & iterations)
      const params = await getJSON<{ salt: string; iterations: number }>(
        `/api/auth/login-params?username=${encodeURIComponent(username)}`
      );

      // 2. Derive auth secret client-side
      const authSecret = await deriveAuthSecret(password, params.salt, params.iterations);

      // 3. Authenticate with authSecret
      const res = await postJSON<{ ok: boolean; user: any }>("/api/auth/login", {
        username,
        authSecret,
      });

      // Pass master password to parent to unlock client-side vault key envelope
      onLoginSuccess(res.user, password);
    } catch (err) {
      setError(toErrorMessage(err, "Invalid username or password"));
    } finally {
      setBusy(false);
    }
  };

  const handleRecoverySubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");

    try {
      const res = await postJSON<{ ok: boolean; user: any }>("/api/auth/recovery", {
        username,
        recoverySecret: recoverySecret.trim().toUpperCase(),
      });

      onLoginSuccess(res.user, recoverySecret.trim().toUpperCase());
    } catch (err) {
      setError(toErrorMessage(err, "Invalid paper recovery code"));
    } finally {
      setBusy(false);
    }
  };

  const handleSetupSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");

    try {
      const res = await postJSON<{ ok: boolean; user: any }>("/api/setup", {
        username,
        password,
      });
      onLoginSuccess(res.user, password);
    } catch (err) {
      setError(toErrorMessage(err, "Setup failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <div className="auth-header">
          <img src="/logo.png" alt="KyPasswords" />
          <h1>{mode === "setup" ? "Initial Setup" : "KyPasswords"}</h1>
          <p>
            {mode === "setup"
              ? "Create the primary administrator account for this instance."
              : mode === "recovery"
              ? "Unlock vault using your paper recovery code."
              : "Zero-Knowledge KeePass Vault & Sync"}
          </p>
        </div>

        {error ? (
          <div
            style={{
              background: "var(--danger-soft)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--danger)",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              marginBottom: "1.25rem",
            }}
          >
            {error}
          </div>
        ) : null}

        {mode === "setup" ? (
          <form onSubmit={handleSetupSubmit}>
            <div className="input-group">
              <label className="input-label">Administrator Username</label>
              <input
                type="text"
                className="input"
                placeholder="admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="input-group">
              <label className="input-label">Master Password</label>
              <input
                type="password"
                className="input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: "100%" }} disabled={busy}>
              {busy ? "Initializing…" : "Complete Setup & Initialize"}
            </button>
          </form>
        ) : mode === "recovery" ? (
          <form onSubmit={handleRecoverySubmit}>
            <div className="input-group">
              <label className="input-label">Account Username</label>
              <input
                type="text"
                className="input"
                placeholder="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="input-group">
              <label className="input-label">Paper Recovery Code</label>
              <input
                type="text"
                className="input font-mono"
                placeholder="KYPASS-XXXX-XXXX-XXXX"
                value={recoverySecret}
                onChange={(e) => setRecoverySecret(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: "100%", marginBottom: "1rem" }} disabled={busy}>
              {busy ? "Unlocking…" : "Unlock Vault"}
            </button>
            <div style={{ textAlign: "center" }}>
              <button type="button" className="btn btn-quiet btn-sm" onClick={() => setMode("login")}>
                Back to Standard Sign In
              </button>
            </div>
          </form>
        ) : (
          <div>
            {ssoEnabled ? (
              <div style={{ marginBottom: "1.5rem" }}>
                <a
                  href="/api/auth/oidc/login"
                  className="btn btn-primary"
                  style={{
                    width: "100%",
                    marginBottom: "1rem",
                  }}
                >
                  <ShieldCheck size={18} /> Sign in with KySignOn
                </a>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    textAlign: "center",
                    color: "var(--ink)",
                    fontSize: "0.8rem",
                    margin: "1rem 0",
                  }}
                >
                  <div style={{ flex: 1, borderBottom: "1px solid var(--line)" }} />
                  <span style={{ padding: "0 0.5rem" }}>or enter master password</span>
                  <div style={{ flex: 1, borderBottom: "1px solid var(--line)" }} />
                </div>
              </div>
            ) : null}

            <form onSubmit={handleLoginSubmit}>
              <div className="input-group">
                <label className="input-label">Username</label>
                <input
                  type="text"
                  className="input"
                  placeholder="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>

              <div className="input-group">
                <label className="input-label">Master Password</label>
                <input
                  type="password"
                  className="input"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="btn btn-primary" style={{ width: "100%", marginBottom: "1.25rem" }} disabled={busy}>
                {busy ? "Signing in…" : "Sign In & Unlock Vault"}
              </button>
            </form>

            <div style={{ textAlign: "center", borderTop: "1px solid var(--line)", paddingTop: "1rem" }}>
              <button
                type="button"
                className="btn btn-quiet btn-sm"
                onClick={() => setMode("recovery")}
              >
                <FileText size={14} /> Lost Password? Use Paper Recovery
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
