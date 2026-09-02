import React, { useState, useEffect } from "react";
import { getJSON } from "../lib/api";
import { ShieldCheck, Lock, AlertTriangle } from "lucide-react";

// KySignOn is the only way in. There is no local password to type here, because the
// master password is not a credential: it unwraps the vault key in your browser, after a
// KySignOn session already exists. That second step lives in the unlock dialog.

export function LoginPage() {
  const [ssoEnabled, setSsoEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    getJSON<{ enabled: boolean }>("/api/auth/sso-config")
      .then((res) => setSsoEnabled(res.enabled))
      .catch(() => setSsoEnabled(false));
  }, []);

  return (
    <div className="auth-container">
      <div className="auth-box">
        <div className="auth-header">
          <img src="/logo.png" alt="KyPasswords" />
          <h1>KyPasswords</h1>
          <p>Zero-Knowledge KeePass Vault &amp; Sync</p>
        </div>

        {ssoEnabled === false ? (
          <div
            style={{
              background: "var(--danger-soft)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--danger)",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              marginBottom: "1.25rem",
              display: "flex",
              gap: "0.6rem",
              alignItems: "flex-start",
            }}
          >
            <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
            <span>
              KySignOn is unavailable, so sign-in is unavailable. Your passwords are not lost — any
              copy of your vault opens in a standard KeePass client. Ask your administrator to check
              the identity provider.
            </span>
          </div>
        ) : null}

        {/* A link with aria-disabled still navigates and still takes focus, so when
            KySignOn is unavailable this becomes a real disabled button instead: the click
            goes nowhere, the control leaves the tab order, and what a screen reader
            announces matches what the control actually does. */}
        {ssoEnabled === false ? (
          <button
            type="button"
            className="btn btn-primary"
            style={{ width: "100%", marginBottom: "1.25rem" }}
            disabled
          >
            <ShieldCheck size={18} /> Sign in with KySignOn
          </button>
        ) : (
          <a
            href="/api/auth/oidc/login"
            className="btn btn-primary"
            style={{ width: "100%", marginBottom: "1.25rem" }}
          >
            <ShieldCheck size={18} /> Sign in with KySignOn
          </a>
        )}

        <div
          style={{
            borderTop: "1px solid var(--line)",
            paddingTop: "1rem",
            color: "var(--ink-muted)",
            fontSize: "0.8rem",
            display: "flex",
            gap: "0.6rem",
            alignItems: "flex-start",
          }}
        >
          <Lock size={16} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
          <span>
            Signing in proves who you are to KySignOn. Your vault is unlocked separately, with a
            master password this server never receives.
          </span>
        </div>
      </div>
    </div>
  );
}
