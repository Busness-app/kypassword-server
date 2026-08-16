import React, { useState, useEffect } from "react";
import QRCode from "qrcode";
import { postJSON, toErrorMessage } from "../lib/api";
import { Smartphone, Laptop, Check, Copy } from "lucide-react";

type Props = {
  onClose: () => void;
};

export function DevicePairingModal({ onClose }: Props) {
  const [pin, setPin] = useState("");
  const [secret, setSecret] = useState("");
  const [qrUrl, setQrUrl] = useState("");
  const [secondsRemaining, setSecondsRemaining] = useState(90);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const fetchPairingCode = async () => {
    try {
      setError("");
      setSecondsRemaining(90);
      const res = await postJSON<{ pin: string; secret: string; expiresAt: string }>("/api/devices/pairing/start", {});
      setPin(res.pin);
      setSecret(res.secret);

      const qrPayload = JSON.stringify({
        server: window.location.origin,
        secret: res.secret,
        pin: res.pin,
      });

      const qr = await QRCode.toDataURL(qrPayload, {
        errorCorrectionLevel: "M",
        margin: 2,
        width: 220,
        color: {
          dark: "#4deeea",
          light: "#0d0f14",
        },
      });
      setQrUrl(qr);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to generate pairing code"));
    }
  };

  useEffect(() => {
    fetchPairingCode();
  }, []);

  useEffect(() => {
    if (secondsRemaining <= 0) return;
    const timer = setInterval(() => {
      setSecondsRemaining((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [secondsRemaining]);

  const copyPIN = () => {
    navigator.clipboard.writeText(pin);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" style={{ textAlign: "center" }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Pair Device or Extension</h3>
          <button className="btn btn-quiet btn-sm" onClick={onClose}>
            ✕
          </button>
        </div>

        <p style={{ color: "var(--ink-muted)", fontSize: "0.9rem", margin: "0 0 1.5rem 0" }}>
          Scan this QR code with the <strong>KyPasswords Mobile App</strong>, or enter the PIN in your <strong>Browser Extension</strong>.
        </p>

        {error ? (
          <p style={{ color: "var(--danger)" }}>{error}</p>
        ) : secondsRemaining > 0 ? (
          <div>
            {qrUrl ? (
              <div
                style={{
                  display: "inline-block",
                  padding: "0.5rem",
                  background: "#0d0f14",
                  border: "1px solid var(--line)",
                  borderRadius: "8px",
                  marginBottom: "1rem",
                }}
              >
                <img src={qrUrl} alt="Pairing QR Code" style={{ display: "block" }} />
              </div>
            ) : null}

            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "1rem",
                background: "#0d0f14",
                border: "1px solid var(--line)",
                padding: "0.75rem 1.5rem",
                borderRadius: "8px",
                maxWidth: "260px",
                margin: "0 auto 1.5rem auto",
              }}
            >
              <span style={{ fontSize: "1.75rem", fontWeight: 700, letterSpacing: "0.25em", color: "var(--accent)" }} className="font-mono">
                {pin}
              </span>
              <button className="btn btn-quiet btn-sm" onClick={copyPIN} title="Copy PIN">
                {copied ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
              </button>
            </div>

            <div style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
              Expires in <strong style={{ color: "var(--accent)" }}>{secondsRemaining}s</strong>
            </div>
          </div>
        ) : (
          <div style={{ padding: "2rem 0" }}>
            <p style={{ color: "var(--ink-muted)", marginBottom: "1rem" }}>Pairing PIN expired.</p>
            <button className="btn btn-primary" onClick={fetchPairingCode}>
              Generate New PIN
            </button>
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "center", gap: "0.5rem" }}>
          <button className="btn btn-secondary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
