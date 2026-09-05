import { HttpError, requestJSON, toErrorMessage } from "./api";
import type { KeePassVault } from "./kdbx";

export type SaveState =
  | { kind: "saved"; version: number }
  | { kind: "saving"; version: number }
  | { kind: "error"; version: number; message: string };

export async function uploadVault(binary: ArrayBuffer, version: number, passwordEnvelope?: string): Promise<number> {
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "If-Match": `"${version}"`,
  };
  if (passwordEnvelope) headers["X-Password-Envelope"] = passwordEnvelope;
  const data = await requestJSON<unknown>("/api/vault/upload", { method: "POST", headers, body: binary });
  if (typeof data !== "object" || data === null || !("metadata" in data) ||
      typeof data.metadata !== "object" || data.metadata === null || !("version" in data.metadata) ||
      typeof data.metadata.version !== "number" || !Number.isSafeInteger(data.metadata.version) || data.metadata.version <= version) {
    throw new Error("The server did not confirm the saved vault version.");
  }
  return data.metadata.version;
}

// One queue per unlocked vault; a successful upload only acknowledges its starting revision.
export class VaultSaveQueue {
  private revision = 0;
  private savedRevision = 0;
  private running = false;
  private listeners = new Set<() => void>();
  private state: SaveState;
  private exporting: Promise<unknown> = Promise.resolve();

  constructor(private vault: KeePassVault, version: number) {
    this.state = { kind: "saved", version };
  }

  // Downloads and uploads share the same mutable KDBX serializer.
  exportBinary = (): Promise<ArrayBuffer> => {
    const result = this.exporting.then(() => this.vault.exportBinary());
    this.exporting = result.catch(() => {});
    return result;
  };

  getSnapshot = (): SaveState => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  private publish(state: SaveState) {
    this.state = state;
    this.listeners.forEach((listener) => listener());
  }

  changed = (): void => {
    this.revision++;
    // Failed uploads stop automatic retries, including conflicts. Retry is explicit.
    if (this.state.kind !== "error") void this.save();
  };

  save = async (): Promise<void> => {
    if (this.running || this.revision === this.savedRevision) return;
    this.running = true;
    this.publish({ kind: "saving", version: this.state.version });
    try {
      while (this.savedRevision < this.revision) {
        const revision = this.revision;
        const binary = await this.exportBinary();
        const version = await uploadVault(binary, this.state.version);
        this.savedRevision = revision;
        this.publish({ kind: this.savedRevision === this.revision ? "saved" : "saving", version });
      }
    } catch (err) {
      this.publish({ kind: "error", version: this.state.version, message:
        err instanceof HttpError && err.status === 409
          ? "A newer vault exists on the server. Your edits are unsaved here. Download this copy before reloading to compare changes."
          : toErrorMessage(err, "Unable to save vault. Your edits are still here.") });
    } finally {
      this.running = false;
    }
  };
}
