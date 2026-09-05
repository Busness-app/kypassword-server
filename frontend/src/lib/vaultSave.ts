import { HttpError, requestJSON, toErrorMessage } from "./api";
import type { KeePassVault } from "./kdbx";

export type SaveState =
  | { kind: "saved"; version: number }
  | { kind: "saving"; version: number }
  | { kind: "error"; version: number; message: string };

export async function uploadVault(binary: ArrayBuffer, version: number, passwordEnvelope?: string, signal?: AbortSignal): Promise<number> {
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "If-Match": `"${version}"`,
  };
  if (passwordEnvelope) headers["X-Password-Envelope"] = passwordEnvelope;
  const data = await requestJSON<unknown>("/api/vault/upload", { method: "POST", headers, body: binary, signal });
  if (typeof data !== "object" || data === null || !("metadata" in data) ||
      typeof data.metadata !== "object" || data.metadata === null || !("version" in data.metadata) ||
      typeof data.metadata.version !== "number" || !Number.isSafeInteger(data.metadata.version) || data.metadata.version <= version) {
    throw new Error("The server did not confirm the saved vault version.");
  }
  return data.metadata.version;
}

// Security actions may proceed in every save state; only the user's refusal cancels them.
export function canDiscardVault(state: SaveState, hasDraft: boolean, confirmDiscard: () => boolean): boolean {
  return (!hasDraft && state.kind === "saved") || confirmDiscard();
}

// One queue per unlocked vault; a successful upload only acknowledges its starting revision.
export class VaultSaveQueue {
  private revision = 0;
  private savedRevision = 0;
  private running = false;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private controller = new AbortController();
  private listeners = new Set<() => void>();
  private state: SaveState;
  private exporting: Promise<unknown> = Promise.resolve();

  constructor(private vault: KeePassVault | null, version: number) {
    this.state = { kind: "saved", version };
  }

  // Downloads and uploads share the same mutable KDBX serializer.
  exportBinary = (): Promise<ArrayBuffer> => {
    const result = this.exporting.then(() => {
      if (!this.vault) throw new Error("Vault is locked.");
      return this.vault.exportBinary();
    });
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

  // Explicitly discarding cancels debounce, aborts transport, and prevents later revisions
  // from uploading after a new unlock/session. A request already accepted cannot be undone.
  discard = (): void => {
    clearTimeout(this.timer);
    this.controller.abort();
    this.vault = null;
    this.listeners.clear();
  };

  changed = (): void => {
    if (this.controller.signal.aborted) return;
    this.revision++;
    // Failed uploads stop automatic retries, including conflicts. Retry is explicit.
    if (this.state.kind === "error" || this.running) return;
    clearTimeout(this.timer);
    this.publish({ kind: "saving", version: this.state.version });
    this.timer = setTimeout(() => { void this.save(); }, 1500);
  };

  save = async (): Promise<void> => {
    clearTimeout(this.timer);
    if (this.controller.signal.aborted || this.running || this.revision === this.savedRevision) return;
    this.running = true;
    this.publish({ kind: "saving", version: this.state.version });
    try {
      while (this.savedRevision < this.revision) {
        const revision = this.revision;
        const binary = await this.exportBinary();
        if (this.controller.signal.aborted) return;
        const version = await uploadVault(binary, this.state.version, undefined, this.controller.signal);
        if (this.controller.signal.aborted) return;
        this.savedRevision = revision;
        this.publish({ kind: this.savedRevision === this.revision ? "saved" : "saving", version });
      }
    } catch (err) {
      if (this.controller.signal.aborted) return;
      this.publish({ kind: "error", version: this.state.version, message:
        err instanceof HttpError && err.status === 409
          ? "A newer vault exists on the server. Your edits are unsaved here. Download this copy before reloading to compare changes."
          : toErrorMessage(err, "Unable to save vault. Your edits are still here.") });
    } finally {
      this.running = false;
    }
  };
}
