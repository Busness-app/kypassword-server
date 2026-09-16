export const AUTO_LOCK_MINUTES = [1, 5, 15, 30, 60] as const;
export type AutoLockMinutes = typeof AUTO_LOCK_MINUTES[number];
const settingKey = "kyvault.autoLockMinutes";
const legacySettingKey = "kypassword.autoLockMinutes";

export function parseAutoLockMinutes(value: unknown): AutoLockMinutes {
  for (const minutes of AUTO_LOCK_MINUTES) {
    if (value === minutes || value === String(minutes)) return minutes;
  }
  return 5;
}

export function loadAutoLockMinutes(): AutoLockMinutes {
  try {
    const value = localStorage.getItem(settingKey);
    return parseAutoLockMinutes(value ?? localStorage.getItem(legacySettingKey));
  } catch { return 5; }
}

export function storeAutoLockMinutes(minutes: AutoLockMinutes): void {
  localStorage.setItem(settingKey, String(minutes));
  localStorage.removeItem(legacySettingKey);
}

// Wall time catches suspended devices; monotonic time prevents a clock adjustment
// backwards from postponing the deadline. Check expiry BEFORE accepting new activity.
export class IdleDeadline {
  constructor(
    private timeoutMs: number,
    private wall = Date.now(),
    private monotonic = performance.now(),
  ) {}

  expired(wall = Date.now(), monotonic = performance.now()): boolean {
    return Math.max(wall - this.wall, monotonic - this.monotonic) >= this.timeoutMs;
  }

  activity(wall = Date.now(), monotonic = performance.now()): boolean {
    if (this.expired(wall, monotonic)) return false;
    this.wall = wall;
    this.monotonic = monotonic;
    return true;
  }
}

// A fresh tab has no sessionStorage. Missing/invalid activity must not give an old
// trusted-device key an unlimited lifetime; a backwards clock also requires unlock.
export function cachedKeyExpired(lastActivity: string | null, timeoutMs: number, now = Date.now()): boolean {
  const last = Number(lastActivity);
  return !Number.isFinite(last) || last <= 0 || now < last || now - last >= timeoutMs;
}
