export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(`request failed: ${status} - ${message}`);
    this.name = "HttpError";
  }
}

async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body && typeof options.body === "string") {
    headers.set("Content-Type", "application/json");
  }

  // Double-submit CSRF protection
  const csrfMatch = document.cookie.match(/csrf_token=([^;]+)/);
  if (csrfMatch && !headers.has("X-CSRF-Token")) {
    headers.set("X-CSRF-Token", csrfMatch[1]);
  }

  const res = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
  });

  if (!res.ok) {
    const text = await res.text();
    throw new HttpError(res.status, text || res.statusText);
  }

  return res;
}

export async function requestJSON<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await request(path, options);

  if (res.status === 204) {
    return {} as T;
  }

  return res.json() as Promise<T>;
}

export async function postBlob(path: string): Promise<Blob> {
  const res = await request(path, { method: "POST" });
  return res.blob();
}

export function getJSON<T>(path: string): Promise<T> {
  return requestJSON<T>(path, { method: "GET" });
}

export function postJSON<T>(path: string, body: unknown): Promise<T> {
  return requestJSON<T>(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function putJSON<T>(path: string, body: unknown): Promise<T> {
  return requestJSON<T>(path, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export function deleteJSON<T>(path: string): Promise<T> {
  return requestJSON<T>(path, { method: "DELETE" });
}

export function toErrorMessage(err: unknown, fallback = "An error occurred"): string {
  if (err instanceof Error) {
    const prefix = "request failed: ";
    if (err.message.startsWith(prefix)) {
      const idx = err.message.indexOf(" - ");
      if (idx !== -1) {
        return err.message.slice(idx + 3);
      }
    }
    return err.message;
  }
  return fallback;
}
