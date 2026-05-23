/**
 * Shared HTTP client helpers for talking to the FastAPI backend.
 */
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

/**
 * Convert a failed fetch response into a readable error message.
 */
async function parseError(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      const payload = (await response.json()) as { detail?: string };
      return payload.detail || JSON.stringify(payload);
    } catch {
      return response.statusText || "Unknown API error";
    }
  }

  const message = await response.text();
  return message || response.statusText || "Unknown API error";
}

/**
 * Issue a JSON GET request against the configured API base URL.
 */
export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    const message = await parseError(response);
    throw new Error(`API request failed ${response.status}: ${message}`);
  }

  return response.json();
}

/**
 * Issue a JSON POST request against the configured API base URL.
 */
export async function apiPost<T, U>(path: string, body: T): Promise<U> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const message = await parseError(response);
    throw new Error(`API request failed ${response.status}: ${message}`);
  }

  return response.json();
}
