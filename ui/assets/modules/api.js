import { state } from "./runtime.js";

export async function apiOrNull(path) {
  try {
    return await api(path);
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

export async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("X-Actor", state.actor);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof payload === "string" ? payload : payload.detail || payload.message || "Request failed";
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return options.raw ? payload : payload;
}
