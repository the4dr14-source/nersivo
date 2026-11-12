// Comunicación con la API de Nersivo. No contiene lógica de presentación.

import { API_BASE, REQUEST_TIMEOUT_MS } from "./config.js";

/** Error de la API con un tipo que la interfaz sabe traducir. */
export class ApiError extends Error {
  /**
   * @param {"invalid_domain" | "network" | "timeout" | "server" | "unavailable" | "limit" | "not_found" | "unauthorized"} kind
   * @param {string} [detail] Mensaje/código del backend ("invalid_domain" y "limit").
   * @param {number | null} [retryAfter] Segundos que indica `Retry-After` en un 429 (o null si no se pudo leer).
   */
  constructor(kind, detail = "", retryAfter = null) {
    super(kind);
    this.kind = kind;
    this.detail = detail;
    this.retryAfter = retryAfter;
  }
}

/**
 * Analiza un dominio llamando a GET /analyze/{domain}.
 * @param {string} domain Dominio ya normalizado.
 * @returns {Promise<import("./types.js").AnalyzeResponse>}
 */
export async function analyzeDomain(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const url = `${API_BASE}/analyze/${encodeURIComponent(domain)}`;

  let response;
  try {
    response = await fetch(url, { signal: controller.signal, headers: { Accept: "application/json" } });
  } catch (err) {
    console.error("[Nersivo] Error de red al llamar a la API:", err);
    throw new ApiError(err && err.name === "AbortError" ? "timeout" : "network");
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 400) {
    let detail = "";
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch (_) { /* sin detalle */ }
    throw new ApiError("invalid_domain", detail);
  }

  if (!response.ok) {
    console.error("[Nersivo] La API respondió con HTTP", response.status);
    throw new ApiError("server");
  }

  try {
    return await response.json();
  } catch (err) {
    console.error("[Nersivo] Respuesta de la API no válida:", err);
    throw new ApiError("server");
  }
}

// ---------------------------------------------------------------------------
// Guías y monitorización (endpoints nuevos; /analyze no cambia)
// ---------------------------------------------------------------------------

const AUX_TIMEOUT_MS = 20_000;

/**
 * Segundos de la cabecera `Retry-After` (solo la forma numérica). Devuelve null si falta,
 * no es un entero positivo o el navegador no la expone (CORS sin `expose_headers`).
 */
export function parseRetryAfter(value) {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!/^\d{1,6}$/.test(text)) return null;
  const seconds = Number(text);
  return seconds > 0 ? seconds : null;
}

/** Petición JSON genérica para los endpoints auxiliares. Devuelve el cuerpo ya parseado. */
async function requestJson(path, { method = "GET", body, headers = {} } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AUX_TIMEOUT_MS);
  const init = { method, signal: controller.signal, headers: { Accept: "application/json", ...headers } };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch (err) {
    console.error("[Nersivo] Error de red al llamar a la API:", err);
    throw new ApiError(err && err.name === "AbortError" ? "timeout" : "network");
  } finally {
    clearTimeout(timer);
  }

  let data = null;
  try { data = await response.json(); } catch (_) { /* sin cuerpo JSON */ }
  const detail = data && typeof data.detail === "string" ? data.detail : "";

  if (response.ok) {
    if (data === null) throw new ApiError("server");
    return data;
  }
  if (response.status === 400) throw new ApiError("invalid_domain", detail);
  if (response.status === 401) throw new ApiError("unauthorized");
  if (response.status === 404) throw new ApiError("not_found");
  if (response.status === 429) {
    throw new ApiError("limit", detail, parseRetryAfter(response.headers.get("Retry-After")));
  }
  if (response.status === 503) throw new ApiError("unavailable");
  console.error("[Nersivo] La API respondió con HTTP", response.status);
  throw new ApiError("server");
}

/**
 * Guías «Cómo solucionarlo» de un análisis ya realizado (POST /guides).
 * @param {import("./types.js").AnalyzeResponse} analysis Respuesta de /analyze tal cual.
 */
export function fetchGuides(analysis) {
  return requestJson("/guides", { method: "POST", body: analysis });
}

/** Activa la monitorización. Devuelve `{ token, monitor }`. */
export function activateMonitor(domain) {
  return requestJson("/monitor", { method: "POST", body: { domain } });
}

/** Estado de la monitorización asociada a un token. */
export function getMonitor(token) {
  return requestJson("/monitor", { headers: { "X-Monitor-Token": token } });
}

/** Desactiva la monitorización asociada a un token. */
export function deactivateMonitor(token) {
  return requestJson("/monitor", { method: "DELETE", headers: { "X-Monitor-Token": token } });
}
