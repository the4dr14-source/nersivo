// Comunicación con la API de Nersivo. No contiene lógica de presentación.

import { API_BASE, REQUEST_TIMEOUT_MS } from "./config.js";

/** Error de la API con un tipo que la interfaz sabe traducir. */
export class ApiError extends Error {
  /**
   * @param {"invalid_domain" | "network" | "timeout" | "server"} kind
   * @param {string} [detail] Mensaje del backend (solo para "invalid_domain").
   */
  constructor(kind, detail = "") {
    super(kind);
    this.kind = kind;
    this.detail = detail;
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
