// Configuración del frontend de Nersivo.

const fromWindow = typeof window !== "undefined" ? window.NERSIVO_API_BASE : undefined;
const hostname = (typeof location !== "undefined" && location.hostname) || "localhost";

const defaultApiBase =
  hostname === "localhost" || hostname === "127.0.0.1"
    ? `http://${hostname}:8000`
    : "https://nersivo-backend.onrender.com";

export const API_BASE = (fromWindow || defaultApiBase).replace(/\/+$/, "");

/** Tiempo máximo de espera de un análisis (ms). */
export const REQUEST_TIMEOUT_MS = 90_000;
