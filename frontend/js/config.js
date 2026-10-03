// Configuración del frontend de Nersivo.
//
// La API se busca por defecto en el mismo host que sirve esta página, puerto 8000
// (el puerto con el que se arranca el backend FastAPI en local).
// Para apuntar a otra API, define antes de cargar main.js:
//   <script>window.NERSIVO_API_BASE = "https://api.ejemplo.com";</script>

const fromWindow = typeof window !== "undefined" ? window.NERSIVO_API_BASE : undefined;
const hostname = (typeof location !== "undefined" && location.hostname) || "localhost";

export const API_BASE = (fromWindow || `http://${hostname}:8000`).replace(/\/+$/, "");

/** Tiempo máximo de espera de un análisis (ms). */
export const REQUEST_TIMEOUT_MS = 90_000;
