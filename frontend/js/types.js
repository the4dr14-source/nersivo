// Tipos (JSDoc) del contrato de la API de Nersivo: GET /analyze/{domain}.
// Reflejan webguard_mvp_v1.json. Este archivo solo contiene documentación.

/** @typedef {"ok" | "warning" | "error" | "unknown"} Status */
/** @typedef {"none" | "low" | "medium" | "high" | "critical" | "unknown"} Severity */
/** @typedef {"web" | "https" | "dns" | "mx" | "spf" | "dmarc"} CheckKey */

/**
 * @typedef {Object} CheckResult
 * @property {Status} status
 * @property {Severity} severity
 * @property {string} title              Título técnico del backend (no se muestra como principal).
 * @property {string} summary
 * @property {boolean} checked
 * @property {Object<string, unknown>} details
 * @property {string | null} [technical_reason]
 * @property {string | null} [recommendation]
 * @property {string | null} [user_message]
 */

/**
 * @typedef {Object} Summary
 * @property {string} headline
 * @property {number} total_checks
 * @property {number} passed
 * @property {number} warnings
 * @property {number} errors
 * @property {number} unknown
 */

/**
 * @typedef {Object} AnalyzeResponse
 * @property {string} domain
 * @property {string} analyzed_at
 * @property {Status} global_status
 * @property {number | null} score       Entero 0-100, o null si hay pocos checks evaluables.
 * @property {Summary} summary
 * @property {Object<CheckKey, CheckResult>} checks
 */

export {};
