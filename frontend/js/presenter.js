// Capa de presentación: traduce los datos técnicos de la API a lenguaje de negocio.
// No hace peticiones ni toca el DOM. Todo lo que devuelve es texto/estructuras
// listas para pintar. No recalcula nada del backend (score, estados, contadores).

/** @typedef {import("./types.js").AnalyzeResponse} AnalyzeResponse */
/** @typedef {import("./types.js").CheckResult} CheckResult */
/** @typedef {import("./types.js").CheckKey} CheckKey */

import { explainCheck, statusHeadline } from "./explanations.js";

/** Orden en que se muestran las comprobaciones. */
export const CHECK_ORDER = /** @type {CheckKey[]} */ (["web", "https", "dns", "mx", "spf", "dmarc"]);

/** Nombre comprensible, término técnico (secundario) y explicación de por qué importa. */
const CHECK_META = {
  web: {
    icon: "globe",
    name: "Funcionamiento de la web",
    technicalLabel: "Web",
  },
  https: {
    icon: "lock",
    name: "Seguridad de la web",
    technicalLabel: "HTTPS",
  },
  dns: {
    icon: "network",
    name: "Configuración del dominio",
    technicalLabel: "DNS",
  },
  mx: {
    icon: "mail",
    name: "Correo electrónico",
    technicalLabel: "MX",
  },
  spf: {
    icon: "shield",
    name: "Protección del correo",
    technicalLabel: "SPF",
  },
  dmarc: {
    icon: "shield-check",
    name: "Protección contra suplantaciones",
    technicalLabel: "DMARC",
  },
};

/** Estados visuales. `unknown` NUNCA se trata como error. */
export const STATUS_META = {
  ok: { label: "Todo correcto", symbol: "✓" },
  warning: { label: "Conviene revisarlo", symbol: "⚠\uFE0E" },
  error: { label: "Hay un problema", symbol: "✕" },
  unknown: { label: "No se ha podido verificar", symbol: "?" },
};

/** Textos de ayuda de los iconos "?". Solo explican; no calculan nada. */
export const HELP = {
  score:
    "Esta puntuación resume el resultado de las comprobaciones realizadas por Nersivo. Una puntuación más alta indica que se han encontrado menos aspectos que requieren atención.",
  states: [
    { label: "Todo correcto", text: "significa que Nersivo ha comprobado este aspecto y no ha encontrado ningún problema relevante." },
    { label: "Conviene revisarlo", text: "indica que hemos detectado algo que conviene revisar para evitar problemas futuros o mejorar la protección de tu negocio. No es necesariamente grave." },
    { label: "Hay un problema", text: "indica que hemos detectado un problema que puede afectar al funcionamiento, la seguridad o el correo de tu negocio y conviene solucionarlo." },
    { label: "No se ha podido verificar", text: "significa que Nersivo no ha podido comprobar este aspecto en este momento. No quiere decir que haya un problema." },
  ],
};

const GLOBAL_META = {
  ok: { symbol: "✓", title: "Todo está correcto", chip: "Todo correcto" },
  warning: { symbol: "⚠\uFE0E", title: "Hay aspectos que conviene revisar", chip: "Conviene revisarlo" },
  error: { symbol: "✕", title: "Hemos detectado problemas que conviene solucionar", chip: "Hay un problema" },
  unknown: { symbol: "?", title: "No hemos podido completar el análisis", chip: "No se ha podido verificar" },
};

function safeStatus(status) {
  return Object.prototype.hasOwnProperty.call(STATUS_META, status) ? status : "unknown";
}

function text(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

/**
 * Resultado general.
 * @param {AnalyzeResponse} data
 */
export function presentGlobal(data) {
  const status = safeStatus(data.global_status);
  return {
    status,
    symbol: GLOBAL_META[status].symbol,
    title: GLOBAL_META[status].title,
    chip: GLOBAL_META[status].chip,
    // El titular del backend (summary.headline) repite el título y usa otros términos para los mismos
    // estados ("problemas que conviene revisar"), así que no se muestra aquí. Sigue en la respuesta de la API.
    subtitle: "",
  };
}

/**
 * Puntuación. Si el backend envía null no se muestra ninguna nota.
 * @param {AnalyzeResponse} data
 */
export function presentScore(data) {
  const score = data.score;
  if (typeof score === "number" && Number.isFinite(score)) {
    const value = Math.max(0, Math.min(100, Math.round(score)));
    return { hasScore: true, value, note: "" };
  }
  return {
    hasScore: false,
    value: null,
    note: "Hemos podido comprobar muy pocos aspectos, así que todavía no podemos darte una puntuación.",
  };
}

/**
 * Contadores del resumen (campos reales de `summary`). Se muestran siempre
 * correctos, por revisar y problemas (aunque sean 0); "sin verificar" solo si hay alguno.
 * @param {AnalyzeResponse} data
 */
export function presentSummary(data) {
  const s = data.summary || {};
  const total = Number(s.total_checks) || CHECK_ORDER.length;
  const n = (v) => Number(v) || 0;
  const plural = (count, one, many) => (count === 1 ? one : many);

  const stats = [
    { status: "ok", count: n(s.passed), label: plural(n(s.passed), "correcto", "correctos") },
    { status: "warning", count: n(s.warnings), label: "por revisar" },
    { status: "error", count: n(s.errors), label: plural(n(s.errors), "problema", "problemas") },
  ];
  if (n(s.unknown) > 0) {
    stats.push({ status: "unknown", count: n(s.unknown), label: "sin verificar" });
  }
  return {
    total,
    intro: `Hemos revisado ${total} aspectos de tu dominio.`,
    stats: stats.map((i) => ({ ...i, symbol: STATUS_META[i.status].symbol })),
  };
}

/**
 * Una comprobación lista para pintar (tarjeta y detalle).
 * Dos niveles: texto para el propietario (found / why / action) y datos técnicos reales.
 * @param {CheckKey} key
 * @param {CheckResult | undefined} result
 * @param {string} [domain]  Solo para personalizar ejemplos (p. ej. info@dominio).
 */
export function presentCheck(key, result, domain = "") {
  const meta = CHECK_META[key];
  const status = safeStatus(result && result.status);
  const safeResult = result || /** @type {CheckResult} */ ({});

  // NIVEL 1 · usuario normal: qué hemos encontrado → por qué importa → qué puedes hacer.
  const e = explainCheck(key, safeResult, status, { domain });
  const found = e.found.length ? e.found : [STATUS_META[status].label];
  const action = e.action && e.action.length ? e.action : null;

  // NIVEL 2 · usuario técnico: textos originales del backend, sin tocar.
  const raw = [text(safeResult.summary), text(safeResult.user_message), text(safeResult.recommendation)];
  const consoleMessages = raw.filter((m, i) => m && raw.indexOf(m) === i);

  return {
    key,
    icon: meta.icon,
    name: meta.name,
    technicalLabel: meta.technicalLabel,
    status,
    statusLabel: STATUS_META[status].label,
    statusSymbol: STATUS_META[status].symbol,
    // Frase de estado (solo «conviene revisarlo» y «hay un problema»); null en el resto.
    headline: statusHeadline(key, safeResult, status),
    found,
    // Texto de la tarjeta: lo encontrado y, solo si hay acción, su primera frase.
    cardMessage: found.join(" "),
    why: e.why,
    action,
    actionPreview: action ? action[0] : null,
    technical: presentTechnicalDetails(key, result),
    consoleMessages,
  };
}

/**
 * Datos técnicos (información secundaria; se muestran en la consola del detalle).
 * @param {CheckKey} key
 * @param {CheckResult | undefined} result
 * @returns {{label: string, value: string}[]}
 */
export function presentTechnicalDetails(key, result) {
  if (!result) return [];
  const rows = [{ label: "CHECK", value: CHECK_META[key].technicalLabel }];
  rows.push({ label: "STATUS", value: String(result.status || "unknown").toUpperCase() });
  if (text(result.technical_reason)) rows.push({ label: "CODE", value: result.technical_reason });
  if (text(result.severity)) rows.push({ label: "SEVERITY", value: result.severity });
  rows.push({ label: "CHECKED", value: result.checked ? "true" : "false" });

  const details = result.details && typeof result.details === "object" ? result.details : {};
  for (const [k, v] of Object.entries(details)) {
    rows.push({ label: k.toUpperCase(), value: formatValue(v) });
  }
  return rows;
}

function formatValue(v) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) {
    if (!v.length) return "—";
    return v.map((x) => (typeof x === "object" && x !== null ? JSON.stringify(x) : String(x))).join("\n");
  }
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/**
 * Todo el resultado listo para pintar.
 * @param {AnalyzeResponse} data
 */
export function presentAnalysis(data) {
  return {
    domain: data.domain,
    analyzedAt: formatDate(data.analyzed_at),
    global: presentGlobal(data),
    score: presentScore(data),
    summary: presentSummary(data),
    help: HELP,
    checks: CHECK_ORDER.map((key) => presentCheck(key, data.checks && data.checks[key], data.domain)),
  };
}

function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat("es-ES", { dateStyle: "long", timeStyle: "short" }).format(d);
}

/** Mensajes amigables para los errores de la API. */
export function presentError(err) {
  const kind = err && err.kind;
  if (kind === "invalid_domain") {
    return { inline: true, message: err.detail || "Ese dominio no parece válido. Revisa que esté bien escrito." };
  }
  if (kind === "timeout") {
    return { inline: false, message: "El análisis está tardando más de lo normal. Inténtalo de nuevo en unos minutos." };
  }
  return { inline: false, message: "Comprueba tu conexión e inténtalo de nuevo." };
}
