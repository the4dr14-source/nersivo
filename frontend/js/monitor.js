// Controlador de la sección «Monitorización»: estado, llamadas a la API y token del navegador.
//
// Sin cuentas de usuario: al activar, la API devuelve un token que se guarda en este navegador
// y sirve para consultar y desactivar. Si el token se pierde, la monitorización sigue en el
// servidor pero este navegador ya no puede gestionarla (limitación del MVP sin cuentas).

import { activateMonitor, ApiError, deactivateMonitor, getMonitor } from "./api.js";
import { clearToken, loadToken, saveToken } from "./monitor-store.js";
import { renderMonitor } from "./monitor-view.js";

/** Espera aproximada en lenguaje natural a partir de `Retry-After` (segundos, o null si se desconoce). */
export function waitHint(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "dentro de unos minutos";
  if (seconds < 60) return "en unos segundos";
  const minutes = Math.ceil(seconds / 60);
  return minutes === 1 ? "en 1 minuto" : `en ${minutes} minutos`;
}

/** Mensajes comprensibles para cada error de la API. */
export function monitorErrorMessage(err, action) {
  if (err instanceof ApiError) {
    if (err.kind === "limit") {
      if (err.detail === "monitor_domain_limit_reached") {
        return "Este dominio ya tiene el máximo de monitorizaciones activas durante la fase de pruebas.";
      }
      if (err.detail === "monitor_rate_limited") {
        return `Has intentado activar la monitorización demasiadas veces seguidas. Vuelve a intentarlo ${waitHint(err.retryAfter)}.`;
      }
      if (err.detail === "monitor_busy") {
        return "Ahora mismo hay muchas comprobaciones en marcha. Inténtalo de nuevo en unos segundos.";
      }
      return "Ahora mismo no podemos aceptar más monitorizaciones durante la fase de pruebas. Inténtalo más adelante.";
    }
    if (err.kind === "unavailable") return "La monitorización no está disponible en este momento. Inténtalo de nuevo en unos minutos.";
    if (err.kind === "invalid_domain") return "No podemos monitorizar este dominio.";
    if (err.kind === "network" || err.kind === "timeout") return "No hemos podido conectar con Nersivo. Comprueba tu conexión e inténtalo de nuevo.";
  }
  return action === "activate"
    ? "No hemos podido activar la monitorización. Inténtalo de nuevo."
    : "No hemos podido completar la operación. Inténtalo de nuevo.";
}

/**
 * Monta la sección de monitorización de un dominio.
 * @param {HTMLElement} slot Contenedor de la sección.
 * @param {string} domain Dominio analizado (normalizado por la API).
 * @param {() => boolean} isStale Devuelve true si ya se muestra otro análisis (se ignora este).
 */
export function mountMonitor(slot, domain, isStale) {
  const state = { phase: "loading", view: null, message: "", confirming: false, busy: false, retry: false };
  slot.hidden = false;

  const render = () => {
    if (isStale()) return;
    renderMonitor(slot, state, { onActivate, onRefresh, onDeactivate, onCancelDeactivate });
  };
  const set = (patch) => { Object.assign(state, patch); render(); };

  async function load() {
    const token = loadToken(domain);
    if (!token) { set({ phase: "idle", view: null, message: "" }); return; }
    try {
      const view = await getMonitor(token);
      if (isStale()) return;
      if (view.status === "active") set({ phase: "active", view, message: "", retry: false });
      else { clearToken(domain); set({ phase: "idle", view: null, message: "" }); }
    } catch (err) {
      if (isStale()) return;
      if (err instanceof ApiError && (err.kind === "not_found" || err.kind === "unauthorized")) {
        clearToken(domain);
        set({ phase: "idle", view: null, message: "" });
      } else {
        set({ phase: "error", view: null, retry: true, message: monitorErrorMessage(err, "status") });
      }
    }
  }

  async function onActivate() {
    set({ phase: "activating", busy: true, message: "" });
    try {
      const { token, monitor } = await activateMonitor(domain);
      if (isStale()) return;
      saveToken(domain, token);
      set({ phase: "active", view: monitor, busy: false, message: "", confirming: false, retry: false });
      const heading = slot.querySelector("#monitor-title");
      if (heading) { heading.setAttribute("tabindex", "-1"); heading.focus({ preventScroll: true }); }
    } catch (err) {
      if (isStale()) return;
      set({ phase: "idle", busy: false, view: null, message: monitorErrorMessage(err, "activate") });
    }
  }

  async function onRefresh() {
    set({ busy: true, message: "" });
    await load();
    if (!isStale()) set({ busy: false });
  }

  async function onDeactivate() {
    if (!state.confirming) { set({ confirming: true, message: "" }); return; }
    const token = loadToken(domain);
    set({ busy: true });
    try {
      if (token) await deactivateMonitor(token);
      clearToken(domain);
      if (isStale()) return;
      set({ phase: "idle", view: null, busy: false, confirming: false, message: "", retry: false });
    } catch (err) {
      if (isStale()) return;
      if (err instanceof ApiError && err.kind === "not_found") {
        clearToken(domain);
        set({ phase: "idle", view: null, busy: false, confirming: false, message: "" });
      } else {
        set({ busy: false, confirming: false, message: monitorErrorMessage(err, "deactivate") });
      }
    }
  }

  function onCancelDeactivate() { set({ confirming: false }); }

  render();
  load();
}
