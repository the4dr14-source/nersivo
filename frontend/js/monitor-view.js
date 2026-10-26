// Vista de la sección «Monitorización». Solo pinta un estado ya calculado (monitor.js).
// Todo el texto se inserta con textContent (vía dom.js).

import { el } from "./dom.js";

const STATUS_LABEL = { ok: "OK", warning: "Requiere atención", error: "Problema", unknown: "No se ha podido verificar" };
const SEVERITY_META = {
  critical: { cls: "error", symbol: "✕" },
  warning: { cls: "warning", symbol: "⚠\uFE0E" },
  info: { cls: "ok", symbol: "✓" },
};

/** @param {string|null|undefined} iso */
export function formatDateTime(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return new Intl.DateTimeFormat("es-ES", { dateStyle: "long", timeStyle: "short" }).format(d);
}

function infoRow(label, value) {
  return el("div", { className: "monitor-row" }, [
    el("dt", { text: label }),
    el("dd", { text: value }),
  ]);
}

function eventItem(ev) {
  const meta = SEVERITY_META[ev.severity] || SEVERITY_META.info;
  return el("li", { className: `monitor-event monitor-event-${meta.cls}` }, [
    el("span", { className: "monitor-event-symbol", "aria-hidden": "true", text: meta.symbol }),
    el("div", {}, [
      el("p", { className: "monitor-event-text", text: ev.summary }),
      ev.created_at ? el("p", { className: "monitor-event-date", text: formatDateTime(ev.created_at) || "" }) : null,
    ]),
  ]);
}

function nextCheckText(view, now = Date.now()) {
  const text = formatDateTime(view.next_check_at);
  if (!text) return "Pendiente de programar";
  return new Date(view.next_check_at).getTime() <= now ? "Pendiente: se comprobará en breve" : text;
}

function intro() {
  return el("p", { className: "monitor-lead", text: "Nersivo comprobará periódicamente tu dominio para detectar cambios o nuevos problemas." });
}

/**
 * @param {HTMLElement} slot
 * @param {{phase: "loading"|"idle"|"activating"|"active"|"error", view: any, message: string, confirming: boolean, busy: boolean}} state
 * @param {{onActivate: Function, onRefresh: Function, onDeactivate: Function, onCancelDeactivate: Function}} handlers
 */
export function renderMonitor(slot, state, handlers) {
  const title = el("h3", { className: "section-title monitor-title", id: "monitor-title", text: state.phase === "active" ? "Monitorización activa" : "Monitorización" });
  const body = [];

  if (state.phase === "loading") {
    body.push(el("p", { className: "monitor-note", text: "Comprobando el estado de la monitorización…" }));
  } else if (state.phase === "active" && state.view) {
    const v = state.view;
    const events = v.recent_events || [];
    body.push(
      el("div", { className: "monitor-status" }, [
        el("span", { className: "badge badge-ok" }, [
          el("span", { className: "badge-symbol", "aria-hidden": "true", text: "✓" }),
          el("span", { className: "badge-label", text: "Vigilando" }),
        ]),
        el("p", { className: "monitor-lead", text: "Nersivo está vigilando este dominio y te mostrará aquí los cambios que detecte." }),
      ]),
      el("dl", { className: "monitor-info" }, [
        infoRow("Estado actual", STATUS_LABEL[v.current_status] || "Sin datos"),
        infoRow("Puntuación", Number.isInteger(v.current_score) ? `${v.current_score}/100` : "Sin puntuación"),
        infoRow("Última comprobación", formatDateTime(v.last_checked_at) || "Aún no realizada"),
        infoRow("Próxima comprobación", nextCheckText(v)),
      ]),
      el("div", { className: "monitor-changes" }, [
        el("h4", { text: "Cambios detectados" }),
        events.length
          ? el("ul", { className: "monitor-events" }, events.map(eventItem))
          : el("p", { className: "monitor-note", text: "Todavía no se han detectado cambios desde que activaste la monitorización." }),
      ]),
      el("p", { className: "monitor-note", text: "De momento no enviamos avisos por correo: cuando vuelvas a Nersivo verás aquí los cambios." })
    );
  } else {
    body.push(
      intro(),
      el("ul", { className: "monitor-benefits" }, [
        el("li", { text: "Te avisamos aquí si aparece un problema nuevo o si se soluciona uno." }),
        el("li", { text: "Detectamos cambios en el correo, SPF, DMARC y el certificado de tu web." }),
        el("li", { text: "Gratis durante la fase de pruebas. Sin registro ni tarjeta." }),
      ])
    );
  }

  if (state.message) body.push(el("p", { className: "monitor-message", role: "alert", text: state.message }));

  const actions = [];
  if (state.phase === "idle" || state.phase === "activating" || (state.phase === "error" && !state.view)) {
    const btn = el("button", { type: "button", className: "btn btn-primary", id: "monitor-activate", text: state.phase === "activating" ? "Activando…" : "Monitorizar este dominio" });
    btn.disabled = state.busy;
    btn.addEventListener("click", handlers.onActivate);
    actions.push(btn);
  }
  if (state.phase === "active") {
    const refresh = el("button", { type: "button", className: "btn btn-secondary", text: "Actualizar estado" });
    refresh.disabled = state.busy;
    refresh.addEventListener("click", handlers.onRefresh);
    actions.push(refresh);
    if (state.confirming) {
      const confirm = el("button", { type: "button", className: "btn btn-danger", id: "monitor-confirm", text: "Sí, desactivar" });
      confirm.disabled = state.busy;
      confirm.addEventListener("click", handlers.onDeactivate);
      const cancel = el("button", { type: "button", className: "btn btn-ghost", text: "Cancelar" });
      cancel.addEventListener("click", handlers.onCancelDeactivate);
      actions.push(el("span", { className: "monitor-confirm-text", text: "¿Dejar de monitorizar este dominio?" }), confirm, cancel);
    } else {
      const off = el("button", { type: "button", className: "btn btn-ghost", id: "monitor-deactivate", text: "Desactivar monitorización" });
      off.addEventListener("click", handlers.onDeactivate);
      actions.push(off);
    }
  }
  if (state.phase === "error" && state.view === null && state.retry) {
    const retry = el("button", { type: "button", className: "btn btn-secondary", text: "Reintentar" });
    retry.addEventListener("click", handlers.onRefresh);
    actions.push(retry);
  }

  slot.replaceChildren(title, ...body, actions.length ? el("div", { className: "actions monitor-actions" }, actions) : null);
}
