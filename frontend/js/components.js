// Componentes de interfaz: reciben datos ya presentados (presenter.js) y devuelven DOM.

import { el, svg } from "./dom.js";
import { icon } from "./icons.js";

const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function statusBadge(status, label, symbol) {
  return el("span", { className: `badge badge-${status}` }, [
    el("span", { className: "badge-symbol", "aria-hidden": "true", text: symbol }),
    el("span", { className: "badge-label", text: label }),
  ]);
}

// ---------------------------------------------------------------------------
// Ayuda "?" · un único popover compartido, discreto y accesible.
// Escritorio: aparece al pasar el ratón o al enfocar; clic/tap/Enter lo fija. Escape lo cierra.
// Se pinta en <body> con position: fixed para no quedar recortado por las tarjetas.
// ---------------------------------------------------------------------------
let popEl = null;
let activeBtn = null;
let pinned = false;
let helpBound = false;

function getPop() {
  if (!popEl) {
    popEl = el("div", { className: "help-pop", id: "help-pop", role: "tooltip", hidden: true });
    document.body.append(popEl);
  }
  return popEl;
}

function placePop() {
  if (!activeBtn || !popEl) return;
  const r = activeBtn.getBoundingClientRect();
  const m = 8;
  const w = popEl.offsetWidth, h = popEl.offsetHeight;
  const left = Math.max(m, Math.min(window.innerWidth - m - w, r.left + r.width / 2 - w / 2));
  let top = r.bottom + 10;
  if (top + h > window.innerHeight - m && r.top - 10 - h > m) top = r.top - 10 - h;
  popEl.style.left = `${Math.round(left)}px`;
  popEl.style.top = `${Math.round(top)}px`;
}

function closeHelp() {
  if (!activeBtn) return;
  popEl.hidden = true;
  activeBtn.setAttribute("aria-expanded", "false");
  activeBtn.removeAttribute("aria-describedby");
  activeBtn = null;
  pinned = false;
}

function openHelp(btn, build) {
  if (activeBtn && activeBtn !== btn) closeHelp();
  const pop = getPop();
  pop.replaceChildren(...build());
  pop.hidden = false;
  activeBtn = btn;
  btn.setAttribute("aria-expanded", "true");
  btn.setAttribute("aria-describedby", "help-pop");
  placePop();
}

function bindHelpListeners() {
  if (helpBound) return;
  helpBound = true;
  document.addEventListener("click", (e) => {
    if (activeBtn && !activeBtn.contains(e.target) && !(popEl && popEl.contains(e.target))) closeHelp();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && activeBtn) {
      const btn = activeBtn;
      closeHelp();
      btn.focus();
    }
  });
  window.addEventListener("scroll", closeHelp, { passive: true, capture: true });
  window.addEventListener("resize", closeHelp);
}

/**
 * Icono "?" con ayuda.
 * @param {string} label  Nombre accesible del botón.
 * @param {() => Node[]} build  Contenido del popover.
 */
function helpTip(label, build) {
  bindHelpListeners();
  const btn = el("button", { type: "button", className: "help-btn", "aria-label": label, "aria-expanded": "false", text: "?" });
  btn.addEventListener("click", () => {
    if (activeBtn === btn && pinned) { closeHelp(); return; }
    openHelp(btn, build);
    pinned = true;
  });
  btn.addEventListener("pointerenter", (e) => {
    if (e.pointerType === "mouse" && !activeBtn) openHelp(btn, build);
  });
  btn.addEventListener("pointerleave", (e) => {
    if (e.pointerType === "mouse" && activeBtn === btn && !pinned) closeHelp();
  });
  return btn;
}

/** Anillo de salud: el progreso es exactamente el score recibido de la API. */
function healthRing(value, status) {
  const r = 84;
  const c = 2 * Math.PI * r;
  const progress = svg("circle", {
    class: "ring-progress", cx: 100, cy: 100, r, fill: "none", "stroke-width": 12, "stroke-linecap": "round",
    transform: "rotate(-90 100 100)", "stroke-dasharray": `0 ${c}`,
  });
  const ticks = [];
  for (let i = 0; i < 40; i++) {
    const a = (i / 40) * 2 * Math.PI;
    const r1 = 100, r2 = i % 5 === 0 ? 94 : 96.5;
    ticks.push(svg("line", {
      class: "ring-tick", x1: 100 + r1 * Math.cos(a), y1: 100 + r1 * Math.sin(a),
      x2: 100 + r2 * Math.cos(a), y2: 100 + r2 * Math.sin(a), "stroke-width": 1,
    }));
  }
  const ring = svg("svg", { viewBox: "0 0 200 200", class: "ring", "aria-hidden": "true" }, [
    ...ticks,
    svg("circle", { class: "ring-track", cx: 100, cy: 100, r, fill: "none", "stroke-width": 12 }),
    progress,
  ]);

  const number = el("span", { className: "ring-value", text: reducedMotion() ? String(value) : "0" });
  const wrap = el("div", { className: `ring-wrap ring-${status}`, role: "img", "aria-label": `Salud del dominio: ${value} sobre 100` }, [
    ring,
    el("div", { className: "ring-center" }, [number, el("span", { className: "ring-max", text: "/100" })]),
  ]);

  // Animación de entrada (el valor final es siempre el score real).
  requestAnimationFrame(() => requestAnimationFrame(() => {
    progress.setAttribute("stroke-dasharray", `${(c * value) / 100} ${c}`);
  }));
  if (!reducedMotion()) {
    const t0 = performance.now(), dur = 1100;
    const tick = (now) => {
      const k = Math.min(1, (now - t0) / dur);
      number.textContent = String(Math.round(value * (1 - Math.pow(1 - k, 3))));
      if (k < 1) requestAnimationFrame(tick);
      else number.textContent = String(value);
    };
    requestAnimationFrame(tick);
  }
  return wrap;
}

function emptyRing(note) {
  return el("div", { className: "ring-wrap ring-empty" }, [
    svg("svg", { viewBox: "0 0 200 200", class: "ring", "aria-hidden": "true" }, [
      svg("circle", { class: "ring-track", cx: 100, cy: 100, r: 84, fill: "none", "stroke-width": 12, "stroke-dasharray": "4 8" }),
    ]),
    el("div", { className: "ring-center" }, [
      el("span", { className: "ring-value ring-value-empty", text: "—" }),
      el("span", { className: "ring-max", text: "Sin puntuación" }),
    ]),
  ]);
}

function checkCard(check, index, onOpen) {
  const btn = el(
    "button",
    {
      type: "button",
      className: `check-card check-${check.status}`,
      "data-check": check.key,
      "aria-haspopup": "dialog",
      "aria-label": `${check.name}: ${check.statusLabel}. Ver detalles`,
      style: `--i:${index}`,
    },
    [
      el("div", { className: "check-head" }, [
        el("span", { className: "check-icon" }, [icon(check.icon, 22)]),
        el("div", { className: "check-titles" }, [
          el("h3", { className: "check-name", text: check.name }),
        ]),
      ]),
      statusBadge(check.status, check.statusLabel, check.statusSymbol),
      el("p", { className: "check-message", text: check.cardMessage }),
      check.status !== "ok" && check.actionPreview
        ? el("p", { className: "check-reco" }, [
            el("span", { className: "check-reco-label", text: "Qué puedes hacer" }),
            el("span", { className: "check-reco-text", text: check.actionPreview }),
          ])
        : null,
      el("span", { className: "check-more", "aria-hidden": "true", text: "Ver detalles" }),
    ]
  );
  btn.addEventListener("click", () => onOpen(check, btn));
  return el("li", {}, [btn]);
}

/**
 * Pantalla de resultados.
 * Jerarquía: 1) dominio  2) salud  3) problemas  4) qué solucionar (en cada tarjeta)  5) datos técnicos (detalle).
 * @param {HTMLElement} container
 * @param {ReturnType<import("./presenter.js").presentAnalysis>} view
 * @param {{onOpenDetail: Function, onRestart: Function, onRetry: Function}} handlers
 */
export function renderResults(container, view, handlers) {
  closeHelp();
  const status = view.global.status;
  const scoreBlock = view.score.hasScore ? healthRing(view.score.value, status) : emptyRing(view.score.note);

  container.replaceChildren(
    el("div", { className: "results-top" }, [
      el("div", {}, [
        el("p", { className: "mono-label", text: "Resultados para" }),
        el("h2", { className: "results-domain", id: "results-title", tabindex: "-1", text: view.domain }),
        view.analyzedAt ? el("p", { className: "results-date", text: `Análisis realizado el ${view.analyzedAt}` }) : null,
      ]),
      el("div", { className: "actions" }, [
        el("button", { type: "button", className: "btn btn-secondary", id: "restart-btn", text: "Analizar otro dominio" }),
        el("button", { type: "button", className: "btn btn-ghost", id: "reanalyze-btn", text: "Volver a analizar" }),
      ]),
    ]),

    el("section", { className: `overview overview-${status}`, "aria-labelledby": "overview-title" }, [
      el("div", { className: "overview-ring" }, [
        scoreBlock,
        el("p", { className: "ring-caption" }, [
          el("span", { id: "overview-title", text: "Salud del dominio" }),
          view.score.hasScore
            ? helpTip("¿Qué significa la puntuación?", () => [el("p", { text: view.help.score })])
            : null,
        ]),
        view.score.hasScore ? null : el("p", { className: "ring-note", text: view.score.note }),
      ]),
      el("div", { className: "overview-info" }, [
        el("div", { className: "chip-row" }, [
          el("p", { className: `state-chip state-${status}` }, [
            el("span", { className: "state-dot", "aria-hidden": "true" }),
            el("span", { text: `Estado: ${view.global.chip}` }),
          ]),
          helpTip("¿Qué significan los estados?", () =>
            view.help.states.map((s) => el("p", {}, [el("strong", { text: s.label }), ` ${s.text}`]))
          ),
        ]),
        el("h3", { className: "global-title", text: view.global.title }),
        view.global.subtitle ? el("p", { className: "global-subtitle", text: view.global.subtitle }) : null,
        el("p", { className: "summary-intro", text: view.summary.intro }),
        el(
          "ul",
          { className: "stats" },
          view.summary.stats.map((i) =>
            el("li", { className: `stat stat-${i.status}` }, [
              el("span", { className: "stat-count", text: String(i.count) }),
              el("span", { className: "stat-label" }, [
                el("span", { className: "stat-symbol", "aria-hidden": "true", text: i.symbol }),
                el("span", { text: i.label }),
              ]),
            ])
          )
        ),
      ]),
    ]),

    el("section", { "aria-labelledby": "checks-title" }, [
      el("h3", { id: "checks-title", className: "section-title", text: "Lo que hemos revisado" }),
      el("ul", { className: "check-grid" }, view.checks.map((c, i) => checkCard(c, i, handlers.onOpenDetail))),
    ])
  );

  container.querySelector("#restart-btn").addEventListener("click", handlers.onRestart);
  container.querySelector("#reanalyze-btn").addEventListener("click", handlers.onRetry);
}

function detailSection(title, children) {
  return el("section", { className: "detail-section" }, [el("h3", { text: title }), ...children]);
}

/** Consola técnica (información secundaria). */
function technicalConsole(check) {
  const rows = check.technical.map((row) =>
    el("div", { className: "term-row" }, [
      el("span", { className: "term-key", text: row.label }),
      el("span", { className: "term-dots", "aria-hidden": "true" }),
      el("span", { className: `term-val term-val-${row.label === "STATUS" ? check.status : "plain"}`, text: row.value }),
    ])
  );
  const messages = check.consoleMessages.map((m) => el("p", { className: "term-msg", text: m }));
  return el("div", { className: "terminal", role: "group", "aria-label": "Salida técnica" }, [
    el("div", { className: "terminal-bar" }, [
      el("span", { className: `terminal-dot terminal-dot-${check.status}`, "aria-hidden": "true" }),
      el("span", { text: "NERSIVO / TECHNICAL OUTPUT" }),
    ]),
    el("div", { className: "terminal-body" }, [...rows, messages.length ? el("div", { className: "term-sep" }) : null, ...messages]),
  ]);
}

/**
 * Contenido del diálogo de detalle (único sistema de modal).
 * @param {HTMLDialogElement} dialog
 * @param {ReturnType<import("./presenter.js").presentCheck>} check
 * @param {Function} onClose
 */
export function renderDetail(dialog, check, onClose) {
  const closeBtn = el("button", { type: "button", className: "dialog-close", "aria-label": "Cerrar detalle", text: "✕" });
  closeBtn.addEventListener("click", onClose);
  const closeBtn2 = el("button", { type: "button", className: "btn btn-secondary", text: "Cerrar" });
  closeBtn2.addEventListener("click", onClose);

  dialog.replaceChildren(
    el("div", { className: `dialog-inner dialog-${check.status}` }, [
      el("div", { className: "dialog-head" }, [
        el("span", { className: "check-icon check-icon-lg" }, [icon(check.icon, 26)]),
        el("div", {}, [
          el("h2", { id: "detail-title", text: check.name }),
        ]),
        closeBtn,
      ]),
      statusBadge(check.status, check.statusLabel, check.statusSymbol),
      check.headline ? el("p", { className: "detail-headline" }, [el("strong", { text: check.headline })]) : null,

      // NIVEL 1 · lenguaje de negocio
      el("div", { className: `detail-explanation explanation-${check.status}` }, [
        check.why || check.action ? el("h3", { text: "Qué hemos encontrado" }) : null,
        ...check.found.map((p) => el("p", { text: p })),
      ]),

      check.why ? detailSection("¿Por qué importa?", [el("p", { text: check.why })]) : null,
      check.action ? detailSection("¿Qué puedes hacer?", check.action.map((p) => el("p", { text: p }))) : null,

      // NIVEL 2 · datos técnicos reales del backend
      el("details", { className: "tech-details" }, [
        el("summary", { text: "Ver detalles técnicos" }),
        technicalConsole(check),
      ]),

      el("div", { className: "dialog-actions" }, [closeBtn2]),
    ])
  );
}
