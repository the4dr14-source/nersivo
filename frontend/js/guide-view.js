// Vista de la guía «Cómo solucionarlo». Se muestra en el mismo diálogo del detalle.
// Todo el texto se inserta con textContent (vía dom.js): nada de HTML procedente de la API.

import { el } from "./dom.js";
import { icon } from "./icons.js";

/** @typedef {{record_type?: string|null, host?: string|null, value: string, label: string, note?: string|null}} GuideValue */
/** @typedef {{check: string, guide_id: string, title: string, why: string, audience: "specific"|"generic", intro: string, detected: string[], steps: string[], values: GuideValue[], verify: string, notes: string[]}} Guide */

/** Copia texto al portapapeles (con alternativa para navegadores sin Clipboard API). */
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = el("textarea", { "aria-hidden": "true", tabindex: "-1", style: "position:fixed;opacity:0;top:0;left:0" });
  area.value = text;
  document.body.append(area);
  area.select();
  try { document.execCommand("copy"); } finally { area.remove(); }
}

function copyButton(text) {
  const btn = el("button", { type: "button", className: "copy-btn", text: "Copiar", "aria-label": "Copiar el valor" });
  btn.addEventListener("click", async () => {
    try {
      await copyText(text);
      btn.textContent = "Copiado";
    } catch (_) {
      btn.textContent = "Selecciona y copia";
    }
    setTimeout(() => { btn.textContent = "Copiar"; }, 2000);
  });
  return btn;
}

/** Valor técnico que el usuario debe introducir, con botón de copiar. */
function valueBlock(v) {
  const rows = [];
  if (v.record_type) rows.push(["Tipo", v.record_type]);
  if (v.host) rows.push(["Nombre / host", v.host]);
  return el("div", { className: "guide-value" }, [
    el("p", { className: "guide-value-label", text: v.label }),
    ...rows.map(([k, val]) =>
      el("div", { className: "guide-value-row" }, [
        el("span", { className: "guide-value-key", text: k }),
        el("code", { className: "guide-value-code", text: val }),
      ])
    ),
    el("div", { className: "guide-value-row guide-value-main" }, [
      el("span", { className: "guide-value-key", text: "Valor" }),
      el("code", { className: "guide-value-code", text: v.value }),
      copyButton(v.value),
    ]),
    v.note ? el("p", { className: "guide-value-note", text: v.note }) : null,
  ]);
}

function section(title, children) {
  return el("section", { className: "detail-section guide-section" }, [el("h3", { text: title }), ...children]);
}

/**
 * Pinta la guía en el diálogo.
 * @param {HTMLDialogElement} dialog
 * @param {{status: string, name: string, icon: string}} check Comprobación presentada.
 * @param {Guide} guide
 * @param {{onClose: Function, onBack: Function}} handlers
 */
export function renderGuide(dialog, check, guide, handlers) {
  const closeBtn = el("button", { type: "button", className: "dialog-close", "aria-label": "Cerrar guía", text: "✕" });
  closeBtn.addEventListener("click", handlers.onClose);
  const backBtn = el("button", { type: "button", className: "btn btn-secondary", text: "← Volver al detalle" });
  backBtn.addEventListener("click", handlers.onBack);
  const closeBtn2 = el("button", { type: "button", className: "btn btn-ghost", text: "Cerrar" });
  closeBtn2.addEventListener("click", handlers.onClose);

  const specific = guide.audience === "specific";

  dialog.replaceChildren(
    el("div", { className: `dialog-inner dialog-${check.status}` }, [
      el("div", { className: "dialog-head" }, [
        el("span", { className: "check-icon check-icon-lg" }, [icon(check.icon, 26)]),
        el("div", {}, [
          el("p", { className: "mono-label", text: "Cómo solucionarlo" }),
          el("h2", { id: "detail-title", text: guide.title }),
        ]),
        closeBtn,
      ]),

      el("p", { className: `guide-audience ${specific ? "is-specific" : "is-generic"}`, text: specific ? "Adaptada a tu proveedor" : "Guía general: sirve para cualquier proveedor" }),
      guide.intro ? el("p", { className: "guide-intro", text: guide.intro }) : null,

      section("¿Por qué importa?", [el("p", { text: guide.why })]),
      guide.detected.length
        ? section("Lo que hemos encontrado", [el("ul", { className: "guide-detected" }, guide.detected.map((t) => el("li", { text: t })))])
        : null,
      section("Qué tienes que hacer", [el("ol", { className: "guide-steps" }, guide.steps.map((t) => el("li", { text: t })))]),
      guide.values.length ? section(guide.values.length > 1 ? "Valores que debes introducir" : "Valor que debes introducir", guide.values.map(valueBlock)) : null,
      section("Cómo comprobar que está solucionado", [el("p", { text: guide.verify })]),
      guide.notes.length ? section("Ten en cuenta", guide.notes.map((t) => el("p", { text: t }))) : null,

      el("div", { className: "dialog-actions guide-actions" }, [backBtn, closeBtn2]),
    ])
  );
}

/**
 * Botón «Cómo solucionarlo» para la tarjeta de una comprobación.
 * @param {Guide} guide @param {Function} onOpen
 */
export function guideButton(guide, onOpen) {
  const btn = el("button", { type: "button", className: "guide-btn", "aria-haspopup": "dialog" }, [
    el("span", { className: "guide-btn-icon", "aria-hidden": "true", text: "🛠\uFE0E" }),
    el("span", { text: "Cómo solucionarlo" }),
  ]);
  btn.addEventListener("click", () => onOpen(btn));
  return btn;
}
