// Punto de entrada de Nersivo: controla las pantallas y conecta formulario, API y presentación.

import { analyzeDomain, ApiError, fetchGuides } from "./api.js";
import { validateDomain } from "./validation.js";
import { presentAnalysis, presentError } from "./presenter.js";
import { renderResults, renderDetail } from "./components.js";
import { renderGuide, guideButton } from "./guide-view.js";
import { mountMonitor } from "./monitor.js";

const $ = (id) => document.getElementById(id);

const views = {
  home: $("view-home"),
  loading: $("view-loading"),
  error: $("view-error"),
  results: $("view-results"),
};
const form = $("domain-form");
const input = $("domain-input");
const submitBtn = $("submit-btn");
const fieldError = $("domain-error");
const dialog = $("detail-dialog");

let currentDomain = "";
let lastTrigger = null;
let requestId = 0; // descarta respuestas de análisis antiguos
let currentView = null; // análisis presentado actualmente
let guidesByCheck = new Map(); // guía «Cómo solucionarlo» por comprobación (si la hay)

$("year").textContent = String(new Date().getFullYear());

function show(name) {
  for (const [key, node] of Object.entries(views)) node.hidden = key !== name;
}

function setFieldError(message) {
  fieldError.textContent = message || "";
  fieldError.hidden = !message;
  input.toggleAttribute("aria-invalid", Boolean(message));
  input.classList.toggle("is-invalid", Boolean(message));
  form.classList.toggle("is-invalid", Boolean(message));
}

async function runAnalysis(domain) {
  const myRequest = ++requestId;
  currentDomain = domain;
  setFieldError("");
  $("loading-domain").textContent = domain;
  submitBtn.disabled = true;
  show("loading");
  window.scrollTo({ top: 0 });

  try {
    const data = await analyzeDomain(domain);
    if (myRequest !== requestId) return;
    const view = presentAnalysis(data);
    renderResults(views.results, view, {
      onOpenDetail: openDetail,
      onRestart: restart,
      onRetry: () => runAnalysis(currentDomain),
    });
    document.title = `Resultados de ${view.domain} · Nersivo`;
    currentView = view;
    guidesByCheck = new Map();
    show("results");
    window.scrollTo({ top: 0 });
    $("results-title").focus({ preventScroll: true });
    // Extras opcionales: si fallan, los resultados siguen mostrándose igual.
    loadGuides(data, myRequest);
    mountMonitor($("monitor-slot"), view.domain, () => myRequest !== requestId);
  } catch (err) {
    if (myRequest !== requestId) return;
    const friendly = presentError(err instanceof ApiError ? err : null);
    if (err instanceof ApiError && friendly.inline) {
      show("home");
      setFieldError(friendly.message);
      input.focus();
    } else {
      $("error-message").textContent = friendly.message;
      show("error");
      $("retry-btn").focus();
    }
  } finally {
    if (myRequest === requestId) submitBtn.disabled = false;
  }
}

/** Descarga las guías de solución y añade el botón «Cómo solucionarlo» a cada problema. */
async function loadGuides(data, myRequest) {
  try {
    const { guides } = await fetchGuides(data);
    if (myRequest !== requestId) return;
    guidesByCheck = new Map(guides.map((g) => [g.check, g]));
    for (const [key, guide] of guidesByCheck) {
      const check = currentView.checks.find((c) => c.key === key); // solo claves conocidas
      if (!check) continue;
      const item = views.results.querySelector(`[data-check-item="${check.key}"]`);
      if (!item || item.querySelector(".guide-btn")) continue;
      item.append(guideBtn(check, guide));
    }
  } catch (err) {
    console.error("[Nersivo] No se han podido cargar las guías:", err);
  }
}

function guideBtn(check, guide) {
  return guideButton(guide, (trigger) => openGuide(check, guide, trigger));
}

function openGuide(check, guide, trigger) {
  lastTrigger = trigger;
  showGuideInDialog(check, guide);
  openDialog();
}

function showGuideInDialog(check, guide) {
  renderGuide(dialog, check, guide, {
    onClose: closeDetail,
    onBack: () => { renderDetail(dialog, check, closeDetail, detailExtra(check)); },
  });
  dialog.scrollTop = 0;
}

function detailExtra(check) {
  const guide = guidesByCheck.get(check.key);
  return guide ? { onOpenGuide: () => showGuideInDialog(check, guide) } : {};
}

function openDialog() {
  dialog.classList.remove("is-closing");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

function restart() {
  requestId++;
  currentView = null;
  guidesByCheck = new Map();
  document.title = "Nersivo · Comprueba la salud de tu web y correo";
  setFieldError("");
  show("home");
  input.value = "";
  input.focus();
  window.scrollTo({ top: 0 });
}

function openDetail(check, trigger) {
  lastTrigger = trigger;
  renderDetail(dialog, check, closeDetail, detailExtra(check));
  openDialog();
}

function closeDetail() {
  if (!dialog.open) return;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) { dialog.close(); return; }
  // Animación breve de cierre antes de cerrar el diálogo.
  dialog.classList.add("is-closing");
  setTimeout(() => { dialog.classList.remove("is-closing"); dialog.close(); }, 160);
}

dialog.addEventListener("cancel", (e) => { e.preventDefault(); closeDetail(); });
dialog.addEventListener("close", () => {
  if (lastTrigger && document.contains(lastTrigger)) lastTrigger.focus();
});
// Cerrar al pulsar fuera del cuadro.
dialog.addEventListener("click", (e) => {
  if (e.target === dialog) closeDetail();
});

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const result = validateDomain(input.value);
  if (!result.ok) {
    setFieldError(result.message);
    input.focus();
    return;
  }
  input.value = result.domain;
  runAnalysis(result.domain);
});
input.addEventListener("input", () => setFieldError(""));

$("retry-btn").addEventListener("click", () => runAnalysis(currentDomain));
$("error-back-btn").addEventListener("click", restart);
