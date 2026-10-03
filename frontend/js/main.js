// Punto de entrada de Nersivo: controla las pantallas y conecta formulario, API y presentación.

import { analyzeDomain, ApiError } from "./api.js";
import { validateDomain } from "./validation.js";
import { presentAnalysis, presentError } from "./presenter.js";
import { renderResults, renderDetail } from "./components.js";

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
    show("results");
    window.scrollTo({ top: 0 });
    $("results-title").focus({ preventScroll: true });
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

function restart() {
  requestId++;
  document.title = "Nersivo · Comprueba la salud de tu web y correo";
  setFieldError("");
  show("home");
  input.value = "";
  input.focus();
  window.scrollTo({ top: 0 });
}

function openDetail(check, trigger) {
  lastTrigger = trigger;
  renderDetail(dialog, check, closeDetail);
  dialog.classList.remove("is-closing");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
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
