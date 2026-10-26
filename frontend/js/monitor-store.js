// Almacén del token de monitorización en este navegador (no hay cuentas de usuario).
//
// El token es la "llave" que permite ver y desactivar la monitorización de un dominio.
// Se guarda en localStorage; si no está disponible (modo privado, bloqueado), se usa memoria
// durante la sesión y la interfaz sigue funcionando.

const PREFIX = "nersivo.monitor.";
const memory = new Map();

/** @param {string} domain */
export function loadToken(domain) {
  try {
    return window.localStorage.getItem(PREFIX + domain) || memory.get(domain) || null;
  } catch (_) {
    return memory.get(domain) || null;
  }
}

/** @param {string} domain @param {string} token */
export function saveToken(domain, token) {
  memory.set(domain, token);
  try { window.localStorage.setItem(PREFIX + domain, token); } catch (_) { /* solo memoria */ }
}

/** @param {string} domain */
export function clearToken(domain) {
  memory.delete(domain);
  try { window.localStorage.removeItem(PREFIX + domain); } catch (_) { /* nada que borrar */ }
}
