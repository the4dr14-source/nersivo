// Validación y normalización del dominio introducido por la persona usuaria.
// El backend vuelve a validar; esto solo evita peticiones claramente inválidas.

const DOMAIN_REGEX =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Limpia lo que la gente suele pegar (https://, rutas, espacios, mayúsculas).
 * @param {string} raw
 * @returns {string}
 */
export function cleanDomainInput(raw) {
  let value = String(raw || "").trim().toLowerCase();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // http://, https://
  value = value.replace(/[/?#].*$/, "");                // ruta, query, hash
  value = value.replace(/\.+$/, "");                    // punto final
  return value;
}

/**
 * @param {string} raw
 * @returns {{ok: true, domain: string} | {ok: false, message: string}}
 */
export function validateDomain(raw) {
  const domain = cleanDomainInput(raw);

  if (!domain) {
    return { ok: false, message: "Escribe el dominio que quieres revisar, por ejemplo minegocio.es." };
  }
  if (/\s/.test(domain)) {
    return { ok: false, message: "El dominio no puede contener espacios." };
  }
  if (domain.includes("@")) {
    return { ok: false, message: "Escribe el dominio, no una dirección de correo. Por ejemplo: minegocio.es." };
  }
  if (IPV4_REGEX.test(domain) || domain.includes(":")) {
    return { ok: false, message: "Escribe un nombre de dominio, no una dirección IP." };
  }
  if (!domain.includes(".")) {
    return { ok: false, message: "Falta la extensión del dominio, por ejemplo .es o .com." };
  }
  if (!DOMAIN_REGEX.test(domain)) {
    return { ok: false, message: "Ese dominio no parece válido. Revisa que esté bien escrito." };
  }
  return { ok: true, domain };
}
