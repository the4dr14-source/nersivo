// Textos en lenguaje de negocio para cada resultado.
//
// Estructura de cada explicación:
//   found  -> "Qué hemos encontrado"  (array de párrafos)
//   why    -> "¿Por qué importa?"     (string | null)
//   action -> "¿Qué puedes hacer?"    (array de párrafos | null)
//
// Se elige según (comprobación, technical_reason) y, si no hay texto específico,
// según el estado. Solo se usan datos reales de la respuesta de la API; si un
// código no está contemplado se recurre al mensaje original del backend, sin
// inventar causas.

/** @typedef {import("./types.js").CheckResult} CheckResult */
/** @typedef {import("./types.js").CheckKey} CheckKey */

/** A quién acudir según el tipo de comprobación. */
const WHO = {
  web: "quien gestione tu página web o tu alojamiento",
  https: "quien gestione tu página web o tu alojamiento",
  dns: "quien gestione tu dominio",
  mx: "quien gestione tu correo electrónico o tu dominio",
  spf: "quien gestione tu correo electrónico o tu dominio",
  dmarc: "quien gestione tu correo electrónico o tu dominio",
};

/** Por qué importa cada comprobación, en general (se usa cuando no hay texto más específico). */
export const GENERAL_WHY = {
  web: "Si tu web no responde bien, tus clientes pueden no encontrarte ni contactar contigo.",
  https: "La conexión segura ayuda a proteger a tus visitantes y transmite confianza cuando acceden a tu página.",
  dns: "Es lo que conecta el nombre de tu dominio con tu web. Si falla, tus clientes pueden no llegar a ella.",
  mx: "Si el correo de tu dominio no está bien configurado, podrías no recibir algunos mensajes de tus clientes.",
  spf: "Esta protección ayuda a que los correos de tu empresa lleguen a la bandeja de entrada de tus clientes y no acaben en spam.",
  dmarc: "Esta protección ayuda a proteger a tu empresa y a tus clientes frente a correos que se hacen pasar por ti.",
};

const ASK = (key) => `Pide a ${WHO[key]} que`;

// ---------------------------------------------------------------------------
// Correcto
// ---------------------------------------------------------------------------

/** @returns {{found: string[], why: string | null, action: string[] | null}} */
function okExplanation(key, result, ctx) {
  const d = ctx.details;
  switch (key) {
    case "web":
      return {
        found: [
          d.redirected_to_https === true
            ? "Tu web funciona correctamente y dirige a los visitantes a la versión segura."
            : "Tu web funciona correctamente.",
        ],
        why: null,
        action: null,
      };
    case "https":
      return { found: ["La seguridad de tu web está correctamente configurada: el certificado es válido y corresponde a tu dominio."], why: null, action: null };
    case "dns":
      return { found: ["La configuración de tu dominio es correcta: está conectado con el servicio que responde por tu web."], why: null, action: null };
    case "mx":
      if (result.technical_reason === "null_mx") {
        // Null MX bien configurado: NO es un error.
        return {
          found: ["Tu dominio está configurado para no recibir correo electrónico."],
          why: `Esto puede ser correcto si tu empresa no utiliza correo con este dominio. Si sí lo utilizas (por ejemplo, info@${ctx.domain}), no podrías recibir mensajes en esas direcciones y convendría que ${WHO[key]} lo revise.`,
          action: null,
        };
      }
      return { found: ["Tu correo está correctamente configurado: tu dominio indica dónde debe recibir los mensajes."], why: null, action: null };
    case "spf":
      return {
        found: ["La protección de tu correo está correctamente configurada: tu dominio indica qué servicios pueden enviar correos en nombre de tu empresa."],
        why: null,
        action: null,
      };
    case "dmarc":
      return {
        found: ["La protección contra suplantaciones está correctamente configurada: tu dominio tiene activada una protección frente a correos que se hacen pasar por tu empresa."],
        why: null,
        action: null,
      };
    default:
      return { found: [], why: null, action: null };
  }
}

// ---------------------------------------------------------------------------
// Avisos y problemas con texto específico
// ---------------------------------------------------------------------------

/** Plazo legible a partir de details.days_remaining (dato real del backend). */
function plazo(details) {
  const days = Number(details.days_remaining);
  if (!Number.isFinite(days)) return "próximamente";
  const whole = Math.floor(days);
  if (whole < 1) return "en menos de 1 día";
  return whole === 1 ? "en 1 día" : `en ${whole} días`;
}

const CERT_WARNING =
  "Los navegadores pueden mostrar a tus visitantes un aviso de que tu web no es de confianza, y algunos no seguirán adelante.";

/** @type {Record<string, (ctx: {domain: string, details: Record<string, any>}) => {found: string[], why: string | null, action: string[] | null}>} */
const SPECIFIC = {
  // ---- Funcionamiento de la web ----
  "web:no_https_redirect": () => ({
    found: [
      "Cuando alguien entra por la dirección no segura, no se le lleva automáticamente a la versión segura.",
    ],
    why: "Esos visitantes navegan sin la protección de la conexión segura, y los navegadores pueden mostrarles que tu web no es segura, lo que resta confianza.",
    action: [
      `${ASK("web")} configure una redirección automática hacia la versión segura de tu web.`,
      "No suele ser necesario cambiar el contenido de tu página; normalmente es un ajuste de configuración.",
    ],
  }),
  "web:unresolved_redirect": () => ({
    found: ["Cuando alguien intenta abrir tu página, se le envía a otra dirección y ese recorrido no termina correctamente."],
    why: "Esto puede dificultar que algunos visitantes lleguen a ver tu web, aunque no significa necesariamente que tu web no funcione.",
    action: [`${ASK("web")} revise a dónde envía tu página a los visitantes.`],
  }),
  "web:too_many_redirects": () => ({
    found: ["Al abrir tu página, se envía al visitante de una dirección a otra más veces de las razonables, sin llegar a una página final."],
    why: "Si esto se mantiene, tus clientes podrían no poder abrir tu web.",
    action: [
      `${ASK("web")} revise la configuración de tu página y corrija este bucle.`,
      "Puedes enseñarle los detalles técnicos de este resultado.",
    ],
  }),
  "web:http_5xx": () => ({
    found: ["Hemos intentado acceder a tu página, pero el servidor no ha podido entregarla correctamente."],
    why: "Esto puede impedir que algunos visitantes puedan acceder a tu web.",
    action: [
      "Te recomendamos contactar con quien gestione tu alojamiento o tu página web y facilitarle el resultado del análisis.",
      "Puedes enseñarle los detalles técnicos de este resultado.",
    ],
  }),

  // ---- Seguridad de la web ----
  "https:expiring_soon": (ctx) => ({
    found: [`El certificado de seguridad de tu web caduca ${plazo(ctx.details)}.`],
    why: "Si caduca sin renovarse, los navegadores mostrarán un aviso de que tu web no es segura y algunos visitantes podrían marcharse.",
    action: [`${ASK("https")} compruebe que la renovación está prevista o la haga a tiempo.`],
  }),
  "https:expiring_very_soon": (ctx) => ({
    found: [`El certificado de seguridad de tu web caduca muy pronto (${plazo(ctx.details)}).`],
    why: "Si caduca sin renovarse, los navegadores mostrarán un aviso de que tu web no es segura y algunos visitantes podrían marcharse.",
    action: [`${ASK("https")} renueve el certificado de seguridad cuanto antes.`],
  }),
  "https:certificate_expired": () => ({
    found: ["El certificado de seguridad de tu web ha caducado."],
    why: CERT_WARNING,
    action: [`${ASK("https")} renueve el certificado de seguridad cuanto antes.`],
  }),
  "https:hostname_mismatch": () => ({
    found: ["El certificado de seguridad de tu web no corresponde a este dominio."],
    why: CERT_WARNING,
    action: [`${ASK("https")} revise el certificado de seguridad para que corresponda a tu dominio.`],
  }),
  "https:self_signed_certificate": () => ({
    found: ["El certificado de seguridad de tu web no ha sido emitido por una entidad reconocida."],
    why: CERT_WARNING,
    action: [`${ASK("https")} lo sustituya por un certificado emitido por una entidad reconocida.`],
  }),
  "https:invalid_certificate": () => ({
    found: ["El certificado de seguridad de tu web tiene problemas de validación."],
    why: CERT_WARNING,
    action: [`${ASK("https")} revise el certificado de seguridad de tu web.`],
  }),
  "https:tls_error": () => ({
    found: ["No hemos podido establecer una conexión segura con tu web."],
    why: "Tus visitantes podrían ver avisos de seguridad o no poder entrar de forma segura.",
    action: [
      `${ASK("https")} revise la configuración de seguridad de tu web.`,
      "Puedes enseñarle los detalles técnicos de este resultado.",
    ],
  }),
  "https:https_not_available": () => ({
    found: ["Tu web no ofrece una versión segura: el servidor no acepta conexiones seguras."],
    why: "Los navegadores suelen avisar de que la web no es segura, lo que resta confianza a quienes te visitan.",
    action: [`${ASK("https")} active la versión segura de tu web.`],
  }),

  // ---- Configuración del dominio ----
  "dns:no_records": () => ({
    found: ["No hemos podido confirmar correctamente la conexión de tu dominio con el servicio que debería responder por él."],
    why: "Si tu dominio no está bien conectado con el servicio que aloja tu web, tus clientes podrían no llegar a ella al escribir tu dirección.",
    action: [
      "Vuelve a analizar el dominio en unos minutos.",
      `Si sigue igual, pide a ${WHO.dns} que compruebe a qué servicio web está conectado. Si solo usas este dominio para el correo, es posible que no sea un problema.`,
    ],
  }),

  // ---- Correo electrónico ----
  "mx:missing_mx": (ctx) => ({
    found: ["No hemos encontrado una configuración que indique dónde debe recibir el correo electrónico de tu dominio."],
    why: `Si utilizas direcciones como info@${ctx.domain}, esto puede impedir que recibas correctamente algunos mensajes.`,
    action: [
      `${ASK("mx")} revise la configuración del correo.`,
      "Si no usas correo con este dominio, es posible que no sea un problema.",
    ],
  }),
  "mx:mx_resolution_issue": () => ({
    found: [
      "Tu dominio indica dónde recibir el correo, pero al menos uno de esos servicios no se ha podido localizar correctamente.",
    ],
    why: "Esto puede provocar problemas al recibir algunos mensajes.",
    action: [`${ASK("mx")} revise la configuración del correo.`],
  }),

  // ---- Protección del correo (SPF) ----
  "spf:missing_spf": () => ({
    found: [
      "Tu dominio no tiene configurada una protección que ayuda a indicar qué servicios están autorizados a enviar correos en nombre de tu empresa.",
    ],
    why: "Sin ella, algunos correos de tu empresa podrían tener más dificultades para llegar a la bandeja de entrada de tus clientes y acabar en spam.",
    action: [`${ASK("spf")} revise la configuración y añada la protección correspondiente.`],
  }),
  "spf:multiple_spf_records": () => ({
    found: [
      "Tu dominio tiene varias configuraciones que indican qué servicios pueden enviar correos en nombre de tu empresa, y pueden entrar en conflicto entre sí.",
    ],
    why: "Esto puede provocar que algunos servicios no sepan correctamente qué servidores están autorizados a enviar tus correos.",
    action: [`${ASK("spf")} revise las configuraciones existentes y las unifique en una única configuración válida.`],
  }),

  // ---- Protección contra suplantaciones (DMARC) ----
  "dmarc:missing_dmarc": () => ({
    found: [
      "Tu dominio no tiene activada una protección que ayuda a evitar que otras personas envíen correos haciéndose pasar por tu empresa.",
    ],
    why: "Sin esta protección, alguien podría intentar enviar correos haciéndose pasar por tu empresa y afectar a la confianza de tus clientes. No hemos detectado que esto esté ocurriendo: se trata de una medida preventiva.",
    action: [
      `${ASK("dmarc")} configure esta protección.`,
      "Si no sabes quién lo gestiona, normalmente será la empresa que lleva tu web, tu correo profesional o tu dominio.",
    ],
  }),
  "dmarc:multiple_dmarc_records": () => ({
    found: ["Tu dominio tiene varias configuraciones de esta protección y pueden entrar en conflicto entre sí."],
    why: "Esto puede hacer que la protección contra correos que se hacen pasar por tu empresa no funcione como debería.",
    action: [`${ASK("dmarc")} revise las configuraciones existentes y las unifique en una única configuración válida.`],
  }),
  "dmarc:invalid_dmarc_record": () => ({
    found: ["Tu dominio tiene activada una protección contra correos que se hacen pasar por tu empresa, pero su configuración contiene un error."],
    why: "Con ese error, la protección puede no funcionar como debería.",
    action: [`${ASK("dmarc")} revise y corrija esta configuración.`],
  }),
};

// ---------------------------------------------------------------------------
// "No se ha podido verificar" (unknown): nunca se presenta como problema
// ---------------------------------------------------------------------------

const BLOCKED = new Set(["blocked_private_ip", "blocked_non_public_ip", "blocked_redirect"]);

/** Qué no hemos podido comprobar, por comprobación (frase que sigue a "No hemos podido comprobar"). */
const UNKNOWN_SUBJECT = {
  web: "si tu web está disponible",
  https: "el certificado de seguridad de tu web",
  dns: "si tu dominio está bien conectado con el servicio que responde por tu web",
  mx: "dónde debe recibir el correo electrónico tu dominio",
  spf: "la protección que indica qué servicios pueden enviar correos en nombre de tu empresa",
  dmarc: "la protección contra correos que se hacen pasar por tu empresa",
};

/** Qué conviene que revise quien gestiona la parte técnica. */
const UNKNOWN_CHECK_TARGET = {
  web: "que el servicio está funcionando correctamente",
  https: "que el certificado de seguridad está en orden",
  dns: "que la conexión con tu web es correcta",
  mx: "que el correo de tu dominio está bien configurado",
  spf: "que esta protección está configurada",
  dmarc: "que esta protección está configurada",
};

/** Por qué importa la comprobación cuando no hemos podido hacerla (sin afirmar que haya un problema). */
const UNKNOWN_WHY = {
  web: "Si tu web no responde correctamente, tus clientes podrían tener dificultades para acceder a ella, consultar tus servicios o ponerse en contacto contigo.",
  https: "Si el certificado de seguridad no está en orden, los navegadores pueden mostrar avisos a tus visitantes y hacerles dudar de tu web.",
  dns: "Si tu dominio no está bien conectado con tu web, tus clientes podrían no llegar a ella al escribir tu dirección.",
  mx: "Si el correo de tu dominio no está bien configurado, podrías no recibir algunos mensajes de tus clientes.",
  spf: "Esta protección ayuda a que los correos de tu empresa lleguen a la bandeja de entrada de tus clientes y no acaben en spam.",
  dmarc: "Esta protección ayuda a evitar que otras personas envíen correos haciéndose pasar por tu empresa.",
};

/** Motivo conocido y seguro de que no se pudiera comprobar (frase que sigue a "porque"), o null. */
function unknownCause(key, reason) {
  switch (reason) {
    case "timeout":
      if (key === "web") return "tu página ha tardado demasiado en responder";
      if (key === "https") return "la conexión segura ha tardado demasiado en responder";
      return "la consulta sobre tu dominio ha tardado demasiado en responder";
    case "dns_resolution_error":
      return "no hemos encontrado tu dominio en Internet en este momento";
    case "connection_error":
      if (key === "web") return "no hemos conseguido conectar con ella";
      if (key === "https") return "no hemos conseguido conectar con la parte segura de tu web";
      return null;
    case "dns_error":
    case "dns_lookup_error":
      return "no hemos recibido una respuesta clara al consultar la configuración de tu dominio";
    default:
      return null; // unexpected_status_*, request_error, unknown_error… sin inventar causas
  }
}

function unknownExplanation(key, result) {
  const reason = result.technical_reason || "";
  const blocked = BLOCKED.has(reason);
  const cause = blocked ? null : unknownCause(key, reason);

  // Una sola frase en "Qué hemos encontrado": qué no hemos podido comprobar y, si se sabe, por qué.
  const found = blocked
    ? `No hemos podido comprobar ${UNKNOWN_SUBJECT[key]}: por motivos de seguridad, Nersivo no analiza esa dirección.`
    : `No hemos podido comprobar ${UNKNOWN_SUBJECT[key]}${cause ? ` porque ${cause}` : " en este momento"}.`;

  const action = [];
  if (blocked) {
    action.push("Comprueba que el dominio esté bien escrito y que sea público.");
  } else if (reason === "dns_resolution_error") {
    action.push("Comprueba que el nombre del dominio esté bien escrito y vuelve a analizarlo en unos minutos.");
  } else {
    action.push("Vuelve a analizar el dominio en unos minutos.");
    action.push(`Si sigue sin poder comprobarse, pide a ${WHO[key]} que compruebe ${UNKNOWN_CHECK_TARGET[key]}.`);
  }

  return { found: [found], why: UNKNOWN_WHY[key], action };
}

// ---------------------------------------------------------------------------
// Conviene revisarlo / hay un problema sin texto específico: texto de reserva (el original del backend va a los detalles técnicos)
// ---------------------------------------------------------------------------

/** De qué trata cada comprobación, para el texto de reserva. */
const TOPIC = {
  web: "el funcionamiento de tu web",
  https: "la seguridad de tu web",
  dns: "la configuración de tu dominio",
  mx: "el correo electrónico de tu dominio",
  spf: "la protección del correo de tu dominio",
  dmarc: "la protección de tu dominio contra suplantaciones",
};

// Texto de reserva para códigos no contemplados. No usa el texto del backend (puede contener
// términos técnicos); ese texto original sigue disponible en «Ver detalles técnicos».
function genericExplanation(key, result, status) {
  return {
    found: [
      status === "error"
        ? `Hemos encontrado un problema en ${TOPIC[key]} que conviene corregir.`
        : `Hemos encontrado algo que conviene revisar en ${TOPIC[key]}.`,
    ],
    why: GENERAL_WHY[key],
    action: [`${ASK(key)} revise este punto.`, "Puedes facilitarle el resultado del análisis y sus detalles técnicos."],
  };
}

// ---------------------------------------------------------------------------
// Frase de estado (misma jerarquía en los seis checks)
//   warning -> «Conviene revisarlo»: no es necesariamente grave.
//   error   -> «Hay un problema»: problema confirmado por el análisis.
// ok y unknown no la usan: su explicación ya cumple esa función y evitamos repetir.
// No se afirma que la web funcione o esté caída si el análisis no lo confirma.
// ---------------------------------------------------------------------------

const WARNING_HEADLINE = {
  web: "Hay un aspecto de tu web que conviene revisar.",
  https: "La seguridad de tu web funciona, pero hay una configuración que debería revisarse.",
  dns: "Hay un aspecto de la configuración de tu dominio que conviene revisar.",
  mx: "Hay un aspecto de la configuración de tu correo que conviene revisar.",
  spf: "La protección de tu correo podría mejorarse.",
  dmarc: "La protección de tu dominio contra suplantaciones podría mejorarse.",
};

const ERROR_HEADLINE = {
  web: "Hemos detectado un problema que puede afectar al funcionamiento de tu web.",
  https: "Hemos detectado un problema de seguridad que deberías solucionar.",
  dns: "Hemos detectado un problema en la configuración de tu dominio que conviene solucionar.",
  mx: "Hemos detectado una configuración de correo que puede impedir su funcionamiento correcto.",
  spf: "Hemos detectado una configuración de la protección del correo que puede afectar a que tus mensajes lleguen correctamente.",
  dmarc: "Hemos detectado un problema en la protección contra suplantaciones que conviene solucionar.",
};

/**
 * @param {CheckKey} key
 * @param {CheckResult} result
 * @param {"ok"|"warning"|"error"|"unknown"} status
 * @returns {string | null}
 */
export function statusHeadline(key, result, status) {
  if (status === "warning") {
    // Aquí sí sabemos que la web responde (el análisis la ha cargado).
    if (key === "web" && result.technical_reason === "no_https_redirect") {
      return "Tu web funciona, pero hay un aspecto que conviene revisar.";
    }
    return WARNING_HEADLINE[key] || null;
  }
  if (status === "error") return ERROR_HEADLINE[key] || null;
  return null;
}

// ---------------------------------------------------------------------------
// API del módulo
// ---------------------------------------------------------------------------

/**
 * @param {CheckKey} key
 * @param {CheckResult} result
 * @param {"ok"|"warning"|"error"|"unknown"} status
 * @param {{domain: string}} ctx
 */
export function explainCheck(key, result, status, ctx) {
  const reason = typeof result.technical_reason === "string" ? result.technical_reason : "";
  const full = {
    domain: ctx.domain || "tudominio.com",
    details: result.details && typeof result.details === "object" ? result.details : {},
  };

  if (status === "ok") return okExplanation(key, result, full);
  if (status === "unknown") {
    // Algunos "unknown" tienen texto propio más útil (p. ej. dominio sin dirección asociada).
    const own = SPECIFIC[`${key}:${reason}`];
    if (own) return own(full);
    return unknownExplanation(key, result);
  }

  // warning / error
  let id = `${key}:${reason}`;
  if (key === "web" && /^http_4\d\d$/.test(reason)) id = "web:http_4xx";
  const specific = id === "web:http_4xx"
    ? () => ({
        found: ["Hemos intentado acceder a tu página, pero el servidor no nos ha entregado su página principal."],
        why: "Esto puede impedir que algunos visitantes puedan acceder a tu web.",
        action: [
          "Te recomendamos contactar con quien gestione tu alojamiento o tu página web y facilitarle el resultado del análisis.",
          "Puedes enseñarle los detalles técnicos de este resultado.",
        ],
      })
    : SPECIFIC[id];
  return specific ? specific(full) : genericExplanation(key, result, status);
}
