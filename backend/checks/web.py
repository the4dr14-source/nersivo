"""
Comprobación real de disponibilidad WEB de un dominio.

Este módulo implementa `check_web`, que realiza una petición HTTP al dominio
y determina si el sitio web responde correctamente, mide el tiempo de
respuesta y detecta si redirige a HTTPS.

Consideraciones de seguridad:
- Timeout acotado (10 s) para no bloquear el servidor.
- Número máximo de redirecciones limitado (10) para evitar bucles.
- User-Agent identificable ("Nersivo/1.0").
- Solo se realizan peticiones GET al dominio recibido (ya validado por
  `domain_utils`), evitando su uso como proxy abierto.
- Protección SSRF (`net_safety.safe_get`): se resuelve el hostname, se exige que
  todas sus IPs sean públicas y los redirects se siguen de forma manual
  validando cada destino antes de conectar.
"""

import socket
import time
from typing import List, Optional

import httpx

from .. import net_safety
from ..models import CheckResult, Severity, Status

# --- Constantes de configuración -----------------------------------------
_TIMEOUT_SECONDS = 10.0
_MAX_REDIRECTS = 10
_USER_AGENT = "Nersivo/1.0 (Domain Analyzer)"
_TITLE = "Sitio web"


def _build_details(
    requested_url: str,
    final_url: Optional[str],
    status_code: Optional[int],
    response_time_ms: Optional[int],
    error: Optional[str],
    timeout: bool,
    redirect_chain: Optional[List[str]] = None,
    final_is_https: Optional[bool] = None,
    redirected_to_https: Optional[bool] = None,
) -> dict:
    """
    Construye el diccionario `details` del CheckResult de web.

    Mantiene siempre las mismas claves base del contrato y añade información
    adicional útil sobre las redirecciones y el estado de HTTPS.

    Args:
        requested_url: URL inicial solicitada (http://dominio).
        final_url: URL final tras seguir redirecciones (o None).
        status_code: Código HTTP final (o None si no se obtuvo).
        response_time_ms: Tiempo de respuesta en milisegundos (o None).
        error: Código técnico de error (o None si no hubo).
        timeout: True si la petición agotó el tiempo de espera.
        redirect_chain: Lista de URLs por las que pasó la petición.
        final_is_https: True si la URL final usa el esquema https://.
        redirected_to_https: True si hubo un cambio real de http:// a https://
            en algún punto de la cadena de redirecciones.

    Returns:
        Diccionario con los detalles del check.
    """
    return {
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "error": error,
        "timeout": timeout,
        "redirect_chain": redirect_chain if redirect_chain is not None else [],
        "final_is_https": final_is_https,
        "redirected_to_https": redirected_to_https,
    }


def _detect_redirect_to_https(redirect_chain: List[str]) -> bool:
    """
    Detecta si en la cadena de redirecciones hubo un cambio de HTTP a HTTPS.

    Recorre las URLs consecutivas de la cadena y devuelve True en cuanto
    encuentra un paso en el que una URL http:// es seguida por una https://.

    Args:
        redirect_chain: Lista de URLs (strings) por las que pasó la petición,
            en orden. El primer elemento es la URL inicial y el último la final.

    Returns:
        True si hubo una redirección real de http:// a https://, False si no.
    """
    if not redirect_chain or len(redirect_chain) < 2:
        return False

    for i in range(len(redirect_chain) - 1):
        current_url = (redirect_chain[i] or "").lower()
        next_url = (redirect_chain[i + 1] or "").lower()
        if current_url.startswith("http://") and next_url.startswith("https://"):
            return True

    return False


def check_web(
    domain: str, *, transport: Optional[httpx.BaseTransport] = None
) -> CheckResult:
    """
    Comprueba la disponibilidad web de un dominio.

    Realiza una petición GET a `http://{domain}` siguiendo redirecciones de
    forma controlada, mide el tiempo de respuesta y evalúa el resultado según
    el código HTTP final.

    Reglas de estado:
    - 2xx  -> ok (si además redirige a HTTPS, se menciona en el summary).
    - 3xx final (no se resolvió) -> warning (configuración de redirección).
    - 4xx  -> error (problema del dominio/recurso).
    - 5xx  -> error (problema del servidor).
    - Timeout -> unknown (technical_reason="timeout").
    - Error de conexión/DNS -> unknown (technical_reason apropiado).
    - Cualquier otra excepción -> unknown.

    - Destino bloqueado por seguridad (IP no pública, redirect peligroso) ->
      unknown, checked=False (technical_reason `blocked_private_ip`,
      `blocked_non_public_ip` o `blocked_redirect`). No se afirma que el
      dominio tenga un problema: Nersivo simplemente no pudo verificarlo.

    Args:
        domain: Dominio ya validado y normalizado (sin esquema ni ruta).
        transport: Transporte httpx alternativo (solo para tests).

    Returns:
        CheckResult compatible con el contrato JSON de Nersivo.
    """
    requested_url = f"http://{domain}"

    # Configuración del cliente HTTP con límites de seguridad.
    headers = {"User-Agent": _USER_AGENT}

    start = time.time()
    try:
        response = net_safety.safe_get(
            requested_url,
            timeout=_TIMEOUT_SECONDS,
            max_redirects=_MAX_REDIRECTS,
            headers=headers,
            transport=transport,
        )
        elapsed_ms = int((time.time() - start) * 1000)

        final_url = response.final_url
        status_code = response.status_code

        # Cadena de redirecciones: primera URL = solicitada, última = final.
        redirect_chain: List[str] = list(response.redirect_chain)
        if not redirect_chain or redirect_chain[0].lower() != requested_url.lower():
            redirect_chain.insert(0, requested_url)

        # Distinguimos dos conceptos diferentes:
        # - final_is_https: la URL final usa el esquema https://.
        # - redirected_to_https: hubo un cambio real de http:// a https://
        #   en algún punto de la cadena de redirecciones.
        final_is_https = final_url.lower().startswith("https://")
        redirected_to_https = _detect_redirect_to_https(redirect_chain)

        details = _build_details(
            requested_url=requested_url,
            final_url=final_url,
            status_code=status_code,
            response_time_ms=elapsed_ms,
            error=None,
            timeout=False,
            redirect_chain=redirect_chain,
            final_is_https=final_is_https,
            redirected_to_https=redirected_to_https,
        )

        # --- Evaluación por rango de código HTTP -------------------------
        if 200 <= status_code < 300:
            # Sitio disponible.
            if final_is_https and redirected_to_https:
                # Redirige de forma automática y segura a HTTPS.
                return CheckResult(
                    status=Status.OK,
                    severity=Severity.NONE,
                    title=_TITLE,
                    summary=(
                        "El sitio responde correctamente y redirige de forma "
                        "segura a HTTPS."
                    ),
                    checked=True,
                    details=details,
                    technical_reason=None,
                    recommendation=None,
                    user_message=None,
                )

            if final_is_https:
                # La URL final ya es HTTPS aunque no detectamos un salto
                # explícito http->https (p. ej. se solicitó y respondió en
                # HTTPS directamente): se considera correcto.
                return CheckResult(
                    status=Status.OK,
                    severity=Severity.NONE,
                    title=_TITLE,
                    summary=(
                        "El sitio responde correctamente mediante HTTPS."
                    ),
                    checked=True,
                    details=details,
                    technical_reason=None,
                    recommendation=None,
                    user_message=None,
                )

            # final_is_https == False: responde por HTTP y no fuerza HTTPS.
            return CheckResult(
                status=Status.WARNING,
                severity=Severity.LOW,
                title=_TITLE,
                summary=(
                    "El sitio responde correctamente pero no fuerza "
                    "automáticamente la redirección a HTTPS."
                ),
                checked=True,
                details=details,
                technical_reason="no_https_redirect",
                recommendation=(
                    "Se recomienda configurar una redirección automática de "
                    "HTTP a HTTPS para mayor seguridad."
                ),
                user_message="Tu web funciona, pero podría ser más segura usando HTTPS.",
            )

        if 300 <= status_code < 400:
            # La respuesta final sigue siendo una redirección: la cadena no
            # se resolvió correctamente (posible configuración incorrecta).
            details["error"] = "unresolved_redirect"
            return CheckResult(
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                title=_TITLE,
                summary=(
                    "El sitio devuelve una redirección que no se resuelve "
                    "correctamente."
                ),
                checked=True,
                details=details,
                technical_reason="unresolved_redirect",
                recommendation=(
                    "Revisa la configuración de redirecciones del servidor; "
                    "parece que apuntan a un destino que no responde."
                ),
                user_message=(
                    "Tu web tiene un problema de configuración en las "
                    "redirecciones."
                ),
            )

        if 400 <= status_code < 500:
            # Error del lado del cliente/recurso.
            details["error"] = f"http_{status_code}"
            return CheckResult(
                status=Status.ERROR,
                severity=Severity.HIGH,
                title=_TITLE,
                summary=(
                    f"El sitio responde con un error {status_code} "
                    "(no se encuentra el contenido)."
                ),
                checked=True,
                details=details,
                technical_reason=f"http_{status_code}",
                recommendation=(
                    "Verifica que la página principal del dominio esté "
                    "publicada y accesible."
                ),
                user_message="Tu web no está mostrando contenido accesible.",
            )

        if 500 <= status_code < 600:
            # Error del lado del servidor.
            details["error"] = f"http_{status_code}"
            return CheckResult(
                status=Status.ERROR,
                severity=Severity.HIGH,
                title=_TITLE,
                summary=(
                    f"El servidor responde con un error {status_code} "
                    "(problema del servidor)."
                ),
                checked=True,
                details=details,
                technical_reason="http_5xx",
                recommendation=(
                    "El servidor está devolviendo errores. Contacta con tu "
                    "proveedor de hosting."
                ),
                user_message="Tu web está teniendo problemas técnicos en el servidor.",
            )

        # Código HTTP fuera de los rangos habituales (1xx u otros): unknown.
        details["error"] = f"unexpected_status_{status_code}"
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido determinar el estado del sitio web.",
            checked=True,
            details=details,
            technical_reason=f"unexpected_status_{status_code}",
            recommendation=None,
            user_message=None,
        )

    except net_safety.BlockedDestinationError as exc:
        # Destino bloqueado por seguridad (SSRF). No es un problema del dominio
        # analizado: Nersivo no ha podido verificarlo -> unknown, checked=False.
        # No se expone ninguna IP ni dato interno del servidor.
        elapsed_ms = int((time.time() - start) * 1000)
        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error=exc.code,
            timeout=False,
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary=net_safety.BLOCKED_SUMMARY,
            checked=False,
            details=details,
            technical_reason=exc.code,
            recommendation=None,
            user_message=net_safety.BLOCKED_SUMMARY,
        )

    except socket.gaierror:
        # El nombre no resuelve (antes lo envolvía httpx.ConnectError).
        elapsed_ms = int((time.time() - start) * 1000)
        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error="dns_resolution_error",
            timeout=False,
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido resolver el dominio.",
            checked=True,
            details=details,
            technical_reason="dns_resolution_error",
            recommendation=(
                "Comprueba que el dominio está activo y que el servidor web "
                "está en funcionamiento."
            ),
            user_message="No hemos podido encontrar tu dominio en Internet.",
        )

    except httpx.TooManyRedirects:
        # Se superó el límite de redirecciones: posible bucle.
        elapsed_ms = int((time.time() - start) * 1000)
        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error="too_many_redirects",
            timeout=False,
        )
        return CheckResult(
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            title=_TITLE,
            summary="El sitio entra en un bucle de redirecciones.",
            checked=True,
            details=details,
            technical_reason="too_many_redirects",
            recommendation=(
                "Revisa la configuración de redirecciones; parece haber un "
                "bucle que impide cargar la web."
            ),
            user_message="Tu web tiene un problema de redirecciones que impide abrirla.",
        )

    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout, httpx.TimeoutException):
        # Timeout: no podemos determinar el estado -> unknown (no error).
        elapsed_ms = int((time.time() - start) * 1000)
        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error="timeout",
            timeout=True,
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="El sitio ha tardado demasiado en responder.",
            checked=True,
            details=details,
            technical_reason="timeout",
            recommendation=(
                "El servidor tarda demasiado en responder. Puede ser algo "
                "temporal; inténtalo de nuevo más tarde."
            ),
            user_message="No hemos podido comprobar tu web porque tarda demasiado en responder.",
        )

    except httpx.ConnectError as exc:
        # Error de conexión: DNS no resuelve, host inaccesible, etc.
        elapsed_ms = int((time.time() - start) * 1000)
        message = str(exc).lower()
        # Distinguimos, dentro de lo posible, un fallo de resolución DNS.
        if "name or service not known" in message or "nodename nor servname" in message or "getaddrinfo" in message:
            technical_reason = "dns_resolution_error"
            summary = "No se ha podido resolver el dominio."
            user_message = "No hemos podido encontrar tu dominio en Internet."
        else:
            technical_reason = "connection_error"
            summary = "No se ha podido conectar con el sitio web."
            user_message = "No hemos podido conectar con tu web en este momento."

        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error=technical_reason,
            timeout=False,
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary=summary,
            checked=True,
            details=details,
            technical_reason=technical_reason,
            recommendation=(
                "Comprueba que el dominio está activo y que el servidor web "
                "está en funcionamiento."
            ),
            user_message=user_message,
        )

    except httpx.HTTPError as exc:
        # Cualquier otro error de httpx no contemplado arriba.
        elapsed_ms = int((time.time() - start) * 1000)
        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error="request_error",
            timeout=False,
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido completar la comprobación del sitio web.",
            checked=True,
            details=details,
            technical_reason="request_error",
            recommendation=None,
            user_message=None,
        )

    except Exception:  # noqa: BLE001 - último recurso: nunca dejar caer la API.
        # Cualquier excepción inesperada -> unknown, sin romper la API.
        elapsed_ms = int((time.time() - start) * 1000)
        details = _build_details(
            requested_url=requested_url,
            final_url=None,
            status_code=None,
            response_time_ms=elapsed_ms,
            error="unknown_error",
            timeout=False,
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido determinar el estado del sitio web.",
            checked=True,
            details=details,
            technical_reason="unknown_error",
            recommendation=None,
            user_message=None,
        )