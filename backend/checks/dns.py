"""
Comprobación real de resolución DNS de un dominio.

Este módulo implementa `check_dns`, que consulta de forma independiente los
registros A (IPv4) y AAAA (IPv6) del dominio mediante dnspython y determina si
el dominio resuelve correctamente.

Criterios de diseño:
- Las consultas A y AAAA se realizan por separado, con manejo de excepciones
  individual: si la de A falla, la de AAAA se intenta igualmente.
- La ausencia de registros AAAA NUNCA es un error ni un aviso; un dominio con
  solo A (o solo AAAA) se considera correcto.
- Los estados problemáticos (dominio inexistente, timeout, sin registros, otros
  errores) se marcan como `unknown`, nunca como `error`, porque no podemos
  afirmar con certeza que el dominio esté mal configurado.
- Timeout acotado (5 s) por consulta para no bloquear el servidor.
"""

from typing import List, Optional

import dns.exception
import dns.resolver

from ..models import CheckResult, Severity, Status

# --- Constantes de configuración -----------------------------------------
_TIMEOUT_SECONDS = 5.0
_TITLE = "DNS"


def _build_details(
    resolves: bool,
    a_records: List[str],
    aaaa_records: List[str],
    error: Optional[str],
) -> dict:
    """
    Construye el diccionario `details` del CheckResult de DNS.

    Mantiene siempre las mismas claves definidas en el contrato.

    Args:
        resolves: True si el dominio resuelve (hay al menos un A o AAAA).
        a_records: Lista de IPs IPv4 (registros A) como cadenas.
        aaaa_records: Lista de IPs IPv6 (registros AAAA) como cadenas.
        error: Código técnico de error (o None si no hubo).

    Returns:
        Diccionario con los detalles del check.
    """
    return {
        "resolves": resolves,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "error": error,
    }


def _resolve_records(domain: str, record_type: str) -> tuple[List[str], Optional[str]]:
    """
    Resuelve un tipo de registro DNS concreto para el dominio.

    Realiza una única consulta (A o AAAA) con manejo de excepciones propio,
    de modo que el fallo de una consulta no impida intentar la otra.

    Args:
        domain: Dominio a consultar (ya validado y normalizado).
        record_type: Tipo de registro a consultar ("A" o "AAAA").

    Returns:
        Una tupla `(records, error)` donde:
        - `records` es la lista de valores encontrados (vacía si no hay).
        - `error` es un código técnico de error, o None si la consulta fue
          correcta o simplemente no devolvió registros (`NoAnswer`).
          Posibles valores: "dns_resolution_error" (NXDOMAIN), "timeout"
          o "dns_error" (otros errores).
    """
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=_TIMEOUT_SECONDS)
        return [str(rdata) for rdata in answers], None

    except dns.resolver.NXDOMAIN:
        # El dominio no existe en el DNS.
        return [], "dns_resolution_error"

    except dns.resolver.NoAnswer:
        # El dominio existe pero no tiene registros de este tipo. No es un
        # error: simplemente no hay registros A (o AAAA).
        return [], None

    except dns.resolver.Timeout:
        # La consulta agotó el tiempo de espera.
        return [], "timeout"

    except (dns.resolver.NoNameservers, dns.exception.DNSException):
        # Otros errores DNS (servidores no disponibles, fallos varios, etc.).
        return [], "dns_error"

    except Exception:  # noqa: BLE001 - último recurso: nunca romper la API.
        # Cualquier excepción inesperada se trata como error DNS genérico.
        return [], "dns_error"


def check_dns(domain: str) -> CheckResult:
    """
    Comprueba la resolución DNS de un dominio (registros A y AAAA).

    Consulta de forma independiente los registros A (IPv4) y AAAA (IPv6). Si se
    obtiene al menos un registro de cualquiera de los dos tipos, el dominio se
    considera resuelto correctamente (`ok`). En caso contrario, se clasifica el
    resultado como `unknown` con el motivo técnico correspondiente.

    Reglas de estado:
    - Al menos un A o AAAA -> ok (severity none). La ausencia de AAAA (o de A)
      no penaliza.
    - NXDOMAIN (el dominio no existe) -> unknown (technical_reason
      "dns_resolution_error").
    - Timeout -> unknown (technical_reason "timeout"), nunca error.
    - Sin registros A ni AAAA pero sin error de resolución (NoAnswer en ambos)
      -> unknown (technical_reason "no_records").
    - Cualquier otro error DNS -> unknown (technical_reason "dns_error").

    Args:
        domain: Dominio ya validado y normalizado (sin esquema ni ruta).

    Returns:
        CheckResult compatible con el contrato JSON de Nersivo.
    """
    # Consultamos A y AAAA de forma independiente.
    a_records, a_error = _resolve_records(domain, "A")
    aaaa_records, aaaa_error = _resolve_records(domain, "AAAA")

    # --- Caso OK: hay al menos un registro A o AAAA ----------------------
    if a_records or aaaa_records:
        details = _build_details(
            resolves=True,
            a_records=a_records,
            aaaa_records=aaaa_records,
            error=None,
        )
        return CheckResult(
            status=Status.OK,
            severity=Severity.NONE,
            title=_TITLE,
            summary="El dominio resuelve correctamente.",
            checked=True,
            details=details,
            technical_reason=None,
            recommendation=None,
            user_message=None,
        )

    # --- A partir de aquí no hay registros: determinamos el motivo -------
    # Priorizamos NXDOMAIN (el dominio no existe) sobre el resto de motivos,
    # ya que es la señal más informativa.
    if a_error == "dns_resolution_error" or aaaa_error == "dns_resolution_error":
        details = _build_details(
            resolves=False,
            a_records=[],
            aaaa_records=[],
            error="dns_resolution_error",
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar la resolución DNS del dominio.",
            checked=True,
            details=details,
            technical_reason="dns_resolution_error",
            recommendation=(
                "Verifica que el dominio esté correctamente configurado en tu "
                "proveedor DNS."
            ),
            user_message="No hemos podido encontrar tu dominio en Internet.",
        )

    # Timeout en alguna de las consultas.
    if a_error == "timeout" or aaaa_error == "timeout":
        details = _build_details(
            resolves=False,
            a_records=[],
            aaaa_records=[],
            error="timeout",
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar la resolución DNS (timeout).",
            checked=True,
            details=details,
            technical_reason="timeout",
            recommendation=(
                "La consulta DNS ha tardado demasiado. Puede ser algo temporal; "
                "inténtalo de nuevo más tarde."
            ),
            user_message="No hemos podido comprobar tu dominio porque la consulta DNS tardó demasiado.",
        )

    # Otros errores DNS (servidores no disponibles, fallos genéricos, etc.).
    if a_error == "dns_error" or aaaa_error == "dns_error":
        details = _build_details(
            resolves=False,
            a_records=[],
            aaaa_records=[],
            error="dns_error",
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar la resolución DNS del dominio.",
            checked=True,
            details=details,
            technical_reason="dns_error",
            recommendation=(
                "Se ha producido un problema al consultar el DNS. Comprueba la "
                "configuración de tu proveedor DNS."
            ),
            user_message="No hemos podido comprobar la configuración DNS de tu dominio.",
        )

    # Sin registros A ni AAAA, pero sin error de resolución (NoAnswer en ambos).
    details = _build_details(
        resolves=False,
        a_records=[],
        aaaa_records=[],
        error="no_records",
    )
    return CheckResult(
        status=Status.UNKNOWN,
        severity=Severity.UNKNOWN,
        title=_TITLE,
        summary="No se han encontrado registros A ni AAAA para el dominio.",
        checked=True,
        details=details,
        technical_reason="no_records",
        recommendation=(
            "Configura al menos un registro A (IPv4) o AAAA (IPv6) para que el "
            "dominio apunte a un servidor."
        ),
        user_message="No hemos encontrado ninguna dirección IP asociada a tu dominio.",
    )