"""
Comprobación real de registros MX (correo entrante) de un dominio.

Este módulo implementa `check_mx`, que consulta los registros MX del dominio
mediante dnspython y, además, verifica que cada servidor de correo (hostname MX)
sea resoluble (que tenga al menos un registro A o AAAA).

Criterios de diseño:
- Los registros MX se consultan con un timeout acotado (5 s) para no bloquear
  el servidor.
- La ausencia total de registros MX se considera un ERROR: sin MX el dominio no
  puede recibir correo.
- Si existen registros MX pero alguno de sus hostnames no resuelve, se marca
  como WARNING (posible configuración incorrecta), sin afirmar que sea un fallo
  total. Solo cuenta como "no resuelve" un NXDOMAIN o un hostname sin A/AAAA
  confirmado; si el DNS falla temporalmente (timeout, SERVFAIL, NoNameservers)
  y no hay ningún fallo confirmado, el resultado es UNKNOWN con checked=False
  (`resolves: null` en ese registro).
- Los fallos de consulta DNS del propio dominio (NXDOMAIN, timeout u otros
  errores) se marcan como UNKNOWN con `checked=False`, nunca como ERROR, porque
  no podemos determinar con certeza el estado real del correo.
"""

from typing import List, Optional, Tuple

import dns.exception
import dns.resolver

from ..models import CheckResult, Severity, Status

# --- Constantes de configuración -----------------------------------------
_TIMEOUT_SECONDS = 5.0
_TITLE = "Correo entrante (MX)"


def _build_details(
    found: bool,
    records: List[dict],
    error: Optional[str],
) -> dict:
    """
    Construye el diccionario `details` del CheckResult de MX.

    Mantiene siempre las mismas claves definidas en el contrato.

    Args:
        found: True si se ha encontrado al menos un registro MX.
        records: Lista de registros MX, cada uno con priority, hostname y
            resolves.
        error: Código técnico de error (o None si no hubo).

    Returns:
        Diccionario con los detalles del check.
    """
    return {
        "found": found,
        "records": records,
        "error": error,
    }


def _hostname_resolves(hostname: str) -> Optional[bool]:
    """
    Comprueba si un hostname MX resuelve (tiene A o AAAA), distinguiendo
    "no existe" de "no se ha podido comprobar".

    Consulta A (IPv4) y AAAA (IPv6) de forma independiente:

    - Alguna consulta devuelve registros            -> True (resuelve).
    - NXDOMAIN (el nombre no existe)                -> False (problema real).
    - NoAnswer en A y AAAA (existe pero sin IP)     -> False (problema real).
    - Timeout / SERVFAIL / NoNameservers / otro
      fallo DNS y ninguna consulta confirma nada    -> None (no verificable).

    `None` significa "no podemos afirmar que el hostname no exista": quien llama
    no debe tratarlo como un fallo del dominio.

    Args:
        hostname: Nombre del servidor de correo (hostname del registro MX).

    Returns:
        True, False o None según lo descrito.
    """
    temporary_failure = False
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(
                hostname, record_type, lifetime=_TIMEOUT_SECONDS
            )
            if len(answers) > 0:
                return True
        except dns.resolver.NXDOMAIN:
            # El nombre no existe para ningún tipo de registro.
            return False
        except dns.resolver.NoAnswer:
            # El nombre existe pero no tiene este tipo de registro: probamos
            # el siguiente tipo.
            continue
        except Exception:  # noqa: BLE001 - Timeout, NoNameservers, SERVFAIL...
            temporary_failure = True
            continue

    return None if temporary_failure else False


def _query_mx(domain: str) -> Tuple[List[Tuple[int, str]], Optional[str]]:
    """
    Consulta los registros MX del dominio.

    Args:
        domain: Dominio a consultar (ya validado y normalizado).

    Returns:
        Una tupla `(records, error)` donde:
        - `records` es una lista de tuplas `(priority, hostname)` ordenadas por
          prioridad ascendente (vacía si no hay registros o si hubo error).
        - `error` es un código técnico de error, o None si la consulta fue
          correcta. Posibles valores: "dns_resolution_error" (NXDOMAIN),
          "timeout", "no_records" (NoAnswer) o "dns_error" (otros errores).
    """
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=_TIMEOUT_SECONDS)
        records: List[Tuple[int, str]] = []
        for rdata in answers:
            priority = int(rdata.preference)
            # `exchange` es un nombre absoluto con punto final; lo normalizamos.
            hostname = str(rdata.exchange).rstrip(".")
            records.append((priority, hostname))

        # Ordenamos por prioridad ascendente (menor número = mayor prioridad).
        records.sort(key=lambda item: item[0])
        return records, None

    except dns.resolver.NXDOMAIN:
        # El dominio no existe en el DNS.
        return [], "dns_resolution_error"

    except dns.resolver.NoAnswer:
        # El dominio responde pero no tiene registros MX.
        return [], "no_records"

    except dns.resolver.Timeout:
        # La consulta agotó el tiempo de espera.
        return [], "timeout"

    except (dns.resolver.NoNameservers, dns.exception.DNSException):
        # Otros errores DNS (servidores no disponibles, fallos varios, etc.).
        return [], "dns_error"

    except Exception:  # noqa: BLE001 - último recurso: nunca romper la API.
        # Cualquier excepción inesperada se trata como error DNS genérico.
        return [], "dns_error"


def check_mx(domain: str) -> CheckResult:
    """
    Comprueba los registros MX (correo entrante) de un dominio.

    Consulta los registros MX del dominio y verifica que cada servidor de correo
    listado sea resoluble (tenga al menos un registro A o AAAA).

    Reglas de estado:
    - 0 registros MX (NoAnswer) -> error (severity high,
      technical_reason "missing_mx").
    - 1+ registros MX y todos resuelven -> ok (severity none).
    - 1+ registros MX pero alguno no resuelve -> warning (severity medium,
      technical_reason "mx_resolution_issue").
    - NXDOMAIN -> unknown (severity unknown, technical_reason
      "dns_resolution_error", checked=False).
    - Timeout -> unknown (severity unknown, technical_reason "timeout",
      checked=False).
    - Otros errores DNS -> unknown (severity unknown, technical_reason
      "dns_error", checked=False).

    Args:
        domain: Dominio ya validado y normalizado (sin esquema ni ruta).

    Returns:
        CheckResult compatible con el contrato JSON de Nersivo.
    """
    mx_records, error = _query_mx(domain)

    # --- Fallos de consulta DNS del dominio -> UNKNOWN (checked=False) ---
    if error == "dns_resolution_error":
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar los registros MX del dominio.",
            checked=False,
            details=_build_details(found=False, records=[], error="dns_resolution_error"),
            technical_reason="dns_resolution_error",
            recommendation=(
                "Verifica que el dominio esté correctamente configurado en tu "
                "proveedor DNS."
            ),
            user_message="No hemos podido encontrar tu dominio en Internet.",
        )

    if error == "timeout":
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar los registros MX (timeout).",
            checked=False,
            details=_build_details(found=False, records=[], error="timeout"),
            technical_reason="timeout",
            recommendation=(
                "La consulta DNS ha tardado demasiado. Puede ser algo temporal; "
                "inténtalo de nuevo más tarde."
            ),
            user_message="No hemos podido comprobar tu dominio porque la consulta DNS tardó demasiado.",
        )

    if error == "dns_error":
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar los registros MX del dominio.",
            checked=False,
            details=_build_details(found=False, records=[], error="dns_error"),
            technical_reason="dns_error",
            recommendation=(
                "Se ha producido un problema al consultar el DNS. Comprueba la "
                "configuración de tu proveedor DNS."
            ),
            user_message="No hemos podido comprobar la configuración de correo de tu dominio.",
        )

    # --- Sin registros MX (NoAnswer) -> WARNING -------------------------
    # No sabemos si la organización utiliza correo con este dominio, por lo que
    # la ausencia de MX no se considera un error crítico, sino un aviso prudente.
    if error == "no_records" or not mx_records:
        return CheckResult(
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            title=_TITLE,
            summary="No se han encontrado registros MX para este dominio.",
            checked=True,
            details=_build_details(found=False, records=[], error="missing_mx"),
            technical_reason="missing_mx",
            recommendation=(
                "Si utilizas correo electrónico con este dominio, configura al "
                "menos un registro MX para poder recibir mensajes."
            ),
            user_message=(
                "No hemos encontrado servidores de correo para este dominio. Si "
                "utilizas correo con él, conviene revisar su configuración."
            ),
        )

    # --- Null MX (RFC 7505) -> situación informativa (OK) ----------------
    # Un único registro MX con prioridad 0 y hostname vacío (".") indica de
    # forma explícita que el dominio NO acepta correo. No es un fallo, sino una
    # declaración intencionada de "sin correo", por lo que NO se trata como
    # problema (status ok / severity none).
    if len(mx_records) == 1 and mx_records[0][1] == "":
        priority = mx_records[0][0]
        return CheckResult(
            status=Status.OK,
            severity=Severity.NONE,
            title=_TITLE,
            summary="El dominio está configurado para no recibir correo.",
            checked=True,
            details=_build_details(
                found=True,
                records=[{"priority": priority, "hostname": "", "resolves": False}],
                error="null_mx",
            ),
            technical_reason="null_mx",
            recommendation=None,
            user_message=(
                "Este dominio está configurado para no recibir correo "
                "electrónico. Si es intencionado, no requiere ninguna acción."
            ),
        )

    # --- Hay registros MX: verificamos que cada hostname resuelva -------
    # resolves: True (resuelve), False (no existe / sin IP) o None (no se pudo
    # comprobar por un fallo temporal de DNS).
    records_details: List[dict] = []
    for priority, hostname in mx_records:
        records_details.append(
            {
                "priority": priority,
                "hostname": hostname,
                "resolves": _hostname_resolves(hostname),
            }
        )

    all_resolve = all(r["resolves"] is True for r in records_details)
    any_failed = any(r["resolves"] is False for r in records_details)
    any_unverifiable = any(r["resolves"] is None for r in records_details)

    if all_resolve:
        return CheckResult(
            status=Status.OK,
            severity=Severity.NONE,
            title=_TITLE,
            summary="Se han encontrado registros MX válidos.",
            checked=True,
            details=_build_details(found=True, records=records_details, error=None),
            technical_reason=None,
            recommendation=None,
            user_message=None,
        )

    # Sin ningún fallo confirmado pero con hostnames que no se han podido
    # comprobar (timeout/SERVFAIL): no podemos afirmar que estén mal -> UNKNOWN.
    if not any_failed and any_unverifiable:
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary=(
                "No hemos podido comprobar si los servidores de correo (MX) "
                "resuelven (fallo temporal de DNS)."
            ),
            checked=False,
            details=_build_details(
                found=True, records=records_details, error="dns_error"
            ),
            technical_reason="dns_error",
            recommendation=(
                "La consulta DNS ha fallado temporalmente. Inténtalo de nuevo "
                "más tarde."
            ),
            user_message=(
                "No hemos podido comprobar la configuración de correo de tu "
                "dominio. Puede ser algo temporal."
            ),
        )

    # Al menos un hostname MX no resuelve -> WARNING.
    return CheckResult(
        status=Status.WARNING,
        severity=Severity.MEDIUM,
        title=_TITLE,
        summary="Alguno de los servidores de correo (MX) no resuelve correctamente.",
        checked=True,
        details=_build_details(
            found=True, records=records_details, error="mx_resolution_issue"
        ),
        technical_reason="mx_resolution_issue",
        recommendation=(
            "Revisa que todos los servidores de correo (registros MX) apunten a "
            "hostnames con direcciones IP válidas (registros A o AAAA)."
        ),
        user_message="La configuración de correo de tu dominio podría tener problemas de entrega.",
    )
