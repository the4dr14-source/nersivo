"""
Comprobación real de registros SPF de un dominio.

Este módulo implementa `check_spf`, que consulta los registros TXT del dominio
mediante dnspython y detecta los que corresponden a políticas SPF (los que
empiezan por `v=spf1`, sin distinguir mayúsculas/minúsculas).

Criterios de diseño:
- Los registros TXT se consultan con un timeout acotado (5 s) para no bloquear
  el servidor.
- Un registro TXT puede venir dividido en varias cadenas (`rdata.strings`);
  se reconstruye concatenándolas antes de evaluarlo.
- Exactamente un registro SPF -> OK.
- Cero registros SPF -> WARNING (falta SPF, recomendable pero no crítico).
- Varios registros SPF -> ERROR (configuración inválida según el RFC 7208:
  solo puede haber un registro SPF por dominio).
- Los fallos de consulta DNS (NXDOMAIN, timeout u otros errores) se marcan como
  UNKNOWN con `checked=False`, nunca como ERROR, porque no podemos determinar
  con certeza el estado real del SPF.

Alcance de `details.syntax_valid` (IMPORTANTE):
  `syntax_valid=True` significa únicamente que se ha detectado un registro con
  el formato básico `v=spf1` (sin distinguir mayúsculas/minúsculas). NO implica
  una validación completa de la sintaxis SPF: no se parsean mecanismos,
  modificadores, `include:` ni el límite de 10 consultas DNS (RFC 7208). Un
  parser completo queda fuera del alcance del MVP. El nombre del campo se
  mantiene por compatibilidad con el contrato.
"""

from typing import List, Optional, Tuple

import dns.exception
import dns.resolver

from ..models import CheckResult, Severity, Status

# --- Constantes de configuración -----------------------------------------
_TIMEOUT_SECONDS = 5.0
_TITLE = "SPF"
_SPF_PREFIX = "v=spf1"


def _build_details(
    found: bool,
    record_count: int,
    records: List[str],
    syntax_valid: Optional[bool],
    error: Optional[str],
) -> dict:
    """
    Construye el diccionario `details` del CheckResult de SPF.

    Mantiene siempre las mismas claves definidas en el contrato.

    Args:
        found: True si se ha encontrado al menos un registro SPF.
        record_count: Número de registros SPF encontrados.
        records: Lista de registros SPF (cadenas completas reconstruidas).
        syntax_valid: True si se ha detectado exactamente un registro con el
            formato básico `v=spf1`; NO es una validación completa de la
            sintaxis SPF (ver docstring del módulo). None cuando no se ha
            podido/procede evaluar.
        error: Código técnico de error (o None si no hubo).

    Returns:
        Diccionario con los detalles del check.
    """
    return {
        "found": found,
        "record_count": record_count,
        "records": records,
        "syntax_valid": syntax_valid,
        "error": error,
    }


def _query_spf(domain: str) -> Tuple[List[str], Optional[str]]:
    """
    Consulta los registros TXT del dominio y filtra los que son SPF.

    Un registro TXT puede estar dividido en varias cadenas; se reconstruye
    concatenando todas las partes (`rdata.strings`). Después se conservan solo
    los registros cuyo contenido empieza por `v=spf1` (case-insensitive).

    Args:
        domain: Dominio a consultar (ya validado y normalizado).

    Returns:
        Una tupla `(spf_records, error)` donde:
        - `spf_records` es la lista de registros SPF encontrados (vacía si no
          hay o si hubo error).
        - `error` es un código técnico de error, o None si la consulta fue
          correcta. Posibles valores: "dns_resolution_error" (NXDOMAIN),
          "timeout" o "dns_error" (otros errores). El caso NoAnswer (no hay
          TXT) no es un error: devuelve `([], None)`.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=_TIMEOUT_SECONDS)
        spf_records: List[str] = []
        for rdata in answers:
            # Reconstruimos el registro TXT concatenando sus cadenas.
            # `rdata.strings` es una lista de bytes; las decodificamos y unimos.
            try:
                parts = [
                    part.decode("utf-8", errors="replace") for part in rdata.strings
                ]
                txt_value = "".join(parts)
            except AttributeError:
                # Por robustez: si no hubiera `strings`, usamos la repr textual
                # quitando las comillas envolventes.
                txt_value = str(rdata).strip('"')

            if txt_value.strip().lower().startswith(_SPF_PREFIX):
                spf_records.append(txt_value)

        return spf_records, None

    except dns.resolver.NXDOMAIN:
        # El dominio no existe en el DNS.
        return [], "dns_resolution_error"

    except dns.resolver.NoAnswer:
        # El dominio existe pero no tiene registros TXT. No es un error de
        # consulta: simplemente no hay SPF (se tratará como WARNING más tarde).
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


def check_spf(domain: str) -> CheckResult:
    """
    Comprueba el registro SPF de un dominio.

    Consulta los registros TXT del dominio y filtra los que son políticas SPF
    (empiezan por `v=spf1`). Según cuántos se encuentren, determina el estado.

    Reglas de estado:
    - Exactamente 1 registro SPF -> ok (severity none).
    - 0 registros SPF -> warning (severity medium, technical_reason
      "missing_spf").
    - 2 o más registros SPF -> error (severity high, technical_reason
      "multiple_spf_records"); según el RFC 7208 solo puede haber uno.
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
    spf_records, error = _query_spf(domain)

    # --- Fallos de consulta DNS -> UNKNOWN (checked=False) --------------
    if error == "dns_resolution_error":
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No hemos podido comprobar el registro SPF del dominio.",
            checked=False,
            details=_build_details(
                found=False,
                record_count=0,
                records=[],
                syntax_valid=None,
                error="dns_resolution_error",
            ),
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
            summary="No hemos podido comprobar el registro SPF (timeout).",
            checked=False,
            details=_build_details(
                found=False,
                record_count=0,
                records=[],
                syntax_valid=None,
                error="timeout",
            ),
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
            summary="No hemos podido comprobar el registro SPF del dominio.",
            checked=False,
            details=_build_details(
                found=False,
                record_count=0,
                records=[],
                syntax_valid=None,
                error="dns_error",
            ),
            technical_reason="dns_error",
            recommendation=(
                "Se ha producido un problema al consultar el DNS. Comprueba la "
                "configuración de tu proveedor DNS."
            ),
            user_message="No hemos podido comprobar la configuración de correo de tu dominio.",
        )

    record_count = len(spf_records)

    # --- Varios registros SPF -> ERROR ----------------------------------
    if record_count > 1:
        return CheckResult(
            status=Status.ERROR,
            severity=Severity.HIGH,
            title=_TITLE,
            summary="Se han encontrado varios registros SPF en el dominio.",
            checked=True,
            details=_build_details(
                found=True,
                record_count=record_count,
                records=spf_records,
                syntax_valid=None,
                error="multiple_spf_records",
            ),
            technical_reason="multiple_spf_records",
            recommendation=(
                "Combina los registros SPF necesarios en un único registro. "
                "Un dominio solo debe tener un registro SPF (RFC 7208)."
            ),
            user_message="El correo de tu empresa podría tener problemas de autenticación o entrega.",
        )

    # --- Ningún registro SPF -> WARNING ---------------------------------
    if record_count == 0:
        return CheckResult(
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            title=_TITLE,
            summary="No se ha encontrado ningún registro SPF en el dominio.",
            checked=True,
            details=_build_details(
                found=False,
                record_count=0,
                records=[],
                syntax_valid=None,
                error="missing_spf",
            ),
            technical_reason="missing_spf",
            recommendation=(
                "Configura un registro SPF para indicar qué servidores están "
                "autorizados a enviar correo en nombre de tu dominio."
            ),
            user_message="Tu dominio no tiene SPF configurado, lo que puede afectar a la entrega del correo.",
        )

    # --- Exactamente un registro SPF -> OK ------------------------------
    return CheckResult(
        status=Status.OK,
        severity=Severity.NONE,
        title=_TITLE,
        summary="Se ha encontrado un registro SPF.",
        checked=True,
        details=_build_details(
            found=True,
            record_count=1,
            records=spf_records,
            syntax_valid=True,
            error=None,
        ),
        technical_reason=None,
        recommendation=None,
        user_message=None,
    )
