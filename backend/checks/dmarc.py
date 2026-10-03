"""
Comprobación real del registro DMARC de un dominio.

Este módulo implementa `check_dmarc`, que consulta los registros TXT del
subdominio especial `_dmarc.<dominio>` mediante dnspython y determina si existe
un registro DMARC válido.

Criterios de diseño (MVP):
- Se consulta SIEMPRE `_dmarc.<dominio>`, nunca los TXT del dominio raíz.
- Un registro DMARC candidato debe comenzar por "v=DMARC1".
- La validación de sintaxis es BÁSICA: exige el tag obligatorio `p=` con una
  política válida (none / quarantine / reject). Se toleran tags adicionales
  (rua, ruf, adkim, aspf, pct, sp, fo, ...), pero no se validan en profundidad.
- La política `p=none` es una política VÁLIDA: se informa de ella, no se penaliza.
- Los registros TXT divididos en múltiples cadenas se reconstruyen correctamente.
- Distinción importante:
    * DNS funciona pero NO hay DMARC (incluye NXDOMAIN/NoAnswer del subdominio
      `_dmarc`, que en la práctica significa "no existe DMARC") -> WARNING
      (missing_dmarc), checked=True.
    * DNS NO se puede consultar de forma fiable (timeout, resolver caído, otros
      errores) -> UNKNOWN (dns_lookup_error), checked=True.
"""

from typing import List, Optional

import dns.exception
import dns.resolver

from ..models import CheckResult, Severity, Status

# --- Constantes de configuración -----------------------------------------
_TIMEOUT_SECONDS = 5.0
_TITLE = "DMARC"
_DMARC_PREFIX = "v=dmarc1"
_VALID_POLICIES = {"none", "quarantine", "reject"}


def _build_details(
    found: bool,
    record: Optional[str],
    policy: Optional[str],
    syntax_valid: Optional[bool],
    error: Optional[str],
) -> dict:
    """
    Construye el diccionario `details` del CheckResult de DMARC.

    Mantiene siempre las mismas claves definidas en el contrato V1.

    Args:
        found: True si se encontró al menos un registro DMARC candidato.
        record: Registro DMARC completo (o None).
        policy: Política declarada en `p=` (none/quarantine/reject) o None.
        syntax_valid: True si la sintaxis básica es válida, False si es
            inválida, None cuando no aplica (sin DMARC, múltiples, errores).
        error: Código técnico de error (o None si no hubo).

    Returns:
        Diccionario con los detalles del check.
    """
    return {
        "found": found,
        "record": record,
        "policy": policy,
        "syntax_valid": syntax_valid,
        "error": error,
    }


def _reconstruct_txt_record(txt_strings: tuple) -> str:
    """
    Reconstruye un registro TXT completo a partir de sus fragmentos.

    Los registros TXT pueden venir divididos en múltiples cadenas. Esta función
    las concatena correctamente para obtener el contenido completo.

    Args:
        txt_strings: Tupla de cadenas (bytes o str) del registro TXT.

    Returns:
        Cadena completa del registro TXT.
    """
    parts = []
    for part in txt_strings:
        if isinstance(part, bytes):
            parts.append(part.decode("utf-8", errors="replace"))
        else:
            parts.append(str(part))
    return "".join(parts)


def _extract_policy(record: str) -> Optional[str]:
    """
    Extrae el valor de la política DMARC (tag `p=`) de un registro.

    Recorre los tags del registro (separados por ';'), localiza el tag cuyo
    nombre es exactamente `p` (ignorando mayúsculas/minúsculas y espacios) y
    devuelve su valor en minúsculas.

    Args:
        record: Registro DMARC completo.

    Returns:
        El valor de la política (p. ej. "none") o None si el tag `p=` no existe
        o no tiene valor.
    """
    for tag in record.split(";"):
        tag = tag.strip()
        if not tag or "=" not in tag:
            continue
        key, _, value = tag.partition("=")
        if key.strip().lower() == "p":
            value = value.strip().lower()
            return value if value else None
    return None


def _base_domain_resolvable(domain: str, resolver: "dns.resolver.Resolver") -> Optional[bool]:
    """
    Indica si el dominio base existe en el DNS.

    Se usa para distinguir dos situaciones que, al consultar `_dmarc.<domain>`,
    producen ambas un NXDOMAIN:
      - El dominio base existe pero no tiene registro DMARC (falta DMARC).
      - El dominio base NO existe en el DNS (NXDOMAIN del propio dominio).

    Returns:
        True  -> el dominio base existe (tiene registros o responde).
        False -> el dominio base no existe (NXDOMAIN).
        None  -> no se ha podido determinar (timeout u otros errores DNS).
    """
    for record_type in ("A", "AAAA"):
        try:
            resolver.resolve(domain, record_type)
            return True
        except dns.resolver.NoAnswer:
            # El nombre existe, aunque no tenga ese tipo de registro concreto.
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.DNSException:
            # Error transitorio con este tipo: probamos el siguiente.
            continue
    return None


def _dmarc_dns_resolution_error() -> CheckResult:
    """
    CheckResult de DMARC cuando el dominio base no existe (NXDOMAIN).

    En este caso no podemos concluir que falte el registro DMARC: simplemente el
    dominio no se resuelve. Se marca como UNKNOWN y `checked=False`, en línea con
    los demás checks (web, https, dns, mx, spf) ante un dominio inexistente.
    """
    return CheckResult(
        status=Status.UNKNOWN,
        severity=Severity.UNKNOWN,
        title=_TITLE,
        summary="No hemos podido comprobar la configuración DMARC del dominio.",
        checked=False,
        details=_build_details(
            found=False,
            record=None,
            policy=None,
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


def check_dmarc(domain: str) -> CheckResult:
    """
    Comprueba el registro DMARC de un dominio.

    Consulta los registros TXT de `_dmarc.<domain>` mediante dnspython y verifica:
    1. Existencia de al menos un registro que comience por "v=DMARC1".
    2. Unicidad (debe haber exactamente uno, no varios).
    3. Sintaxis básica válida (tag `p=` con política none/quarantine/reject).

    Reglas de estado:
    - Exactamente 1 DMARC válido -> ok (severity none). Se informa de la política.
    - Sin DMARC (incluye NXDOMAIN/NoAnswer del subdominio) -> warning
      (severity medium, technical_reason "missing_dmarc").
    - 1 DMARC candidato inválido -> error (severity high, technical_reason
      "invalid_dmarc_record").
    - Múltiples DMARC candidatos -> error (severity high, technical_reason
      "multiple_dmarc_records").
    - Error real de consulta DNS (timeout, resolver, etc.) -> unknown
      (severity unknown, technical_reason "dns_lookup_error").

    Args:
        domain: Dominio ya validado y normalizado (sin esquema ni ruta).

    Returns:
        CheckResult compatible con el contrato JSON de Nersivo.
    """
    dmarc_name = f"_dmarc.{domain}"

    try:
        # Configurar resolver con timeout.
        resolver = dns.resolver.Resolver()
        resolver.timeout = _TIMEOUT_SECONDS
        resolver.lifetime = _TIMEOUT_SECONDS

        # Consultar registros TXT del subdominio especial _dmarc.
        answers = resolver.resolve(dmarc_name, "TXT")

        # Reconstruir los TXT completos y filtrar los candidatos DMARC.
        dmarc_records: List[str] = []
        for rdata in answers:
            txt_content = _reconstruct_txt_record(rdata.strings).strip()
            if txt_content.lower().startswith(_DMARC_PREFIX):
                dmarc_records.append(txt_content)

    except dns.resolver.NXDOMAIN:
        # `_dmarc.<domain>` no existe. Esto puede deberse a dos motivos:
        #   1. El dominio base existe pero no tiene registro DMARC -> falta DMARC.
        #   2. El dominio base NO existe (NXDOMAIN del propio dominio).
        # Solo en el caso 1 tiene sentido informar de "missing_dmarc". Si el
        # dominio base no se resuelve, no podemos concluir que falte DMARC.
        if _base_domain_resolvable(domain, resolver) is False:
            return _dmarc_dns_resolution_error()
        return CheckResult(
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            title=_TITLE,
            summary="No se ha encontrado ningún registro DMARC.",
            checked=True,
            details=_build_details(
                found=False,
                record=None,
                policy=None,
                syntax_valid=None,
                error=None,
            ),
            technical_reason="missing_dmarc",
            recommendation=(
                "Configurar DMARC permite establecer una política para los "
                "mensajes que no superen las comprobaciones de autenticación."
            ),
            user_message="Tu dominio no tiene DMARC configurado.",
        )

    except dns.resolver.NoAnswer:
        # El nombre `_dmarc.<domain>` existe pero no tiene registro TXT: en la
        # práctica significa que NO hay DMARC configurado -> WARNING.
        return CheckResult(
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            title=_TITLE,
            summary="No se ha encontrado ningún registro DMARC.",
            checked=True,
            details=_build_details(
                found=False,
                record=None,
                policy=None,
                syntax_valid=None,
                error=None,
            ),
            technical_reason="missing_dmarc",
            recommendation=(
                "Configurar DMARC permite establecer una política para los "
                "mensajes que no superen las comprobaciones de autenticación."
            ),
            user_message="Tu dominio no tiene DMARC configurado.",
        )

    except (dns.resolver.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
        # No podemos determinar la configuración de forma fiable -> UNKNOWN.
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido determinar la configuración DMARC del dominio.",
            checked=True,
            details=_build_details(
                found=False,
                record=None,
                policy=None,
                syntax_valid=None,
                error="dns_lookup_error",
            ),
            technical_reason="dns_lookup_error",
            recommendation=None,
            user_message=None,
        )

    except Exception:  # noqa: BLE001 - último recurso: nunca romper la API.
        # Cualquier excepción inesperada se trata como error de consulta DNS.
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido determinar la configuración DMARC del dominio.",
            checked=True,
            details=_build_details(
                found=False,
                record=None,
                policy=None,
                syntax_valid=None,
                error="dns_lookup_error",
            ),
            technical_reason="dns_lookup_error",
            recommendation=None,
            user_message=None,
        )

    # --- La consulta DNS funcionó: evaluamos los candidatos DMARC --------
    record_count = len(dmarc_records)

    # Caso: no hay ningún registro DMARC candidato (había otros TXT, o ninguno).
    if record_count == 0:
        return CheckResult(
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            title=_TITLE,
            summary="No se ha encontrado ningún registro DMARC.",
            checked=True,
            details=_build_details(
                found=False,
                record=None,
                policy=None,
                syntax_valid=None,
                error=None,
            ),
            technical_reason="missing_dmarc",
            recommendation=(
                "Configurar DMARC permite establecer una política para los "
                "mensajes que no superen las comprobaciones de autenticación."
            ),
            user_message="Tu dominio no tiene DMARC configurado.",
        )

    # Caso: múltiples registros DMARC -> error (no elegimos uno arbitrariamente).
    if record_count > 1:
        return CheckResult(
            status=Status.ERROR,
            severity=Severity.HIGH,
            title=_TITLE,
            summary="Se han encontrado varios registros DMARC en el dominio.",
            checked=True,
            details=_build_details(
                found=True,
                record=None,
                policy=None,
                syntax_valid=None,
                error="multiple_dmarc_records",
            ),
            technical_reason="multiple_dmarc_records",
            recommendation=(
                "Mantén un único registro DMARC para el dominio y elimina las "
                "configuraciones duplicadas."
            ),
            user_message="Tu dominio tiene varios registros DMARC y debería revisarse su configuración.",
        )

    # Caso: exactamente un registro DMARC candidato -> validar sintaxis básica.
    record = dmarc_records[0]
    policy = _extract_policy(record)

    if policy is not None and policy in _VALID_POLICIES:
        # Registro DMARC válido: v=DMARC1 + p= con política permitida.
        return CheckResult(
            status=Status.OK,
            severity=Severity.NONE,
            title=_TITLE,
            summary="Se ha encontrado un registro DMARC válido.",
            checked=True,
            details=_build_details(
                found=True,
                record=record,
                policy=policy,
                syntax_valid=True,
                error=None,
            ),
            technical_reason=None,
            recommendation=None,
            user_message=None,
        )

    # Registro DMARC candidato pero inválido: falta p= o política no permitida.
    return CheckResult(
        status=Status.ERROR,
        severity=Severity.HIGH,
        title=_TITLE,
        summary="Se ha encontrado un registro DMARC con una configuración no válida.",
        checked=True,
        details=_build_details(
            found=True,
            record=record,
            policy=None,
            syntax_valid=False,
            error="invalid_dmarc_record",
        ),
        technical_reason="invalid_dmarc_record",
        recommendation=(
            "Revisa la sintaxis del registro DMARC y asegúrate de que contiene "
            "una versión DMARC válida y una política p= válida."
        ),
        user_message="Tu configuración DMARC contiene un error que debería revisarse.",
    )
