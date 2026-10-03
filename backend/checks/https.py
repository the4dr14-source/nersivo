"""
Comprobación real del certificado HTTPS/TLS de un dominio.

Este módulo implementa `check_https`, que verifica la disponibilidad HTTPS,
la validez del certificado TLS y la coincidencia del hostname.

Criterios de diseño:
- Conexión TCP directa al puerto 443 con timeout acotado (10 s), siempre a una
  IP pública ya validada (protección SSRF, ver `net_safety`).
- Verificación TLS mediante contexto por defecto (seguro).
- Extracción de fechas del certificado (issued_at, expires_at).
- Cálculo de días restantes hasta la expiración.
- Comprobación de coincidencia de dominio (SAN + CN fallback, wildcards).
- Los errores técnicos (timeout, DNS, conexión) se marcan como `unknown`.
- Los problemas de certificado (expirado, hostname mismatch, autofirmado) se
  marcan como `error` con severidad apropiada.
"""

import socket
import ssl
from datetime import datetime, timedelta, timezone
from typing import Optional

from .. import net_safety
from ..models import CheckResult, Severity, Status

# --- Constantes de configuración -----------------------------------------
_TIMEOUT_SECONDS = 10.0
_TITLE = "HTTPS"


def _build_details(
    https_available: bool,
    valid: bool,
    matches_domain: bool,
    issued_at: Optional[str],
    expires_at: Optional[str],
    days_remaining: Optional[int],
    error: Optional[str],
) -> dict:
    """
    Construye el diccionario `details` del CheckResult de HTTPS.

    Mantiene siempre las mismas claves definidas en el contrato.

    Args:
        https_available: True si el puerto 443 acepta conexiones TLS.
        valid: True si el certificado es válido (fechas, firma, etc.).
        matches_domain: True si el certificado coincide con el dominio.
        issued_at: Fecha de emisión del certificado (ISO 8601) o None.
        expires_at: Fecha de expiración del certificado (ISO 8601) o None.
        days_remaining: Días restantes hasta la expiración, o None.
        error: Código técnico de error (o None si no hubo).

    Returns:
        Diccionario con los detalles del check.
    """
    return {
        "https_available": https_available,
        "valid": valid,
        "matches_domain": matches_domain,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "days_remaining": days_remaining,
        "error": error,
    }


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """
    Convierte una fecha del certificado (formato ASN.1) a datetime UTC.

    Utiliza ssl.cert_time_to_seconds() que es independiente del locale del
    sistema y está diseñada específicamente para parsear fechas de certificados.

    Args:
        date_str: Cadena de fecha del certificado (formato ASN.1).

    Returns:
        Objeto datetime aware (UTC) o None si no se pudo parsear.
    """
    try:
        # ssl.cert_time_to_seconds convierte la fecha del certificado a timestamp Unix
        timestamp = ssl.cert_time_to_seconds(date_str)
        # Convertir el timestamp a datetime UTC aware
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def _matches_domain(cert: dict, domain: str) -> bool:
    """
    Comprueba si el certificado coincide con el dominio.

    Primero busca en Subject Alternative Name (SAN). Si no existe SAN,
    usa Common Name (CN) como fallback. Soporta wildcards (*.ejemplo.com).

    Args:
        cert: Certificado obtenido con `getpeercert()`.
        domain: Dominio a verificar (ya normalizado, sin esquema ni ruta).

    Returns:
        True si el certificado coincide con el dominio, False si no.
    """
    domain_lower = domain.lower()

    # 1. Intentar Subject Alternative Name (SAN) primero.
    san = cert.get("subjectAltName", ())
    for entry_type, entry_value in san:
        if entry_type == "DNS":
            pattern = entry_value.lower()
            # Wildcard: *.ejemplo.com coincide con sub.ejemplo.com pero no ejemplo.com
            if pattern.startswith("*."):
                suffix = pattern[2:]  # Quita "*."
                if domain_lower.endswith(suffix) and domain_lower != suffix:
                    # Verifica que haya al menos un nivel de subdominio.
                    prefix = domain_lower[: -len(suffix)]
                    if prefix.endswith(".") and "." not in prefix[:-1]:
                        return True
            elif pattern == domain_lower:
                return True

    # 2. Fallback: Common Name (CN) si no hay SAN.
    if not san:
        subject = cert.get("subject", ())
        for rdn in subject:
            for name, value in rdn:
                if name.lower() == "commonname":
                    cn = value.lower()
                    if cn.startswith("*."):
                        suffix = cn[2:]
                        if domain_lower.endswith(suffix) and domain_lower != suffix:
                            prefix = domain_lower[: -len(suffix)]
                            if prefix.endswith(".") and "." not in prefix[:-1]:
                                return True
                    elif cn == domain_lower:
                        return True

    return False


def check_https(domain: str) -> CheckResult:
    """
    Comprueba la disponibilidad HTTPS y la validez del certificado TLS.

    Conecta al puerto 443 del dominio, realiza el handshake TLS y extrae
    información del certificado (fechas, coincidencia de dominio). Evalúa
    el estado según el TIEMPO REAL restante hasta la expiración (fecha y hora),
    no según `days_remaining`, que es solo un dato informativo (días enteros,
    truncados) y nunca decide si el certificado ha expirado.

    Reglas de estado (certificado válido y coincide con el dominio):
    - Expirado (`expires_at <= ahora`) -> error (severity critical).
    - Hasta 30 días restantes (incluidas las últimas horas) -> warning:
      más de 7 días -> severity medium (`expiring_soon`); 7 días o menos ->
      severity high (`expiring_very_soon`).
    - Más de 30 días restantes -> ok (severity none).

    Errores de certificado:
    - Hostname mismatch -> error (severity high, technical_reason
      "hostname_mismatch").
    - Certificado expirado -> error (severity critical, technical_reason
      "certificate_expired").
    - Certificado autofirmado -> error (severity high, technical_reason
      "self_signed_certificate").
    - Otro certificado inválido -> error (severity high).
    - Otros errores SSL -> error (severity high, technical_reason "tls_error").

    Errores de conexión:
    - Puerto 443 rechaza la conexión -> error (severity high, technical_reason
      "https_not_available").
    - Timeout -> unknown (technical_reason "timeout").
    - DNS no resuelve -> unknown (technical_reason "dns_resolution_error").
    - Otros errores de conexión -> unknown.
    - Cualquier excepción inesperada -> unknown.
    - Destino bloqueado por seguridad (el dominio resuelve a una IP no pública)
      -> unknown, checked=False (technical_reason `blocked_private_ip` o
      `blocked_non_public_ip`).

    Args:
        domain: Dominio ya validado y normalizado (sin esquema ni ruta).

    Returns:
        CheckResult compatible con el contrato JSON de Nersivo.
    """
    sock = None
    try:
        # Crear contexto TLS con valores por defecto seguros.
        context = ssl.create_default_context()

        # Crear socket TCP y conectar al puerto 443.
        # Resuelve el dominio, exige IPs públicas y conecta a la IP validada.
        sock = net_safety.create_safe_connection(domain, 443, _TIMEOUT_SECONDS)

        # Realizar handshake TLS.
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

        # --- Certificado obtenido correctamente ---------------------------
        # Extraer fechas.
        not_before_str = cert.get("notBefore")
        not_after_str = cert.get("notAfter")

        issued_at_dt = _parse_cert_date(not_before_str) if not_before_str else None
        expires_at_dt = _parse_cert_date(not_after_str) if not_after_str else None

        issued_at_iso = issued_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if issued_at_dt else None
        expires_at_iso = expires_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if expires_at_dt else None

        # Tiempo restante real. `days_remaining` es solo informativo (días
        # enteros); las decisiones se toman con `expires_at_dt` y `now`.
        days_remaining = None
        is_expired = False
        remaining = None
        if expires_at_dt:
            now = datetime.now(timezone.utc)
            remaining = expires_at_dt - now
            days_remaining = remaining.days
            is_expired = expires_at_dt <= now

        # Comprobar coincidencia de dominio.
        matches = _matches_domain(cert, domain)

        # --- Evaluación del estado ----------------------------------------
        # Si el certificado no coincide con el dominio -> error.
        if not matches:
            details = _build_details(
                https_available=True,
                valid=False,
                matches_domain=False,
                issued_at=issued_at_iso,
                expires_at=expires_at_iso,
                days_remaining=days_remaining,
                error="hostname_mismatch",
            )
            return CheckResult(
                status=Status.ERROR,
                severity=Severity.HIGH,
                title=_TITLE,
                summary="El certificado HTTPS no coincide con el dominio.",
                checked=True,
                details=details,
                technical_reason="hostname_mismatch",
                recommendation=(
                    "El certificado SSL/TLS no está emitido para este dominio. "
                    "Configura un certificado válido."
                ),
                user_message="Tu certificado HTTPS no es válido para este dominio.",
            )

        # Si el certificado ha expirado -> error crítico.
        if is_expired:
            details = _build_details(
                https_available=True,
                valid=False,
                matches_domain=True,
                issued_at=issued_at_iso,
                expires_at=expires_at_iso,
                days_remaining=days_remaining,
                error="certificate_expired",
            )
            return CheckResult(
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                title=_TITLE,
                summary="El certificado HTTPS ha expirado.",
                checked=True,
                details=details,
                technical_reason="certificate_expired",
                recommendation="Renueva el certificado SSL/TLS urgentemente.",
                user_message="Tu certificado HTTPS ha caducado y los navegadores lo marcarán como inseguro.",
            )

        # Certificado válido: evaluar según el tiempo real restante.
        if remaining is not None:
            details = _build_details(
                https_available=True,
                valid=True,
                matches_domain=True,
                issued_at=issued_at_iso,
                expires_at=expires_at_iso,
                days_remaining=days_remaining,
                error=None,
            )

            if remaining > timedelta(days=30):
                # Más de 30 días: ok.
                return CheckResult(
                    status=Status.OK,
                    severity=Severity.NONE,
                    title=_TITLE,
                    summary="El certificado HTTPS es válido.",
                    checked=True,
                    details=details,
                    technical_reason=None,
                    recommendation=None,
                    user_message=None,
                )

            # Texto de plazo: con menos de 1 día entero no se dice "0 días".
            if days_remaining >= 1:
                plazo = f"en {days_remaining} días"
            else:
                plazo = "en menos de 1 día"

            if remaining > timedelta(days=7):
                # Entre 7 y 30 días: warning.
                return CheckResult(
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    title=_TITLE,
                    summary=f"El certificado HTTPS caduca {plazo}.",
                    checked=True,
                    details=details,
                    technical_reason="expiring_soon",
                    recommendation=(
                        "El certificado SSL/TLS está próximo a caducar. "
                        "Renuévalo pronto para evitar interrupciones."
                    ),
                    user_message=f"Tu certificado HTTPS caduca {plazo}.",
                )

            # 7 días o menos (aún no expirado): warning de severidad alta.
            return CheckResult(
                status=Status.WARNING,
                severity=Severity.HIGH,
                title=_TITLE,
                summary=f"El certificado HTTPS caduca {plazo}.",
                checked=True,
                details=details,
                technical_reason="expiring_very_soon",
                recommendation="Renueva el certificado SSL/TLS urgentemente.",
                user_message=f"Tu certificado HTTPS caduca muy pronto ({plazo}).",
            )

        # Si no pudimos calcular days_remaining pero el certificado es válido
        # y coincide -> ok con advertencia.
        details = _build_details(
            https_available=True,
            valid=True,
            matches_domain=True,
            issued_at=issued_at_iso,
            expires_at=expires_at_iso,
            days_remaining=None,
            error=None,
        )
        return CheckResult(
            status=Status.OK,
            severity=Severity.NONE,
            title=_TITLE,
            summary="El certificado HTTPS es válido.",
            checked=True,
            details=details,
            technical_reason=None,
            recommendation=None,
            user_message=None,
        )

    except net_safety.BlockedDestinationError as exc:
        # El dominio resuelve a una IP no pública: Nersivo no se conecta.
        # No es un problema del dominio analizado -> unknown, checked=False.
        details = _build_details(
            https_available=False,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error=exc.code,
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

    except ssl.SSLCertVerificationError as exc:
        # Certificado inválido: puede ser autofirmado, cadena rota, etc.
        message = str(exc).lower()
        if "self signed certificate" in message or "self-signed" in message:
            technical_reason = "self_signed_certificate"
            summary = "El certificado HTTPS es autofirmado."
            recommendation = (
                "Usa un certificado firmado por una autoridad de certificación "
                "reconocida (por ejemplo, Let's Encrypt)."
            )
            user_message = "Tu certificado HTTPS no está firmado por una autoridad reconocida."
        elif "certificate has expired" in message or "expired" in message:
            technical_reason = "certificate_expired"
            summary = "El certificado HTTPS ha expirado."
            recommendation = "Renueva el certificado SSL/TLS urgentemente."
            user_message = "Tu certificado HTTPS ha caducado."
        elif "hostname" in message or "does not match" in message:
            technical_reason = "hostname_mismatch"
            summary = "El certificado HTTPS no coincide con el dominio."
            recommendation = (
                "El certificado SSL/TLS no está emitido para este dominio. "
                "Configura un certificado válido."
            )
            user_message = "Tu certificado HTTPS no es válido para este dominio."
        else:
            technical_reason = "invalid_certificate"
            summary = "El certificado HTTPS no es válido."
            recommendation = (
                "Revisa la configuración del certificado SSL/TLS; puede haber "
                "problemas de cadena de confianza o validación."
            )
            user_message = "Tu certificado HTTPS tiene problemas de validación."

        details = _build_details(
            https_available=True,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error=technical_reason,
        )
        return CheckResult(
            status=Status.ERROR,
            severity=Severity.HIGH,
            title=_TITLE,
            summary=summary,
            checked=True,
            details=details,
            technical_reason=technical_reason,
            recommendation=recommendation,
            user_message=user_message,
        )

    except ssl.SSLError as exc:
        # Otros errores SSL (handshake fallido, protocolo no soportado, etc.).
        details = _build_details(
            https_available=True,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error="tls_error",
        )
        return CheckResult(
            status=Status.ERROR,
            severity=Severity.HIGH,
            title=_TITLE,
            summary="No se ha podido establecer una conexión HTTPS segura.",
            checked=True,
            details=details,
            technical_reason="tls_error",
            recommendation=(
                "El servidor tiene problemas con la configuración TLS/SSL. "
                "Contacta con tu proveedor de hosting."
            ),
            user_message="Tu servidor tiene problemas con la conexión HTTPS.",
        )

    except socket.timeout:
        # Timeout: no podemos determinar el estado -> unknown.
        details = _build_details(
            https_available=False,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error="timeout",
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="La conexión HTTPS ha tardado demasiado.",
            checked=True,
            details=details,
            technical_reason="timeout",
            recommendation=(
                "El servidor tarda demasiado en responder en el puerto 443. "
                "Puede ser algo temporal; inténtalo de nuevo más tarde."
            ),
            user_message="No hemos podido comprobar HTTPS porque la conexión tardó demasiado.",
        )

    except ConnectionRefusedError:
        # Puerto 443 rechaza la conexión: HTTPS no disponible -> error.
        details = _build_details(
            https_available=False,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error="https_not_available",
        )
        return CheckResult(
            status=Status.ERROR,
            severity=Severity.HIGH,
            title=_TITLE,
            summary="El puerto 443 (HTTPS) no está disponible.",
            checked=True,
            details=details,
            technical_reason="https_not_available",
            recommendation=(
                "El servidor no acepta conexiones HTTPS en el puerto 443. "
                "Verifica que el servidor web esté configurado para HTTPS."
            ),
            user_message="Tu servidor no acepta conexiones HTTPS.",
        )

    except socket.gaierror as exc:
        # Error de resolución DNS -> unknown.
        details = _build_details(
            https_available=False,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error="dns_resolution_error",
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
                "Comprueba que el dominio está activo y configurado correctamente."
            ),
            user_message="No hemos podido encontrar tu dominio en Internet.",
        )

    except OSError as exc:
        # Otros errores de conexión (red inaccesible, host no alcanzable, etc.).
        details = _build_details(
            https_available=False,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error="connection_error",
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido conectar al puerto 443.",
            checked=True,
            details=details,
            technical_reason="connection_error",
            recommendation=(
                "No se ha podido establecer conexión. Comprueba que el servidor "
                "está en funcionamiento."
            ),
            user_message="No hemos podido conectar con tu servidor HTTPS.",
        )

    except Exception:  # noqa: BLE001 - último recurso: nunca romper la API.
        # Cualquier excepción inesperada -> unknown.
        details = _build_details(
            https_available=False,
            valid=False,
            matches_domain=False,
            issued_at=None,
            expires_at=None,
            days_remaining=None,
            error="unknown_error",
        )
        return CheckResult(
            status=Status.UNKNOWN,
            severity=Severity.UNKNOWN,
            title=_TITLE,
            summary="No se ha podido comprobar HTTPS.",
            checked=True,
            details=details,
            technical_reason="unknown_error",
            recommendation=None,
            user_message=None,
        )

    finally:
        if sock:
            try:
                sock.close()
            except Exception:  # noqa: BLE001, S110
                pass