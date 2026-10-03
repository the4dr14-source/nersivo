"""
Utilidades para validar y normalizar dominios.

Este módulo expone `validate_and_normalize_domain`, encargada de garantizar
que la entrada del usuario es un dominio válido antes de analizarlo. Rechaza
direcciones IP, esquemas de URL (http://, javascript:, etc.) y formatos
claramente inválidos.
"""

import ipaddress
import re

import tldextract

# Extractor de tldextract configurado en modo OFFLINE (`suffix_list_urls=()`):
# usa el snapshot de la Public Suffix List empaquetado con la librería, sin
# realizar ninguna petición de red. Esto nos permite obtener de forma robusta
# el "dominio registrable" (p. ej. neoestudio.net, empresa.com.es) y saber si
# el input es un subdominio, teniendo en cuenta TLD multinivel como com.es.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def _registrable_from_extract(extract_result) -> str:
    """
    Devuelve el dominio registrable a partir de un resultado de tldextract.

    Compatible con distintas versiones de tldextract: las versiones recientes
    exponen `top_domain_under_public_suffix` (y deprecan `registered_domain`),
    mientras que las antiguas solo tienen `registered_domain`.
    """
    value = getattr(extract_result, "top_domain_under_public_suffix", None)
    if not value:
        value = getattr(extract_result, "registered_domain", "") or ""
    return value


def get_registrable_domain(domain: str) -> str:
    """
    Devuelve el dominio registrable (dominio principal) del input.

    Ejemplos:
        - "neoestudio.net"                -> "neoestudio.net"
        - "aula-virtual.neoestudio.net"   -> "neoestudio.net"
        - "www.empresa.com.es"            -> "empresa.com.es"

    Si no se puede determinar (input atípico), devuelve el dominio original.

    Args:
        domain: Dominio ya validado y normalizado.

    Returns:
        El dominio registrable, o el dominio original si no puede calcularse.
    """
    registrable = _registrable_from_extract(_TLD_EXTRACT(domain))
    return registrable or domain


def is_subdomain(domain: str) -> bool:
    """
    Indica si el dominio introducido es (probablemente) un subdominio.

    Se apoya en la Public Suffix List (vía tldextract) para distinguir el
    dominio registrable del resto de etiquetas. De este modo:
        - "neoestudio.net"              -> False (dominio principal)
        - "empresa.com.es"              -> False (TLD multinivel, no subdominio)
        - "aula-virtual.neoestudio.net" -> True  (subdominio)
        - "www.empresa.es"              -> True  (subdominio)

    NOTA: `www` se considera un subdominio a todos los efectos.

    Args:
        domain: Dominio ya validado y normalizado.

    Returns:
        True si hay una parte de subdominio por delante del dominio registrable.
    """
    extract_result = _TLD_EXTRACT(domain)
    return bool(extract_result.subdomain) and bool(
        _registrable_from_extract(extract_result)
    )

def get_email_check_domain(hostname: str) -> str:
    """
    Devuelve el dominio sobre el que se comprueban MX, SPF y DMARC.

    Regla (MVP): solo se elimina el prefijo inicial `www.`, porque `www` es el
    nombre habitual de la web y el correo vive en el dominio base. Cualquier
    otro subdominio (`mail.`, `smtp.`, `aula.`...) se mantiene intacto.

    Ejemplos:
        - "example.com"          -> "example.com"
        - "www.example.com"      -> "example.com"
        - "www.petitglamour.es"  -> "petitglamour.es"
        - "www.empresa.com.es"   -> "empresa.com.es"
        - "mail.example.com"     -> "mail.example.com"   (sin cambios)
        - "www.com.es"           -> "www.com.es"         (sin cambios: quitar
          `www.` dejaría solo un sufijo público, no un dominio registrable)

    La comprobación WEB sigue usando el hostname original; esta función solo
    decide el dominio de las comprobaciones de correo.

    Args:
        hostname: Dominio ya validado y normalizado.

    Returns:
        El hostname sin el `www.` inicial, o el mismo hostname si no aplica.
    """
    if hostname.startswith("www."):
        remainder = hostname[len("www."):]
        # Reutiliza tldextract: solo se quita `www.` si lo que queda sigue
        # siendo un dominio registrable (no un sufijo público como "co.uk").
        if _registrable_from_extract(_TLD_EXTRACT(remainder)):
            return remainder
    return hostname


# Expresión regular para validar el formato básico de un nombre de dominio.
# - Uno o más labels separados por puntos.
# - Cada label: caracteres alfanuméricos y guiones (no al inicio/fin).
# - TLD final de al menos 2 letras.
_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"  # longitud total del dominio entre 1 y 253 caracteres
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"  # uno o más labels + punto
    r"[a-z]{2,63}$"  # TLD final (solo letras)
)

# Palabras reservadas que no son dominios analizables reales.
_RESERVED_HOSTNAMES = {"localhost"}

# Esquemas de URL que deben rechazarse explícitamente.
_SCHEME_REGEX = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def _is_ip_address(value: str) -> bool:
    """Devuelve True si `value` es una dirección IP (v4 o v6) válida."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_and_normalize_domain(domain: str) -> str:
    """
    Valida y normaliza un dominio.

    Pasos que realiza:
    - Elimina espacios en blanco y convierte a minúsculas.
    - Rechaza esquemas de URL (http://, https://, javascript:, file://, ...).
    - Rechaza direcciones IP (127.0.0.1, 192.168.x.x, IPv6, ...) y `localhost`.
    - Valida el formato básico del dominio (debe contener un punto y no tener
      caracteres extraños).

    Args:
        domain: Cadena introducida por el usuario.

    Returns:
        El dominio normalizado (minúsculas, sin espacios).

    Raises:
        ValueError: Si el dominio no es válido, con un mensaje claro del motivo.
    """
    if domain is None:
        raise ValueError("El dominio no puede estar vacío.")

    # Normalización: quitar espacios y pasar a minúsculas.
    normalized = domain.strip().lower()

    if not normalized:
        raise ValueError("El dominio no puede estar vacío.")

    # Rechazar esquemas de URL (http://, https://, javascript:, file://, etc.).
    if _SCHEME_REGEX.match(normalized):
        raise ValueError(
            "El dominio no debe incluir un esquema (por ejemplo 'http://'). "
            "Introduce solo el dominio, por ejemplo 'midominio.es'."
        )

    # Rechazar barras y rutas: solo se admite el dominio puro.
    if "/" in normalized:
        raise ValueError(
            "El dominio no debe contener rutas ni barras. "
            "Introduce solo el dominio, por ejemplo 'midominio.es'."
        )

    # Rechazar nombres reservados como 'localhost'.
    if normalized in _RESERVED_HOSTNAMES:
        raise ValueError(
            f"'{normalized}' no es un dominio analizable. "
            "Introduce un dominio público válido."
        )

    # Rechazar direcciones IP (v4 y v6).
    if _is_ip_address(normalized):
        raise ValueError(
            "Las direcciones IP no están permitidas. "
            "Introduce un nombre de dominio, por ejemplo 'midominio.es'."
        )

    # Debe contener al menos un punto (dominio con TLD).
    if "." not in normalized:
        raise ValueError(
            f"'{normalized}' no parece un dominio válido. "
            "Debe incluir una extensión, por ejemplo 'midominio.es'."
        )

    # Validación de formato básico mediante expresión regular.
    if not _DOMAIN_REGEX.match(normalized):
        raise ValueError(
            f"'{normalized}' no es un dominio válido. "
            "Revisa que no contenga caracteres extraños."
        )

    return normalized
