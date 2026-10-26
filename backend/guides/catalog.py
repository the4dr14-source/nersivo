"""
Catálogo de guías de solución (solo DATOS y texto; sin lógica de detección).

Estructura:
- `GUIDES`: `"<check>:<technical_reason>" -> GuideDef`.
- `FALLBACKS`: `"<check>" -> GuideDef` genérica para códigos sin guía propia.
- `SPF_INCLUDES`: valores SPF verificados por proveedor de correo.
- `PANEL_HINTS`: pista de navegación por proveedor de panel DNS.

Para añadir un problema nuevo basta con añadir una entrada a `GUIDES`.
Para añadir un proveedor, una entrada en `SPF_INCLUDES` / `PANEL_HINTS` (y,
si hace falta, su patrón en `backend/infrastructure/providers.py`).

Plantillas: `{domain}` (dominio del análisis) y `{mail_domain}` (dominio de
correo: el mismo sin `www.`). Los pasos que empiezan por `@` son macros que
expande el constructor: `@dns_open`, `@dns_save`, `@recheck`.

Principio: las instrucciones específicas de un proveedor solo se muestran si
`providers.identify` lo identificó con confianza alta; si no, guía genérica.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class GuideDef:
    """Definición estática de una guía."""

    guide_id: str
    title: str
    why: str
    steps: Tuple[str, ...]
    verify: str
    notes: Tuple[str, ...] = ()
    # Qué proveedor personaliza la guía (None = ninguno).
    uses: Optional[str] = None  # "mail" | "dns_panel" | "both"
    # Clave de generador de valores técnicos (ver builder.VALUE_BUILDERS).
    values: Optional[str] = None
    # Qué datos reales del análisis se muestran (ver builder.DETECTED_BUILDERS).
    detected: Optional[str] = None


# --- Valores verificados por proveedor --------------------------------------
# Registros SPF oficiales de cada servicio de buzones.
SPF_INCLUDES: Dict[str, str] = {
    "google_workspace": "v=spf1 include:_spf.google.com ~all",
    "microsoft_365": "v=spf1 include:spf.protection.outlook.com ~all",
}

# Pista de dónde está la gestión DNS en cada panel (las pantallas pueden variar).
PANEL_HINTS: Dict[str, str] = {
    "cloudflare": "Entra en Cloudflare, selecciona tu dominio y abre la sección «DNS».",
    "godaddy": "Entra en tu cuenta de GoDaddy, abre tu dominio y busca «DNS» o «Administrar DNS».",
    "namecheap": "En Namecheap abre «Domain List», pulsa «Manage» en tu dominio y ve a «Advanced DNS».",
    "ovhcloud": "En el área de cliente de OVHcloud abre «Dominios», tu dominio y la pestaña «Zona DNS».",
    "amazon_route_53": "En la consola de AWS abre Route 53 > «Hosted zones» y selecciona tu dominio.",
    "ionos": "En IONOS abre la gestión de tu dominio y busca la opción de «DNS».",
}

# --- Guías por problema -------------------------------------------------------
_HOSTING_ENTRY = (
    "Entra en el panel de tu proveedor de hosting o del gestor de tu web "
    "(el sitio donde está alojada tu web: tu hosting, WordPress, Wix, Shopify, etc.)."
)

GUIDES: Dict[str, GuideDef] = {
    # ---------------------------------------------------------------- web
    "web:no_https_redirect": GuideDef(
        guide_id="web.no_https_redirect",
        title="Tu web no redirige a la versión segura (HTTPS)",
        why=(
            "Quien escriba http://{domain} verá tu web sin cifrar y el navegador puede "
            "mostrar el aviso «No seguro». Los clientes confían menos y los buscadores "
            "lo penalizan."
        ),
        steps=(
            _HOSTING_ENTRY,
            "Busca la opción «Forzar HTTPS», «Redirigir a HTTPS» o «Certificado SSL» "
            "(suele estar en «Seguridad» o «Dominios»).",
            "Actívala y guarda los cambios.",
            "Si no la encuentras, escribe a tu proveedor: «Quiero que http://{domain} "
            "redirija siempre a https://{domain}».",
            "@recheck",
        ),
        verify=(
            "Escribe http://{domain} en el navegador: debe cambiar solo a https:// y "
            "mostrar el candado."
        ),
        notes=(
            "Para redirigir, HTTPS tiene que funcionar antes. Si Nersivo también marca "
            "un problema de HTTPS o de certificado, soluciónalo primero.",
        ),
    ),
    "web:too_many_redirects": GuideDef(
        guide_id="web.too_many_redirects",
        title="Tu web entra en un bucle de redirecciones",
        why=(
            "El navegador da vueltas entre direcciones sin llegar a ninguna y tus "
            "visitantes ven un error en lugar de tu web."
        ),
        steps=(
            _HOSTING_ENTRY,
            "Revisa las redirecciones configuradas. El bucle suele aparecer cuando hay "
            "dos redirecciones contrarias (de «www» a sin «www» y al revés) o cuando «Forzar "
            "HTTPS» está activado a la vez en tu web y en otro servicio.",
            "Deja una sola regla de redirección y desactiva las duplicadas.",
            "Si no sabes dónde está el problema, envía a tu proveedor el mensaje: «http://{domain} "
            "entra en un bucle de redirecciones».",
            "@recheck",
        ),
        verify="Abre {domain} en una ventana privada del navegador: debe cargar tu web.",
    ),
    "web:unresolved_redirect": GuideDef(
        guide_id="web.unresolved_redirect",
        title="Tu web redirige a una dirección que no funciona",
        why="Tus visitantes son enviados a una dirección que no se puede abrir.",
        steps=(
            _HOSTING_ENTRY,
            "Revisa la redirección de {domain}: comprueba que apunta a una dirección "
            "completa y correcta (por ejemplo https://www.{domain}).",
            "Corrige o elimina la redirección y guarda los cambios.",
            "@recheck",
        ),
        verify="Abre {domain} en el navegador: debe cargar tu web sin errores.",
    ),
    "web:http_error": GuideDef(
        guide_id="web.http_error",
        title="Tu web responde con un error",
        why="Tus visitantes no pueden ver tu web mientras el error continúe.",
        steps=(
            "Abre {domain} en tu navegador para ver si el error aparece también.",
            _HOSTING_ENTRY,
            "Comprueba que tu hosting está al día de pago y sin incidencias.",
            "Si el error continúa, contacta con tu proveedor indicando la hora y la "
            "dirección afectada.",
            "@recheck",
        ),
        verify="Abre {domain} en el navegador: debe cargar tu web.",
    ),
    # -------------------------------------------------------------- https
    "https:https_not_available": GuideDef(
        guide_id="https.not_available",
        title="Tu web no tiene conexión segura (HTTPS)",
        why=(
            "Sin HTTPS los navegadores avisan de que tu web «no es segura», los datos "
            "viajan sin cifrar y los clientes desconfían."
        ),
        steps=(
            _HOSTING_ENTRY,
            "Busca «Certificado SSL», «HTTPS» o «Seguridad». Muchos proveedores lo ofrecen "
            "gratis (por ejemplo con Let's Encrypt).",
            "Activa el certificado para {domain} (y para www.{domain}) y guarda los cambios.",
            "Si tu proveedor no ofrece SSL, pídeselo por escrito o valora cambiar de plan.",
            "@recheck",
        ),
        verify="Abre https://{domain}: debe cargar mostrando el candado.",
    ),
    "https:expiring_soon": GuideDef(
        guide_id="https.expiring",
        title="El certificado de seguridad de tu web caduca pronto",
        why=(
            "Cuando caduca, los navegadores muestran un aviso de seguridad a pantalla "
            "completa y casi nadie entra en tu web."
        ),
        detected="certificate",
        steps=(
            _HOSTING_ENTRY,
            "Comprueba si la renovación del certificado SSL es automática y actívala.",
            "Si compraste el certificado aparte, renuévalo en su proveedor e instálalo "
            "después en tu hosting.",
            "@recheck",
        ),
        verify="Tras renovarlo, Nersivo mostrará una nueva fecha de caducidad.",
    ),
    "https:expiring_very_soon": GuideDef(
        guide_id="https.expiring",
        title="El certificado de seguridad de tu web caduca en muy pocos días",
        why=(
            "Cuando caduca, los navegadores muestran un aviso de seguridad a pantalla "
            "completa y casi nadie entra en tu web. Conviene actuar hoy."
        ),
        detected="certificate",
        steps=(
            _HOSTING_ENTRY,
            "Renueva el certificado SSL ahora o activa su renovación automática.",
            "Si compraste el certificado aparte, renuévalo en su proveedor e instálalo "
            "después en tu hosting.",
            "Si no encuentras cómo, contacta con tu proveedor indicando que es urgente.",
            "@recheck",
        ),
        verify="Tras renovarlo, Nersivo mostrará una nueva fecha de caducidad.",
    ),
    "https:certificate_expired": GuideDef(
        guide_id="https.expired",
        title="El certificado de seguridad de tu web ha caducado",
        why=(
            "Los navegadores bloquean tu web con un aviso de seguridad y la mayoría de "
            "visitantes se marcharán."
        ),
        detected="certificate",
        steps=(
            _HOSTING_ENTRY,
            "Renueva el certificado SSL (muchos proveedores lo hacen con un solo clic o "
            "de forma gratuita).",
            "Si el certificado se renovaba solo, pregunta a tu proveedor por qué ha fallado.",
            "@recheck",
        ),
        verify="Abre https://{domain}: no debe aparecer ningún aviso de seguridad.",
    ),
    "https:hostname_mismatch": GuideDef(
        guide_id="https.hostname_mismatch",
        title="El certificado de tu web no corresponde a tu dominio",
        why=(
            "El certificado está emitido para otro nombre (por ejemplo, cubre «www» pero "
            "no «{domain}»). Los navegadores muestran un aviso de seguridad."
        ),
        steps=(
            _HOSTING_ENTRY,
            "Abre la sección de certificados SSL.",
            "Emite o instala un certificado que cubra {domain} y www.{domain}.",
            "Si usas varios servicios (hosting, tienda, CDN), comprueba que el certificado "
            "se asigna al dominio correcto.",
            "@recheck",
        ),
        verify="Abre https://{domain} y https://www.{domain}: ninguna debe mostrar avisos.",
    ),
    "https:self_signed_certificate": GuideDef(
        guide_id="https.self_signed",
        title="Tu web usa un certificado «autofirmado»",
        why=(
            "Un certificado autofirmado no está avalado por ninguna entidad de confianza: "
            "los navegadores avisan de que la conexión no es segura."
        ),
        steps=(
            _HOSTING_ENTRY,
            "Sustituye el certificado por uno emitido por una entidad reconocida; "
            "muchos hostings lo ofrecen gratis (Let's Encrypt).",
            "@recheck",
        ),
        verify="Abre https://{domain}: no debe aparecer ningún aviso de seguridad.",
    ),
    "https:invalid_certificate": GuideDef(
        guide_id="https.invalid_certificate",
        title="El certificado de tu web tiene problemas",
        why=(
            "Los navegadores no confían en el certificado (por ejemplo, por un fallo en "
            "su instalación) y avisan a tus visitantes."
        ),
        steps=(
            _HOSTING_ENTRY,
            "Reinstala o vuelve a emitir el certificado SSL de {domain}; si lo "
            "instalaste a mano, comprueba que incluiste también los certificados intermedios.",
            "Si no sabes hacerlo, pide a tu proveedor: «Revisad el certificado SSL de {domain}».",
            "@recheck",
        ),
        verify="Abre https://{domain}: no debe aparecer ningún aviso de seguridad.",
    ),
    "https:tls_error": GuideDef(
        guide_id="https.tls_error",
        title="No se puede establecer una conexión segura con tu web",
        why="Los navegadores pueden no ser capaces de abrir tu web de forma segura.",
        steps=(
            _HOSTING_ENTRY,
            "Comprueba que el certificado SSL está activo para {domain}.",
            "Si el problema continúa, pide a tu proveedor que revise la configuración "
            "SSL/TLS de {domain}.",
            "@recheck",
        ),
        verify="Abre https://{domain}: debe cargar mostrando el candado.",
    ),
    # ----------------------------------------------------------------- mx
    "mx:missing_mx": GuideDef(
        guide_id="mx.missing",
        title="Tu dominio no está preparado para recibir correo",
        why=(
            "Sin registros MX, los correos enviados a direcciones @{mail_domain} rebotan "
            "o se pierden."
        ),
        steps=(
            "Localiza los valores MX de tu proveedor de correo (Google Workspace, "
            "Microsoft 365, tu hosting...). Cada proveedor los publica en su ayuda; "
            "busca «registros MX».",
            "@dns_open",
            "Añade los registros MX con exactamente los servidores y prioridades que te "
            "indique tu proveedor de correo.",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, el apartado de correo (MX) debe aparecer en verde.",
        notes=(
            "Si no usas correo con este dominio, puedes ignorar este aviso.",
        ),
        uses="dns_panel",
    ),
    "mx:mx_resolution_issue": GuideDef(
        guide_id="mx.resolution_issue",
        title="Algunos servidores de correo de tu dominio no responden",
        why=(
            "Si un servidor de correo configurado no existe, parte de los correos que te "
            "envían pueden fallar o retrasarse."
        ),
        detected="mx_unresolved",
        steps=(
            "@dns_open",
            "Localiza los registros MX y compara cada servidor con los que indica tu "
            "proveedor de correo: deben estar escritos exactamente igual.",
            "Corrige los que tengan errores de escritura y elimina los que tu proveedor "
            "no use.",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, todos los servidores MX deben resolverse.",
        uses="dns_panel",
    ),
    # ---------------------------------------------------------------- spf
    "spf:missing_spf": GuideDef(
        guide_id="spf.missing",
        title="Tu dominio no tiene SPF",
        why=(
            "SPF indica qué servicios pueden enviar correo en nombre de {mail_domain}. "
            "Sin él, tus emails tienen más probabilidades de acabar en spam y es más fácil "
            "que alguien se haga pasar por ti."
        ),
        steps=(
            "@dns_open",
            "Añade un registro nuevo de tipo TXT con el nombre «@» (o el propio "
            "{mail_domain}, según el panel) y el valor que aparece abajo.",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, SPF debe aparecer en verde.",
        notes=(
            "Si además envías correo desde otros servicios (boletines, facturación, "
            "tienda online), añade también su «include:» dentro del mismo registro SPF; "
            "cada servicio indica el suyo en su ayuda.",
        ),
        uses="both",
        values="spf_missing",
    ),
    "spf:multiple_spf_records": GuideDef(
        guide_id="spf.multiple",
        title="Tu dominio tiene más de un registro SPF",
        why=(
            "Solo se permite un registro SPF. Con varios, muchos servidores de correo "
            "ignoran SPF por completo y tus emails pierden fiabilidad."
        ),
        detected="spf_records",
        steps=(
            "@dns_open",
            "Localiza los registros de tipo TXT que empiezan por «v=spf1» (los que "
            "aparecen arriba).",
            "Combínalos en uno solo: deja un único «v=spf1» y junta dentro todos los "
            "«include:» de los registros, sin repetir los iguales, y termina con un solo "
            "«~all» (o «-all»).",
            "Elimina los registros SPF sobrantes.",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, SPF debe aparecer en verde con un único registro.",
        notes=("No borres un «include:» sin saber qué servicio lo usa: podrías dejar de poder enviar desde él.",),
        uses="dns_panel",
    ),
    # -------------------------------------------------------------- dmarc
    "dmarc:missing_dmarc": GuideDef(
        guide_id="dmarc.missing",
        title="Tu dominio no tiene DMARC",
        why=(
            "DMARC indica qué hacer con los correos que dicen venir de {mail_domain} pero "
            "no son tuyos. Sin él, es más fácil que alguien suplante tu dominio."
        ),
        steps=(
            "@dns_open",
            "Añade un registro nuevo de tipo TXT con el nombre «_dmarc» y el valor "
            "que aparece abajo.",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, DMARC debe aparecer en verde.",
        notes=(
            "«p=none» solo observa: no bloquea nada, por lo que es un punto de partida "
            "seguro. Cuando compruebes que tu correo legítimo pasa las comprobaciones, "
            "puedes endurecerlo más adelante.",
            "Algunos paneles piden el nombre completo: _dmarc.{mail_domain}.",
        ),
        uses="dns_panel",
        values="dmarc_record",
    ),
    "dmarc:multiple_dmarc_records": GuideDef(
        guide_id="dmarc.multiple",
        title="Tu dominio tiene más de un registro DMARC",
        why=(
            "Solo se permite un registro DMARC. Con varios, los servidores lo ignoran y "
            "tu dominio queda sin esa protección."
        ),
        detected="dmarc_records",
        steps=(
            "@dns_open",
            "Localiza los registros TXT con nombre «_dmarc» que empiezan por «v=DMARC1».",
            "Deja solo uno (el que mejor refleje lo que quieres) y elimina los demás.",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, DMARC debe aparecer en verde.",
        uses="dns_panel",
    ),
    "dmarc:invalid_dmarc_record": GuideDef(
        guide_id="dmarc.invalid",
        title="Tu registro DMARC no es válido",
        why=(
            "Si el registro tiene errores, los servidores de correo lo ignoran y tu "
            "dominio queda sin esa protección."
        ),
        detected="dmarc_records",
        steps=(
            "@dns_open",
            "Localiza el registro TXT con nombre «_dmarc».",
            "Sustitúyelo por el valor correcto que aparece abajo (debe empezar por "
            "«v=DMARC1» e incluir «p=»).",
            "@dns_save",
            "@recheck",
        ),
        verify="Tras la nueva comprobación, DMARC debe aparecer en verde.",
        uses="dns_panel",
        values="dmarc_record",
    ),
}

# --- Guías genéricas de reserva (un código sin guía propia) ---------------------
FALLBACKS: Dict[str, GuideDef] = {
    "web": GuideDef(
        guide_id="fallback.web",
        title="Hay un problema con tu web",
        why="Tu web puede no ser accesible o no estar configurada de forma segura.",
        steps=(
            _HOSTING_ENTRY,
            "Revisa la configuración del dominio y las redirecciones.",
            "Si no encuentras el motivo, contacta con tu proveedor indicando el aviso de Nersivo.",
            "@recheck",
        ),
        verify="Abre {domain} en el navegador: debe cargar tu web.",
    ),
    "https": GuideDef(
        guide_id="fallback.https",
        title="Hay un problema con la conexión segura de tu web",
        why="Los navegadores pueden mostrar avisos de seguridad a tus visitantes.",
        steps=(
            _HOSTING_ENTRY,
            "Revisa el certificado SSL de {domain} y su configuración.",
            "Si no encuentras el motivo, contacta con tu proveedor indicando el aviso de Nersivo.",
            "@recheck",
        ),
        verify="Abre https://{domain}: no debe aparecer ningún aviso de seguridad.",
    ),
    "dns": GuideDef(
        guide_id="fallback.dns",
        title="Hay un problema con el DNS de tu dominio",
        why="Si el DNS falla, tu web y tu correo pueden dejar de funcionar.",
        steps=("@dns_open", "Revisa los registros de {domain}.", "@dns_save", "@recheck"),
        verify="Tras la nueva comprobación, el apartado DNS debe aparecer en verde.",
        uses="dns_panel",
    ),
    "mx": GuideDef(
        guide_id="fallback.mx",
        title="Hay un problema con el correo de tu dominio",
        why="Puede que no recibas todos los correos que te envían.",
        steps=("@dns_open", "Revisa los registros MX de {mail_domain} con tu proveedor de correo.", "@dns_save", "@recheck"),
        verify="Tras la nueva comprobación, el apartado de correo (MX) debe aparecer en verde.",
        uses="dns_panel",
    ),
    "spf": GuideDef(
        guide_id="fallback.spf",
        title="Hay un problema con el SPF de tu dominio",
        why="Tus correos pueden acabar en spam o ser suplantados con más facilidad.",
        steps=("@dns_open", "Revisa el registro TXT que empieza por «v=spf1».", "@dns_save", "@recheck"),
        verify="Tras la nueva comprobación, SPF debe aparecer en verde.",
        uses="dns_panel",
    ),
    "dmarc": GuideDef(
        guide_id="fallback.dmarc",
        title="Hay un problema con el DMARC de tu dominio",
        why="Tu dominio puede ser suplantado con más facilidad.",
        steps=("@dns_open", "Revisa el registro TXT con nombre «_dmarc».", "@dns_save", "@recheck"),
        verify="Tras la nueva comprobación, DMARC debe aparecer en verde.",
        uses="dns_panel",
    ),
}
