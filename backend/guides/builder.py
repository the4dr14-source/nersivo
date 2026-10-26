"""
Constructor de guías: une análisis + proveedores + catálogo.

Es una función PURA (sin red): recibe el análisis y el contexto de proveedores
ya identificados y devuelve las guías. No contiene texto de guías (vive en
`catalog.py`) ni lógica de detección de problemas (vive en los checks): solo
selecciona la guía de cada check con estado `warning`/`error`.

UNKNOWN nunca genera guía: significa "no hemos podido comprobarlo", no
"hay un problema".
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from ..domain_utils import get_email_check_domain
from ..providers import ProviderContext
from ..providers.identify import as_dict
from . import catalog
from .models import Guide, GuideValue

CHECK_ORDER = ("web", "https", "dns", "mx", "spf", "dmarc")
_PROBLEM_STATUSES = ("warning", "error")
_MAX_DETECTED_CHARS = 300

_GENERIC_DNS_PANEL = (
    "Entra en el panel donde gestionas el DNS de tu dominio (normalmente es la web "
    "de la empresa donde compraste el dominio o de tu proveedor de hosting)."
)
_GENERIC_NO_PROVIDER_DNS = (
    "No hemos podido identificar automáticamente tu proveedor. Consulta el panel "
    "de gestión DNS de tu proveedor y añade el registro indicado."
)


# ---------------------------------------------------------------------------
# Selección
# ---------------------------------------------------------------------------
def select_guide(check: str, technical_reason: Optional[str]) -> catalog.GuideDef:
    """Guía específica del problema o, si no existe, la genérica del check."""
    key = f"{check}:{technical_reason}"
    found = catalog.GUIDES.get(key)
    if found is not None:
        return found
    if check == "web" and technical_reason and technical_reason.startswith("http_"):
        return catalog.GUIDES["web:http_error"]
    return catalog.FALLBACKS[check]


def problem_checks(analysis: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """Checks con estado `warning`/`error`, en orden estable."""
    checks = as_dict(analysis).get("checks") or {}
    return [
        (name, checks[name])
        for name in CHECK_ORDER
        if isinstance(checks.get(name), dict) and checks[name].get("status") in _PROBLEM_STATUSES
    ]


def needs_dns_panel(analysis: Any) -> bool:
    """True si alguna guía a generar se personaliza con el panel DNS."""
    return any(
        select_guide(name, check.get("technical_reason")).uses in ("dns_panel", "both")
        for name, check in problem_checks(analysis)
    )


# ---------------------------------------------------------------------------
# Datos reales del análisis que se muestran en la guía
# ---------------------------------------------------------------------------
def _short(text: str) -> str:
    text = str(text)
    return text if len(text) <= _MAX_DETECTED_CHARS else text[: _MAX_DETECTED_CHARS - 1] + "…"


def _detected_certificate(check: Dict[str, Any], _a: Dict[str, Any]) -> List[str]:
    details = check.get("details") or {}
    lines: List[str] = []
    if details.get("expires_at"):
        lines.append(f"Fecha de caducidad: {str(details['expires_at'])[:10]}")
    days = details.get("days_remaining")
    if isinstance(days, int):
        lines.append(f"Días restantes: {days}" if days >= 0 else f"Caducó hace {-days} días")
    return lines


def _detected_mx_unresolved(check: Dict[str, Any], _a: Dict[str, Any]) -> List[str]:
    records = (check.get("details") or {}).get("records") or []
    return [
        f"No responde: {r.get('hostname')}"
        for r in records
        if isinstance(r, dict) and r.get("resolves") is False and r.get("hostname")
    ]


def _detected_spf_records(check: Dict[str, Any], _a: Dict[str, Any]) -> List[str]:
    records = (check.get("details") or {}).get("records") or []
    return [f"Registro encontrado: {_short(r)}" for r in records if isinstance(r, str)]


def _detected_dmarc_records(check: Dict[str, Any], _a: Dict[str, Any]) -> List[str]:
    record = (check.get("details") or {}).get("record")
    return [f"Registro encontrado: {_short(record)}"] if isinstance(record, str) and record else []


DETECTED_BUILDERS: Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], List[str]]] = {
    "certificate": _detected_certificate,
    "mx_unresolved": _detected_mx_unresolved,
    "spf_records": _detected_spf_records,
    "dmarc_records": _detected_dmarc_records,
}


# ---------------------------------------------------------------------------
# Valores técnicos (dependen del proveedor)
# ---------------------------------------------------------------------------
def _values_spf_missing(
    ctx: ProviderContext, mail_domain: str
) -> Tuple[List[GuideValue], List[str]]:
    """SPF: valor verificado solo si el proveedor de correo está identificado."""
    mail = ctx.mail
    if mail is not None and mail.id in catalog.SPF_INCLUDES:
        value = GuideValue(
            label="Registro SPF",
            record_type="TXT",
            host="@",
            value=catalog.SPF_INCLUDES[mail.id],
            note=f"Es el valor que corresponde al servicio de correo {mail.name}.",
        )
        return [value], []
    if mail is not None:
        return [], [
            f"Hemos detectado que tu correo utiliza {mail.name}, pero no tenemos su valor "
            "SPF verificado. Búscalo en la ayuda de tu proveedor de correo («registro SPF») "
            "o pídeselo."
        ]
    notes = [
        "No hemos podido identificar tu proveedor de correo, así que no podemos darte el "
        "valor exacto. Búscalo en la ayuda de tu proveedor de correo («registro SPF») o pídeselo."
    ]
    if ctx.mail_intermediary is not None:
        notes.append(
            f"Tu correo pasa por {ctx.mail_intermediary.name}, un filtro de seguridad: el "
            "valor SPF depende del servicio de buzones que haya detrás."
        )
    return [], notes


def _values_dmarc_record(
    _ctx: ProviderContext, mail_domain: str
) -> Tuple[List[GuideValue], List[str]]:
    value = GuideValue(
        label="Registro DMARC",
        record_type="TXT",
        host="_dmarc",
        value="v=DMARC1; p=none;",
        note=(
            f"Si quieres recibir informes, añade al final «rua=mailto:tu-correo@{mail_domain};» "
            "con una dirección que leas."
        ),
    )
    return [value], []


VALUE_BUILDERS: Dict[str, Callable[[ProviderContext, str], Tuple[List[GuideValue], List[str]]]] = {
    "spf_missing": _values_spf_missing,
    "dmarc_record": _values_dmarc_record,
}


# ---------------------------------------------------------------------------
# Texto: macros y plantillas
# ---------------------------------------------------------------------------
def _fill(text: str, domain: str, mail_domain: str) -> str:
    return text.replace("{mail_domain}", mail_domain).replace("{domain}", domain)


def _dns_open_steps(ctx: ProviderContext) -> List[str]:
    panel = ctx.dns_panel
    if panel is None:
        first = _GENERIC_DNS_PANEL
    else:
        hint = catalog.PANEL_HINTS.get(panel.id, "")
        first = (
            f"Entra en el panel donde gestionas el DNS de tu dominio. Según los servidores "
            f"de nombres de tu dominio, parece ser {panel.name}. {hint}".strip()
            + " (Las pantallas pueden variar.)"
        )
    return [
        first,
        "Busca la sección de registros DNS (a veces se llama «Zona DNS», «Gestión DNS» o «Registros»).",
    ]


def _expand_steps(steps: Tuple[str, ...], ctx: ProviderContext) -> List[str]:
    expanded: List[str] = []
    for step in steps:
        if step == "@dns_open":
            expanded.extend(_dns_open_steps(ctx))
        elif step == "@dns_save":
            expanded.append(
                "Guarda los cambios. Pueden tardar desde unos minutos hasta unas horas en aplicarse."
            )
        elif step == "@recheck":
            expanded.append("Vuelve a Nersivo y haz una nueva comprobación del dominio.")
        else:
            expanded.append(step)
    return expanded


def _intro(definition: catalog.GuideDef, ctx: ProviderContext) -> str:
    parts: List[str] = []
    uses = definition.uses
    if uses in ("mail", "both"):
        if ctx.mail is not None:
            parts.append(f"Hemos detectado que tu correo utiliza {ctx.mail.name}.")
    if uses in ("dns_panel", "both"):
        if ctx.dns_panel is not None:
            parts.append(
                f"Los servidores de nombres de tu dominio indican que el DNS lo gestiona {ctx.dns_panel.name}."
            )
        else:
            parts.append(_GENERIC_NO_PROVIDER_DNS)
    if uses is None:
        parts.append("Estos pasos sirven para cualquier proveedor de hosting o gestor de web.")
    return " ".join(parts)


def _is_specific(definition: catalog.GuideDef, ctx: ProviderContext) -> bool:
    uses = definition.uses
    return bool(
        (uses in ("mail", "both") and ctx.mail is not None)
        or (uses in ("dns_panel", "both") and ctx.dns_panel is not None)
    )


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def build_guides(analysis: Any, ctx: ProviderContext) -> List[Guide]:
    """
    Guías para cada check con problema (`warning`/`error`) del análisis.

    Args:
        analysis: `AnalyzeResponse` (o dict equivalente).
        ctx: proveedores identificados (`providers.identify_providers`).
    """
    data = as_dict(analysis)
    domain = str(data.get("domain") or "")
    try:
        mail_domain = get_email_check_domain(domain)
    except Exception:  # noqa: BLE001
        mail_domain = domain

    guides: List[Guide] = []
    for name, check in problem_checks(data):
        reason = check.get("technical_reason")
        definition = select_guide(name, reason)

        values: List[GuideValue] = []
        extra_notes: List[str] = []
        if definition.values:
            values, extra_notes = VALUE_BUILDERS[definition.values](ctx, mail_domain)
        detected: List[str] = []
        if definition.detected:
            detected = DETECTED_BUILDERS[definition.detected](check, data)

        def fill(text: str) -> str:
            return _fill(text, domain, mail_domain)

        guides.append(
            Guide(
                check=name,
                problem_code=reason,
                guide_id=definition.guide_id,
                title=fill(definition.title),
                why=fill(definition.why),
                audience="specific" if _is_specific(definition, ctx) else "generic",
                intro=_intro(definition, ctx),
                detected=detected,
                steps=[fill(s) for s in _expand_steps(definition.steps, ctx)],
                values=values,
                verify=fill(definition.verify),
                notes=[fill(n) for n in list(definition.notes) + extra_notes],
            )
        )
    return guides
