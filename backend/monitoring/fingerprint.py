"""
Huella estable de un análisis para comparar resultados en el tiempo.

NO se compara el JSON completo: contiene campos dinámicos (`analyzed_at`,
`response_time_ms`, `status_code`, `days_remaining`, listas de IPs de CDN...)
que cambiarían en cada ejecución y producirían falsos cambios. La huella
conserva solo lo que representa un cambio real de configuración o de estado:

- estado y `technical_reason` de cada check (UNKNOWN se conserva tal cual);
- web: redirección a HTTPS;
- https: fecha de caducidad del certificado (sin los días restantes);
- mx: conjunto de servidores de correo;
- spf: registros SPF normalizados;
- dmarc: registro y política.

Las IPs de A/AAAA se excluyen a propósito: con CDN o balanceadores cambian
sin que haya ningún problema (el check `dns` ya señala si el dominio no resuelve).
"""

import re
from typing import Any, Dict, List, Optional

from ..providers.identify import as_dict

FINGERPRINT_VERSION = 1
CHECK_ORDER = ("web", "https", "dns", "mx", "spf", "dmarc")

_WS = re.compile(r"\s+")


def _norm_text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = _WS.sub(" ", value.strip())
    return cleaned or None


def _norm_list(values: Any, *, lower: bool = True) -> List[str]:
    out = set()
    for value in values if isinstance(values, list) else []:
        text = _norm_text(value)
        if text:
            out.add(text.lower() if lower else text)
    return sorted(out)


def _date_only(value: Any) -> Optional[str]:
    return str(value)[:10] if isinstance(value, str) and value else None


def _facts(name: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """Hechos estables de un check (vacío si el check no tiene hechos relevantes)."""
    if name == "web":
        return {
            "redirected_to_https": details.get("redirected_to_https"),
            "final_is_https": details.get("final_is_https"),
        }
    if name == "https":
        return {"expires_on": _date_only(details.get("expires_at"))}
    if name == "mx":
        hosts = [
            r.get("hostname")
            for r in details.get("records") or []
            if isinstance(r, dict) and isinstance(r.get("hostname"), str)
        ]
        return {"hosts": _norm_list([h.rstrip(".") for h in hosts])}
    if name == "spf":
        return {"records": _norm_list(details.get("records"))}
    if name == "dmarc":
        policy = _norm_text(details.get("policy"))
        return {
            "record": _norm_text(details.get("record")),
            "policy": policy.lower() if policy else None,
        }
    return {}


def make_fingerprint(analysis: Any) -> Dict[str, Any]:
    """
    Huella estable de un `AnalyzeResponse` (o dict equivalente).

    `score` es `None` cuando el análisis no tiene puntuación (se conserva:
    nunca se inventa un número).
    """
    data = as_dict(analysis)
    checks_in = data.get("checks") or {}
    checks: Dict[str, Any] = {}
    for name in CHECK_ORDER:
        check = checks_in.get(name)
        if not isinstance(check, dict):
            continue
        details = check.get("details") if isinstance(check.get("details"), dict) else {}
        checks[name] = {
            "status": check.get("status"),
            "reason": check.get("technical_reason"),
            "facts": _facts(name, details),
        }
    score = data.get("score")
    return {
        "v": FINGERPRINT_VERSION,
        "global_status": data.get("global_status"),
        "score": score if isinstance(score, int) and not isinstance(score, bool) else None,
        "checks": checks,
    }


def merge_baseline(
    baseline: Optional[Dict[str, Any]], current: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Nueva base de comparación tras un análisis.

    Si un check está `unknown` ahora (fallo transitorio de DNS, timeout...),
    se conserva su último valor conocido en lugar de sustituirlo: así un
    problema que aparece justo después de un `unknown` no se pierde, y un
    `unknown` nunca se interpreta como mejora ni como empeoramiento.
    """
    merged = {**current, "checks": dict(current["checks"])}
    if baseline:
        for name, entry in current["checks"].items():
            previous = (baseline.get("checks") or {}).get(name)
            if entry.get("status") == "unknown" and previous and previous.get("status") != "unknown":
                merged["checks"][name] = previous
    return merged
