"""
Comparación de huellas: qué cambios son relevantes y cuáles no.

Reglas (ver `fingerprint.py` para qué se compara):

- UNKNOWN no es comparable: un check `unknown` ahora, o sin valor conocido
  previo, no genera cambios (ni "problema nuevo" ni "resuelto").
- ok -> warning/error: `new_problem` (critical si error, warning si warning).
- warning/error -> ok: `resolved_problem` (info).
- warning <-> error, o distinto problema: `status_change`.
- Mismo estado pero distinta configuración relevante (MX, SPF, DMARC, redirección
  HTTPS): `config_change`. Si el check ya generó un cambio de estado, no se
  duplica con un `config_change`.
- Certificado con nueva fecha de caducidad posterior: `certificate_renewed` (info).
- Score: solo si ambos existen y la diferencia es >= `SCORE_THRESHOLD`.
  Cambios de/hacia `null` no generan evento (null = datos insuficientes).
- Sin huella previa (primer análisis): sin cambios.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..guides.builder import select_guide
from .fingerprint import CHECK_ORDER

SCORE_THRESHOLD = 10

KIND_NEW_PROBLEM = "new_problem"
KIND_RESOLVED = "resolved_problem"
KIND_STATUS_CHANGE = "status_change"
KIND_CONFIG_CHANGE = "config_change"
KIND_CERT_RENEWED = "certificate_renewed"
KIND_SCORE_CHANGE = "score_change"

SEV_INFO = "info"
SEV_WARNING = "warning"
SEV_CRITICAL = "critical"

_LABELS = {
    "web": "la web",
    "https": "HTTPS",
    "dns": "el DNS",
    "mx": "el correo (MX)",
    "spf": "SPF",
    "dmarc": "DMARC",
}
_BAD = ("warning", "error")


@dataclass
class Change:
    """Un cambio relevante entre dos análisis."""

    kind: str
    severity: str
    check: Optional[str]
    summary: str
    before: Any = None
    after: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "check": self.check,
            "summary": self.summary,
            "before": self.before,
            "after": self.after,
        }


def _problem_text(check: str, reason: Optional[str]) -> str:
    return select_guide(check, reason).title.replace("{domain}", "").replace("{mail_domain}", "").strip()


def _facts_changed(name: str, before: Dict[str, Any], after: Dict[str, Any]) -> Optional[Change]:
    if before == after:
        return None
    label = _LABELS[name]
    if name == "https":
        old, new = before.get("expires_on"), after.get("expires_on")
        if old and new and new > old:
            return Change(
                KIND_CERT_RENEWED, SEV_INFO, name,
                f"El certificado se ha renovado (nueva caducidad: {new}).", old, new,
            )
        return Change(
            KIND_CONFIG_CHANGE, SEV_WARNING, name,
            f"Ha cambiado el certificado de {label}.", old, new,
        )
    return Change(
        KIND_CONFIG_CHANGE, SEV_WARNING, name,
        f"Ha cambiado la configuración de {label}.", before, after,
    )


def diff_fingerprints(
    baseline: Optional[Dict[str, Any]], current: Dict[str, Any]
) -> List[Change]:
    """
    Cambios relevantes entre la base de comparación y el análisis actual.

    Args:
        baseline: huella previa (ya fusionada con `merge_baseline`) o None.
        current: huella del análisis actual.
    """
    if not baseline:
        return []
    changes: List[Change] = []
    base_checks = baseline.get("checks") or {}

    for name in CHECK_ORDER:
        cur = (current.get("checks") or {}).get(name)
        old = base_checks.get(name)
        if not cur or not old:
            continue
        old_status, new_status = old.get("status"), cur.get("status")
        if "unknown" in (old_status, new_status) or None in (old_status, new_status):
            continue

        label = _LABELS[name]
        status_event: Optional[Change] = None
        if old_status != new_status:
            if old_status == "ok" and new_status in _BAD:
                status_event = Change(
                    KIND_NEW_PROBLEM,
                    SEV_CRITICAL if new_status == "error" else SEV_WARNING,
                    name,
                    f"Nuevo problema en {label}: {_problem_text(name, cur.get('reason'))}",
                    old_status, new_status,
                )
            elif old_status in _BAD and new_status == "ok":
                status_event = Change(
                    KIND_RESOLVED, SEV_INFO, name,
                    f"Problema resuelto en {label}.", old_status, new_status,
                )
            else:  # warning <-> error
                status_event = Change(
                    KIND_STATUS_CHANGE,
                    SEV_CRITICAL if new_status == "error" else SEV_WARNING,
                    name,
                    f"{label.capitalize()} ha pasado de {old_status} a {new_status}.",
                    old_status, new_status,
                )
        elif old_status in _BAD and old.get("reason") != cur.get("reason"):
            status_event = Change(
                KIND_STATUS_CHANGE,
                SEV_CRITICAL if new_status == "error" else SEV_WARNING,
                name,
                f"El problema de {label} ha cambiado: {_problem_text(name, cur.get('reason'))}",
                old.get("reason"), cur.get("reason"),
            )

        if status_event is not None:
            changes.append(status_event)
            continue
        facts_event = _facts_changed(name, old.get("facts") or {}, cur.get("facts") or {})
        if facts_event is not None:
            changes.append(facts_event)

    old_score, new_score = baseline.get("score"), current.get("score")
    if isinstance(old_score, int) and isinstance(new_score, int):
        delta = new_score - old_score
        if abs(delta) >= SCORE_THRESHOLD:
            word = "subido" if delta > 0 else "bajado"
            changes.append(
                Change(
                    KIND_SCORE_CHANGE,
                    SEV_INFO if delta > 0 else SEV_WARNING,
                    None,
                    f"La puntuación ha {word} de {old_score} a {new_score}.",
                    old_score, new_score,
                )
            )
    return changes
