"""Constructores de análisis de prueba (sin red) para guías y monitorización."""

import copy
from typing import Any, Dict, Optional

from backend.models import AnalyzeResponse

_SEVERITY = {"ok": "none", "warning": "medium", "error": "high", "unknown": "unknown"}

_DEFAULT_DETAILS: Dict[str, Dict[str, Any]] = {
    "web": {
        "requested_url": "http://example.com", "final_url": "https://example.com/",
        "status_code": 200, "response_time_ms": 120, "error": None, "timeout": False,
        "redirect_chain": [], "final_is_https": True, "redirected_to_https": True,
    },
    "https": {
        "https_available": True, "valid": True, "matches_domain": True,
        "issued_at": "2026-07-15T00:00:00+00:00", "expires_at": "2027-01-15T00:00:00+00:00",
        "days_remaining": 100, "error": None,
    },
    "dns": {
        "resolves": True, "a_records": ["93.184.216.34"], "aaaa_records": [], "error": None,
    },
    "mx": {
        "found": True, "error": None,
        "records": [{"priority": 1, "hostname": "aspmx.l.google.com", "resolves": True}],
    },
    "spf": {
        "found": True, "record_count": 1, "syntax_valid": True, "error": None,
        "records": ["v=spf1 include:_spf.google.com ~all"],
    },
    "dmarc": {
        "found": True, "record": "v=DMARC1; p=none;", "policy": "none", "error": None,
    },
}


def check(name: str, status: str = "ok", reason: Optional[str] = None, **details: Any) -> Dict[str, Any]:
    """CheckResult (como dict) con detalles realistas y overrides opcionales."""
    merged = copy.deepcopy(_DEFAULT_DETAILS[name])
    merged.update(details)
    return {
        "status": status,
        "severity": _SEVERITY[status],
        "title": name,
        "summary": f"{name} {status}",
        "checked": status != "unknown",
        "details": merged,
        "technical_reason": reason,
        "recommendation": None,
        "user_message": None,
    }


def analysis(
    domain: str = "example.com",
    *,
    score: Optional[int] = 90,
    global_status: str = "ok",
    analyzed_at: str = "2026-10-07T10:00:00Z",
    **overrides: Dict[str, Any],
) -> AnalyzeResponse:
    """
    AnalyzeResponse con los 6 checks en OK por defecto.

    `overrides`: `nombre_check=check(...)` (dict ya construido con `check`).
    """
    checks = {name: check(name) for name in _DEFAULT_DETAILS}
    checks.update(overrides)
    statuses = [c["status"] for c in checks.values()]
    return AnalyzeResponse.model_validate({
        "domain": domain,
        "analyzed_at": analyzed_at,
        "global_status": global_status,
        "score": score,
        "summary": {
            "headline": "h", "total_checks": 6, "passed": statuses.count("ok"),
            "warnings": statuses.count("warning"), "errors": statuses.count("error"),
            "unknown": statuses.count("unknown"),
        },
        "checks": checks,
    })
