"""
Analizador de dominios de Nersivo.

`analyze_domain` ejecuta los seis checks reales (web, https, dns, mx, spf,
dmarc) y construye la respuesta: resumen, estado global y puntuación (score)
calculada de forma determinista a partir de los resultados reales.
"""

from datetime import datetime, timezone
from typing import Optional

from .checks.dmarc import check_dmarc
from .checks.dns import check_dns
from .checks.https import check_https
from .checks.mx import check_mx
from .checks.spf import check_spf
from .checks.web import check_web
from .domain_utils import get_email_check_domain
from .models import (
    AnalyzeResponse,
    CheckResult,
    Checks,
    Status,
    Summary,
)

# --- Puntuación (score) ---------------------------------------------------
# Todos los checks pesan lo mismo. Cada check evaluado aporta una fracción de
# su peso según su estado:
#   ok      -> 100 % del peso
#   warning ->  50 % del peso (penalización moderada)
#   error   ->   0 % del peso (penalización fuerte)
#   unknown -> NO se evalúa: se excluye del cálculo, ni suma ni penaliza.
#
# Para que el score sea representativo se exige un mínimo de checks evaluados;
# con menos, el score es `None` (null en el JSON).
_MIN_EVALUATED_CHECKS = 3
_STATUS_CREDIT = {
    Status.OK: 1.0,
    Status.WARNING: 0.5,
    Status.ERROR: 0.0,
}


def _utc_now_iso() -> str:
    """Devuelve la fecha/hora UTC actual en formato ISO 8601 con sufijo 'Z'."""
    # Usamos datetime.now(timezone.utc) (aware) en lugar de datetime.utcnow()
    # (naive, deprecado). Formateamos con 'Z' para indicar UTC, igual que en
    # el contrato ("2026-09-22T10:15:32Z").
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_checks(
    domain: str,
    web_check: CheckResult,
    https_check: CheckResult,
    dns_check: CheckResult,
    mx_check: CheckResult,
    spf_check: CheckResult,
    dmarc_check: CheckResult,
) -> Checks:
    """
    Construye el conjunto de checks del análisis.

    Todos los checks (`web`, `https`, `dns`, `mx`, `spf` y `dmarc`) se reciben
    ya calculados por sus implementaciones REALES (`checks.web.check_web`,
    `checks.https.check_https`, `checks.dns.check_dns`, `checks.mx.check_mx`,
    `checks.spf.check_spf` y `checks.dmarc.check_dmarc`).

    Args:
        domain: Dominio ya validado y normalizado.
        web_check: Resultado REAL del check de web.
        https_check: Resultado REAL del check de https.
        dns_check: Resultado REAL del check de dns.
        mx_check: Resultado REAL del check de mx.
        spf_check: Resultado REAL del check de spf.
        dmarc_check: Resultado REAL del check de dmarc.

    Returns:
        Objeto `Checks` con los seis checks del análisis.
    """

    # ==================================================================
    # CHECKS REALES
    # ==================================================================
    # Se calculan en sus respectivos módulos y se pasan como argumentos.
    web = web_check  # checks/web.py
    https = https_check  # checks/https.py
    dns = dns_check  # checks/dns.py
    mx = mx_check  # checks/mx.py
    spf = spf_check  # checks/spf.py
    dmarc = dmarc_check  # checks/dmarc.py

    return Checks(web=web, https=https, dns=dns, mx=mx, spf=spf, dmarc=dmarc)


def _compute_summary(checks: Checks) -> Summary:
    """
    Calcula el resumen agregado contando los estados de todos los checks.

    - passed   -> checks con estado OK
    - warnings -> checks con estado WARNING
    - errors   -> checks con estado ERROR
    - unknown  -> checks con estado UNKNOWN
    """
    all_checks = [
        checks.web,
        checks.https,
        checks.dns,
        checks.mx,
        checks.spf,
        checks.dmarc,
    ]

    passed = sum(1 for c in all_checks if c.status == Status.OK)
    warnings = sum(1 for c in all_checks if c.status == Status.WARNING)
    errors = sum(1 for c in all_checks if c.status == Status.ERROR)
    unknown = sum(1 for c in all_checks if c.status == Status.UNKNOWN)
    total = len(all_checks)

    # Titular en función del estado agregado de los checks.
    # Prioridad: error > warning > ok > unknown (todos desconocidos).
    if errors > 0:
        headline = "Se han detectado problemas que conviene revisar."
    elif warnings > 0:
        headline = "Se han detectado aspectos que conviene revisar."
    elif passed > 0:
        headline = "No se han detectado problemas."
    else:
        # Todos los checks son unknown: no hemos podido determinar el estado.
        headline = "No hemos podido completar el análisis."

    return Summary(
        headline=headline,
        total_checks=total,
        passed=passed,
        warnings=warnings,
        errors=errors,
        unknown=unknown,
    )


def _compute_global_status(summary: Summary) -> Status:
    """
    Calcula el estado global según la prioridad conceptual: error > warning > ok.

    Reglas:
    - Si hay algún check en ERROR    -> error.
    - Si hay algún check en WARNING   -> warning.
    - Si hay al menos un check OK real -> ok.
    - Si NO hay ningún error, warning ni ok (todos los checks relevantes son
      UNKNOWN) -> unknown.

    Importante: los `unknown` NO se convierten artificialmente en warning/error.
    `unknown` significa que no hemos podido determinar el estado. Por eso un
    dominio que no resuelve (todos sus checks unknown) tiene `global_status`
    unknown, no warning ni error.
    """
    if summary.errors > 0:
        return Status.ERROR
    if summary.warnings > 0:
        return Status.WARNING
    if summary.passed > 0:
        return Status.OK
    # No hay errores ni warnings ni checks OK: todo es unknown.
    return Status.UNKNOWN


def _compute_score(checks: Checks) -> Optional[int]:
    """
    Calcula la puntuación (entero 0-100) o `None` si no hay base suficiente.

    Fórmula (todos los checks con el mismo peso):

        score = round(100 * suma(crédito de cada check evaluado) / nº evaluados)

    con crédito ok=1.0, warning=0.5, error=0.0. Los checks `unknown` no se
    cuentan (ni en el numerador ni en el denominador).

    Solo se calcula si hay al menos `_MIN_EVALUATED_CHECKS` (3) checks
    evaluados; con 0, 1 o 2 devuelve `None`: no se muestra una nota
    engañosa (0/100 o 100/100) cuando casi no se ha podido analizar el dominio.
    Esto también evita cualquier división por cero.

    Es determinista: depende solo de los estados de los checks.
    """
    all_checks = [
        checks.web,
        checks.https,
        checks.dns,
        checks.mx,
        checks.spf,
        checks.dmarc,
    ]
    evaluated = [c for c in all_checks if c.status in _STATUS_CREDIT]
    if len(evaluated) < _MIN_EVALUATED_CHECKS:
        return None
    credit = sum(_STATUS_CREDIT[c.status] for c in evaluated)
    # Redondeo "half up" explícito (round() de Python redondea .5 al par).
    score = int(100 * credit / len(evaluated) + 0.5)
    return max(0, min(100, score))


def analyze_domain(domain: str) -> AnalyzeResponse:
    """
    Analiza un dominio y devuelve la respuesta completa.

    Ejecuta los seis checks reales sobre el hostname recibido (sea dominio
    principal o subdominio) y calcula resumen, estado global y puntuación.

    - web, https y dns usan el hostname tal cual se ha introducido.
    - mx, spf y dmarc usan `get_email_check_domain(domain)`: solo se quita un
      `www.` inicial (www.example.com -> example.com). El resto de subdominios
      (mail.example.com...) se comprueban tal cual, sin marcarse como "no
      aplicables".

    Args:
        domain: Dominio ya validado y normalizado.

    Returns:
        AnalyzeResponse compatible con el contrato JSON.
    """
    web_check = check_web(domain)
    https_check = check_https(domain)
    dns_check = check_dns(domain)
    email_domain = get_email_check_domain(domain)
    mx_check = check_mx(email_domain)
    spf_check = check_spf(email_domain)
    dmarc_check = check_dmarc(email_domain)

    checks = _build_checks(
        domain, web_check, https_check, dns_check, mx_check, spf_check, dmarc_check
    )

    summary = _compute_summary(checks)
    global_status = _compute_global_status(summary)

    return AnalyzeResponse(
        domain=domain,
        analyzed_at=_utc_now_iso(),
        global_status=global_status,
        score=_compute_score(checks),
        summary=summary,
        checks=checks,
    )
