"""
Modelos Pydantic de Nersivo.

Estos modelos reflejan EXACTAMENTE el contrato JSON congelado
(`webguard_mvp_v1.json`) que define la estructura de la respuesta del
endpoint `/analyze/{domain}`.

Notas de diseño:
- Los `details` de cada check son diccionarios dinámicos (`Dict[str, Any]`)
  porque cada tipo de check tiene una estructura de detalles diferente.
- `technical_reason`, `recommendation` y `user_message` son opcionales
  (pueden ser `null` en el contrato).
"""

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Status(str, Enum):
    """Estado de un check o estado global del análisis."""

    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Nivel de severidad asociado a un check."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    # Aunque no aparece en el ejemplo del contrato, se incluye por decisión
    # explícita del usuario para poder representar severidades desconocidas.
    UNKNOWN = "unknown"


class CheckResult(BaseModel):
    """
    Resultado de un check individual (web, https, dns, mx, spf, dmarc).

    El campo `details` es un diccionario dinámico porque cada check tiene
    una estructura de detalles distinta (ver contrato JSON).
    """

    status: Status
    severity: Severity
    title: str
    summary: str
    checked: bool
    details: Dict[str, Any]
    # Campos opcionales: pueden ser `null` en el contrato.
    technical_reason: Optional[str] = None
    recommendation: Optional[str] = None
    user_message: Optional[str] = None


class Summary(BaseModel):
    """Resumen agregado del análisis."""

    headline: str
    total_checks: int
    passed: int
    warnings: int
    errors: int
    unknown: int


class Checks(BaseModel):
    """
    Conjunto de checks que componen el análisis de un dominio.

    El orden y los nombres coinciden con el contrato JSON.
    """

    web: CheckResult
    https: CheckResult
    dns: CheckResult
    mx: CheckResult
    spf: CheckResult
    dmarc: CheckResult


class AnalyzeResponse(BaseModel):
    """
    Respuesta completa del endpoint `/analyze/{domain}`.

    Refleja exactamente la estructura del contrato JSON congelado.
    """

    domain: str
    analyzed_at: str
    global_status: Status
    # Entero entre 0 y 100, o null si hay menos de 3 checks evaluados
    # (ver analyzer._compute_score). El campo siempre está presente.
    score: Optional[int] = Field(..., ge=0, le=100)
    summary: Summary
    checks: Checks
