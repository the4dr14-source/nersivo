"""
Modelos de la respuesta de `POST /guides`.

Son independientes del contrato congelado de `/analyze` (`webguard_mvp_v1.json`):
la API de guías es un contrato nuevo y aditivo.
"""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class ProviderOut(BaseModel):
    """Proveedor identificado con evidencia suficiente."""

    id: str
    name: str
    confidence: str
    evidence: List[str] = Field(default_factory=list)


class ProvidersOut(BaseModel):
    """Proveedores identificados (cada uno puede ser null)."""

    mail: Optional[ProviderOut] = None
    dns_panel: Optional[ProviderOut] = None
    mail_intermediary: Optional[ProviderOut] = None


class GuideValue(BaseModel):
    """Valor técnico que el usuario debe introducir (p. ej. un registro TXT)."""

    label: str
    record_type: Optional[str] = None
    host: Optional[str] = None
    value: str
    note: Optional[str] = None


class Guide(BaseModel):
    """Guía "Cómo solucionarlo" para un problema detectado."""

    check: str
    problem_code: Optional[str] = None
    guide_id: str
    title: str
    why: str
    # "specific": el texto/valores dependen de un proveedor identificado.
    # "generic": válida para cualquier proveedor (guía segura de reserva).
    audience: Literal["specific", "generic"]
    intro: str
    detected: List[str] = Field(default_factory=list)  # datos reales del análisis
    steps: List[str]
    values: List[GuideValue] = Field(default_factory=list)
    verify: str
    notes: List[str] = Field(default_factory=list)


class GuidesResponse(BaseModel):
    """Respuesta de `POST /guides`."""

    domain: str
    providers: ProvidersOut
    guides: List[Guide]
