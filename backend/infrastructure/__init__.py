"""
Módulo aislado de detección de infraestructura/proveedores de un dominio.

Fase de validación técnica: NO está conectado a `analyzer.py`, al contrato JSON
ni al frontend. Punto de entrada: `analyze_infrastructure(domain)`.

Ver `detector.py` para la semántica de datos confirmados (`detected`) frente a
inferencias (`inferred`) y la confianza (`confidence`).
"""

from .detector import analyze_infrastructure
from .models import Detection, InfrastructureReport, RdapResult

__all__ = [
    "analyze_infrastructure",
    "Detection",
    "InfrastructureReport",
    "RdapResult",
]
