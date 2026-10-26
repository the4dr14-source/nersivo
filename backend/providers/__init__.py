"""
Identificación de proveedores a partir de datos que Nersivo YA obtiene.

Este paquete es independiente de las guías de solución y de los checks:
recibe un análisis (`AnalyzeResponse`) y, opcionalmente, los nameservers del
dominio, y devuelve qué proveedor de correo y de panel DNS se pueden afirmar
con evidencia suficiente. Si no hay evidencia suficiente, devuelve `None`.
"""

from .identify import ProviderContext, ProviderMatch, identify_providers
from .nameservers import lookup_nameservers

__all__ = ["ProviderContext", "ProviderMatch", "identify_providers", "lookup_nameservers"]
