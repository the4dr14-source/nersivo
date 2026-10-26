"""
Guías «Cómo solucionarlo»: capa independiente de los checks y de la
identificación de proveedores.

- `catalog.py`: texto y estructura de las guías (solo datos).
- `builder.py`: selecciona y personaliza guías (función pura).
- `routes.py`: `POST /guides`.
"""

from .builder import build_guides

__all__ = ["build_guides"]
