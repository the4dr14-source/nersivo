"""Configuración común de tests: hace importables los módulos de `backend/`."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(autouse=True)
def _fresh_rate_limiter():
    """
    Reinicia el estado del rate limiter de `main.app` antes de cada test.

    `app.middleware_stack` se construye de forma perezosa en la primera
    petición y esa construcción instancia `AnalyzeRateLimitMiddleware` (y con
    él su `InMemoryRateLimiter`, que es donde viven los contadores). Al poner
    la pila a `None`, la siguiente petición la reconstruye con instancias
    nuevas, así que ningún test hereda cuota consumida por otro.

    Que esto reinicia realmente los contadores se comprueba de forma explícita
    en `test_rate_limit_integration.py` (no se da por supuesto).
    """
    from backend import main

    main.app.middleware_stack = None
    yield
    main.app.middleware_stack = None
