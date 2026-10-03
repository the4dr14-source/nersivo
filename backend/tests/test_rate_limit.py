"""Tests del rate limiting de análisis."""

from backend.rate_limit import InMemoryRateLimiter


def test_rate_limiter_permite_hasta_el_limite_y_bloquea_despues():
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)

    assert limiter.allow("client", now=100)[0] is True
    assert limiter.allow("client", now=101)[0] is True
    assert limiter.allow("client", now=102)[0] is True

    allowed, retry_after = limiter.allow("client", now=103)
    assert allowed is False
    assert retry_after == 57


def test_rate_limiter_expira_peticion_fuera_de_la_ventana():
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)

    assert limiter.allow("client", now=100)[0] is True
    assert limiter.allow("client", now=101)[0] is True
    assert limiter.allow("client", now=102)[0] is False

    allowed, retry_after = limiter.allow("client", now=160)
    assert allowed is True
    assert retry_after == 0


def test_rate_limiter_separa_clientes():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)

    assert limiter.allow("client-a", now=100)[0] is True
    assert limiter.allow("client-a", now=101)[0] is False
    assert limiter.allow("client-b", now=101)[0] is True
