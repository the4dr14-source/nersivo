"""Tests del score determinista (analyzer._compute_score)."""

import pytest

from backend.analyzer import _compute_score
from backend.models import Checks, Status
from backend.tests.helpers import make_check

NAMES = ["web", "https", "dns", "mx", "spf", "dmarc"]
OK, WARN, ERR, UNK = Status.OK, Status.WARNING, Status.ERROR, Status.UNKNOWN


def _checks(*statuses: Status) -> Checks:
    assert len(statuses) == 6
    return Checks(**{n: make_check(s) for n, s in zip(NAMES, statuses)})


# --- Casos con 6 checks evaluados ------------------------------------------
def test_6_ok_100():
    assert _compute_score(_checks(OK, OK, OK, OK, OK, OK)) == 100


def test_5_ok_1_warning_92():
    assert _compute_score(_checks(OK, OK, OK, OK, OK, WARN)) == 92


def test_5_ok_1_error_83():
    assert _compute_score(_checks(OK, OK, OK, OK, OK, ERR)) == 83


def test_4_ok_2_error_67():
    assert _compute_score(_checks(OK, OK, OK, OK, ERR, ERR)) == 67


def test_todo_error_0():
    assert _compute_score(_checks(ERR, ERR, ERR, ERR, ERR, ERR)) == 0


def test_warnings_reducen_y_errores_reducen_mas():
    ok = _compute_score(_checks(OK, OK, OK, OK, OK, OK))
    warn = _compute_score(_checks(OK, OK, OK, OK, OK, WARN))
    err = _compute_score(_checks(OK, OK, OK, OK, OK, ERR))
    assert err < warn < ok


# --- Mínimo de 3 checks evaluados ------------------------------------------
def test_6_unknown_score_null():
    assert _compute_score(_checks(UNK, UNK, UNK, UNK, UNK, UNK)) is None


def test_1_ok_5_unknown_score_null():
    assert _compute_score(_checks(OK, UNK, UNK, UNK, UNK, UNK)) is None


def test_2_ok_4_unknown_score_null():
    assert _compute_score(_checks(OK, OK, UNK, UNK, UNK, UNK)) is None


def test_3_ok_3_unknown_100():
    assert _compute_score(_checks(OK, OK, OK, UNK, UNK, UNK)) == 100


def test_2_ok_1_warning_3_unknown_83():
    assert _compute_score(_checks(OK, OK, WARN, UNK, UNK, UNK)) == 83


def test_unknown_no_penaliza_con_suficientes_evaluados():
    todos_ok = _compute_score(_checks(OK, OK, OK, OK, OK, OK))
    assert _compute_score(_checks(OK, OK, OK, OK, OK, UNK)) == todos_ok
    assert _compute_score(_checks(OK, OK, OK, OK, UNK, UNK)) == todos_ok


# --- ERROR + UNKNOWN --------------------------------------------------------
def test_error_con_unknown_menos_de_3_evaluados_null():
    assert _compute_score(_checks(ERR, UNK, UNK, UNK, UNK, UNK)) is None
    assert _compute_score(_checks(ERR, ERR, UNK, UNK, UNK, UNK)) is None
    assert _compute_score(_checks(OK, ERR, UNK, UNK, UNK, UNK)) is None


def test_error_con_unknown_3_evaluados():
    assert _compute_score(_checks(ERR, ERR, ERR, UNK, UNK, UNK)) == 0
    assert _compute_score(_checks(OK, OK, ERR, UNK, UNK, UNK)) == 67
    assert _compute_score(_checks(OK, ERR, ERR, UNK, UNK, UNK)) == 33
    assert _compute_score(_checks(OK, OK, OK, ERR, UNK, UNK)) == 75  # 3/4
    assert _compute_score(_checks(OK, WARN, ERR, UNK, UNK, UNK)) == 50


def test_mezcla_formula():
    # ok,ok,ok,warning,error,unknown -> (3 + 0.5 + 0) / 5 = 70
    assert _compute_score(_checks(OK, OK, OK, WARN, ERR, UNK)) == 70


# --- Propiedades: sin división por cero, entero 0-100 o None ----------------
ALL = [OK, WARN, ERR, UNK]


@pytest.mark.parametrize("s1", ALL)
@pytest.mark.parametrize("s2", ALL)
@pytest.mark.parametrize("s3", ALL)
@pytest.mark.parametrize("s4", ALL)
def test_exhaustivo_nunca_falla_y_respeta_el_minimo(s1, s2, s3, s4):
    for tail in [(UNK, UNK), (OK, UNK), (ERR, WARN)]:
        statuses = (s1, s2, s3, s4) + tail
        checks = _checks(*statuses)
        evaluated = sum(1 for s in statuses if s != UNK)
        score = _compute_score(checks)  # no debe lanzar ZeroDivisionError
        if evaluated < 3:
            assert score is None
        else:
            assert isinstance(score, int) and 0 <= score <= 100
        assert score == _compute_score(checks)  # determinista
