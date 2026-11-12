"""A2.1 (punto 1): `NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS` es una variable ESTRICTA.

* Ausente: 4.
* Entero positivo válido: el valor indicado.
* Cualquier otra cosa (`abc`, `0`, `-1`, cadena vacía, no enteros...): error
  explícito, y además DURANTE EL ARRANQUE de la aplicación, no solo al construir
  `MonitorSettings` a mano. Esto último importa porque `MonitorSettings.from_env()`
  solo se ejecuta en la primera petición a `/monitor` (`get_service`), donde un
  error acabaría convertido en un 503 que nadie asocia con la variable.

Todo es local: sin red, sin base de datos real, sin tocar producción.
"""

import os
import subprocess
import sys

import pytest

from backend.monitoring.config import MonitorSettings, validate_monitor_environment

NAME = "NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

INVALID = [
    "abc",
    "cuatro",
    "0",
    "00",
    "-1",
    "",
    "   ",
    "\n",
    "4.5",
    "4.0",
    "+4",
    "1_0",
    "0x4",
    "4e0",
    "4 5",
    "٤",  # dígito arábigo-índico: int() lo aceptaría, aquí no
    "1" + "0" * 9,  # 10 dígitos: fuera del máximo de 9
    "1" + "0" * 5000,  # cadena enorme (no debe depender de la versión de Python)
]

VALID = [("1", 1), ("2", 2), ("4", 4), ("16", 16), (" 7 ", 7), ("007", 7), ("999999999", 999_999_999)]


# ----------------------------------------------------- MonitorSettings.from_env
def test_variable_ausente_vale_4(monkeypatch):
    monkeypatch.delenv(NAME, raising=False)
    assert MonitorSettings.from_env({}).max_concurrent_activations == 4
    assert MonitorSettings.from_env().max_concurrent_activations == 4  # os.environ real
    assert MonitorSettings().max_concurrent_activations == 4


@pytest.mark.parametrize("raw,expected", VALID)
def test_entero_positivo_valido_se_respeta(raw, expected):
    assert MonitorSettings.from_env({NAME: raw}).max_concurrent_activations == expected
    validate_monitor_environment({NAME: raw})  # no lanza


@pytest.mark.parametrize("raw", INVALID)
def test_valor_invalido_es_un_error_explicito_y_nombra_la_variable(raw):
    with pytest.raises(ValueError, match=NAME):
        MonitorSettings.from_env({NAME: raw})
    with pytest.raises(ValueError, match=NAME):
        validate_monitor_environment({NAME: raw})


def test_el_mensaje_de_error_no_vuelca_valores_enormes():
    with pytest.raises(ValueError) as info:
        MonitorSettings.from_env({NAME: "1" + "0" * 5000})
    assert len(str(info.value)) < 300


def test_leer_el_entorno_real_tambien_es_estricto(monkeypatch):
    monkeypatch.setenv(NAME, "abc")
    with pytest.raises(ValueError, match=NAME):
        MonitorSettings.from_env()
    with pytest.raises(ValueError, match=NAME):
        validate_monitor_environment()


def test_las_demas_variables_de_monitorizacion_siguen_siendo_tolerantes():
    """El cambio es solo para esta variable: el resto conserva su comportamiento."""
    settings = MonitorSettings.from_env(
        {
            "NERSIVO_MONITOR_MAX_ACTIVE": "abc",  # inválida -> defecto
            "NERSIVO_MONITOR_MAX_PER_DOMAIN": "0",  # mínimo 1
            "NERSIVO_MONITOR_RUN_BATCH": "",  # vacía -> defecto
        }
    )
    assert settings.max_active == 200
    assert settings.max_per_domain == 1
    assert settings.run_batch == 10
    assert settings.max_concurrent_activations == 4


# ----------------------------------------------------------- arranque REAL de la app
def _run(code, extra_env, timeout=120):
    environ = {k: v for k, v in os.environ.items() if not k.startswith("NERSIVO_")}
    environ.update(extra_env)
    environ["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-W", "ignore", *code],
        cwd=ROOT, env=environ, capture_output=True, text=True, timeout=timeout,
    )


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "", "4.5"])
def test_importar_la_app_con_valor_invalido_falla_al_arrancar(raw):
    """`import backend.main` es lo que hace uvicorn: sin construir MonitorSettings a mano."""
    proc = _run(["-c", "import backend.main"], {NAME: raw})
    assert proc.returncode != 0, "la app arrancó con una variable inválida"
    assert "ValueError" in proc.stderr and NAME in proc.stderr


@pytest.mark.parametrize("extra", [{}, {NAME: "2"}, {NAME: " 8 "}])
def test_importar_la_app_con_variable_ausente_o_valida_arranca(extra):
    proc = _run(["-c", "import backend.main"], extra)
    assert proc.returncode == 0, proc.stderr


def test_uvicorn_real_se_niega_a_arrancar_con_valor_invalido():
    try:
        proc = _run(
            ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "0"],
            {NAME: "abc"},
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("uvicorn ARRANCÓ (siguió en marcha) con NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS=abc")
    assert proc.returncode != 0
    assert "ValueError" in proc.stderr and NAME in proc.stderr
