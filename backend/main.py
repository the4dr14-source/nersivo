"""
Punto de entrada de la API de Nersivo (FastAPI).

Endpoints propios:
- GET /                  -> mensaje de bienvenida.
- GET /health            -> estado de salud del servicio.
- GET /analyze/{domain}  -> analiza un dominio y devuelve el resultado.

Los routers de guías (`/guides`) y monitorización (`/monitor`,
`/internal/monitor/run`) se incluyen al final de este archivo.

CORS está restringido a los orígenes oficiales de Nersivo y a los entornos
locales de desarrollo. `/analyze/` y `POST /monitor` están protegidos por rate
limiters en memoria independientes (`AnalyzeRateLimitMiddleware`).
"""

from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import analyze_domain
from .guides.routes import router as guides_router
from .monitoring.config import validate_monitor_environment
from .monitoring.routes import router as monitoring_router
from .domain_utils import validate_and_normalize_domain
from .models import AnalyzeResponse
from .rate_limit import AnalyzeRateLimitMiddleware, validate_environment

app = FastAPI(
    title="Nersivo API",
    description="API para analizar la salud y seguridad de dominios.",
    version="1.0",
)

# --- Middlewares -------------------------------------------------------------
# IMPORTANTE: en Starlette el ÚLTIMO middleware añadido es el más EXTERNO.
# Por eso el rate limiter se registra primero y CORS después: CORS envuelve al
# limitador y las respuestas 429 también llevan cabeceras CORS (si no, el
# navegador no podría leer el 429 y lo mostraría como un error de red).

# Rate limiting en memoria: /analyze/ (30 peticiones / 60 s por IP) y
# POST /monitor (5 / 600 s por IP por defecto, ver rate_limit.py).
# Starlette construye los middlewares en la primera petición, no al arrancar:
# se valida la configuración aquí para que un error impida desplegar (A3, A2).
validate_environment()
# Igual para los ajustes estrictos de monitorización: `MonitorSettings.from_env()`
# solo se llama en la primera petición a /monitor, donde un error sería un 503.
validate_monitor_environment()
app.add_middleware(AnalyzeRateLimitMiddleware)

# CORS: lista explícita de orígenes (sin comodines). No se exponen cookies ni
# credenciales, y solo se permiten los métodos y cabeceras que usa el frontend.
# `X-Cron-Token` NO se permite: lo envía un cron externo, nunca un navegador.
ALLOWED_ORIGINS = [
    "https://nersivo-frontend.onrender.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Monitor-Token"],
    # Un navegador cross-origin solo puede leer `Retry-After` si se expone
    # explícitamente. Es la única cabecera de respuesta que se expone.
    expose_headers=["Retry-After"],
)


@app.get("/")
def read_root() -> dict:
    """Mensaje de bienvenida simple para comprobar que la API está activa."""
    return {"message": "Nersivo API v1.0", "status": "running"}


@app.get("/health")
def health_check() -> dict:
    """Endpoint de salud: devuelve el estado y la marca de tiempo actual."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@app.get("/analyze/{domain}", response_model=AnalyzeResponse)
def analyze(domain: str) -> AnalyzeResponse:
    """
    Analiza un dominio.

    Valida y normaliza el dominio recibido; si no es válido, responde con
    un error 400. En caso contrario, ejecuta el análisis (6 checks reales)
    y devuelve el resultado según el contrato.

    Args:
        domain: Dominio a analizar (por ejemplo 'midominio.es').

    Returns:
        AnalyzeResponse con el resultado del análisis.

    Raises:
        HTTPException: 400 si el dominio no es válido.
    """
    try:
        normalized_domain = validate_and_normalize_domain(domain)
    except ValueError as exc:
        # Dominio inválido -> 400 con el detalle del motivo.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return analyze_domain(normalized_domain)


# --- Routers adicionales (no modifican /analyze ni su contrato) ---------------
app.include_router(guides_router)
app.include_router(monitoring_router)
