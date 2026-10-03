"""
Punto de entrada de la API de Nersivo (FastAPI).

Expone tres endpoints:
- GET /                  -> mensaje de bienvenida.
- GET /health            -> estado de salud del servicio.
- GET /analyze/{domain}  -> analiza un dominio y devuelve el resultado.

CORS está habilitado para permitir el consumo desde un futuro frontend.
"""

from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import analyze_domain
from .domain_utils import validate_and_normalize_domain
from .models import AnalyzeResponse

app = FastAPI(
    title="Nersivo API",
    description="API para analizar la salud y seguridad de dominios.",
    version="1.0",
)

# --- CORS -----------------------------------------------------------------
# Habilitado de forma permisiva para facilitar el desarrollo del frontend.
# TODO: restringir `allow_origins` a los orígenes concretos en producción.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
