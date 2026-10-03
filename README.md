# Nersivo

**Nersivo** es un micro-SaaS para analizar la salud y la seguridad de un dominio:
disponibilidad web, HTTPS/certificado SSL, DNS, correo (MX), SPF y DMARC.

Este repositorio contiene el **backend** (API construida con FastAPI). En esta
primera fase, los 6 checks (web, https, dns, mx, spf, dmarc) son **reales** y el
`score` (0-100) se calcula de forma determinista a partir de sus resultados.
El contrato de la respuesta está descrito en `webguard_mvp_v1.json` (JSON Schema).

> 🔒 **Seguridad (SSRF):** las peticiones HTTP/HTTPS solo se hacen a IPs públicas
> y cada redirect se valida antes de conectar (`backend/net_safety.py`).

---

## Nota sobre SPF (`details.syntax_valid`)

En el check SPF, `syntax_valid: true` significa únicamente que se ha detectado
exactamente un registro con el formato básico `v=spf1`. **No implica una
validación completa de la sintaxis SPF** (no se parsean mecanismos,
modificadores ni el límite de 10 consultas DNS del RFC 7208). El nombre del
campo se mantiene por compatibilidad con el contrato; un parser SPF completo
queda fuera del alcance del MVP.

## Estructura de carpetas

```
Nersivo/                   # raíz del proyecto: todos los comandos se ejecutan desde aquí
├── backend/               # paquete Python `backend` (API FastAPI)
│   ├── __init__.py
│   ├── main.py            # App FastAPI y endpoints
│   ├── analyzer.py        # Orquesta los checks y calcula resumen/score
│   ├── net_safety.py      # Protección SSRF (validación de IPs y redirects)
│   ├── models.py          # Modelos Pydantic (contrato de la respuesta)
│   ├── domain_utils.py    # Validación y normalización de dominios
│   ├── requirements.txt   # Dependencias
│   ├── checks/            # Los 6 checks reales (+ tests de DMARC)
│   └── tests/             # Tests de score, SSRF, subdominios, checks y contrato
├── frontend/              # Interfaz web oscura (HTML + CSS + JS, fuentes incluidas, sin build)
├── pytest.ini             # Configuración de los tests (se ejecutan desde la raíz)
└── README.md
```

El backend es un **paquete Python**: los módulos se importan con rutas relativas
(`from .analyzer import ...`), por lo que debe arrancarse como `backend.main`
desde la raíz del proyecto (no hace falta, ni funciona, entrar en `backend/`).

---

## Instalación de dependencias

Desde la raíz del proyecto, con un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate        # En Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
```

---

## Arrancar Nersivo

Desde la raíz del proyecto, en **dos terminales**:

```bash
# 1) Backend (API en http://localhost:8000)
uvicorn backend.main:app --reload --port 8000

# 2) Frontend (interfaz en http://localhost:5500)
cd frontend
python -m http.server 5500
```

Abre `http://localhost:5500` para usar Nersivo.
La API queda en `http://localhost:8000`; su documentación interactiva (Swagger UI)
está en `http://localhost:8000/docs`.

## Ejecutar los tests

Desde la raíz del proyecto:

```bash
pytest
```

---

## Endpoints

### 1. `GET /` — Bienvenida

Comprueba que la API está activa.

```bash
curl http://localhost:8000/
```

Respuesta:

```json
{
  "message": "Nersivo API v1.0",
  "status": "running"
}
```

### 2. `GET /health` — Estado de salud

```bash
curl http://localhost:8000/health
```

Respuesta:

```json
{
  "status": "healthy",
  "timestamp": "2026-09-22T10:15:32Z"
}
```

### 3. `GET /analyze/{domain}` — Analizar un dominio

Valida el dominio y devuelve el análisis real (6 checks + score).

```bash
curl http://localhost:8000/analyze/midominio.es
```

Respuesta (resumida):

```json
{
  "domain": "midominio.es",
  "analyzed_at": "2026-09-22T10:15:32Z",
  "global_status": "error",
  "score": 72,
  "summary": {
    "headline": "Se han detectado problemas que conviene revisar.",
    "total_checks": 6,
    "passed": 4,
    "warnings": 1,
    "errors": 1,
    "unknown": 0
  },
  "checks": {
    "web": { "...": "..." },
    "https": { "...": "..." },
    "dns": { "...": "..." },
    "mx": { "...": "..." },
    "spf": { "...": "..." },
    "dmarc": { "...": "..." }
  }
}
```

Si el dominio no es válido (una IP, una URL con esquema, etc.), la API responde
con un **error 400** y el detalle del motivo:

```bash
curl http://localhost:8000/analyze/127.0.0.1
```

```json
{
  "detail": "Las direcciones IP no están permitidas. Introduce un nombre de dominio, por ejemplo 'midominio.es'."
}
```
