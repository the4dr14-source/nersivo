# Nersivo

**Nersivo** es un micro-SaaS para analizar la salud y la seguridad de un dominio:
disponibilidad web, HTTPS/certificado SSL, DNS, correo (MX), SPF y DMARC.

Este repositorio contiene el **backend** (API construida con FastAPI). En esta
primera fase, los 6 checks (web, https, dns, mx, spf, dmarc) son **reales** y el
`score` (0-100) se calcula de forma determinista a partir de sus resultados.
El contrato de la respuesta estÃ¡ descrito en `nersivo_mvp_v1.json` (JSON Schema).

> ðŸ”’ **Seguridad (SSRF):** las peticiones HTTP/HTTPS solo se hacen a IPs pÃºblicas
> y cada redirect se valida antes de conectar (`backend/net_safety.py`).

---

## Nota sobre SPF (`details.syntax_valid`)

En el check SPF, `syntax_valid: true` significa Ãºnicamente que se ha detectado
exactamente un registro con el formato bÃ¡sico `v=spf1`. **No implica una
validaciÃ³n completa de la sintaxis SPF** (no se parsean mecanismos,
modificadores ni el lÃ­mite de 10 consultas DNS del RFC 7208). El nombre del
campo se mantiene por compatibilidad con el contrato; un parser SPF completo
queda fuera del alcance del MVP.

## Estructura de carpetas

```
Nersivo/                   # raÃ­z del proyecto: todos los comandos se ejecutan desde aquÃ­
â”œâ”€â”€ backend/               # paquete Python `backend` (API FastAPI)
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ main.py            # App FastAPI y endpoints
â”‚   â”œâ”€â”€ analyzer.py        # Orquesta los checks y calcula resumen/score
â”‚   â”œâ”€â”€ net_safety.py      # ProtecciÃ³n SSRF (validaciÃ³n de IPs y redirects)
â”‚   â”œâ”€â”€ models.py          # Modelos Pydantic (contrato de la respuesta)
â”‚   â”œâ”€â”€ domain_utils.py    # ValidaciÃ³n y normalizaciÃ³n de dominios
â”‚   â”œâ”€â”€ requirements.txt   # Dependencias
â”‚   â”œâ”€â”€ checks/            # Los 6 checks reales (+ tests de DMARC)
â”‚   â””â”€â”€ tests/             # Tests de score, SSRF, subdominios, checks y contrato
â”œâ”€â”€ frontend/              # Interfaz web oscura (HTML + CSS + JS, fuentes incluidas, sin build)
â”œâ”€â”€ pytest.ini             # ConfiguraciÃ³n de los tests (se ejecutan desde la raÃ­z)
â””â”€â”€ README.md
```

El backend es un **paquete Python**: los mÃ³dulos se importan con rutas relativas
(`from .analyzer import ...`), por lo que debe arrancarse como `backend.main`
desde la raÃ­z del proyecto (no hace falta, ni funciona, entrar en `backend/`).

---

## InstalaciÃ³n de dependencias

Desde la raÃ­z del proyecto, con un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate        # En Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
```

---

## Arrancar Nersivo

Desde la raÃ­z del proyecto, en **dos terminales**:

```bash
# 1) Backend (API en http://localhost:8000)
uvicorn backend.main:app --reload --port 8000

# 2) Frontend (interfaz en http://localhost:5500)
cd frontend
python -m http.server 5500
```

Abre `http://localhost:5500` para usar Nersivo.
La API queda en `http://localhost:8000`; su documentaciÃ³n interactiva (Swagger UI)
estÃ¡ en `http://localhost:8000/docs`.

## Ejecutar los tests

Desde la raÃ­z del proyecto:

```bash
pytest
```

---

## Endpoints

### 1. `GET /` â€” Bienvenida

Comprueba que la API estÃ¡ activa.

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

### 2. `GET /health` â€” Estado de salud

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

### 3. `GET /analyze/{domain}` â€” Analizar un dominio

Valida el dominio y devuelve el anÃ¡lisis real (6 checks + score).

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

Si el dominio no es vÃ¡lido (una IP, una URL con esquema, etc.), la API responde
con un **error 400** y el detalle del motivo:

```bash
curl http://localhost:8000/analyze/127.0.0.1
```

```json
{
  "detail": "Las direcciones IP no estÃ¡n permitidas. Introduce un nombre de dominio, por ejemplo 'midominio.es'."
}
```
