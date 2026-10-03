# Nersivo · Frontend (MVP)

Interfaz web de Nersivo. Es un frontend estático (HTML + CSS + JavaScript con
módulos ES): **sin build, sin `npm install` y sin dependencias**.

## Arrancar en local

Desde la carpeta raíz del proyecto, en dos terminales:

```bash
# 1) Backend (puerto 8000)
uvicorn backend.main:app --reload

# 2) Frontend (puerto 5500)
cd frontend
python -m http.server 5500
```

Abre <http://localhost:5500>. (Instalación de dependencias: ver el README de la raíz.)

## Conexión con la API

El frontend llama a `GET {API}/analyze/{dominio}`. Por defecto `{API}` es
`http://<mismo host de la página>:8000`. Para usar otra URL, define antes de
cargar `js/main.js`:

```html
<script>window.NERSIVO_API_BASE = "https://api.ejemplo.com";</script>
```

El backend ya permite CORS (`allow_origins=["*"]`; restringir en producción).

## Estructura

| Archivo | Responsabilidad |
|---|---|
| `index.html` | Estructura de la página y pantallas |
| `css/styles.css` | Estilos (responsive, sin dependencias) |
| `js/config.js` | URL de la API y tiempo máximo de espera |
| `js/api.js` | Llamada a la API y tipos de error |
| `js/validation.js` | Validación y limpieza del dominio escrito |
| `js/presenter.js` | **Capa de traducción** del JSON técnico a lenguaje de negocio (nombres, estados, textos de ayuda `?`) |
| `js/explanations.js` | Textos «Qué hemos encontrado / ¿Por qué importa? / ¿Qué puedes hacer?» según comprobación y `technical_reason` |
| `js/components.js` | Componentes DOM (tarjetas, resultado, detalle) |
| `js/dom.js` | Utilidades para crear DOM de forma segura |
| `js/icons.js` | Iconos SVG propios de las seis comprobaciones |
| `fonts/` | Fuentes alojadas en local (Space Grotesk, Inter, JetBrains Mono; licencia OFL) |
| `js/main.js` | Control de pantallas y eventos |
| `js/types.js` | Tipos (JSDoc) del contrato de la API |

Los textos que ve el usuario están en `js/presenter.js` (nombres, estados,
ayuda `?`) y `js/explanations.js` (qué hemos encontrado, por qué importa, qué
puedes hacer). Para cambiar el lenguaje no hace falta tocar el backend.

### Dos niveles de información

1. **Usuario normal:** qué hemos encontrado → por qué importa → qué puedes hacer
   (sin jerga; la sección «qué puedes hacer» desaparece cuando todo está bien).
2. **Usuario técnico:** «Ver detalles técnicos» (consola) con los datos reales
   del backend, sin modificar (`CODE`, `SEVERITY`, `details`, textos originales).

Si el backend devuelve un `technical_reason` que no conoce `explanations.js`, se
muestra el `user_message`/`summary` original del backend (nunca se inventa una causa).
Un resultado `unknown` se presenta siempre como «No se ha podido verificar», nunca
como error.

## Tema visual (Dark / Futuristic Premium)

Todo el sistema visual está en `css/styles.css` y se controla con variables CSS
al inicio del archivo (`--bg-primary`, `--surface`, `--border`, `--text-primary`,
`--accent`, `--success`, `--warning`, `--error`, `--info`...). Las fuentes se
sirven desde `fonts/`, así que la interfaz **funciona sin conexión** y no depende
de ningún CDN. Se respeta `prefers-reduced-motion`.
