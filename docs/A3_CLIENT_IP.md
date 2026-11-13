# A3 — Identificación del cliente y rate limiting (X-Forwarded-For)

Estado del código: corregido y probado **en local**. La seguridad **en producción**
depende de una condición que solo se puede comprobar en Render (ver §5).

## 1. Qué protege

Los limitadores de `/analyze/*` (30 / 60 s) y `POST /monitor` (5 / 600 s por defecto)
usan la clave que devuelve `backend/client_ip.py::resolve_client`.

| Configuración | Clave del limitador |
|---|---|
| `NERSIVO_TRUSTED_PROXY_HOPS=0` (defecto) | Dirección TCP que ve la app (`request.client.host`) |
| `NERSIVO_TRUSTED_PROXY_HOPS=N` (1–5) | Entrada `-N` de `X-Forwarded-For`, leída de la cabecera |
| Cadena más corta que N, o entrada ilegible | Cubo constante `untrusted-proxy-chain` |
| Con `..._CIDRS` y peer TCP fuera de esas redes | Cubo constante `untrusted-peer` |

* IPv4: una clave por dirección. IPv6: una clave por **/64** (cierre A3: antes, rotar
  la parte baja de un /64 daba cuota ilimitada y llenaba la tabla del limitador).
* Se normalizan puertos, corchetes, mayúsculas, formas comprimidas e IPv4 mapeada.
* Nunca se leen `X-Real-IP`, `Forwarded`, `CF-Connecting-IP` ni `True-Client-IP`.
* Todo error de cadena falla **cerrado**: nada desactiva el limitador y el nombre del
  cubo de respaldo no depende de nada que envíe el cliente.

## 2. Configuración correcta en Render

* `NERSIVO_TRUSTED_PROXY_HOPS=3`, sin `NERSIVO_TRUSTED_PROXY_CIDRS`.
* `FORWARDED_ALLOW_IPS=*` es el valor por defecto que Render documenta para Python 3;
  con `HOPS>=1` es inocuo porque la app lee la cabecera directamente.
* `NERSIVO_LOG_CLIENT_IP_RESOLUTION=0` salvo durante la verificación de §5.
* Si algún día se define `NERSIVO_TRUSTED_PROXY_CIDRS`, `FORWARDED_ALLOW_IPS` **no** puede
  ser `*` ni solapar con esas redes (Uvicorn reescribiría el cliente y todos los usuarios
  caerían en un único cubo). Desde este cierre eso impide arrancar. Solo se ve la variable
  de entorno, no `--forwarded-allow-ips`/`--no-proxy-headers`.

## 3. Garantías (probadas en local con Uvicorn real y con tests ASGI)

Con una cadena de la longitud configurada:
1. Cambiar, rotar, rellenar, repetir en varias líneas o ensuciar la parte izquierda de
   `X-Forwarded-For` no cambia la clave ni recupera cuota.
2. Dos clientes con IP distinta no comparten cuota; los límites de `/analyze` y
   `POST /monitor` son independientes.
3. Cabeceras malformadas, vacías o de 100 KB no desactivan el limitador ni lo rompen.
4. Variantes de ruta (`%61nalyze`, `%2F`, `/monitor?x`) se cuentan igual; las que no
   enrutan (`//monitor`, `/Monitor`, `/monitor;x`) devuelven 404 sin alcanzar el handler.
5. 250 peticiones concurrentes de 25 clientes: cada uno recibe exactamente su cuota.

## 4. Límites de confianza y riesgos residuales

1. **Número de saltos no documentado por Render.** El `3` se obtuvo empíricamente. Si la
   plataforma añadiera menos entradas, la 3.ª desde la derecha la escribiría el cliente y
   podría rotarla (reproducido: 40/40 aceptadas). Si añadiera más, todos los usuarios
   compartirían un cubo (fallo cerrado y ruidoso: aviso `A3: peticion en cubo de respaldo`).
   El código no puede detectar el primer caso. Mitigación: §5 y vigilar esos avisos tras
   cualquier cambio de Render.
2. **Acceso al contenedor sin pasar por el proxy** (advertencia de arranque
   `HOPS=3 sin CIDRS`). Quien llegue así elige su clave (reproducido). No se conoce vía
   pública; el único camino plausible es la red privada de Render desde otro servicio del
   mismo workspace y región. No se definen CIDRS porque no se ha verificado ningún rango
   del proxy de entrada de Render y no se inventan.
3. IP compartida (NAT/CGNAT/oficina) comparte cuota; igual que dos usuarios en un /64.
4. Atacante con muchas IP (botnet, delegaciones IPv6 mayores que /64) multiplica su cuota.
5. Estado en memoria de un solo proceso: se reinicia con el servicio y no se comparte.
6. `HOPS=0` con `FORWARDED_ALLOW_IPS=*` sigue siendo evadible (avisa; la app no ve los flags).
7. IPv4 incrustada en 6to4/Teredo/NAT64 no se canoniza a su IPv4.

## 5. Verificación en producción (obligatoria para dar A3 por cerrada)

Reproducción local: `python backend/tests/e2e_a3_uvicorn.py` (Uvicorn real + proxy falso).
Lo siguiente solo se puede comprobar en Render. Lo ejecuta el operador; nada de esto
modifica cron-job.org.

**Preparación.** Tras desplegar el commit (Auto-Deploy desactivado: Manual Deploy), en los
logs de arranque debe verse solo el aviso conocido `A3: NERSIVO_TRUSTED_PROXY_HOPS=3 sin
NERSIVO_TRUSTED_PROXY_CIDRS` y ningún `ValueError`. Añade `NERSIVO_LOG_CLIENT_IP_RESOLUTION=1`
(Render reinicia el servicio) y obtén tu IP pública:

```powershell
$u = "https://nersivo-backend.onrender.com/analyze/no_valido!"
curl.exe -s https://api.ipify.org ; "`n"; curl.exe -s https://api64.ipify.org
```

**Peticiones** (`/analyze` devuelve 400 y cuenta para el límite de 30/60 s):

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" $u                                                        # 0 falsas
curl.exe -s -o NUL -w "%{http_code}`n" -H "X-Forwarded-For: 203.0.113.7" $u                      # 1
curl.exe -s -o NUL -w "%{http_code}`n" -H "X-Forwarded-For: 203.0.113.7, 203.0.113.8" $u         # 2
curl.exe -s -o NUL -w "%{http_code}`n" -H "X-Forwarded-For: 203.0.113.1, 203.0.113.2, 203.0.113.3, 203.0.113.4, 203.0.113.5" $u   # 5
curl.exe -s -o NUL -w "%{http_code}`n" -H "X-Forwarded-For: 203.0.113.7" -H "X-Forwarded-For: 203.0.113.8" $u   # 2 líneas
curl.exe -s -o NUL -w "%{http_code}`n" -H "X-Forwarded-For: basura" $u                           # malformada
curl.exe -s -o NUL -w "%{http_code}`n" -X POST -H "Content-Type: application/json" -d "{}" https://nersivo-backend.onrender.com/monitor   # 422, 1 sola vez
```

**Criterio** (Render → Logs, buscar `A3-diagnostico`; hay una línea por petición): en CADA línea,
`(entradas de xff) − (entradas falsas que enviaste) = 3`, la 3.ª entrada desde la derecha es
tu IP pública y `key=` es esa IP (IPv4) o tu prefijo `…::/64` (IPv6), con `source=forwarded-for`.
* Resta 2 → `HOPS` debería ser 2; con 3 el límite es evadible. **Bloqueante.**
* Resta 4 → `key` será una IP interna y todos comparten cubo (aparecen avisos
  `peticion en cubo de respaldo`). **Bloqueante** (fallo cerrado).

**Repeticiones.** Desde otra red (datos móviles), en al menos 3 momentos distintos (incluyendo
justo tras un reinicio/despliegue y tras un periodo de inactividad del plan Free) y al menos
10 peticiones en total: el resultado debe ser siempre 3. Si tu red tiene IPv6, repite con
`curl.exe -6 ...`; si no conecta, anótalo (Render no acepta IPv6 en origen y el vector /64
no existe en la práctica).

**Efecto funcional** (usa 32 de tu cuota durante 60 s):

```powershell
1..32 | ForEach-Object { curl.exe -s -o NUL -w "$_ %{http_code}`n" -H "X-Forwarded-For: 203.0.113.$_" $u }
```

Esperado: 1–30 → `400`, 31 y 32 → `429` (rotar la cabecera no ayuda).

**Acceso directo.** En el panel de Render, lista los servicios del mismo workspace y región
que puedan alcanzar `nersivo-backend` por red privada. Esperado: ninguno que ejecute
código no confiable. Anota el resultado.

**Cierre.** Vuelve a `NERSIVO_LOG_CLIENT_IP_RESOLUTION=0`. Reversión del parche: Manual Deploy
del commit anterior (`2748bc7`); este cierre no introduce variables de entorno nuevas.
