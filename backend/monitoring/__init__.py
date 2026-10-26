"""
Monitorización de dominios (MVP gratuito, sin cuentas ni pagos).

- `fingerprint.py` / `diff.py`: huella estable y comparación de resultados.
- `repository.py`: persistencia portable (SQLite en desarrollo, Postgres en producción).
- `service.py`: casos de uso (activar, consultar, desactivar, ejecutar job).
- `routes.py`: endpoints HTTP.
- `notifications.py`: punto de extensión para avisos (hoy: no-op).
"""
