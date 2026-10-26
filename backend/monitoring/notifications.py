"""
Punto de extensión de notificaciones.

Flujo previsto: cambio detectado -> evento persistido -> `Notifier.notify`.
En esta fase solo existe `NullNotifier` (no envía nada, no cuesta nada, no
requiere proveedor de correo). Los eventos se guardan con `notified_at = NULL`,
de modo que un futuro notificador (correo, webhook...) puede procesarlos sin
cambiar el resto del código.
"""

from typing import List, Protocol

from .repository import EventRecord, MonitorRecord


class Notifier(Protocol):
    """Interfaz que debe cumplir un notificador."""

    def notify(self, monitor: MonitorRecord, events: List[EventRecord]) -> None:
        """Avisa de los eventos nuevos. No debe lanzar excepciones al llamador."""


class NullNotifier:
    """Notificador por defecto: no hace nada."""

    def notify(self, monitor: MonitorRecord, events: List[EventRecord]) -> None:
        return None
