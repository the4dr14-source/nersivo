"""Configuración común de tests: hace importables los módulos de `backend/`."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
