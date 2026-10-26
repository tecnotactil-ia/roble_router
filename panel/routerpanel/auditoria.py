"""Registro de auditoría propio del panel (distinto del oplog de routerd).

Cada intento de cambio (incluso los rechazados por validación) se anota aquí
con usuario, IP, acción y resultado.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def ruta_audit() -> str:
    return os.environ.get("PANEL_AUDIT", "/var/log/router-panel/audit.log")


def registrar(usuario: str, ip: str, accion: str, resultado: str, detalle: str = "") -> None:
    ruta = ruta_audit()
    try:
        os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
        linea = {
            "fecha": datetime.now(timezone.utc).isoformat(),
            "usuario": usuario,
            "ip": ip,
            "accion": accion,
            "resultado": resultado,
            "detalle": detalle,
        }
        with open(ruta, "a", encoding="utf-8") as f:
            f.write(json.dumps(linea, ensure_ascii=False) + "\n")
    except OSError:
        # La auditoría nunca debe romper la petición del usuario.
        pass
