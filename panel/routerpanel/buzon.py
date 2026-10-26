"""Buzón de peticiones hacia routerd.

El panel NUNCA ejecuta comandos del sistema. Para cualquier cambio escribe
una petición JSON atómica (tmp + rename) en `ROUTER_BUZON` y espera a que
aparezca la respuesta correspondiente en `ROUTER_RESPUESTAS`, sondeando
durante un tiempo máximo (por defecto ~6 s: un worker gunicorn queda
bloqueado mientras tanto, de ahí que se sirva con `--threads 4`, worker
gthread, para no agotar la concurrencia con una sola petición lenta). Si
agota el tiempo sin respuesta no se considera un error: la petición ya se
dejó en el buzón y routerd puede aplicarla en cualquier momento.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass


def ruta_buzon() -> str:
    return os.environ.get("ROUTER_BUZON", "/var/lib/router/solicitudes")


def ruta_respuestas() -> str:
    return os.environ.get("ROUTER_RESPUESTAS", "/var/lib/router/respuestas")


@dataclass
class RespuestaPeticion:
    id: str
    estado: str  # "ok" | "error" | "pendiente"
    mensaje: str


def escribir_peticion(usuario: str, accion: str, datos: dict) -> str:
    """Escribe la petición de forma atómica (tmp + rename) y devuelve su id."""
    peticion_id = str(uuid.uuid4())
    peticion = {"id": peticion_id, "usuario": usuario, "accion": accion, "datos": datos}

    carpeta = ruta_buzon()
    os.makedirs(carpeta, exist_ok=True)
    destino = os.path.join(carpeta, f"{peticion_id}.json")
    temporal = os.path.join(carpeta, f"{peticion_id}.json.tmp")

    try:
        with open(temporal, "w", encoding="utf-8") as f:
            json.dump(peticion, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.rename(temporal, destino)
    except Exception:
        # No dejar un .tmp a medias en el buzón si algo falla a mitad de la
        # escritura (disco lleno, permisos...): se borra si llegó a crearse
        # y se relanza para que la vista lo trate como un error real.
        try:
            os.remove(temporal)
        except OSError:
            pass
        raise
    return peticion_id


def leer_respuesta(peticion_id: str) -> dict | None:
    ruta = os.path.join(ruta_respuestas(), f"{peticion_id}.json")
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError):
        return None


def esperar_respuesta(peticion_id: str, timeout_s: float = 6.0, intervalo_s: float = 0.2) -> RespuestaPeticion:
    """Sondea hasta que aparezca la respuesta o se agote el timeout."""
    inicio = time.monotonic()
    while time.monotonic() - inicio < timeout_s:
        respuesta = leer_respuesta(peticion_id)
        if respuesta is not None:
            ok = respuesta.get("ok")
            mensaje = respuesta.get("mensaje") or ("Operación realizada." if ok else "La operación falló.")
            return RespuestaPeticion(id=peticion_id, estado="ok" if ok else "error", mensaje=mensaje)
        time.sleep(intervalo_s)
    # No es un error: la petición ya quedó escrita en el buzón y routerd
    # puede procesarla en cualquier momento; sólo no hubo tiempo de verlo.
    return RespuestaPeticion(
        id=peticion_id,
        estado="pendiente",
        mensaje="Petición enviada; se aplicará en unos segundos.",
    )


def enviar_y_esperar(usuario: str, accion: str, datos: dict, timeout_s: float = 6.0) -> RespuestaPeticion:
    peticion_id = escribir_peticion(usuario, accion, datos)
    return esperar_respuesta(peticion_id, timeout_s=timeout_s)
