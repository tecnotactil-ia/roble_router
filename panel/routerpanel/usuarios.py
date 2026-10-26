"""Gestión de usuarios del panel.

Los usuarios se guardan en un JSON (`PANEL_USUARIOS`) con el hash de la
contraseña (scrypt, vía werkzeug.security). Dos roles: `admin` (puede
cambiar configuración) y `lectura` (sólo puede ver).

También implementa un bloqueo simple por fuerza bruta: tras 5 fallos en 15
minutos para la combinación IP+usuario, se bloquea 15 minutos. El estado del
bloqueo vive en memoria del proceso (se documenta como limitación: con varios
workers de gunicorn cada proceso lleva su propia cuenta; para un panel
doméstico de LAN es suficiente y evita depender de un almacén compartido).
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

from werkzeug.security import check_password_hash, generate_password_hash

ROLES_VALIDOS = ("admin", "lectura")

MAX_FALLOS = 5
VENTANA_FALLOS_S = 15 * 60
BLOQUEO_S = 15 * 60

# Hash scrypt ficticio (contraseña aleatoria, descartada) contra el que se
# verifica cuando el usuario no existe, para que el tiempo de respuesta del
# login no revele por temporización si un login existe o no. Se calcula una
# sola vez al importar el módulo (scrypt es deliberadamente lento).
_HASH_FICTICIO = generate_password_hash(secrets.token_hex(32), method="scrypt")


def ruta_usuarios() -> str:
    return os.environ.get("PANEL_USUARIOS", "/var/lib/router-panel/usuarios.json")


@dataclass
class Usuario:
    login: str
    rol: str
    hash_password: str
    # Se incrementa al cambiar la contraseña (o para forzar el cierre de
    # todas las sesiones de un usuario). La sesión guarda la versión vigente
    # en el momento de iniciar sesión; si no coincide con esta, la sesión se
    # considera revocada.
    version_sesion: int = 0

    def verificar(self, password: str) -> bool:
        try:
            return check_password_hash(self.hash_password, password)
        except ValueError:
            return False


def verificar_ficticio(password: str) -> None:
    """Comprueba `password` contra un hash scrypt ficticio. Se usa cuando el
    usuario de login no existe, para que el tiempo de respuesta sea
    parecido al de un usuario real y no se pueda enumerar usuarios por
    temporización."""
    try:
        check_password_hash(_HASH_FICTICIO, password)
    except ValueError:
        pass


def cargar_usuarios() -> dict[str, Usuario]:
    ruta = ruta_usuarios()
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            bruto = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(bruto, dict):
        return {}
    usuarios = {}
    for login, datos in bruto.items():
        if not isinstance(datos, dict):
            continue
        rol = datos.get("rol")
        hash_password = datos.get("hash_password")
        if rol not in ROLES_VALIDOS or not hash_password:
            continue
        version_sesion = datos.get("version_sesion", 0)
        if not isinstance(version_sesion, int):
            version_sesion = 0
        usuarios[login] = Usuario(
            login=login, rol=rol, hash_password=hash_password, version_sesion=version_sesion
        )
    return usuarios


def guardar_usuarios(usuarios: dict[str, Usuario]) -> None:
    """L4: el temporal se crea YA con permisos 0600 (os.open, no un open()
    normal seguido de chmod): con open()+chmod hay una ventana, aunque sea
    breve, en la que el fichero con los hashes de contraseña queda con los
    permisos por defecto del sistema (legible por otros) antes del chmod.
    fsync antes del rename: que un corte de luz justo después no deje el
    fichero de usuarios a medias ni pierda lo que se acababa de escribir."""
    ruta = ruta_usuarios()
    os.makedirs(os.path.dirname(ruta) or ".", exist_ok=True)
    bruto = {
        login: {"rol": u.rol, "hash_password": u.hash_password, "version_sesion": u.version_sesion}
        for login, u in usuarios.items()
    }
    temporal = ruta + ".tmp"
    try:
        os.unlink(temporal)
    except OSError:
        pass
    fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(bruto, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise
    os.rename(temporal, ruta)


def crear_usuario(login: str, password: str, rol: str) -> None:
    if rol not in ROLES_VALIDOS:
        raise ValueError("Rol inválido: debe ser 'admin' o 'lectura'.")
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres.")
    usuarios = cargar_usuarios()
    # L4: si el usuario ya existía (se está recreando, o cambiando de rol a
    # mano) version_sesion sigue subiendo desde la que tenía, en vez de
    # volver a 0 — igual que hace cambiar_password(): una sesión abierta con
    # la versión anterior queda invalidada, no vuelve a ser válida porque la
    # cuenta se haya "reiniciado" a la versión 0 otra vez.
    anterior = usuarios.get(login)
    version_sesion = anterior.version_sesion + 1 if anterior is not None else 0
    usuarios[login] = Usuario(
        login=login,
        rol=rol,
        hash_password=generate_password_hash(password, method="scrypt"),
        version_sesion=version_sesion,
    )
    guardar_usuarios(usuarios)


def obtener_usuario(login: str) -> Usuario | None:
    return cargar_usuarios().get(login)


def cambiar_password(login: str, password_actual: str, password_nueva: str) -> None:
    """Cambia la contraseña del propio usuario. Lanza ValueError (mensaje en
    español) si la actual no coincide, la nueva es demasiado corta o es
    igual que la actual.

    Incrementa `version_sesion`, lo que invalida TODAS las sesiones vigentes
    de ese usuario (no sólo la que hizo el cambio): cualquier otra sesión
    abierta en otro dispositivo deja de ser válida en la siguiente petición.
    """
    usuario = obtener_usuario(login)
    if usuario is None:
        raise ValueError("Usuario no encontrado.")
    if not usuario.verificar(password_actual):
        raise ValueError("La contraseña actual no es correcta.")
    if len(password_nueva) < 12:
        raise ValueError("La contraseña nueva debe tener al menos 12 caracteres.")
    if usuario.verificar(password_nueva):
        raise ValueError("La contraseña nueva debe ser distinta de la actual.")

    usuarios_todos = cargar_usuarios()
    usuarios_todos[login] = Usuario(
        login=login,
        rol=usuario.rol,
        hash_password=generate_password_hash(password_nueva, method="scrypt"),
        version_sesion=usuario.version_sesion + 1,
    )
    guardar_usuarios(usuarios_todos)


class ControlFuerzaBruta:
    """Bloqueo en memoria por combinación IP+usuario. Documentado como no
    compartido entre procesos: válido para un panel doméstico con un único
    proceso gunicorn de referencia (o aceptando el pequeño margen adicional
    con varios workers)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # clave -> lista de timestamps de fallos
        self._fallos: dict[str, list[float]] = {}
        # clave -> timestamp hasta el que está bloqueado
        self._bloqueos: dict[str, float] = {}

    @staticmethod
    def _clave(ip: str, login: str) -> str:
        return f"{ip}:{login}"

    def bloqueado(self, ip: str, login: str) -> tuple[bool, float]:
        clave = self._clave(ip, login)
        with self._lock:
            hasta = self._bloqueos.get(clave)
            ahora = time.time()
            if hasta and hasta > ahora:
                return True, hasta - ahora
            if hasta and hasta <= ahora:
                del self._bloqueos[clave]
                self._fallos.pop(clave, None)
            return False, 0.0

    def registrar_fallo(self, ip: str, login: str) -> None:
        clave = self._clave(ip, login)
        ahora = time.time()
        with self._lock:
            historial = [t for t in self._fallos.get(clave, []) if ahora - t < VENTANA_FALLOS_S]
            historial.append(ahora)
            self._fallos[clave] = historial
            if len(historial) >= MAX_FALLOS:
                self._bloqueos[clave] = ahora + BLOQUEO_S
                self._fallos[clave] = []

    def registrar_exito(self, ip: str, login: str) -> None:
        clave = self._clave(ip, login)
        with self._lock:
            self._fallos.pop(clave, None)
            self._bloqueos.pop(clave, None)
