from __future__ import annotations

import os
import stat

from routerpanel import usuarios as usuarios_mod


def test_crear_usuario_nuevo_version_sesion_cero(tmp_path, monkeypatch):
    ruta = tmp_path / "usuarios.json"
    monkeypatch.setenv("PANEL_USUARIOS", str(ruta))

    usuarios_mod.crear_usuario("admin", "contrasena-larga-1", "admin")

    usuario = usuarios_mod.obtener_usuario("admin")
    assert usuario is not None
    assert usuario.version_sesion == 0


def test_crear_usuario_existente_incrementa_version_sesion(tmp_path, monkeypatch):
    """L4: recrear un usuario que ya existía (p. ej. para cambiarle el rol o
    restablecerle la contraseña a mano) no debe volver version_sesion a 0:
    eso invalidaría la protección de cambiar_password() si, por casualidad,
    alguna sesión vieja llevara guardado ese mismo número de versión."""
    ruta = tmp_path / "usuarios.json"
    monkeypatch.setenv("PANEL_USUARIOS", str(ruta))

    usuarios_mod.crear_usuario("admin", "contrasena-larga-1", "admin")
    assert usuarios_mod.obtener_usuario("admin").version_sesion == 0

    usuarios_mod.crear_usuario("admin", "otra-contrasena-larga-2", "admin")
    assert usuarios_mod.obtener_usuario("admin").version_sesion == 1

    usuarios_mod.crear_usuario("admin", "tercera-contrasena-larga-3", "lectura")
    usuario = usuarios_mod.obtener_usuario("admin")
    assert usuario.version_sesion == 2
    assert usuario.rol == "lectura"
    # La contraseña vigente es la última: las anteriores dejan de valer.
    assert usuario.verificar("tercera-contrasena-larga-3")
    assert not usuario.verificar("contrasena-larga-1")


def test_crear_usuario_no_pisa_version_sesion_de_otro_usuario(tmp_path, monkeypatch):
    ruta = tmp_path / "usuarios.json"
    monkeypatch.setenv("PANEL_USUARIOS", str(ruta))

    usuarios_mod.crear_usuario("admin", "contrasena-larga-1", "admin")
    usuarios_mod.crear_usuario("admin", "contrasena-larga-2", "admin")
    usuarios_mod.crear_usuario("lector", "contrasena-larga-3", "lectura")

    assert usuarios_mod.obtener_usuario("admin").version_sesion == 1
    assert usuarios_mod.obtener_usuario("lector").version_sesion == 0


def test_guardar_usuarios_permisos_0600(tmp_path, monkeypatch):
    """L4: el fichero de usuarios (con los hashes de contraseña) se escribe
    con permisos 0600 desde el primer momento (os.open), nunca con los
    permisos por defecto del sistema antes de un chmod posterior."""
    ruta = tmp_path / "usuarios.json"
    monkeypatch.setenv("PANEL_USUARIOS", str(ruta))

    usuarios_mod.crear_usuario("admin", "contrasena-larga-1", "admin")

    assert ruta.exists()
    permisos = stat.S_IMODE(os.stat(ruta).st_mode)
    assert permisos == 0o600
    # No debe quedar el temporal suelto.
    assert not (tmp_path / "usuarios.json.tmp").exists()


def test_guardar_usuarios_permisos_0600_tras_reescritura(tmp_path, monkeypatch):
    """El fichero sigue en 0600 aunque se reescriba varias veces (no sólo
    la primera vez que se crea)."""
    ruta = tmp_path / "usuarios.json"
    monkeypatch.setenv("PANEL_USUARIOS", str(ruta))

    usuarios_mod.crear_usuario("admin", "contrasena-larga-1", "admin")
    usuarios_mod.crear_usuario("lector", "contrasena-larga-2", "lectura")
    usuarios_mod.cambiar_password("admin", "contrasena-larga-1", "contrasena-larga-nueva-3")

    permisos = stat.S_IMODE(os.stat(ruta).st_mode)
    assert permisos == 0o600
