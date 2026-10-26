"""Decoradores de autenticación y autorización para las vistas del panel."""
from __future__ import annotations

import functools

from flask import abort, flash, redirect, request, session, url_for

from . import usuarios as usuarios_mod


def usuario_actual() -> dict | None:
    """Devuelve el usuario de la sesión actual, o `None` si no hay sesión o
    si ésta ha quedado revocada.

    Una sesión se considera revocada (y se cierra en el momento) si el
    usuario ya no existe, si cambió de rol, o si su `version_sesion` ya no
    coincide con la que se guardó en la sesión al iniciar sesión (lo que
    ocurre, por ejemplo, tras un cambio de contraseña: así se cierran todas
    las sesiones del usuario, no sólo la que hizo el cambio).
    """
    if "usuario" not in session or "rol" not in session:
        return None

    usuario = usuarios_mod.obtener_usuario(session["usuario"])
    if (
        usuario is None
        or usuario.rol != session.get("rol")
        or usuario.version_sesion != session.get("version_sesion")
    ):
        session.clear()
        return None

    return {"login": usuario.login, "rol": usuario.rol}


def login_requerido(vista):
    @functools.wraps(vista)
    def envoltura(*args, **kwargs):
        if usuario_actual() is None:
            return redirect(url_for("auth.login", next=request.path))
        return vista(*args, **kwargs)

    return envoltura


def rol_requerido(*roles):
    def decorador(vista):
        @functools.wraps(vista)
        def envoltura(*args, **kwargs):
            usuario = usuario_actual()
            if usuario is None:
                return redirect(url_for("auth.login", next=request.path))
            if usuario["rol"] not in roles:
                abort(403)
            return vista(*args, **kwargs)

        return envoltura

    return decorador
