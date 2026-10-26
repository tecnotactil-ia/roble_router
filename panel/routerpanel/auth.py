from __future__ import annotations

from urllib.parse import urlsplit

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from . import auditoria, usuarios
from .seguridad import usuario_actual

bp = Blueprint("auth", __name__)


def _destino_seguro(valor: str | None) -> str:
    """Sólo acepta como destino de redirección rutas relativas propias del
    panel: deben empezar por "/", y no por "//" ni "/\\" (ambos los
    interpretan algunos navegadores como un salto a otro host), y no deben
    llevar esquema ni netloc (`https://evil.com`, `//evil.com`). Cualquier
    otro valor se descarta en favor del dashboard, para evitar una
    redirección abierta vía el parámetro `next`."""
    destino = url_for("dashboard.index")
    if not valor:
        return destino
    if not valor.startswith("/") or valor.startswith("//") or valor.startswith("/\\"):
        return destino
    partes = urlsplit(valor)
    if partes.scheme or partes.netloc:
        return destino
    return valor


@bp.route("/login", methods=["GET", "POST"])
def login():
    if usuario_actual() is not None:
        return redirect(url_for("dashboard.index"))

    siguiente = _destino_seguro(request.args.get("next"))

    if request.method == "POST":
        login_usuario = (request.form.get("usuario") or "").strip()
        password = request.form.get("password") or ""
        ip = request.remote_addr or "desconocida"
        control = current_app.extensions["control_fuerza_bruta"]

        bloqueado, restante = control.bloqueado(ip, login_usuario)
        if bloqueado:
            minutos = max(1, int(restante // 60) + 1)
            flash(f"Demasiados intentos fallidos. Inténtalo de nuevo en unos {minutos} minuto(s).", "error")
            auditoria.registrar(login_usuario, ip, "login", "bloqueado")
            return render_template("login.html", siguiente=siguiente)

        usuario = usuarios.obtener_usuario(login_usuario)
        if usuario is not None and usuario.verificar(password):
            control.registrar_exito(ip, login_usuario)
            session.clear()
            session.permanent = True
            session["usuario"] = usuario.login
            session["rol"] = usuario.rol
            session["version_sesion"] = usuario.version_sesion
            auditoria.registrar(login_usuario, ip, "login", "ok")
            return redirect(siguiente)

        if usuario is None:
            # Usuario inexistente: se comprueba igualmente contra un hash
            # ficticio para que el tiempo de respuesta no permita enumerar
            # usuarios por temporización.
            usuarios.verificar_ficticio(password)

        control.registrar_fallo(ip, login_usuario)
        auditoria.registrar(login_usuario, ip, "login", "error", "credenciales inválidas")
        flash("Usuario o contraseña incorrectos.", "error")

    return render_template("login.html", siguiente=siguiente)


@bp.route("/logout", methods=["POST"])
def logout():
    usuario = usuario_actual()
    if usuario is not None:
        auditoria.registrar(usuario["login"], request.remote_addr or "desconocida", "logout", "ok")
    session.clear()
    return redirect(url_for("auth.login"))
