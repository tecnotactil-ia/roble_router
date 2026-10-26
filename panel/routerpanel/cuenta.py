"""Página «Mi cuenta»: permite a cada usuario cambiar su propia contraseña.

Nunca permite cambiar la contraseña de otro usuario: siempre actúa sobre el
login de la sesión actual. Tras un cambio correcto se invalida la sesión y
se exige volver a iniciar sesión.
"""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from . import auditoria, usuarios as usuarios_mod
from .formularios import CambiarPasswordForm
from .seguridad import login_requerido, usuario_actual

bp = Blueprint("cuenta", __name__)


@bp.route("/cuenta", methods=["GET", "POST"])
@login_requerido
def index():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = CambiarPasswordForm()

    if form.validate_on_submit():
        try:
            usuarios_mod.cambiar_password(
                usuario["login"], form.password_actual.data, form.password_nueva.data
            )
        except ValueError as exc:
            flash(str(exc), "error")
            auditoria.registrar(usuario["login"], ip, "cambiar_password", "error", str(exc))
            return render_template("cuenta.html", form=form)

        auditoria.registrar(usuario["login"], ip, "cambiar_password", "ok")
        session.clear()
        flash("Contraseña cambiada correctamente. Vuelve a iniciar sesión.", "ok")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        auditoria.registrar(usuario["login"], ip, "cambiar_password", "error", "formulario inválido")

    return render_template("cuenta.html", form=form)
