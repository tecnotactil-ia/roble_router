from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from . import auditoria, buzon, estado as estado_mod, reparto, validacion
from .formularios import ModoForm, ModoPesosForm, WanActualizarForm
from .seguridad import login_requerido, rol_requerido, usuario_actual

bp = Blueprint("wan", __name__)


@bp.route("/wan")
@login_requerido
def index():
    est = estado_mod.leer_estado()
    modo_pesos = est.modo_pesos if est.modo_pesos in ("auto", "manual") else "auto"
    form_modo = ModoForm(modo=est.modo or "balanceo")
    form_modo_pesos = ModoPesosForm(modo_pesos=modo_pesos)

    wans = [
        {
            **w,
            "rx_bytes_fmt": estado_mod.formatear_bytes(w.get("rx_bytes")),
            "tx_bytes_fmt": estado_mod.formatear_bytes(w.get("tx_bytes")),
            "rx_bps_fmt": estado_mod.formatear_bitrate(w.get("rx_bps")),
            "tx_bps_fmt": estado_mod.formatear_bitrate(w.get("tx_bps")),
        }
        for w in reparto.anotar_pct_reparto(est.wans, modo_pesos, est.fase)
    ]
    return render_template(
        "wan.html",
        est=est,
        wans=wans,
        form_modo=form_modo,
        form_modo_pesos=form_modo_pesos,
        modo_pesos=modo_pesos,
    )


@bp.route("/wan/actualizar", methods=["POST"])
@rol_requerido("admin")
def actualizar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = WanActualizarForm()

    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "wan_actualizar", "error", "formulario inválido")
        return redirect(url_for("wan.index"))

    datos = {"wan": form.wan.data}
    if form.nombre.data:
        datos["nombre"] = form.nombre.data
    # BooleanField: desmarcado => False siempre (WTForms ya lo interpreta
    # así cuando el campo no llega en el POST), así que se envía siempre.
    datos["habilitada"] = bool(form.habilitada.data)
    if form.peso.data is not None and str(request.form.get("peso", "")).strip() != "":
        datos["peso"] = form.peso.data
    if form.prioridad.data is not None and str(request.form.get("prioridad", "")).strip() != "":
        datos["prioridad"] = form.prioridad.data

    est = estado_mod.leer_estado()
    contexto = estado_mod.contexto_validacion(est)

    try:
        datos_validos = validacion.validar_peticion("wan_actualizar", datos, contexto)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "wan_actualizar", "error", str(exc))
        return redirect(url_for("wan.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "wan_actualizar", datos_validos)
    categoria = "ok" if respuesta.estado == "ok" else ("warning" if respuesta.estado == "pendiente" else "error")
    flash(respuesta.mensaje, categoria)
    auditoria.registrar(usuario["login"], ip, "wan_actualizar", respuesta.estado, respuesta.mensaje)
    return redirect(url_for("wan.index"))


@bp.route("/wan/modo", methods=["POST"])
@rol_requerido("admin")
def modo():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = ModoForm()

    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "modo", "error", "formulario inválido")
        return redirect(url_for("wan.index"))

    try:
        datos_validos = validacion.validar_peticion("modo", {"modo": form.modo.data})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "modo", "error", str(exc))
        return redirect(url_for("wan.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "modo", datos_validos)
    categoria = "ok" if respuesta.estado == "ok" else ("warning" if respuesta.estado == "pendiente" else "error")
    flash(respuesta.mensaje, categoria)
    auditoria.registrar(usuario["login"], ip, "modo", respuesta.estado, respuesta.mensaje)
    return redirect(url_for("wan.index"))


@bp.route("/wan/modo_pesos", methods=["POST"])
@rol_requerido("admin")
def modo_pesos():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = ModoPesosForm()

    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "modo_pesos", "error", "formulario inválido")
        return redirect(url_for("wan.index"))

    try:
        datos_validos = validacion.validar_peticion("modo_pesos", {"modo_pesos": form.modo_pesos.data})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "modo_pesos", "error", str(exc))
        return redirect(url_for("wan.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "modo_pesos", datos_validos)
    categoria = "ok" if respuesta.estado == "ok" else ("warning" if respuesta.estado == "pendiente" else "error")
    flash(respuesta.mensaje, categoria)
    auditoria.registrar(usuario["login"], ip, "modo_pesos", respuesta.estado, respuesta.mensaje)
    return redirect(url_for("wan.index"))
