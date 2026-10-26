from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from . import auditoria, buzon, estado as estado_mod, validacion
from .formularios import DhcpRangoForm, DnsForm, MonitorForm
from .seguridad import login_requerido, rol_requerido, usuario_actual

bp = Blueprint("configuracion", __name__)


@bp.route("/configuracion")
@login_requerido
def index():
    est = estado_mod.leer_estado()
    cfg = est.config or {}
    dhcp = cfg.get("dhcp") or {}
    dns = cfg.get("dns") or []
    monitor = cfg.get("monitor") or {}

    form_dhcp = DhcpRangoForm(inicio=dhcp.get("inicio"), fin=dhcp.get("fin"), lease=dhcp.get("lease"))
    form_dns = DnsForm(servidores=", ".join(dns))
    form_monitor = MonitorForm(
        destinos=", ".join(monitor.get("destinos") or []),
        intervalo_s=monitor.get("intervalo_s"),
        fallos_caida=monitor.get("fallos_caida"),
        exitos_alta=monitor.get("exitos_alta"),
    )

    return render_template(
        "configuracion.html",
        cfg=cfg,
        form_dhcp=form_dhcp,
        form_dns=form_dns,
        form_monitor=form_monitor,
    )


def _responder(usuario, ip, accion, respuesta):
    categoria = "ok" if respuesta.estado == "ok" else ("warning" if respuesta.estado == "pendiente" else "error")
    flash(respuesta.mensaje, categoria)
    auditoria.registrar(usuario["login"], ip, accion, respuesta.estado, respuesta.mensaje)


@bp.route("/configuracion/dhcp", methods=["POST"])
@rol_requerido("admin")
def dhcp():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = DhcpRangoForm()
    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "dhcp_rango", "error", "formulario inválido")
        return redirect(url_for("configuracion.index"))

    datos = {"inicio": form.inicio.data, "fin": form.fin.data, "lease": form.lease.data}
    est = estado_mod.leer_estado()
    contexto = estado_mod.contexto_validacion(est)
    try:
        datos_validos = validacion.validar_peticion("dhcp_rango", datos, contexto)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "dhcp_rango", "error", str(exc))
        return redirect(url_for("configuracion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "dhcp_rango", datos_validos)
    _responder(usuario, ip, "dhcp_rango", respuesta)
    return redirect(url_for("configuracion.index"))


@bp.route("/configuracion/dns", methods=["POST"])
@rol_requerido("admin")
def dns():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = DnsForm()
    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "dns", "error", "formulario inválido")
        return redirect(url_for("configuracion.index"))

    servidores = [s.strip() for s in (form.servidores.data or "").split(",") if s.strip()]
    try:
        datos_validos = validacion.validar_peticion("dns", {"servidores": servidores})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "dns", "error", str(exc))
        return redirect(url_for("configuracion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "dns", datos_validos)
    _responder(usuario, ip, "dns", respuesta)
    return redirect(url_for("configuracion.index"))


@bp.route("/configuracion/monitor", methods=["POST"])
@rol_requerido("admin")
def monitor():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = MonitorForm()
    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "monitor", "error", "formulario inválido")
        return redirect(url_for("configuracion.index"))

    destinos = [d.strip() for d in (form.destinos.data or "").split(",") if d.strip()]
    datos = {
        "destinos": destinos,
        "intervalo_s": form.intervalo_s.data,
        "fallos_caida": form.fallos_caida.data,
        "exitos_alta": form.exitos_alta.data,
    }
    try:
        datos_validos = validacion.validar_peticion("monitor", datos)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "monitor", "error", str(exc))
        return redirect(url_for("configuracion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "monitor", datos_validos)
    _responder(usuario, ip, "monitor", respuesta)
    return redirect(url_for("configuracion.index"))
