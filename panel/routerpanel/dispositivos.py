from __future__ import annotations

import ipaddress
import re

from flask import Blueprint, flash, redirect, render_template, request, url_for

from . import auditoria, buzon, estado as estado_mod, validacion
from .formularios import EtiquetarForm, ReservaAgregarForm, ReservaEliminarForm
from .seguridad import login_requerido, rol_requerido, usuario_actual

bp = Blueprint("dispositivos", __name__)

# Dispositivos cuya MAC empieza por este prefijo son CT/VM del Proxmox
# (OUI asignado a Proxmox Server Solutions): se muestran con icono de
# servidor en vez del icono genérico. Esto es puramente de presentación,
# no afecta a ningún dato que se envíe a routerd.
_PREFIJO_MAC_PROXMOX = "bc:24:11"

_RE_NO_VALIDO_RESERVA = re.compile(r"[^a-z0-9-]+")
_RE_GUIONES_REPETIDOS = re.compile(r"-{2,}")


def _tipo_dispositivo(mac: str) -> dict:
    if mac.lower().startswith(_PREFIJO_MAC_PROXMOX):
        return {"tipo": "servidor", "icono": "bi-hdd-rack"}
    return {"tipo": "generico", "icono": "bi-laptop"}


def _sugerir_nombre_reserva(nombre: str, mac: str) -> str:
    """Propone un nombre de reserva válido ([a-z0-9-]{1,40}) a partir del
    hostname del dispositivo, para precargar el modal de «Reservar»."""
    base = (nombre or "").strip().lower()
    base = _RE_NO_VALIDO_RESERVA.sub("-", base)
    base = _RE_GUIONES_REPETIDOS.sub("-", base).strip("-")
    if not base:
        sufijo = mac.replace(":", "")[-6:] or "nuevo"
        base = f"equipo-{sufijo}"
    return base[:40]


def _clave_orden(d: dict) -> tuple:
    """Conectados primero; dentro de cada grupo, por IP numérica (no por
    orden lexicográfico de texto, que ordenaría mal p. ej. .10 antes que
    .101 pero después de .2)."""
    conectado = 0 if d["estado"] == "Conectado" else 1
    try:
        ip_num = int(ipaddress.ip_address(d["ip"])) if d["ip"] else -1
    except ValueError:
        ip_num = -1
    return (conectado, ip_num)


@bp.route("/dispositivos")
@login_requerido
def index():
    est = estado_mod.leer_estado()
    leases, error_leases = estado_mod.leer_leases()
    dispositivos = estado_mod.construir_dispositivos(est, leases)

    for d in dispositivos:
        d.update(_tipo_dispositivo(d["mac"]))
        d["sugerencia_reserva"] = _sugerir_nombre_reserva(d["nombre"], d["mac"])
        d["estado_filtro"] = "conectado" if d["estado"] == "Conectado" else "inactivo"
        d["busqueda"] = " ".join(
            filter(None, [d["nombre"], d["ip"], d["mac"], d["etiqueta"]])
        ).lower()

    dispositivos.sort(key=_clave_orden)

    resumen = {
        "total": len(dispositivos),
        "conectados": sum(1 for d in dispositivos if d["estado"] == "Conectado"),
        "reservados": sum(1 for d in dispositivos if d["reserva"]),
    }

    form_etiqueta = EtiquetarForm()
    form_reserva = ReservaAgregarForm()
    form_eliminar = ReservaEliminarForm()
    return render_template(
        "dispositivos.html",
        dispositivos=dispositivos,
        resumen=resumen,
        error_leases=error_leases,
        form_etiqueta=form_etiqueta,
        form_reserva=form_reserva,
        form_eliminar=form_eliminar,
    )


def _responder(usuario, ip, accion, respuesta):
    categoria = "ok" if respuesta.estado == "ok" else ("warning" if respuesta.estado == "pendiente" else "error")
    flash(respuesta.mensaje, categoria)
    auditoria.registrar(usuario["login"], ip, accion, respuesta.estado, respuesta.mensaje)


@bp.route("/dispositivos/etiquetar", methods=["POST"])
@rol_requerido("admin")
def etiquetar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = EtiquetarForm()
    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "dispositivo_etiquetar", "error", "formulario inválido")
        return redirect(url_for("dispositivos.index"))

    datos = {"mac": form.mac.data, "etiqueta": form.etiqueta.data or ""}
    try:
        datos_validos = validacion.validar_peticion("dispositivo_etiquetar", datos)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "dispositivo_etiquetar", "error", str(exc))
        return redirect(url_for("dispositivos.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "dispositivo_etiquetar", datos_validos)
    _responder(usuario, ip, "dispositivo_etiquetar", respuesta)
    return redirect(url_for("dispositivos.index"))


@bp.route("/dispositivos/reserva/agregar", methods=["POST"])
@rol_requerido("admin")
def reserva_agregar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = ReservaAgregarForm()
    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "reserva_agregar", "error", "formulario inválido")
        return redirect(url_for("dispositivos.index"))

    datos = {"mac": form.mac.data, "ip": form.ip.data, "nombre": form.nombre.data}
    est = estado_mod.leer_estado()
    contexto = estado_mod.contexto_validacion(est)
    try:
        datos_validos = validacion.validar_peticion("reserva_agregar", datos, contexto)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "reserva_agregar", "error", str(exc))
        return redirect(url_for("dispositivos.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "reserva_agregar", datos_validos)
    _responder(usuario, ip, "reserva_agregar", respuesta)
    return redirect(url_for("dispositivos.index"))


@bp.route("/dispositivos/reserva/eliminar", methods=["POST"])
@rol_requerido("admin")
def reserva_eliminar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = ReservaEliminarForm()
    if not form.validate_on_submit():
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "reserva_eliminar", "error", "formulario inválido")
        return redirect(url_for("dispositivos.index"))

    try:
        datos_validos = validacion.validar_peticion("reserva_eliminar", {"mac": form.mac.data})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "reserva_eliminar", "error", str(exc))
        return redirect(url_for("dispositivos.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "reserva_eliminar", datos_validos)
    _responder(usuario, ip, "reserva_eliminar", respuesta)
    return redirect(url_for("dispositivos.index"))
