"""WAN Wi-Fi: la tarjeta Wi-Fi del router como clienta de un hotspot de
teléfono (docs/CONTRATO.md, sección `wifi`). Mismo patrón que `wan.py`: el
panel nunca toca NetworkManager, sólo valida y deja la petición en el buzón
para que routerd la ejecute."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from . import auditoria, buzon, estado as estado_mod, validacion
from .formularios import (
    WifiAgregarForm,
    WifiConectarForm,
    WifiConfigForm,
    WifiEliminarForm,
    WifiEscanearForm,
)
from .seguridad import login_requerido, rol_requerido, usuario_actual

bp = Blueprint("wifi", __name__)

# Clave de sesión donde se guarda la petición wifi_escanear en curso (ver
# `escanear()` e `_info_escaneo_pendiente()`): routerd puede tardar varios
# segundos en terminar el `nmcli --rescan`, así que el panel no se queda
# bloqueado esperando (ver docs/CONTRATO.md) sino que recuerda el id entre
# peticiones y lo consulta en cada GET siguiente.
_LLAVE_SESION_ESCANEO = "wifi_escaneo_peticion"
_ESCANEO_TIMEOUT_S = 30


def _contexto_wifi(est: estado_mod.Estado) -> dict:
    return {"wifi_bloqueadas": est.wifi.get("bloqueadas") or []}


def _wan_asociada(est: estado_mod.Estado) -> dict | None:
    """La WAN Wi-Fi aparece también en `est.wans` con id "wifi-<interfaz>"
    (ver docs/CONTRATO.md): esto busca esa entrada para enlazar a /wan."""
    interfaz = est.wifi.get("interfaz")
    if not interfaz:
        return None
    wan_id = f"wifi-{interfaz}"
    for w in est.wans:
        if w.get("id") == wan_id:
            return w
    return None


def _mensaje_pendiente_conectar(ssid: str) -> str:
    return (
        "Conectando a «%s»… puede tardar unos segundos; el estado de arriba "
        "se actualizará. Si no conecta, revisa Registro." % ssid
    )


def _mensaje_pendiente_agregar(ssid: str) -> str:
    return "Guardando «%s»…; se conectará automáticamente si está al alcance." % ssid


def _primer_error_formulario(form) -> str:
    """Primer mensaje de error de WTForms (siempre un texto fijo propio del
    validador —"Este campo es obligatorio.", "La clave no es válida."...—,
    nunca interpola el valor que escribió quien lo envió). Si por lo que sea
    no hay ninguno (p. ej. el fallo es el CSRF, que ya se corta antes de
    llegar aquí), se usa un texto genérico de repuesto."""
    for errores in form.errors.values():
        for error in errores:
            if error:
                return str(error)
    return "Formulario inválido."


def _info_escaneo_pendiente() -> bool:
    """Mira si hay una petición `wifi_escanear` en curso guardada en la
    sesión: si ya hay respuesta la consume (y avisa si falló); si no hay
    respuesta todavía y no han pasado más de `_ESCANEO_TIMEOUT_S` segundos,
    se considera "pendiente" (la plantilla añade un data-attribute para que
    `wifi.js` recargue la página sola). Devuelve True si sigue pendiente."""
    info = session.get(_LLAVE_SESION_ESCANEO)
    if not isinstance(info, dict) or not info.get("id"):
        return False

    respuesta = buzon.leer_respuesta(info["id"])
    if respuesta is not None:
        session.pop(_LLAVE_SESION_ESCANEO, None)
        if respuesta.get("ok") is False:
            mensaje = respuesta.get("mensaje") or "El escaneo de redes Wi-Fi falló."
            flash(mensaje, "error")
        return False

    try:
        enviado_en = datetime.fromisoformat(info.get("enviado_en"))
    except (TypeError, ValueError):
        session.pop(_LLAVE_SESION_ESCANEO, None)
        return False
    if enviado_en.tzinfo is None:
        enviado_en = enviado_en.replace(tzinfo=timezone.utc)

    transcurrido = (datetime.now(timezone.utc) - enviado_en).total_seconds()
    if transcurrido >= _ESCANEO_TIMEOUT_S:
        # Se agotó la espera: se deja de considerar "pendiente" (ya no se
        # promete un refresco automático) aunque routerd pudiera responder
        # más tarde; la próxima vez que se pida un escaneo se parte de cero.
        session.pop(_LLAVE_SESION_ESCANEO, None)
        return False
    return True


@bp.route("/wifi")
@login_requerido
def index():
    est = estado_mod.leer_estado()
    wifi = est.wifi
    wan_asociada = _wan_asociada(est)
    escaneo_pendiente = _info_escaneo_pendiente()

    # Prellenado del SSID desde "Usar" en redes cercanas: sólo display, nunca
    # la clave. Jinja escapa automáticamente al renderizarlo en la plantilla.
    ssid_sugerido = (request.args.get("ssid") or "")[:64]

    form_config = WifiConfigForm(habilitada="1" if wifi.get("habilitada") else "0")
    form_agregar = WifiAgregarForm(ssid=ssid_sugerido)
    form_eliminar = WifiEliminarForm()
    form_conectar = WifiConectarForm()
    form_escanear = WifiEscanearForm()

    escaneo_relativo = estado_mod.formatear_relativo(wifi.get("escaneo_ts"))

    return render_template(
        "wifi.html",
        wifi=wifi,
        wifi_ap=est.wifi_ap,
        wan_asociada=wan_asociada,
        form_config=form_config,
        form_agregar=form_agregar,
        form_eliminar=form_eliminar,
        form_conectar=form_conectar,
        form_escanear=form_escanear,
        escaneo_relativo=escaneo_relativo,
        escaneo_pendiente=escaneo_pendiente,
    )


def _responder(usuario, ip, accion, respuesta, detalle_auditoria=None):
    categoria = "ok" if respuesta.estado == "ok" else ("warning" if respuesta.estado == "pendiente" else "error")
    flash(respuesta.mensaje, categoria)
    auditoria.registrar(
        usuario["login"],
        ip,
        accion,
        respuesta.estado,
        detalle_auditoria if detalle_auditoria is not None else respuesta.mensaje,
    )


@bp.route("/wifi/config", methods=["POST"])
@rol_requerido("admin")
def config():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = WifiConfigForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "wifi_config", "error", mensaje)
        return redirect(url_for("wifi.index"))

    datos = {"habilitada": form.habilitada.data == "1"}
    try:
        datos_validos = validacion.validar_peticion("wifi_config", datos)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "wifi_config", "error", str(exc))
        return redirect(url_for("wifi.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "wifi_config", datos_validos)
    _responder(usuario, ip, "wifi_config", respuesta)
    return redirect(url_for("wifi.index"))


@bp.route("/wifi/agregar", methods=["POST"])
@rol_requerido("admin")
def agregar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = WifiAgregarForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "wifi_agregar", "error", mensaje)
        return redirect(url_for("wifi.index"))

    ssid = form.ssid.data or ""
    clave = form.clave.data or ""
    prioridad = form.prioridad.data
    if prioridad is None or str(request.form.get("prioridad", "")).strip() == "":
        prioridad = 50

    datos = {"ssid": ssid, "clave": clave, "prioridad": prioridad}

    est = estado_mod.leer_estado()
    contexto = _contexto_wifi(est)
    try:
        datos_validos = validacion.validar_peticion("wifi_agregar", datos, contexto)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        # La clave NUNCA se registra, ni siquiera en el detalle del error
        # (docs/CONTRATO.md): el mensaje de validación nunca la contiene.
        auditoria.registrar(usuario["login"], ip, "wifi_agregar", "error", str(exc))
        return redirect(url_for("wifi.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "wifi_agregar", datos_validos)
    # Redacción obligatoria: "clave" se sustituye por "***" en cualquier
    # registro (auditoría propia del panel), igual que hace routerd en el
    # oplog con _redactar_datos().
    detalle = "ssid=%r prioridad=%r clave=***" % (datos_validos["ssid"], datos_validos["prioridad"])
    if respuesta.estado == "pendiente":
        # Guardar el perfil (nmcli connection load + autoconnect) puede
        # tardar más que el sondeo del buzón: un mensaje propio, más útil
        # que "pendiente" a secas, y distinto del de "conectar" (aquí no se
        # ha pedido conectar expresamente, sólo guardar el perfil).
        flash(_mensaje_pendiente_agregar(datos_validos["ssid"]), "info")
        auditoria.registrar(usuario["login"], ip, "wifi_agregar", respuesta.estado, detalle)
    else:
        _responder(usuario, ip, "wifi_agregar", respuesta, detalle_auditoria=detalle)
    return redirect(url_for("wifi.index"))


@bp.route("/wifi/eliminar", methods=["POST"])
@rol_requerido("admin")
def eliminar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = WifiEliminarForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "wifi_eliminar", "error", mensaje)
        return redirect(url_for("wifi.index"))

    try:
        datos_validos = validacion.validar_peticion("wifi_eliminar", {"ssid": form.ssid.data})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "wifi_eliminar", "error", str(exc))
        return redirect(url_for("wifi.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "wifi_eliminar", datos_validos)
    _responder(usuario, ip, "wifi_eliminar", respuesta)
    return redirect(url_for("wifi.index"))


@bp.route("/wifi/conectar", methods=["POST"])
@rol_requerido("admin")
def conectar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = WifiConectarForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "wifi_conectar", "error", mensaje)
        return redirect(url_for("wifi.index"))

    try:
        datos_validos = validacion.validar_peticion("wifi_conectar", {"ssid": form.ssid.data})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "wifi_conectar", "error", str(exc))
        return redirect(url_for("wifi.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "wifi_conectar", datos_validos)
    if respuesta.estado == "pendiente":
        flash(_mensaje_pendiente_conectar(datos_validos["ssid"]), "info")
        auditoria.registrar(usuario["login"], ip, "wifi_conectar", respuesta.estado, datos_validos["ssid"])
    else:
        _responder(usuario, ip, "wifi_conectar", respuesta)
    return redirect(url_for("wifi.index"))


@bp.route("/wifi/escanear", methods=["POST"])
@rol_requerido("admin")
def escanear():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = WifiEscanearForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "wifi_escanear", "error", mensaje)
        return redirect(url_for("wifi.index"))

    try:
        datos_validos = validacion.validar_peticion("wifi_escanear", {})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "wifi_escanear", "error", str(exc))
        return redirect(url_for("wifi.index"))

    # A propósito NO se espera respuesta (a diferencia del resto de
    # acciones): `nmcli … --rescan yes` puede tardar varios segundos y el
    # resultado es asíncrono, queda en estado.json -> wifi.escaneo cuando
    # routerd termine. Sólo se deja la petición en el buzón; el id se
    # recuerda en la sesión para que el siguiente GET /wifi (y los que
    # vengan mientras siga "pendiente") sepan si ya hay respuesta.
    peticion_id = buzon.escribir_peticion(usuario["login"], "wifi_escanear", datos_validos)
    session[_LLAVE_SESION_ESCANEO] = {
        "id": peticion_id,
        "enviado_en": datetime.now(timezone.utc).isoformat(),
    }
    flash("Buscando redes… la página se actualizará sola en unos segundos.", "info")
    auditoria.registrar(usuario["login"], ip, "wifi_escanear", "enviado", "Escaneo solicitado")
    return redirect(url_for("wifi.index"))
