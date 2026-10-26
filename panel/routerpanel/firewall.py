"""Firewall con reglas propias estilo Kerio (docs/FIREWALL_PLAN.md).

Mismo patrón que `proteccion.py`/`wifi.py`: el panel nunca toca nftables ni
ejecuta comandos, sólo valida y deja la petición `fw_*` en el buzón para que
routerd la aplique de verdad (con su propia validación campo a campo). Cada
petición lleva la `firewall.version` vista al pintar la página: si el núcleo
detecta que la configuración cambió mientras se editaba, rechaza la petición
ENTERA con «La configuración cambió mientras editabas; recarga la página»
(concurrencia optimista, igual que `bloqueo_config`).

`config.firewall` (estado.json) lo publica routerd como copia de la sección
firewall de router.json más `firewall_error` y `firewall_aciertos` (contadores
por regla). Se lee SIEMPRE a través de `estado.normalizar_firewall`: tipos
raros de un routerd viejo o un estado.json corrupto nunca deben romper la
página.
"""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for

from . import auditoria, buzon, estado as estado_mod, validacion
from .formularios import (
    FwGrupoEliminarForm,
    FwGrupoForm,
    FwReglaAccionForm,
    FwReglaForm,
)
from .seguridad import login_requerido, rol_requerido, usuario_actual

bp = Blueprint("firewall", __name__)

# Plantillas de ejemplo (FIREWALL_PLAN.md): rellenan el formulario de regla
# con parámetros GET. Sólo preseleccionan la forma; el usuario sigue teniendo
# que elegir el dispositivo/puerto concreto y darle a «Guardar».
EJEMPLOS_REGLA = {
    "bloquear_dispositivo": {
        "titulo": "Bloquear un dispositivo",
        "descripcion": "Corta el Internet de un dispositivo concreto de la casa.",
        "parametros": {
            "nombre": "Bloquear un dispositivo",
            "accion": "bloquear",
            "origen_tipo": "mac",
            "destino_tipo": "cualquiera",
            "protocolo": "cualquiera",
            "puertos": "",
        },
    },
    "bloquear_puerto": {
        "titulo": "Bloquear un puerto para todos",
        "descripcion": "Cierra un puerto hacia Internet para toda la LAN.",
        "parametros": {
            "nombre": "Bloquear un puerto",
            "accion": "bloquear",
            "origen_tipo": "cualquiera",
            "destino_tipo": "cualquiera",
            "protocolo": "tcp",
            "puertos": "443",
        },
    },
}

# Columnas de presentación de un endpoint (origen/destino) en la tabla.
_ETIQUETAS_ENDPOINT = {
    "cualquiera": "Cualquiera",
    "mac": "MAC",
    "ip": "IP",
    "red": "Red",
    "grupo": "Grupo",
}


def _clasificar_linea(linea: str) -> str:
    despojada = linea.strip()
    if despojada.startswith("table "):
        return "tt-fw-tabla"
    if despojada.startswith("chain ") or despojada.startswith("}") and "chain" in linea:
        return "tt-fw-cadena"
    if despojada.startswith("chain"):
        return "tt-fw-cadena"
    if "accept" in despojada:
        return "tt-fw-accept"
    if "drop" in despojada or "reject" in despojada:
        return "tt-fw-drop"
    return "tt-fw-normal"


def _formatear_endpoint(ep: dict, grupos_por_id: dict) -> str:
    """Texto de una celda origen/destino: «Cualquiera», «MAC aa:bb:…»,
    «192.168.50.50», «10.0.0.0/8» o el nombre del grupo referenciado."""
    tipo = ep.get("tipo", "cualquiera")
    if tipo == "cualquiera":
        return "Cualquiera"
    valor = ep.get("valor") or ""
    if tipo == "grupo":
        grupo = grupos_por_id.get(valor)
        return grupo["nombre"] if grupo else valor
    etiqueta = _ETIQUETAS_ENDPOINT.get(tipo, tipo)
    return "%s %s" % (etiqueta, valor) if valor else etiqueta


def _formatear_servicio(regla: dict) -> str:
    """«tcp/443», «udp/53, 80-90», «icmp» o «Cualquiera»."""
    protocolo = regla.get("protocolo", "cualquiera")
    puertos = regla.get("puertos") or []
    if protocolo == "cualquiera" and not puertos:
        return "Cualquiera"
    if not puertos:
        return protocolo
    trozos = []
    for rango in puertos:
        desde, hasta = rango.get("desde"), rango.get("hasta")
        if desde == hasta:
            trozos.append(str(desde))
        else:
            trozos.append("%s-%s" % (desde, hasta))
    return "%s/%s" % (protocolo, ", ".join(trozos))


def _filas_reglas(fw: dict) -> list[dict]:
    """Una fila de tabla por regla, con el texto ya formateado para la
    plantilla (nº, nombre, origen, destino, servicio, acción, hits…)."""
    grupos_por_id = {g["id"]: g for g in fw["grupos"]}
    aciertos = fw["firewall_aciertos"]
    filas = []
    for indice, regla in enumerate(fw["reglas"]):
        filas.append(
            {
                "indice": indice,
                "numero": indice + 1,
                "id": regla["id"],
                "nombre": regla["nombre"],
                "habilitada": regla["habilitada"],
                "accion": regla["accion"],
                "origen": _formatear_endpoint(regla["origen"], grupos_por_id),
                "destino": _formatear_endpoint(regla["destino"], grupos_por_id),
                "servicio": _formatear_servicio(regla),
                "registrar": regla["registrar"],
                "comentario": regla["comentario"],
                "aciertos": aciertos.get(regla["id"]),
            }
        )
    return filas


def _dispositivos_para_selector() -> list[dict]:
    """Dispositivos conocidos (leases + reservas + vecinos) para el selector
    de origen de una regla y de miembros de un grupo: nombre + MAC + IP."""
    est = estado_mod.leer_estado()
    leases, _ = estado_mod.leer_leases()
    dispositivos = estado_mod.construir_dispositivos(est, leases)
    return [
        {"mac": d["mac"], "ip": d["ip"], "nombre": d["nombre"]}
        for d in dispositivos
        if d.get("mac")
    ]


def _contexto_fw() -> dict:
    """Config de firewall normalizada + estado crudo de la página."""
    est = estado_mod.leer_estado()
    fw = estado_mod.normalizar_firewall((est.config or {}).get("firewall"))
    fw_disponible = isinstance((est.config or {}).get("firewall"), dict)
    return {"fw": fw, "fw_disponible": fw_disponible}


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


def _primer_error_formulario(form) -> str:
    for errores in form.errors.values():
        for error in errores:
            if error:
                return str(error)
    return "Formulario inválido."


def _version_actual() -> int:
    return _contexto_fw()["fw"]["version"]


def _puntos_formulario(form) -> tuple[dict, dict]:
    """Compone `origen` y `destino` a partir de los campos del formulario.
    El selector de dispositivos (`origen_dispositivo`) manda sobre el valor
    escrito a mano cuando el origen es un MAC; si no, se usa el texto."""
    tipo_o = form.origen_tipo.data
    if tipo_o == "cualquiera":
        origen = {"tipo": "cualquiera"}
    elif tipo_o == "grupo":
        origen = {"tipo": "grupo", "valor": (form.origen_grupo.data or "").strip()}
    elif tipo_o == "mac":
        valor = (form.origen_dispositivo.data or "").strip() or (form.origen_valor.data or "").strip()
        origen = {"tipo": "mac", "valor": valor}
    else:  # ip | red
        origen = {"tipo": tipo_o, "valor": (form.origen_valor.data or "").strip()}

    tipo_d = form.destino_tipo.data
    if tipo_d == "cualquiera":
        destino = {"tipo": "cualquiera"}
    elif tipo_d == "grupo":
        destino = {"tipo": "grupo", "valor": (form.destino_grupo.data or "").strip()}
    else:  # ip | red
        destino = {"tipo": tipo_d, "valor": (form.destino_valor.data or "").strip()}
    return origen, destino


def _parsear_puertos(texto: str) -> list:
    """«443, 8000-8100» → `[{"desde": 443, "hasta": 443}, {"desde": 8000, "hasta": 8100}]`.
    Vacío → `[]`. La validación fina la hace `validacion.validar_fw_regla_guardar`."""
    texto = (texto or "").strip()
    if not texto:
        return []
    rangos = []
    for trozo in texto.split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        if "-" in trozo:
            desde_s, hasta_s = trozo.split("-", 1)
        else:
            desde_s = hasta_s = trozo
        try:
            rangos.append({"desde": int(desde_s.strip()), "hasta": int(hasta_s.strip())})
        except ValueError:
            rangos.append({"desde": -1, "hasta": -1})  # validacion.py lo rechazará
    return rangos


def _regla_desde_formulario(form, es_edicion: bool) -> dict:
    origen, destino = _puntos_formulario(form)
    regla = {
        "nombre": (form.nombre.data or "").strip(),
        "habilitada": bool(form.habilitada.data),
        "accion": form.accion.data,
        "origen": origen,
        "destino": destino,
        "protocolo": form.protocolo.data,
        "puertos": _parsear_puertos(form.puertos.data),
        "registrar": bool(form.registrar.data),
        "comentario": (form.comentario.data or "").strip(),
    }
    if es_edicion:
        regla["id"] = form.regla_id.data
    return regla


def _datos_regla_iniciales(regla: dict | None, ejemplo: str | None) -> dict:
    """Rellena el formulario al editar una regla existente o al aplicar una
    plantilla de ejemplo vía GET. Sólo campos presentes (nunca inventa).
    Una regla NUEVA nace activada (modelo del plan `habilitada: true`):
    si llegara apagada, las plantillas de ejemplo se guardarían inertes."""
    datos: dict = {"habilitada": True}
    if regla is not None:
        origen, destino = regla.get("origen") or {}, regla.get("destino") or {}
        datos.update(
            {
                "regla_id": regla.get("id"),
                "nombre": regla.get("nombre"),
                "habilitada": regla.get("habilitada", True),
                "accion": regla.get("accion"),
                "origen_tipo": origen.get("tipo", "cualquiera"),
                "destino_tipo": destino.get("tipo", "cualquiera"),
                "protocolo": regla.get("protocolo", "cualquiera"),
                "registrar": regla.get("registrar", False),
                "comentario": regla.get("comentario", ""),
            }
        )
        if origen.get("tipo") == "mac":
            datos["origen_valor"] = origen.get("valor", "")
        elif origen.get("tipo") in ("ip", "red"):
            datos["origen_valor"] = origen.get("valor", "")
        elif origen.get("tipo") == "grupo":
            datos["origen_grupo"] = origen.get("valor", "")
        if destino.get("tipo") in ("ip", "red"):
            datos["destino_valor"] = destino.get("valor", "")
        elif destino.get("tipo") == "grupo":
            datos["destino_grupo"] = destino.get("valor", "")
        puertos = regla.get("puertos") or []
        trozos = [
            str(r["desde"]) if r.get("desde") == r.get("hasta") else "%s-%s" % (r.get("desde"), r.get("hasta"))
            for r in puertos
        ]
        datos["puertos"] = ", ".join(trozos)
    if ejemplo:
        plantilla = EJEMPLOS_REGLA.get(ejemplo)
        if plantilla:
            datos.update(plantilla["parametros"])
    return datos


def _contexto_regla(form, regla_id: str | None, ejemplo: str | None) -> dict:
    contexto = _contexto_fw()
    grupos = contexto["fw"]["grupos"]
    return {
        **contexto,
        "form": form,
        "regla_id": regla_id,
        "es_edicion": regla_id is not None,
        "ejemplo": ejemplo,
        "ejemplo_info": EJEMPLOS_REGLA.get(ejemplo or ""),
        "ejemplos": EJEMPLOS_REGLA,
        "grupos": grupos,
        "dispositivos": _dispositivos_para_selector(),
    }


@bp.route("/firewall")
@login_requerido
def index():
    contenido, error = estado_mod.leer_firewall()
    lineas = []
    if contenido:
        for linea in contenido.splitlines():
            lineas.append({"texto": linea, "clase": _clasificar_linea(linea)})
    contexto = _contexto_fw()
    fw = contexto["fw"]
    es_admin = (usuario_actual() or {}).get("rol") == "admin"
    return render_template(
        "firewall.html",
        lineas=lineas,
        error=error,
        n_lineas=len(lineas),
        fw=fw,
        fw_disponible=contexto["fw_disponible"],
        filas=_filas_reglas(fw),
        es_admin=es_admin,
        ejemplos=EJEMPLOS_REGLA,
    )


@bp.route("/firewall/regla/nueva")
@rol_requerido("admin")
def regla_nueva():
    ejemplo = request.args.get("ejemplo") or None
    datos = _datos_regla_iniciales(None, ejemplo)
    # También se admiten parámetros GET sueltos (más flexibles que las
    # plantillas de ejemplo): /firewall/regla/nueva?accion=bloquear&...
    for campo in (
        "nombre", "accion", "origen_tipo", "origen_valor", "origen_grupo",
        "destino_tipo", "destino_valor", "destino_grupo", "protocolo",
        "puertos", "comentario",
    ):
        if campo in request.args and campo not in datos:
            datos[campo] = request.args.get(campo)
    form = FwReglaForm(data=datos)
    form.version.data = str(_version_actual())
    return render_template("firewall_regla.html", **_contexto_regla(form, None, ejemplo))


@bp.route("/firewall/regla/<regla_id>")
@rol_requerido("admin")
def regla_editar(regla_id):
    contexto = _contexto_fw()
    regla = next((r for r in contexto["fw"]["reglas"] if r["id"] == regla_id), None)
    if regla is None:
        flash("No existe ninguna regla con esa id.", "error")
        return redirect(url_for("firewall.index"))
    form = FwReglaForm(data=_datos_regla_iniciales(regla, None))
    form.version.data = str(contexto["fw"]["version"])
    return render_template("firewall_regla.html", **_contexto_regla(form, regla_id, None))


@bp.route("/firewall/regla/guardar", methods=["POST"])
@rol_requerido("admin")
def regla_guardar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = FwReglaForm()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_guardar", "error", mensaje)
        return redirect(url_for("firewall.index"))

    es_edicion = bool((form.regla_id.data or "").strip())
    try:
        regla = _regla_desde_formulario(form, es_edicion)
        datos = {"version": int(form.version.data or _version_actual()), "regla": regla}
        datos_validos = validacion.validar_peticion("fw_regla_guardar", datos)
    except (validacion.ErrorValidacion, ValueError) as exc:
        mensaje = str(exc) or "Formulario inválido."
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_guardar", "error", mensaje)
        destino = url_for("firewall.regla_editar", regla_id=form.regla_id.data) if es_edicion else url_for("firewall.regla_nueva")
        return redirect(destino)

    respuesta = buzon.enviar_y_esperar(usuario["login"], "fw_regla_guardar", datos_validos)
    _responder(usuario, ip, "fw_regla_guardar", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("firewall.index"))


@bp.route("/firewall/regla/eliminar", methods=["POST"])
@rol_requerido("admin")
def regla_eliminar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = FwReglaAccionForm()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_eliminar", "error", mensaje)
        return redirect(url_for("firewall.index"))
    try:
        datos = {"version": int(form.version.data or _version_actual()), "id": (form.regla_id.data or "").strip()}
        datos_validos = validacion.validar_peticion("fw_regla_eliminar", datos)
    except (validacion.ErrorValidacion, ValueError) as exc:
        flash(str(exc) or "Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_eliminar", "error", str(exc))
        return redirect(url_for("firewall.index"))
    respuesta = buzon.enviar_y_esperar(usuario["login"], "fw_regla_eliminar", datos_validos)
    _responder(usuario, ip, "fw_regla_eliminar", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("firewall.index"))


@bp.route("/firewall/regla/mover", methods=["POST"])
@rol_requerido("admin")
def regla_mover():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = FwReglaAccionForm()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_mover", "error", mensaje)
        return redirect(url_for("firewall.index"))
    try:
        datos = {
            "version": int(form.version.data or _version_actual()),
            "id": (form.regla_id.data or "").strip(),
            "posicion": int(form.posicion.data),
        }
        datos_validos = validacion.validar_peticion("fw_regla_mover", datos)
    except (validacion.ErrorValidacion, ValueError) as exc:
        flash(str(exc) or "Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_mover", "error", str(exc))
        return redirect(url_for("firewall.index"))
    respuesta = buzon.enviar_y_esperar(usuario["login"], "fw_regla_mover", datos_validos)
    _responder(usuario, ip, "fw_regla_mover", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("firewall.index"))


@bp.route("/firewall/regla/activar", methods=["POST"])
@rol_requerido("admin")
def regla_activar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = FwReglaAccionForm()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_activar", "error", mensaje)
        return redirect(url_for("firewall.index"))
    try:
        datos = {
            "version": int(form.version.data or _version_actual()),
            "id": (form.regla_id.data or "").strip(),
            "habilitada": form.habilitada.data == "1",
        }
        datos_validos = validacion.validar_peticion("fw_regla_activar", datos)
    except (validacion.ErrorValidacion, ValueError) as exc:
        flash(str(exc) or "Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "fw_regla_activar", "error", str(exc))
        return redirect(url_for("firewall.index"))
    respuesta = buzon.enviar_y_esperar(usuario["login"], "fw_regla_activar", datos_validos)
    _responder(usuario, ip, "fw_regla_activar", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("firewall.index"))


@bp.route("/firewall/grupos")
@rol_requerido("admin")
def grupos():
    contexto = _contexto_fw()
    fw = contexto["fw"]
    editar_id = request.args.get("editar")
    grupo_editar = next((g for g in fw["grupos"] if g["id"] == editar_id), None) if editar_id else None
    datos_form: dict = {}
    if grupo_editar is not None:
        datos_form = {
            "grupo_id": grupo_editar["id"],
            "nombre": grupo_editar["nombre"],
            "tipo": grupo_editar["tipo"],
        }
    form = FwGrupoForm(data=datos_form)
    form.version.data = str(fw["version"])
    return render_template(
        "firewall_grupos.html",
        **contexto,
        form=form,
        form_eliminar=FwGrupoEliminarForm(version=str(fw["version"])),
        grupo_editar=grupo_editar,
        grupos=fw["grupos"],
        dispositivos=_dispositivos_para_selector(),
    )


@bp.route("/firewall/grupo/guardar", methods=["POST"])
@rol_requerido("admin")
def grupo_guardar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = FwGrupoForm()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_grupo_guardar", "error", mensaje)
        return redirect(url_for("firewall.grupos"))
    try:
        miembros = [m for m in request.form.getlist("miembros") if isinstance(m, str) and m.strip()]
        texto = form.miembros_texto.data or ""
        miembros += [linea.strip() for linea in texto.splitlines() if linea.strip()]
        datos = {
            "version": int(form.version.data or _version_actual()),
            "grupo": {
                "nombre": (form.nombre.data or "").strip(),
                "tipo": form.tipo.data,
                "miembros": miembros,
            },
        }
        grupo_id = (form.grupo_id.data or "").strip()
        if grupo_id:
            datos["grupo"]["id"] = grupo_id
        datos_validos = validacion.validar_peticion("fw_grupo_guardar", datos)
    except (validacion.ErrorValidacion, ValueError) as exc:
        flash(str(exc) or "Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "fw_grupo_guardar", "error", str(exc))
        return redirect(url_for("firewall.grupos"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "fw_grupo_guardar", datos_validos)
    _responder(usuario, ip, "fw_grupo_guardar", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("firewall.grupos"))


@bp.route("/firewall/grupo/eliminar", methods=["POST"])
@rol_requerido("admin")
def grupo_eliminar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = FwGrupoEliminarForm()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "fw_grupo_eliminar", "error", mensaje)
        return redirect(url_for("firewall.grupos"))
    try:
        datos = {"version": int(form.version.data or _version_actual()), "id": (form.grupo_id.data or "").strip()}
        datos_validos = validacion.validar_peticion("fw_grupo_eliminar", datos)
    except (validacion.ErrorValidacion, ValueError) as exc:
        flash(str(exc) or "Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "fw_grupo_eliminar", "error", str(exc))
        return redirect(url_for("firewall.grupos"))
    respuesta = buzon.enviar_y_esperar(usuario["login"], "fw_grupo_eliminar", datos_validos)
    _responder(usuario, ip, "fw_grupo_eliminar", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("firewall.grupos"))
