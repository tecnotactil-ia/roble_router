"""Protección: bloqueador de anuncios/rastreadores/amenazas por DNS
(docs/CONTRATO.md, acciones `bloqueo_*`; núcleo: `core/router_bloqueo.py`).

Mismo patrón que `wifi.py`/`wan.py`: el panel nunca descarga listas ni toca
dnsmasq, sólo valida y deja la petición en el buzón para que routerd (o el
proceso aparte `router_bloqueo.py`) la aplique de verdad. El catálogo de
listas vive en el núcleo (`router_bloqueo.CATALOGO`, con las URLs fijas);
aquí sólo se copian id/nombre/descripción para pintar la página -las URLs
NUNCA viajan al panel-.

`routerd` publica SIEMPRE `config.bloqueo` (copia de `router.json` ->
"bloqueo", con `lista_blanca`/`lista_negra` incluidas), `config.bloqueo_version`
(hex 16 car., concurrencia optimista de `bloqueo_config` -> "version") y
`dns_emergencia` (fail-open del bloqueador: `{activo, desde, motivo}`,
docs/CONTRATO.md). Aun así, `cfg_disponible` (ver `_contexto_pagina`) sigue
tratando `config.bloqueo` como opcional de forma defensiva -un routerd más
antiguo, una instalación a medias, o un `estado.json` corrupto no deben
dejar esta página fingiendo una configuración que no es la real: en ese
caso se avisa y se deshabilitan los «Guardar» que dependen de ella-.
"""
from __future__ import annotations

import math

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from . import auditoria, buzon, estado as estado_mod, validacion
from .formularios import (
    BloqueoActualizarForm,
    BloqueoListaForm,
    BloqueoProbarForm,
    BloqueoSeccionEstadoForm,
    BloqueoSeccionListasForm,
    BloqueoSeccionOpcionesForm,
)
from .seguridad import login_requerido, rol_requerido, usuario_actual

bp = Blueprint("proteccion", __name__)

_LLAVE_SESION_PROBAR = "proteccion_probar_resultado"

# Valor por defecto SÓLO para rellenar filas que de verdad existen (p. ej.
# para no pintar el catálogo entero vacío cuando `config.bloqueo` sí está
# disponible pero con un campo suelto raro). Cuando `config.bloqueo` falta
# del todo, la vista usa `cfg_disponible=False` y NO rellena con esto -ver
# el aviso del módulo-.
DEFECTO_CONFIG_BLOQUEO = {
    "habilitado": True,
    "listas": ["hagezi_pro", "hagezi_tif"],
    "lista_blanca": [],
    "lista_negra": [],
    "forzar_dns": True,
    "bloquear_doh": True,
    "actualizar_h": 24,
    "registro_dns_dias": 30,
}

# Catálogo de listas del bloqueador (docs/CONTRATO.md, router_bloqueo.CATALOGO):
# sólo nombre/descripción para pintar la página; las URLs reales NUNCA
# llegan al panel, sólo estos ids fijos.
CATALOGO_BLOQUEO = {
    "hagezi_light": {
        "nombre": "HaGeZi Light",
        "descripcion": "Lo mínimo: anuncios y rastreadores básicos, muy pocos falsos positivos.",
        "recomendada": False,
    },
    "hagezi_multi": {
        "nombre": "HaGeZi Multi",
        "descripcion": "Equilibrio entre Light y Pro: anuncios, rastreadores y telemetría habituales.",
        "recomendada": False,
    },
    "hagezi_pro": {
        "nombre": "HaGeZi Pro",
        "descripcion": "Más agresiva: anuncios, rastreadores, telemetría y afiliados. Recomendada por defecto.",
        "recomendada": True,
    },
    "hagezi_pro_plus": {
        "nombre": "HaGeZi Pro++",
        "descripcion": "Como Pro, más agresiva aún (más listas de terceros incluidas): más riesgo de falsos positivos.",
        "recomendada": False,
    },
    "hagezi_tif": {
        "nombre": "HaGeZi Threat Intelligence Feeds",
        "descripcion": "Amenazas: malware, phishing, cryptojacking, servidores de mando y control (versión «medium», ~600 mil dominios).",
        "recomendada": True,
    },
    "hagezi_doh": {
        "nombre": "HaGeZi DNS-over-HTTPS/TLS/QUIC",
        "descripcion": "Servidores DNS cifrados públicos conocidos (se añade sola si activas «Bloquear DoH»).",
        "recomendada": False,
    },
    "hagezi_nsfw": {
        "nombre": "HaGeZi NSFW",
        "descripcion": "Contenido para adultos (opcional).",
        "recomendada": False,
    },
    "hagezi_gambling": {
        "nombre": "HaGeZi Apuestas",
        "descripcion": "Sitios de apuestas y juego online.",
        "recomendada": False,
    },
}

# Marcador estable del mensaje de error que emite router_bloqueo.generar()
# cuando la guarda de variación ±50% frena una pasada (ver core/router_bloqueo.py
# -> generar()): sirve para distinguir ese caso concreto de cualquier otro
# motivo por el que `activo` pueda ser False (dnsmasq --test rechazado...).
_MARCA_GUARDA_VARIACION = "varía más de un"


def _normalizar_config_bloqueo(bruto) -> tuple[dict, list[str]]:
    """Normalización defensiva de `estado.config.bloqueo` (docs/CONTRATO.md):
    tipos inesperados nunca deben romper la página, sólo caer al valor por
    defecto campo a campo (mismo patrón que `estado._normalizar_wifi`).
    Devuelve `(cfg, avisos)`: `avisos` describe qué campos se tuvieron que
    recortar a su rango válido (para que la plantilla pueda avisar de que lo
    guardado en `router.json` no es exactamente lo que se ve aquí)."""
    out = dict(DEFECTO_CONFIG_BLOQUEO)
    avisos: list[str] = []
    if not isinstance(bruto, dict):
        return out, avisos
    if isinstance(bruto.get("habilitado"), bool):
        out["habilitado"] = bruto["habilitado"]
    if isinstance(bruto.get("listas"), list):
        listas_str = [x for x in bruto["listas"] if isinstance(x, str)]
        out["listas"] = [x for x in listas_str if x in CATALOGO_BLOQUEO]
        desconocidas = sorted(set(listas_str) - CATALOGO_BLOQUEO.keys())
        if desconocidas:
            avisos.append("El router tiene lista(s) activada(s) que ya no están en el catálogo "
                           "(%s): se ignoran al mostrarlas aquí." % ", ".join(desconocidas))
    if isinstance(bruto.get("lista_blanca"), list):
        out["lista_blanca"] = [x for x in bruto["lista_blanca"] if isinstance(x, str)]
    if isinstance(bruto.get("lista_negra"), list):
        out["lista_negra"] = [x for x in bruto["lista_negra"] if isinstance(x, str)]
    if isinstance(bruto.get("forzar_dns"), bool):
        out["forzar_dns"] = bruto["forzar_dns"]
    if isinstance(bruto.get("bloquear_doh"), bool):
        out["bloquear_doh"] = bruto["bloquear_doh"]
    actualizar_h = bruto.get("actualizar_h")
    if isinstance(actualizar_h, (int, float)) and not isinstance(actualizar_h, bool) and math.isfinite(actualizar_h):
        recortado = max(6, min(168, int(actualizar_h)))
        out["actualizar_h"] = recortado
        if recortado != actualizar_h:
            avisos.append("La frecuencia de actualización guardada (%s h) está fuera de rango "
                           "y se ha ajustado a %d h; se guardará ajustado al próximo Guardar."
                           % (actualizar_h, recortado))
    dias = bruto.get("registro_dns_dias")
    if isinstance(dias, (int, float)) and not isinstance(dias, bool) and math.isfinite(dias):
        recortado = max(1, min(365, int(dias)))
        out["registro_dns_dias"] = recortado
        if recortado != dias:
            avisos.append("Los días de registro DNS guardados (%s) están fuera de rango y se han "
                           "ajustado a %d; se guardará ajustado al próximo Guardar." % (dias, recortado))
    return out, avisos


def _filas_catalogo(cfg_bloqueo: dict, bloqueo_estado: dict) -> list[dict]:
    """Une el catálogo fijo con lo que de verdad se procesó en la última
    pasada (`bloqueo.json` -> listas), una fila por lista del catálogo."""
    por_id = {l["id"]: l for l in (bloqueo_estado.get("listas") or [])}
    activas = set(cfg_bloqueo.get("listas") or [])
    filas = []
    for id_, info in CATALOGO_BLOQUEO.items():
        real = por_id.get(id_)
        actualizada = real.get("actualizada") if real else None
        filas.append(
            {
                "id": id_,
                "nombre": info["nombre"],
                "descripcion": info["descripcion"],
                "recomendada": info["recomendada"],
                "activa": id_ in activas,
                "dominios": real.get("dominios") if real else None,
                "actualizada_relativo": estado_mod.formatear_relativo(actualizada) if actualizada else "sin datos",
                "error": real.get("error") if real else None,
            }
        )
    return filas


def _guarda_variacion_activa(bloqueo_estado: dict) -> bool:
    error = bloqueo_estado.get("error_actualizacion")
    return bool(error) and _MARCA_GUARDA_VARIACION in error


def _primer_error_formulario(form) -> str:
    for errores in form.errors.values():
        for error in errores:
            if error:
                return str(error)
    return "Formulario inválido."


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


def _cfg_bloqueo_no_disponible() -> dict:
    """BLOQ (revisión Opus): cuando `config.bloqueo` no existe en absoluto,
    NUNCA se usan los valores por defecto para rellenar los formularios -eso
    fingiría una configuración que podría no ser la real-. En su lugar, todo
    queda "desconocido": ningún radio/casilla marcado, campos numéricos
    vacíos. La plantilla, además, deshabilita los botones Guardar por
    completo cuando `cfg_disponible` es False."""
    return {
        "habilitado": None,
        "listas": [],
        "lista_blanca": [],
        "lista_negra": [],
        "forzar_dns": False,
        "bloquear_doh": False,
        "actualizar_h": None,
        "registro_dns_dias": None,
    }


def _contexto_pagina(resultado_prueba: dict | None) -> dict:
    est = estado_mod.leer_estado()
    bruto_bloqueo = (est.config or {}).get("bloqueo")
    cfg_disponible = isinstance(bruto_bloqueo, dict)
    if cfg_disponible:
        cfg_bloqueo, avisos_recorte = _normalizar_config_bloqueo(bruto_bloqueo)
    else:
        cfg_bloqueo, avisos_recorte = _cfg_bloqueo_no_disponible(), []
    bloqueo_version = (est.config or {}).get("bloqueo_version")
    bloqueo_version = bloqueo_version if isinstance(bloqueo_version, str) else ""
    bloqueo_estado = estado_mod.leer_bloqueo()

    form_estado = BloqueoSeccionEstadoForm(
        seccion="estado", version=bloqueo_version,
        habilitado=({True: "1", False: "0"}.get(cfg_bloqueo["habilitado"])),
    )
    form_listas = BloqueoSeccionListasForm(seccion="listas", version=bloqueo_version)
    form_opciones = BloqueoSeccionOpcionesForm(
        seccion="opciones", version=bloqueo_version,
        forzar_dns=cfg_bloqueo["forzar_dns"], bloquear_doh=cfg_bloqueo["bloquear_doh"],
        actualizar_h=cfg_bloqueo["actualizar_h"], registro_dns_dias=cfg_bloqueo["registro_dns_dias"],
    )

    return {
        "cfg_bloqueo": cfg_bloqueo,
        "cfg_disponible": cfg_disponible,
        "avisos_recorte": avisos_recorte,
        "bloqueo_estado": bloqueo_estado,
        "dns_emergencia": est.dns_emergencia,
        "dns_emergencia_desde_relativo": (
            estado_mod.formatear_relativo(est.dns_emergencia.get("desde"))
            if est.dns_emergencia.get("desde") else None
        ),
        "filas_catalogo": _filas_catalogo(cfg_bloqueo, bloqueo_estado),
        "guarda_variacion_activa": _guarda_variacion_activa(bloqueo_estado),
        "generado_relativo": estado_mod.formatear_relativo(bloqueo_estado.get("generado")),
        "siguiente_relativo": estado_mod.formatear_proximo(bloqueo_estado.get("siguiente")),
        "form_estado": form_estado,
        "form_listas": form_listas,
        "form_opciones": form_opciones,
        "form_actualizar": BloqueoActualizarForm(),
        "form_probar": BloqueoProbarForm(),
        "form_lista": BloqueoListaForm(),
        "resultado_prueba": resultado_prueba,
    }


@bp.route("/proteccion")
@login_requerido
def index():
    resultado_prueba = session.pop(_LLAVE_SESION_PROBAR, None)
    return render_template("proteccion.html", **_contexto_pagina(resultado_prueba))


_FORM_POR_SECCION = {
    "estado": BloqueoSeccionEstadoForm,
    "listas": BloqueoSeccionListasForm,
    "opciones": BloqueoSeccionOpcionesForm,
}


@bp.route("/proteccion/config", methods=["POST"])
@rol_requerido("admin")
def config():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"

    seccion = request.form.get("seccion")
    clase_form = _FORM_POR_SECCION.get(seccion)
    if clase_form is None:
        flash("Formulario inválido.", "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_config", "error", "sección desconocida")
        return redirect(url_for("proteccion.index"))

    form = clase_form()
    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_config", "error", mensaje)
        return redirect(url_for("proteccion.index"))

    # ALTA (condición de carrera): se relee el estado FRESCO justo antes de
    # combinar, en vez de fiarse de lo que esta sección no edita y que el
    # cliente pudiera llevar en un campo oculto desde que se pintó la
    # página (podría estar obsoleto si otra persona guardó mientras tanto).
    est_fresco = estado_mod.leer_estado()
    bruto_fresco = (est_fresco.config or {}).get("bloqueo")
    if not isinstance(bruto_fresco, dict):
        mensaje = "El router todavía no ha enviado su configuración de bloqueo; recarga en unos segundos."
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_config", "error", "config.bloqueo ausente")
        return redirect(url_for("proteccion.index"))
    cfg_actual, _ = _normalizar_config_bloqueo(bruto_fresco)

    datos = {
        "habilitado": cfg_actual["habilitado"],
        "listas": cfg_actual["listas"],
        "forzar_dns": cfg_actual["forzar_dns"],
        "bloquear_doh": cfg_actual["bloquear_doh"],
        "actualizar_h": cfg_actual["actualizar_h"],
        "registro_dns_dias": cfg_actual["registro_dns_dias"],
    }
    if seccion == "estado":
        datos["habilitado"] = form.habilitado.data == "1"
    elif seccion == "listas":
        # MEDIA: los ids fuera del catálogo se descartan en silencio en vez
        # de tirar toda la sección -sólo pueden llegar aquí con un POST
        # manipulado a mano, nunca desde las casillas que pinta la página-;
        # validacion.py también los rechazaría como defensa en profundidad.
        enviadas = request.form.getlist("listas")
        datos["listas"] = [i for i in enviadas if i in CATALOGO_BLOQUEO]
    else:  # opciones
        datos["forzar_dns"] = bool(form.forzar_dns.data)
        datos["bloquear_doh"] = bool(form.bloquear_doh.data)
        datos["actualizar_h"] = form.actualizar_h.data
        datos["registro_dns_dias"] = form.registro_dns_dias.data

    version_enviada = (form.version.data or "").strip()
    if version_enviada:
        datos["version"] = version_enviada

    try:
        datos_validos = validacion.validar_peticion("bloqueo_config", datos)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_config", "error", str(exc))
        return redirect(url_for("proteccion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "bloqueo_config", datos_validos)
    _responder(usuario, ip, "bloqueo_config", respuesta)
    return redirect(url_for("proteccion.index"))


@bp.route("/proteccion/actualizar", methods=["POST"])
@rol_requerido("admin")
def actualizar():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = BloqueoActualizarForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_actualizar", "error", mensaje)
        return redirect(url_for("proteccion.index"))

    datos = {"forzar": True} if form.forzar.data else {}
    try:
        datos_validos = validacion.validar_peticion("bloqueo_actualizar", datos)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_actualizar", "error", str(exc))
        return redirect(url_for("proteccion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "bloqueo_actualizar", datos_validos)
    _responder(usuario, ip, "bloqueo_actualizar", respuesta, detalle_auditoria=str(datos_validos))
    return redirect(url_for("proteccion.index"))


@bp.route("/proteccion/probar", methods=["POST"])
@login_requerido
def probar():
    """BAJA: `bloqueo_probar` nunca muta nada (sólo consulta las cachés en
    disco, sin red -docs/CONTRATO.md-), así que se permite a cualquier rol
    conectado, no sólo admin -a diferencia del resto de acciones de esta
    página, que sí cambian la configuración o disparan un systemctl-."""
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = BloqueoProbarForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_probar", "error", mensaje)
        return redirect(url_for("proteccion.index"))

    try:
        datos_validos = validacion.validar_peticion("bloqueo_probar", {"dominio": form.dominio.data})
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_probar", "error", str(exc))
        return redirect(url_for("proteccion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "bloqueo_probar", datos_validos)
    # El resultado se muestra en un recuadro persistente (no sólo un toast):
    # se guarda una vez en la sesión y `index()` lo consume (pop) en el
    # siguiente GET, mismo patrón que el escaneo Wi-Fi pendiente. `categoria`
    # distingue 3 casos visuales: bloqueado (rojo), permitido (verde) y
    # pendiente/error (neutro) -cuando routerd no ha contestado a tiempo o
    # falló, nunca se pinta como si fuera un resultado «permitido»-.
    if respuesta.estado == "ok" and respuesta.mensaje.strip().upper().startswith("BLOQUEADO"):
        categoria = "bloqueado"
    elif respuesta.estado == "ok":
        categoria = "permitido"
    else:
        categoria = "pendiente"
    session[_LLAVE_SESION_PROBAR] = {
        "dominio": datos_validos["dominio"],
        "estado": respuesta.estado,
        "mensaje": respuesta.mensaje,
        "categoria": categoria,
    }
    auditoria.registrar(usuario["login"], ip, "bloqueo_probar", respuesta.estado, respuesta.mensaje)
    return redirect(url_for("proteccion.index"))


@bp.route("/proteccion/lista", methods=["POST"])
@rol_requerido("admin")
def lista():
    usuario = usuario_actual()
    ip = request.remote_addr or "desconocida"
    form = BloqueoListaForm()

    if not form.validate_on_submit():
        mensaje = _primer_error_formulario(form)
        flash(mensaje, "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_lista", "error", mensaje)
        return redirect(url_for("proteccion.index"))

    datos = {"tipo": form.tipo.data, "accion": form.accion.data, "dominio": form.dominio.data}
    try:
        datos_validos = validacion.validar_peticion("bloqueo_lista", datos)
    except validacion.ErrorValidacion as exc:
        flash(str(exc), "error")
        auditoria.registrar(usuario["login"], ip, "bloqueo_lista", "error", str(exc))
        return redirect(url_for("proteccion.index"))

    respuesta = buzon.enviar_y_esperar(usuario["login"], "bloqueo_lista", datos_validos)
    _responder(usuario, ip, "bloqueo_lista", respuesta)
    return redirect(url_for("proteccion.index"))
