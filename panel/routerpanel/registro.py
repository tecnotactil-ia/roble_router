from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone

from flask import Blueprint, render_template

from . import estado as estado_mod
from .seguridad import login_requerido

bp = Blueprint("registro", __name__)

ICONOS_ACCION = {
    "modo": "bi-toggle2-on",
    "wan_actualizar": "bi-diagram-3",
    "wan_estado": "bi-diagram-3",
    "wan_nueva": "bi-plus-circle",
    "dispositivo_etiquetar": "bi-tag",
    "reserva_agregar": "bi-bookmark-plus",
    "reserva_eliminar": "bi-bookmark-dash",
    "dnsmasq": "bi-hdd-network",
    "dhcp_rango": "bi-hdd-network",
    "dns": "bi-globe2",
    "monitor": "bi-activity",
    "login": "bi-box-arrow-in-right",
    "logout": "bi-box-arrow-right",
}
ICONO_DEFECTO = "bi-journal-text"


def _icono_accion(accion: str) -> str:
    return ICONOS_ACCION.get(accion, ICONO_DEFECTO)


def _fecha_dt(valor) -> datetime | None:
    if not isinstance(valor, str):
        return None
    try:
        dt = datetime.fromisoformat(valor)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _etiqueta_dia(dt: datetime, hoy) -> str:
    dias = (hoy - dt.date()).days
    if dias == 0:
        return "Hoy"
    if dias == 1:
        return "Ayer"
    return dt.strftime("%d/%m/%Y")


def _relativo(dt: datetime, ahora: datetime) -> str:
    segundos = int((ahora - dt).total_seconds())
    if segundos < 0:
        segundos = 0
    if segundos < 60:
        return "hace instantes"
    minutos = segundos // 60
    if minutos < 60:
        return f"hace {minutos} min"
    horas = minutos // 60
    if horas < 24:
        return f"hace {horas} h"
    dias = horas // 24
    return f"hace {dias} d"


def _agrupar_por_dia(operaciones: list[dict]) -> list[dict]:
    """Agrupa las operaciones (ya ordenadas de más a menos reciente por
    `leer_oplog`) en bloques por día: «Hoy», «Ayer» o la fecha. Conserva el
    orden de llegada dentro de cada grupo."""
    ahora = datetime.now(timezone.utc)
    hoy = ahora.date()
    grupos: "OrderedDict[str, dict]" = OrderedDict()

    for op in operaciones:
        dt = _fecha_dt(op.get("fecha"))
        if dt is not None:
            clave = dt.date().isoformat()
            etiqueta = _etiqueta_dia(dt, hoy)
            hora = dt.strftime("%H:%M:%S")
            fecha_abs = dt.strftime("%d/%m/%Y %H:%M:%S")
            relativo = _relativo(dt, ahora)
        else:
            clave = "desconocida"
            etiqueta = "Fecha desconocida"
            hora = "—"
            fecha_abs = str(op.get("fecha") or "—")
            relativo = "—"

        datos = op.get("datos")
        datos_fmt = repr(datos) if datos else None

        if clave not in grupos:
            grupos[clave] = {"etiqueta": etiqueta, "operaciones": []}
        grupos[clave]["operaciones"].append(
            {
                **op,
                "hora": hora,
                "fecha_abs": fecha_abs,
                "relativo": relativo,
                "icono": _icono_accion(str(op.get("accion", ""))),
                "datos_fmt": datos_fmt,
            }
        )

    return list(grupos.values())


@bp.route("/registro")
@login_requerido
def index():
    operaciones, error = estado_mod.leer_oplog(limite=200)
    grupos = _agrupar_por_dia(operaciones)
    return render_template("registro.html", grupos=grupos, error=error, total=len(operaciones))
