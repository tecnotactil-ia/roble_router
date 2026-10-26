from __future__ import annotations

import psutil
from flask import Blueprint, abort, jsonify, render_template, request

from . import estadisticas as estadisticas_mod, estado as estado_mod, reparto
from .seguridad import login_requerido

bp = Blueprint("dashboard", __name__)


def _datos_sistema() -> dict:
    try:
        cpu = psutil.cpu_percent(interval=None)
        memoria = psutil.virtual_memory()
        disco = psutil.disk_usage("/")
        return {
            "cpu_pct": cpu,
            "memoria_pct": memoria.percent,
            "disco_pct": disco.percent,
        }
    except Exception:
        return {"cpu_pct": None, "memoria_pct": None, "disco_pct": None}


def _peso_modo(w: dict, modo_pesos: str) -> int | float | None:
    """Peso que se muestra junto a cada línea (distinto del que usa
    `reparto.valor_peso_reparto` para el % de reparto, que además descarta
    valores <= 0 o no finitos): `peso_efectivo` en auto, `peso` en manual.
    Tal cual, sin filtrar, para que un peso 0 o negativo siga siendo
    visible como dato (aunque no participe en el reparto)."""
    valor = w.get("peso_efectivo") if modo_pesos == "auto" else w.get("peso")
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        return None
    return valor


def _resumen() -> dict:
    est = estado_mod.leer_estado()
    sistema = _datos_sistema()
    n_conectados = estado_mod.contar_dispositivos_lan(est)
    modo_pesos = est.modo_pesos if est.modo_pesos in ("auto", "manual") else "auto"

    wans = []
    for w in reparto.anotar_pct_reparto(est.wans, modo_pesos, est.fase):
        wans.append(
            {
                **w,
                "rx_bps_fmt": estado_mod.formatear_bitrate(w.get("rx_bps")),
                "tx_bps_fmt": estado_mod.formatear_bitrate(w.get("tx_bps")),
                "peso_modo": _peso_modo(w, modo_pesos),
            }
        )

    return {
        "disponible": est.disponible,
        "caido": est.caido,
        "error": est.error,
        "antiguedad_s": round(est.antiguedad_s, 1) if est.antiguedad_s is not None else None,
        "uptime_s": est.uptime_s,
        "uptime_fmt": estado_mod.formatear_uptime(est.uptime_s),
        "modo": est.modo,
        "modo_pesos": modo_pesos,
        "fase": est.fase,
        "internet": est.internet,
        "servicios": est.servicios,
        "servicios_fmt": estado_mod.formatear_servicios(est.servicios, est.fase),
        "wifi_ap": est.wifi_ap,
        "wans": wans,
        "hay_reparto": any(w.get("pct_reparto") is not None for w in wans),
        "n_dispositivos": n_conectados,
        "sistema": sistema,
    }


@bp.route("/")
@login_requerido
def index():
    return render_template("dashboard.html", datos=_resumen())


@bp.route("/dashboard/datos.json")
@login_requerido
def datos_json():
    return jsonify(_resumen())


@bp.route("/dashboard/estadisticas.json")
@login_requerido
def estadisticas_json():
    rango = request.args.get("rango", "24h")
    if rango not in estadisticas_mod.RANGOS_VALIDOS:
        abort(400)
    return jsonify(estadisticas_mod.obtener_estadisticas(rango))
