"""Estadísticas históricas de tráfico/DNS, leídas en sólo lectura de la base
SQLite que publica el recolector (proceso aparte, en `core/`, ver
docs/CONTRATO.md). El panel NUNCA escribe esta base: se abre siempre con
`sqlite3` en modo URI `mode=ro` y con un timeout corto, y cualquier fallo
(fichero ausente, corrupto, bloqueado, esquema inesperado, consulta que
revienta...) se traduce en una estructura "sin datos" segura -- igual que
`estado.py` con `estado.json` -- en vez de lanzar una excepción o devolver
un 500. Se distinguen dos motivos en `estado_vacio` para que la UI no use la
misma frase para cosas distintas:

    "sin_datos" -- no hay base todavía, o el esquema no es el esperado
                   (recolector no arrancado / a medio instalar).
    "error"     -- la base existe y el esquema es válido, pero una consulta
                   ha fallado (corrupción puntual, bloqueo, etc.).

Esquema exacto esperado (lo escribe el recolector, documentado en
docs/CONTRATO.md):

    trafico_wan(ts, wan, nombre, rx_bytes, tx_bytes, latencia_ms, perdida_pct,
                en_balanceo)          -- por minuto, 48 h
    trafico_wan_hora(misma forma)     -- por hora, 400 días
    trafico_disp(ts, ip, mac, nombre, bajada_bytes, subida_bytes, conexiones)
                                        -- por minuto, 48 h
    trafico_disp_hora(misma forma)    -- por hora, 400 días
    conexiones(ts, total)             -- por minuto, 48 h (no existe versión
                                          por hora: en 7d/30d no hay datos)
    dns_hora(hora, cliente, dominio, consultas, bloqueadas)
    meta(clave, valor)                -- se exige meta.version_esquema = '1'

Todas las consultas van parametrizadas (`?`): nunca se interpola directamente
texto que venga del usuario en el SQL. El único "parámetro" que decide qué
tabla o qué tamaño de bucket se usa es `rango`, y se valida contra una lista
blanca (`RANGOS_VALIDOS`) antes de llegar a ningún nombre de tabla.

Mbit/s: en vez de dividir siempre por el ancho nominal del bucket, se divide
por los segundos REALMENTE cubiertos por filas en ese bucket (nº de filas
agregadas × el paso temporal de la tabla de origen: 60 s en las tablas por
minuto, 3600 s en las tablas por hora). Así un bucket incompleto (el primero
del rango, o el que todavía está en curso) no sale con una caída artificial
sólo por tener menos filas que el resto.

30 días: se agrega por día de CALENDARIO LOCAL (zona horaria del router),
no por bloques de 86400 s en UTC, para que el cambio de hora (DST) no
desplace ni junte días de forma rara.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import estado as estado_mod

LOG = logging.getLogger(__name__)

RANGOS_VALIDOS: tuple[str, ...] = ("1h", "24h", "7d", "30d")

# TTL de caché por rango: los rangos cortos cambian rápido (interesa un
# refresco más vivo); 7d/30d apenas varían minuto a minuto, así que una
# caché más larga ahorra reabrir la base sin que nadie note la diferencia.
_CACHE_TTL_S: dict[str, float] = {"1h": 30.0, "24h": 60.0, "7d": 300.0, "30d": 300.0}

# Un resultado "error" (consulta que revienta, corrupción puntual...) se
# cachea mucho menos tiempo que uno normal: ni se reintenta en cada petición
# (machacaría la base si el fallo es persistente) ni se queda pegado hasta
# 5 minutos si ya se arregló solo (p. ej. terminó un `VACUUM` del
# recolector).
_TTL_ERROR_S = 15.0

_cache_lock = threading.Lock()  # protege `_cache` y la creación de `_locks_por_clave`
_cache: dict[tuple[str, str], tuple[float, dict, float]] = {}
_locks_por_clave: dict[tuple[str, str], threading.Lock] = {}


def ruta_db() -> str:
    return os.environ.get("ROUTER_ESTADISTICAS_DB", "/var/lib/router/estadisticas/estadisticas.db")


def _zona_horaria() -> ZoneInfo:
    """TZ del sistema (variable de entorno `TZ`) o `Europe/Rome` por defecto;
    si el nombre no es válido también se usa `Europe/Rome` en vez de romper."""
    nombre = os.environ.get("TZ") or "Europe/Rome"
    try:
        return ZoneInfo(nombre)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        return ZoneInfo("Europe/Rome")


def _conectar() -> sqlite3.Connection | None:
    ruta = ruta_db()
    uri = f"file:{ruta}?mode=ro"
    con = None
    try:
        con = sqlite3.connect(uri, uri=True, timeout=2.0)
        con.execute("PRAGMA query_only = TRUE")
        return con
    except (sqlite3.Error, OSError, ValueError):
        if con is not None:
            try:
                con.close()
            except sqlite3.Error:
                pass
        return None


def _version_esquema_valida(con: sqlite3.Connection) -> bool:
    """Devuelve False si no hay una versión de esquema soportada: la tabla
    `meta` existe pero no tiene la fila `version_esquema`, o tiene un valor
    distinto de "1" (versión más nueva/antigua que esta instalación del
    panel, o recolector a medio instalar). Deliberadamente NO atrapa
    `sqlite3.Error` aquí: si la propia consulta falla (p. ej. la tabla
    `meta` ni siquiera existe, o hay corrupción) eso es un fallo de lectura
    real -- lo captura el `except Exception` de `_calcular`, que lo clasifica
    como "error", no como "sin_datos"."""
    fila = con.execute("SELECT valor FROM meta WHERE clave = 'version_esquema'").fetchone()
    return bool(fila) and fila[0] == "1"


@dataclass
class _ParamRango:
    tabla_wan: str
    tabla_disp: str
    bucket_s: int
    desde: int
    granularidad_s: int  # paso temporal de las filas de origen: 60 ó 3600
    dia_local: bool = False  # True sólo en 30d (agregación por día de calendario local)


def _parametros(rango: str, ahora: int) -> _ParamRango:
    if rango == "1h":
        return _ParamRango("trafico_wan", "trafico_disp", 60, ahora - 3600, 60)
    if rango == "24h":
        return _ParamRango("trafico_wan", "trafico_disp", 300, ahora - 86400, 60)
    if rango == "7d":
        return _ParamRango("trafico_wan_hora", "trafico_disp_hora", 3600, ahora - 7 * 86400, 3600)
    if rango == "30d":
        return _ParamRango(
            "trafico_wan_hora", "trafico_disp_hora", 86400, ahora - 30 * 86400, 3600, dia_local=True
        )
    raise ValueError(f"rango no válido: {rango!r}")


def _generar_buckets(desde: int, ahora: int, bucket_s: int) -> list[int]:
    inicio = (desde // bucket_s) * bucket_s
    fin = (ahora // bucket_s) * bucket_s
    if fin < inicio:
        fin = inicio
    return list(range(inicio, fin + bucket_s, bucket_s))


def _generar_dias_locales(desde: int, ahora: int, tz: ZoneInfo) -> list[date]:
    """Lista de fechas de calendario LOCAL entre `desde` y `ahora` (ambas
    marcas epoch UTC), ambas inclusive. Al trabajar con `date` en vez de con
    aritmética de 86400 s, un día con 23 o 25 horas por el cambio de hora
    sigue siendo "un día" sin desplazar ni fusionar los siguientes."""
    inicio = datetime.fromtimestamp(desde, tz=timezone.utc).astimezone(tz).date()
    fin = datetime.fromtimestamp(ahora, tz=timezone.utc).astimezone(tz).date()
    dias = []
    d = inicio
    while d <= fin:
        dias.append(d)
        d += timedelta(days=1)
    return dias


def _etiqueta(ts: int, bucket_s: int, tz: ZoneInfo) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(tz)
    if bucket_s >= 86400:
        return dt.strftime("%d/%m")
    if bucket_s >= 3600:
        return dt.strftime("%d/%m %H:%M")
    return dt.strftime("%H:%M")


def _etiqueta_bucket(bucket: Any, bucket_s: int, tz: ZoneInfo, dia_local: bool) -> str:
    if dia_local:
        return bucket.strftime("%d/%m")
    return _etiqueta(bucket, bucket_s, tz)


def _estructura_vacia(rango: str, error: str | None, tz: ZoneInfo, estado_vacio: str) -> dict:
    return {
        "disponible": False,
        "error": error,
        "estado_vacio": estado_vacio,
        "rango": rango,
        "zona_horaria": str(tz),
        "generado": datetime.now(timezone.utc).isoformat(),
        "dns_nota": None,
        "trafico": {"etiquetas": [], "series": []},
        "latencia": {"etiquetas": [], "series": []},
        "top_dispositivos": [],
        "actividad": {"etiquetas": [], "conexiones": [], "dispositivos_activos": [], "conexiones_disponible": True},
        "dns_top": [],
        "dns_bloqueados_top": [],
        "dns_consultas_vs_bloqueadas": {"etiquetas": [], "consultas": [], "bloqueadas": []},
        "totales": {
            "bajada_bytes": 0,
            "subida_bytes": 0,
            "bajada_fmt": "—",
            "subida_fmt": "—",
            "consultas": 0,
            "bloqueadas": 0,
            "pct_bloqueado": None,
        },
    }


def _bucket_vacio(n: int) -> dict:
    return {
        "_rx": [0] * n,
        "_tx": [0] * n,
        "_lat_suma": [0.0] * n,
        "_lat_n": [0] * n,
        "_perd_suma": [0.0] * n,
        "_perd_n": [0] * n,
        "_filas": [0] * n,
    }


def _trafico_y_latencia(con, parametros: _ParamRango, buckets: list, tz: ZoneInfo) -> tuple[dict, dict, dict]:
    n = len(buckets)
    gran = parametros.granularidad_s
    wans: dict[str, dict] = {}

    def info(wan: str, nombre: str | None) -> dict:
        d = wans.get(wan)
        if d is None:
            d = {"id": wan, "nombre": nombre or wan, **_bucket_vacio(n)}
            wans[wan] = d
        elif nombre:
            d["nombre"] = nombre
        return d

    if parametros.dia_local:
        indice = {d: i for i, d in enumerate(buckets)}
        sql = (
            f"SELECT ts, wan, nombre, rx_bytes, tx_bytes, latencia_ms, perdida_pct "
            f"FROM {parametros.tabla_wan} WHERE ts >= ? ORDER BY ts"
        )
        for ts, wan, nombre, rx, tx, lat, perdida in con.execute(sql, (parametros.desde,)).fetchall():
            dia = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(tz).date()
            i = indice.get(dia)
            if i is None:
                continue
            d = info(wan, nombre)
            d["_rx"][i] += rx or 0
            d["_tx"][i] += tx or 0
            d["_filas"][i] += 1
            if lat is not None:
                d["_lat_suma"][i] += lat
                d["_lat_n"][i] += 1
            if perdida is not None:
                d["_perd_suma"][i] += perdida
                d["_perd_n"][i] += 1
    else:
        indice = {b: i for i, b in enumerate(buckets)}
        bucket_expr = f"(ts/{parametros.bucket_s})*{parametros.bucket_s}"
        sql = (
            f"SELECT {bucket_expr} AS bucket, wan, MAX(nombre), SUM(rx_bytes), SUM(tx_bytes), "
            f"AVG(latencia_ms), AVG(perdida_pct), COUNT(*) "
            f"FROM {parametros.tabla_wan} WHERE ts >= ? GROUP BY bucket, wan ORDER BY bucket, wan"
        )
        for bucket, wan, nombre, rx, tx, lat, perdida, cuenta in con.execute(sql, (parametros.desde,)).fetchall():
            i = indice.get(bucket)
            if i is None:
                continue
            d = info(wan, nombre)
            d["_rx"][i] += rx or 0
            d["_tx"][i] += tx or 0
            d["_filas"][i] += cuenta
            if lat is not None:
                d["_lat_suma"][i] += lat * cuenta
                d["_lat_n"][i] += cuenta
            if perdida is not None:
                d["_perd_suma"][i] += perdida * cuenta
                d["_perd_n"][i] += cuenta

    # Fusiona la hora EN CURSO (la que todavía no se ha cerrado) desde la
    # tabla por minuto -- igual en 7d y en 30d, con el mismo criterio que
    # `_top_dispositivos`: se mira si la tabla por hora ya tiene alguna fila
    # con ts >= inicio de la hora en curso (no "el día entero", sólo esa
    # hora); si no la tiene, se suma `trafico_wan` desde ese instante al
    # bucket que la contiene -- la propia hora en 7d, el día LOCAL en 30d
    # (nunca se pasa un `date` como parámetro SQL: el filtro siempre es por
    # epoch).
    if parametros.tabla_wan.endswith("_hora") and buckets:
        ahora_real = int(time.time())
        inicio_actual = (ahora_real // 3600) * 3600
        hay_hora_actual = con.execute(
            f"SELECT 1 FROM {parametros.tabla_wan} WHERE ts >= ? LIMIT 1", (inicio_actual,)
        ).fetchone()
        if not hay_hora_actual:
            if parametros.dia_local:
                bucket_actual = datetime.fromtimestamp(inicio_actual, tz=timezone.utc).astimezone(tz).date()
            else:
                bucket_actual = (inicio_actual // parametros.bucket_s) * parametros.bucket_s
            i_actual = indice.get(bucket_actual)
            if i_actual is not None:
                sql_min = (
                    "SELECT wan, MAX(nombre), SUM(rx_bytes), SUM(tx_bytes), AVG(latencia_ms), "
                    "AVG(perdida_pct), COUNT(*) FROM trafico_wan WHERE ts >= ? GROUP BY wan"
                )
                for wan, nombre, rx, tx, lat, perdida, cuenta in con.execute(sql_min, (inicio_actual,)).fetchall():
                    d = info(wan, nombre)
                    d["_rx"][i_actual] += rx or 0
                    d["_tx"][i_actual] += tx or 0
                    d["_filas"][i_actual] += cuenta
                    if lat is not None:
                        d["_lat_suma"][i_actual] += lat * cuenta
                        d["_lat_n"][i_actual] += cuenta
                    if perdida is not None:
                        d["_perd_suma"][i_actual] += perdida * cuenta
                        d["_perd_n"][i_actual] += cuenta

    etiquetas = [_etiqueta_bucket(b, parametros.bucket_s, tz, parametros.dia_local) for b in buckets]
    series_trafico = []
    series_latencia = []
    bajada_bytes_total = 0
    subida_bytes_total = 0

    for w in sorted(wans.values(), key=lambda w: w["nombre"]):
        bajada_mbps: list[float | None] = []
        subida_mbps: list[float | None] = []
        latencia_ms: list[float | None] = []
        perdida_pct: list[float | None] = []
        for i in range(n):
            filas_i = w["_filas"][i]
            if filas_i > 0:
                segundos_cubiertos = filas_i * gran
                bajada_mbps.append(round(w["_rx"][i] * 8 / segundos_cubiertos / 1_000_000, 3))
                subida_mbps.append(round(w["_tx"][i] * 8 / segundos_cubiertos / 1_000_000, 3))
            else:
                bajada_mbps.append(None)
                subida_mbps.append(None)
            latencia_ms.append(round(w["_lat_suma"][i] / w["_lat_n"][i], 1) if w["_lat_n"][i] else None)
            perdida_pct.append(round(w["_perd_suma"][i] / w["_perd_n"][i], 2) if w["_perd_n"][i] else None)
        bajada_bytes_total += sum(w["_rx"])
        subida_bytes_total += sum(w["_tx"])
        series_trafico.append(
            {"id": w["id"], "nombre": w["nombre"], "bajada_mbps": bajada_mbps, "subida_mbps": subida_mbps}
        )
        series_latencia.append(
            {"id": w["id"], "nombre": w["nombre"], "latencia_ms": latencia_ms, "perdida_pct": perdida_pct}
        )

    trafico = {"etiquetas": etiquetas, "series": series_trafico}
    latencia = {"etiquetas": etiquetas, "series": series_latencia}
    bytes_totales = {"bajada_bytes": bajada_bytes_total, "subida_bytes": subida_bytes_total}
    return trafico, latencia, bytes_totales


def _top_dispositivos(con, parametros: _ParamRango, limite: int = 10) -> list[dict]:
    tabla = parametros.tabla_disp
    sql = (
        "SELECT ip, MAX(mac), MAX(nombre), SUM(bajada_bytes), SUM(subida_bytes) "
        f"FROM {tabla} WHERE ts >= ? GROUP BY ip"
    )
    acumulado: dict[str, dict] = {}
    for ip, mac, nombre, bajada, subida in con.execute(sql, (parametros.desde,)).fetchall():
        acumulado[ip] = {"ip": ip, "mac": mac, "nombre": nombre, "bajada": bajada or 0, "subida": subida or 0}

    # Igual que en `_trafico_y_latencia`: si la tabla por hora todavía no
    # tiene ninguna fila de la hora en curso, se completa con la tabla por
    # minuto para que el "top dispositivos" de 7d/30d no se quede corto
    # justo en el tramo más reciente.
    if tabla.endswith("_hora"):
        ahora = int(time.time())
        inicio_actual = (ahora // 3600) * 3600
        ya_tiene_hora_actual = con.execute(f"SELECT 1 FROM {tabla} WHERE ts >= ? LIMIT 1", (inicio_actual,)).fetchone()
        if not ya_tiene_hora_actual:
            sql_min = (
                "SELECT ip, MAX(mac), MAX(nombre), SUM(bajada_bytes), SUM(subida_bytes) "
                "FROM trafico_disp WHERE ts >= ? GROUP BY ip"
            )
            for ip, mac, nombre, bajada, subida in con.execute(sql_min, (inicio_actual,)).fetchall():
                destino = acumulado.setdefault(ip, {"ip": ip, "mac": mac, "nombre": nombre, "bajada": 0, "subida": 0})
                destino["mac"] = destino["mac"] or mac
                destino["nombre"] = destino["nombre"] or nombre
                destino["bajada"] += bajada or 0
                destino["subida"] += subida or 0

    ordenado = sorted(acumulado.values(), key=lambda d: d["bajada"] + d["subida"], reverse=True)[:limite]
    return [
        {
            "ip": d["ip"],
            "mac": d["mac"],
            "nombre": d["nombre"] or d["ip"] or "(desconocido)",
            "bajada_bytes": d["bajada"],
            "subida_bytes": d["subida"],
            "bajada_fmt": estado_mod.formatear_bytes(d["bajada"]),
            "subida_fmt": estado_mod.formatear_bytes(d["subida"]),
        }
        for d in ordenado
    ]


def _actividad(con, parametros: _ParamRango, buckets: list, tz: ZoneInfo) -> dict:
    n = len(buckets)
    # `conexiones` sólo se registra por minuto y se purga a las 48 h: en
    # 7d/30d no hay (casi) nada que mostrar, así que se avisa explícitamente
    # en vez de pintar un gráfico vacío sin explicación.
    conexiones_disponible = parametros.granularidad_s == 60
    conexiones_vals: list[float | None] = [None] * n

    if conexiones_disponible:
        indice = {b: i for i, b in enumerate(buckets)}
        bucket_expr = f"(ts/{parametros.bucket_s})*{parametros.bucket_s}"
        sql_con = f"SELECT {bucket_expr} AS bucket, AVG(total) FROM conexiones WHERE ts >= ? GROUP BY bucket"
        for bucket, total in con.execute(sql_con, (parametros.desde,)).fetchall():
            i = indice.get(bucket)
            if i is not None and total is not None:
                conexiones_vals[i] = round(total, 1)

    disp_vals: list[int | None]
    if parametros.dia_local:
        indice_dia = {d: i for i, d in enumerate(buckets)}
        vistos: list[set] = [set() for _ in range(n)]
        sql_disp = f"SELECT ts, ip FROM {parametros.tabla_disp} WHERE ts >= ?"
        for ts, ip in con.execute(sql_disp, (parametros.desde,)).fetchall():
            dia = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(tz).date()
            i = indice_dia.get(dia)
            if i is not None:
                vistos[i].add(ip)
        disp_vals = [len(s) if s else None for s in vistos]
    else:
        disp_vals = [None] * n
        indice = {b: i for i, b in enumerate(buckets)}
        bucket_expr = f"(ts/{parametros.bucket_s})*{parametros.bucket_s}"
        sql_disp = (
            f"SELECT {bucket_expr} AS bucket, COUNT(DISTINCT ip) FROM {parametros.tabla_disp} "
            "WHERE ts >= ? GROUP BY bucket"
        )
        for bucket, cuenta in con.execute(sql_disp, (parametros.desde,)).fetchall():
            i = indice.get(bucket)
            if i is not None:
                disp_vals[i] = cuenta

    return {
        "etiquetas": [_etiqueta_bucket(b, parametros.bucket_s, tz, parametros.dia_local) for b in buckets],
        "conexiones": conexiones_vals,
        "dispositivos_activos": disp_vals,
        "conexiones_disponible": conexiones_disponible,
    }


def _dns_resumen_dominios(con, desde_hora: int, limite: int = 15) -> tuple[list[dict], list[dict]]:
    """Una sola consulta agrupada por dominio (en vez de dos) para sacar a
    la vez el top de más consultados y el top de más bloqueados."""
    sql = "SELECT dominio, SUM(consultas), SUM(bloqueadas) FROM dns_hora WHERE hora >= ? GROUP BY dominio"
    filas = [(d, c or 0, b or 0) for d, c, b in con.execute(sql, (desde_hora,)).fetchall()]

    top_consultados = sorted(filas, key=lambda f: f[1], reverse=True)[:limite]
    top_bloqueados = sorted((f for f in filas if f[2] > 0), key=lambda f: f[2], reverse=True)[:limite]

    return (
        [{"dominio": d, "consultas": c} for d, c, _ in top_consultados],
        [{"dominio": d, "bloqueadas": b} for d, _, b in top_bloqueados],
    )


def _dns_vs_tiempo(
    con, desde_hora: int, bucket_dns_s: int, ahora: int, tz: ZoneInfo, dia_local: bool = False
) -> dict:
    if dia_local:
        # Igual que el tráfico en 30d: se agrupa por día de calendario LOCAL
        # (no por bloques de 86400s en UTC) para que el cambio de hora no
        # desplace ni junte días.
        dias = _generar_dias_locales(desde_hora, ahora, tz)
        indice = {d: i for i, d in enumerate(dias)}
        n = len(dias)
        consultas = [0] * n
        bloqueadas = [0] * n
        sql = "SELECT hora, SUM(consultas), SUM(bloqueadas) FROM dns_hora WHERE hora >= ? GROUP BY hora"
        for hora, c, b in con.execute(sql, (desde_hora,)).fetchall():
            dia = datetime.fromtimestamp(hora, tz=timezone.utc).astimezone(tz).date()
            i = indice.get(dia)
            if i is not None:
                consultas[i] += c or 0
                bloqueadas[i] += b or 0
        etiquetas = [d.strftime("%d/%m") for d in dias]
        return {"etiquetas": etiquetas, "consultas": consultas, "bloqueadas": bloqueadas}

    bucket_expr = f"(hora/{bucket_dns_s})*{bucket_dns_s}"
    sql = (
        f"SELECT {bucket_expr} AS bucket, SUM(consultas), SUM(bloqueadas) FROM dns_hora "
        "WHERE hora >= ? GROUP BY bucket"
    )
    por_bucket = {b: (c or 0, bl or 0) for b, c, bl in con.execute(sql, (desde_hora,)).fetchall()}

    # Huecos (horas sin ninguna consulta registrada) rellenos a 0 en vez de
    # desaparecer del eje de tiempo -- así la serie no "salta" visualmente.
    buckets = _generar_buckets(desde_hora, ahora, bucket_dns_s)
    consultas = [por_bucket.get(b, (0, 0))[0] for b in buckets]
    bloqueadas = [por_bucket.get(b, (0, 0))[1] for b in buckets]
    etiquetas = [_etiqueta(b, bucket_dns_s, tz) for b in buckets]
    return {"etiquetas": etiquetas, "consultas": consultas, "bloqueadas": bloqueadas}


def _nota_dns(rango: str, desde_hora: int, tz: ZoneInfo) -> str | None:
    """`dns_hora` sólo tiene resolución de una hora: en el rango "1h" la
    ventana de DNS que se puede mostrar es, de hecho, más ancha que la de
    tráfico (desde el inicio de la hora en curso, no desde "hace 60 min").
    Se avisa explícitamente en vez de dejar que parezca el mismo rango."""
    if rango != "1h":
        return None
    hora_local = datetime.fromtimestamp(desde_hora, tz=timezone.utc).astimezone(tz)
    return f"Consultas DNS desde las {hora_local.strftime('%H:%M')} (resolución mínima de una hora)."


def _totales(bytes_totales: dict, dns_vs_tiempo: dict) -> dict:
    bajada = bytes_totales["bajada_bytes"]
    subida = bytes_totales["subida_bytes"]
    consultas = sum(dns_vs_tiempo["consultas"])
    bloqueadas = sum(dns_vs_tiempo["bloqueadas"])
    pct_bloqueado = round(bloqueadas / consultas * 100, 1) if consultas > 0 else None
    return {
        "bajada_bytes": bajada,
        "subida_bytes": subida,
        "bajada_fmt": estado_mod.formatear_bytes(bajada),
        "subida_fmt": estado_mod.formatear_bytes(subida),
        "consultas": consultas,
        "bloqueadas": bloqueadas,
        "pct_bloqueado": pct_bloqueado,
    }


def _calcular(rango: str) -> dict:
    tz = _zona_horaria()
    ahora = int(time.time())

    try:
        parametros = _parametros(rango, ahora)
    except ValueError as exc:
        return _estructura_vacia(rango, str(exc), tz, "error")

    con = _conectar()
    if con is None:
        return _estructura_vacia(rango, "Aún no hay datos de estadísticas.", tz, "sin_datos")

    try:
        if not _version_esquema_valida(con):
            LOG.warning(
                "estadisticas.db (%s): falta meta.version_esquema='1' -- recolector no arrancado o esquema "
                "incompatible; se muestra el panel sin datos.",
                ruta_db(),
            )
            return _estructura_vacia(rango, "Aún no hay datos de estadísticas.", tz, "sin_datos")

        if parametros.dia_local:
            buckets = _generar_dias_locales(parametros.desde, ahora, tz)
            bucket_dns_s = 86400
        else:
            buckets = _generar_buckets(parametros.desde, ahora, parametros.bucket_s)
            bucket_dns_s = max(parametros.bucket_s, 3600)
        desde_hora = (parametros.desde // 3600) * 3600

        trafico, latencia, bytes_totales = _trafico_y_latencia(con, parametros, buckets, tz)
        top_dispositivos = _top_dispositivos(con, parametros)
        actividad = _actividad(con, parametros, buckets, tz)
        dns_top, dns_bloqueados_top = _dns_resumen_dominios(con, desde_hora)
        dns_vs_tiempo = _dns_vs_tiempo(con, desde_hora, bucket_dns_s, ahora, tz, dia_local=parametros.dia_local)
        totales = _totales(bytes_totales, dns_vs_tiempo)
        dns_nota = _nota_dns(rango, desde_hora, tz)
    except Exception:
        LOG.warning("estadisticas.py: fallo leyendo %s para rango=%s", ruta_db(), rango, exc_info=True)
        return _estructura_vacia(rango, "No se pudieron leer las estadísticas ahora mismo.", tz, "error")
    finally:
        con.close()

    return {
        "disponible": True,
        "error": None,
        "estado_vacio": None,
        "rango": rango,
        "zona_horaria": str(tz),
        "generado": datetime.now(timezone.utc).isoformat(),
        "dns_nota": dns_nota,
        "trafico": trafico,
        "latencia": latencia,
        "top_dispositivos": top_dispositivos,
        "actividad": actividad,
        "dns_top": dns_top,
        "dns_bloqueados_top": dns_bloqueados_top,
        "dns_consultas_vs_bloqueadas": dns_vs_tiempo,
        "totales": totales,
    }


def _lock_de(clave: tuple[str, str]) -> threading.Lock:
    with _cache_lock:
        lock = _locks_por_clave.get(clave)
        if lock is None:
            lock = threading.Lock()
            _locks_por_clave[clave] = lock
        return lock


def obtener_estadisticas(rango: str) -> dict:
    """Punto de entrada único: valida `rango` contra la lista blanca, usa una
    caché en memoria con TTL por rango (ver `_CACHE_TTL_S`) y "single
    flight" por clave (un solo hilo recalcula una clave dada a la vez; el
    resto espera y reutiliza el resultado en vez de reabrir la base en
    paralelo), y nunca lanza una excepción por datos ausentes, corruptos o
    vacíos (ver `_calcular`)."""
    if rango not in RANGOS_VALIDOS:
        raise ValueError(f"rango no válido: {rango!r}")

    clave = (ruta_db(), rango)

    def _desde_cache() -> dict | None:
        entrada = _cache.get(clave)
        if entrada is not None and (time.monotonic() - entrada[0]) < entrada[2]:
            return entrada[1]
        return None

    with _cache_lock:
        resultado = _desde_cache()
    if resultado is not None:
        return resultado

    with _lock_de(clave):
        with _cache_lock:
            resultado = _desde_cache()
        if resultado is not None:
            return resultado

        resultado = _calcular(rango)
        ttl_usado = _TTL_ERROR_S if resultado.get("estado_vacio") == "error" else _CACHE_TTL_S[rango]

        with _cache_lock:
            _cache[clave] = (time.monotonic(), resultado, ttl_usado)
        return resultado
