from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest
from conftest import login

from routerpanel import estadisticas as estadisticas_mod

WAN1 = "R58M123ABC"
WAN2 = "R58M456DEF"

ESQUEMA = """
CREATE TABLE trafico_wan(
    ts INTEGER, wan TEXT, nombre TEXT, rx_bytes INTEGER, tx_bytes INTEGER,
    latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER,
    PRIMARY KEY(ts, wan)
);
CREATE TABLE trafico_wan_hora(
    ts INTEGER, wan TEXT, nombre TEXT, rx_bytes INTEGER, tx_bytes INTEGER,
    latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER,
    PRIMARY KEY(ts, wan)
);
CREATE TABLE trafico_disp(
    ts INTEGER, ip TEXT, mac TEXT, nombre TEXT, bajada_bytes INTEGER,
    subida_bytes INTEGER, conexiones INTEGER,
    PRIMARY KEY(ts, ip)
);
CREATE TABLE trafico_disp_hora(
    ts INTEGER, ip TEXT, mac TEXT, nombre TEXT, bajada_bytes INTEGER,
    subida_bytes INTEGER, conexiones INTEGER,
    PRIMARY KEY(ts, ip)
);
CREATE TABLE conexiones(ts INTEGER PRIMARY KEY, total INTEGER);
CREATE TABLE dns_hora(
    hora INTEGER, cliente TEXT, dominio TEXT, consultas INTEGER, bloqueadas INTEGER,
    PRIMARY KEY(hora, cliente, dominio)
);
CREATE TABLE meta(clave TEXT PRIMARY KEY, valor TEXT);
"""


def _crear_esquema(ruta, con_version: bool = True) -> sqlite3.Connection:
    """Crea el esquema exacto del contrato. Por defecto incluye
    `meta.version_esquema = '1'` (lo que escribiría un recolector real recién
    arrancado); los tests que quieren probar el caso "sin versión válida"
    pasan `con_version=False`."""
    con = sqlite3.connect(str(ruta))
    con.executescript(ESQUEMA)
    if con_version:
        con.execute("INSERT INTO meta VALUES ('version_esquema', '1')")
    con.commit()
    return con


def _poblar_basica(con: sqlite3.Connection, ahora: int, nombre_malicioso: str | None = None) -> None:
    """Datos suficientes para que los 4 rangos (1h/24h/7d/30d) devuelvan
    algo: minutos recientes (<48h) y horas de los últimos ~10 días."""
    minuto = (ahora // 60) * 60
    hora = (ahora // 3600) * 3600

    nombre_disp = nombre_malicioso or "portatil-salon"

    filas_wan_min = []
    filas_disp_min = []
    filas_con_min = []
    for i in range(80):  # 80 minutos hacia atrás: cubre de sobra el rango 1h
        ts = minuto - i * 60
        filas_wan_min.append((ts, WAN1, "WAN1", 1_000_000 + i * 1000, 200_000 + i * 100, 45.0 + (i % 5), 0.0, 1))
        filas_wan_min.append((ts, WAN2, "WAN2", 500_000, 100_000, 90.0, 1.0, 0))
        filas_disp_min.append((ts, "192.168.50.10", "aa:bb:cc:dd:ee:01", nombre_disp, 50_000, 10_000, 3))
        filas_disp_min.append((ts, "192.168.50.11", "aa:bb:cc:dd:ee:02", "movil-2", 20_000, 5_000, 1))
        filas_con_min.append((ts, 12 + (i % 4)))

    con.executemany("INSERT OR REPLACE INTO trafico_wan VALUES (?,?,?,?,?,?,?,?)", filas_wan_min)
    con.executemany("INSERT OR REPLACE INTO trafico_disp VALUES (?,?,?,?,?,?,?)", filas_disp_min)
    con.executemany("INSERT OR REPLACE INTO conexiones VALUES (?,?)", filas_con_min)

    filas_wan_hora = []
    filas_disp_hora = []
    filas_dns = []
    for i in range(24 * 10):  # 10 días de horas: cubre 7d y 30d (parcial)
        ts = hora - i * 3600
        filas_wan_hora.append((ts, WAN1, "WAN1", 60_000_000, 12_000_000, 48.0, 0.0, 1))
        filas_wan_hora.append((ts, WAN2, "WAN2", 30_000_000, 6_000_000, 95.0, 1.5, 0))
        filas_disp_hora.append((ts, "192.168.50.10", "aa:bb:cc:dd:ee:01", nombre_disp, 3_000_000, 600_000, 180))
        filas_disp_hora.append((ts, "192.168.50.11", "aa:bb:cc:dd:ee:02", "movil-2", 1_000_000, 300_000, 60))
        filas_dns.append((ts, "192.168.50.10", "ejemplo.com", 40, 0))
        filas_dns.append((ts, "192.168.50.10", "anuncios-molestos.test", 15, 15))
        filas_dns.append((ts, "192.168.50.11", "api.ejemplo.com", 10, 0))

    con.executemany("INSERT OR REPLACE INTO trafico_wan_hora VALUES (?,?,?,?,?,?,?,?)", filas_wan_hora)
    con.executemany("INSERT OR REPLACE INTO trafico_disp_hora VALUES (?,?,?,?,?,?,?)", filas_disp_hora)
    con.executemany("INSERT OR REPLACE INTO dns_hora VALUES (?,?,?,?,?)", filas_dns)
    con.commit()


@pytest.fixture
def db_estadisticas(entorno, tmp_path, monkeypatch):
    ruta = tmp_path / "estadisticas.db"
    con = _crear_esquema(ruta)
    _poblar_basica(con, int(time.time()))
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    estadisticas_mod._cache.clear()
    return ruta


def _login_admin(cliente):
    return login(cliente, "admin", "contrasena-admin-1")


def _limpiar_cache():
    estadisticas_mod._cache.clear()
    estadisticas_mod._locks_por_clave.clear()


# ---------- forma esperada por rango (vía HTTP) ----------

CLAVES_RAIZ = {
    "disponible", "error", "estado_vacio", "rango", "zona_horaria", "generado", "dns_nota",
    "trafico", "latencia", "top_dispositivos", "actividad", "dns_top", "dns_bloqueados_top",
    "dns_consultas_vs_bloqueadas", "totales",
}


@pytest.mark.parametrize("rango", ["1h", "24h", "7d", "30d"])
def test_cada_rango_devuelve_la_forma_esperada(db_estadisticas, cliente, rango):
    _login_admin(cliente)
    resp = cliente.get(f"/dashboard/estadisticas.json?rango={rango}")
    assert resp.status_code == 200
    datos = resp.get_json()

    assert set(datos.keys()) == CLAVES_RAIZ
    assert datos["disponible"] is True
    assert datos["estado_vacio"] is None
    assert datos["rango"] == rango
    assert "zona_horaria" in datos

    assert set(datos["trafico"].keys()) == {"etiquetas", "series"}
    assert len(datos["trafico"]["series"]) >= 1
    for serie in datos["trafico"]["series"]:
        assert len(serie["bajada_mbps"]) == len(datos["trafico"]["etiquetas"])
        assert len(serie["subida_mbps"]) == len(datos["trafico"]["etiquetas"])

    assert set(datos["latencia"].keys()) == {"etiquetas", "series"}

    assert isinstance(datos["top_dispositivos"], list)
    assert len(datos["top_dispositivos"]) <= 10
    for d in datos["top_dispositivos"]:
        assert set(d.keys()) >= {"ip", "mac", "nombre", "bajada_bytes", "subida_bytes", "bajada_fmt", "subida_fmt"}

    assert set(datos["actividad"].keys()) == {"etiquetas", "conexiones", "dispositivos_activos", "conexiones_disponible"}
    assert datos["actividad"]["conexiones_disponible"] == (rango in ("1h", "24h"))

    assert isinstance(datos["dns_top"], list)
    assert len(datos["dns_top"]) <= 15
    assert isinstance(datos["dns_bloqueados_top"], list)
    assert len(datos["dns_bloqueados_top"]) <= 15

    assert set(datos["dns_consultas_vs_bloqueadas"].keys()) == {"etiquetas", "consultas", "bloqueadas"}
    serie_dns = datos["dns_consultas_vs_bloqueadas"]
    assert len(serie_dns["consultas"]) == len(serie_dns["etiquetas"])
    assert len(serie_dns["bloqueadas"]) == len(serie_dns["etiquetas"])

    if rango == "1h":
        assert datos["dns_nota"] is not None
        assert "DNS" in datos["dns_nota"].upper()
    else:
        assert datos["dns_nota"] is None

    totales = datos["totales"]
    assert set(totales.keys()) == {
        "bajada_bytes", "subida_bytes", "bajada_fmt", "subida_fmt",
        "consultas", "bloqueadas", "pct_bloqueado",
    }
    assert totales["bajada_bytes"] >= 0
    assert totales["consultas"] >= 0
    # Los totales de DNS deben coincidir con sumar la propia serie (misma
    # fuente, sin una segunda consulta que pueda desincronizarse).
    assert totales["consultas"] == sum(serie_dns["consultas"])
    assert totales["bloqueadas"] == sum(serie_dns["bloqueadas"])


def test_hay_datos_reales_en_1h(db_estadisticas, cliente):
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=1h")
    datos = resp.get_json()
    assert len(datos["trafico"]["etiquetas"]) > 0
    nombres_wan = {s["nombre"] for s in datos["trafico"]["series"]}
    assert "WAN1" in nombres_wan
    assert datos["totales"]["bajada_bytes"] > 0
    assert len(datos["top_dispositivos"]) > 0
    assert datos["top_dispositivos"][0]["bajada_bytes"] >= datos["top_dispositivos"][-1]["bajada_bytes"]


def test_dns_bloqueados_solo_incluye_dominios_con_bloqueos(db_estadisticas, cliente):
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=7d")
    datos = resp.get_json()
    dominios_bloqueados = {d["dominio"] for d in datos["dns_bloqueados_top"]}
    assert "anuncios-molestos.test" in dominios_bloqueados
    assert "ejemplo.com" not in dominios_bloqueados  # nunca se bloqueó


def test_conexiones_no_disponible_mas_alla_de_48h(db_estadisticas, cliente):
    _login_admin(cliente)
    for rango in ("7d", "30d"):
        resp = cliente.get(f"/dashboard/estadisticas.json?rango={rango}")
        datos = resp.get_json()
        assert datos["actividad"]["conexiones_disponible"] is False
    for rango in ("1h", "24h"):
        resp = cliente.get(f"/dashboard/estadisticas.json?rango={rango}")
        datos = resp.get_json()
        assert datos["actividad"]["conexiones_disponible"] is True


# ---------- tolerancia a base ausente/corrupta/vacía/esquema inválido ----------

def test_rango_invalido_devuelve_400(entorno, cliente):
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=10y")
    assert resp.status_code == 400


def test_base_ausente_json_devuelve_200_vacio(entorno, monkeypatch, tmp_path, cliente):
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(tmp_path / "no-existe.db"))
    _limpiar_cache()
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 200
    datos = resp.get_json()
    assert datos["disponible"] is False
    assert datos["estado_vacio"] == "sin_datos"
    assert datos["trafico"]["series"] == []
    assert datos["top_dispositivos"] == []


def test_base_ausente_dashboard_devuelve_200(entorno, monkeypatch, tmp_path, cliente):
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(tmp_path / "no-existe.db"))
    _limpiar_cache()
    _login_admin(cliente)
    resp = cliente.get("/")
    assert resp.status_code == 200
    assert b"tt-estadisticas" in resp.data


def test_base_corrupta_devuelve_200_vacio(entorno, monkeypatch, tmp_path, cliente):
    ruta = tmp_path / "corrupta.db"
    ruta.write_text("esto no es una base sqlite", encoding="utf-8")
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 200
    datos = resp.get_json()
    assert datos["disponible"] is False
    assert datos["estado_vacio"] in ("sin_datos", "error")


def test_base_con_esquema_pero_sin_filas_devuelve_200_vacio(entorno, monkeypatch, tmp_path, cliente):
    ruta = tmp_path / "vacia.db"
    con = _crear_esquema(ruta)  # incluye meta.version_esquema='1' por defecto
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 200
    datos = resp.get_json()
    # Conecta bien, el esquema es válido, consulta bien, pero no hay filas:
    # "disponible" sigue en True (la base funciona) con listas vacías.
    assert datos["disponible"] is True
    assert datos["estado_vacio"] is None
    assert datos["trafico"]["series"] == []
    assert datos["top_dispositivos"] == []
    assert datos["totales"]["bajada_bytes"] == 0
    assert datos["totales"]["pct_bloqueado"] is None


def test_meta_version_esquema_ausente_da_sin_datos(entorno, monkeypatch, tmp_path, cliente, caplog):
    ruta = tmp_path / "sin_version.db"
    con = _crear_esquema(ruta, con_version=False)  # sin meta.version_esquema
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()
    _login_admin(cliente)
    with caplog.at_level("WARNING", logger="routerpanel.estadisticas"):
        resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 200
    datos = resp.get_json()
    assert datos["disponible"] is False
    assert datos["estado_vacio"] == "sin_datos"
    assert any("version_esquema" in r.message for r in caplog.records)


def test_meta_version_esquema_incorrecta_da_sin_datos(entorno, monkeypatch, tmp_path, cliente):
    ruta = tmp_path / "version_mala.db"
    con = _crear_esquema(ruta, con_version=False)
    con.execute("INSERT INTO meta VALUES ('version_esquema', '2')")
    con.commit()
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    datos = resp.get_json()
    assert datos["disponible"] is False
    assert datos["estado_vacio"] == "sin_datos"


def test_base_con_esquema_valido_pero_tabla_rota_da_error_no_sin_datos(entorno, monkeypatch, tmp_path, cliente, caplog):
    """A diferencia del esquema ausente/mal versionado (`sin_datos`), si la
    versión es válida pero una consulta revienta de verdad (p. ej. falta una
    tabla que debería existir) se distingue como `error` -- caso distinto,
    texto distinto en la UI."""
    ruta = tmp_path / "rota.db"
    con = sqlite3.connect(str(ruta))
    con.execute(
        "CREATE TABLE trafico_wan(ts INTEGER, wan TEXT, nombre TEXT, rx_bytes INTEGER, "
        "tx_bytes INTEGER, latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER, PRIMARY KEY(ts, wan))"
    )
    con.execute("CREATE TABLE meta(clave TEXT PRIMARY KEY, valor TEXT)")
    con.execute("INSERT INTO meta VALUES ('version_esquema', '1')")
    # trafico_disp, conexiones, dns_hora... no existen: cualquier consulta
    # posterior a _trafico_y_latencia debe fallar.
    con.commit()
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()
    _login_admin(cliente)
    with caplog.at_level("WARNING", logger="routerpanel.estadisticas"):
        resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 200
    datos = resp.get_json()
    assert datos["disponible"] is False
    assert datos["estado_vacio"] == "error"
    assert datos["error"] != "Aún no hay datos de estadísticas."
    assert any("fallo leyendo" in r.message for r in caplog.records)


# ---------- login requerido ----------

def test_estadisticas_json_requiere_login(entorno, cliente):
    resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# ---------- escapado / seguridad ----------

def test_nombre_malicioso_no_se_refleja_sin_escapar_en_el_html(entorno, tmp_path, monkeypatch, cliente):
    ruta = tmp_path / "estadisticas.db"
    con = _crear_esquema(ruta)
    nombre_malicioso = "<script>alert(1)</script>"
    _poblar_basica(con, int(time.time()), nombre_malicioso=nombre_malicioso)
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()

    _login_admin(cliente)

    resp_html = cliente.get("/")
    assert resp_html.status_code == 200
    assert b"<script>alert(1)</script>" not in resp_html.data

    resp_json = cliente.get("/dashboard/estadisticas.json?rango=24h")
    datos = resp_json.get_json()
    nombres = {d["nombre"] for d in datos["top_dispositivos"]}
    assert nombre_malicioso in nombres  # el dato llega intacto en JSON (seguro: no es HTML)


def test_consultas_parametrizadas_no_rompen_con_caracteres_especiales(db_estadisticas, cliente):
    """El propio endpoint sólo acepta `rango` de una lista blanca, así que no
    hay ninguna entrada de usuario que llegue al SQL; esta prueba comprueba
    que intentar "inyectar" algo por ahí no cuela (400) y no revienta nada."""
    _login_admin(cliente)
    for intento in ["1h'; DROP TABLE trafico_wan; --", "24h OR 1=1", "../../etc/passwd"]:
        resp = cliente.get("/dashboard/estadisticas.json", query_string={"rango": intento})
        assert resp.status_code == 400

    resp_ok = cliente.get("/dashboard/estadisticas.json?rango=1h")
    assert resp_ok.status_code == 200
    assert resp_ok.get_json()["disponible"] is True


# ---------- caché: TTL por rango + single-flight ----------

def test_cache_ttl_por_rango():
    assert estadisticas_mod._CACHE_TTL_S == {"1h": 30.0, "24h": 60.0, "7d": 300.0, "30d": 300.0}


def test_cache_evita_reabrir_la_base_dentro_del_ttl(db_estadisticas, monkeypatch):
    primero = estadisticas_mod.obtener_estadisticas("1h")
    llamadas = {"n": 0}
    original = estadisticas_mod._calcular

    def contador(rango):
        llamadas["n"] += 1
        return original(rango)

    monkeypatch.setattr(estadisticas_mod, "_calcular", contador)
    segundo = estadisticas_mod.obtener_estadisticas("1h")
    assert llamadas["n"] == 0  # servido desde caché, no se recalculó
    assert segundo == primero


def test_cache_single_flight_una_sola_llamada_concurrente(db_estadisticas, monkeypatch):
    """Dos hilos piden el mismo rango a la vez justo después de limpiar la
    caché: sólo uno debe calcularlo de verdad; el resto espera y reutiliza
    el resultado en vez de reabrir la base en paralelo."""
    _limpiar_cache()
    llamadas = {"n": 0}
    original = estadisticas_mod._calcular

    def lento(rango):
        llamadas["n"] += 1
        time.sleep(0.15)
        return original(rango)

    monkeypatch.setattr(estadisticas_mod, "_calcular", lento)

    resultados = []

    def trabajador():
        resultados.append(estadisticas_mod.obtener_estadisticas("24h"))

    hilos = [threading.Thread(target=trabajador) for _ in range(4)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join(timeout=5)

    assert llamadas["n"] == 1
    assert len(resultados) == 4
    assert all(r == resultados[0] for r in resultados)


# ---------- lógica nueva: cobertura real de los buckets ----------

def test_bucket_incompleto_no_sale_con_caida_artificial(tmp_path):
    """Si un bucket de 5 min sólo tiene 2 de las 5 filas por minuto que le
    corresponderían (el primero del rango, o el que está en curso), el
    Mbit/s debe calcularse dividiendo por los segundos REALMENTE cubiertos
    (2*60=120s), no por el ancho nominal del bucket (300s) -- si no, saldría
    una caída artificial de ~60% sin que haya pasado nada."""
    ruta = tmp_path / "cobertura.db"
    con = _crear_esquema(ruta)

    base_ts = 1_700_000_000
    base_ts = (base_ts // 300) * 300  # alineado a un bucket de 5 min

    filas = []
    # bucket 0: 5 minutos completos, 10000 bytes/min cada uno
    for m in range(5):
        filas.append((base_ts + m * 60, WAN1, "WAN1", 10000, 2000, 10.0, 0.0, 1))
    # bucket 1: sólo 2 de los 5 minutos (p. ej. el bucket en curso)
    for m in range(2):
        filas.append((base_ts + 300 + m * 60, WAN1, "WAN1", 10000, 2000, 10.0, 0.0, 1))
    con.executemany("INSERT INTO trafico_wan VALUES (?,?,?,?,?,?,?,?)", filas)
    con.commit()

    parametros = estadisticas_mod._ParamRango("trafico_wan", "trafico_disp", 300, base_ts, 60)
    buckets = [base_ts, base_ts + 300]
    tz = ZoneInfo("Europe/Rome")

    trafico, _, _ = estadisticas_mod._trafico_y_latencia(con, parametros, buckets, tz)
    con.close()

    serie = trafico["series"][0]
    bajada_bucket_completo = serie["bajada_mbps"][0]
    bajada_bucket_incompleto = serie["bajada_mbps"][1]

    assert bajada_bucket_completo is not None
    assert bajada_bucket_incompleto is not None
    # Misma tasa (bytes/segundo cubierto) en los dos buckets: el incompleto
    # NO debe salir más bajo sólo por tener menos filas.
    assert bajada_bucket_incompleto == pytest.approx(bajada_bucket_completo, rel=1e-6)


# ---------- lógica nueva: 30d agrupa por día de calendario LOCAL (DST-safe) ----------

def test_30d_agrupa_por_dia_local_respetando_el_cambio_de_hora(tmp_path):
    """27 de octubre de 2024 es el día en que Europe/Rome vuelve de verano a
    invierno (un día de 25 horas en hora local). Agregar por bloques UTC de
    86400s partiría o fusionaría mal ese día; agregando por fecha de
    calendario local debe salir exactamente UN bucket para esa fecha, con
    las 25 horas correctamente promediadas (no como caída de tasa)."""
    tz = ZoneInfo("Europe/Rome")
    ruta = tmp_path / "dst.db"
    con = _crear_esquema(ruta)

    inicio_local = datetime(2024, 10, 26, 0, 0, tzinfo=tz)
    fin_local = datetime(2024, 10, 28, 0, 0, tzinfo=tz)
    desde = int(inicio_local.timestamp())
    ahora = int(fin_local.timestamp())

    filas = []
    ts = desde
    # 450_000_000 bytes/hora exactos -> 1,0 Mbit/s de media sea cual sea el
    # número de horas reales que tenga el día (23, 24 ó 25):
    # 450_000_000 B * 8 / 3600 s / 1e6 = 1,0 Mbit/s.
    while ts < ahora:
        filas.append((ts, WAN1, "WAN1", 450_000_000, 450_000_000, 20.0, 0.0, 1))
        ts += 3600
    con.executemany("INSERT INTO trafico_wan_hora VALUES (?,?,?,?,?,?,?,?)", filas)
    con.commit()

    dias = estadisticas_mod._generar_dias_locales(desde, ahora, tz)
    fechas = [d.isoformat() for d in dias]
    assert "2024-10-26" in fechas
    assert "2024-10-27" in fechas
    assert "2024-10-28" in fechas
    assert len(fechas) == len(set(fechas))  # ningún día duplicado

    parametros = estadisticas_mod._ParamRango(
        "trafico_wan_hora", "trafico_disp_hora", 86400, desde, 3600, dia_local=True
    )
    trafico, _, _ = estadisticas_mod._trafico_y_latencia(con, parametros, dias, tz)
    con.close()

    serie = trafico["series"][0]
    i_27 = fechas.index("2024-10-27")
    # Pese a tener 25 filas (una hora más que un día normal), la media sigue
    # siendo 1,0 Mbit/s: la cobertura real (25*3600 s) se usa como divisor.
    assert serie["bajada_mbps"][i_27] == pytest.approx(1.0, rel=1e-3)


# ---------- lógica nueva: huecos de la serie DNS rellenos a 0 ----------

def test_dns_huecos_rellenos_a_cero(tmp_path):
    ruta = tmp_path / "dns_huecos.db"
    con = _crear_esquema(ruta)

    hora_base = (1_700_000_000 // 3600) * 3600
    # Sólo se escribe la hora 0 y la hora 3 de una ventana de 4 horas: las
    # horas 1 y 2 deben aparecer igualmente en la serie, con 0 consultas.
    con.execute("INSERT INTO dns_hora VALUES (?,?,?,?,?)", (hora_base, "192.168.50.10", "a.test", 10, 2))
    con.execute("INSERT INTO dns_hora VALUES (?,?,?,?,?)", (hora_base + 3 * 3600, "192.168.50.10", "a.test", 7, 0))
    con.commit()

    tz = ZoneInfo("Europe/Rome")
    ahora = hora_base + 4 * 3600
    serie = estadisticas_mod._dns_vs_tiempo(con, hora_base, 3600, ahora, tz)
    con.close()

    # _generar_buckets incluye también el bucket en curso (el que contiene
    # "ahora"), así que una ventana de 4h completas da 5 buckets.
    assert len(serie["etiquetas"]) == 5
    assert serie["consultas"] == [10, 0, 0, 7, 0]
    assert serie["bloqueadas"] == [2, 0, 0, 0, 0]


# ---------- lógica nueva: una sola consulta para los dos "top dominios" ----------

def test_dns_resumen_dominios_una_sola_consulta(tmp_path, monkeypatch):
    ruta = tmp_path / "dns_resumen.db"
    con = _crear_esquema(ruta)
    hora = (1_700_000_000 // 3600) * 3600
    con.execute("INSERT INTO dns_hora VALUES (?,?,?,?,?)", (hora, "c1", "muy-visitado.test", 100, 0))
    con.execute("INSERT INTO dns_hora VALUES (?,?,?,?,?)", (hora, "c1", "bloqueado.test", 5, 5))
    con.commit()

    ejecuciones = []

    def rastrear(sql):
        if "dns_hora" in sql and "GROUP BY dominio" in sql:
            ejecuciones.append(sql)

    con.set_trace_callback(rastrear)
    top, bloqueados = estadisticas_mod._dns_resumen_dominios(con, hora)
    con.set_trace_callback(None)
    con.close()

    assert len(ejecuciones) == 1  # una sola consulta agrupada, no dos
    assert top[0]["dominio"] == "muy-visitado.test"
    assert bloqueados[0]["dominio"] == "bloqueado.test"


# ---------- lógica nueva: fusión de la hora en curso (7d/30d) desde la tabla por minuto ----------

def test_top_dispositivos_fusiona_hora_en_curso_desde_tabla_por_minuto(tmp_path):
    ruta = tmp_path / "fusion.db"
    con = _crear_esquema(ruta)

    ahora = int(time.time())
    inicio_hora_actual = (ahora // 3600) * 3600
    hora_pasada = inicio_hora_actual - 3600

    # trafico_disp_hora: sólo tiene la hora YA CERRADA (la actual todavía no
    # se ha volcado).
    con.execute(
        "INSERT INTO trafico_disp_hora VALUES (?,?,?,?,?,?,?)",
        (hora_pasada, "192.168.50.50", "aa:aa:aa:aa:aa:aa", "viejo", 1000, 500, 10),
    )
    # trafico_disp (minuto): un dispositivo que sólo existe en la hora en
    # curso -- debe aparecer igualmente en el top.
    con.execute(
        "INSERT INTO trafico_disp VALUES (?,?,?,?,?,?,?)",
        (inicio_hora_actual + 30, "192.168.50.60", "bb:bb:bb:bb:bb:bb", "nuevo-ahora-mismo", 999999, 1, 1),
    )
    con.commit()

    parametros = estadisticas_mod._ParamRango(
        "trafico_wan_hora", "trafico_disp_hora", 3600, hora_pasada, 3600
    )
    resultado = estadisticas_mod._top_dispositivos(con, parametros)
    con.close()

    ips = {d["ip"] for d in resultado}
    assert "192.168.50.60" in ips  # el de la hora en curso se fusionó


# ---------- rendimiento: no hay más tablas de las necesarias ----------

def test_dns_por_dispositivo_eliminado_por_no_usarse(db_estadisticas, cliente):
    _login_admin(cliente)
    resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    datos = resp.get_json()
    assert "dns_por_dispositivo" not in datos


# ---------- ronda 2 de revisión: fusión de la hora en curso también en 30d ----------

def test_trafico_30d_fusiona_hora_en_curso_en_el_dia_local(tmp_path):
    """La fusión de la hora en curso (ver `_trafico_y_latencia`) antes sólo
    miraba el día ENTERO (`i_ultimo`) y sólo corría en la rama no-dia_local,
    así que 30d nunca se beneficiaba de ella. Ahora corre igual para 7d y
    30d, mirando sólo la hora en curso (como `_top_dispositivos`)."""
    ruta = tmp_path / "fusion_30d.db"
    con = _crear_esquema(ruta)

    tz = ZoneInfo("Europe/Rome")
    ahora_real = int(time.time())
    inicio_hora_actual = (ahora_real // 3600) * 3600
    hora_pasada = inicio_hora_actual - 48 * 3600  # claramente otro día

    # trafico_wan_hora: sólo tiene datos de hace 2 días (nada de la hora en curso).
    con.execute(
        "INSERT INTO trafico_wan_hora VALUES (?,?,?,?,?,?,?,?)",
        (hora_pasada, WAN1, "WAN1", 1000, 500, 10.0, 0.0, 1),
    )
    # trafico_wan (minuto): sí tiene datos de la hora en curso.
    con.execute(
        "INSERT INTO trafico_wan VALUES (?,?,?,?,?,?,?,?)",
        (inicio_hora_actual + 30, WAN1, "WAN1", 450_000_000, 450_000_000, 20.0, 0.0, 1),
    )
    con.commit()

    desde = hora_pasada
    dias = estadisticas_mod._generar_dias_locales(desde, ahora_real, tz)
    parametros = estadisticas_mod._ParamRango(
        "trafico_wan_hora", "trafico_disp_hora", 86400, desde, 3600, dia_local=True
    )
    trafico, _, _ = estadisticas_mod._trafico_y_latencia(con, parametros, dias, tz)
    con.close()

    hoy_local = datetime.fromtimestamp(ahora_real, tz=timezone.utc).astimezone(tz).date()
    i_hoy = dias.index(hoy_local)
    serie = trafico["series"][0]
    assert serie["bajada_mbps"][i_hoy] is not None
    assert serie["bajada_mbps"][i_hoy] > 0


# ---------- ronda 2: DNS en 30d también agrupa por día LOCAL ----------

def test_dns_30d_agrupa_por_dia_local_respetando_el_cambio_de_hora(tmp_path):
    tz = ZoneInfo("Europe/Rome")
    ruta = tmp_path / "dns_dst.db"
    con = _crear_esquema(ruta)

    inicio_local = datetime(2024, 10, 26, 0, 0, tzinfo=tz)
    fin_local = datetime(2024, 10, 28, 0, 0, tzinfo=tz)
    desde = int(inicio_local.timestamp())
    ahora = int(fin_local.timestamp())

    ts = desde
    while ts < ahora:
        con.execute("INSERT INTO dns_hora VALUES (?,?,?,?,?)", (ts, "192.168.50.10", "a.test", 10, 1))
        ts += 3600
    con.commit()

    serie = estadisticas_mod._dns_vs_tiempo(con, desde, 86400, ahora, tz, dia_local=True)
    con.close()

    fechas = serie["etiquetas"]
    assert len(fechas) == 3  # 26, 27, 28 -- ningún día duplicado ni perdido
    i_27 = fechas.index("27/10")
    # 25 horas ese día (DST, vuelta de verano a invierno), 10 consultas cada
    # una -> 250 consultas, no 240 (perdiendo una hora) ni partido en dos días.
    assert serie["consultas"][i_27] == 250
    assert serie["bloqueadas"][i_27] == 25


# ---------- ronda 2: un resultado "error" se cachea poco tiempo ----------

def test_resultado_error_se_cachea_poco_tiempo(tmp_path, monkeypatch):
    ruta = tmp_path / "rota_cache.db"
    con = sqlite3.connect(str(ruta))
    con.execute("CREATE TABLE meta(clave TEXT PRIMARY KEY, valor TEXT)")
    con.execute("INSERT INTO meta VALUES ('version_esquema', '1')")
    # Sin trafico_wan ni el resto de tablas: cualquier consulta posterior revienta.
    con.commit()
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()

    resultado = estadisticas_mod.obtener_estadisticas("30d")
    assert resultado["estado_vacio"] == "error"

    clave = (str(ruta), "30d")
    entrada = estadisticas_mod._cache[clave]
    assert entrada[2] == estadisticas_mod._TTL_ERROR_S
    assert entrada[2] < estadisticas_mod._CACHE_TTL_S["30d"]


# ---------- ronda 2: excepción leyendo meta (error) vs versión distinta (sin_datos) ----------

def test_meta_tabla_ausente_es_error_no_sin_datos(entorno, monkeypatch, tmp_path, cliente, caplog):
    """Si la tabla `meta` ni siquiera existe, leerla lanza `sqlite3.Error`:
    eso es un fallo de lectura real (`error`), distinto de "la fila/versión
    no es la soportada" (`sin_datos`, ver los dos tests de más arriba)."""
    ruta = tmp_path / "sin_tabla_meta.db"
    esquema_sin_meta = ESQUEMA.split("CREATE TABLE meta")[0]
    con = sqlite3.connect(str(ruta))
    con.executescript(esquema_sin_meta)
    con.commit()
    con.close()
    monkeypatch.setenv("ROUTER_ESTADISTICAS_DB", str(ruta))
    _limpiar_cache()
    _login_admin(cliente)
    with caplog.at_level("WARNING", logger="routerpanel.estadisticas"):
        resp = cliente.get("/dashboard/estadisticas.json?rango=24h")
    assert resp.status_code == 200
    datos = resp.get_json()
    assert datos["disponible"] is False
    assert datos["estado_vacio"] == "error"
    assert any("fallo leyendo" in r.message for r in caplog.records)
