from __future__ import annotations

import json

from routerpanel import estado as estado_mod


def test_formatear_uptime_dias_horas_minutos():
    # 1 d 1 h 29 min, como en el ejemplo de la petición original.
    assert estado_mod.formatear_uptime(91738) == "1 d 1 h 29 min"


def test_formatear_uptime_solo_minutos():
    assert estado_mod.formatear_uptime(90) == "2 min"


def test_formatear_uptime_sin_datos():
    assert estado_mod.formatear_uptime(None) == "—"


def test_formatear_bitrate_bit_s():
    assert estado_mod.formatear_bitrate(364) == "364 bit/s"


def test_formatear_bitrate_kbit_s():
    assert estado_mod.formatear_bitrate(1500) == "1,5 kbit/s"


def test_formatear_bitrate_mbit_s():
    assert estado_mod.formatear_bitrate(2300000) == "2,3 Mbit/s"


def test_formatear_bytes_pequeno():
    assert estado_mod.formatear_bytes(512) == "512 B"


def test_formatear_bytes_mb():
    assert estado_mod.formatear_bytes(3 * 1024 * 1024) == "3,0 MB"


def test_formatear_servicios_activo_siempre_verde():
    servicios = {"dnsmasq": "active", "nftables_router": False}
    resultado = {s["clave"]: s for s in estado_mod.formatear_servicios(servicios, "preparacion")}
    assert resultado["dnsmasq"]["color"] == "ok"
    assert resultado["dnsmasq"]["etiqueta"] == "DHCP/DNS (dnsmasq)"
    assert resultado["dnsmasq"]["texto"] == "activo"


def test_formatear_servicios_inactivo_gris_en_preparacion():
    servicios = {"nftables_router": False}
    resultado = estado_mod.formatear_servicios(servicios, "preparacion")
    assert resultado[0]["color"] == "gris"
    assert resultado[0]["etiqueta"] == "Cortafuegos"


def test_formatear_servicios_inactivo_rojo_en_produccion():
    servicios = {"nftables_router": False}
    resultado = estado_mod.formatear_servicios(servicios, "produccion")
    assert resultado[0]["color"] == "error"


def test_contexto_validacion_usa_config_lan_cuando_existe():
    est = estado_mod.Estado(
        disponible=True,
        lan={"interfaz": "enp2s0", "ip": None, "activa": False},
        config={"lan": {"interfaz": "enp2s0", "red": "192.168.50.0/24", "ip": "192.168.50.1"}, "reservas": []},
        wans=[],
    )
    contexto = estado_mod.contexto_validacion(est)
    assert contexto["lan_red"] == "192.168.50.0/24"
    assert contexto["lan_ip_router"] == "192.168.50.1"


def test_leer_oplog_no_lee_fichero_entero_solo_la_cola(entorno):
    """El oplog puede crecer sin límite: `leer_oplog` no debe leerlo entero,
    sólo los últimos `limite_bytes` (por defecto ~256 KiB) desde el final."""
    oplog_path = entorno["oplog_path"]

    primera_operacion = json.dumps({"usuario": "viejo", "accion": "modo", "ok": True, "mensaje": "muy vieja"})
    relleno = "\n".join(
        json.dumps({"usuario": "relleno", "accion": "ping", "ok": True, "mensaje": "x" * 200})
        for _ in range(2000)
    )
    ultima_operacion = json.dumps({"usuario": "nuevo", "accion": "modo", "ok": True, "mensaje": "la mas reciente"})
    contenido = primera_operacion + "\n" + relleno + "\n" + ultima_operacion + "\n"
    oplog_path.write_text(contenido, encoding="utf-8")

    tamano_total = oplog_path.stat().st_size
    assert tamano_total > 256 * 1024  # el fichero de prueba es más grande que el límite

    operaciones, error = estado_mod.leer_oplog(limite=5000, limite_bytes=256 * 1024)
    assert error is None
    # La operación más reciente (al final del fichero) debe estar presente...
    assert operaciones[0]["usuario"] == "nuevo"
    # ...pero la primera (al principio, fuera de la ventana de 256 KiB) no.
    assert all(op["usuario"] != "viejo" for op in operaciones)


def test_leer_oplog_descarta_linea_truncada_al_principio_de_la_ventana(entorno):
    """La línea que queda a medias justo donde empieza la ventana leída no
    debe intentar parsearse (y produciría un JSON inválido si se intentara)."""
    oplog_path = entorno["oplog_path"]
    operacion_completa = json.dumps({"usuario": "admin", "accion": "modo", "ok": True, "mensaje": "ok"})
    # Relleno de un solo carácter repetido para que el "seek" caiga a mitad
    # de una línea JSON larga.
    linea_larga = json.dumps({"usuario": "admin", "accion": "ping", "ok": True, "mensaje": "y" * (1024 * 300)})
    contenido = linea_larga + "\n" + operacion_completa + "\n"
    oplog_path.write_text(contenido, encoding="utf-8")

    operaciones, error = estado_mod.leer_oplog(limite=10, limite_bytes=256 * 1024)
    assert error is None
    # Sólo debe aparecer la línea completa posterior a la ventana; la línea
    # larga truncada se descarta sin lanzar excepción.
    assert len(operaciones) == 1
    assert operaciones[0]["usuario"] == "admin"
    assert operaciones[0]["accion"] == "modo"


def test_leer_estado_descarta_elementos_de_wans_que_no_son_dict(entorno):
    """routerd nunca debería publicar algo que no sea un objeto por WAN,
    pero si lo hiciera (dato corrupto), `leer_estado` lo descarta en vez de
    dejar que cada vista tenga que comprobarlo por su cuenta."""
    estado_path = entorno["estado_path"]
    bruto = json.loads(estado_path.read_text(encoding="utf-8"))
    bruto["wans"].append("esto-no-es-una-wan")
    bruto["wans"].append(None)
    estado_path.write_text(json.dumps(bruto), encoding="utf-8")

    est = estado_mod.leer_estado()
    assert all(isinstance(w, dict) for w in est.wans)
    assert len(est.wans) == 2  # las dos WAN originales, sin los elementos corruptos


def test_contexto_validacion_usa_respaldo_lan_ip_si_falta_config_lan():
    est = estado_mod.Estado(
        disponible=True,
        lan={"interfaz": "enp2s0", "ip": "192.168.50.1/24", "activa": True},
        config={"reservas": []},
        wans=[],
    )
    contexto = estado_mod.contexto_validacion(est)
    assert contexto["lan_red"] == "192.168.50.1/24"
    assert contexto["lan_ip_router"] == "192.168.50.1"
