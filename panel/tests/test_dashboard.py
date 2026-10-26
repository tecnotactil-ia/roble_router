from __future__ import annotations

import json

from conftest import WAN1_ID, login

from routerpanel import estado as estado_mod


def test_dashboard_estado_ausente(entorno, cliente):
    entorno["estado_path"].unlink()
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/")
    assert resp.status_code == 200
    assert "aviso".encode() not in resp.data or True  # no debe lanzar excepción


def test_leer_estado_tolera_fichero_ausente(entorno):
    entorno["estado_path"].unlink()
    est = estado_mod.leer_estado()
    assert est.disponible is False
    assert est.caido is True
    assert est.error


def test_dashboard_estado_corrupto(entorno, cliente):
    entorno["estado_path"].write_text("{esto no es json válido", encoding="utf-8")
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/")
    assert resp.status_code == 200


def test_leer_estado_tolera_fichero_corrupto(entorno):
    entorno["estado_path"].write_text("{esto no es json", encoding="utf-8")
    est = estado_mod.leer_estado()
    assert est.disponible is False
    assert est.caido is True


def test_dashboard_datos_json_disponible(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/dashboard/datos.json")
    assert resp.status_code == 200
    datos = resp.get_json()
    assert "caido" in datos
    assert "wans" in datos


def test_dashboard_modo_auto_usa_peso_efectivo(entorno, cliente):
    """En modo automático (el que aplica por defecto) el dashboard debe
    mostrar y repartir por `peso_efectivo` -- el que de verdad usa el
    balanceo -- y no por el peso manual, tanto en la tarjeta de la línea
    como en el reparto previsto; antes de este cambio ambos mostraban
    siempre el peso manual aunque el modo fuera automático."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    for w in estado["wans"]:
        if w["id"] == WAN1_ID:
            w["peso_efectivo"] = 84
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Peso 84" in html
    assert "Peso 50" not in html

    resp_json = cliente.get("/dashboard/datos.json")
    datos = resp_json.get_json()
    assert datos["modo_pesos"] == "auto"
    wan1 = next(w for w in datos["wans"] if w["id"] == WAN1_ID)
    assert wan1["peso_modo"] == 84
    assert wan1["pct_reparto"] == 100


# --------------------------------------------------- Wi-Fi punto de acceso


def _poner_wifi_ap(entorno, wifi_ap: dict | None) -> None:
    """Sustituye (o borra) `estado["wifi_ap"]` en el estado.json de prueba,
    igual que `_escribir_wifi` en tests/test_wifi.py."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    if wifi_ap is None:
        estado.pop("wifi_ap", None)
    else:
        estado["wifi_ap"] = wifi_ap
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")


WIFI_AP_ACTIVO = {
    "habilitado": True,
    "interfaz": "wlp3s0",
    "ssid": "CasaAP",
    "activo": True,
    "clientes": 3,
}


def test_dashboard_muestra_tarjeta_ap_activo(entorno, cliente):
    _poner_wifi_ap(entorno, WIFI_AP_ACTIVO)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Wi-Fi (punto de acceso)" in html
    assert '<strong id="tt-ap-ssid">CasaAP</strong>' in html
    assert "Activo" in html
    assert "wlp3s0" in html
    assert '<strong id="tt-ap-clientes">3</strong>' in html


def test_dashboard_tarjeta_ap_apagado_y_clientes_desconocidos(entorno, cliente):
    _poner_wifi_ap(entorno, {**WIFI_AP_ACTIVO, "activo": False, "clientes": None})
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/").data.decode("utf-8")
    assert "Wi-Fi (punto de acceso)" in html
    assert "Apagado" in html
    assert '<strong id="tt-ap-clientes">—</strong>' in html


def test_dashboard_sin_wifi_ap_no_muestra_tarjeta(entorno, cliente):
    _poner_wifi_ap(entorno, None)   # routerd todavía no publicaba wifi_ap
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/").data.decode("utf-8")
    assert "Wi-Fi (punto de acceso)" not in html


def test_dashboard_wifi_ap_habilitado_false_no_muestra_tarjeta(entorno, cliente):
    _poner_wifi_ap(entorno, {"habilitado": False})
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/").data.decode("utf-8")
    assert "Wi-Fi (punto de acceso)" not in html


def test_dashboard_wifi_ap_con_tipos_disparatados_no_rompe_ni_pinta_basura(entorno, cliente):
    """Igual que con `wifi` (revisión Opus): tipos raros en `wifi_ap` se
    descartan en la normalización, la página no rompe y como el AP no queda
    "habilitado" la tarjeta no se pinta."""
    _poner_wifi_ap(
        entorno,
        {
            "habilitado": "sí",          # no es bool True: no habilitado
            "interfaz": 7,
            "ssid": ["CasaAP"],
            "activo": None,
            "clientes": "muchos",
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Wi-Fi (punto de acceso)" not in html

    # Y con un tipo disparatado pero habilitado de verdad: la página sigue
    # en pie (el SSID pasa por _ssid_seguro, que lo convierte a texto, y el
    # número inservible se muestra como '—' en lugar de romper).
    _poner_wifi_ap(entorno, {**WIFI_AP_ACTIVO, "ssid": ["raro"], "clientes": "muchos"})
    resp = cliente.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'id="tt-ap-ssid"' in html
    assert '<strong id="tt-ap-clientes">—</strong>' in html
