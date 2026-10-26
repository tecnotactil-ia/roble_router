from __future__ import annotations

import json
import os

from conftest import extraer_csrf, login

from routerpanel.buzon import RespuestaPeticion


def _escribir_wifi(entorno, wifi: dict, wans_extra: list | None = None) -> None:
    """Sustituye `estado["wifi"]` (y opcionalmente añade WAN a `wans`) en el
    estado.json de prueba, replicando el patrón de tests/test_wan.py."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    estado["wifi"] = wifi
    if wans_extra:
        estado["wans"].extend(wans_extra)
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")


def _ficheros_buzon(entorno) -> list[str]:
    buzon_dir = str(entorno["buzon_dir"])
    return [n for n in os.listdir(buzon_dir) if n.endswith(".json")] if os.path.isdir(buzon_dir) else []


def _leer_peticion_unica(entorno) -> dict:
    ficheros = _ficheros_buzon(entorno)
    assert len(ficheros) == 1, f"se esperaba exactamente 1 petición en el buzón, hay {len(ficheros)}"
    with open(os.path.join(str(entorno["buzon_dir"]), ficheros[0]), "r", encoding="utf-8") as f:
        return json.load(f)


def _leer_audit(entorno) -> str:
    try:
        return entorno["audit_path"].read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------- render ----


def test_wifi_sin_seccion_en_estado_muestra_aviso_y_deshabilita(cliente):
    """`estado.json` sin la clave "wifi" (routerd todavía no la publica, o
    versión antigua): la página no debe romperse, debe avisar de que no hay
    tarjeta y dejar los controles deshabilitados."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "No se detecta la tarjeta Wi-Fi" in html
    assert "<select" not in html.lower()
    assert 'id="tt-wifi-ssid"' in html and " disabled" in html


def test_wifi_presente_false_muestra_aviso_y_deshabilita(entorno, cliente):
    _escribir_wifi(
        entorno,
        {
            "habilitada": False,
            "interfaz": "wlp3s0b1",
            "presente": False,
            "radio": None,
            "conectada_a": None,
            "senal": None,
            "redes": [],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": ["MI-WIFI"],
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "No se detecta la tarjeta Wi-Fi" in html
    assert 'id="tt-wifi-ssid"' in html and " disabled" in html


def test_wifi_con_redes_y_escaneo_se_muestran_ordenadas_y_bloqueadas_atenuadas(entorno, cliente):
    _escribir_wifi(
        entorno,
        {
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": "CasaMovil",
            "senal": 80,
            "redes": [{"ssid": "CasaMovil", "prioridad": 70}, {"ssid": "Otra", "prioridad": 10}],
            "escaneo": [
                {"ssid": "CasaMovil", "senal": 80, "seguridad": "WPA2", "canal": "6", "bloqueada": False},
                {"ssid": "MI-WIFI", "senal": 95, "seguridad": "WPA2", "canal": "1", "bloqueada": True},
            ],
            "escaneo_ts": "2026-10-11T09:59:00+00:00",
            "bloqueadas": ["MI-WIFI"],
        },
        wans_extra=[
            {
                "id": "wifi-wlp3s0b1",
                "nombre": "Wi-Fi",
                "interfaz": "wlp3s0b1",
                "telefono": "CasaMovil",
                "ip": "192.168.55.10/24",
                "gateway": "192.168.55.1",
                "tethering": True,
                "internet": True,
                "latencia_ms": 30,
                "perdida_pct": 0,
                "habilitada": True,
                "en_balanceo": True,
                "peso": 50,
                "prioridad": 2,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_bps": 0,
                "tx_bps": 0,
                "ultimo_cambio": "2026-10-11T09:00:00+00:00",
                "presente": True,
            }
        ],
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "CasaMovil" in html
    assert "Wi-Fi de casa · bloqueada" in html
    assert "tt-wifi-fila-bloqueada" in html
    assert "Ver en WAN" in html
    assert 'href="/wan"' in html
    assert 'data-pct="80"' in html
    # Conectada: aparece como "Conectada" junto al SSID activo.
    assert "Conectada" in html


def test_wifi_lectura_ve_todo_deshabilitado_y_sin_botones_de_guardar(entorno, cliente):
    _escribir_wifi(
        entorno,
        {
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": None,
            "senal": None,
            "redes": [{"ssid": "CasaMovil", "prioridad": 50}],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
    )
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/wifi")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    # Los campos siguen presentes (mismo patrón que WAN) pero deshabilitados;
    # los botones de guardar/añadir/buscar/conectar/eliminar, que sólo tienen
    # sentido para quien puede escribir, no se renderizan para lectura.
    assert 'id="tt-wifi-ssid"' in html and " disabled" in html
    # Ningún botón de acción (guardar/añadir/buscar/conectar/eliminar) debe
    # renderizarse para un rol de sólo lectura, sólo los campos (deshabilitados).
    assert "tt-btn-primario" not in html
    assert "tt-btn-secundario" not in html
    assert "tt-btn-peligro" not in html


def test_wifi_modo_ap_muestra_aviso_y_oculta_formularios_de_wan(entorno, cliente):
    """Con la tarjeta en modo punto de acceso (`wifi_ap.habilitado`) la
    página de WAN Wi-Fi no tiene sentido: aviso de que reinstale con
    --wifi-modo wan y sin formularios controles."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    estado["wifi"] = {
        "habilitada": True,
        "interfaz": "wlp3s0b1",
        "presente": True,
        "radio": True,
        "conectada_a": None,
        "senal": None,
        "redes": [],
        "escaneo": [],
        "escaneo_ts": None,
        "bloqueadas": [],
    }
    estado["wifi_ap"] = {
        "habilitado": True,
        "interfaz": "wlp3s0b1",
        "ssid": "CasaAP",
        "activo": True,
        "clientes": 2,
    }
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "modo punto de acceso" in html
    assert "--wifi-modo wan" in html
    assert "CasaAP" in html
    # Los formularios y secciones de WAN Wi-Fi desaparecen por completo.
    assert 'id="tt-wifi-ssid"' not in html
    assert "Estado de la WAN Wi-Fi" not in html
    assert "Redes guardadas" not in html
    assert "Redes cercanas" not in html


def test_wifi_habilitado_false_deja_ver_los_formularios_de_wan(entorno, cliente):
    """En instalaciones normales (o con la tarjeta como WAN) la página
    funciona como siempre: sin aviso de AP y con los formularios de WAN."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    estado["wifi_ap"] = {"habilitado": False}
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/wifi").data.decode("utf-8")
    assert "--wifi-modo wan" not in html
    assert 'id="tt-wifi-ssid"' in html
    assert "Estado de la WAN Wi-Fi" in html


def test_wifi_estado_sin_wifi_ap_seguira_mostrando_formularios(cliente):
    """routerd más antiguo sin `wifi_ap` en estado.json: la página no debe
    romperse y muestra la de siempre."""
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/wifi").data.decode("utf-8")
    assert "--wifi-modo wan" not in html
    assert 'id="tt-wifi-ssid"' in html


def test_wifi_ssid_en_query_se_prellena_escapado(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi?ssid=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ------------------------------------------------------------- contrato ----


def test_wifi_config_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/config", data={"csrf_token": token, "habilitada": "1"})
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert set(peticion.keys()) == {"id", "usuario", "accion", "datos"}
    assert peticion["usuario"] == "admin"
    assert peticion["accion"] == "wifi_config"
    assert peticion["datos"] == {"habilitada": True}


def test_wifi_agregar_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "password1", "prioridad": "70"},
    )
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "wifi_agregar"
    assert peticion["datos"] == {"ssid": "CasaMovil", "clave": "password1", "prioridad": 70}


def test_wifi_agregar_sin_prioridad_usa_50_por_defecto(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "Abierta", "clave": ""},
    )
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"] == {"ssid": "Abierta", "clave": "", "prioridad": 50}


def test_wifi_eliminar_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/eliminar", data={"csrf_token": token, "ssid": "CasaMovil"})
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "wifi_eliminar"
    assert peticion["datos"] == {"ssid": "CasaMovil"}


def test_wifi_conectar_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/conectar", data={"csrf_token": token, "ssid": "CasaMovil"})
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "wifi_conectar"
    assert peticion["datos"] == {"ssid": "CasaMovil"}


def test_wifi_escanear_escribe_forma_contractual_sin_esperar_respuesta(entorno, cliente):
    """wifi_escanear es asíncrono: no se espera respuesta (a diferencia de
    las demás acciones), así que esta prueba no necesita `simulador_routerd`
    y debe ser rápida (sin los ~6 s de espera de un timeout de buzón)."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/escanear", data={"csrf_token": token})
    assert resp.status_code == 302
    html = cliente.get("/wifi").data.decode("utf-8")
    assert "Buscando redes" in html

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "wifi_escanear"
    assert peticion["datos"] == {}


# ------------------------------------------------------------ rechazos ----


def test_wifi_agregar_clave_demasiado_corta_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "passwd1", "prioridad": "50"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_wifi_agregar_clave_demasiado_larga_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "a" * 64, "prioridad": "50"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_wifi_agregar_clave_no_ascii_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "contraseña12", "prioridad": "50"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_wifi_agregar_ssid_bloqueada_no_escribe_y_avisa_del_bucle(entorno, cliente):
    _escribir_wifi(
        entorno,
        {
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": None,
            "senal": None,
            "redes": [],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": ["MI-WIFI"],
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "MI-WIFI", "clave": "password1", "prioridad": "50"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []

    html = cliente.get("/wifi").data.decode("utf-8")
    assert "crearía un bucle" in html


# -------------------------------------------------------------- rol lectura


def test_wifi_rutas_post_rechazadas_para_lectura(cliente):
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    for ruta, datos in (
        ("/wifi/config", {"habilitada": "1"}),
        ("/wifi/agregar", {"ssid": "CasaMovil", "clave": "password1", "prioridad": "50"}),
        ("/wifi/eliminar", {"ssid": "CasaMovil"}),
        ("/wifi/conectar", {"ssid": "CasaMovil"}),
        ("/wifi/escanear", {}),
    ):
        resp = cliente.post(ruta, data={**datos, "csrf_token": token})
        assert resp.status_code == 403, f"{ruta} debería rechazar a un usuario de lectura"


# -------------------------------------------------------- seguridad: clave


def test_wifi_clave_nunca_aparece_en_html_tras_error(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    clave_secreta = "clave-no-valida-ñ"
    cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": clave_secreta, "prioridad": "50"},
    )

    html = cliente.get("/wifi").data.decode("utf-8")
    assert clave_secreta not in html
    assert "value=\"clave-no-valida" not in html


def test_wifi_clave_nunca_aparece_en_auditoria_exito(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "password1", "prioridad": "70"},
    )

    auditoria_texto = _leer_audit(entorno)
    assert "password1" not in auditoria_texto
    assert "clave=***" in auditoria_texto


def test_wifi_clave_nunca_aparece_en_auditoria_error(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "passwd1", "prioridad": "50"},
    )

    auditoria_texto = _leer_audit(entorno)
    assert "passwd1" not in auditoria_texto


# ------------------------------------------------- robustez (revisión Opus)


def test_wifi_estado_con_tipos_disparatados_no_rompe_wifi_ni_el_dashboard(entorno, cliente):
    """Reproduce el caso que tumbaba TODAS las páginas: `redes`/`escaneo`/
    `bloqueadas` que no son listas (p. ej. {"redes": 5}) deben descartarse en
    vez de provocar un TypeError al iterarlas; `senal` con valores NaN,
    infinito o fuera de rango tampoco debe romper nada."""
    login(cliente, "admin", "contrasena-admin-1")

    variantes = [
        {  # redes/escaneo/bloqueadas con el tipo equivocado
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": "CasaMovil",
            "senal": 80,
            "redes": 5,
            "escaneo": True,
            "escaneo_ts": None,
            "bloqueadas": 7,
        },
        {  # senal NaN
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": "CasaMovil",
            "senal": float("nan"),
            "redes": [],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
        {  # senal infinito
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": "CasaMovil",
            "senal": float("inf"),
            "redes": [],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
        {  # senal fuera de rango (debe recortarse a 100, nunca romper)
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": "CasaMovil",
            "senal": 500,
            "redes": [],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
        {  # SSID con "surrogate" suelto, no codificable en UTF-8
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": None,
            "senal": None,
            "redes": [{"ssid": "Red\udcff", "prioridad": 50}],
            "escaneo": [{"ssid": "Red\udcff", "senal": 50, "seguridad": "WPA2", "canal": "6", "bloqueada": False}],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
    ]

    for wifi in variantes:
        _escribir_wifi(entorno, wifi)
        resp = cliente.get("/wifi")
        assert resp.status_code == 200, f"/wifi rompió con {wifi!r}"
        resp_dashboard = cliente.get("/")
        assert resp_dashboard.status_code == 200, f"/ (dashboard) rompió con {wifi!r}"


def test_wifi_senal_fuera_de_rango_se_recorta_no_se_descarta(entorno, cliente):
    _escribir_wifi(
        entorno,
        {
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": "CasaMovil",
            "senal": 500,
            "redes": [],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/wifi").data.decode("utf-8")
    assert 'data-pct="100"' in html


# --------------------------------------------------------- UX: timeout ----


def test_wifi_conectar_con_timeout_muestra_mensaje_de_conectando(entorno, cliente, monkeypatch):
    import routerpanel.wifi as wifi_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(
            id="falso-id", estado="pendiente", mensaje="Petición enviada; se aplicará en unos segundos."
        )

    monkeypatch.setattr(wifi_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/conectar", data={"csrf_token": token, "ssid": "CasaMovil"})
    assert resp.status_code == 302

    html = cliente.get("/wifi").data.decode("utf-8")
    assert "Conectando a «CasaMovil»" in html
    assert "revisa Registro" in html

    auditoria_texto = _leer_audit(entorno)
    assert '"resultado": "pendiente"' in auditoria_texto


def test_wifi_agregar_con_timeout_muestra_mensaje_de_guardando_y_redacta_clave(entorno, cliente, monkeypatch):
    import routerpanel.wifi as wifi_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(
            id="falso-id", estado="pendiente", mensaje="Petición enviada; se aplicará en unos segundos."
        )

    monkeypatch.setattr(wifi_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wifi/agregar",
        data={"csrf_token": token, "ssid": "CasaMovil", "clave": "password1", "prioridad": "50"},
    )
    assert resp.status_code == 302

    html = cliente.get("/wifi").data.decode("utf-8")
    assert "Guardando «CasaMovil»" in html
    assert "se conectará automáticamente si está al alcance" in html

    auditoria_texto = _leer_audit(entorno)
    assert "password1" not in auditoria_texto
    assert "clave=***" in auditoria_texto


# ----------------------------------------------- UX: escaneo asíncrono ----


def test_wifi_escaneo_pendiente_activa_data_attribute_de_autorrefresco(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/escanear", data={"csrf_token": token})
    assert resp.status_code == 302

    html = cliente.get("/wifi").data.decode("utf-8")
    assert 'data-wifi-escaneo-pendiente="1"' in html
    assert "se actualizará sola" in html
    assert 'src="/static/js/wifi.js"' in html


def test_wifi_escaneo_con_respuesta_de_error_se_muestra_y_quita_pendiente(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wifi/escanear", data={"csrf_token": token})
    assert resp.status_code == 302

    # Simula que routerd ya contestó con un fallo (p. ej. "nmcli" falló).
    peticion_id = _leer_peticion_unica(entorno)["id"]
    respuestas_dir = str(entorno["respuestas_dir"])
    os.makedirs(respuestas_dir, exist_ok=True)
    with open(os.path.join(respuestas_dir, f"{peticion_id}.json"), "w", encoding="utf-8") as f:
        json.dump({"id": peticion_id, "ok": False, "mensaje": "No se pudo escanear: nmcli falló."}, f)

    html = cliente.get("/wifi").data.decode("utf-8")
    assert "No se pudo escanear: nmcli falló." in html
    assert 'data-wifi-escaneo-pendiente="1"' not in html


def test_wifi_escaneo_sin_peticion_pendiente_no_promete_refresco(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/wifi").data.decode("utf-8")
    assert 'data-wifi-escaneo-pendiente="0"' in html
    assert "Último escaneo:" in html
    assert "se actualizará sola" not in html


# -------------------------------------------- seguridad: XSS en acciones --


def test_wifi_ssid_con_comillas_script_y_unicode_queda_escapado_en_acciones(entorno, cliente):
    ssid_hostil = '"><script>alert(1)</script> Wifi 中文'
    _escribir_wifi(
        entorno,
        {
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": ssid_hostil,
            "senal": 50,
            "redes": [{"ssid": ssid_hostil, "prioridad": 50}],
            "escaneo": [],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/wifi").data.decode("utf-8")

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # El SSID hostil también se usa como `value` en los hidden inputs de los
    # formularios de Conectar/Eliminar: las comillas deben quedar escapadas
    # (&#34;), nunca cerrar el atributo antes de tiempo.
    assert 'value="">' not in html
    assert "&#34;&gt;&lt;script&gt;" in html or "&#34;&gt;" in html


# ------------------------------------------------------- CSRF: sin token --


def test_wifi_post_lector_sin_csrf_token_es_rechazado(entorno, cliente):
    login(cliente, "lector", "contrasena-lector-1")
    # Sin csrf_token en absoluto (no sólo un rol incorrecto): Flask-WTF debe
    # rechazarlo (normalmente 400, antes incluso de llegar al chequeo de
    # rol); en ningún caso debe escribirse nada en el buzón.
    resp = cliente.post("/wifi/conectar", data={"ssid": "CasaMovil"})
    assert resp.status_code in (400, 403)
    assert _ficheros_buzon(entorno) == []


def test_wifi_post_admin_sin_csrf_token_es_rechazado(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.post("/wifi/conectar", data={"ssid": "CasaMovil"})
    assert resp.status_code in (400, 403)
    assert _ficheros_buzon(entorno) == []


# ---------------------------------------- revisión Opus (ronda 2, bajas) --


def test_wifi_formulario_invalido_muestra_primer_error_fijo_no_el_dato(cliente):
    """En vez del genérico "Formulario inválido.", debe verse el primer
    mensaje fijo de WTForms (p. ej. el de Length en la prioridad fuera de
    rango), que nunca interpola el valor enviado."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    token = extraer_csrf(resp.data)

    valor_fuera_de_rango = "999999"
    resp = cliente.post(
        "/wifi/agregar",
        data={
            "csrf_token": token,
            "ssid": "CasaMovil",
            "clave": "password1",
            "prioridad": valor_fuera_de_rango,
        },
    )
    assert resp.status_code == 302

    html = cliente.get("/wifi").data.decode("utf-8")
    assert "Formulario inválido." not in html
    assert valor_fuera_de_rango not in html
    # Mensaje fijo de wtforms.validators.NumberRange (nunca el dato enviado).
    assert "La prioridad debe estar entre 0 y 100." in html


def test_wifi_canal_y_seguridad_con_tipo_no_valido_se_descartan_a_none(entorno, cliente):
    """`seguridad`/`canal` sólo se aceptan como `str` o `int`; cualquier otro
    tipo (aquí una lista y un diccionario) se descarta como `None` en vez de
    forzarse a texto, y la página no debe romperse."""
    _escribir_wifi(
        entorno,
        {
            "habilitada": True,
            "interfaz": "wlp3s0b1",
            "presente": True,
            "radio": True,
            "conectada_a": None,
            "senal": None,
            "redes": [],
            "escaneo": [
                {
                    "ssid": "RedRara",
                    "senal": 40,
                    "seguridad": ["WPA2", "WPA3"],
                    "canal": {"primario": 6},
                    "bloqueada": False,
                },
                {
                    "ssid": "RedNormal",
                    "senal": 30,
                    "seguridad": "WPA2",
                    "canal": 11,
                    "bloqueada": False,
                },
            ],
            "escaneo_ts": None,
            "bloqueadas": [],
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wifi")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "RedRara" in html
    assert "RedNormal" in html
    # El canal numérico (int) sí se admite y se muestra como texto.
    assert "canal 11" in html
