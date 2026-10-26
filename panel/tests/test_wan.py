from __future__ import annotations

import json
import os

from conftest import WAN1_ID, extraer_csrf, login


def test_wan_detalle_usa_tarjetas_no_tabla(cliente):
    """El detalle de líneas se muestra como tarjetas (una por WAN, en vez
    de una tabla ancha con muchas columnas): la información de tethering y
    habilitada se conserva, ahora dentro de la tarjeta de cada línea."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "tt-tarjeta-wan-detalle" in html
    assert "<table" not in html.lower()
    assert "Tethering" in html
    assert "Habilitada" in html or "Deshabilitada" in html


def test_wan_internet_se_muestra_como_insignia_compacta(cliente):
    """WAN1 (presente, con internet) muestra la insignia «Internet»; WAN2
    (no presente, sin internet) muestra «Desconectado»: estar ausente
    pesa más que no tener internet, igual que en el dashboard."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    html = resp.data.decode("utf-8")
    assert 'badge tt-badge-ok"><i class="bi bi-wifi" aria-hidden="true"></i> Internet' in html
    assert 'badge tt-badge-gris"><i class="bi bi-plug" aria-hidden="true"></i> Desconectado' in html


def test_wan_modo_es_control_segmentado(cliente):
    """El selector de modo es un control segmentado (radios con las dos
    opciones habituales), no un <select> suelto."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    html = resp.data.decode("utf-8")
    assert "tt-segmentado" in html
    assert 'id="tt-modo-balanceo"' in html
    assert 'id="tt-modo-respaldo"' in html
    assert "<select" not in html.lower()


def test_wan_editar_es_plegable_dentro_de_la_tarjeta(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    html = resp.data.decode("utf-8")
    assert "tt-wan-editar-boton" in html
    assert 'data-bs-toggle="collapse"' in html
    assert "collapse tt-wan-editar" in html
    assert 'name="csrf_token"' in html
    assert 'name="peso"' in html
    assert 'name="prioridad"' in html


def test_wan_modo_pesos_es_control_segmentado(cliente):
    """El reparto de pesos (Automático/Manual) es también un control
    segmentado, junto al de modo, y no un <select>."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    html = resp.data.decode("utf-8")
    assert 'id="tt-modo-pesos-auto"' in html
    assert 'id="tt-modo-pesos-manual"' in html
    assert "<select" not in html.lower()


def test_wan_modo_pesos_ausente_muestra_automatico_activo(cliente):
    """Cuando `modo_pesos` falta en estado.json (va en el nivel superior del
    JSON, no dentro de `config`; nunca se cambió), el panel lo trata como
    "auto" (el valor por defecto del demonio) y deja marcada la opción
    Automático."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'id="tt-modo-pesos-auto" value="auto" checked' in html
    assert 'id="tt-modo-pesos-manual" value="manual" checked' not in html


def test_wan_modo_pesos_null_muestra_automatico_activo(entorno, cliente):
    """`modo_pesos` puede venir explícitamente `null` (JSON) en vez de
    faltar del todo: se trata igual, como "auto"."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    estado["modo_pesos"] = None
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'id="tt-modo-pesos-auto" value="auto" checked' in html
    assert 'id="tt-modo-pesos-manual" value="manual" checked' not in html


def test_wan_modo_pesos_valor_desconocido_muestra_automatico_activo(entorno, cliente):
    """Un valor que routerd nunca debería publicar (ni "auto" ni "manual")
    también cae al valor por defecto "auto", en vez de romper la página o
    marcar una opción que no existe."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    estado["modo_pesos"] = "turbo"
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'id="tt-modo-pesos-auto" value="auto" checked' in html
    assert 'id="tt-modo-pesos-manual" value="manual" checked' not in html


def test_wan_peso_efectivo_ausente_no_rompe(entorno, cliente):
    """`peso_efectivo` puede faltar en cada WAN (routerd todavía no lo
    publica): la página debe seguir renderizando sin romperse."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Peso automático: —" in html
    assert "Reparto previsto: —" in html


def test_wan_peso_efectivo_no_numerico_o_cero_no_rompe_y_sin_reparto(entorno, cliente):
    """Si `peso_efectivo` llega como cadena (dato corrupto/inesperado) o
    como 0 en todas las WAN, no hay un peso calculable con el que repartir:
    la página no debe romperse (nada de 500) y debe mostrar «Reparto
    previsto: —» en vez de inventar un porcentaje."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    for i, w in enumerate(estado["wans"]):
        w["peso_efectivo"] = "84" if i == 0 else 0
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Reparto previsto: —" in html
    assert "Reparto previsto: 100" not in html


def test_wan_muestra_peso_efectivo(entorno, cliente):
    """Cuando routerd sí publica `peso_efectivo`, la tarjeta de la línea lo
    muestra como el peso destacado en modo automático."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    for w in estado["wans"]:
        if w["id"] == WAN1_ID:
            w["peso_efectivo"] = 84
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Peso automático: 84" in html


def test_wan_modo_pesos_valido_escribe_peticion_en_buzon(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wan/modo_pesos", data={"csrf_token": token, "modo_pesos": "manual"})
    assert resp.status_code == 302

    respuestas_dir = str(entorno["respuestas_dir"])
    ficheros = os.listdir(respuestas_dir) if os.path.isdir(respuestas_dir) else []
    assert len(ficheros) == 1
    with open(os.path.join(respuestas_dir, ficheros[0]), "r", encoding="utf-8") as f:
        respuesta = json.load(f)
    assert respuesta["ok"] is True


def test_wan_modo_pesos_forma_contractual(entorno, cliente, simulador_routerd):
    """El fichero de petición escrito en el buzón tiene exactamente la
    forma del contrato: {"modo_pesos": "auto"|"manual"}."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    cliente.post("/wan/modo_pesos", data={"csrf_token": token, "modo_pesos": "auto"})

    buzon_dir = str(entorno["buzon_dir"])
    ficheros = [n for n in os.listdir(buzon_dir) if n.endswith(".json")]
    assert len(ficheros) == 1
    with open(os.path.join(buzon_dir, ficheros[0]), "r", encoding="utf-8") as f:
        peticion = json.load(f)

    assert set(peticion.keys()) == {"id", "usuario", "accion", "datos"}
    assert peticion["usuario"] == "admin"
    assert peticion["accion"] == "modo_pesos"
    assert peticion["datos"] == {"modo_pesos": "auto"}


def test_wan_modo_pesos_invalido_no_escribe_en_buzon(entorno, cliente):
    """Un valor que no sea "auto" ni "manual" se rechaza antes de llegar al
    buzón (ni WTForms, con sus choices, ni validacion.py lo dejan pasar)."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/wan/modo_pesos", data={"csrf_token": token, "modo_pesos": "turbo"})
    assert resp.status_code == 302

    buzon_dir = str(entorno["buzon_dir"])
    ficheros = [n for n in os.listdir(buzon_dir) if n.endswith(".json")] if os.path.isdir(buzon_dir) else []
    assert ficheros == []


def test_wan_modo_pesos_usuario_lectura_rechazado(cliente):
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)
    resp = cliente.post("/wan/modo_pesos", data={"csrf_token": token, "modo_pesos": "manual"})
    assert resp.status_code == 403
