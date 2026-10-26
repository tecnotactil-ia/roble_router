"""Pruebas de la interfaz del firewall con reglas propias (FIREWALL_PLAN.md).

Cubre: página de reglas, estado vacío, formularios de regla/grupo, CSRF,
peticiones fw_* hacia el buzón con su `version`, errores del core, versión
caducada, y la normalización defensiva de `config.firewall` en `estado.py`.
"""
from __future__ import annotations

import json
import os
import re
from html import unescape
from pathlib import Path

import pytest

from conftest import extraer_csrf, login

from routerpanel import estado as estado_mod
from routerpanel.buzon import RespuestaPeticion

# Modelo de `config.firewall` tal como lo publica routerd (FIREWALL_PLAN.md):
# copia de la sección firewall + firewall_error + firewall_aciertos.
FIREWALL_CON_REGLAS = {
    "version": 3,
    "grupos": [
        {
            "id": "g_a1b2c3d4",
            "nombre": "Móviles de los niños",
            "tipo": "mac",
            "miembros": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
        },
    ],
    "reglas": [
        {
            "id": "r_ab12cd34",
            "nombre": "Sin juegos de noche",
            "habilitada": True,
            "accion": "bloquear",
            "origen": {"tipo": "mac", "valor": "aa:bb:cc:dd:ee:01"},
            "destino": {"tipo": "cualquiera"},
            "protocolo": "tcp",
            "puertos": [{"desde": 443, "hasta": 443}],
            "registrar": True,
            "comentario": "Por la noche",
        },
        {
            "id": "r_ef56ab78",
            "nombre": "Permitir DNS",
            "habilitada": False,
            "accion": "permitir",
            "origen": {"tipo": "cualquiera"},
            "destino": {"tipo": "ip", "valor": "1.1.1.1"},
            "protocolo": "udp",
            "puertos": [{"desde": 53, "hasta": 53}],
            "registrar": False,
            "comentario": "",
        },
    ],
    "firewall_error": None,
    "firewall_aciertos": {"r_ab12cd34": 42},
}


# ------------------------------------------------------------- utilidades ---


def _escribir_config_firewall(entorno, firewall) -> None:
    """Sustituye `estado["config"]["firewall"]` en el estado.json de prueba
    (o lo quita por completo si `firewall` es None), mismo patrón que
    `_escribir_config_bloqueo` de test_proteccion.py."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    if firewall is None:
        estado["config"].pop("firewall", None)
    else:
        estado["config"]["firewall"] = firewall
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")


def _ficheros_buzon(entorno) -> list[str]:
    buzon_dir = str(entorno["buzon_dir"])
    return [n for n in os.listdir(buzon_dir) if n.endswith(".json")] if os.path.isdir(buzon_dir) else []


def _leer_peticion_unica(entorno) -> dict:
    ficheros = _ficheros_buzon(entorno)
    assert len(ficheros) == 1, f"se esperaba exactamente 1 petición en el buzón, hay {len(ficheros)}"
    with open(os.path.join(str(entorno["buzon_dir"]), ficheros[0]), "r", encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------- estado normalizado ---


def test_normalizar_firewall_conserva_reglas_y_grupos_sanos():
    normalizado = estado_mod.normalizar_firewall(FIREWALL_CON_REGLAS)
    assert normalizado["version"] == 3
    assert [g["id"] for g in normalizado["grupos"]] == ["g_a1b2c3d4"]
    assert [r["id"] for r in normalizado["reglas"]] == ["r_ab12cd34", "r_ef56ab78"]
    assert normalizado["reglas"][0]["accion"] == "bloquear"
    assert normalizado["reglas"][0]["puertos"] == [{"desde": 443, "hasta": 443}]
    assert normalizado["firewall_error"] is None
    assert normalizado["firewall_aciertos"] == {"r_ab12cd34": 42}


def test_normalizar_firewall_tipos_disparatados_no_rompe():
    """Un routerd viejo o un estado.json corrupto nunca debe dejar la página
    sin renderizar: cada campo cae a su valor seguro."""
    normalizado = estado_mod.normalizar_firewall(
        {
            "version": "no-es-un-entero",
            "grupos": "no-es-una-lista",
            "reglas": [{"id": 5, "nombre": ["una", "lista"], "puertos": 7,
                        "habilitada": "sí", "origen": "cadena", "registrar": None},
                       "no-soy-una-regla",
                       {"id": "r_ffffffff", "nombre": "Sana", "accion": "bloquear",
                        "origen": {"tipo": "cualquiera"}, "destino": {"tipo": "cualquiera"},
                        "protocolo": "tcp", "puertos": [{"desde": 1, "hasta": 2}],
                        "registrar": False, "comentario": ""}],
            "firewall_error": 123,
            "firewall_aciertos": {"r_ffffffff": "mil", "otra": 3, "r_otra": float("nan")},
        }
    )
    assert normalizado["version"] == 1
    assert normalizado["grupos"] == []
    # La regla sana sobrevive; la basura se descarta sin tumbar la página.
    ids = [r["id"] for r in normalizado["reglas"]]
    assert "r_ffffffff" in ids
    sana = next(r for r in normalizado["reglas"] if r["id"] == "r_ffffffff")
    assert sana["nombre"] == "Sana"
    assert sana["puertos"] == [{"desde": 1, "hasta": 2}]
    assert normalizado["firewall_error"] is None
    assert normalizado["firewall_aciertos"] == {}


def test_normalizar_firewall_ausente_devuelve_estructura_vacia():
    normalizado = estado_mod.normalizar_firewall(None)
    assert normalizado["version"] == 1
    assert normalizado["grupos"] == []
    assert normalizado["reglas"] == []
    assert normalizado["firewall_error"] is None
    assert normalizado["firewall_aciertos"] == {}
    normalizado = estado_mod.normalizar_firewall(["no", "soy", "un", "dict"])
    assert normalizado["reglas"] == []


# ------------------------------------------------------------- render --------


def test_firewall_pagina_muestra_tabla_con_reglas(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Sin juegos de noche" in html
    assert "Permitir DNS" in html
    assert "Bloquear" in html
    assert "Permitir" in html
    # Origen / destino / servicio de cada regla.
    assert "aa:bb:cc:dd:ee:01" in html
    assert "1.1.1.1" in html
    assert "Cualquiera" in html
    # Hits leídos de firewall_aciertos.
    assert "42" in html
    # Acciones de fila como formularios POST con CSRF (sin JS obligatorio).
    assert 'action="/firewall/regla/mover"' in html
    assert 'action="/firewall/regla/eliminar"' in html
    assert 'action="/firewall/regla/activar"' in html
    # El formulario de guardar vive en la página propia de la regla.
    assert "/firewall/regla/nueva" in html
    assert "csrf_token" in html
    # Enlace a editar la regla por id.
    assert "/firewall/regla/r_ab12cd34" in html
    assert "/firewall/regla/r_ef56ab78" in html


def test_firewall_pagina_estado_vacio_muestra_mensaje(entorno, cliente):
    _escribir_config_firewall(
        entorno,
        {"version": 1, "grupos": [], "reglas": [], "firewall_error": None, "firewall_aciertos": {}},
    )
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "No hay reglas todavía" in html
    assert "Nueva regla" in html


def test_firewall_pagina_sin_config_no_rompe(entorno, cliente):
    _escribir_config_firewall(entorno, None)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "todavía no ha enviado su configuración de firewall" in html


def test_firewall_pagina_muestra_firewall_error(entorno, cliente):
    cfg = dict(FIREWALL_CON_REGLAS)
    cfg["firewall_error"] = "firewall base no válido: falta la interfaz WAN"
    _escribir_config_firewall(entorno, cfg)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "firewall base no válido" in html


def test_firewall_pagina_quita_el_aviso_de_solo_lectura(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "sólo lectura" not in html
    assert "solo lectura" not in html


def test_firewall_pagina_muestra_volcado_nft(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "tt-firewall-pre" in html
    assert "table inet filtro_router" in html


def test_firewall_pagina_con_tipos_disparatados_no_rompe(entorno, cliente):
    _escribir_config_firewall(
        entorno,
        {
            "version": None,
            "grupos": {"no": "lista"},
            "reglas": ["basura", {"id": 123, "nombre": ["x"]}],
            "firewall_error": {"dict": "no sirve"},
            "firewall_aciertos": "no-es-un-dict",
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall")
    assert resp.status_code == 200


def test_firewall_pagina_muestra_servicio_y_accion_con_color(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "tt-fw-accion-bloquear" in html
    assert "tt-fw-accion-permitir" in html
    assert "tcp/443" in html
    assert "udp/53" in html


def test_firewall_pagina_lectura_ve_formularios_de_cambio_deshabilitados(entorno, cliente):
    """BAJA: el rol lectura ve la tabla pero no ningún formulario de mutación."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "lector", "contrasena-lector-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "Sin juegos de noche" in html
    assert 'action="/firewall/regla/guardar"' not in html
    assert 'action="/firewall/regla/eliminar"' not in html
    assert 'action="/firewall/regla/mover"' not in html
    assert 'action="/firewall/regla/activar"' not in html
    assert "tt-btn-peligro" not in html


def test_firewall_ejemplos_se_enlazan_con_parametros_get(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "Bloquear un dispositivo" in html
    assert "Bloquear un puerto para todos" in html
    assert "ejemplo=bloquear_dispositivo" in html
    assert "ejemplo=bloquear_puerto" in html


# ------------------------------------------------------------- formularios ---


def test_firewall_formulario_nueva_muestra_campos(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall/regla/nueva")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    for campo in ("nombre", "accion", "origen_tipo", "destino_tipo", "protocolo",
                  "puertos", "registrar", "comentario"):
        assert f'name="{campo}"' in html, f"falta el campo {campo}"
    # `version` de la config vista (concurrencia optimista).
    assert 'name="version"' in html
    assert 'value="3"' in html
    # La id NO la pone el panel en creación: se manda vacía o ausente.
    assert 'name="regla_id"' in html


def test_firewall_formulario_nueva_regla_viene_activada_por_defecto(entorno, cliente):
    """Una regla nueva se crea ACTIVADA (modelo del plan: `habilitada: true`).
    Si el formulario llegara apagado, «Bloquear un dispositivo» se guardaría
    deshabilitada y el usuario creería que está bloqueando."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    for ruta in ("/firewall/regla/nueva", "/firewall/regla/nueva?ejemplo=bloquear_dispositivo"):
        html = cliente.get(ruta).data.decode("utf-8")
        campo = re.search(r'<input[^>]*name="habilitada"[^>]*>', html)
        assert campo, f"falta el campo habilitada en {ruta}"
        assert "checked" in campo.group(0), f"el interruptor de {ruta} no viene marcado"
    # Al editar, en cambio, manda el valor real de la regla (la 2 está inactiva).
    html = cliente.get("/firewall/regla/r_ef56ab78").data.decode("utf-8")
    campo = re.search(r'<input[^>]*name="habilitada"[^>]*>', html)
    assert campo and "checked" not in campo.group(0)


def test_firewall_formulario_editar_rellena_campos_de_la_regla(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall/regla/r_ab12cd34")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Sin juegos de noche" in html
    assert 'value="r_ab12cd34"' in html
    assert 'value="3"' in html
    assert "bloquear" in html
    assert "aa:bb:cc:dd:ee:01" in html
    assert "443" in html
    assert "Por la noche" in html


def test_firewall_formulario_editar_id_desconocida_redirige(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall/regla/r_00000000")
    assert resp.status_code == 302
    resp = cliente.get("/firewall/regla/r_00000000", follow_redirects=True)
    assert "No existe ninguna regla con esa id" in resp.data.decode("utf-8")


def test_firewall_formulario_incluye_selector_de_dispositivos(entorno, cliente):
    """El selector de origen/miembros se rellena a partir de los dispositivos
    conocidos (vecinos + leases): nombre + MAC + IP."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall/regla/nueva").data.decode("utf-8")
    assert "tt-fw-selector-dispositivos" in html
    assert "aa:bb:cc:dd:ee:ff" in html  # MAC del lease `nas`
    assert "nas" in html
    assert "192.168.50.10" in html


def test_firewall_ejemplo_bloquear_dispositivo_rellena_el_formulario(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall/regla/nueva?ejemplo=bloquear_dispositivo").data.decode("utf-8")
    assert "Bloquear un dispositivo" in html
    assert "bloquear" in html
    assert 'name="origen_tipo"' in html


def test_firewall_ejemplo_bloquear_puerto_rellena_el_formulario(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall/regla/nueva?ejemplo=bloquear_puerto").data.decode("utf-8")
    assert "Bloquear un puerto para todos" in html
    assert "443" in html
    assert "tcp" in html


def test_firewall_grupos_pagina_lista_grupos_y_formulario(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/firewall/grupos")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Móviles de los niños" in html
    assert "g_a1b2c3d4" in html
    assert 'name="nombre"' in html
    assert 'name="tipo"' in html
    assert "mac" in html and "ip" in html
    # Los miembros del grupo se muestran.
    assert "aa:bb:cc:dd:ee:01" in html
    # Acciones de grupo como formularios POST.
    assert 'action="/firewall/grupo/guardar"' in html
    assert 'action="/firewall/grupo/eliminar"' in html


def test_firewall_grupos_editar_grupo_rellena_formulario(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall/grupos?editar=g_a1b2c3d4").data.decode("utf-8")
    assert 'value="g_a1b2c3d4"' in html
    assert "Móviles de los niños" in html


def test_firewall_grupos_placeholder_no_ensena_entidad_html(entorno, cliente):
    """WTForms escapa los atributos: un «&#10;» en el placeholder del textarea
    de miembros llega al navegador como texto literal «&#10;» en mitad del
    campo (se ve en pantalla, no hace salto de línea)."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/firewall/grupos").data.decode("utf-8")
    placeholders = [unescape(p) for p in re.findall(r'placeholder="([^"]*)"', html)]
    assert placeholders, "la página no tiene ningún placeholder"
    assert not any("#10" in p for p in placeholders), (
        "un placeholder enseña la entidad &#10; literal: %s"
        % [p for p in placeholders if "#10" in p]
    )
    assert any(p.startswith("aa:bb:cc:dd:ee:01") for p in placeholders)


# --------------------------------------------------------- peticiones fw_* ---


def test_firewall_regla_guardar_escribe_forma_contractual_con_version(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/regla/nueva").data)

    resp = cliente.post(
        "/firewall/regla/guardar",
        data={
            "csrf_token": token,
            "version": "3",
            "regla_id": "",
            "nombre": "Sin VPN",
            "accion": "bloquear",
            "origen_tipo": "cualquiera",
            "origen_valor": "",
            "destino_tipo": "ip",
            "destino_valor": "203.0.113.7",
            "protocolo": "tcp",
            "puertos": "443, 8000-8100",
            "registrar": "1",
            "comentario": "Nada de VPN",
        },
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_regla_guardar"
    assert peticion["datos"]["version"] == 3
    regla = peticion["datos"]["regla"]
    assert regla["nombre"] == "Sin VPN"
    assert regla["accion"] == "bloquear"
    assert regla["origen"] == {"tipo": "cualquiera"}
    assert regla["destino"] == {"tipo": "ip", "valor": "203.0.113.7"}
    assert regla["protocolo"] == "tcp"
    assert regla["puertos"] == [{"desde": 443, "hasta": 443}, {"desde": 8000, "hasta": 8100}]
    assert regla["registrar"] is True
    assert regla["comentario"] == "Nada de VPN"
    # En creación la id NO viaja: la genera el core.
    assert "id" not in regla


def test_firewall_regla_guardar_edita_con_id(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/regla/r_ab12cd34").data)

    resp = cliente.post(
        "/firewall/regla/guardar",
        data={
            "csrf_token": token,
            "version": "3",
            "regla_id": "r_ab12cd34",
            "nombre": "Sin juegos de noche",
            "accion": "rechazar",
            "origen_tipo": "mac",
            "origen_valor": "aa:bb:cc:dd:ee:01",
            "destino_tipo": "cualquiera",
            "protocolo": "tcp",
            "puertos": "443",
            "comentario": "",
        },
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_regla_guardar"
    assert peticion["datos"]["regla"]["id"] == "r_ab12cd34"
    assert peticion["datos"]["regla"]["accion"] == "rechazar"


def test_firewall_regla_eliminar_escribe_peticion(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall").data)

    resp = cliente.post(
        "/firewall/regla/eliminar",
        data={"csrf_token": token, "version": "3", "regla_id": "r_ab12cd34"},
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_regla_eliminar"
    assert peticion["datos"] == {"version": 3, "id": "r_ab12cd34"}


def test_firewall_regla_mover_escribe_peticion_con_posicion(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall").data)

    resp = cliente.post(
        "/firewall/regla/mover",
        data={"csrf_token": token, "version": "3", "regla_id": "r_ef56ab78", "posicion": "0"},
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_regla_mover"
    assert peticion["datos"] == {"version": 3, "id": "r_ef56ab78", "posicion": 0}


def test_firewall_regla_activar_escribe_peticion(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall").data)

    resp = cliente.post(
        "/firewall/regla/activar",
        data={"csrf_token": token, "version": "3", "regla_id": "r_ab12cd34", "habilitada": "0"},
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_regla_activar"
    assert peticion["datos"] == {"version": 3, "id": "r_ab12cd34", "habilitada": False}


def test_firewall_grupo_guardar_escribe_peticion(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/grupos").data)

    resp = cliente.post(
        "/firewall/grupo/guardar",
        data={
            "csrf_token": token,
            "version": "3",
            "grupo_id": "",
            "nombre": "Invitados",
            "tipo": "ip",
            "miembros": ["192.168.50.50", "192.168.50.51"],
            "miembros_texto": "192.168.50.52",
        },
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_grupo_guardar"
    assert peticion["datos"]["version"] == 3
    grupo = peticion["datos"]["grupo"]
    assert grupo["nombre"] == "Invitados"
    assert grupo["tipo"] == "ip"
    assert grupo["miembros"] == ["192.168.50.50", "192.168.50.51", "192.168.50.52"]
    assert "id" not in grupo


def test_firewall_grupo_guardar_edita_con_id(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/grupos").data)

    resp = cliente.post(
        "/firewall/grupo/guardar",
        data={
            "csrf_token": token,
            "version": "3",
            "grupo_id": "g_a1b2c3d4",
            "nombre": "Móviles de los niños",
            "tipo": "mac",
            "miembros": ["aa:bb:cc:dd:ee:01"],
        },
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"]["grupo"]["id"] == "g_a1b2c3d4"


def test_firewall_grupo_eliminar_escribe_peticion(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/grupos").data)

    resp = cliente.post(
        "/firewall/grupo/eliminar",
        data={"csrf_token": token, "version": "3", "grupo_id": "g_a1b2c3d4"},
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "fw_grupo_eliminar"
    assert peticion["datos"] == {"version": 3, "id": "g_a1b2c3d4"}


def test_firewall_regla_guardar_con_dispositivo_del_selector(entorno, cliente, simulador_routerd):
    """Cuando el origen es un dispositivo elegido en el selector, la MAC del
    selector se usa como valor del origen."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/regla/nueva").data)

    cliente.post(
        "/firewall/regla/guardar",
        data={
            "csrf_token": token,
            "version": "3",
            "nombre": "Bloquear portátil",
            "accion": "bloquear",
            "origen_tipo": "mac",
            "origen_dispositivo": "11:22:33:44:55:66",
            "origen_valor": "",
            "destino_tipo": "cualquiera",
            "protocolo": "cualquiera",
            "puertos": "",
        },
    )
    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"]["regla"]["origen"] == {"tipo": "mac", "valor": "11:22:33:44:55:66"}


# ------------------------------------------------- CSRF / roles / respuestas -


def test_firewall_csrf_es_obligatorio_en_post(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.post(
        "/firewall/regla/eliminar",
        data={"version": "3", "regla_id": "r_ab12cd34"},
    )
    assert resp.status_code == 400
    assert _ficheros_buzon(entorno) == []


def test_firewall_lectura_no_puede_mutar(entorno, cliente):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/firewall")
    token = extraer_csrf(resp.data)
    for ruta, datos in (
        ("/firewall/regla/eliminar", {"version": "3", "regla_id": "r_ab12cd34"}),
        ("/firewall/regla/mover", {"version": "3", "regla_id": "r_ab12cd34", "posicion": "0"}),
        ("/firewall/regla/activar", {"version": "3", "regla_id": "r_ab12cd34", "habilitada": "0"}),
    ):
        resp = cliente.post(ruta, data={"csrf_token": token, **datos})
        assert resp.status_code == 403, ruta
    assert _ficheros_buzon(entorno) == []


def test_firewall_error_del_core_se_muestra(entorno, cliente, monkeypatch):
    import routerpanel.firewall as firewall_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(id="falso-id", estado="error", mensaje="No existe ninguna regla con esa id")

    monkeypatch.setattr(firewall_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall").data)
    cliente.post(
        "/firewall/regla/eliminar",
        data={"csrf_token": token, "version": "3", "regla_id": "r_ab12cd34"},
    )
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "No existe ninguna regla con esa id" in html


def test_firewall_version_caducada_se_muestra(entorno, cliente, monkeypatch):
    """Cuando el core rechaza por versión («La configuración cambió mientras
    editabas…»), el panel muestra ese mensaje con los mensajes flash."""
    import routerpanel.firewall as firewall_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(
            id="falso-id",
            estado="error",
            mensaje="La configuración cambió mientras editabas; recarga la página",
        )

    monkeypatch.setattr(firewall_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall/regla/nueva").data)
    cliente.post(
        "/firewall/regla/guardar",
        data={
            "csrf_token": token,
            "version": "3",
            "nombre": "Regla nueva",
            "accion": "bloquear",
            "origen_tipo": "cualquiera",
            "destino_tipo": "ip",
            "destino_valor": "203.0.113.7",
            "protocolo": "tcp",
            "puertos": "443",
        },
    )
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "La configuración cambió mientras editabas; recarga la página" in html


def test_firewall_peticion_pendiente_se_muestra_como_aviso(entorno, cliente, monkeypatch):
    import routerpanel.firewall as firewall_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(id="falso-id", estado="pendiente", mensaje="Petición enviada; se aplicará en unos segundos.")

    monkeypatch.setattr(firewall_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall").data)
    cliente.post(
        "/firewall/regla/eliminar",
        data={"csrf_token": token, "version": "3", "regla_id": "r_ab12cd34"},
    )
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "se aplicará en unos segundos" in html


def test_firewall_peticion_ok_se_muestra_como_exito(entorno, cliente, simulador_routerd):
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    login(cliente, "admin", "contrasena-admin-1")
    token = extraer_csrf(cliente.get("/firewall").data)
    cliente.post(
        "/firewall/regla/eliminar",
        data={"csrf_token": token, "version": "3", "regla_id": "r_ab12cd34"},
    )
    html = cliente.get("/firewall").data.decode("utf-8")
    assert "Operación aplicada (simulada)." in html


# ------------------------------------------------------------ validación ----


def test_validacion_fw_regla_guardar_forma_contractual():
    from routerpanel import validacion

    datos = {
        "version": 3,
        "regla": {
            "nombre": "Sin juegos",
            "accion": "bloquear",
            "origen": {"tipo": "mac", "valor": "AA:BB:CC:DD:EE:01"},
            "destino": {"tipo": "cualquiera"},
            "protocolo": "tcp",
            "puertos": [{"desde": 443, "hasta": 443}],
            "registrar": False,
            "comentario": "",
        },
    }
    salida = validacion.validar_peticion("fw_regla_guardar", datos)
    assert salida["version"] == 3
    assert salida["regla"]["origen"] == {"tipo": "mac", "valor": "aa:bb:cc:dd:ee:01"}
    assert "id" not in salida["regla"]


def test_validacion_fw_rechaza_formas_invalidas():
    from routerpanel import validacion

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("fw_regla_guardar", {"regla": {}})  # falta version
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "fw_regla_guardar",
            {"version": 3, "regla": {"nombre": "x" * 50, "accion": "bloquear"}},
        )
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "fw_regla_guardar",
            {"version": 3, "regla": {"nombre": "ok", "accion": "saltar"}},
        )
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "fw_regla_guardar",
            {"version": 3, "regla": {"nombre": "ok", "accion": "bloquear",
                                     "origen": {"tipo": "mac", "valor": "no-es-una-mac"}}},
        )
    with pytest.raises(validacion.ErrorValidacion):
        # El MAC sólo tiene sentido como origen, nunca como destino.
        validacion.validar_peticion(
            "fw_regla_guardar",
            {"version": 3, "regla": {"nombre": "ok", "accion": "bloquear",
                                     "destino": {"tipo": "mac", "valor": "aa:bb:cc:dd:ee:01"}}},
        )
    with pytest.raises(validacion.ErrorValidacion):
        # Los puertos sólo aplican a tcp/udp/tcp_udp.
        validacion.validar_peticion(
            "fw_regla_guardar",
            {"version": 3, "regla": {"nombre": "ok", "accion": "bloquear",
                                     "protocolo": "icmp", "puertos": [{"desde": 1, "hasta": 2}]}},
        )
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("fw_regla_eliminar", {"version": 3, "id": "una-id-rara"})
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("fw_regla_mover", {"version": 3, "id": "r_ab12cd34", "posicion": -1})
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("fw_grupo_guardar", {"version": 3, "grupo": {"nombre": "ok", "tipo": "bt"}})


def test_validacion_fw_regla_guardar_admite_edicion_y_posicion():
    from routerpanel import validacion

    datos = {
        "version": 2,
        "regla": {
            "id": "r_ab12cd34",
            "nombre": "Editada",
            "accion": "permitir",
            "origen": {"tipo": "cualquiera"},
            "destino": {"tipo": "cualquiera"},
            "protocolo": "cualquiera",
            "puertos": [],
            "registrar": False,
            "comentario": "hola",
        },
        "posicion": 0,
    }
    salida = validacion.validar_peticion("fw_regla_guardar", datos)
    assert salida["regla"]["id"] == "r_ab12cd34"
    assert salida["posicion"] == 0


def test_validacion_fw_grupo_miembros_segun_tipo():
    from routerpanel import validacion

    ok = validacion.validar_peticion(
        "fw_grupo_guardar",
        {"version": 1, "grupo": {"nombre": "Macs", "tipo": "mac", "miembros": ["AA:BB:CC:DD:EE:01"]}},
    )
    assert ok["grupo"]["miembros"] == ["aa:bb:cc:dd:ee:01"]
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "fw_grupo_guardar",
            {"version": 1, "grupo": {"nombre": "Macs", "tipo": "mac", "miembros": ["192.168.1.1"]}},
        )
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "fw_grupo_guardar",
            {"version": 1, "grupo": {"nombre": "Ips", "tipo": "ip", "miembros": ["no-ip"]}},
        )


# ------------------------------------------------------------------ CSS ---


def _clases_renderizadas(html: str) -> set[str]:
    """Todas las clases de los atributos `class="…"` de una página ya
    renderizada (los `id` no cuentan: eso es selector de JS/labels)."""
    clases: set[str] = set()
    for atributo in re.findall(r'class="([^"]*)"', html):
        clases.update(atributo.split())
    return clases


def test_plantillas_firewall_tienen_regla_en_css_para_sus_clases(entorno, cliente):
    """Las tres plantillas del firewall usan clases `tt-fw-*`/`tt-btn-icono`
    nuevas: cada una debe tener su regla en panel.css, si no la página se
    pinta sin diseño (interruptor, colores de acción, formularios…) y los
    tests funcionales no lo ven."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    ruta_css = Path(__file__).resolve().parent.parent / "routerpanel" / "static" / "css" / "panel.css"
    css = ruta_css.read_text(encoding="utf-8")
    faltan = set()

    login(cliente, "admin", "contrasena-admin-1")
    paginas = ["/firewall", "/firewall/regla/nueva", "/firewall/grupos"]
    for ruta in paginas:
        resp = cliente.get(ruta)
        assert resp.status_code == 200, ruta
        for clase in sorted(_clases_renderizadas(resp.data.decode("utf-8"))):
            if not (clase.startswith("tt-fw-") or clase.startswith("tt-btn-icono")):
                continue
            if not re.search(r"\.%s(?![A-Za-z0-9-])" % re.escape(clase), css):
                faltan.add("%s (%s)" % (clase, ruta))

    assert not faltan, "Clases sin regla en panel.css: " + ", ".join(sorted(faltan))


def test_pagina_firewall_lector_tiene_regla_en_css_para_el_interruptor(entorno, app):
    """El interruptor de sólo lectura (`tt-fw-interruptor-lectura`) sólo se
    pinta con el rol lector: su clase también debe estar en panel.css."""
    _escribir_config_firewall(entorno, FIREWALL_CON_REGLAS)
    ruta_css = Path(__file__).resolve().parent.parent / "routerpanel" / "static" / "css" / "panel.css"
    css = ruta_css.read_text(encoding="utf-8")
    lector = app.test_client()
    login(lector, "lector", "contrasena-lector-1")
    resp = lector.get("/firewall")
    assert resp.status_code == 200
    faltan = {
        clase
        for clase in _clases_renderizadas(resp.data.decode("utf-8"))
        if clase.startswith("tt-fw-")
        and not re.search(r"\.%s(?![A-Za-z0-9-])" % re.escape(clase), css)
    }
    assert not faltan, "Clases sin regla en panel.css: " + ", ".join(sorted(faltan))
