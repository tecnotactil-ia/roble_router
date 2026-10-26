from __future__ import annotations

import json
import os

import pytest
from conftest import extraer_csrf, login, WAN1_ID

from routerpanel import buzon


def test_wan_actualizar_escribe_peticion_valida_y_recibe_respuesta(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/wan/actualizar",
        data={
            "csrf_token": token,
            "wan": WAN1_ID,
            "nombre": "WAN principal",
            "habilitada": "y",
            "peso": "70",
            "prioridad": "1",
        },
    )
    assert resp.status_code == 302

    # La petición debió haberse consumido (routerd simulado la recoge y
    # escribe la respuesta); comprobamos que en algún momento existió un
    # fichero de petición con la forma correcta inspeccionando las
    # respuestas generadas.
    respuestas_dir = str(entorno["respuestas_dir"])
    ficheros = os.listdir(respuestas_dir) if os.path.isdir(respuestas_dir) else []
    assert len(ficheros) == 1
    with open(os.path.join(respuestas_dir, ficheros[0]), "r", encoding="utf-8") as f:
        respuesta = json.load(f)
    assert respuesta["ok"] is True

    resp_redirigida = cliente.get("/wan")
    assert resp_redirigida.status_code == 200


def test_peticion_tiene_forma_contractual(entorno, cliente, simulador_routerd):
    """Sin el simulador: comprueba el fichero de petición escrito en el buzón
    tiene exactamente los campos que exige el contrato."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    cliente.post(
        "/wan/actualizar",
        data={
            "csrf_token": token,
            "wan": WAN1_ID,
            "nombre": "WAN nueva",
            # El checkbox "habilitada" no se envía: en HTML un checkbox
            # desmarcado no viaja en el POST, igual que si el usuario lo
            # desmarca en el formulario real.
            "peso": "",
            "prioridad": "",
        },
    )

    buzon_dir = str(entorno["buzon_dir"])
    ficheros = [n for n in os.listdir(buzon_dir) if n.endswith(".json")]
    assert len(ficheros) == 1
    with open(os.path.join(buzon_dir, ficheros[0]), "r", encoding="utf-8") as f:
        peticion = json.load(f)

    assert set(peticion.keys()) == {"id", "usuario", "accion", "datos"}
    assert peticion["usuario"] == "admin"
    assert peticion["accion"] == "wan_actualizar"
    assert peticion["datos"]["wan"] == WAN1_ID
    assert peticion["datos"]["nombre"] == "WAN nueva"


def test_habilitada_desmarcada_se_envia_como_false(entorno, cliente, simulador_routerd):
    """Una sola casilla «Habilitada»: desmarcada debe significar False y
    viajar siempre en la petición (sin el checkbox auxiliar «cambiar
    estado» que existía antes)."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    cliente.post(
        "/wan/actualizar",
        data={
            "csrf_token": token,
            "wan": WAN1_ID,
            "peso": "",
            "prioridad": "",
            # Sin "habilitada": simula el checkbox desmarcado.
        },
    )

    buzon_dir = str(entorno["buzon_dir"])
    ficheros = [n for n in os.listdir(buzon_dir) if n.endswith(".json")]
    assert len(ficheros) == 1
    with open(os.path.join(buzon_dir, ficheros[0]), "r", encoding="utf-8") as f:
        peticion = json.load(f)

    assert peticion["datos"]["habilitada"] is False


def test_habilitada_marcada_se_envia_como_true(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)

    cliente.post(
        "/wan/actualizar",
        data={
            "csrf_token": token,
            "wan": WAN1_ID,
            "habilitada": "y",
            "peso": "",
            "prioridad": "",
        },
    )

    buzon_dir = str(entorno["buzon_dir"])
    ficheros = [n for n in os.listdir(buzon_dir) if n.endswith(".json")]
    assert len(ficheros) == 1
    with open(os.path.join(buzon_dir, ficheros[0]), "r", encoding="utf-8") as f:
        peticion = json.load(f)

    assert peticion["datos"]["habilitada"] is True


def test_esperar_respuesta_sin_respuesta_no_es_error(entorno):
    """Si nadie responde a tiempo no debe tratarse como un fallo: el mensaje
    debe ser neutro («se enviará igualmente») y el estado "pendiente", nunca
    "error". Se usa un timeout corto para no ralentizar los tests (el valor
    por defecto en producción es ~6 s, antes ~10 s)."""
    peticion_id = buzon.escribir_peticion("admin", "modo", {"modo": "balanceo"})
    respuesta = buzon.esperar_respuesta(peticion_id, timeout_s=0.3, intervalo_s=0.05)
    assert respuesta.estado == "pendiente"
    assert respuesta.mensaje == "Petición enviada; se aplicará en unos segundos."


def test_escribir_peticion_borra_el_tmp_si_falla_el_volcado(entorno, monkeypatch):
    """Si `json.dump`/`fsync`/`rename` fallan a mitad (disco lleno, permisos,
    etc.) no debe quedar un `.tmp` a medias en el buzón: se borra y se
    relanza el error original (revisión Opus, punto 6)."""

    def _dump_que_falla(*args, **kwargs):
        raise OSError("disco lleno (simulado)")

    monkeypatch.setattr(buzon.json, "dump", _dump_que_falla)

    with pytest.raises(OSError):
        buzon.escribir_peticion("admin", "modo", {"modo": "balanceo"})

    buzon_dir = str(entorno["buzon_dir"])
    ficheros = os.listdir(buzon_dir) if os.path.isdir(buzon_dir) else []
    assert ficheros == []


def test_enviar_y_esperar_usa_6_segundos_por_defecto():
    import inspect

    firma = inspect.signature(buzon.enviar_y_esperar)
    assert firma.parameters["timeout_s"].default == 6.0
    firma_espera = inspect.signature(buzon.esperar_respuesta)
    assert firma_espera.parameters["timeout_s"].default == 6.0
