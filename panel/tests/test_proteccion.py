from __future__ import annotations

import json
import os
import sys

import pytest

from conftest import extraer_csrf, login

from routerpanel.buzon import RespuestaPeticion

CONFIG_BLOQUEO_COMPLETA = {
    "habilitado": True,
    "listas": ["hagezi_pro", "hagezi_tif"],
    "lista_blanca": ["tienda-de-confianza.com"],
    "lista_negra": ["anuncios-molestos.ejemplo.com"],
    "forzar_dns": True,
    "bloquear_doh": True,
    "actualizar_h": 24,
    "registro_dns_dias": 30,
}


def _escribir_config_bloqueo(entorno, bloqueo) -> None:
    """Sustituye `estado["config"]["bloqueo"]` en el estado.json de prueba
    (o lo quita por completo si `bloqueo` es None -el estado por defecto del
    fixture, que refleja lo que routerd publica hoy-), replicando el patrón
    de tests/test_wifi.py."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    if bloqueo is None:
        estado["config"].pop("bloqueo", None)
    else:
        estado["config"]["bloqueo"] = bloqueo
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")


def _escribir_bloqueo_version(entorno, version) -> None:
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    if version is None:
        estado["config"].pop("bloqueo_version", None)
    else:
        estado["config"]["bloqueo_version"] = version
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")


def _escribir_bloqueo_json(entorno, contenido) -> None:
    if contenido is None:
        try:
            os.remove(str(entorno["bloqueo_path"]))
        except FileNotFoundError:
            pass
        return
    entorno["bloqueo_path"].write_text(json.dumps(contenido), encoding="utf-8")


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


def test_proteccion_sin_config_bloqueo_muestra_aviso_y_deshabilita(entorno, cliente):
    """Caso defensivo (BLOQ): un routerd más antiguo, o una instalación a
    medias, sin "bloqueo" en "config" -el fixture por defecto SÍ lo incluye,
    porque el routerd actual lo publica siempre-. La página no debe fingir
    una configuración ni dejar guardar nada que dependa de ella."""
    _escribir_config_bloqueo(entorno, None)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "todavía no ha enviado su configuración de bloqueo" in html
    # Ningún botón «Guardar» de las 3 secciones que dependen de config.bloqueo.
    assert "Guardar listas" not in html
    assert "Guardar opciones" not in html
    # El segmentado Activado/Desactivado no debe aparecer con ningún valor
    # marcado como si fuera el real.
    assert "checked" not in html.split('id="tt-proteccion-habilitado-1"')[1].split(">")[0]
    assert "checked" not in html.split('id="tt-proteccion-habilitado-0"')[1].split(">")[0]
    # Las acciones independientes de config.bloqueo siguen disponibles.
    assert "Actualizar listas ahora" in html
    assert 'action="/proteccion/probar"' in html


def test_proteccion_sin_config_bloqueo_catalogo_no_marca_ninguna_lista(entorno, cliente):
    _escribir_config_bloqueo(entorno, None)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    # Ninguna casilla del catálogo debe salir marcada por defecto.
    assert 'name="listas" value="hagezi_pro" id="tt-proteccion-lista-hagezi_pro" aria-describedby="tt-proteccion-lista-hagezi_pro-desc" checked' not in html


def test_proteccion_con_config_bloqueo_completa_rinde_normal(entorno, cliente):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "todavía no ha enviado su configuración de bloqueo" not in html
    assert "Guardar listas" in html
    assert "Guardar opciones" in html
    assert "tienda-de-confianza.com" in html
    assert "anuncios-molestos.ejemplo.com" in html


def test_proteccion_config_bloqueo_con_tipos_disparatados_no_rompe(entorno, cliente):
    _escribir_config_bloqueo(
        entorno,
        {
            "habilitado": "sí",
            "listas": "no-es-una-lista",
            "lista_blanca": 5,
            "lista_negra": {"no": "lista"},
            "forzar_dns": "sí",
            "actualizar_h": float("nan"),
            "registro_dns_dias": "treinta",
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    assert resp.status_code == 200


def test_proteccion_sin_bloqueo_json_no_rompe(entorno, cliente):
    _escribir_bloqueo_json(entorno, None)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "No hay datos de bloqueo todavía" in html


def test_proteccion_guarda_variacion_texto_amable(entorno, cliente):
    """MEDIA: el texto deja claro que lo que se ve (recuentos) es de la
    pasada NUEVA sin aplicar, y que sigue activa la anterior -ni jerga
    técnica ni el mensaje crudo del núcleo-."""
    bloqueo_json = json.loads(entorno["bloqueo_path"].read_text(encoding="utf-8"))
    bloqueo_json["activo"] = False
    bloqueo_json["error"] = (
        "el total de dominios bloqueados varía más de un 50% respecto a la última pasada "
        "(100000 -> 5000) sin haber cambiado las listas elegidas: se mantiene la config "
        "anterior por seguridad (podría ser una lista rota)"
    )
    entorno["bloqueo_path"].write_text(json.dumps(bloqueo_json), encoding="utf-8")
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "Los recuentos que ves son de la pasada nueva, que NO se ha aplicado" in html
    assert "sigue activa la anterior" in html
    # El error crudo del núcleo no debe mostrarse duplicado como un segundo
    # aviso de error independiente cuando es justo este caso.
    assert "se mantiene la config anterior por seguridad" not in html


def test_proteccion_bloqueo_json_con_tipos_disparatados_no_rompe(entorno, cliente):
    _escribir_bloqueo_json(
        entorno,
        {
            "habilitado": "sí",
            "listas": "no-es-una-lista",
            "total_dominios": float("nan"),
            "generado": 12345,
            "siguiente": {"no": "es texto"},
            "activo": "no-es-bool",
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    assert resp.status_code == 200


def test_proteccion_muestra_total_dominios_con_separador_de_miles(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "254.329" in html  # BLOQUEO_JSON.total_dominios = 254329
    assert "HaGeZi Threat Intelligence Feeds" in html
    assert "Recomendada" in html


def test_proteccion_lectura_ve_formularios_de_escritura_deshabilitados(entorno, cliente):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "lector", "contrasena-lector-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "tt-btn-peligro" not in html
    assert "Guardar listas" not in html
    assert "Guardar opciones" not in html
    assert " disabled" in html


def test_proteccion_lectura_puede_usar_esta_bloqueado(entorno, cliente):
    """BAJA: bloqueo_probar es de sólo lectura, así que el botón/øformulario
    de "¿Está bloqueado?" debe seguir disponible para un rol de lectura."""
    login(cliente, "lector", "contrasena-lector-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert 'action="/proteccion/probar"' in html
    assert "<button" in html.split('action="/proteccion/probar"')[1].split("</form>")[0]


def test_proteccion_menu_tiene_enlace_entre_firewall_y_configuracion(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    pos_firewall = html.index("Firewall")
    pos_proteccion = html.index(">Protección<")
    pos_config = html.index(">Configuración<")
    assert pos_firewall < pos_proteccion < pos_config


def test_proteccion_recorte_de_rango_avisa(entorno, cliente):
    _escribir_config_bloqueo(entorno, {**CONFIG_BLOQUEO_COMPLETA, "actualizar_h": 999})
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "fuera de rango" in html
    assert "168 h" in html
    assert "se guardará ajustado al próximo Guardar" in html


def test_proteccion_listas_fuera_de_catalogo_se_ignoran_y_avisan(entorno, cliente):
    _escribir_config_bloqueo(entorno, {**CONFIG_BLOQUEO_COMPLETA, "listas": ["hagezi_pro", "lista-vieja-retirada"]})
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "lista-vieja-retirada" in html
    assert "ya no están en el catálogo" in html
    # La lista retirada no debe aparecer marcada en ningún checkbox del catálogo.
    assert 'value="hagezi_pro" id="tt-proteccion-lista-hagezi_pro"' in html
    assert "tt-proteccion-lista-lista-vieja-retirada" not in html


def test_proteccion_fail_open_banner_cuando_el_estado_lo_indica(entorno, cliente):
    """docs/CONTRATO.md: `estado.json` -> `dns_emergencia` (SIEMPRE
    presente, M6/M1 ronda 3). El aviso es informativo (tt-alerta-warning,
    no tt-alerta-error: "se resuelve solo"), nunca se pide acción."""
    estado = json.loads(entorno["estado_path"].read_text(encoding="utf-8"))
    estado["dns_emergencia"] = {
        "activo": True,
        "desde": "2026-10-11T09:00:00+00:00",
        "motivo": "dnsmasq lleva varios arranques fallidos seguidos: servers-file vaciado.",
    }
    entorno["estado_path"].write_text(json.dumps(estado), encoding="utf-8")
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "Modo de emergencia DNS activo" in html
    assert "tt-alerta-warning" in html.split("Modo de emergencia DNS activo")[0][-400:]
    assert "Se resuelve solo" in html
    # El motivo técnico va DENTRO de un <details> "Detalles técnicos", no en
    # el texto amable fijo que se lee de corrido.
    assert "Detalles técnicos" in html
    bloque_detalles = html.split("<summary>Detalles técnicos</summary>")[1].split("</details>")[0]
    assert "dnsmasq lleva varios arranques fallidos seguidos" in bloque_detalles


def test_proteccion_sin_fail_open_no_muestra_banner(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "Modo de emergencia DNS activo" not in html


def test_proteccion_h3_bloqueo_dns_y_aria_describedby_presentes(entorno, cliente):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "<h3" in html and "Bloqueo DNS" in html
    assert 'aria-describedby="tt-proteccion-forzar-dns-desc"' in html
    assert 'id="tt-proteccion-forzar-dns-desc"' in html


# ------------------------------------------------------------- contrato ----


def test_proteccion_config_estado_escribe_forma_contractual_y_relee_el_resto(entorno, cliente, simulador_routerd):
    """ALTA: la sección «estado» sólo envía `habilitado`; el resto de campos
    del contrato debe venir de RELEER estado.json en el servidor, no de lo
    que el cliente llevara oculto desde que se pintó la página."""
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    # Cambia la config EN DISCO después de pintar la página (simula otra
    # persona guardando mientras tanto): la petición final debe reflejar
    # esto, no lo que había cuando se cargó /proteccion.
    _escribir_config_bloqueo(entorno, {**CONFIG_BLOQUEO_COMPLETA, "listas": ["hagezi_nsfw"], "actualizar_h": 48})

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "estado", "habilitado": "0"},
    )
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "bloqueo_config"
    assert peticion["datos"]["habilitado"] is False
    assert peticion["datos"]["listas"] == ["hagezi_nsfw"]
    assert peticion["datos"]["actualizar_h"] == 48


def test_proteccion_config_listas_filtra_ids_fuera_de_catalogo(entorno, cliente, simulador_routerd):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/config",
        data={
            "csrf_token": token,
            "seccion": "listas",
            "listas": ["hagezi_pro", "lista-inventada"],
        },
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"]["listas"] == ["hagezi_pro"]


def test_proteccion_config_opciones_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/config",
        data={
            "csrf_token": token,
            "seccion": "opciones",
            "actualizar_h": "12",
            "registro_dns_dias": "7",
            # forzar_dns/bloquear_doh desmarcados: ausentes del POST.
        },
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"] == {
        "habilitado": True,
        "listas": ["hagezi_pro", "hagezi_tif"],
        "forzar_dns": False,
        "bloquear_doh": False,
        "actualizar_h": 12,
        "registro_dns_dias": 7,
    }


def test_proteccion_config_version_se_incluye_cuando_esta_publicada(entorno, cliente, simulador_routerd):
    """El campo oculto `version` lo pinta la plantilla (form.hidden_tag());
    aquí se extrae del HTML real -como haría un navegador- en vez de
    asumirlo, para probar también que SE PINTA de verdad."""
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    _escribir_bloqueo_version(entorno, "abc1234567890def")
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)
    html = resp.data.decode("utf-8")
    assert 'name="version" type="hidden" value="abc1234567890def"' in html

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "estado", "habilitado": "1", "version": "abc1234567890def"},
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"]["version"] == "abc1234567890def"


def test_proteccion_config_sin_bloqueo_version_publicada_no_incluye_version(entorno, cliente, simulador_routerd):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "estado", "habilitado": "1"},
    )
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert "version" not in peticion["datos"]


def test_proteccion_config_sin_config_bloqueo_rechaza_sin_escribir(entorno, cliente):
    """BLOQ: aunque el formulario en sí sea válido -se pintó con
    `config.bloqueo` disponible-, si al procesar el POST la RELECTURA
    FRESCA ya no lo encuentra (p. ej. un rollback de routerd a mitad de
    sesión), la petición no se envía nunca al buzón."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    _escribir_config_bloqueo(entorno, None)

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "estado", "habilitado": "1"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "todavía no ha enviado su configuración de bloqueo" in html


def test_proteccion_config_seccion_desconocida_no_escribe(entorno, cliente):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "otra-cosa"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_proteccion_actualizar_escribe_forma_contractual_sin_forzar(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/proteccion/actualizar", data={"csrf_token": token})
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "bloqueo_actualizar"
    assert peticion["datos"] == {}


def test_proteccion_actualizar_forzar_incluye_el_campo(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/proteccion/actualizar", data={"csrf_token": token, "forzar": "1"})
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "bloqueo_actualizar"
    assert peticion["datos"] == {"forzar": True}


def test_proteccion_probar_escribe_forma_contractual_y_muestra_resultado(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/proteccion/probar", data={"csrf_token": token, "dominio": "Ejemplo.COM"})
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "bloqueo_probar"
    assert peticion["datos"] == {"dominio": "ejemplo.com"}


def test_proteccion_probar_resultado_bloqueado_se_muestra_en_recuadro(entorno, cliente, monkeypatch):
    import routerpanel.proteccion as proteccion_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(
            id="falso-id", estado="ok", mensaje="BLOQUEADO: está en la lista «HaGeZi Pro»."
        )

    monkeypatch.setattr(proteccion_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    cliente.post("/proteccion/probar", data={"csrf_token": token, "dominio": "anuncios.ejemplo.com"})
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "tt-proteccion-resultado-bloqueado" in html
    assert 'id="tt-proteccion-resultado"' in html
    assert 'tabindex="-1"' in html
    assert "BLOQUEADO" in html
    assert "anuncios.ejemplo.com" in html
    assert 'src="/static/js/proteccion.js"' in html

    # El resultado se consume una sola vez (como el escaneo Wi-Fi pendiente).
    html2 = cliente.get("/proteccion").data.decode("utf-8")
    assert "tt-proteccion-resultado-bloqueado" not in html2


def test_proteccion_probar_resultado_permitido_se_muestra_en_recuadro(entorno, cliente, monkeypatch):
    import routerpanel.proteccion as proteccion_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(
            id="falso-id", estado="ok", mensaje="NO bloqueado: no aparece en ninguna lista activa."
        )

    monkeypatch.setattr(proteccion_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    cliente.post("/proteccion/probar", data={"csrf_token": token, "dominio": "ejemplo.com"})
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "tt-proteccion-resultado-permitido" in html
    assert "NO bloqueado" in html


def test_proteccion_probar_resultado_pendiente_no_se_pinta_como_permitido(entorno, cliente, monkeypatch):
    import routerpanel.proteccion as proteccion_mod

    def _falso_enviar_y_esperar(usuario, accion, datos, timeout_s=6.0):
        return RespuestaPeticion(
            id="falso-id", estado="pendiente", mensaje="Petición enviada; se aplicará en unos segundos."
        )

    monkeypatch.setattr(proteccion_mod.buzon, "enviar_y_esperar", _falso_enviar_y_esperar)

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    cliente.post("/proteccion/probar", data={"csrf_token": token, "dominio": "ejemplo.com"})
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "tt-proteccion-resultado-pendiente" in html
    assert "tt-proteccion-resultado-permitido" not in html
    assert "tt-proteccion-resultado-bloqueado" not in html


def test_proteccion_lista_blanca_agregar_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={"csrf_token": token, "tipo": "blanca", "accion": "agregar", "dominio": "Ejemplo.COM"},
    )
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["accion"] == "bloqueo_lista"
    assert peticion["datos"] == {"tipo": "blanca", "accion": "agregar", "dominio": "ejemplo.com"}


def test_proteccion_lista_negra_quitar_escribe_forma_contractual(entorno, cliente, simulador_routerd):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={"csrf_token": token, "tipo": "negra", "accion": "quitar", "dominio": "malware.ejemplo.com"},
    )
    assert resp.status_code == 302

    peticion = _leer_peticion_unica(entorno)
    assert peticion["datos"] == {"tipo": "negra", "accion": "quitar", "dominio": "malware.ejemplo.com"}


# ------------------------------------------------------------ rechazos ----


def test_proteccion_config_opciones_actualizar_h_fuera_de_rango_no_escribe(entorno, cliente):
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "opciones", "actualizar_h": "999", "registro_dns_dias": "30"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_proteccion_config_opciones_sin_actualizar_h_muestra_mensaje_propio(entorno, cliente):
    """MEDIA: IntegerField con InputRequired + mensaje en español propio
    (nunca el genérico "Formulario inválido.")."""
    _escribir_config_bloqueo(entorno, CONFIG_BLOQUEO_COMPLETA)
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/config",
        data={"csrf_token": token, "seccion": "opciones", "registro_dns_dias": "30"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "La frecuencia de actualización es obligatoria." in html


def test_proteccion_lista_dominio_invalido_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={"csrf_token": token, "tipo": "negra", "accion": "agregar", "dominio": "no es un dominio"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_proteccion_lista_negra_sufijo_publico_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={"csrf_token": token, "tipo": "negra", "accion": "agregar", "dominio": "co.uk"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "sufijo público" in html


def test_proteccion_lista_negra_dominio_protegido_no_escribe(entorno, cliente):
    """BAJA: paridad con router_bloqueo.PROTEGIDOS_FIJOS."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={"csrf_token": token, "tipo": "negra", "accion": "agregar", "dominio": "github.com"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "dominio protegido" in html


def test_proteccion_lista_negra_subdominio_protegido_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={"csrf_token": token, "tipo": "negra", "accion": "agregar", "dominio": "raw.githubusercontent.com"},
    )
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


def test_proteccion_probar_dominio_invalido_no_escribe(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/proteccion/probar", data={"csrf_token": token, "dominio": "###"})
    assert resp.status_code == 302
    assert _ficheros_buzon(entorno) == []


# -------------------------------------------------------------- rol lectura


def test_proteccion_rutas_mutantes_rechazadas_para_lectura(entorno, cliente):
    """Todo lo que cambia configuración o dispara una acción de sistema
    sigue siendo admin-only; bloqueo_probar (sólo lectura) se prueba aparte."""
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    for ruta, datos in (
        ("/proteccion/config", {"seccion": "estado", "habilitado": "1"}),
        ("/proteccion/actualizar", {}),
        ("/proteccion/lista", {"tipo": "blanca", "accion": "agregar", "dominio": "ejemplo.com"}),
    ):
        resp = cliente.post(ruta, data={**datos, "csrf_token": token})
        assert resp.status_code == 403, f"{ruta} debería rechazar a un usuario de lectura"
    assert _ficheros_buzon(entorno) == []


def test_proteccion_probar_permitido_para_lectura(entorno, cliente, simulador_routerd):
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post("/proteccion/probar", data={"csrf_token": token, "dominio": "ejemplo.com"})
    assert resp.status_code == 302
    peticion = _leer_peticion_unica(entorno)
    assert peticion["usuario"] == "lector"
    assert peticion["accion"] == "bloqueo_probar"


def test_proteccion_lectura_sin_sesion_redirige_a_login(cliente):
    resp = cliente.get("/proteccion")
    assert resp.status_code in (302, 401, 403)


# -------------------------------------------------------- CSRF: sin token --


def test_proteccion_post_sin_csrf_token_es_rechazado(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.post("/proteccion/actualizar", data={})
    assert resp.status_code in (400, 403)
    assert _ficheros_buzon(entorno) == []


# -------------------------------------------------------------- XSS -------


def test_proteccion_lista_blanca_con_dominio_invalido_hostil_no_rompe_render(entorno, cliente):
    """Un dominio malicioso nunca puede escribirse (se valida antes de
    tocar el buzón), pero si por lo que sea YA estuviera en estado.json
    (p. ej. escrito a mano, o una versión antigua del núcleo), el render no
    debe romperse ni dejar HTML sin escapar."""
    hostil = '"><script>alert(1)</script>.com'
    _escribir_config_bloqueo(
        entorno,
        {
            "habilitado": True,
            "listas": ["hagezi_pro"],
            "lista_blanca": [hostil],
            "lista_negra": [],
            "forzar_dns": True,
            "bloquear_doh": True,
            "actualizar_h": 24,
            "registro_dns_dias": 30,
        },
    )
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_proteccion_mensaje_de_error_con_html_queda_escapado(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/proteccion")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/proteccion/lista",
        data={
            "csrf_token": token,
            "tipo": "negra",
            "accion": "agregar",
            "dominio": '<script>alert(1)</script>',
        },
    )
    assert resp.status_code == 302
    html = cliente.get("/proteccion").data.decode("utf-8")
    assert "<script>alert(1)</script>" not in html


# -------------------------------------------------------- normalización ---


def test_proteccion_validacion_rechaza_desde_validacion_py_para_todas_las_acciones():
    """Unidad rápida de los 4 validadores nuevos, sin pasar por Flask (igual
    que tests/test_validacion.py)."""
    from routerpanel import validacion

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("bloqueo_config", {"habilitado": True})  # faltan campos

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "bloqueo_config",
            {
                "habilitado": True,
                "listas": ["no-existe"],
                "forzar_dns": True,
                "bloquear_doh": True,
                "actualizar_h": 24,
                "registro_dns_dias": 30,
            },
        )

    ok = validacion.validar_peticion(
        "bloqueo_config",
        {
            "habilitado": True,
            "listas": ["hagezi_pro", "hagezi_pro"],
            "forzar_dns": False,
            "bloquear_doh": False,
            "actualizar_h": 24,
            "registro_dns_dias": 30,
        },
    )
    assert ok["listas"] == ["hagezi_pro"]  # deduplicado y ordenado

    # `version` opcional: hex de 16 caracteres (docs/CONTRATO.md), pasa
    # adelante tal cual si cumple el formato.
    con_version = validacion.validar_peticion(
        "bloqueo_config",
        {
            "habilitado": True, "listas": [], "forzar_dns": False, "bloquear_doh": False,
            "actualizar_h": 24, "registro_dns_dias": 30, "version": "abc1234567890def",
        },
    )
    assert con_version["version"] == "abc1234567890def"
    for version_invalida in ("", "abc123", "ABC1234567890DEF", "g" * 16, "a" * 17):
        with pytest.raises(validacion.ErrorValidacion):
            validacion.validar_peticion(
                "bloqueo_config",
                {
                    "habilitado": True, "listas": [], "forzar_dns": False, "bloquear_doh": False,
                    "actualizar_h": 24, "registro_dns_dias": 30, "version": version_invalida,
                },
            )

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("bloqueo_lista", {"tipo": "negra", "accion": "agregar", "dominio": "co.uk"})

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("bloqueo_lista", {"tipo": "negra", "accion": "agregar", "dominio": "github.com"})

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("bloqueo_probar", {"dominio": "###"})

    assert validacion.validar_peticion("bloqueo_actualizar", {}) == {}
    assert validacion.validar_peticion("bloqueo_actualizar", {"forzar": True}) == {"forzar": True}

    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("bloqueo_actualizar", {"forzar": "si"})


# --------------------------------------------- paridad con el núcleo (BAJA)


def _cargar_modulo_core(nombre):
    """Importa un módulo de `core/` directamente desde disco, sin tocarlo:
    sólo lectura, vía sys.path, para comparar su comportamiento con lo que
    replica el panel en validacion.py (que nunca importa core/ en producción
    -el panel no tiene privilegios- pero sí debe comportarse IGUAL)."""
    raiz_core = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "core"))
    if raiz_core not in sys.path:
        sys.path.insert(0, raiz_core)
    import importlib

    return importlib.import_module(nombre)


DOMINIOS_BATERIA = [
    "Ejemplo.COM", "ejemplo.com.", "EJEMPLO.COM", "  ejemplo.com  ",
    "xn--mnchen-3ya.de", "münchen.de", "a" * 64 + ".com", "a" * 63 + ".com",
    "1.2.3.4", "123.com", "co.uk", "sub.co.uk", "example.co.uk",
    "ejemplo..com", "-ejemplo.com", "ejemplo-.com", ".ejemplo.com",
    "ejemplo.com/x", "ejemplo.com#frag", "ejemplo.com;x", "ejemplo com",
    "ejemplo.com\n", "", "#comentario", None, 123, "a.b", "a" * 250 + ".com",
    "a" * 300 + ".com", "東京.jp",
]


def test_paridad_catalogo_ids_con_core_router_bloqueo():
    router_bloqueo = _cargar_modulo_core("router_bloqueo")
    from routerpanel import validacion

    assert validacion.CATALOGO_BLOQUEO_IDS == frozenset(router_bloqueo.CATALOGO.keys())


def test_paridad_sufijos_publicos_con_core_router_bloqueo():
    router_bloqueo = _cargar_modulo_core("router_bloqueo")
    from routerpanel import validacion

    assert validacion.SUFIJOS_PUBLICOS_DOS_ETIQUETAS == router_bloqueo.SUFIJOS_PUBLICOS_DOS_ETIQUETAS


def test_paridad_protegidos_fijos_con_core_router_bloqueo():
    router_bloqueo = _cargar_modulo_core("router_bloqueo")
    from routerpanel import validacion

    # El panel no incluye el dominio de casa (router.json -> "dominio"), que
    # no puede leer; PROTEGIDOS_FIJOS sí debe coincidir exactamente.
    assert validacion.PROTEGIDOS_FIJOS == router_bloqueo.PROTEGIDOS_FIJOS


def test_paridad_normalizar_dominio_con_core_router_bloqueo():
    router_bloqueo = _cargar_modulo_core("router_bloqueo")
    from routerpanel import validacion

    for crudo in DOMINIOS_BATERIA:
        esperado = router_bloqueo.normalizar_dominio(crudo)
        obtenido = validacion.normalizar_dominio_bloqueo(crudo)
        assert obtenido == esperado, f"normalizar_dominio({crudo!r}): core={esperado!r} panel={obtenido!r}"


def test_paridad_catalogo_ids_coincide_con_proteccion_py():
    """El catálogo de visualización de proteccion.py (sólo nombre/descripción,
    sin URLs) debe tener exactamente los mismos ids que el núcleo."""
    router_bloqueo = _cargar_modulo_core("router_bloqueo")
    from routerpanel import proteccion

    assert frozenset(proteccion.CATALOGO_BLOQUEO.keys()) == frozenset(router_bloqueo.CATALOGO.keys())
