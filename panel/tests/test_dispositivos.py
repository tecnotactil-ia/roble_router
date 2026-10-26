from __future__ import annotations

from conftest import MAC_CADUCADO, MAC_RESERVA, MAC_SIN_VECINO, login

from routerpanel import estado as estado_mod


def test_lease_sin_vecino_no_se_marca_conectado(entorno):
    est = estado_mod.leer_estado()
    leases, error = estado_mod.leer_leases()
    assert error is None
    dispositivos = estado_mod.construir_dispositivos(est, leases)
    por_mac = {d["mac"]: d for d in dispositivos}

    assert por_mac[MAC_SIN_VECINO]["estado"] != "Conectado"
    assert por_mac[MAC_SIN_VECINO]["estado"] == "Inactivo"


def test_lease_con_vecino_reachable_se_marca_conectado(entorno):
    est = estado_mod.leer_estado()
    leases, _ = estado_mod.leer_leases()
    dispositivos = estado_mod.construir_dispositivos(est, leases)
    por_mac = {d["mac"]: d for d in dispositivos}

    assert por_mac[MAC_RESERVA]["estado"] == "Conectado"
    assert por_mac[MAC_RESERVA]["reserva"] is True


def test_lease_caducado_se_marca_correctamente(entorno):
    est = estado_mod.leer_estado()
    leases, _ = estado_mod.leer_leases()
    dispositivos = estado_mod.construir_dispositivos(est, leases)
    por_mac = {d["mac"]: d for d in dispositivos}

    assert por_mac[MAC_CADUCADO]["estado"] == "Lease caducado"


def test_pagina_dispositivos_renderiza(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/dispositivos")
    assert resp.status_code == 200
    assert "Conectado".encode() in resp.data


def test_dispositivos_buscador_y_filtros_no_rompen_el_render(cliente):
    """La lista compacta trae buscador y chips de filtro rápido; su
    presencia (y la de las filas) no debe romper el renderizado."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/dispositivos")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'id="tt-dispositivos-busqueda"' in html
    assert 'data-filtro="todos"' in html
    assert 'data-filtro="conectado"' in html
    assert 'data-filtro="inactivo"' in html
    assert 'data-filtro="reservado"' in html
    assert "tt-dispositivo-fila" in html
    assert "<table" not in html.lower()


def test_dispositivos_modales_contienen_csrf_y_campos_esperados(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/dispositivos")
    html = resp.data.decode("utf-8")

    assert 'id="tt-modal-etiquetar"' in html
    assert 'id="tt-modal-reservar"' in html
    assert 'id="tt-modal-quitar-reserva"' in html

    # Cada modal es un <form> independiente con su propio csrf_token y los
    # campos que espera el backend (ver formularios.py / dispositivos.py).
    assert html.count('name="csrf_token"') >= 3
    assert 'id="tt-modal-etiquetar-mac"' in html
    assert 'name="mac"' in html
    assert 'name="etiqueta"' in html
    assert 'name="ip"' in html
    assert 'name="nombre"' in html


def test_dispositivos_orden_conectados_primero_por_ip_numerica(cliente):
    """Orden esperado: conectados primero; dentro de cada grupo, por IP
    numérica (no por texto, que pondría .101 antes que .20)."""
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/dispositivos")
    html = resp.data.decode("utf-8")
    pos_reserva = html.index(MAC_RESERVA)  # Conectado, 192.168.50.10
    pos_sin_vecino = html.index(MAC_SIN_VECINO)  # Inactivo, 192.168.50.20
    pos_caducado = html.index(MAC_CADUCADO)  # Lease caducado, 192.168.50.30
    assert pos_reserva < pos_sin_vecino < pos_caducado
