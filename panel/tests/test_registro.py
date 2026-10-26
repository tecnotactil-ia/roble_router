from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from conftest import login


def _escribir_oplog(ruta, operaciones):
    """Escribe el oplog en orden cronológico (más antiguo primero), tal y
    como lo hace routerd al ir anexando líneas: `leer_oplog` las invierte
    después para mostrar las más recientes primero."""
    lineas = [json.dumps(op, ensure_ascii=False) for op in operaciones]
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")


def test_registro_agrupa_por_dia(entorno, cliente):
    ahora = datetime.now(timezone.utc)
    operaciones = [
        {
            "fecha": (ahora - timedelta(days=5)).isoformat(),
            "usuario": "sistema",
            "accion": "dnsmasq",
            "datos": {},
            "ok": False,
            "mensaje": "Fallo al activar DHCP/DNS.",
        },
        {
            "fecha": (ahora - timedelta(days=1)).isoformat(),
            "usuario": "admin",
            "accion": "wan_actualizar",
            "datos": {"wan": "WAN1"},
            "ok": True,
            "mensaje": "WAN actualizada.",
        },
        {
            "fecha": ahora.isoformat(),
            "usuario": "admin",
            "accion": "modo",
            "datos": {"modo": "balanceo"},
            "ok": True,
            "mensaje": "Modo cambiado a balanceo.",
        },
    ]
    _escribir_oplog(entorno["oplog_path"], operaciones)

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/registro")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    assert "Hoy" in html
    assert "Ayer" in html
    assert "tt-registro-grupo" in html
    assert "tt-registro-item" in html
    # Más reciente primero: el grupo "Hoy" aparece antes que "Ayer".
    assert html.index("Hoy") < html.index("Ayer")


def test_registro_filtros_y_buscador_no_rompen_el_render(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/registro")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'id="tt-registro-busqueda"' in html
    assert 'data-filtro="todos"' in html
    assert 'data-filtro="error"' in html
    assert "<table" not in html.lower()


def test_registro_datos_son_plegables(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/registro")
    html = resp.data.decode("utf-8")
    assert "<details" in html
    assert "<summary>Datos</summary>" in html
