from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from routerpanel import create_app
from routerpanel import usuarios as usuarios_mod

WAN1_ID = "R58M123ABC"
WAN2_ID = "R58M456DEF"

MAC_RESERVA = "aa:bb:cc:dd:ee:ff"
MAC_SIN_VECINO = "11:22:33:44:55:66"
MAC_CADUCADO = "77:88:99:aa:bb:cc"


def _estado_dict(generado: str | None = None) -> dict:
    ahora = generado or datetime.now(timezone.utc).isoformat()
    return {
        "generado": ahora,
        "uptime_s": 12345,
        "modo": "balanceo",
        "fase": "produccion",
        "lan": {"interfaz": "enp2s0", "ip": "192.168.50.1/24", "activa": True},
        "servicios": {"dnsmasq": "active", "nftables_router": True, "balanceo": True, "routerd": "active"},
        "internet": True,
        "wans": [
            {
                "id": WAN1_ID,
                "nombre": "WAN1",
                "interfaz": "enx0a1b2c3d4e5f",
                "telefono": "SAMSUNG SM-A515F",
                "ip": "192.168.42.17/24",
                "gateway": "192.168.42.129",
                "tethering": True,
                "internet": True,
                "latencia_ms": 48.2,
                "perdida_pct": 0,
                "habilitada": True,
                "en_balanceo": True,
                "peso": 50,
                "prioridad": 1,
                "rx_bytes": 123,
                "tx_bytes": 456,
                "rx_bps": 1000,
                "tx_bps": 200,
                "ultimo_cambio": ahora,
                "presente": True,
            },
            {
                "id": WAN2_ID,
                "nombre": "WAN2",
                "interfaz": "enx0a1b2c3d4e60",
                "telefono": None,
                "ip": None,
                "gateway": None,
                "tethering": False,
                "internet": False,
                "latencia_ms": None,
                "perdida_pct": None,
                "habilitada": False,
                "en_balanceo": False,
                "peso": 50,
                "prioridad": 2,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_bps": 0,
                "tx_bps": 0,
                "ultimo_cambio": ahora,
                "presente": False,
            },
        ],
        "config": {
            "lan": {"interfaz": "enp2s0", "red": "192.168.50.0/24", "ip": "192.168.50.1"},
            "dhcp": {"inicio": "192.168.50.100", "fin": "192.168.50.250", "lease": "12h"},
            "dns": ["1.1.1.1", "9.9.9.9"],
            "monitor": {"destinos": ["1.1.1.1", "8.8.8.8"], "intervalo_s": 5, "fallos_caida": 3, "exitos_alta": 2},
            "reservas": [{"mac": MAC_RESERVA, "ip": "192.168.50.10", "nombre": "nas"}],
            "etiquetas": {MAC_RESERVA: "NAS del salón"},
            # routerd publica SIEMPRE "bloqueo" (copia de router.json) y
            # "bloqueo_version" dentro de "config" (docs/CONTRATO.md,
            # core/routerd.py -> _config_para_panel()): el fixture refleja
            # eso por defecto. tests/test_proteccion.py también prueba el
            # caso defensivo sin "bloqueo" (routerd más antiguo, instalación
            # a medias) quitándolo explícitamente con `_escribir_config_bloqueo`.
            "bloqueo": {
                "habilitado": True,
                "listas": ["hagezi_pro", "hagezi_tif"],
                "lista_blanca": [],
                "lista_negra": [],
                "forzar_dns": True,
                "bloquear_doh": True,
                "actualizar_h": 24,
                "registro_dns_dias": 30,
            },
            "bloqueo_version": "0123456789abcdef",
        },
        "vecinos": {MAC_RESERVA: "REACHABLE"},
        # M6/M1 (ronda 3): fail-open del bloqueador DNS, SIEMPRE presente
        # (docs/CONTRATO.md); por defecto inactivo.
        "dns_emergencia": {"activo": False, "desde": None, "motivo": None},
    }


BLOQUEO_JSON = {
    "habilitado": True,
    "listas": [
        {"id": "hagezi_pro", "nombre": "HaGeZi Pro", "dominios": 234567,
         "actualizada": "2026-10-11T10:00:00+00:00", "error": None},
        {"id": "hagezi_tif", "nombre": "HaGeZi Threat Intelligence Feeds", "dominios": 19762,
         "actualizada": "2026-10-11T10:00:05+00:00", "error": None},
    ],
    "total_dominios": 254329,
    "generado": "2026-10-11T10:00:10+00:00",
    "siguiente": "2026-10-12T10:00:10+00:00",
    "activo": True,
}


FIREWALL_TXT = """table inet filtro_router {
    chain entrada {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname "enp2s0" accept
        drop
    }
}
"""


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    estado_path = tmp_path / "estado.json"
    firewall_path = tmp_path / "firewall.txt"
    leases_path = tmp_path / "dnsmasq.leases"
    oplog_path = tmp_path / "operaciones.log"
    buzon_dir = tmp_path / "solicitudes"
    respuestas_dir = tmp_path / "respuestas"
    usuarios_path = tmp_path / "usuarios.json"
    secret_path = tmp_path / "secret_key"
    audit_path = tmp_path / "audit.log"
    bloqueo_path = tmp_path / "bloqueo.json"

    estado_path.write_text(json.dumps(_estado_dict()), encoding="utf-8")
    firewall_path.write_text(FIREWALL_TXT, encoding="utf-8")
    bloqueo_path.write_text(json.dumps(BLOQUEO_JSON), encoding="utf-8")

    ahora = int(time.time())
    lineas_leases = [
        f"{ahora + 3600} {MAC_RESERVA} 192.168.50.10 nas *",
        f"{ahora + 3600} {MAC_SIN_VECINO} 192.168.50.20 portatil *",
        f"{ahora - 3600} {MAC_CADUCADO} 192.168.50.30 viejo *",
    ]
    leases_path.write_text("\n".join(lineas_leases) + "\n", encoding="utf-8")

    oplog_path.write_text(
        json.dumps(
            {
                "fecha": datetime.now(timezone.utc).isoformat(),
                "usuario": "admin",
                "accion": "modo",
                "datos": {"modo": "balanceo"},
                "ok": True,
                "mensaje": "Modo cambiado a balanceo.",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("ROUTER_ESTADO", str(estado_path))
    monkeypatch.setenv("ROUTER_FIREWALL", str(firewall_path))
    monkeypatch.setenv("ROUTER_LEASES", str(leases_path))
    monkeypatch.setenv("ROUTER_OPLOG", str(oplog_path))
    monkeypatch.setenv("ROUTER_BUZON", str(buzon_dir))
    monkeypatch.setenv("ROUTER_RESPUESTAS", str(respuestas_dir))
    monkeypatch.setenv("ROUTER_BLOQUEO", str(bloqueo_path))
    monkeypatch.setenv("PANEL_USUARIOS", str(usuarios_path))
    monkeypatch.setenv("PANEL_SECRET_FILE", str(secret_path))
    monkeypatch.setenv("PANEL_AUDIT", str(audit_path))
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "False")

    usuarios_mod.crear_usuario("admin", "contrasena-admin-1", "admin")
    usuarios_mod.crear_usuario("lector", "contrasena-lector-1", "lectura")

    return {
        "estado_path": estado_path,
        "firewall_path": firewall_path,
        "leases_path": leases_path,
        "oplog_path": oplog_path,
        "buzon_dir": buzon_dir,
        "respuestas_dir": respuestas_dir,
        "usuarios_path": usuarios_path,
        "audit_path": audit_path,
        "bloqueo_path": bloqueo_path,
    }


@pytest.fixture
def app(entorno):
    aplicacion = create_app()
    aplicacion.config.update(TESTING=True)
    return aplicacion


@pytest.fixture
def cliente(app):
    return app.test_client()


def extraer_csrf(html: bytes) -> str:
    coincidencia = re.search(rb'name="csrf_token" value="([^"]+)"', html)
    assert coincidencia, "No se encontró csrf_token en la página"
    return coincidencia.group(1).decode()


def login(cliente, usuario: str, password: str):
    resp = cliente.get("/login")
    token = extraer_csrf(resp.data)
    return cliente.post("/login", data={"usuario": usuario, "password": password, "csrf_token": token})


@pytest.fixture
def simulador_routerd(entorno):
    """Simula routerd: observa el buzón y responde ok=True a cada petición."""
    detener = threading.Event()
    buzon_dir = str(entorno["buzon_dir"])
    respuestas_dir = str(entorno["respuestas_dir"])
    vistos: set[str] = set()

    def bucle():
        while not detener.is_set():
            try:
                nombres = os.listdir(buzon_dir)
            except FileNotFoundError:
                nombres = []
            for nombre in nombres:
                if not nombre.endswith(".json") or nombre in vistos:
                    continue
                vistos.add(nombre)
                try:
                    with open(os.path.join(buzon_dir, nombre), "r", encoding="utf-8") as f:
                        peticion = json.load(f)
                except (OSError, json.JSONDecodeError):
                    continue
                os.makedirs(respuestas_dir, exist_ok=True)
                respuesta = {
                    "id": peticion["id"],
                    "ok": True,
                    "mensaje": "Operación aplicada (simulada).",
                    "aplicado": datetime.now(timezone.utc).isoformat(),
                }
                tmp = os.path.join(respuestas_dir, f"{peticion['id']}.json.tmp")
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(respuesta, f)
                os.rename(tmp, os.path.join(respuestas_dir, f"{peticion['id']}.json"))
            time.sleep(0.05)

    hilo = threading.Thread(target=bucle, daemon=True)
    hilo.start()
    yield
    detener.set()
    hilo.join(timeout=2)
