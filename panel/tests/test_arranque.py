from __future__ import annotations

import logging
import os

import pytest

from routerpanel import create_app


def test_secret_key_ilegible_da_error_claro_en_el_log(tmp_path, monkeypatch, caplog):
    """Si `secret_key` existe pero no se puede leer (típicamente porque lo
    creó un proceso con otro usuario), el arranque debe fallar con un
    mensaje de log explícito en vez de un error genérico difícil de
    diagnosticar."""
    secret_path = tmp_path / "secret_key"
    secret_path.write_bytes(b"0" * 32)
    os.chmod(secret_path, 0o000)

    monkeypatch.setenv("PANEL_SECRET_FILE", str(secret_path))
    # Resto de rutas a ficheros vacíos/temporales, igual que en `conftest`.
    monkeypatch.setenv("PANEL_USUARIOS", str(tmp_path / "usuarios.json"))
    monkeypatch.setenv("ROUTER_ESTADO", str(tmp_path / "estado.json"))
    monkeypatch.setenv("ROUTER_FIREWALL", str(tmp_path / "firewall.txt"))
    monkeypatch.setenv("ROUTER_LEASES", str(tmp_path / "dnsmasq.leases"))
    monkeypatch.setenv("ROUTER_OPLOG", str(tmp_path / "operaciones.log"))
    monkeypatch.setenv("ROUTER_BUZON", str(tmp_path / "solicitudes"))
    monkeypatch.setenv("ROUTER_RESPUESTAS", str(tmp_path / "respuestas"))
    monkeypatch.setenv("PANEL_AUDIT", str(tmp_path / "audit.log"))

    try:
        with caplog.at_level(logging.ERROR, logger="routerpanel"):
            with pytest.raises(PermissionError):
                create_app()
    finally:
        os.chmod(secret_path, 0o600)  # para que tmp_path se pueda limpiar

    mensajes = " ".join(registro.message for registro in caplog.records)
    assert "permiso denegado" in mensajes.lower()
    assert "sudo -u routerpanel" in mensajes
