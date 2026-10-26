from __future__ import annotations

import pytest

from routerpanel import validacion


def test_peso_cero_rechazado():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("wan_actualizar", {"wan": "X", "peso": 0})


def test_peso_101_rechazado():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("wan_actualizar", {"wan": "X", "peso": 101})


def test_peso_valido_aceptado():
    datos = validacion.validar_peticion("wan_actualizar", {"wan": "X", "peso": 50})
    assert datos["peso"] == 50


def test_mac_invalida_rechazada():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("reserva_eliminar", {"mac": "no-es-una-mac"})


def test_mac_valida_aceptada():
    datos = validacion.validar_peticion("reserva_eliminar", {"mac": "AA:BB:CC:DD:EE:FF"})
    assert datos["mac"] == "aa:bb:cc:dd:ee:ff"


def test_ip_fuera_de_lan_rechazada():
    contexto = {"lan_red": "192.168.50.1/24", "lan_ip_router": "192.168.50.1", "reservas": []}
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion(
            "reserva_agregar",
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5", "nombre": "fuera"},
            contexto,
        )


def test_ip_dentro_de_lan_aceptada():
    contexto = {"lan_red": "192.168.50.1/24", "lan_ip_router": "192.168.50.1", "reservas": []}
    datos = validacion.validar_peticion(
        "reserva_agregar",
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.50.77", "nombre": "nuevo"},
        contexto,
    )
    assert datos["ip"] == "192.168.50.77"


def test_dns_no_ipv4_rechazado():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("dns", {"servidores": ["no-es-una-ip"]})


def test_dns_ipv6_rechazado():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("dns", {"servidores": ["2001:db8::1"]})


def test_dns_valido_aceptado():
    datos = validacion.validar_peticion("dns", {"servidores": ["1.1.1.1", "9.9.9.9"]})
    assert datos["servidores"] == ["1.1.1.1", "9.9.9.9"]


def test_dns_mas_de_4_rechazado():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("dns", {"servidores": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]})


def test_accion_no_reconocida_rechazada():
    with pytest.raises(validacion.ErrorValidacion):
        validacion.validar_peticion("borrar_todo", {})
