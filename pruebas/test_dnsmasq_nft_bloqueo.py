#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root) de la parte del
bloqueador DNS que vive en dnsmasq_conf.py y nft_conf.py: cuándo se
referencia dnsmasq-bloqueo.conf, el log de consultas, y las reglas nft de
forzar_dns/bloquear_doh.

Uso:  python3 -m unittest pruebas/test_dnsmasq_nft_bloqueo.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import dnsmasq_conf  # noqa: E402
import nft_conf       # noqa: E402


def _cfg(bloqueo=None):
    return {
        'lan': {'interfaz': 'lan0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'},
        'dhcp': {'inicio': '192.168.50.100', 'fin': '192.168.50.200', 'lease': '12h'},
        'dns': ['1.1.1.1', '9.9.9.9'],
        'dominio': 'home.arpa',
        'reservas': [],
        'bloqueo': bloqueo if bloqueo is not None else {},
    }


class TestDnsmasqConfBloqueo(unittest.TestCase):
    """M2: el servers-file del bloqueador se referencia SIEMPRE,
    incondicionalmente (ya no hay un 'existe_bloqueo' que lo decida — ver
    docstring de dnsmasq_conf.generar): routerd es quien garantiza que el
    fichero existe (vacío si hace falta) antes de llamar a generar()."""

    def test_local_home_arpa_siempre_presente(self):
        # BAJA3 (ronda 3): incondicional, independiente del dominio de la
        # casa configurado y de si el bloqueador está habilitado.
        conf, _ = dnsmasq_conf.generar(_cfg({'habilitado': False}))
        self.assertIn('local=/home.arpa/', conf)

    def test_local_home_arpa_presente_con_dominio_de_casa_distinto(self):
        cfg = _cfg()
        cfg['dominio'] = 'lan.home.arpa'
        conf, _ = dnsmasq_conf.generar(cfg)
        self.assertIn('local=/home.arpa/', conf)
        self.assertIn('local=/lan.home.arpa/', conf)

    def test_servers_file_siempre_presente(self):
        conf, _ = dnsmasq_conf.generar(_cfg({'habilitado': True}))
        self.assertIn('servers-file=/var/lib/router/bloqueo/dnsmasq-bloqueo.conf', conf)

    def test_servers_file_presente_aunque_deshabilitado(self):
        # Deshabilitado = el FICHERO queda vacío (lo genera router_bloqueo),
        # no que routerd deje de referenciarlo: sigue haciendo falta la
        # línea, o dnsmasq --test fallaría si alguna vez se reactiva sin
        # que el fichero exista todavía.
        conf, _ = dnsmasq_conf.generar(_cfg({'habilitado': False}))
        self.assertIn('servers-file=', conf)

    def test_nunca_usa_conf_file_para_el_bloqueo(self):
        conf, _ = dnsmasq_conf.generar(_cfg({'habilitado': True}))
        self.assertNotIn('conf-file=/var/lib/router/bloqueo', conf)

    def test_log_queries_extra_si_se_admite(self):
        conf, _ = dnsmasq_conf.generar(_cfg(), log_queries_extra=True)
        self.assertIn('log-queries=extra', conf)

    def test_log_queries_simple_si_no_se_admite(self):
        conf, _ = dnsmasq_conf.generar(_cfg(), log_queries_extra=False)
        self.assertIn('log-queries\n', conf)
        self.assertNotIn('log-queries=extra', conf)

    def test_log_facility_siempre_presente(self):
        conf, _ = dnsmasq_conf.generar(_cfg())
        self.assertIn('log-facility=/var/log/router/dns.log', conf)

    def test_log_async_presente(self):
        conf, _ = dnsmasq_conf.generar(_cfg())
        self.assertIn('log-async=25', conf)

    def test_desactivar_log_quita_log_queries_y_facility(self):
        # M6 (fail-open): routerd puede pedir una config sin log cuando
        # dnsmasq lleva varios arranques fallidos seguidos.
        conf, _ = dnsmasq_conf.generar(_cfg(), desactivar_log=True)
        self.assertNotIn('log-queries', conf)
        self.assertNotIn('log-facility', conf)
        self.assertNotIn('log-async', conf)
        # El resto de la config (DHCP, servers-file) sigue intacto.
        self.assertIn('servers-file=', conf)
        self.assertIn('dhcp-range=', conf)


class TestNftConfBloqueo(unittest.TestCase):
    def test_forzar_dns_crea_cadena_redirigir(self):
        texto = nft_conf.generar(_cfg({'forzar_dns': True, 'bloquear_doh': False}))
        self.assertIn('chain redirigir_dns', texto)
        self.assertIn('redirect to :53', texto)

    def test_sin_forzar_dns_no_hay_cadena_redirigir(self):
        texto = nft_conf.generar(_cfg({'forzar_dns': False, 'bloquear_doh': False}))
        self.assertNotIn('chain redirigir_dns', texto)

    def test_bloquear_doh_corta_853(self):
        texto = nft_conf.generar(_cfg({'forzar_dns': False, 'bloquear_doh': True}))
        self.assertIn('tcp dport 853 reject', texto)
        self.assertIn('udp dport 853 reject', texto)

    def test_sin_bloquear_doh_no_corta_853(self):
        texto = nft_conf.generar(_cfg({'forzar_dns': False, 'bloquear_doh': False}))
        self.assertNotIn('dport 853', texto)

    def test_defecto_sin_seccion_bloqueo_activa_ambas(self):
        # Los defectos de nft_conf.generar() para 'forzar_dns'/'bloquear_doh'
        # (True si no hay sección 'bloqueo' en absoluto) deben coincidir con
        # CONFIG_DEFECTO de routerd — nunca "silenciosamente desactivado".
        texto = nft_conf.generar(_cfg(bloqueo={}))
        self.assertIn('chain redirigir_dns', texto)
        self.assertIn('dport 853', texto)

    def test_redirigir_dns_restringido_a_ipv4(self):
        # BAJA10: la tabla es "inet" (dual-stack) pero los literales de la
        # cadena son IPv4 — debe acotarse explícitamente.
        texto = nft_conf.generar(_cfg({'forzar_dns': True, 'bloquear_doh': False}))
        inicio = texto.index('chain redirigir_dns')
        bloque = texto[inicio:texto.index('}', inicio)]
        self.assertIn('meta nfproto ipv4', bloque)

    def test_redirect_excluye_al_propio_router(self):
        texto = nft_conf.generar(_cfg({'forzar_dns': True, 'bloquear_doh': False}))
        # La línea "ip daddr <ip-del-router> return" debe venir ANTES de
        # los "redirect" dentro de la cadena redirigir_dns.
        inicio = texto.index('chain redirigir_dns')
        bloque = texto[inicio:texto.index('}', inicio)]
        self.assertIn('ip daddr 192.168.50.1 return', bloque)
        self.assertLess(bloque.index('192.168.50.1 return'), bloque.index('redirect to :53'))


if __name__ == '__main__':
    unittest.main()
