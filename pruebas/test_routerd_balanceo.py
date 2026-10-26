#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root, sin nft/ip/ping de
verdad — todo mockeado) de dos correcciones de ronda 4 pedidas por el fallo
intermitente del paso 2 del e2e (netns_multiwan.sh, ~1/200 conexiones falladas
al arrancar, en ~1 de cada 3 pasadas):

- MUESTRAS_MINIMAS_BALANCEO: una WAN no entra en el balanceo hasta llevar un
  mínimo de ciclos SEGUIDOS con enlace válido comprobado (EstadoWan.
  muestras_validas) — evita que "parpadee" dentro y fuera del balanceo justo
  al arrancar/reconectar, mientras calienta.
- instalar_base() puebla wan_ifs/wan_gws en la MISMA transacción nft que crea
  la tabla — nunca queda una vuelta con esos sets recién creados y vacíos
  antes de que aplicar_balanceo() los repueble más adelante en el ciclo.

Uso:  python3 -m unittest pruebas/test_routerd_balanceo.py -v
"""
import copy
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import routerd  # noqa: E402


def _rutas_prueba(tmp):
    rutas = {k: os.path.join(tmp, k) for k in routerd.RUTAS}
    rutas['grupo_panel'] = 'routerpanel'
    return rutas


def _cfg_base():
    cfg = copy.deepcopy(routerd.CONFIG_DEFECTO)
    cfg['lan'] = {'interfaz': 'lan0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'}
    cfg['dhcp'] = {'inicio': '192.168.50.100', 'fin': '192.168.50.200', 'lease': '12h'}
    return cfg


def _router(tmp, cfg=None):
    r = routerd.Router(_rutas_prueba(tmp))
    r.cfg = cfg if cfg is not None else _cfg_base()
    r.fase = 'produccion'
    return r


class TestMuestrasMinimasBalanceo(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-muestras-')
        self.r = _router(self.tmp)
        self.c = {'n': 1, 'habilitada': True, 'peso': 50, 'nombre': 'WAN1'}
        self.r.cfg['wans'] = {'w1': self.c}
        self.w = {'id': 'w1', 'ip': '192.168.42.17', 'gw': '192.168.42.129',
                  'ifname': 'wan1', 'operstate': 'up'}
        self.r.presentes = {'w1': self.w}

    def _ciclo_ping_ok(self, w=None):
        with mock.patch('routerd.ping', return_value=(10.0, 0.0)), \
             mock.patch('routerd._leer', return_value=None):
            self.r._comprobar(w or self.w, self.c)

    def test_no_entra_en_balanceo_antes_de_las_muestras_minimas(self):
        for _ in range(routerd.MUESTRAS_MINIMAS_BALANCEO - 1):
            self._ciclo_ping_ok()
        e = self.r.estados['w1']
        self.assertTrue(e.internet)   # con exitos_alta=2 ya tiene Internet...
        self.assertLess(e.muestras_validas, routerd.MUESTRAS_MINIMAS_BALANCEO)
        self.assertEqual(self.r.wans_activas(), [])   # ...pero aún no entra en el balanceo

    def test_entra_en_balanceo_tras_las_muestras_minimas(self):
        for _ in range(routerd.MUESTRAS_MINIMAS_BALANCEO):
            self._ciclo_ping_ok()
        activas = self.r.wans_activas()
        self.assertEqual(len(activas), 1)
        self.assertEqual(activas[0][1]['id'], 'w1')

    def test_muestras_validas_solo_cuenta_con_enlace_valido(self):
        w_sin_gw = dict(self.w, gw=None)
        for _ in range(5):
            self._ciclo_ping_ok(w_sin_gw)
        self.assertEqual(self.r.estados['w1'].muestras_validas, 0)

    def test_muestras_validas_sigue_subiendo_aunque_el_ping_falle(self):
        # El contador es "lleva un rato siendo comprobada de verdad", no
        # "está sana" — eso ya lo gestiona e.internet/e.fallos aparte.
        with mock.patch('routerd.ping', return_value=(None, 100.0)), \
             mock.patch('routerd._leer', return_value=None):
            for _ in range(routerd.MUESTRAS_MINIMAS_BALANCEO):
                self.r._comprobar(self.w, self.c)
        e = self.r.estados['w1']
        self.assertFalse(e.internet)
        self.assertEqual(e.muestras_validas, routerd.MUESTRAS_MINIMAS_BALANCEO)


class TestInstalarBasePoblacionDeSetsSinVentana(unittest.TestCase):
    """Ronda 4: wan_ifs/wan_gws se pueblan en la MISMA transacción nft que
    (re)instala la tabla base — nunca queda una vuelta con esos sets vacíos
    antes de que aplicar_balanceo() los repueble de verdad."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-poblacion-')
        self.r = _router(self.tmp)
        self.r.presentes = {
            'w1': {'id': 'w1', 'ip': '192.168.42.17', 'gw': '192.168.42.129', 'ifname': 'wan1'},
            'w2': {'id': 'w2', 'ip': '192.168.43.20', 'gw': '192.168.43.1', 'ifname': 'wan2'},
        }

    def test_la_primera_instalacion_ya_incluye_los_sets_poblados(self):
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        llamadas_f = [c.args[0] for c in m_run.call_args_list if c.args and c.args[0][:2] == ['nft', '-f']]
        self.assertTrue(llamadas_f, 'debería haber aplicado el firewall base')
        with open(self.r.rutas['nft_base']) as f:
            contenido = f.read()
        self.assertIn('add element inet router wan_ifs { "wan1", "wan2" }', contenido)
        self.assertIn('add element inet router wan_gws { 192.168.42.129, 192.168.43.1 }', contenido)

    def test_sin_wan_presente_no_anade_elementos_pero_no_falla(self):
        self.r.presentes = {}
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        self.assertTrue(self.r.base_instalada)
        with open(self.r.rutas['nft_base']) as f:
            contenido = f.read()
        self.assertNotIn('add element', contenido)

    def test_la_poblacion_de_sets_no_perturba_la_comparacion_de_base_texto(self):
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        texto_tras_primera = self.r.base_texto
        self.assertNotIn('add element', texto_tras_primera,
                          'self.base_texto debe ser la política "pura", sin los sets poblados')
        # Cambia la topología (otra WAN presente) sin cambiar nada de la
        # política del firewall: NO debe forzar una reinstalación.
        self.r.presentes['w3'] = {'id': 'w3', 'ip': '10.0.0.5', 'gw': '10.0.0.1', 'ifname': 'wan3'}
        with mock.patch('routerd.run') as m_run2:
            m_run2.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        self.assertEqual(self.r.base_texto, texto_tras_primera)
        # Sólo la comprobación de la tabla (BAJA1) — nada de "nft -f" de más.
        llamadas = [c.args[0] for c in m_run2.call_args_list]
        self.assertFalse(any(c[:2] == ['nft', '-f'] for c in llamadas))


if __name__ == '__main__':
    unittest.main()
