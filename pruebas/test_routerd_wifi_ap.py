#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin root, sin red, sin systemctl de
verdad) de la parte del modo punto de acceso Wi-Fi (AP1) que vive en
core/routerd.py: la sección wifi_ap de CONFIG_DEFECTO, el conflicto de
interfaces con wifi_wan al normalizar la config cargada (en memoria, sin
reescribir router.json) y la sección 'wifi_ap' que se publica en estado.json
con su caché de 30 s. La misma prueba de conflicto de router_migrar vive en
pruebas/test_router_migrar.py.

Uso:  python3 -m unittest pruebas/test_routerd_wifi_ap.py -v
"""
import copy
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import routerd  # noqa: E402
import wifi_ap  # noqa: E402


def _escribir(ruta, objeto):
    with open(ruta, 'w') as f:
        json.dump(objeto, f)


class TestConflictoWifiApWifiWan(unittest.TestCase):
    """Una tarjeta no puede ser AP y WAN a la vez: al NORMALIZAR la config
    cargada, wifi_wan queda deshabilitada EN MEMORIA; router.json no se
    toca (la config en disco sigue como la dejó el admin)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-routerd-wifi-ap-')
        self.ruta = os.path.join(self.tmp, 'router.json')

    def test_misma_interfaz_deja_wan_deshabilitada_en_memoria(self):
        _escribir(self.ruta, {
            'wifi_wan': {'habilitada': True, 'interfaz': 'wlan0', 'ssid_bloqueadas': []},
            'wifi_ap': {'habilitado': True, 'interfaz': 'wlan0', 'pais': 'ES', 'canal': 6},
        })
        cfg, valida = routerd.cargar_config(self.ruta)
        self.assertTrue(valida)
        self.assertTrue(cfg['wifi_ap']['habilitado'])        # el AP se queda
        self.assertFalse(cfg['wifi_wan']['habilitada'])       # la WAN, no
        self.assertEqual(cfg['wifi_wan']['interfaz'], 'wlan0')  # lo demás intacto
        # router.json SIN TOCAR: en disco sigue habilitada
        with open(self.ruta) as f:
            en_disco = json.load(f)
        self.assertTrue(en_disco['wifi_wan']['habilitada'])

    def test_interfaz_distinta_no_afecta_a_la_wan(self):
        _escribir(self.ruta, {
            'wifi_wan': {'habilitada': True, 'interfaz': 'wlan1', 'ssid_bloqueadas': []},
            'wifi_ap': {'habilitado': True, 'interfaz': 'wlan0', 'pais': 'ES', 'canal': 6},
        })
        cfg, _ = routerd.cargar_config(self.ruta)
        self.assertTrue(cfg['wifi_wan']['habilitada'])
        self.assertTrue(cfg['wifi_ap']['habilitado'])

    def test_ap_deshabilitado_no_toca_la_wan(self):
        _escribir(self.ruta, {
            'wifi_wan': {'habilitada': True, 'interfaz': 'wlan0', 'ssid_bloqueadas': []},
            'wifi_ap': {'habilitado': False, 'interfaz': 'wlan0', 'pais': 'ES', 'canal': 6},
        })
        cfg, _ = routerd.cargar_config(self.ruta)
        self.assertTrue(cfg['wifi_wan']['habilitada'])

    def test_defecto_wifi_ap(self):
        self.assertEqual(routerd.CONFIG_DEFECTO['wifi_ap'],
                         {'habilitado': False, 'interfaz': '', 'pais': 'ES', 'canal': 6})
        self.assertIn('wifi_ap', routerd.TIPOS_CONFIG)
        # la config por defecto carga sin conflicto alguno
        cfg, _ = routerd.cargar_config(os.path.join(self.tmp, 'no-existe.json'))
        self.assertFalse(cfg['wifi_ap']['habilitado'])
        self.assertFalse(cfg['wifi_wan']['habilitada'])


class TestEstadoWifiAp(unittest.TestCase):
    """La sección 'wifi_ap' de estado.json: nada con el AP deshabilitado,
    lecturas caras CACHÉDAS ≥30 s y sin tirar publicar() si algo falla."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-routerd-wifi-ap-')
        rutas = {k: os.path.join(self.tmp, k) for k in routerd.RUTAS}
        rutas['grupo_panel'] = 'routerpanel'
        self.r = routerd.Router(rutas)

    def _cfg_ap(self, habilitado=True, interfaz='wlan0'):
        cfg = copy.deepcopy(routerd.CONFIG_DEFECTO)
        cfg['wifi_ap'] = {'habilitado': habilitado, 'interfaz': interfaz,
                          'pais': 'ES', 'canal': 6}
        self.r.cfg = cfg
        return cfg

    def test_deshabilitado_solo_habilitado_false_y_nada_se_ejecuta(self):
        self._cfg_ap(habilitado=False)
        with mock.patch.object(routerd, 'run') as run_m, \
                mock.patch.object(wifi_ap, 'leer_ssid') as ssid_m, \
                mock.patch.object(wifi_ap, 'clientes') as clientes_m:
            self.assertEqual(self.r._estado_wifi_ap(), {'habilitado': False})
        run_m.assert_not_called()
        ssid_m.assert_not_called()
        clientes_m.assert_not_called()

    def test_habilitado_sin_interfaz_cuenta_como_apagado(self):
        self._cfg_ap(habilitado=True, interfaz='')
        with mock.patch.object(routerd, 'run') as run_m:
            self.assertEqual(self.r._estado_wifi_ap(), {'habilitado': False})
        run_m.assert_not_called()

    def test_habilitado_publica_ssid_activo_y_clientes(self):
        self._cfg_ap()
        activo = mock.Mock(returncode=0, stdout='active\n', stderr='')
        with mock.patch.object(routerd, 'run', return_value=activo) as run_m, \
                mock.patch.object(wifi_ap, 'leer_ssid', return_value='Red de Casa'), \
                mock.patch.object(wifi_ap, 'clientes', return_value=['aa', 'bb', 'cc']) as clientes_m:
            estado = self.r._estado_wifi_ap()
        self.assertEqual(estado, {'habilitado': True, 'interfaz': 'wlan0',
                                  'ssid': 'Red de Casa', 'activo': True, 'clientes': 3})
        run_m.assert_called_once()          # sólo el systemctl is-active
        clientes_m.assert_called_once_with('wlan0')
        # el SSID sale de la config de hostapd, SIN la clave: wifi_ap.leer_ssid
        self.assertNotIn('clave', json.dumps(estado))

    def test_cachera_30_s(self):
        self._cfg_ap()
        activo = mock.Mock(returncode=0, stdout='active\n', stderr='')
        with mock.patch.object(routerd, 'run', return_value=activo) as run_m, \
                mock.patch.object(wifi_ap, 'leer_ssid', return_value='Red'), \
                mock.patch.object(wifi_ap, 'clientes', return_value=[]) as clientes_m:
            self.r._estado_wifi_ap()
            self.r._estado_wifi_ap()          # segunda seguida: caché
        self.assertEqual(run_m.call_count, 1)
        self.assertEqual(clientes_m.call_count, 1)
        # cambia la interfaz: NO se sirve la caché del otro AP
        cfg_nueva = copy.deepcopy(self.r.cfg)
        cfg_nueva['wifi_ap']['interfaz'] = 'wlan1'
        self.r.cfg = cfg_nueva
        with mock.patch.object(routerd, 'run', return_value=activo) as run_m, \
                mock.patch.object(wifi_ap, 'leer_ssid', return_value='Red'), \
                mock.patch.object(wifi_ap, 'clientes', return_value=[]) as clientes_m:
            self.r._estado_wifi_ap()
        self.assertEqual(clientes_m.call_count, 1)   # 1 de esta pasada (+1 de antes en otro mock)
        self.assertEqual(run_m.call_count, 1)
        # pasados 30 s, vuelve a leer
        cache = self.r._wifi_ap_cache
        self.r._wifi_ap_cache = dict(cache, ts=cache['ts'] - 31.0)
        self.r.cfg = copy.deepcopy(cfg_nueva)
        with mock.patch.object(routerd, 'run', return_value=activo) as run_m2, \
                mock.patch.object(wifi_ap, 'leer_ssid', return_value='Red'), \
                mock.patch.object(wifi_ap, 'clientes', return_value=[]):
            self.r._estado_wifi_ap()
        self.assertEqual(run_m2.call_count, 1)

    def test_fallos_no_tiran_publicar(self):
        self._cfg_ap()
        with mock.patch.object(wifi_ap, 'leer_ssid', side_effect=OSError('boom')), \
                mock.patch.object(wifi_ap, 'clientes', side_effect=OSError('boom')), \
                mock.patch.object(routerd, 'run',
                                  side_effect=RuntimeError('systemctl se cuelga')):
            estado = self.r._estado_wifi_ap()
        self.assertEqual(estado['habilitado'], True)
        self.assertEqual(estado['ssid'], '')
        self.assertEqual(estado['activo'], False)
        self.assertIsNone(estado['clientes'])

    def test_wlan_absente_da_clientes_0_mientras_tanto(self):
        # wifi_ap.clientes ya devuelve [] ante cualquier error: el número en
        # el estado es 0, no una excepción del ciclo.
        self._cfg_ap()
        activo = mock.Mock(returncode=1, stdout='inactive\n', stderr='')
        with mock.patch.object(routerd, 'run', return_value=activo), \
                mock.patch.object(wifi_ap, 'leer_ssid', return_value=''), \
                mock.patch.object(wifi_ap, 'clientes', return_value=[]):
            estado = self.r._estado_wifi_ap()
        self.assertEqual(estado['activo'], False)
        self.assertEqual(estado['clientes'], 0)


if __name__ == '__main__':
    unittest.main()
