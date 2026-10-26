#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin root, sin red, con mocks de run) de
la configuración de core/router_migrar.py: lectura de lan.* y activacion.*
de router.json, IP con/sin prefijo y los pasos Wi-Fi opcionales (con
activacion.perfil_wifi o activacion.wifi_interfaz vacíos NO se llama a
nmcli para nada Wi-Fi).

Uso:  python3 -m unittest pruebas/test_router_migrar.py -v
  o:  python3 -m unittest discover -s pruebas -p 'test_*.py'
"""
import builtins
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import router_migrar  # noqa: E402
import wifi_ap         # noqa: E402  (router_migrar lo usa en el modo AP)


def _run_ok(args, **kw):
    """run() falso: todo "funciona" (código 0), nada se ejecuta de verdad."""
    return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


def _escribir(ruta, objeto):
    with open(ruta, 'w') as f:
        json.dump(objeto, f)


class TestCargarConfiguracion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-migrar-')
        self.ruta = os.path.join(self.tmp, 'router.json')

    def test_sin_seccion_activacion_valores_por_defecto(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'dominio': 'lan.home.arpa',
        })
        conf = router_migrar.cargar_configuracion(self.ruta)
        self.assertEqual(conf, {
            'lan_if': 'lan0', 'lan_ip': '192.168.50.1', 'prefijo': 24,
            'perfil': 'LAN-ROUTER', 'perfil_wifi': '', 'wifi_if': '',
            'wifi_activa': False,
            'if_enlace': 'lan0', 'puerto_cable': '', 'ap_if': '', 'ap_activo': False,
        })
        self.assertFalse(router_migrar.WIFI_ACTIVA)
        # sin wifiap en router.json, nada de AP ni especiales
        self.assertFalse(router_migrar.AP_ACTIVO)
        self.assertEqual(router_migrar.AP_IF, '')
        self.assertEqual(router_migrar.PUERTO_CABLE, '')

    def test_ip_con_prefijo_se_quita_el_prefijo(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1/24', 'red': '192.168.50.0/24'},
            'activacion': {'perfil_lan': 'MI-LAN', 'perfil_wifi': 'WAN-WIFI',
                           'wifi_interfaz': 'wifisim0'},
        })
        router_migrar.cargar_configuracion(self.ruta)
        self.assertEqual(router_migrar.LAN_IP, '192.168.50.1')
        self.assertEqual(router_migrar.LAN_IF, 'lan0')
        self.assertEqual(router_migrar.PERFIL, 'MI-LAN')
        self.assertEqual(router_migrar.PERFIL_WIFI, 'WAN-WIFI')
        self.assertEqual(router_migrar.WIFI_IF, 'wifisim0')
        self.assertTrue(router_migrar.WIFI_ACTIVA)

    def test_prefijo_viene_de_lan_red(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '10.0.0.1', 'red': '10.0.0.0/8'}},
        )
        conf = router_migrar.cargar_configuracion(self.ruta)
        self.assertEqual(conf['prefijo'], 8)

    def test_red_mala_cae_al_prefijo_anterior(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': 'no-es-una-red'}},
        )
        conf = router_migrar.cargar_configuracion(self.ruta)
        self.assertEqual(conf['prefijo'], router_migrar.LAN_PREFIJO or 24)

    def test_activacion_con_perfil_wifi_pero_sin_interfaz_no_es_activa(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'activacion': {'perfil_lan': 'LAN-X', 'perfil_wifi': 'WAN-WIFI'},
        })
        conf = router_migrar.cargar_configuracion(self.ruta)
        self.assertFalse(conf['wifi_activa'])

    def test_activacion_con_interfaz_pero_sin_perfil_no_es_activa(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'activacion': {'wifi_interfaz': 'wifisim0'},
        })
        conf = router_migrar.cargar_configuracion(self.ruta)
        self.assertFalse(conf['wifi_activa'])
        self.assertEqual(conf['perfil'], 'LAN-ROUTER')   # defecto del campo presentes

    def test_router_json_ilegible_usa_los_defectos(self):
        with open(self.ruta, 'w') as f:
            f.write('esto no es json')
        conf = router_migrar.cargar_configuracion(self.ruta)
        self.assertEqual(conf['lan_if'], router_migrar.DEFECTO_LAN['interfaz'])
        self.assertEqual(conf['lan_ip'], router_migrar.DEFECTO_LAN['ip'])
        self.assertEqual(conf['perfil'], 'LAN-ROUTER')
        self.assertFalse(conf['wifi_activa'])

    def test_router_json_ausente_usa_los_defectos(self):
        conf = router_migrar.cargar_configuracion(os.path.join(self.tmp, 'no-existe.json'))
        self.assertEqual(conf['lan_if'], router_migrar.DEFECTO_LAN['interfaz'])
        self.assertEqual(conf['lan_ip'], router_migrar.DEFECTO_LAN['ip'])

    def _habla_por(self, perfil, gestor):
        # haga que run() diga que el perfil existe, sin gateway, con la IP
        # correcta (nmcli -g pero aquí basta el returncode == 0).
        gestor.return_value = subprocess.CompletedProcess(['nmcli'], 0,
                                                          stdout='%s/24' % router_migrar.LAN_IP,
                                                          stderr='')

    def test_comprobaciones_previas_usa_la_config_cargada(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan50', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'activacion': {'perfil_lan': 'MI-LAN', 'perfil_wifi': '', 'wifi_interfaz': ''},
        })
        with mock.patch('router_migrar.CONFIG', self.ruta), \
                mock.patch('router_migrar.run', side_effect=_run_ok) as run_m:
            router_migrar.comprobaciones_previas()
            perfiles_pedido = any('MI-LAN' in ' '.join(map(str, c[0][0]))
                                  for c in run_m.call_args_list)
        self.assertTrue(perfiles_pedido, 'la comprobación no preguntó por el perfil de router.json')


class TestWifiOpcional(unittest.TestCase):
    """Con activacion.perfil_wifi o wifi_interfaz vacíos, NINGÚN paso Wi-Fi
    llama a nmcli (ni ping): no apaga/apaga la radio, no reconecta, no
    consulta por Wi-Fi."""

    def _cfg(self, ruta, wifi):
        datos = {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'activacion': {'perfil_lan': 'LAN-ROUTER',
                           'perfil_wifi': 'WAN-WIFI' if wifi else '',
                           'wifi_interfaz': 'wifisim0' if wifi else ''},
        }
        _escribir(ruta, datos)

    def _cargar(self, wifi):
        self.ruta = os.path.join(self.tmp, 'router.json')
        self._cfg(self.ruta, self.wifi if hasattr(self, 'wifi') else wifi)
        router_migrar.cargar_configuracion(self.ruta)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-migrar-wifi-')

    def test_sin_wifi_desconectar_y_reconectar_no_llaman_a_nada(self):
        self._cargar(wifi=False)
        self.assertFalse(router_migrar.WIFI_ACTIVA)
        with mock.patch('router_migrar.run') as run_m:
            router_migrar.desconectar_wifi()
            router_migrar.reconectar_wifi()
            self.assertFalse(router_migrar.router_viejo_por_wifi())
        run_m.assert_not_called()

    def test_con_wifi_se_comporta_como_siempre(self):
        self._cargar(wifi=True)
        self.assertTrue(router_migrar.WIFI_ACTIVA)
        with mock.patch('router_migrar.run', side_effect=_run_ok) as run_m, \
                mock.patch.object(router_migrar, 'log') as log_m:
            router_migrar.desconectar_wifi()
        args = [c[0][0] for c in run_m.call_args_list]
        self.assertEqual([
            ['nmcli', 'con', 'down', router_migrar.PERFIL_WIFI],
            ['nmcli', 'con', 'mod', router_migrar.PERFIL_WIFI, 'connection.autoconnect', 'no'],
            ['nmcli', 'radio', 'wifi', 'off'],
        ], args)

    def test_con_wifi_reconectar_hace_radio_on_autoconnect_y_con_up(self):
        self._cargar(wifi=True)
        with mock.patch('router_migrar.run', side_effect=_run_ok) as run_m:
            router_migrar.reconectar_wifi()
        args = [c[0][0] for c in run_m.call_args_list]
        self.assertEqual([
            ['nmcli', 'radio', 'wifi', 'on'],
            ['nmcli', 'con', 'mod', router_migrar.PERFIL_WIFI, 'connection.autoconnect', 'yes'],
            ['nmcli', 'con', 'up', router_migrar.PERFIL_WIFI],
        ], args)

    def test_deshacer_sin_wifi_no_toca_nada_de_wifi(self):
        self._cargar(wifi=False)
        router_migrar.FASE_RUTA = os.path.join(self.tmp, 'fase')
        router_migrar.MARCADOR = os.path.join(self.tmp, 'marcador')
        with mock.patch('router_migrar._esperar_o_forzar_retirada'), \
                mock.patch('router_migrar.run') as run_m, \
                mock.patch.object(router_migrar, 'log') as log_m, \
                mock.patch.object(router_migrar, 'cancelar_deshacer_programado'):
            router_migrar.deshacer('prueba')
        args = [c[0][0] for c in run_m.call_args_list]
        wifi_sensibles = [a for a in args
                          if 'wifi' in ' '.join(a).lower()
                          or (router_migrar.PERFIL_WIFI and router_migrar.PERFIL_WIFI in ' '.join(a))]
        self.assertEqual(wifi_sensibles, [])
        # el perfil de la LAN SÍ se baja y se le quita la autoconexión
        self.assertIn(['nmcli', 'con', 'down', router_migrar.PERFIL], args)
        self.assertIn(['nmcli', 'con', 'mod', router_migrar.PERFIL,
                       'connection.autoconnect', 'no'], args)
        log_m.assert_called_with('Activación deshecha (prueba). La máquina vuelve a preparación.',
                                 fase='deshecha')

    def test_nada_de_wifi_ni_en_variables_cuando_esta_vacio(self):
        # coherencia de nombres: el nombre del perfil de LAN se usa en los
        # pasos de nmcli; el de Wi-Fi no aparece si está vacío.
        self._cfg(os.path.join(self.tmp, 'router2.json'), False)
        router_migrar.cargar_configuracion(os.path.join(self.tmp, 'router2.json'))
        self.assertEqual(router_migrar.PERFIL_WIFI, '')
        self.assertEqual(router_migrar.WIFI_IF, '')


if __name__ == '__main__':
    unittest.main()


class TestConfigLanObligatoria(unittest.TestCase):
    """Sin router.json legible (o sin lan.interfaz / lan.ip) la activación
    no puede seguir con los valores por defecto: CONFIG_LAN_OK queda False."""

    def _cargar(self, contenido):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            f.write(contenido)
        self.addCleanup(os.unlink, f.name)
        router_migrar.cargar_configuracion(f.name)
        return router_migrar.CONFIG_LAN_OK

    def test_json_roto(self):
        self.assertFalse(self._cargar('{roto'))

    def test_sin_lan(self):
        self.assertFalse(self._cargar('{"dominio": "lan"}'))

    def test_sin_ip(self):
        self.assertFalse(self._cargar('{"lan": {"interfaz": "eth1"}}'))

    def test_completa(self):
        self.assertTrue(self._cargar('{"lan": {"interfaz": "eth1", "ip": "10.0.0.1", "red": "10.0.0.0/24"}}'))


class TestPrincipalNoActivaSinConfig(unittest.TestCase):
    """Revisión del equipo (H1): con router.json roto, principal() se para en
    las comprobaciones previas y no llega a esperar ni a activar nada."""

    def test_principal_aborta_con_config_rota(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            f.write('{roto')
        self.addCleanup(os.unlink, f.name)
        ok = subprocess.CompletedProcess([], 0, '', '')
        with mock.patch.object(router_migrar, 'CONFIG', f.name), \
             mock.patch.object(router_migrar, 'run', return_value=ok), \
             mock.patch.object(router_migrar, 'log') as log, \
             mock.patch.object(router_migrar, 'enlace') as enlace, \
             mock.patch.object(router_migrar, 'activar', create=True) as activar:
            self.assertEqual(router_migrar.principal(), 1)
        enlace.assert_not_called()
        activar.assert_not_called()
        self.assertIn('cancelada', str(log.call_args))


class TestModoAp(unittest.TestCase):
    """AP1: modo punto de acceso Wi-Fi. Carga de la config (PUERTO_CABLE,
    AP_ACTIVO, IF_ENLACE), el enlace y el arping van por el puerto de cable
    (no por el puente), el modo sólo-AP no bloquea la activación, y los
    pasos del AP están en su sitio: encender tras el con up, apagar antes
    del con down al deshacer, y configuración permanente al confirmar."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-migrar-ap-')
        self.ruta = os.path.join(self.tmp, 'router.json')

    def _cfg(self, ap=False, wifi=False, puerto_cable='', lan_if='br-lan', misma_if=False):
        datos = {
            'lan': {'interfaz': lan_if, 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'activacion': {'perfil_lan': 'LAN-ROUTER', 'perfil_wifi': 'WAN-WIFI' if wifi else '',
                           'wifi_interfaz': 'wlan0' if (wifi and misma_if) else ('wifisim0' if wifi else ''),
                           'puerto_cable': puerto_cable},
        }
        if ap:
            datos['wifi_ap'] = {'habilitado': True, 'interfaz': 'wlan0',
                                'pais': 'ES', 'canal': 6}
        _escribir(self.ruta, datos)
        return router_migrar.cargar_configuracion(self.ruta)

    # — carga —

    def test_carga_ap_activo(self):
        conf = self._cfg(ap=True)
        self.assertTrue(conf['ap_activo'])
        self.assertEqual(router_migrar.AP_IF, 'wlan0')
        self.assertTrue(router_migrar.AP_ACTIVO)
        # sin puerto de cable, IF_ENLACE es el puente (la LAN)
        self.assertEqual(conf['if_enlace'], 'br-lan')
        self.assertEqual(router_migrar.IF_ENLACE, 'br-lan')

    def test_carga_puerto_cable(self):
        conf = self._cfg(ap=True, puerto_cable='eth_cable')
        self.assertEqual(conf['puerto_cable'], 'eth_cable')
        self.assertEqual(router_migrar.PUERTO_CABLE, 'eth_cable')
        # con puerto de cable, por ahí se mira el enlace y el arping
        self.assertEqual(conf['if_enlace'], 'eth_cable')
        self.assertEqual(router_migrar.IF_ENLACE, 'eth_cable')

    def test_ap_habilitado_sin_interfaz_o_al_reves_no_es_activo(self):
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'wifi_ap': {'habilitado': True, 'interfaz': ''},
        })
        router_migrar.cargar_configuracion(self.ruta)
        self.assertFalse(router_migrar.AP_ACTIVO)
        _escribir(self.ruta, {
            'lan': {'interfaz': 'lan0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'},
            'wifi_ap': {'habilitado': False, 'interfaz': 'wlan0'},
        })
        router_migrar.cargar_configuracion(self.ruta)
        self.assertFalse(router_migrar.AP_ACTIVO)

    def test_misma_tarjeta_para_ap_y_wan_deja_wan_fuera(self):
        """Una tarjeta no puede ser AP y WAN a la vez (misma regla que
        routerd): si wifi_ap y wifi_wan apuntan a la misma interfaz, la
        activación no debe apagar/reencender la radio (desconectar_wifi la
        tiraria el AP entero)."""
        conf = self._cfg(ap=True, wifi=True, misma_if=True)
        self.assertTrue(conf['ap_activo'])
        self.assertFalse(conf['wifi_activa'])
        self.assertFalse(router_migrar.WIFI_ACTIVA)
        self.assertEqual(router_migrar.PERFIL_WIFI, '')

    # — enlace y arping —

    def test_enlace_va_por_el_puerto_de_cable(self):
        self._cfg(ap=True, puerto_cable='eth_cable')
        carrier_puerto = os.path.join(self.tmp, 'carrier-puerto')
        carrier_puente = os.path.join(self.tmp, 'carrier-puente')
        real_open = builtins.open

        def poner_carrier(ruta, valor):
            with real_open(ruta, 'w') as f:
                f.write(valor)

        def abrir(ruta_falsa, *args, **kwargs):
            # el sysfs de las pruebas: el puerto de cable y el puente leen
            # un fichero propio; cualquier otra /sys/class/net/... falla
            if ruta_falsa == '/sys/class/net/eth_cable/carrier':
                return real_open(carrier_puerto, *args, **kwargs)
            if ruta_falsa == '/sys/class/net/br-lan/carrier':
                return real_open(carrier_puente, *args, **kwargs)
            if ruta_falsa.startswith('/sys/class/net/'):
                raise FileNotFoundError(2, 'mock sysfs sin esta ruta', ruta_falsa)
            return real_open(ruta_falsa, *args, **kwargs)

        poner_carrier(carrier_puerto, '0')
        poner_carrier(carrier_puente, '1')   # si el enlace se leyera del puente, engañaría
        with mock.patch.object(builtins, 'open', abrir):
            # puerto sin carrier → NO hay enlace, aunque el puente diga 1
            self.assertFalse(router_migrar.enlace())
            poner_carrier(carrier_puerto, '1')
            self.assertTrue(router_migrar.enlace())

    def test_enlace_sin_ap_es_la_lan_de_toda_la_vida(self):
        self._cfg(ap=False, lan_if='lan0')
        self.assertEqual(router_migrar.IF_ENLACE, 'lan0')
        with open(os.path.join(self.tmp, 'carrier'), 'w') as f:
            f.write('1')
        real_open = builtins.open
        def abrir(ruta_falsa, *args, **kwargs):
            if ruta_falsa == '/sys/class/net/lan0/carrier':
                return real_open(os.path.join(self.tmp, 'carrier'), *args, **kwargs)
            return real_open(ruta_falsa, *args, **kwargs)
        with mock.patch.object(builtins, 'open', abrir):
            self.assertTrue(router_migrar.enlace())

    def test_solo_ap_enlace_true_y_sin_arping(self):
        """Puente SIN puerto de cable: no hay cable por donde otro router
        pueda contestar el ARP — enlace() responde True sin mirar sysfs y
        otro_tiene_la_ip() responde False sin ejecutar arping."""
        self._cfg(ap=True, puerto_cable='')  # puente sin puerto
        real_open = builtins.open
        def abrir(ruta_falsa, *args, **kwargs):
            self.assertNotIn('/sys/class/net/', ruta_falsa,
                             'en modo sólo-AP no hay que abrir sysfs: %r' % ruta_falsa)
            return real_open(ruta_falsa, *args, **kwargs)
        with mock.patch.object(builtins, 'open', abrir):
            self.assertTrue(router_migrar.enlace())
        # suficiente: si aquí se ejecutara arping por un puente sin puertos,
        # su «no se sabe» se trataría como IP ocupada y nunca se activaría
        with mock.patch.object(builtins, 'open', abrir), \
                mock.patch.object(router_migrar, 'run') as run_m:
            self.assertFalse(router_migrar.otro_tiene_la_ip())
        run_m.assert_not_called()

    # — los pasos del AP en la activación —

    def test_encender_ap_enciende_lo_que_toca_y_sin_ap_nada(self):
        self._cfg(ap=True)
        with mock.patch.object(router_migrar, 'run', side_effect=_run_ok) as run_m:
            router_migrar.encender_ap()
            args = [c[0][0] for c in run_m.call_args_list]
            self.assertIn(['nmcli', 'device', 'set', 'wlan0', 'managed', 'no'], args)
            self.assertIn(['systemctl', 'start', 'router-ap.service'], args)
        self._cfg(ap=False, lan_if='lan0')
        with mock.patch.object(router_migrar, 'run') as run_m:
            router_migrar.encender_ap()
        run_m.assert_not_called()

    def test_apagar_ap_y_sin_ap_nada(self):
        self._cfg(ap=True)
        fichero_conf = os.path.join(self.tmp, '91-router-ap.conf')
        with open(fichero_conf, 'w') as f:
            f.write('[keyfile]\n')
        with mock.patch.object(router_migrar, 'CONF_NM_AP', fichero_conf), \
                mock.patch.object(router_migrar, 'run', side_effect=_run_ok) as run_m:
            router_migrar.apagar_ap()
            args = [c[0][0] for c in run_m.call_args_list]
            self.assertIn(['systemctl', 'disable', '--now', 'router-ap.service'], args)
            self.assertIn(['nmcli', 'general', 'reload', 'conf'], args)
            self.assertIn(['nmcli', 'device', 'set', 'wlan0', 'managed', 'yes'], args)
            self.assertFalse(os.path.exists(fichero_conf))
        self._cfg(ap=False, lan_if='lan0')
        with mock.patch.object(router_migrar, 'run') as run_m:
            router_migrar.apagar_ap()
        run_m.assert_not_called()

    def test_deshacer_apaga_el_ap_antes_de_bajar_la_lan(self):
        self._cfg(ap=True)
        router_migrar.FASE_RUTA = os.path.join(self.tmp, 'fase')
        router_migrar.MARCADOR = os.path.join(self.tmp, 'marcador')
        orden = []
        def run_enviando(args, **kw):
            orden.append(args)
            return _run_ok(args, **kw)
        with mock.patch.object(router_migrar, 'run', side_effect=run_enviando), \
                mock.patch.object(router_migrar, '_esperar_o_forzar_retirada'), \
                mock.patch.object(router_migrar, 'log'), \
                mock.patch.object(router_migrar, 'cancelar_deshacer_programado'), \
                mock.patch.object(router_migrar, 'apagar_ap',
                                  side_effect=lambda *a, **k: orden.append('apagar_ap')):
            router_migrar.deshacer('prueba ap')
        con_down = ['nmcli', 'con', 'down', router_migrar.PERFIL]
        self.assertIn('apagar_ap', orden)
        self.assertIn(con_down, orden)
        self.assertLess(orden.index('apagar_ap'), orden.index(con_down))

    def test_confirmar_deja_conf_y_unidad_habilitada(self):
        self._cfg(ap=True)
        marcador = os.path.join(self.tmp, 'marcador')
        with open(marcador, 'w') as f:
            f.write('limite=now\n')
        conf_ap = os.path.join(self.tmp, '91-router-ap.conf')
        self.assertFalse(os.path.exists(conf_ap))
        with mock.patch.object(router_migrar, 'MARCADOR', marcador), \
                mock.patch.object(router_migrar, 'CONFIRMADA', os.path.join(self.tmp, 'confirmada')), \
                mock.patch.object(router_migrar, 'CONF_NM_AP', conf_ap), \
                mock.patch.object(router_migrar, 'run', side_effect=_run_ok) as run_m, \
                mock.patch('sys.stdout', new=io.StringIO()):
            router_migrar.confirmar()
        with open(conf_ap) as f:
            self.assertEqual(f.read(), '[keyfile]\nunmanaged-devices=interface-name:wlan0\n')
        args = [c[0][0] for c in run_m.call_args_list]
        self.assertIn(['systemctl', 'enable', 'router-ap.service'], args)

    def test_confirmar_sin_ap_no_toca_nada(self):
        self._cfg(ap=False, lan_if='lan0')
        marcador = os.path.join(self.tmp, 'marcador')
        with open(marcador, 'w') as f:
            f.write('limite=now\n')
        with mock.patch.object(router_migrar, 'MARCADOR', marcador), \
                mock.patch.object(router_migrar, 'CONFIRMADA', os.path.join(self.tmp, 'confirmada')), \
                mock.patch.object(router_migrar, 'CONF_NM_AP', os.path.join(self.tmp, '91-router-ap.conf')), \
                mock.patch.object(router_migrar, 'run') as run_m, \
                mock.patch('sys.stdout', new=io.StringIO()):
            router_migrar.confirmar()
        sysfss = [a for a in (c[0][0] for c in run_m.call_args_list)
                  if 'router-ap' in ' '.join(a)]
        self.assertEqual(sysfss, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, '91-router-ap.conf')))

    def test_deshacer_sin_ap_no_toca_nada_de_ap(self):
        self._cfg(ap=False, lan_if='lan0')
        router_migrar.FASE_RUTA = os.path.join(self.tmp, 'fase')
        router_migrar.MARCADOR = os.path.join(self.tmp, 'marcador')
        with mock.patch.object(router_migrar, 'run', side_effect=_run_ok) as run_m, \
                mock.patch.object(router_migrar, '_esperar_o_forzar_retirada'), \
                mock.patch.object(router_migrar, 'log'), \
                mock.patch.object(router_migrar, 'cancelar_deshacer_programado'):
            router_migrar.deshacer('prueba sin ap')
        args = [c[0][0] for c in run_m.call_args_list]
        self.assertEqual([a for a in args if 'router-ap' in ' '.join(a)], [])

    def test_principal_enciende_el_ap_tras_el_con_up(self):
        self._cfg(ap=True)
        router_migrar.FASE_RUTA = os.path.join(self.tmp, 'fase')
        marcador = os.path.join(self.tmp, 'marcador')
        confirmada = os.path.join(self.tmp, 'confirmada')
        orden = []
        def run_enviando(args, **kw):
            orden.append(args)
            return _run_ok(args, **kw)
        # la vigilancia acaba en cuánta vez se llama (2ª vuelta: alguien
        # confirmó); el FILE de confirmación se escribe con el 1er sleep.
        def sleep_creando_confirmada(segundos):
            orden.append('sleep')
            if len([o for o in orden if o == 'sleep']) >= 1:
                open(confirmada, 'w').close()
        with mock.patch.object(router_migrar, 'run', side_effect=run_enviando), \
                mock.patch.object(router_migrar, 'log'), \
                mock.patch.object(router_migrar, 'CONFIG', self.ruta), \
                mock.patch.object(router_migrar, 'MARCADOR', marcador), \
                mock.patch.object(router_migrar, 'CONFIRMADA', confirmada), \
                mock.patch.object(router_migrar, 'verificar_previas',
                                  return_value=([], [])), \
                mock.patch.object(router_migrar, 'programar_deshacer', return_value=True), \
                mock.patch('router_migrar.time.sleep', side_effect=sleep_creando_confirmada), \
                mock.patch.object(router_migrar, 'encender_ap',
                                  side_effect=lambda *a, **k: orden.append('encender_ap')):
            self.assertEqual(router_migrar.principal(), 0)
        con_up = ['nmcli', 'con', 'up', router_migrar.PERFIL]
        self.assertIn(con_up, orden)
        self.assertIn('encender_ap', orden)
        self.assertLess(orden.index(con_up), orden.index('encender_ap'))

    # — comprobaciones previas —

    def test_comprobaciones_previas_con_ap(self):
        self._cfg(ap=True, puerto_cable='eth_cable')
        conf_hostapd = os.path.join(self.tmp, 'hostapd.conf')
        with open(conf_hostapd, 'w') as f:
            f.write('interface=wlan0\n')
        with mock.patch.object(router_migrar, 'CONFIG', self.ruta), \
                mock.patch.object(router_migrar, 'run', side_effect=_run_ok), \
                mock.patch.object(wifi_ap, 'CONF_HOSTAPD', conf_hostapd), \
                mock.patch.object(wifi_ap, 'soporta_ap', return_value=True), \
                mock.patch('sys.stdout', new=io.StringIO()), \
                mock.patch('sys.stderr', new=io.StringIO()):
            resultados = router_migrar.comprobaciones_previas()
        textos = dict((desc, ok) for ok, desc in resultados)
        self.assertTrue(textos['la tarjeta Wi-Fi wlan0 admite modo AP'])
        self.assertTrue(textos['la LAN vive en el puente br-lan (br-lan)'])
        self.assertTrue(textos['existe la config del AP (%s)' % conf_hostapd])
        # el puerto de cable no existe POR VERDAD en el entorno de pruebas
        self.assertFalse(textos['existe el puerto de cable eth_cable (esclavo del puente de la LAN)'])

    def test_comprobaciones_previas_sin_ap_no_menciona_nada(self):
        self._cfg(ap=False, lan_if='lan0')
        with mock.patch.object(router_migrar, 'CONFIG', self.ruta), \
                mock.patch.object(router_migrar, 'run', side_effect=_run_ok), \
                mock.patch('sys.stdout', new=io.StringIO()), \
                mock.patch('sys.stderr', new=io.StringIO()):
            resultados = router_migrar.comprobaciones_previas()
        self.assertEqual([desc for _, desc in resultados
                          if 'AP' in desc or 'hostapd' in desc], [])

