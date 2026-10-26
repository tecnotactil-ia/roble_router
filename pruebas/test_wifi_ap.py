#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin root, sin tarjeta Wi-Fi, sin iw
de verdad — los comandos van mockeados) de core/wifi_ap.py: la validación
de los datos del punto de acceso (AP1), la generación y la relectura de
/etc/router/hostapd.conf (ssid2 en formato P"..." o hex), la escritura
atómica 0600, el recuento de clientes desde `iw station dump` y el
soporte del modo AP según `iw phy info`.

Uso:  python3 -m unittest pruebas/test_wifi_ap.py -v
  o:  python3 -m unittest discover -s pruebas -p 'test_*.py'
"""
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import wifi_ap  # noqa: E402

SALIDA_STATION = '''Station 10:a5:d0:3c:ef:12 (on wlan0)
\tinactive time:\t1200 ms
\trx bytes:\t12345
Station d8:3a:dd:02:a4:09 (on wlan0)
\tinactive time:\t500 ms
Station f4:2b:9c:1e:77:3d (on wlan1)
\tinactive time:\t50 ms
'''

SALIDA_PHY_CON_AP = '''Wiphy phy0
\tmax #scan SSIDs: 4
Supported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * AP/VLAN
\t\t * monitor
Band 1:
\t\tFrequencies:
'''

SALIDA_PHY_SIN_AP = '''Wiphy phy0
Supported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * monitor
Band 1:
\t\tFrequencies:
'''

SALIDA_PHY_SECCION_AUSENTE = '''Wiphy phy0
\tmax #scan SSIDs: 4
\tHT Capabilities: ...
Band 1:
\t\tFrequencies:
'''


def _run_salida(salida, codigo=0):
    """CompletedProcess falso con esa salida (para iw mockeado)."""
    return subprocess.CompletedProcess(['iw'], codigo, stdout=salida, stderr='')


def _fichero_temporal(contenido):
    fd, ruta = tempfile.mkstemp(prefix='pruebas-wifi-ap-')
    with os.fdopen(fd, 'w') as f:
        f.write(contenido)
    os.chmod(ruta, 0o600)
    return ruta


class TestValidar(unittest.TestCase):

    def test_datos_buenos_no_suelta_ningun_error(self):
        self.assertEqual(wifi_ap.validar('wlan0', 'Red de Casa', 'clave1234', 'ES', 6), [])
        # canal como cadena (así llega del CLI) y extremos válidos
        self.assertEqual(wifi_ap.validar('wlp3s0', 'A', '123456789', 'DE', '13'), [])

    def test_interfaz_vacia(self):
        self.assertIn('interfaz', wifi_ap.validar('', 'Red', 'clave1234', 'ES', 6)[0])
        self.assertIn('interfaz', wifi_ap.validar(None, 'Red', 'clave1234', 'ES', 6)[0])

    def test_interfaz_con_caracteres_prohibidos(self):
        for mala in ('wlan 0', 'wlan0;', 'wlan/0'):
            errores = [e for e in wifi_ap.validar(mala, 'Red', 'clave1234', 'ES', 6)
                       if 'interfaz' in e]
            self.assertEqual(len(errores), 1, '%s debía fallar en interfaz' % mala)

    def test_interfaz_de_menos_de_16_caracteres(self):
        self.assertEqual([e for e in wifi_ap.validar('w' * 15, 'Red', 'clave1234', 'ES', 6)
                          if 'interfaz' in e], [])
        self.assertIn('interfaz', wifi_ap.validar('w' * 16, 'Red', 'clave1234', 'ES', 6)[0])

    def test_ssid_vacio(self):
        self.assertIn('ssid', wifi_ap.validar('wlan0', '', 'clave1234', 'ES', 6)[0])

    def test_ssid_con_32_bytes_acepta_y_33_no(self):
        # el límite del 802.11 son 32 BYTES de UTF-8: ññññ... gasta 2 bytes
        # por letra, así que con 'n'*32 se llega justo.
        self.assertEqual([e for e in wifi_ap.validar('wlan0', 'n' * 32, 'clave1234', 'ES', 6)
                          if 'ssid' in e], [])
        for largo in ('n' * 33, 'ñ' * 18):
            self.assertIn('ssid', wifi_ap.validar('wlan0', largo, 'clave1234', 'ES', 6)[0],
                          'SSID de %d chars debía fallar por bytes' % len(largo))

    def test_ssid_con_salto_de_linea_y_control(self):
        for ssid in ('Red\nOculta', 'Red\rOculta', 'Red\x00', 'Red\ttabulado'):
            self.assertIn('ssid', wifi_ap.validar('wlan0', ssid, 'clave1234', 'ES', 6)[0],
                          'SSID %r debía fallar' % ssid)

    def test_clave_corta_larga_y_no_ascii(self):
        self.assertIn('clave', wifi_ap.validar('wlan0', 'Red', '7654321', 'ES', 6)[0])
        self.assertIn('clave', wifi_ap.validar('wlan0', 'Red', 'k' * 64, 'ES', 6)[0])
        self.assertIn('clave', wifi_ap.validar('wlan0', 'Red', 'clave\ncon salto', 'ES', 6)[0])
        self.assertIn('clave', wifi_ap.validar('wlan0', 'Red', 'clavón1234', 'ES', 6)[0])
        # 8 y 63 sí valen
        self.assertEqual([e for e in wifi_ap.validar('wlan0', 'Red', '12345678', 'ES', 6)
                          if 'clave' in e], [])
        self.assertEqual([e for e in wifi_ap.validar('wlan0', 'Red', 'k' * 63, 'ES', 6)
                          if 'clave' in e], [])

    def test_pais_malo(self):
        for pais in ('es', 'Esp', 'E', 'E1', 'ÉC', ''):
            self.assertIn('pais', wifi_ap.validar('wlan0', 'Red', 'clave1234', pais, 6)[0],
                          'país %r debía fallar' % pais)

    def test_canal_fuera_de_rango_y_no_entero(self):
        for canal in (0, 14, -3, 'x', None, ''):
            self.assertIn('canal', wifi_ap.validar('wlan0', 'Red', 'clave1234', 'ES', canal)[0],
                          'canal %r debía fallar' % canal)
        for canal in (1, 13, '13'):
            self.assertEqual([e for e in wifi_ap.validar('wlan0', 'Red', 'clave1234', 'ES', canal)
                              if 'canal' in e], [])


class TestGenerarHostapdConf(unittest.TestCase):

    def test_estructura_completa_en_orden(self):
        texto = wifi_ap.generar_hostapd_conf('wlan0', 'Red de Casa', 'clave1234', 'ES', 6)
        lineas = [l for l in texto.splitlines() if l and not l.startswith('#')]
        self.assertEqual(lineas, [
            'interface=wlan0', 'bridge=br-lan', 'driver=nl80211',
            'ctrl_interface=/run/hostapd',
            'ssid2=P"Red de Casa"', 'utf8_ssid=1',
            'country_code=ES', 'ieee80211d=1', 'hw_mode=g', 'channel=6',
            'ieee80211n=1', 'wmm_enabled=1',
            'auth_algs=1', 'wpa=2', 'wpa_key_mgmt=WPA-PSK', 'rsn_pairwise=CCMP',
            'wpa_passphrase=clave1234',
        ])
        self.assertIn('generado por Roble Router', texto)
        self.assertIn('NO editar a mano', texto)

    def test_ssid_con_espacios_y_acentos_en_formato_p(self):
        texto = wifi_ap.generar_hostapd_conf('wlan0', 'Red de Casa Ñ',
                                             'clave1234', 'ES', 6)
        self.assertIn('ssid2=P"Red de Casa Ñ"', texto)
        # la vuelta atrás recupera el SSID original completo
        self.assertEqual(wifi_ap.leer_ssid(ruta=_fichero_temporal(texto)), 'Red de Casa Ñ')

    def test_ssid_con_comillas_va_en_hex(self):
        texto = wifi_ap.generar_hostapd_conf('wlan0', 'Red "especial"', 'clave1234', 'ES', 6)
        linea = [l for l in texto.splitlines() if l.startswith('ssid2=')][0]
        self.assertEqual(linea, 'ssid2=%s' % 'Red "especial"'.encode('utf-8').hex())
        self.assertEqual(wifi_ap.leer_ssid(ruta=_fichero_temporal(texto)), 'Red "especial"')

    def test_clave_con_almuadilla_y_espacios_intacta(self):
        texto = wifi_ap.generar_hostapd_conf('wlan0', 'Red', 'mi clave #secreta 1', 'ES', 6)
        # hostapd toma TODO el resto de la línea tras el «=»: la almuhadilla
        # y los espacios van tal cual.
        self.assertIn('wpa_passphrase=mi clave #secreta 1', texto)

    def test_datos_malos_lanza_valueerror(self):
        for datos in ((('wlan;;'), 'Red', 'clave1234', 'ES', 6),
                      ('wlan0', '', 'clave1234', 'ES', 6),
                      ('wlan0', 'Red', '1234567', 'ES', 6),
                      ('wlan0', 'Red', 'clave1234', 'es', 6),
                      ('wlan0', 'Red', 'clave1234', 'ES', 14)):
            with self.assertRaises(ValueError) as ctx:
                wifi_ap.generar_hostapd_conf(*datos)
            # el mensaje se sabe interpretar: dice el campo que falló
            self.assertIn('datos de AP', str(ctx.exception))


class TestLeerYEscribirHostapdConf(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-wifi-ap-')
        self.ruta = os.path.join(self.tmp, 'hostapd.conf')

    def test_ida_y_vuelta_ssid_normal(self):
        texto = wifi_ap.generar_hostapd_conf('wlan0', 'Mi Red-Fi', 'clave1234', 'ES', 9)
        wifi_ap.escribir_hostapd_conf(texto, self.ruta)
        self.assertEqual(wifi_ap.leer_ssid(self.ruta), 'Mi Red-Fi')

    def test_ida_y_vuelta_ssid_con_comillas_hex(self):
        texto = wifi_ap.generar_hostapd_conf('wlan0', 'a"b', 'clave1234', 'ES', 9)
        wifi_ap.escribir_hostapd_conf(texto, self.ruta)
        self.assertEqual(wifi_ap.leer_ssid(self.ruta), 'a"b')

    def test_fichero_queda_0600(self):
        wifi_ap.escribir_hostapd_conf('conf\n', self.ruta)
        self.assertEqual(stat.S_IMODE(os.stat(self.ruta).st_mode), 0o600)

    def test_escritura_atomica_sin_temporales_sueltos(self):
        # dos escrituras seguidas: siempre fichero regular con el último
        # contenido, y ningún fichero temporal a medias por donde tropezar.
        wifi_ap.escribir_hostapd_conf('primera\n', self.ruta)
        wifi_ap.escribir_hostapd_conf('segunda\n', self.ruta)
        with open(self.ruta) as f:
            self.assertEqual(f.read(), 'segunda\n')
        self.assertEqual([n for n in os.listdir(self.tmp) if n.startswith('.tmp')], [])

    def test_leer_ssid_sin_fichero_o_rara_da_cadena_vacia(self):
        self.assertEqual(wifi_ap.leer_ssid(os.path.join(self.tmp, 'no-hay.conf')), '')
        self.assertEqual(wifi_ap.leer_ssid(ruta=_fichero_temporal('ssid2=algo-rara\x00\n')), '')
        self.assertEqual(wifi_ap.leer_ssid(ruta=_fichero_temporal('# sólo comentarios\n')), '')


class TestClientes(unittest.TestCase):

    def test_cuenta_las_estaciones_de_su_interfaz(self):
        with mock.patch.object(wifi_ap.subprocess, 'run',
                               return_value=_run_salida(SALIDA_STATION)):
            self.assertEqual(wifi_ap.clientes('wlan0'),
                             ['10:a5:d0:3c:ef:12', 'd8:3a:dd:02:a4:09'])

    def test_otros_no_cuentan(self):
        with mock.patch.object(wifi_ap.subprocess, 'run',
                               return_value=_run_salida(SALIDA_STATION)):
            self.assertEqual(wifi_ap.clientes('wlan1'), ['f4:2b:9c:1e:77:3d'])

    def test_error_o_salida_vacia_da_lista_vacia(self):
        for respuesta in (_run_salida('', 1), _run_salida('', 255), _run_salida('')):
            with mock.patch.object(wifi_ap.subprocess, 'run', return_value=respuesta):
                self.assertEqual(wifi_ap.clientes('wlan0'), [])
        with mock.patch.object(wifi_ap.subprocess, 'run', side_effect=OSError('iw no está')):
            self.assertEqual(wifi_ap.clientes('wlan0'), [])
        with mock.patch.object(wifi_ap.subprocess, 'run',
                               side_effect=subprocess.TimeoutExpired(cmd='iw', timeout=10)):
            self.assertEqual(wifi_ap.clientes('wlan0'), [])


class TestSoportaAp(unittest.TestCase):

    def _con_phy_y_salida(self, salida, codigo=0):
        """Parches: `open` leyendo phy0 de sysfs + iw devolviendo `salida`."""
        def iw_falso(*args, **kwargs):
            return _run_salida(salida, codigo)
        return (mock.patch.object(wifi_ap.subprocess, 'run', side_effect=iw_falso),
                mock.patch('builtins.open', mock.mock_open(read_data='phy0\n')))

    def test_tarjeta_con_ap(self):
        cmd, abrir = self._con_phy_y_salida(SALIDA_PHY_CON_AP)
        with cmd, abrir:
            self.assertTrue(wifi_ap.soporta_ap('wlan0'))

    def test_tarjeta_sin_ap(self):
        cmd, abrir = self._con_phy_y_salida(SALIDA_PHY_SIN_AP)
        with cmd, abrir:
            self.assertFalse(wifi_ap.soporta_ap('wlan0'))

    def test_salida_rara_sin_seccion_de_modos_da_desconocido(self):
        cmd, abrir = self._con_phy_y_salida(SALIDA_PHY_SECCION_AUSENTE)
        with cmd, abrir:
            self.assertIsNone(wifi_ap.soporta_ap('wlan0'))

    def test_sin_phy_da_desconocido(self):
        with mock.patch('builtins.open', side_effect=OSError):
            self.assertIsNone(wifi_ap.soporta_ap('no-existe'))

    def test_iw_fallando_da_desconocido(self):
        cmd, abrir = self._con_phy_y_salida('', codigo=1)
        with cmd, abrir:
            self.assertIsNone(wifi_ap.soporta_ap('wlan0'))
        cmd, abrir = self._con_phy_y_salida('', codigo=0)
        with mock.patch.object(wifi_ap.subprocess, 'run', side_effect=OSError), abrir:
            self.assertIsNone(wifi_ap.soporta_ap('wlan0'))


class TestCLI(unittest.TestCase):

    def test_soporta_ap_imprime_si_no_y_desconocido(self):
        for soporte, palabra in ((True, 'si'), (False, 'no'), (None, 'desconocido')):
            with mock.patch.object(wifi_ap, 'soporta_ap', return_value=soporte), \
                    mock.patch('sys.stdout', new=io.StringIO()) as out:
                self.assertEqual(wifi_ap._cli_soporta(['wlan0']), 0)
            self.assertEqual(out.getvalue().strip(), palabra)

    def test_escribir_valido_deja_0600(self):
        fd, ruta = tempfile.mkstemp(prefix='pruebas-wifi-ap-cli-')
        os.close(fd)
        os.unlink(ruta)
        conf_esperada = wifi_ap.generar_hostapd_conf('wlan0', 'Casa',
                                                     'clavesegura12', 'ES', '6')
        with mock.patch('sys.stdin', new=io.StringIO('clavesegura12\n')), \
                mock.patch.object(wifi_ap, 'CONF_HOSTAPD', ruta):
            self.assertEqual(wifi_ap._cli_escribir(['--interfaz', 'wlan0', '--ssid',
                                                    'Casa', '--pais', 'ES',
                                                    '--canal', '6']), 0)
        # la clave NUNCA entra por argv: el stdin es lo que se usó
        self.assertEqual(wifi_ap.leer_ssid(ruta), 'Casa')
        self.assertEqual(stat.S_IMODE(os.stat(ruta).st_mode), 0o600)
        with open(ruta) as f:
            self.assertEqual(f.read(), conf_esperada)
        os.unlink(ruta)

    def test_escribir_invalid_sale_2_con_errores_en_stderr_y_no_escribe(self):
        with mock.patch('sys.stdin', new=io.StringIO('corta\n')), \
                mock.patch('sys.stderr', new=io.StringIO()) as errores, \
                mock.patch.object(wifi_ap, 'escribir_hostapd_conf') as escribir:
            self.assertEqual(wifi_ap._cli_escribir(['--interfaz', 'wlan0', '--ssid',
                                                    'Casa', '--pais', 'ES',
                                                    '--canal', '6']), 2)
        self.assertIn('ERROR: clave', errores.getvalue())
        escribir.assert_not_called()

    def test_main_sin_subo_comando_da_uso_y_error(self):
        with mock.patch('sys.stderr', new=io.StringIO()) as errores:
            self.assertEqual(wifi_ap.main([]), 2)
        self.assertIn('uso:', errores.getvalue())


if __name__ == '__main__':
    unittest.main()
