#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root, sin nft/ip/nmcli) de
la WAN Wi-Fi en core/routerd.py: generación del perfil NM (keyfile), parseo
de `nmcli -t`, la guarda anti-bucle y la redacción de la clave en el oplog.

Uso:  python3 -m unittest pruebas/test_wifi.py -v
  o:  python3 pruebas/test_wifi.py
"""
import copy
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import routerd  # noqa: E402

try:
    import gi
    gi.require_version('GLib', '2.0')
    from gi.repository import GLib
    _TIENE_GLIB = True
except Exception:
    _TIENE_GLIB = False


def _cfg_base():
    cfg = copy.deepcopy(routerd.CONFIG_DEFECTO)
    cfg['lan'] = {'interfaz': 'enp2s0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'}
    cfg['wifi_wan'] = {'habilitada': True, 'interfaz': 'wlp3s0b1', 'ssid_bloqueadas': ['MI-WIFI']}
    return cfg


def _rutas_prueba(tmp):
    """Rutas de Router bajo un directorio temporal propio del test — nunca
    toca /etc/router/router.json ni ningún fichero real. 'migracion_pendiente'
    apunta a un fichero que nunca se crea: _wifi_permitida() lo ve como "no
    hay migración en curso" salvo que el propio test lo cree."""
    return {
        'config': os.path.join(tmp, 'router.json'),
        'fase': os.path.join(tmp, 'fase'),
        'migracion_pendiente': os.path.join(tmp, 'migracion-pendiente'),
        'estado': os.path.join(tmp, 'estado.json'),
        'firewall': os.path.join(tmp, 'firewall.txt'),
        'buzon': os.path.join(tmp, 'buzon'),
        'respuestas': os.path.join(tmp, 'respuestas'),
        'oplog': os.path.join(tmp, 'oplog.log'),
        'nft_base': os.path.join(tmp, 'base.nft'),
        'dnsmasq_lan': os.path.join(tmp, 'dnsmasq.conf'),
        'dnsmasq_reservas': os.path.join(tmp, 'reservas.conf'),
        'grupo_panel': 'routerpanel',
        'nm_system_connections': os.path.join(tmp, 'nm'),
    }


def _router_en_memoria(cfg, tmp=None):
    """Un Router cuyo __init__ no toca disco de verdad para nada que no sea
    la config (rutas bajo un tmp propio, nunca leídas por estos tests): basta
    para llamar a sus métodos puros (_wifi_guardia_bucle, etc.) sin depender
    de /etc/router/router.json ni de ningún fichero real."""
    r = routerd.Router(_rutas_prueba(tmp or tempfile.mkdtemp(prefix='pruebas-wifi-')))
    r.cfg = cfg
    return r


class TestKeyfileWifi(unittest.TestCase):
    def test_contenido_basico(self):
        nombre, texto = routerd.generar_keyfile_wifi('MiRed', 'password1', 50, 'wlp3s0b1')
        self.assertTrue(nombre.startswith('WAN-wifi-'))
        self.assertIn('id=%s' % nombre, texto)
        self.assertIn('type=wifi', texto)
        self.assertIn('interface-name=wlp3s0b1', texto)
        self.assertIn('autoconnect=true', texto)
        self.assertIn('autoconnect-priority=50', texto)
        self.assertIn('key-mgmt=wpa-psk', texto)
        self.assertIn('psk=password1', texto)
        self.assertIn('route-metric=750', texto)
        self.assertIn('ignore-auto-dns=true', texto)
        self.assertIn('method=disabled', texto)   # ipv6

    def test_red_abierta_sin_seccion_de_seguridad(self):
        _, texto = routerd.generar_keyfile_wifi('Abierta', '', 10, 'wlp3s0b1')
        self.assertNotIn('[wifi-security]', texto)
        self.assertNotIn('key-mgmt', texto)
        self.assertNotIn('psk=', texto)

    def test_ssid_raro_como_lista_de_bytes(self):
        # ';' y '=' y espacio dentro del SSID: si se escribiera el SSID como
        # texto plano en el keyfile, esto podría romper el formato .ini de
        # NetworkManager (un '=' de más, una línea partida en ';'…). Al ir
        # SIEMPRE como lista de bytes no hay nada que escapar.
        ssid = 'Ca;fe=Red con espacios'
        _, texto = routerd.generar_keyfile_wifi(ssid, '', 0, 'wlp3s0b1')
        esperado = routerd._ssid_bytes_keyfile(ssid)
        self.assertIn('ssid=%s' % esperado, texto)
        self.assertNotIn('ssid=%s' % ssid, texto)   # nunca el texto plano
        # la lista de bytes decodifica exactamente al SSID original
        bytes_decodificados = bytes(int(b) for b in esperado.rstrip(';').split(';'))
        self.assertEqual(bytes_decodificados.decode('utf-8'), ssid)

    def test_sin_clave_no_hay_psk(self):
        _, texto = routerd.generar_keyfile_wifi('Abierta', '', 0, 'wlp3s0b1')
        self.assertNotIn('psk', texto)

    def test_nombres_distintos_para_ssid_distinto(self):
        n1, _ = routerd.generar_keyfile_wifi('RedUno', '', 0, 'wlp3s0b1')
        n2, _ = routerd.generar_keyfile_wifi('RedDos', '', 0, 'wlp3s0b1')
        self.assertNotEqual(n1, n2)

    def test_mismo_ssid_mismo_nombre_de_perfil(self):
        # wifi_agregar «reemplaza si ya existe»: necesita que el nombre del
        # perfil sea estable para el mismo SSID entre llamadas.
        n1 = routerd.nombre_perfil_wifi('MiRed')
        n2 = routerd.nombre_perfil_wifi('MiRed')
        self.assertEqual(n1, n2)

    def test_slug_siempre_ascii_seguro(self):
        nombre = routerd.nombre_perfil_wifi('Wí-Fí Ñandú 中文 😀')
        self.assertTrue(nombre.encode('ascii'))   # no lanza: es ASCII puro
        self.assertTrue(nombre.startswith('WAN-wifi-'))


class TestParseoNmcliT(unittest.TestCase):
    def test_linea_simple(self):
        self.assertEqual(routerd._parsear_linea_nmcli_t('a:b:c'), ['a', 'b', 'c'])

    def test_escape_dos_puntos_dentro_de_un_campo(self):
        # un SSID con ':' de verdad llega escapado como '\:' en nmcli -t —
        # no debe partir el campo ahí.
        linea = r'MI\:WIFI:80:WPA2:6'
        self.assertEqual(routerd._parsear_linea_nmcli_t(linea), ['MI:WIFI', '80', 'WPA2', '6'])

    def test_escape_barra_invertida(self):
        linea = r'Red\\Rara:50:--:1'
        self.assertEqual(routerd._parsear_linea_nmcli_t(linea), ['Red\\Rara', '50', '--', '1'])

    def test_parsear_escaneo_completo(self):
        texto = 'MiRed:70:WPA2:6\nMI\\:WIFI:90:WPA2:11\n'
        redes = routerd.parsear_escaneo_wifi(texto)
        self.assertEqual(len(redes), 2)
        self.assertEqual(redes[0], {'ssid': 'MiRed', 'senal': 70, 'seguridad': 'WPA2', 'canal': '6'})
        self.assertEqual(redes[1]['ssid'], 'MI:WIFI')

    def test_linea_con_pocos_campos_se_descarta(self):
        redes = routerd.parsear_escaneo_wifi('solo:dos\n')
        self.assertEqual(redes, [])

    def test_linea_vacia_se_ignora(self):
        redes = routerd.parsear_escaneo_wifi('MiRed:70:WPA2:6\n\n')
        self.assertEqual(len(redes), 1)

    def test_senal_no_numerica_se_trata_como_cero(self):
        redes = routerd.parsear_escaneo_wifi('MiRed:rara:WPA2:6\n')
        self.assertEqual(redes[0]['senal'], 0)


class TestGuardaAntiBucle(unittest.TestCase):
    def setUp(self):
        self.r = _router_en_memoria(_cfg_base())

    def test_ssid_bloqueada(self):
        w = {'ifname': 'wlp3s0b1', 'id': 'wifi-wlp3s0b1', 'telefono': 'MI-WIFI',
             'ip': None, 'gw': None, 'es_wifi': True}
        razon = self.r._wifi_guardia_bucle(w)
        self.assertIsNotNone(razon)
        self.assertIn('bloqueado', razon)

    def test_ip_dentro_de_la_lan(self):
        w = {'ifname': 'wlp3s0b1', 'id': 'wifi-wlp3s0b1', 'telefono': 'Tel1',
             'ip': '192.168.50.55/24', 'gw': '192.168.42.1', 'es_wifi': True}
        razon = self.r._wifi_guardia_bucle(w)
        self.assertIsNotNone(razon)
        self.assertIn('coincide', razon)

    def test_gateway_es_la_ip_del_router(self):
        w = {'ifname': 'wlp3s0b1', 'id': 'wifi-wlp3s0b1', 'telefono': 'Tel1',
             'ip': '10.0.0.5/24', 'gw': '192.168.50.1', 'es_wifi': True}
        razon = self.r._wifi_guardia_bucle(w)
        self.assertIsNotNone(razon)
        self.assertIn('puerta', razon)

    def test_wan_wifi_normal_no_activa_la_guarda(self):
        w = {'ifname': 'wlp3s0b1', 'id': 'wifi-wlp3s0b1', 'telefono': 'TelefonoDeCasa',
             'ip': '192.168.42.10/24', 'gw': '192.168.42.1', 'es_wifi': True}
        self.assertIsNone(self.r._wifi_guardia_bucle(w))

    def test_sin_ip_ni_ssid_no_activa_la_guarda(self):
        w = {'ifname': 'wlp3s0b1', 'id': 'wifi-wlp3s0b1', 'telefono': None,
             'ip': None, 'gw': None, 'es_wifi': True}
        self.assertIsNone(self.r._wifi_guardia_bucle(w))


class TestDescubrirWans(unittest.TestCase):
    def test_wifi_deshabilitada_no_aparece(self):
        cfg = _cfg_base()
        cfg['wifi_wan']['habilitada'] = False
        out = routerd.descubrir_wans(cfg)
        self.assertNotIn('wifi-wlp3s0b1', [w['id'] for w in out])

    def test_wifi_habilitada_pero_sin_interfaz_no_aparece(self):
        cfg = _cfg_base()
        cfg['wifi_wan']['interfaz'] = 'una-interfaz-que-no-existe-de-verdad'
        out = routerd.descubrir_wans(cfg)
        self.assertEqual([w for w in out if w.get('es_wifi')], [])

    def test_wifi_con_interfaz_existente_aparece_con_id_estable(self):
        # 'lo' siempre existe: sirve para probar el descubrimiento sin
        # necesitar hardware wifi de verdad (requisito: que falle en blando
        # si depende de nmcli para el SSID, pero que la interfaz SÍ entre).
        cfg = _cfg_base()
        cfg['wifi_wan']['interfaz'] = 'lo'
        out = routerd.descubrir_wans(cfg)
        wifi = [w for w in out if w.get('es_wifi')]
        self.assertEqual(len(wifi), 1)
        self.assertEqual(wifi[0]['id'], 'wifi-lo')
        self.assertEqual(wifi[0]['ifname'], 'lo')


class TestRedaccionClave(unittest.TestCase):
    def test_redacta_clave_presente(self):
        datos = {'ssid': 'MiRed', 'clave': 'password1', 'prioridad': 50}
        redactado = routerd._redactar_datos(datos)
        self.assertEqual(redactado['clave'], '***')
        self.assertEqual(redactado['ssid'], 'MiRed')
        # el original (lo que de verdad se usó para aplicar la petición) no se muta
        self.assertEqual(datos['clave'], 'password1')

    def test_sin_clave_no_cambia_nada(self):
        datos = {'mac': 'aa:bb:cc:dd:ee:ff'}
        self.assertEqual(routerd._redactar_datos(datos), datos)

    def test_clave_vacia_tambien_se_redacta(self):
        # una red abierta también lleva 'clave' en los datos (= ''): aunque
        # no sea secreta, se redacta igual — la regla es "si existe el
        # campo", no "si tiene contenido".
        datos = {'ssid': 'Abierta', 'clave': '', 'prioridad': 0}
        redactado = routerd._redactar_datos(datos)
        self.assertEqual(redactado['clave'], '***')

    def test_no_es_un_dict_se_devuelve_tal_cual(self):
        self.assertEqual(routerd._redactar_datos('no-es-un-dict'), 'no-es-un-dict')
        self.assertEqual(routerd._redactar_datos(None), None)


class TestSsidBloqueadaNormalizada(unittest.TestCase):
    """Revisión Opus (ronda 2): comparar ssid_bloqueadas con
    .strip().casefold(), para que un espacio de más o una mayúscula/
    minúscula distinta no cuelen una conexión al AP de la propia LAN."""

    def test_normalizacion_directa(self):
        self.assertEqual(routerd._normalizar_ssid_bloqueo('MI-WIFI'), 'mi-wifi')
        self.assertEqual(routerd._normalizar_ssid_bloqueo(' MI-WIFI '), 'mi-wifi')

    def test_minuscula_bloqueada(self):
        self.assertTrue(routerd._ssid_esta_bloqueada('mi-wifi', ['MI-WIFI']))

    def test_espacio_final_bloqueado(self):
        self.assertTrue(routerd._ssid_esta_bloqueada('MI-WIFI ', ['MI-WIFI']))

    def test_no_bloqueada_de_verdad_pasa(self):
        self.assertFalse(routerd._ssid_esta_bloqueada('OtraRed', ['MI-WIFI']))

    def test_guarda_anti_bucle_usa_la_normalizacion(self):
        r = _router_en_memoria(_cfg_base())
        for ssid in ('mi-wifi', 'MI-WIFI ', ' Mi-Wifi'):
            w = {'ifname': 'wlp3s0b1', 'id': 'wifi-wlp3s0b1', 'telefono': ssid,
                 'ip': None, 'gw': None, 'es_wifi': True}
            razon = r._wifi_guardia_bucle(w)
            self.assertIsNotNone(razon, 'no se bloqueó %r' % ssid)


class TestEscapePsk(unittest.TestCase):
    """Revisión Opus (ronda 2), punto 5: escape de la clave al formato
    keyfile (GKeyFile) de NetworkManager/GLib."""

    def test_backslash_se_duplica(self):
        self.assertEqual(routerd._escapar_valor_keyfile('a\\b'), 'a\\\\b')

    def test_secuencia_barra_x_no_se_interpreta_como_escape(self):
        # "\x" NO es un escape de GKeyFile (sólo \\, \s, \n, \t, \r): tras
        # duplicar la barra, "\\x" queda como \\ seguido de 'x' literal.
        self.assertEqual(routerd._escapar_valor_keyfile('a\\xb'), 'a\\\\xb')

    def test_espacio_inicial(self):
        self.assertEqual(routerd._escapar_valor_keyfile(' abcdefgh'), '\\sabcdefgh')

    def test_espacio_final(self):
        self.assertEqual(routerd._escapar_valor_keyfile('abcdefgh '), 'abcdefgh\\s')

    def test_espacio_inicial_y_final(self):
        self.assertEqual(routerd._escapar_valor_keyfile(' abcdefgh '), '\\sabcdefgh\\s')

    def test_un_solo_espacio(self):
        self.assertEqual(routerd._escapar_valor_keyfile(' '), '\\s')

    def test_caracteres_sin_significado_especial_en_un_valor(self):
        # ';', '=', '#', '[' no hace falta escaparlos dentro de un VALOR
        # (keyfile), pero el round-trip debe conservarlos intactos.
        clave = ';=#[clave]#=;'
        self.assertEqual(routerd._escapar_valor_keyfile(clave), clave)

    def _decodificar_a_mano(self, v):
        """Inverso de _escapar_valor_keyfile, para el caso sin GLib
        disponible: desescapa \\\\ -> \\ y \\s -> espacio (las dos únicas
        secuencias que genera la función bajo prueba)."""
        out, i = [], 0
        while i < len(v):
            if v[i] == '\\' and i + 1 < len(v):
                siguiente = v[i + 1]
                if siguiente == '\\':
                    out.append('\\')
                elif siguiente == 's':
                    out.append(' ')
                else:
                    out.append(siguiente)
                i += 2
                continue
            out.append(v[i])
            i += 1
        return ''.join(out)

    def test_roundtrip_a_mano_para_casos_dificiles(self):
        for clave in ('a\\b', 'a\\xb', ' abcdefgh', 'abcdefgh ', ' abcdefgh ',
                      ';=#[clave]#=;', 'normal12345', '\\', '\\\\'):
            escapada = routerd._escapar_valor_keyfile(clave)
            self.assertEqual(self._decodificar_a_mano(escapada), clave, 'falló con %r' % clave)

    @unittest.skipUnless(_TIENE_GLIB, 'python3-gi (GLib) no disponible en este entorno')
    def test_roundtrip_con_glib_keyfile_de_verdad(self):
        """Si python3-gi está instalado, se verifica con el MISMO parser
        (GLib.KeyFile) que usa NetworkManager, no sólo con un desescapado
        propio — es la prueba de verdad de que generar_keyfile_wifi()
        produce un fichero que NetworkManager interpretará correctamente."""
        casos = ['a\\b', 'a\\xb', ' password con espacios ', ';=#[rara]#=;',
                 'normal12345', '\\\\dobleBarra']
        tmp = tempfile.mkdtemp(prefix='pruebas-wifi-glib-')
        try:
            for clave in casos:
                _, texto = routerd.generar_keyfile_wifi('MiRed', clave, 10, 'wlp3s0b1')
                ruta = os.path.join(tmp, 'perfil.nmconnection')
                with open(ruta, 'w') as f:
                    f.write(texto)
                kf = GLib.KeyFile.new()
                kf.load_from_file(ruta, GLib.KeyFileFlags.NONE)
                leida = kf.get_string('wifi-security', 'psk')
                self.assertEqual(leida, clave, 'GLib no reconstruyó la clave %r' % clave)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPreparacionNoTocaWifi(unittest.TestCase):
    """Revisión Opus (ronda 2), punto 2: en fase preparación, o con una
    migración en curso, routerd no debe descubrir la WAN Wi-Fi, ni tocar su
    radio, ni la guarda anti-bucle."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-wifi-prep-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.r = routerd.Router(_rutas_prueba(self.tmp))
        self.r.cfg = _cfg_base()

    def test_preparacion_no_permite_wifi(self):
        self.r.fase = 'preparacion'
        self.assertFalse(self.r._wifi_permitida())

    def test_produccion_sin_marcador_permite_wifi(self):
        self.r.fase = 'produccion'
        self.assertTrue(self.r._wifi_permitida())

    def test_produccion_con_marcador_de_migracion_no_permite_wifi(self):
        self.r.fase = 'produccion'
        with open(self.r.rutas['migracion_pendiente'], 'w') as f:
            f.write('limite=2026-01-01T00:00:00+00:00\n')
        self.assertFalse(self.r._wifi_permitida())

    def test_descubrir_wans_con_permitir_wifi_false_no_incluye_wifi(self):
        cfg = _cfg_base()
        cfg['wifi_wan']['interfaz'] = 'lo'   # existiría si se permitiera
        out = routerd.descubrir_wans(cfg, permitir_wifi=False)
        self.assertEqual([w for w in out if w.get('es_wifi')], [])

    def test_radio_no_se_toca_en_preparacion(self):
        self.r.fase = 'preparacion'
        self.r.cfg['wifi_wan']['interfaz'] = 'lo'   # existe de verdad: si no fuera por la fase, sí tocaría
        with mock.patch('routerd.run') as m_run:
            # ciclo() en preparación no debe ni llamar a _aplicar_radio_wifi
            # (la propia _wifi_permitida() ya lo filtra antes de llegar a
            # nmcli): aquí se comprueba directamente que NUNCA se ejecuta
            # ningún 'nmcli radio'.
            if self.r._wifi_permitida():
                self.r._aplicar_radio_wifi()
            for llamada in m_run.call_args_list:
                args = llamada.args[0] if llamada.args else []
                self.assertFalse('radio' in args and 'wifi' in args)


class TestRadioNoCadaCiclo(unittest.TestCase):
    """Revisión Opus (ronda 2), punto 3: la radio se resincroniza con el
    estado real cada ~60 s (no cada ciclo), y sólo se toca de verdad cuando
    el estado deseado difiere del real."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-wifi-radio-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.r = routerd.Router(_rutas_prueba(self.tmp))
        self.r.cfg = _cfg_base()
        self.r.cfg['wifi_wan']['interfaz'] = 'lo'   # 'lo' siempre existe
        self.r.fase = 'produccion'

    def _run_radio_enabled(self, args, **kw):
        # La LECTURA (_radio_wifi_real) es ['env', 'LC_ALL=C', 'nmcli', 'radio', 'wifi']
        # (termina en 'wifi'); la ESCRITURA real es [..., 'radio', 'wifi', 'on'|'off']
        # (termina en 'on'/'off'): sólo la lectura debe devolver "enabled".
        if args and args[-1] == 'wifi' and 'radio' in args:
            return subprocess.CompletedProcess(args, 0, stdout='enabled\n', stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')

    def test_no_se_lee_el_estado_real_en_cada_ciclo(self):
        with mock.patch('routerd.run', side_effect=self._run_radio_enabled) as m_run:
            self.r._aplicar_radio_wifi()   # primera vez: SÍ resincroniza
            llamadas_1 = m_run.call_count
            self.r._aplicar_radio_wifi()   # segunda vez, acto seguido: NO debería volver a leer
            llamadas_2 = m_run.call_count
        self.assertEqual(llamadas_1, llamadas_2, 'se volvió a consultar el estado real sin que pasara tiempo')

    def test_resincroniza_pasados_60_segundos(self):
        with mock.patch('routerd.run', side_effect=self._run_radio_enabled) as m_run:
            self.r._aplicar_radio_wifi()
            llamadas_1 = m_run.call_count
            self.r._radio_wifi_ultima_lectura -= 61   # simula que pasó más de un minuto
            self.r._aplicar_radio_wifi()
            llamadas_2 = m_run.call_count
        self.assertGreater(llamadas_2, llamadas_1)

    def test_no_se_toca_si_el_estado_real_ya_coincide(self):
        self.r.cfg['wifi_wan']['habilitada'] = True
        with mock.patch('routerd.run', side_effect=self._run_radio_enabled) as m_run:
            self.r._aplicar_radio_wifi()
            comandos = [c.args[0] for c in m_run.call_args_list]
        # Sólo la LECTURA ("nmcli radio wifi" de consulta); nunca un
        # "nmcli radio wifi on/off" de verdad, porque ya estaba "enabled".
        self.assertNotIn(['nmcli', 'radio', 'wifi', 'on'], comandos)
        self.assertNotIn(['nmcli', 'radio', 'wifi', 'off'], comandos)

    def test_gestionar_radio_wifi_false_nunca_toca_nada(self):
        self.r.cfg['gestionar_radio_wifi'] = False
        with mock.patch('routerd.run') as m_run:
            self.r._aplicar_radio_wifi()
            m_run.assert_not_called()


class TestWifiEliminarNoTocaAjenos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-wifi-eliminar-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.r = routerd.Router(_rutas_prueba(self.tmp))
        self.r.cfg = _cfg_base()
        self.r.fase = 'produccion'

    def test_nombre_de_perfil_siempre_propio(self):
        # nombre_perfil_wifi() SIEMPRE antepone "WAN-wifi-": no hay forma de
        # pedir, desde wifi_eliminar, el borrado de un perfil con otro nombre.
        for ssid in ('MiRed', 'OtroSSID', 'red con espacios', 'Ñandú'):
            self.assertTrue(routerd.nombre_perfil_wifi(ssid).startswith('WAN-wifi-'))

    def test_no_borra_si_el_perfil_no_es_propio(self):
        # Simula que existe un perfil AJENO con un nombre que NO es
        # WAN-wifi-* para ese SSID: nmcli -g NAME nunca lo listará como tal
        # (porque _wifi_eliminar busca exactamente nombre_perfil_wifi(ssid),
        # que siempre empieza por WAN-wifi-), así que "delete" nunca se
        # llama sobre el perfil ajeno.
        def run_falso(args, **kw):
            if args[:4] == ['nmcli', '-g', 'NAME', 'connection']:
                return subprocess.CompletedProcess(args, 0, stdout='MiRedDeCasa\n', stderr='')
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='no debería llegar aquí')
        with mock.patch('routerd.run', side_effect=run_falso) as m_run:
            ok, msg = self.r._wifi_eliminar('MiRed')
        self.assertFalse(ok)
        self.assertIn('No hay ninguna red Wi-Fi guardada', msg)
        for llamada in m_run.call_args_list:
            self.assertNotEqual(llamada.args[0][:3], ['nmcli', 'connection', 'delete'])

    def test_borra_su_propio_perfil(self):
        nombre = routerd.nombre_perfil_wifi('MiRed')

        def run_falso(args, **kw):
            if args[:4] == ['nmcli', '-g', 'NAME', 'connection']:
                return subprocess.CompletedProcess(args, 0, stdout=nombre + '\n', stderr='')
            if args[:3] == ['nmcli', 'connection', 'delete']:
                return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        with mock.patch('routerd.run', side_effect=run_falso):
            ok, msg = self.r._wifi_eliminar('MiRed')
        self.assertTrue(ok, msg)

    def test_delete_falla_devuelve_error(self):
        # Punto 8: wifi_eliminar debe comprobar el returncode del delete.
        nombre = routerd.nombre_perfil_wifi('MiRed')

        def run_falso(args, **kw):
            if args[:4] == ['nmcli', '-g', 'NAME', 'connection']:
                return subprocess.CompletedProcess(args, 0, stdout=nombre + '\n', stderr='')
            if args[:3] == ['nmcli', 'connection', 'delete']:
                return subprocess.CompletedProcess(args, 1, stdout='', stderr='nope')
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        with mock.patch('routerd.run', side_effect=run_falso):
            ok, msg = self.r._wifi_eliminar('MiRed')
        self.assertFalse(ok)


class TestUnaAccionWifiPorCiclo(unittest.TestCase):
    """Revisión Opus (ronda 2), punto 6: como mucho una acción wifi_* de
    SISTEMA se ejecuta de verdad por ciclo; las demás quedan sin reclamar
    (ni responder) para el ciclo siguiente."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-wifi-unaporciclo-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.r = routerd.Router(_rutas_prueba(self.tmp))
        self.r.cfg = _cfg_base()
        self.r.fase = 'produccion'
        self.r.permitir_guardar = True
        os.makedirs(self.r.rutas['buzon'], exist_ok=True)

    def _escribir_peticion(self, accion, datos):
        pid = str(uuid.uuid4())
        pet = {'id': pid, 'usuario': 'admin', 'accion': accion, 'datos': datos}
        with open(os.path.join(self.r.rutas['buzon'], pid + '.json'), 'w') as f:
            json.dump(pet, f)
        return pid

    def test_dos_wifi_agregar_en_el_mismo_buzon_solo_ejecuta_uno(self):
        pid1 = self._escribir_peticion('wifi_agregar', {'ssid': 'Red1', 'clave': '', 'prioridad': 0})
        pid2 = self._escribir_peticion('wifi_agregar', {'ssid': 'Red2', 'clave': '', 'prioridad': 0})
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = subprocess.CompletedProcess([], 0, stdout='', stderr='')
            self.r.atender_buzon()
        respondidas = {pid1: os.path.exists(os.path.join(self.r.rutas['respuestas'], pid1 + '.json')),
                       pid2: os.path.exists(os.path.join(self.r.rutas['respuestas'], pid2 + '.json'))}
        # Exactamente una de las dos se ha respondido (= ejecutado) este ciclo;
        # la otra sigue en el buzón, sin reclamar, para el ciclo siguiente.
        self.assertEqual(sum(respondidas.values()), 1, respondidas)
        pendiente = pid1 if not respondidas[pid1] else pid2
        self.assertTrue(os.path.exists(os.path.join(self.r.rutas['buzon'], pendiente + '.json')))

    def test_la_pendiente_se_ejecuta_en_el_siguiente_ciclo(self):
        pid1 = self._escribir_peticion('wifi_agregar', {'ssid': 'Red1', 'clave': '', 'prioridad': 0})
        pid2 = self._escribir_peticion('wifi_agregar', {'ssid': 'Red2', 'clave': '', 'prioridad': 0})
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = subprocess.CompletedProcess([], 0, stdout='', stderr='')
            self.r.atender_buzon()   # ciclo 1: una de las dos
            self.r.atender_buzon()   # ciclo 2: la que quedaba pendiente
        for pid in (pid1, pid2):
            self.assertTrue(os.path.exists(os.path.join(self.r.rutas['respuestas'], pid + '.json')),
                             '%s nunca se respondió' % pid)


class TestAtenderBuzonWifiAgregarE2E(unittest.TestCase):
    """Revisión Opus (ronda 2): wifi_agregar de punta a punta a través de
    atender_buzon() (con `routerd.run` simulado, nunca nmcli de verdad) —
    la clave nunca debe aparecer en el oplog, en la respuesta ni en
    router.json, y el keyfile debe quedar en disco con permisos 0600."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-wifi-e2e-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.r = routerd.Router(_rutas_prueba(self.tmp))
        self.r.cfg = _cfg_base()
        self.r.fase = 'produccion'
        self.r.permitir_guardar = True
        os.makedirs(self.r.rutas['buzon'], exist_ok=True)

    def _escribir_peticion(self, accion, datos):
        pid = str(uuid.uuid4())
        pet = {'id': pid, 'usuario': 'admin', 'accion': accion, 'datos': datos}
        with open(os.path.join(self.r.rutas['buzon'], pid + '.json'), 'w') as f:
            json.dump(pet, f)
        return pid

    def test_wifi_agregar_e2e(self):
        clave = 'secreta12345'
        pid = self._escribir_peticion('wifi_agregar', {'ssid': 'MiRed', 'clave': clave, 'prioridad': 50})
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = subprocess.CompletedProcess([], 0, stdout='', stderr='')
            self.r.atender_buzon()

        # — la respuesta nunca lleva la clave —
        ruta_resp = os.path.join(self.r.rutas['respuestas'], pid + '.json')
        self.assertTrue(os.path.exists(ruta_resp))
        with open(ruta_resp) as f:
            texto_resp = f.read()
        self.assertNotIn(clave, texto_resp)
        resp = json.loads(texto_resp)
        self.assertTrue(resp['ok'], resp)

        # — el oplog nunca lleva la clave (va redactada) —
        with open(self.r.rutas['oplog']) as f:
            texto_oplog = f.read()
        self.assertNotIn(clave, texto_oplog)
        self.assertIn('"clave": "***"', texto_oplog)

        # — router.json nunca se toca (punto 11: wifi_agregar no guarda cfg) —
        self.assertFalse(os.path.exists(self.r.rutas['config']))

        # — el keyfile SÍ lleva la clave (es su único sitio legítimo), 0600 —
        nombre = routerd.nombre_perfil_wifi('MiRed')
        ruta_keyfile = os.path.join(self.r.rutas['nm_system_connections'], nombre + '.nmconnection')
        self.assertTrue(os.path.exists(ruta_keyfile))
        self.assertEqual(stat.S_IMODE(os.stat(ruta_keyfile).st_mode), 0o600)
        with open(ruta_keyfile) as f:
            contenido_keyfile = f.read()
        self.assertIn(clave, contenido_keyfile)

        # — la petición original (que SÍ traía la clave en claro) se borró —
        self.assertFalse(os.path.exists(os.path.join(self.r.rutas['buzon'], pid + '.json')))

    def test_wifi_agregar_nmcli_load_falla_borra_el_keyfile(self):
        def run_falso(args, **kw):
            if args[:3] == ['nmcli', 'connection', 'load']:
                return subprocess.CompletedProcess(args, 1, stdout='', stderr='rechazado')
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        self._escribir_peticion('wifi_agregar', {'ssid': 'MiRed', 'clave': 'secreta12345', 'prioridad': 50})
        with mock.patch('routerd.run', side_effect=run_falso):
            self.r.atender_buzon()
        nombre = routerd.nombre_perfil_wifi('MiRed')
        ruta_keyfile = os.path.join(self.r.rutas['nm_system_connections'], nombre + '.nmconnection')
        self.assertFalse(os.path.exists(ruta_keyfile), 'el keyfile rechazado por nmcli no se borró')


class TestWifiWanSinInterfaz(unittest.TestCase):
    """Configuración genérica por defecto: wifi_wan.interfaz VACÍA significa
    "WAN Wi-Fi desactivada", aunque wifi_wan.habilitada sea True: routerd no
    debe descubrir ninguna WAN Wi-Fi, ni usar nunca una interfaz '' (nmcli,
    keyfile, radio) — las acciones wifi_* del buzón se rechazan con un
    mensaje normal "ok=False"."""

    @staticmethod
    def _cfg_interfaz_vacia():
        cfg = copy.deepcopy(_cfg_base())
        cfg['wifi_wan'] = {'habilitada': True, 'interfaz': '', 'ssid_bloqueadas': []}
        return cfg

    def test_defecto_wifi_wan_desactivada(self):
        ww = routerd.CONFIG_DEFECTO['wifi_wan']
        self.assertFalse(ww['habilitada'])
        self.assertEqual(ww['interfaz'], '')
        self.assertEqual(ww['ssid_bloqueadas'], [])

    def test_descubrir_wans_no_incluye_wifi_con_interfaz_vacia(self):
        # habilitada True pero interfaz '': nada de Wi-Fi en la lista (y ni
        # siquiera se consulta /sys por esa interfaz, que no existe).
        wans = routerd.descubrir_wans(self._cfg_interfaz_vacia(), permitir_wifi=True)
        self.assertEqual([w for w in wans if w.get('es_wifi')], [])
        self.assertFalse(any(w['id'].startswith('wifi-') for w in wans))

    def test_accion_wifi_rechazada_sin_interfaz(self):
        r = _router_en_memoria(self._cfg_interfaz_vacia())
        r.fase = 'produccion'
        for accion, d in (('wifi_escanear', {}),
                          ('wifi_agregar', {'ssid': 'RedX', 'clave': 'password1', 'prioridad': 50})):
            with mock.patch('routerd.run') as run_m:
                ok, msg = r._ejecutar_accion_wifi(accion, d)
            self.assertFalse(ok)
            self.assertIn('interfaz', msg)
            run_m.assert_not_called()   # nunca nmcli (ni nada) con interfaz vacía

    def test_radio_wifi_no_se_toca_sin_interfaz(self):
        r = _router_en_memoria(self._cfg_interfaz_vacia())
        with mock.patch('routerd.run') as run_m:
            r._aplicar_radio_wifi()
        run_m.assert_not_called()
        self.assertIsNone(r._radio_wifi_aplicada)


if __name__ == '__main__':
    unittest.main()
