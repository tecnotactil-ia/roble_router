#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root, sin binario `adb`
real) de core/router_adb.py — el vigilante que mantiene activo el
tethering USB de los teléfonos Android por ADB. Todo lo que ejecutaría un
comando de verdad pasa por `router_adb.run`, que aquí se sustituye por un
`adb` de mentira (`FakeAdb`) vía `mock.patch`. El reloj (`time.time`) se
controla con `FakeReloj` para probar el cooldown/backoff sin dormir de
verdad.

Uso:  python3 -m unittest pruebas/test_router_adb.py -v
  o:  python3 pruebas/test_router_adb.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import router_adb  # noqa: E402


# ───────────────────────── adb y reloj de mentira para las pruebas ─────────────────────────

class FakeAdb:
    """Responde a los mismos argv que construye router_adb.run, sin tocar
    nunca un teléfono de verdad. `funciones` y `getprop` son diccionarios
    serial -> valor que el propio test rellena/actualiza entre ciclos para
    simular lo que "haría" el teléfono tras un setFunctions. Por defecto
    `sys.boot_completed` responde "1" (teléfono ya arrancado) salvo que el
    test lo fije explícitamente a otra cosa."""

    def __init__(self):
        self.devices_text = 'List of devices attached\n'
        self.funciones = {}             # serial -> [str, ...] o str cruda (para probar el saneado)
        self.getprop = {}               # serial -> {propiedad: valor}
        self.fallan_set_functions = set()     # seriales en los que setFunctions "falla" (se desconecta)
        self.fallan_get_functions = set()     # seriales en los que getFunctions falla (ALTA1)
        self.llamadas_set = []          # [(serial, funcion), ...]
        self.llamadas_get_functions = []      # [serial, ...]
        self.llamadas_getprop = []            # [(serial, propiedad), ...]

    def run(self, args, timeout=None):
        if args[:2] == [router_adb.ADB_BIN, 'devices']:
            return subprocess.CompletedProcess(args, 0, stdout=self.devices_text, stderr='')
        if len(args) >= 4 and args[0] == router_adb.ADB_BIN and args[1] == '-s' and args[3] == 'shell':
            serial = args[2]
            resto = args[4:]
            if resto[:3] == ['svc', 'usb', 'getFunctions']:
                self.llamadas_get_functions.append(serial)
                if serial in self.fallan_get_functions:
                    return subprocess.CompletedProcess(args, 1, stdout='', stderr='error: device offline')
                crudo = self.funciones.get(serial, [])
                texto = crudo if isinstance(crudo, str) else (','.join(crudo) or 'none')
                # Como el Android real: la respuesta sale por STDERR.
                return subprocess.CompletedProcess(args, 0, stdout='', stderr=texto)
            if resto[:3] == ['svc', 'usb', 'setFunctions']:
                funcion = resto[3]
                self.llamadas_set.append((serial, funcion))
                if serial in self.fallan_set_functions:
                    return subprocess.CompletedProcess(args, 1, stdout='', stderr='error: closed')
                return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
            if resto[:1] == ['getprop']:
                propiedad = resto[1]
                self.llamadas_getprop.append((serial, propiedad))
                valores = self.getprop.get(serial, {})
                if propiedad == 'sys.boot_completed' and propiedad not in valores:
                    valor = '1'   # por defecto el teléfono ya ha arrancado
                else:
                    valor = valores.get(propiedad, '')
                return subprocess.CompletedProcess(args, 0, stdout=valor, stderr='')
        return subprocess.CompletedProcess(args, 127, stdout='', stderr='comando no reconocido en FakeAdb: %r' % (args,))


class FakeReloj:
    """Dentro de un mismo ciclo, todas las llamadas a time.time() devuelven
    el MISMO valor (salvo que el propio test use una lista explícita de
    valores vía mock.patch(..., side_effect=[...])) — se avanza a mano con
    `avanzar()` entre ciclos para simular el paso del tiempo real."""

    def __init__(self, inicio=1_700_000_000.0):
        self.ahora = inicio

    def avanzar(self, segundos):
        self.ahora += segundos

    def time(self):
        return self.ahora


def _rutas_prueba(tmp):
    return {
        'config': os.path.join(tmp, 'router.json'),
        'estado': os.path.join(tmp, 'adb.json'),
        'oplog': os.path.join(tmp, 'operaciones.log'),
    }


def _leer_oplog(ruta):
    if not os.path.exists(ruta):
        return []
    with open(ruta) as f:
        return [json.loads(l) for l in f if l.strip()]


def _crear_interfaz_fake(raiz, ifname, serial, con_idvendor=True):
    """Construye un /sys/class/net/<ifname>/device de mentira de UN SOLO
    NIVEL: 'idVendor'/'serial' viven directamente en 'device/' (caso
    simple — una interfaz USB "plana", sin padre USB aparte). No se crea
    ningún symlink 'driver': desde la ronda 3 de la revisión Opus,
    _interfaz_tether_para_serial ya NO filtra por driver."""
    dev_dir = os.path.join(raiz, ifname, 'device')
    os.makedirs(dev_dir, exist_ok=True)
    if con_idvendor:
        with open(os.path.join(dev_dir, 'idVendor'), 'w') as f:
            f.write('1234\n')
    if serial is not None:
        with open(os.path.join(dev_dir, 'serial'), 'w') as f:
            f.write(serial + '\n')


def _crear_interfaz_fake_dos_niveles(raiz, ifname, serial):
    """Jerarquía /sys MÁS realista (la que de verdad monta el kernel para
    un adaptador USB): /sys/class/net/<ifname>/device es un symlink al nodo
    de INTERFAZ usb (p. ej. ".../1-2/1-2:1.0", sin idVendor/serial propios)
    cuyo PADRE real (".../1-2", el nodo de DISPOSITIVO usb) es el que de
    verdad tiene idVendor/serial. _interfaz_tether_para_serial debe subir
    un nivel desde 'device' para encontrarlo — exactamente lo que hace
    routerd._usb_info con interfaces USB reales."""
    dispositivo_usb = os.path.join(raiz, '_usb', '1-2')
    interfaz_usb = os.path.join(dispositivo_usb, '1-2:1.0')
    os.makedirs(interfaz_usb, exist_ok=True)
    with open(os.path.join(dispositivo_usb, 'idVendor'), 'w') as f:
        f.write('1234\n')
    with open(os.path.join(dispositivo_usb, 'serial'), 'w') as f:
        f.write(serial + '\n')
    base = os.path.join(raiz, ifname)
    os.makedirs(base, exist_ok=True)
    os.symlink(interfaz_usb, os.path.join(base, 'device'))


# ───────────────────────────── parseo de `adb devices` ─────────────────────────────

class TestParsearAdbDevices(unittest.TestCase):
    def test_un_dispositivo_normal(self):
        texto = 'List of devices attached\nR58M123ABC\tdevice\n\n'
        self.assertEqual(router_adb.parsear_adb_devices(texto), [{'serial': 'R58M123ABC', 'estado': 'device'}])

    def test_varios_estados(self):
        texto = (
            'List of devices attached\n'
            'AAA111\tdevice\n'
            'BBB222\tunauthorized\n'
            'CCC333\toffline\n'
            'DDD444\tno permissions (user in plugdev group; are your udev rules wrong?)\n'
        )
        out = {d['serial']: d['estado'] for d in router_adb.parsear_adb_devices(texto)}
        self.assertEqual(out, {'AAA111': 'device', 'BBB222': 'unauthorized', 'CCC333': 'offline',
                                'DDD444': 'no permissions'})

    def test_estado_no_reconocido_cae_a_desconocido(self):
        texto = 'AAA111\tsideways\n'
        self.assertEqual(router_adb.parsear_adb_devices(texto)[0]['estado'], 'desconocido')

    def test_lineas_basura_y_vacias_ignoradas(self):
        texto = (
            '\n'
            'List of devices attached\n'
            '* daemon not running; starting now at tcp:5037\n'
            '* daemon started successfully\n'
            '   \n'
            'AAA111\tdevice\n'
        )
        self.assertEqual(router_adb.parsear_adb_devices(texto), [{'serial': 'AAA111', 'estado': 'device'}])

    def test_linea_de_un_solo_campo_ignorada(self):
        self.assertEqual(router_adb.parsear_adb_devices('serial_suelto_sin_estado\n'), [])

    def test_serial_malicioso_con_parentesis_y_signos_rechazado(self):
        self.assertEqual(router_adb.parsear_adb_devices('$(touch${IFS}/tmp/pwned)\tdevice\n'), [])

    def test_serial_malicioso_con_punto_y_coma_rechazado(self):
        self.assertEqual(router_adb.parsear_adb_devices('AAA;rm-rf\tdevice\n'), [])

    def test_serial_con_barra_rechazado(self):
        self.assertEqual(router_adb.parsear_adb_devices('../../etc/passwd\tdevice\n'), [])

    def test_serial_valido_con_guion_bajo_y_punto_aceptado(self):
        self.assertEqual(router_adb.parsear_adb_devices('ABC_123.def-456\tdevice\n'),
                          [{'serial': 'ABC_123.def-456', 'estado': 'device'}])

    def test_texto_vacio(self):
        self.assertEqual(router_adb.parsear_adb_devices(''), [])
        self.assertEqual(router_adb.parsear_adb_devices(None), [])


# ───────────────────────────── saneado de salida (MEDIA7) ─────────────────────────────

class TestSanearTexto(unittest.TestCase):
    def test_quita_caracteres_de_control(self):
        self.assertEqual(router_adb._sanear_texto('SM\x00A515F\x07'), 'SMA515F')

    def test_recorta_a_64(self):
        largo = 'X' * 100
        self.assertEqual(len(router_adb._sanear_texto(largo)), 64)

    def test_none_sigue_siendo_none(self):
        self.assertIsNone(router_adb._sanear_texto(None))

    def test_vacio_tras_limpiar_es_none(self):
        self.assertIsNone(router_adb._sanear_texto('\x00\x01'))

    def test_texto_normal_intacto(self):
        self.assertEqual(router_adb._sanear_texto('Pixel 8a'), 'Pixel 8a')


class TestFuncionesSaneadas(unittest.TestCase):
    def test_filtra_tokens_invalidos(self):
        fake = FakeAdb()
        fake.funciones['SER1'] = 'ncm,123abc,rn-dis,' + 'x' * 20
        with mock.patch('router_adb.run', side_effect=fake.run):
            funciones, err = router_adb.adb_get_functions('SER1')
        self.assertIsNone(err)
        self.assertEqual(funciones, ['ncm'])

    def test_tokens_validos_se_conservan_todos(self):
        fake = FakeAdb()
        fake.funciones['SER1'] = 'adb,rndis,mtp'
        with mock.patch('router_adb.run', side_effect=fake.run):
            funciones, _ = router_adb.adb_get_functions('SER1')
        self.assertEqual(funciones, ['adb', 'mtp', 'rndis'])


# ───────────────────────────── interfaz de kernel (MEDIA8) ─────────────────────────────

class TestInterfazTetherParaSerial(unittest.TestCase):
    def test_encuentra_interfaz_con_serial_coincidente(self):
        with tempfile.TemporaryDirectory() as tmp:
            _crear_interfaz_fake(tmp, 'usb0', 'SER1')
            self.assertEqual(router_adb._interfaz_tether_para_serial('SER1', raiz=tmp), 'usb0')

    def test_cualquier_nombre_de_interfaz_vale_sin_filtrar_por_driver(self):
        # Revisión Opus (ronda 3): ya no se filtra por driver — ni siquiera
        # hay un symlink 'device/driver' en este fake, y aun así se
        # encuentra la interfaz por el serie.
        with tempfile.TemporaryDirectory() as tmp:
            _crear_interfaz_fake(tmp, 'eth_rara_de_mentira', 'SER1')
            self.assertEqual(router_adb._interfaz_tether_para_serial('SER1', raiz=tmp), 'eth_rara_de_mentira')

    def test_serial_distinto_no_coincide(self):
        with tempfile.TemporaryDirectory() as tmp:
            _crear_interfaz_fake(tmp, 'usb0', 'OTRO')
            self.assertIsNone(router_adb._interfaz_tether_para_serial('SER1', raiz=tmp))

    def test_ninguna_interfaz_presente(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(router_adb._interfaz_tether_para_serial('SER1', raiz=tmp))

    def test_jerarquia_usb_real_de_dos_niveles(self):
        # BAJA (revisión Opus, ronda 3): 'device' es un symlink a la
        # interfaz usb (sin idVendor propio); hay que subir un nivel más
        # hasta el nodo del DISPOSITIVO usb para encontrar idVendor/serial
        # — igual que con un adaptador USB de verdad, a diferencia del fake
        # de un solo nivel de los demás tests de esta clase.
        with tempfile.TemporaryDirectory() as tmp:
            _crear_interfaz_fake_dos_niveles(tmp, 'enx0a1b2c3d4e5f', 'SER1')
            self.assertEqual(router_adb._interfaz_tether_para_serial('SER1', raiz=tmp), 'enx0a1b2c3d4e5f')

    def test_jerarquia_de_dos_niveles_con_serial_distinto_no_coincide(self):
        with tempfile.TemporaryDirectory() as tmp:
            _crear_interfaz_fake_dos_niveles(tmp, 'enx0a1b2c3d4e5f', 'OTRO')
            self.assertIsNone(router_adb._interfaz_tether_para_serial('SER1', raiz=tmp))


# ───────────────────────────── decidir_accion / confirmar_intento (ALTA2) ─────────────────────────────

class TestElegirCandidata(unittest.TestCase):
    def test_primera_vez_sin_memoria_prueba_rndis(self):
        self.assertEqual(router_adb.elegir_candidata({}), 'rndis')

    def test_primera_vez_con_memoria_prueba_la_que_funciono(self):
        self.assertEqual(router_adb.elegir_candidata({'funcion_funciona': 'ncm'}), 'ncm')

    def test_alterna_tras_un_fallo_de_rndis(self):
        self.assertEqual(router_adb.elegir_candidata({'funcion_probando': 'rndis'}), 'ncm')

    def test_alterna_tras_un_fallo_de_ncm(self):
        self.assertEqual(router_adb.elegir_candidata({'funcion_probando': 'ncm'}), 'rndis')


class TestDecidirAccion(unittest.TestCase):
    def test_ya_comparte_no_manda_nada(self):
        est = {}
        compartiendo, candidata, _ = router_adb.decidir_accion(est, ['adb', 'rndis'], 1000.0)
        self.assertTrue(compartiendo)
        self.assertIsNone(candidata)
        self.assertEqual(est['funcion_funciona'], 'rndis')
        self.assertEqual(est['lecturas_no_comparte'], 0)

    def test_no_actua_hasta_la_tercera_lectura_valida(self):
        est = {}
        for i in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE - 1):
            _, candidata, descripcion = router_adb.decidir_accion(est, [], 1000.0 + i)
            self.assertIsNone(candidata, 'no debe actuar en la lectura %d' % (i + 1))
            self.assertIn('confirmando', descripcion)
        _, candidata, _ = router_adb.decidir_accion(est, [], 2000.0)
        self.assertEqual(candidata, 'rndis')   # a la N-ésima lectura, ya sí

    def test_confirmar_intento_fija_cooldown_60s_el_primero(self):
        est = {}
        candidata = None
        for i in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            _, candidata, _ = router_adb.decidir_accion(est, [], 1000.0 + i)
        router_adb.confirmar_intento(est, candidata, 1010.0)
        self.assertEqual(est['cooldown_actual_s'], 60)
        self.assertEqual(est['nivel_backoff'], 1)
        self.assertEqual(est['lecturas_no_comparte'], 0)
        self.assertEqual(est['funcion_probando'], candidata)

    def test_durante_el_cooldown_no_se_reintenta_aunque_haya_mas_lecturas(self):
        est = {}
        candidata = None
        for i in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            _, candidata, _ = router_adb.decidir_accion(est, [], 1000.0 + i)
        router_adb.confirmar_intento(est, candidata, 1010.0)
        # varias lecturas más "no comparte", todas dentro de los 60s de cooldown
        for t in (1020.0, 1030.0, 1040.0, 1050.0):
            _, candidata2, descripcion = router_adb.decidir_accion(est, [], t)
            self.assertIsNone(candidata2)
            self.assertIn('cooldown', descripcion)

    def test_tras_el_cooldown_se_reintenta_y_escala_el_backoff(self):
        est = {}
        for i in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            router_adb.decidir_accion(est, [], 1000.0 + i)
        router_adb.confirmar_intento(est, 'rndis', 1010.0)   # cooldown de 60s desde 1010
        # pasa el cooldown (>=1070) y se acumulan 3 lecturas más
        _, c1, _ = router_adb.decidir_accion(est, [], 1071.0)
        self.assertIsNone(c1)   # 1ª lectura tras el cooldown: todavía no van 3
        _, c2, _ = router_adb.decidir_accion(est, [], 1072.0)
        self.assertIsNone(c2)
        _, c3, _ = router_adb.decidir_accion(est, [], 1073.0)
        self.assertEqual(c3, 'ncm')   # 3ª lectura: ya toca, y alterna (rndis->ncm)
        router_adb.confirmar_intento(est, c3, 1073.0)
        self.assertEqual(est['cooldown_actual_s'], 120)   # el backoff se dobló
        self.assertEqual(est['nivel_backoff'], 2)

    def test_backoff_no_pasa_de_30_minutos(self):
        est = {'nivel_backoff': 50}   # ya muy escalado
        router_adb.confirmar_intento(est, 'rndis', 1000.0)
        self.assertEqual(est['cooldown_actual_s'], router_adb.NIVELES_BACKOFF_S[-1])
        self.assertEqual(est['cooldown_actual_s'], 1800)
        self.assertEqual(est['nivel_backoff'], len(router_adb.NIVELES_BACKOFF_S) - 1)

    def test_volver_a_compartir_resetea_backoff(self):
        est = {}
        for i in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            router_adb.decidir_accion(est, [], 1000.0 + i)
        router_adb.confirmar_intento(est, 'rndis', 1010.0)
        self.assertGreater(est['nivel_backoff'], 0)
        compartiendo, candidata, _ = router_adb.decidir_accion(est, ['rndis'], 1011.0)
        self.assertTrue(compartiendo)
        self.assertIsNone(candidata)
        self.assertEqual(est['nivel_backoff'], 0)
        self.assertEqual(est['lecturas_no_comparte'], 0)

    def test_volver_a_compartir_olvida_la_funcion_que_se_estaba_probando(self):
        # BAJA-MEDIA (revisión Opus, ronda 3): tras un episodio de intentos
        # (funcion_probando='ncm', por ejemplo), si vuelve a compartir de
        # verdad ese episodio se considera cerrado — el próximo debe poder
        # volver a empezar por "rndis" (o por lo que se recuerde que
        # funcionó), no seguir alternando desde donde se quedó.
        est = {'funcion_probando': 'ncm', 'funcion_funciona': None}
        compartiendo, candidata, _ = router_adb.decidir_accion(est, ['rndis'], 2000.0)
        self.assertTrue(compartiendo)
        self.assertIsNone(candidata)
        self.assertIsNone(est['funcion_probando'])
        self.assertEqual(est['funcion_funciona'], 'rndis')
        # un episodio de fallos posterior debe empezar limpio (probar
        # "rndis" primero, no "seguir alternando" desde 'ncm')
        self.assertEqual(router_adb.elegir_candidata(est), 'rndis')


class TestLeerConfigAdb(unittest.TestCase):
    def test_fichero_ausente_cae_a_defecto(self):
        cfg = router_adb.leer_config_adb('/no/existe/de/verdad/router.json')
        self.assertEqual(cfg, {'habilitada': True, 'intervalo_s': 10})

    def test_json_roto_cae_a_defecto(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            f.write('{ esto no es json')
            ruta = f.name
        try:
            self.assertEqual(router_adb.leer_config_adb(ruta), {'habilitada': True, 'intervalo_s': 10})
        finally:
            os.unlink(ruta)

    def test_sin_seccion_adb_tether_cae_a_defecto(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump({'modo': 'balanceo'}, f)
            ruta = f.name
        try:
            self.assertEqual(router_adb.leer_config_adb(ruta), {'habilitada': True, 'intervalo_s': 10})
        finally:
            os.unlink(ruta)

    def test_seccion_valida_se_respeta(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump({'adb_tether': {'habilitada': False, 'intervalo_s': 20}}, f)
            ruta = f.name
        try:
            self.assertEqual(router_adb.leer_config_adb(ruta), {'habilitada': False, 'intervalo_s': 20})
        finally:
            os.unlink(ruta)

    def test_intervalo_acotado_por_abajo(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump({'adb_tether': {'intervalo_s': 1}}, f)
            ruta = f.name
        try:
            self.assertEqual(router_adb.leer_config_adb(ruta)['intervalo_s'], router_adb.INTERVALO_MIN_S)
        finally:
            os.unlink(ruta)

    def test_intervalo_acotado_por_arriba(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump({'adb_tether': {'intervalo_s': 999}}, f)
            ruta = f.name
        try:
            self.assertEqual(router_adb.leer_config_adb(ruta)['intervalo_s'], router_adb.INTERVALO_MAX_S)
        finally:
            os.unlink(ruta)

    def test_intervalo_negativo_cae_a_defecto_y_sigue_acotado(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump({'adb_tether': {'intervalo_s': -5}}, f)
            ruta = f.name
        try:
            self.assertEqual(router_adb.leer_config_adb(ruta)['intervalo_s'], 10)
        finally:
            os.unlink(ruta)


# ───────────────────────────── oplog y estado atómico ─────────────────────────────

class TestOplogYEstado(unittest.TestCase):
    def test_oplog_una_linea_por_llamada_formato_correcto(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = os.path.join(tmp, 'oplog.log')
            router_adb.escribir_oplog(ruta, 'sistema', 'adb_tether', {'serial': 'X'}, True, 'ok de prueba')
            router_adb.escribir_oplog(ruta, 'sistema', 'adb_tether', {'serial': 'X'}, False, 'fallo de prueba')
            lineas = _leer_oplog(ruta)
            self.assertEqual(len(lineas), 2)
            for l in lineas:
                self.assertEqual(set(l), {'fecha', 'usuario', 'accion', 'datos', 'ok', 'mensaje'})
                self.assertEqual(l['accion'], 'adb_tether')
                self.assertEqual(l['usuario'], 'sistema')

    def test_oplog_datos_demasiado_grandes_se_recortan(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = os.path.join(tmp, 'oplog.log')
            datos_enormes = {'basura': 'x' * 3000}
            router_adb.escribir_oplog(ruta, 'sistema', 'adb_tether', datos_enormes, True, 'ok')
            linea = _leer_oplog(ruta)[0]
            self.assertEqual(linea['datos'], {'_recortado': True})

    def test_oplog_se_niega_a_seguir_un_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            objetivo = os.path.join(tmp, 'de_verdad.log')
            open(objetivo, 'w').close()
            enlace = os.path.join(tmp, 'oplog.log')
            os.symlink(objetivo, enlace)
            with self.assertRaises(OSError):
                router_adb.escribir_oplog(enlace, 'sistema', 'adb_tether', {}, True, 'no debería escribirse')

    def test_estado_se_escribe_atomico_y_0644(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = os.path.join(tmp, 'sub', 'adb.json')
            router_adb.escribir_atomico(ruta, json.dumps([{'serial': 'X'}]) + '\n')
            with open(ruta) as f:
                datos = json.load(f)
            self.assertEqual(datos, [{'serial': 'X'}])
            modo = stat.S_IMODE(os.stat(ruta).st_mode)
            self.assertEqual(modo, 0o644)


# ───────────────────────────── AdbTether: ciclo completo ─────────────────────────────

class TestAdbTetherCiclo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pruebas-router-adb-')
        self.rutas = _rutas_prueba(self.tmp)
        self.fake = FakeAdb()
        self.reloj = FakeReloj()
        self.parche_run = mock.patch('router_adb.run', side_effect=self.fake.run)
        self.parche_run.start()
        self.addCleanup(self.parche_run.stop)
        # Sin interfaz de kernel real en las pruebas: por defecto no existe
        # ninguna (cada test la activa explícitamente si la necesita).
        self.parche_interfaz = mock.patch('router_adb._interfaz_tether_para_serial', return_value=None)
        self.parche_interfaz.start()
        self.addCleanup(self.parche_interfaz.stop)
        self.parche_reloj = mock.patch('router_adb.time.time', side_effect=self.reloj.time)
        self.parche_reloj.start()
        self.addCleanup(self.parche_reloj.stop)

    def _estado_publicado(self):
        with open(self.rutas['estado']) as f:
            return json.load(f)

    def test_no_actua_en_los_dos_primeros_ciclos_sin_compartir(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()
        t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [])   # ALTA2: hacen falta 3 lecturas válidas, no 2

    def test_al_tercer_ciclo_manda_setfunctions_rndis(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        self.fake.getprop['SER1'] = {'ro.product.model': 'SM-A515F', 'ro.build.version.release': '14'}
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()
        t.ciclo()
        t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [('SER1', 'rndis')])
        publicado = self._estado_publicado()[0]
        self.assertEqual(publicado['modelo'], 'SM-A515F')
        self.assertFalse(publicado['compartiendo'])
        self.assertEqual(_leer_oplog(self.rutas['oplog']), [])   # todavía no comparte: sin evento

    def test_getfunctions_fallido_no_hace_nada_alta1(self):
        # Primero llega a compartir de verdad (con interfaz de kernel
        # confirmada), luego la lectura de getFunctions empieza a fallar:
        # no debe tocarse nada (ni orden, ni oplog, ni "compartiendo").
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        self.assertTrue(self._estado_publicado()[0]['compartiendo'])
        eventos_antes = _leer_oplog(self.rutas['oplog'])
        self.assertEqual(len(eventos_antes), 1)

        self.fake.fallan_get_functions.add('SER1')
        llamadas_set_antes = list(self.fake.llamadas_set)
        for _ in range(5):
            self.reloj.avanzar(10)
            t.ciclo()
        publicado = self._estado_publicado()[0]
        self.assertTrue(publicado['compartiendo'])            # se mantiene lo último conocido
        self.assertIsNotNone(publicado['ultimo_error'])        # pero se anota el error
        self.assertEqual(self.fake.llamadas_set, llamadas_set_antes)   # nunca se manda ninguna orden
        self.assertEqual(_leer_oplog(self.rutas['oplog']), eventos_antes)   # ni un evento más

    def test_boot_no_completado_bloquea_la_accion_sin_consumir_backoff(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        self.fake.getprop['SER1'] = {'sys.boot_completed': '0'}
        t = router_adb.AdbTether(self.rutas)
        for _ in range(5):
            t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [])   # nunca se manda setFunctions sin boot_completed
        # al terminar de arrancar, el siguiente ciclo ya sí actúa (no quedó "quemado" el intento)
        self.fake.getprop['SER1']['sys.boot_completed'] = '1'
        t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [('SER1', 'rndis')])

    def test_interfaz_ausente_nunca_manda_setfunctions(self):
        # MEDIA (revisión Opus, ronda 3): adb dice "rndis" pero la interfaz
        # de kernel nunca aparece (mock de _interfaz_tether_para_serial ->
        # None por defecto en setUp) -> NUNCA se manda setFunctions (sería
        # inútil, el teléfono ya cree que comparte); sólo se anota y se
        # avisa una vez, aunque se repita durante muchos ciclos.
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        t = router_adb.AdbTether(self.rutas)
        for _ in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE + 5):
            t.ciclo()
        publicado = self._estado_publicado()[0]
        self.assertFalse(publicado['compartiendo'])
        self.assertIsNone(publicado['interfaz'])
        self.assertIn('no aparece interfaz', publicado['ultima_accion'])
        self.assertEqual(self.fake.llamadas_set, [])   # nunca se intenta nada
        eventos = _leer_oplog(self.rutas['oplog'])
        self.assertEqual(len(eventos), 1)              # avisado una sola vez
        self.assertFalse(eventos[0]['ok'])
        self.assertIn('no aparece ninguna interfaz', eventos[0]['mensaje'])

    def test_interfaz_presente_confirma_que_comparte(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        publicado = self._estado_publicado()[0]
        self.assertTrue(publicado['compartiendo'])
        self.assertEqual(publicado['interfaz'], 'usb0')

    def test_interfaz_aparece_despues_pasa_de_aviso_a_compartir(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()   # sin interfaz todavía: aviso, nunca manda nada
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t.ciclo()   # ahora sí aparece
        publicado = self._estado_publicado()[0]
        self.assertTrue(publicado['compartiendo'])
        eventos = _leer_oplog(self.rutas['oplog'])
        self.assertEqual(len(eventos), 2)
        self.assertFalse(eventos[0]['ok'])
        self.assertIn('no aparece ninguna interfaz', eventos[0]['mensaje'])
        self.assertTrue(eventos[1]['ok'])
        self.assertIn('Activado compartir', eventos[1]['mensaje'])
        self.assertEqual(self.fake.llamadas_set, [])   # en ningún momento se mandó una orden

    def test_offline_conserva_compartiendo_sin_oplog(self):
        # BAJA (revisión Opus, ronda 3): perder adb no significa que el
        # teléfono haya dejado de compartir de verdad.
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        eventos_antes = _leer_oplog(self.rutas['oplog'])
        self.fake.devices_text = 'List of devices attached\nSER1\toffline\n'
        t.ciclo()
        publicado = self._estado_publicado()[0]
        self.assertEqual(publicado['estado_adb'], 'offline')
        self.assertTrue(publicado['compartiendo'])
        self.assertEqual(_leer_oplog(self.rutas['oplog']), eventos_antes)

    def test_estado_desconocido_conserva_compartiendo_sin_oplog(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        eventos_antes = _leer_oplog(self.rutas['oplog'])
        self.fake.devices_text = 'List of devices attached\nSER1\trarorarorarin\n'
        t.ciclo()
        publicado = self._estado_publicado()[0]
        self.assertEqual(publicado['estado_adb'], 'desconocido')
        self.assertTrue(publicado['compartiendo'])
        self.assertEqual(_leer_oplog(self.rutas['oplog']), eventos_antes)

    def test_unauthorized_si_fuerza_compartiendo_a_false(self):
        # A diferencia de offline/desconocido: sin autorización no hay
        # `shell`, así que aquí SÍ se sabe con certeza que no se puede
        # confirmar ningún tethering.
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        self.fake.devices_text = 'List of devices attached\nSER1\tunauthorized\n'
        t.ciclo()
        publicado = self._estado_publicado()[0]
        self.assertFalse(publicado['compartiendo'])

    def test_pasar_a_compartir_escribe_oplog_una_vez(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            for _ in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
                t.ciclo()
            self.fake.funciones['SER1'] = ['rndis']   # "el teléfono ya aplicó el cambio"
            t.ciclo()
            t.ciclo()
        eventos = _leer_oplog(self.rutas['oplog'])
        self.assertEqual(len(eventos), 1)
        self.assertTrue(eventos[0]['ok'])
        self.assertIn('Activado compartir', eventos[0]['mensaje'])
        self.assertIn('SER1', eventos[0]['mensaje'])

    def test_dejar_de_compartir_escribe_oplog_de_regresion(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        self.fake.funciones['SER1'] = []
        for _ in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            t.ciclo()
        eventos = _leer_oplog(self.rutas['oplog'])
        self.assertEqual(len(eventos), 2)
        self.assertTrue(eventos[0]['ok'])
        self.assertFalse(eventos[1]['ok'])
        self.assertIn('dejado de compartir', eventos[1]['mensaje'])

    def test_telefono_no_autorizado_escribe_mensaje_claro_una_vez(self):
        self.fake.devices_text = 'List of devices attached\nSER2\tunauthorized\n'
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()
        t.ciclo()   # sigue sin autorizar: no debe repetirse
        eventos = _leer_oplog(self.rutas['oplog'])
        self.assertEqual(len(eventos), 1)
        self.assertFalse(eventos[0]['ok'])
        self.assertIn('Permitir depuración USB', eventos[0]['mensaje'])
        publicado = self._estado_publicado()[0]
        self.assertEqual(publicado['estado_adb'], 'unauthorized')
        self.assertFalse(publicado['compartiendo'])

    def test_estados_offline_y_sin_permisos_no_tocan_el_telefono(self):
        self.fake.devices_text = (
            'List of devices attached\n'
            'SER3\toffline\n'
            'SER4\tno permissions (udev)\n'
        )
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [])
        self.assertEqual(self.fake.llamadas_get_functions, [])
        publicado = {e['serial']: e for e in self._estado_publicado()}
        self.assertEqual(publicado['SER3']['estado_adb'], 'offline')
        self.assertEqual(publicado['SER4']['estado_adb'], 'no permissions')

    def test_setfunctions_que_falla_por_caida_momentanea_no_cuenta_como_error_de_oplog(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        self.fake.fallan_set_functions.add('SER1')
        t = router_adb.AdbTether(self.rutas)
        for _ in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            t.ciclo()
        self.assertEqual(_leer_oplog(self.rutas['oplog']), [])

    def test_desaparicion_y_reaparicion_conserva_backoff_alta3(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        t = router_adb.AdbTether(self.rutas)
        for _ in range(router_adb.UMBRAL_LECTURAS_NO_COMPARTE):
            t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [('SER1', 'rndis')])
        est_tras_intento = dict(t._estado['SER1'])
        self.assertEqual(est_tras_intento['nivel_backoff'], 1)
        self.assertEqual(est_tras_intento['cooldown_actual_s'], 60)

        # el teléfono se desenchufa un instante: el backoff no debe perderse
        self.fake.devices_text = 'List of devices attached\n'
        self.reloj.avanzar(5)
        t.ciclo()
        self.assertIn('SER1', t._estado)   # ALTA3: no se olvida al primer ciclo ausente
        self.assertEqual(t._estado['SER1']['ultimo_intento_ts'], est_tras_intento['ultimo_intento_ts'])
        self.assertEqual(self._estado_publicado(), [])   # pero no se publica mientras está ausente

        # reaparece, todavía dentro del cooldown de 60s: no debe reintentar
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.reloj.avanzar(10)   # total 15s desde el intento: < 60s
        t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [('SER1', 'rndis')])

        # pasa el cooldown y se acumulan 3 lecturas válidas más: debe alternar a ncm
        for _ in range(3):
            self.reloj.avanzar(25)
            t.ciclo()
        self.assertEqual(self.fake.llamadas_set, [('SER1', 'rndis'), ('SER1', 'ncm')])

    def test_ttl_olvida_tras_media_hora_ausente(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = []
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()
        self.assertIn('SER1', t._estado)
        self.fake.devices_text = 'List of devices attached\n'
        self.reloj.avanzar(router_adb.TTL_AUSENCIA_S + 1)
        t.ciclo()
        self.assertNotIn('SER1', t._estado)

    def test_modelo_y_android_se_leen_una_sola_vez(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        self.fake.getprop['SER1'] = {'ro.product.model': 'Pixel 8a', 'ro.build.version.release': '16'}
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'):
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
            t.ciclo()
            t.ciclo()
        llamadas_modelo = [p for (s, p) in self.fake.llamadas_getprop if p == 'ro.product.model']
        self.assertEqual(len(llamadas_modelo), 1)   # cacheado: sólo se pidió una vez en 3 ciclos

    def test_watchdog_se_notifica_tras_cada_telefono(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\nSER2\tdevice\nSER3\tdevice\n'
        for serial in ('SER1', 'SER2', 'SER3'):
            self.fake.funciones[serial] = ['rndis']
        with mock.patch('router_adb._interfaz_tether_para_serial', return_value='usb0'), \
                mock.patch('router_adb._sd_notify') as m:
            t = router_adb.AdbTether(self.rutas)
            t.ciclo()
        self.assertEqual(m.call_count, 3)
        m.assert_has_calls([mock.call('WATCHDOG=1')] * 3)

    def test_duracion_maxima_de_ciclo_deja_telefonos_pendientes(self):
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\nSER2\tdevice\n'
        self.fake.funciones['SER1'] = ['rndis']
        self.fake.funciones['SER2'] = ['rndis']
        t = router_adb.AdbTether(self.rutas)
        # time.time(): 1 llamada para "ahora_ts" + 1 por teléfono (la
        # comprobación de presupuesto). Con 2 teléfonos: 3 llamadas. La
        # 2ª (tras procesar SER1) ya muestra el presupuesto agotado.
        inicio = self.reloj.ahora
        valores = [inicio, inicio, inicio + router_adb.DURACION_MAX_CICLO_S + 1]
        self.parche_reloj.stop()
        with mock.patch('router_adb.time.time', side_effect=valores):
            t.ciclo()
        self.parche_reloj.start()
        publicado = {e['serial']: e for e in self._estado_publicado()}
        self.assertNotIn('pendiente', publicado['SER1']['ultima_accion'])
        self.assertIn('pendiente', publicado['SER2']['ultima_accion'])
        self.assertNotIn('SER2', self.fake.llamadas_get_functions)   # nunca se llegó a tocar SER2

    def test_serial_malicioso_no_llega_a_ningun_comando_adb(self):
        self.fake.devices_text = 'List of devices attached\n$(id)\tdevice\n'
        t = router_adb.AdbTether(self.rutas)
        t.ciclo()
        self.assertEqual(self.fake.llamadas_get_functions, [])
        self.assertEqual(self._estado_publicado(), [])

    def test_adb_tether_deshabilitada_publica_lista_vacia_y_no_llama_a_adb(self):
        with open(self.rutas['config'], 'w') as f:
            json.dump({'adb_tether': {'habilitada': False}}, f)
        self.fake.devices_text = 'List of devices attached\nSER1\tdevice\n'
        t = router_adb.AdbTether(self.rutas)
        with mock.patch('router_adb.adb_devices') as m:
            t.ciclo()
            m.assert_not_called()
        self.assertEqual(self._estado_publicado(), [])

    def test_fallo_de_adb_devices_no_rompe_el_ciclo(self):
        self.parche_run.stop()
        try:
            with mock.patch('router_adb.run', return_value=subprocess.CompletedProcess(
                    [router_adb.ADB_BIN, 'devices'], 127, stdout='', stderr='adb: comando no encontrado')):
                t = router_adb.AdbTether(self.rutas)
                t.ciclo()   # no debe lanzar
        finally:
            self.parche_run.start()


if __name__ == '__main__':
    unittest.main()


class TestGetFunctionsSalidaReal(unittest.TestCase):
    """svc usb getFunctions responde por stderr; una salida vacía o sin
    funciones reconocibles es lectura NO válida, nunca "no comparte"."""

    def _con(self, stdout, stderr, rc=0):
        cp = subprocess.CompletedProcess([], rc, stdout=stdout, stderr=stderr)
        with mock.patch('router_adb.run', return_value=cp):
            return router_adb.adb_get_functions('SER1')

    def test_respuesta_por_stderr_con_lineas_del_demonio(self):
        f, err = self._con('', '* daemon not running; starting now at tcp:5037\n* daemon started successfully\nrndis\n')
        self.assertEqual((f, err), (['rndis'], None))

    def test_salida_vacia_es_lectura_no_valida(self):
        f, err = self._con('', '')
        self.assertIsNone(f)
        self.assertIsNotNone(err)

    def test_none_es_no_comparte_valido(self):
        self.assertEqual(self._con('', 'none'), (['none'], None))

