#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root, sin nft/ip/systemctl
de verdad — `routerd.run` siempre mockeado) de la parte del bloqueador DNS
que vive en core/routerd.py: el servers-file SIEMPRE existe (M2), el
fail-open tras varios arranques fallidos de dnsmasq (M6), el drop-in del
timer con actualizar_h (BAJA7), el límite de 2 bloqueo_probar por ciclo
(BAJA8), el vaciado de conntrack al activar forzar_dns/bloquear_doh
(BAJA10/11), 'activating'/'reloading' como vivo (BAJA12), y que
bloqueo_config sólo relanza router-bloqueo.service cuando de verdad cambia
algo relevante (BAJA13).

Uso:  python3 -m unittest pruebas/test_routerd_bloqueo.py -v
"""
import copy
import json
import os
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import routerd  # noqa: E402


def _rutas_prueba(tmp):
    """Todas las rutas de Router bajo un directorio temporal propio —
    nunca caen al valor REAL de routerd.RUTAS por una clave que falte."""
    rutas = {k: os.path.join(tmp, k) for k in routerd.RUTAS}
    rutas['grupo_panel'] = 'routerpanel'   # no es una ruta: un nombre de grupo
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


class TestServersFileSiempreExiste(unittest.TestCase):
    """M2: routerd garantiza que el servers-file existe SIEMPRE, vacío si
    hace falta, antes de que dnsmasq_conf.py lo referencie."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-bloqueo-')
        self.r = _router(self.tmp)

    def test_crea_vacio_si_falta(self):
        ruta = self.r.rutas['dnsmasq_bloqueo']
        self.assertFalse(os.path.exists(ruta))
        self.r._asegurar_servers_file_bloqueo()
        self.assertTrue(os.path.exists(ruta))

    def test_no_toca_si_ya_existe(self):
        ruta = self.r.rutas['dnsmasq_bloqueo']
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, 'w') as f:
            f.write('server=/ya-generado.example.com/\n')
        self.r._asegurar_servers_file_bloqueo()
        with open(ruta) as f:
            self.assertIn('ya-generado.example.com', f.read())


class TestLogrotateDns(unittest.TestCase):
    """BAJA9: rotate = registro_dns_dias + maxsize 200M."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-logrotate-')
        self.r = _router(self.tmp)

    def test_incluye_rotate_y_maxsize(self):
        self.r.cfg['bloqueo']['registro_dns_dias'] = 45
        texto = self.r._generar_logrotate_dns()
        self.assertIn('rotate 45', texto)
        self.assertIn('maxsize 200M', texto)
        self.assertIn('copytruncate', texto)


class TestFailOpen(unittest.TestCase):
    """M6: tras 3 arranques fallidos CONSECUTIVOS de dnsmasq, routerd
    entra en fail-open (servers-file vacío, sin log, sin redirigir_dns) y
    sale en cuanto dnsmasq vuelve a estar activo."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-failopen-')
        self.r = _router(self.tmp)

    def test_menos_de_3_fallos_no_entra_en_fail_open(self):
        self.r._registrar_dnsmasq_fallo()
        self.r._registrar_dnsmasq_fallo()
        self.assertFalse(self.r._bloqueo_fail_open)
        self.assertEqual(self.r._dnsmasq_fallos_consecutivos, 2)

    def test_3_fallos_entra_en_fail_open_y_vacia_el_servers_file(self):
        self.r._asegurar_servers_file_bloqueo()
        ruta = self.r.rutas['dnsmasq_bloqueo']
        with open(ruta, 'w') as f:
            f.write('server=/algo.example.com/\n')
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.assertTrue(self.r._bloqueo_fail_open)
        with open(ruta) as f:
            contenido = f.read()
        self.assertNotIn('algo.example.com', contenido)
        self.assertNotIn('server=', contenido)

    def test_fail_open_fuerza_reinstalacion_del_firewall(self):
        self.r.base_instalada = True
        self.r.base_texto = 'algo que ya estaba instalado'
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        # base_texto a None: instalar_base() comparará contra esto y SIEMPRE
        # verá una diferencia, forzando la reinstalación con el override.
        self.assertIsNone(self.r.base_texto)

    def test_oplog_una_sola_vez_al_entrar(self):
        with mock.patch.object(self.r, 'oplog') as m_oplog:
            for _ in range(5):   # varios fallos más allá del tercero
                self.r._registrar_dnsmasq_fallo()
        llamadas_fail_open = [c for c in m_oplog.call_args_list if c.args[1] == 'bloqueo_fail_open']
        self.assertEqual(len(llamadas_fail_open), 1)

    # — M1 (ronda 3): histéresis — no se sale hasta llevar un rato estable —

    def test_recuperado_no_sale_de_inmediato(self):
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.assertTrue(self.r._bloqueo_fail_open)
        self.r._registrar_dnsmasq_recuperado()   # primera vez que se ve activo: empieza a contar
        self.assertTrue(self.r._bloqueo_fail_open)   # todavía NO ha pasado el tiempo estable
        self.assertIsNotNone(self.r._bloqueo_activo_desde)

    def test_recuperado_sale_tras_el_tiempo_estable(self):
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.r._registrar_dnsmasq_recuperado()   # empieza a contar
        self.r._bloqueo_activo_desde = time.time() - (routerd.BLOQUEO_ESTABLE_BASE_S + 1)   # ya ha pasado
        with mock.patch('routerd.run') as m_run:
            self.r._registrar_dnsmasq_recuperado()
        self.assertFalse(self.r._bloqueo_fail_open)
        self.assertEqual(self.r._dnsmasq_fallos_consecutivos, 0)
        # M2 (ronda 4): el nivel ya NO se resetea a 0 al salir — en este
        # test sigue en 0 simplemente porque nunca llegó a subir.
        self.assertEqual(self.r._bloqueo_backoff_nivel, 0)
        self.assertIsNotNone(self.r._bloqueo_salida_desde)   # M2: hora de la salida, guardada
        # M2 (ronda 3): al salir, se pide una pasada real sin esperar al timer.
        llamadas = [c.args[0] for c in m_run.call_args_list]
        self.assertIn(['systemctl', '--no-block', 'start', 'router-bloqueo.service'], llamadas)

    def test_recaida_antes_de_estabilizar_sube_el_backoff(self):
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.r._registrar_dnsmasq_recuperado()   # empieza a contar (nivel 0, 30 min)
        self.assertEqual(self.r._bloqueo_backoff_nivel, 0)
        self.r._registrar_dnsmasq_fallo()   # recae ANTES de los 30 min: backoff
        self.assertTrue(self.r._bloqueo_fail_open)   # sigue en fail-open, no se sale ni se re-entra desde 0
        self.assertEqual(self.r._bloqueo_backoff_nivel, 1)
        self.assertIsNone(self.r._bloqueo_activo_desde)   # hay que volver a empezar a contar

    def test_backoff_dobla_el_tiempo_estable_requerido(self):
        self.assertEqual(self.r._bloqueo_estable_requerido_s(), routerd.BLOQUEO_ESTABLE_BASE_S)
        self.r._bloqueo_backoff_nivel = 1
        self.assertEqual(self.r._bloqueo_estable_requerido_s(), routerd.BLOQUEO_ESTABLE_BASE_S * 2)
        self.r._bloqueo_backoff_nivel = 2
        self.assertEqual(self.r._bloqueo_estable_requerido_s(), routerd.BLOQUEO_ESTABLE_BASE_S * 4)

    def test_backoff_nunca_supera_el_tope_de_24h(self):
        self.r._bloqueo_backoff_nivel = routerd.BLOQUEO_BACKOFF_NIVEL_MAX + 5
        self.assertEqual(self.r._bloqueo_estable_requerido_s(), routerd.BLOQUEO_ESTABLE_MAX_S)

    # — M2 (ronda 4): el nivel YA NO se resetea a 0 al salir; persiste y
    # sobrevive a un reinicio de routerd —

    def test_nivel_no_se_resetea_al_salir(self):
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.r._registrar_dnsmasq_recuperado()   # empieza a contar
        self.r._registrar_dnsmasq_fallo()   # recae antes de estabilizar: nivel 1
        self.assertEqual(self.r._bloqueo_backoff_nivel, 1)
        self.r._registrar_dnsmasq_recuperado()   # empieza a contar otra vez
        self.r._bloqueo_activo_desde = time.time() - (self.r._bloqueo_estable_requerido_s() + 1)
        with mock.patch('routerd.run'):
            self.r._registrar_dnsmasq_recuperado()   # sale de verdad
        self.assertFalse(self.r._bloqueo_fail_open)
        # El nivel sigue en 1 — ya NO se resetea a 0 sólo por salir.
        self.assertEqual(self.r._bloqueo_backoff_nivel, 1)
        self.assertIsNotNone(self.r._bloqueo_salida_desde)

    def test_recaida_dentro_de_24h_desde_la_ultima_salida_sube_nivel(self):
        # Simula una salida "antigua" (hace 1h) y una recaída completa
        # (3 fallos) justo después: debe subir de nivel por la recaída
        # dentro de la ventana de 24h, no por estar ya en fail-open.
        self.r._bloqueo_backoff_nivel = 0
        self.r._bloqueo_salida_desde = time.time() - 3600
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.assertTrue(self.r._bloqueo_fail_open)
        self.assertEqual(self.r._bloqueo_backoff_nivel, 1)

    def test_recaida_fuera_de_24h_desde_la_ultima_salida_no_sube_nivel(self):
        self.r._bloqueo_backoff_nivel = 0
        self.r._bloqueo_salida_desde = time.time() - (routerd.BLOQUEO_RECAIDA_VENTANA_S + 60)
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.assertTrue(self.r._bloqueo_fail_open)
        self.assertEqual(self.r._bloqueo_backoff_nivel, 0)

    def test_nivel_baja_tras_24h_sanas_fuera_de_fail_open(self):
        self.r._bloqueo_backoff_nivel = 2
        self.r._bloqueo_fail_open = False
        self.r._bloqueo_salida_desde = time.time() - (routerd.BLOQUEO_SANO_PARA_BAJAR_S + 60)
        self.r._registrar_dnsmasq_recuperado()
        self.assertEqual(self.r._bloqueo_backoff_nivel, 1)
        # El cronómetro se reinicia: otra bajada exige otras 24h sanas.
        self.r._registrar_dnsmasq_recuperado()
        self.assertEqual(self.r._bloqueo_backoff_nivel, 1)

    def test_nivel_no_baja_antes_de_24h_sanas(self):
        self.r._bloqueo_backoff_nivel = 2
        self.r._bloqueo_fail_open = False
        self.r._bloqueo_salida_desde = time.time() - 60   # hace sólo 1 minuto
        self.r._registrar_dnsmasq_recuperado()
        self.assertEqual(self.r._bloqueo_backoff_nivel, 2)

    def test_estado_persiste_y_sobrevive_a_un_reinicio(self):
        self.r._bloqueo_backoff_nivel = 3
        self.r._bloqueo_salida_desde = time.time() - 1000
        self.r._guardar_estado_fail_open()
        ruta_estado = self.r.rutas['bloqueo_fail_open_estado']
        self.assertTrue(os.path.exists(ruta_estado))
        r2 = _router(self.tmp)   # simula un routerd NUEVO, mismas rutas (mismo /run)
        self.assertEqual(r2._bloqueo_backoff_nivel, 3)
        self.assertIsNotNone(r2._bloqueo_salida_desde)
        self.assertAlmostEqual(r2._bloqueo_salida_desde, self.r._bloqueo_salida_desde, delta=1)

    def test_sin_estado_previo_arranca_en_nivel_0(self):
        self.assertEqual(self.r._bloqueo_backoff_nivel, 0)
        self.assertIsNone(self.r._bloqueo_salida_desde)

    def test_recuperado_sin_haber_fallado_no_hace_nada_raro(self):
        with mock.patch.object(self.r, 'oplog') as m_oplog:
            self.r._registrar_dnsmasq_recuperado()
        m_oplog.assert_not_called()

    # — M2 (ronda 3): al entrar en fail-open, se borra también el .hash —

    def test_entrar_en_fail_open_borra_el_hash(self):
        ruta = self.r.rutas['dnsmasq_bloqueo']
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, 'w') as f:
            f.write('server=/algo.example.com/\n')
        with open(ruta + '.hash', 'w') as f:
            f.write('{"hash": "lo-que-sea"}')
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.assertFalse(os.path.exists(ruta + '.hash'))

    # — M1 (ronda 3): sin reinstalar/vaciar conntrack en cada vuelta mientras dure —

    def test_instalar_base_no_repite_trabajo_en_cada_vuelta_de_fail_open(self):
        self.r.cfg['bloqueo']['forzar_dns'] = True
        self.r._bloqueo_fail_open = True
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()   # 1ª vuelta: SÍ aplica el override
        self.assertTrue(self.r.base_instalada)
        primeras_llamadas = m_run.call_count
        self.assertGreater(primeras_llamadas, 0)
        # BAJA1 (ronda 4): las vueltas siguientes SIEMPRE comprueban que la
        # tabla "inet router" sigue existiendo (una llamada a `nft list
        # table`), pero si sigue ahí y el texto no cambia, no reinstalan
        # nada más (nunca más `nft -f`).
        with mock.patch('routerd.run') as m_run2:
            m_run2.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()   # 2ª, 3ª... vuelta: sólo comprueba la tabla
            self.r.instalar_base()
        llamadas = [c.args[0] for c in m_run2.call_args_list]
        self.assertEqual(m_run2.call_count, 2)   # una comprobación por vuelta, nada más
        for c in llamadas:
            self.assertEqual(c, ['nft', 'list', 'table', 'inet', 'router'])

    def test_instalar_base_en_fail_open_reinstala_si_la_tabla_desaparece(self):
        # BAJA1 (ronda 4): ya NO se salta la comprobación de la tabla
        # entera mientras dure el fail-open — sólo se salta la
        # REINSTALACIÓN cuando el texto no ha cambiado Y la tabla sigue
        # ahí. Si alguien la borra a mano (p. ej. `nft flush ruleset`)
        # durante un fail-open largo, debe reinstalarse igual.
        self.r.cfg['bloqueo']['forzar_dns'] = True
        self.r._bloqueo_fail_open = True
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()   # 1ª vuelta: instala
        self.assertTrue(self.r.base_instalada)

        def _tabla_desaparecida(cmd, **kw):
            if cmd[:3] == ['nft', 'list', 'table']:
                return mock.Mock(returncode=1, stdout='', stderr='No such file or directory')
            return mock.Mock(returncode=0, stdout='', stderr='')

        with mock.patch('routerd.run', side_effect=_tabla_desaparecida) as m_run2:
            self.r.instalar_base()   # tabla "desaparecida": reinstala de verdad
        llamadas = [c.args[0] for c in m_run2.call_args_list]
        self.assertTrue(any(c[:2] == ['nft', '-f'] for c in llamadas),
                         'debería reinstalar el firewall base aunque siga en fail-open')

    def test_instalar_base_respeta_fail_open_desactivando_forzar_dns(self):
        self.r.cfg['bloqueo']['forzar_dns'] = True
        self.r._bloqueo_fail_open = True
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        # El texto efectivamente escrito/validado por `nft -c -f`/`nft -f`
        # no debe tener la cadena redirigir_dns pese a forzar_dns=True.
        escrituras = [c for c in m_run.call_args_list if c.args and c.args[0][:2] == ['nft', '-f']]
        self.assertTrue(self.r.base_instalada)
        self.assertNotIn('redirigir_dns', self.r.base_texto)

    def test_instalar_base_sin_fail_open_incluye_redirigir_dns(self):
        self.r.cfg['bloqueo']['forzar_dns'] = True
        self.r._bloqueo_fail_open = False
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        self.assertIn('redirigir_dns', self.r.base_texto)


class TestDnsmasqActivoOTransicionando(unittest.TestCase):
    """BAJA12: 'activating'/'reloading' cuentan como "sigue vivo"."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-activo-')
        self.r = _router(self.tmp)

    def _con_estado(self, estado):
        return mock.patch('routerd.run', return_value=mock.Mock(stdout=estado, returncode=0))

    def test_active_es_verdad(self):
        with self._con_estado('active'):
            self.assertTrue(self.r._dnsmasq_activo_o_transicionando())

    def test_activating_es_verdad(self):
        with self._con_estado('activating'):
            self.assertTrue(self.r._dnsmasq_activo_o_transicionando())

    def test_reloading_es_verdad(self):
        with self._con_estado('reloading'):
            self.assertTrue(self.r._dnsmasq_activo_o_transicionando())

    def test_inactive_es_falso(self):
        with self._con_estado('inactive'):
            self.assertFalse(self.r._dnsmasq_activo_o_transicionando())

    def test_failed_es_falso(self):
        with self._con_estado('failed'):
            self.assertFalse(self.r._dnsmasq_activo_o_transicionando())


class TestAsegurarDnsmasqNeutro(unittest.TestCase):
    """M3 (ronda 3): si `dnsmasq --test` de la conf LAN falla pero dnsmasq
    SIGUE activo con la de antes, es NEUTRO — nunca cuenta como fallo (no
    empuja hacia fail-open) ni como recuperación."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-neutro-')
        self.r = _router(self.tmp)

    def test_config_nueva_invalida_pero_activo_no_cuenta_como_fallo(self):
        with mock.patch.object(self.r, '_asegurar_servers_file_bloqueo'), \
             mock.patch.object(self.r, '_asegurar_log_dns'), \
             mock.patch.object(self.r, 'asegurar_logrotate_dns'), \
             mock.patch.object(self.r, '_asegurar_timer_bloqueo'), \
             mock.patch.object(self.r, 'aplicar_dnsmasq', return_value=(False, 'config mala')), \
             mock.patch.object(self.r, '_dnsmasq_activo_o_transicionando', return_value=True), \
             mock.patch.object(self.r, '_registrar_dnsmasq_fallo') as m_fallo, \
             mock.patch.object(self.r, '_registrar_dnsmasq_recuperado') as m_recuperado, \
             mock.patch.object(self.r, 'oplog'):
            self.r.asegurar_dnsmasq()
        m_fallo.assert_not_called()
        m_recuperado.assert_not_called()

    def test_config_nueva_invalida_y_no_activo_si_cuenta_como_fallo(self):
        with mock.patch.object(self.r, '_asegurar_servers_file_bloqueo'), \
             mock.patch.object(self.r, '_asegurar_log_dns'), \
             mock.patch.object(self.r, 'asegurar_logrotate_dns'), \
             mock.patch.object(self.r, '_asegurar_timer_bloqueo'), \
             mock.patch.object(self.r, 'aplicar_dnsmasq', return_value=(False, 'config mala')), \
             mock.patch.object(self.r, '_dnsmasq_activo_o_transicionando', return_value=False), \
             mock.patch.object(self.r, '_registrar_dnsmasq_fallo') as m_fallo, \
             mock.patch.object(self.r, 'oplog'):
            self.r.asegurar_dnsmasq()
        m_fallo.assert_called_once()

    def test_config_nueva_valida_y_activo_cuenta_como_recuperado(self):
        with mock.patch.object(self.r, '_asegurar_servers_file_bloqueo'), \
             mock.patch.object(self.r, '_asegurar_log_dns'), \
             mock.patch.object(self.r, 'asegurar_logrotate_dns'), \
             mock.patch.object(self.r, '_asegurar_timer_bloqueo'), \
             mock.patch.object(self.r, 'aplicar_dnsmasq', return_value=(True, 'ok')), \
             mock.patch.object(self.r, '_dnsmasq_activo_o_transicionando', return_value=True), \
             mock.patch.object(self.r, '_registrar_dnsmasq_recuperado') as m_recuperado, \
             mock.patch.object(self.r, 'oplog'):
            self.r.asegurar_dnsmasq()
        m_recuperado.assert_called_once()


class TestTimerBloqueo(unittest.TestCase):
    """BAJA7: drop-in de router-bloqueo.timer con bloqueo.actualizar_h."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-timer-')
        self.r = _router(self.tmp)

    def test_escribe_el_dropin_la_primera_vez(self):
        self.r.cfg['bloqueo']['actualizar_h'] = 48
        with mock.patch('routerd.run') as m_run:
            self.r._asegurar_timer_bloqueo()
        with open(self.r.rutas['bloqueo_timer_dropin']) as f:
            contenido = f.read()
        self.assertIn('OnUnitActiveSec=48h', contenido)
        m_run.assert_called_once()   # systemctl daemon-reload

    def test_baja1_linea_vacia_antes_reinicia_la_lista(self):
        # BAJA1: OnUnitActiveSec= es ADITIVO — sin la línea vacía antes, un
        # drop-in con sólo "OnUnitActiveSec=48h" se SUMARÍA al
        # "OnUnitActiveSec=24h" de la unidad principal (dispararía en los
        # dos), no lo sustituiría.
        contenido = self.r._generar_timer_bloqueo(48)
        lineas = [l for l in contenido.splitlines() if l.startswith('OnUnitActiveSec=')]
        self.assertEqual(lineas, ['OnUnitActiveSec=', 'OnUnitActiveSec=48h'])

    def test_baja2_contenido_ya_correcto_en_disco_no_recarga(self):
        # BAJA2: tras "reiniciar routerd" (un Router nuevo, con
        # _bloqueo_timer_h_aplicado de vuelta a None), si el drop-in en
        # disco YA es el correcto, no debe reescribirse ni recargar
        # systemd — la comparación es por CONTENIDO, no por la caché en
        # memoria.
        self.r.cfg['bloqueo']['actualizar_h'] = 48
        with mock.patch('routerd.run'):
            self.r._asegurar_timer_bloqueo()
        r2 = _router(self.tmp, cfg=self.r.cfg)   # "routerd reiniciado": caché en memoria limpia
        self.assertIsNone(r2._bloqueo_timer_h_aplicado)
        with mock.patch('routerd.run') as m_run2:
            r2._asegurar_timer_bloqueo()
        m_run2.assert_not_called()
        self.assertEqual(r2._bloqueo_timer_h_aplicado, 48)

    def test_no_reescribe_ni_recarga_si_no_cambia(self):
        self.r.cfg['bloqueo']['actualizar_h'] = 24
        with mock.patch('routerd.run'):
            self.r._asegurar_timer_bloqueo()
        with mock.patch('routerd.run') as m_run2:
            self.r._asegurar_timer_bloqueo()
        m_run2.assert_not_called()

    def test_reescribe_si_cambia(self):
        self.r.cfg['bloqueo']['actualizar_h'] = 24
        with mock.patch('routerd.run'):
            self.r._asegurar_timer_bloqueo()
        self.r.cfg['bloqueo']['actualizar_h'] = 72
        with mock.patch('routerd.run') as m_run2:
            self.r._asegurar_timer_bloqueo()
        with open(self.r.rutas['bloqueo_timer_dropin']) as f:
            self.assertIn('OnUnitActiveSec=72h', f.read())
        m_run2.assert_called_once()

    def test_fuera_de_rango_se_acota(self):
        self.r.cfg['bloqueo']['actualizar_h'] = 999
        with mock.patch('routerd.run'):
            self.r._asegurar_timer_bloqueo()
        with open(self.r.rutas['bloqueo_timer_dropin']) as f:
            self.assertIn('OnUnitActiveSec=168h', f.read())

    def test_gestionar_dnsmasq_false_no_toca_nada(self):
        self.r.cfg['gestionar_dnsmasq'] = False
        self.r.cfg['bloqueo']['actualizar_h'] = 48
        with mock.patch('routerd.run') as m_run:
            self.r._asegurar_timer_bloqueo()
        self.assertFalse(os.path.exists(self.r.rutas['bloqueo_timer_dropin']))
        m_run.assert_not_called()


class TestConntrackFlush(unittest.TestCase):
    """BAJA10/11: vacía conntrack SÓLO al ACTIVAR forzar_dns/bloquear_doh
    (transición False→True), nunca al desactivar ni en cada ciclo sin
    cambios."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-conntrack-')
        self.r = _router(self.tmp)

    def _instalar(self, forzar_dns, bloquear_doh):
        self.r.cfg['bloqueo']['forzar_dns'] = forzar_dns
        self.r.cfg['bloqueo']['bloquear_doh'] = bloquear_doh
        self.r.base_instalada = False   # fuerza la reinstalación cada vez en esta prueba
        self.r.base_texto = None
        with mock.patch('routerd.run') as m_run:
            m_run.return_value = mock.Mock(returncode=0, stdout='', stderr='')
            self.r.instalar_base()
        return m_run

    def test_primera_instalacion_nunca_vacia_conntrack(self):
        m_run = self._instalar(True, True)
        llamadas_conntrack = [c for c in m_run.call_args_list if c.args and c.args[0][0] == 'conntrack']
        self.assertEqual(llamadas_conntrack, [])

    def test_activar_forzar_dns_vacia_conntrack_udp_tcp_53(self):
        self._instalar(False, False)
        m_run = self._instalar(True, False)
        llamadas = [c.args[0] for c in m_run.call_args_list if c.args and c.args[0][0] == 'conntrack']
        self.assertTrue(any('53' in a for call in llamadas for a in call))
        self.assertEqual(len(llamadas), 2)   # udp y tcp

    def test_desactivar_forzar_dns_no_vacia_conntrack(self):
        self._instalar(True, False)
        m_run = self._instalar(False, False)
        llamadas = [c for c in m_run.call_args_list if c.args and c.args[0][0] == 'conntrack']
        self.assertEqual(llamadas, [])

    def test_mantener_activo_no_vuelve_a_vaciar(self):
        self._instalar(True, False)
        m_run = self._instalar(True, False)
        llamadas = [c for c in m_run.call_args_list if c.args and c.args[0][0] == 'conntrack']
        self.assertEqual(llamadas, [])

    def test_activar_bloquear_doh_vacia_conntrack_853(self):
        self._instalar(False, False)
        m_run = self._instalar(False, True)
        llamadas = [c.args[0] for c in m_run.call_args_list if c.args and c.args[0][0] == 'conntrack']
        self.assertTrue(any('853' in a for call in llamadas for a in call))
        self.assertEqual(len(llamadas), 2)


class TestBloqueoActualizarForzar(unittest.TestCase):
    """BAJA4 (ronda 3): bloqueo_actualizar {"forzar": true} deja el
    marcador de un solo uso en bloqueo_cache."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-forzar-')
        self.r = _router(self.tmp)

    def test_forzar_deja_el_marcador(self):
        with mock.patch('routerd.run') as m_run:
            ok, msg = self.r._ejecutar_accion_bloqueo('bloqueo_actualizar', {'forzar': True})
        self.assertTrue(ok, msg)
        self.assertIn('forzada', msg)
        self.assertTrue(os.path.exists(os.path.join(self.r.rutas['bloqueo_cache'], '.forzar')))
        m_run.assert_called_once()

    def test_sin_forzar_no_deja_marcador(self):
        with mock.patch('routerd.run'):
            ok, msg = self.r._ejecutar_accion_bloqueo('bloqueo_actualizar', {})
        self.assertTrue(ok, msg)
        self.assertNotIn('forzada', msg)
        self.assertFalse(os.path.exists(os.path.join(self.r.rutas['bloqueo_cache'], '.forzar')))


class TestBloqueoProbarLimite(unittest.TestCase):
    """BAJA8: como mucho 2 bloqueo_probar de verdad ejecutadas por ciclo."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-probar-')
        self.r = _router(self.tmp)
        os.makedirs(self.r.rutas['buzon'], exist_ok=True)
        os.makedirs(self.r.rutas['respuestas'], exist_ok=True)

    def _dejar_peticion(self, dominio):
        pid = str(uuid.uuid4())
        ruta = os.path.join(self.r.rutas['buzon'], '%s.json' % pid)
        with open(ruta, 'w') as f:
            json.dump({'id': pid, 'usuario': 'admin', 'accion': 'bloqueo_probar',
                       'datos': {'dominio': dominio}}, f)
        return pid

    def test_solo_dos_se_ejecutan_de_verdad(self):
        pids = [self._dejar_peticion('d%d.example.com' % i) for i in range(3)]
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run'):
            self.r.atender_buzon()
        resueltas = 0
        for pid in pids:
            ruta_resp = os.path.join(self.r.rutas['respuestas'], pid + '.json')
            if os.path.exists(ruta_resp):
                resueltas += 1
        self.assertEqual(resueltas, 2)
        # La tercera sigue en el buzón, sin reclamar — el panel la verá "pendiente".
        pendientes = [p for p in pids if os.path.exists(os.path.join(self.r.rutas['buzon'], p + '.json'))]
        self.assertEqual(len(pendientes), 1)

    def test_el_tercer_ciclo_siguiente_la_atiende(self):
        pids = [self._dejar_peticion('d%d.example.com' % i) for i in range(3)]
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), mock.patch('routerd.run'):
            self.r.atender_buzon()
            self.r.atender_buzon()   # "siguiente ciclo"
        for pid in pids:
            self.assertTrue(os.path.exists(os.path.join(self.r.rutas['respuestas'], pid + '.json')))


class TestBloqueoConfigRegeneraSoloSiCambiaAlgoRelevante(unittest.TestCase):
    """BAJA13: bloqueo_config sólo relanza router-bloqueo.service cuando
    cambian 'listas'/'bloquear_doh'/'habilitado' — nunca por forzar_dns/
    actualizar_h/registro_dns_dias solos."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-regenera-')
        self.r = _router(self.tmp)
        os.makedirs(self.r.rutas['buzon'], exist_ok=True)
        os.makedirs(self.r.rutas['respuestas'], exist_ok=True)
        self.r.cfg['bloqueo'] = {
            'habilitado': True, 'listas': ['hagezi_pro'], 'lista_blanca': [], 'lista_negra': [],
            'forzar_dns': True, 'bloquear_doh': True, 'actualizar_h': 24, 'registro_dns_dias': 30,
        }

    def _dejar_peticion(self, accion, datos):
        pid = str(uuid.uuid4())
        ruta = os.path.join(self.r.rutas['buzon'], '%s.json' % pid)
        with open(ruta, 'w') as f:
            json.dump({'id': pid, 'usuario': 'admin', 'accion': accion, 'datos': datos}, f)
        return pid

    def _datos_config(self, **cambios):
        datos = {'habilitado': True, 'listas': ['hagezi_pro'], 'forzar_dns': True,
                  'bloquear_doh': True, 'actualizar_h': 24, 'registro_dns_dias': 30}
        datos.update(cambios)
        return datos

    def test_cambiar_solo_actualizar_h_no_relanza(self):
        self._dejar_peticion('bloqueo_config', self._datos_config(actualizar_h=48))
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run') as m_run:
            self.r.atender_buzon()
        llamadas_bloqueo = [c for c in m_run.call_args_list
                             if c.args and 'router-bloqueo.service' in c.args[0]]
        self.assertEqual(llamadas_bloqueo, [])

    def test_cambiar_solo_forzar_dns_no_relanza(self):
        self._dejar_peticion('bloqueo_config', self._datos_config(forzar_dns=False))
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run') as m_run:
            self.r.atender_buzon()
        llamadas_bloqueo = [c for c in m_run.call_args_list
                             if c.args and 'router-bloqueo.service' in c.args[0]]
        self.assertEqual(llamadas_bloqueo, [])

    def test_cambiar_listas_si_relanza(self):
        self._dejar_peticion('bloqueo_config', self._datos_config(listas=['hagezi_pro', 'hagezi_tif']))
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run') as m_run:
            self.r.atender_buzon()
        llamadas_bloqueo = [c for c in m_run.call_args_list
                             if c.args and 'router-bloqueo.service' in c.args[0]]
        self.assertEqual(len(llamadas_bloqueo), 1)

    def test_cambiar_habilitado_si_relanza(self):
        self._dejar_peticion('bloqueo_config', self._datos_config(habilitado=False))
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run') as m_run:
            self.r.atender_buzon()
        llamadas_bloqueo = [c for c in m_run.call_args_list
                             if c.args and 'router-bloqueo.service' in c.args[0]]
        self.assertEqual(len(llamadas_bloqueo), 1)

    def test_bloqueo_lista_siempre_relanza(self):
        self._dejar_peticion('bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'x.example.com'})
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run') as m_run:
            self.r.atender_buzon()
        llamadas_bloqueo = [c for c in m_run.call_args_list
                             if c.args and 'router-bloqueo.service' in c.args[0]]
        self.assertEqual(len(llamadas_bloqueo), 1)


class TestConfigParaPanelYDnsEmergencia(unittest.TestCase):
    """Petición del panel (ronda 3): estado.json → config.bloqueo/
    config.bloqueo_version, y estado.json → dns_emergencia."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-panel-')
        self.r = _router(self.tmp)

    def test_config_incluye_bloqueo_y_version(self):
        config = self.r._config_para_panel()
        self.assertIn('bloqueo', config)
        self.assertEqual(config['bloqueo'], self.r.cfg['bloqueo'])
        self.assertIn('bloqueo_version', config)
        import router_bloqueo
        self.assertEqual(config['bloqueo_version'],
                          router_bloqueo.calcular_version_bloqueo(self.r.cfg['bloqueo']))

    def test_config_incluye_lista_blanca_y_negra_en_bloqueo(self):
        self.r.cfg['bloqueo']['lista_blanca'] = ['bueno.com']
        self.r.cfg['bloqueo']['lista_negra'] = ['malo.com']
        config = self.r._config_para_panel()
        self.assertEqual(config['bloqueo']['lista_blanca'], ['bueno.com'])
        self.assertEqual(config['bloqueo']['lista_negra'], ['malo.com'])

    def test_dns_emergencia_inactivo_por_defecto(self):
        self.assertFalse(self.r._bloqueo_fail_open)
        # Reconstruye lo que publicar() pondría en estado.json, sin
        # ejecutar publicar() entero (que toca nft/ip de verdad).
        self.assertIsNone(self.r._bloqueo_fail_open_desde)

    def test_dns_emergencia_activo_tras_fail_open(self):
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        self.assertTrue(self.r._bloqueo_fail_open)
        self.assertIsNotNone(self.r._bloqueo_fail_open_desde)

    def test_publicar_escribe_dns_emergencia_y_bloqueo_version_de_verdad(self):
        # Integración: publicar() de verdad, con `run` mockeado para no
        # tocar nft/ip reales, y comprobando el estado.json ESCRITO.
        for _ in range(3):
            self.r._registrar_dnsmasq_fallo()
        with mock.patch('routerd.run', return_value=mock.Mock(returncode=1, stdout='', stderr='')):
            self.r.publicar()
        with open(self.r.rutas['estado']) as f:
            estado = json.load(f)
        self.assertTrue(estado['dns_emergencia']['activo'])
        self.assertIsNotNone(estado['dns_emergencia']['desde'])
        self.assertIsNotNone(estado['dns_emergencia']['motivo'])
        self.assertIn('bloqueo_version', estado['config'])
        self.assertIn('bloqueo', estado['config'])


if __name__ == '__main__':
    unittest.main()
