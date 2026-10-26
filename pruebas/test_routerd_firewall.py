#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas de la validación del firewall en routerd.atender_buzon (HIGH-3
de la revisión Opus 2026-10-12): las acciones fw_* se validan generando el
texto nft y pasando `nft -c -f` sobre un temporal ANTES de guardar la
config. Si falla, ok=False con el error y la config en memoria vuelve a la
anterior.

Uso:  python3 -m unittest pruebas/test_routerd_firewall.py -v
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
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
    cfg['firewall'] = {'version': 1, 'grupos': [], 'reglas': []}
    return cfg


def _router(tmp, cfg=None):
    r = routerd.Router(_rutas_prueba(tmp))
    r.cfg = cfg if cfg is not None else _cfg_base()
    r.fase = 'produccion'
    return r


def _resultado_ok(*args, **kwargs):
    return subprocess.CompletedProcess(args[0] if args else [], 0, stdout='', stderr='')


def _run_selectivo_nft_invalido(args, **kwargs):
    """Simula routerd.run: nft -c falla como el binario real (comprobar=True
    convierte returncode != 0 en RuntimeError)."""
    if args[:2] == ['nft', '-c']:
        raise RuntimeError('nft -c -f tmp → Error: Could not resolve protocol name ipv4-icmp')
    return _resultado_ok(args, **kwargs)


class TestValidarFirewallAntesDeGuardar(unittest.TestCase):
    """HIGH-3: las acciones fw_* se validan con nft -c antes de _guardar_config."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-fw-')
        self.r = _router(self.tmp)
        os.makedirs(self.r.rutas['buzon'], exist_ok=True)
        os.makedirs(self.r.rutas['respuestas'], exist_ok=True)

    def _dejar_peticion(self, accion, datos):
        pid = str(uuid.uuid4())
        ruta = os.path.join(self.r.rutas['buzon'], '%s.json' % pid)
        with open(ruta, 'w') as f:
            json.dump({'id': pid, 'usuario': 'admin', 'accion': accion, 'datos': datos}, f)
        return pid

    def _respuesta(self, pid):
        ruta = os.path.join(self.r.rutas['respuestas'], pid + '.json')
        if not os.path.exists(ruta):
            return None
        with open(ruta) as f:
            return json.load(f)

    def _regla_minima(self, **campos):
        base = {
            'nombre': 'Regla', 'habilitada': True, 'accion': 'bloquear',
            'origen': {'tipo': 'cualquiera'}, 'destino': {'tipo': 'cualquiera'},
            'protocolo': 'tcp', 'puertos': [], 'registrar': False, 'comentario': '',
        }
        base.update(campos)
        return base

    def test_fw_valida_con_nft_check_antes_de_guardar(self):
        # Una acción fw_* debe llamar a nft -c antes de _guardar_config.
        pid = self._dejar_peticion('fw_regla_guardar', {
            'version': 1, 'regla': self._regla_minima()})
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run', side_effect=_resultado_ok) as m_run, \
             mock.patch.object(self.r, '_guardar_config') as m_guardar:
            self.r.atender_buzon()
        llamadas_nft_check = [c for c in m_run.call_args_list
                              if c.args and c.args[0][:2] == ['nft', '-c']]
        self.assertTrue(llamadas_nft_check, 'no se llamó a nft -c antes de guardar')
        self.assertTrue(m_guardar.called)
        resp = self._respuesta(pid)
        self.assertIsNotNone(resp)
        self.assertTrue(resp['ok'], resp)

    def test_fw_con_nft_invalido_responde_error_y_no_guarda(self):
        # Si nft -c rechaza el texto generado: ok=False con el error de nft,
        # la config vuelve a la anterior y NO se guarda.
        cfg_antes = copy.deepcopy(self.r.cfg)
        pid = self._dejar_peticion('fw_regla_guardar', {
            'version': 1, 'regla': self._regla_minima()})
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run', side_effect=_run_selectivo_nft_invalido), \
             mock.patch.object(self.r, '_guardar_config') as m_guardar:
            self.r.atender_buzon()
        resp = self._respuesta(pid)
        self.assertIsNotNone(resp)
        self.assertFalse(resp['ok'], resp)
        self.assertIn('nft', resp['mensaje'].lower())
        self.assertFalse(m_guardar.called, 'no se debe guardar una config inválida')
        self.assertEqual(self.r.cfg.get('firewall', {}).get('reglas', []),
                         cfg_antes.get('firewall', {}).get('reglas', []))

    def test_fw_con_config_invalida_responde_error_y_no_guarda(self):
        # Si nft_conf.generar() lanza ValueError, también: ok=False y sin guardar.
        pid = self._dejar_peticion('fw_regla_guardar', {
            'version': 1, 'regla': self._regla_minima()})
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run', side_effect=_resultado_ok), \
             mock.patch('nft_conf.generar',
                        side_effect=ValueError('el destino con grupo exige un grupo tipo ip')), \
             mock.patch.object(self.r, '_guardar_config') as m_guardar:
            self.r.atender_buzon()
        resp = self._respuesta(pid)
        self.assertIsNotNone(resp)
        self.assertFalse(m_guardar.called)

    def test_accion_no_fw_no_pasa_por_nft_check(self):
        # Una acción que no es fw_* no debe llamar a nft -c.
        self.r.cfg.setdefault('etiquetas', {})
        pid = self._dejar_peticion('dispositivo_etiquetar', {
            'mac': 'aa:bb:cc:dd:ee:01', 'etiqueta': 'portatil'})
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run', side_effect=_resultado_ok) as m_run, \
             mock.patch.object(self.r, '_guardar_config'):
            self.r.atender_buzon()
        llamadas_nft_check = [c for c in m_run.call_args_list
                              if c.args and c.args[0][:2] == ['nft', '-c']]
        self.assertEqual(llamadas_nft_check, [])
        resp = self._respuesta(pid)
        self.assertIsNotNone(resp)
        self.assertTrue(resp['ok'], resp)

    def test_config_en_memoria_vuelve_a_la_anterior_si_falla_nft(self):
        # La mutación de peticiones.aplicar() se descarta si nft -c falla.
        self.r.cfg['firewall']['reglas'] = []
        self.r.cfg['firewall']['version'] = 1
        pid = self._dejar_peticion('fw_regla_guardar', {
            'version': 1, 'regla': self._regla_minima(nombre='No debe quedar')})
        with mock.patch.object(self.r, '_uid_routerpanel', return_value=None), \
             mock.patch('routerd.run', side_effect=_run_selectivo_nft_invalido), \
             mock.patch.object(self.r, '_guardar_config'):
            self.r.atender_buzon()
        self.assertEqual(self.r.cfg['firewall']['reglas'], [],
                         'la regla no debía quedarse en la config en memoria')
        self.assertEqual(self.r.cfg['firewall']['version'], 1)


class TestVaciarConntrackReglasFw(unittest.TestCase):
    """MEDIUM-3 (revisión Opus 2026-10-12): el vaciado de conntrack filtra
    por protocolo/puerto/destino, resuelve MAC→IP, recorre miembros de
    grupos ip y se re-vacía al editar una regla (clave id+huella)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-ct-')
        self.r = _router(self.tmp)
        self.llamadas = []

    def _run_registrador(self, args, **kwargs):
        self.llamadas.append(list(args))
        return _resultado_ok(args, **kwargs)

    def _regla(self, **campos):
        base = {
            'id': 'r_ab12cd34', 'nombre': 'R', 'habilitada': True,
            'accion': 'bloquear',
            'origen': {'tipo': 'ip', 'valor': '192.168.50.100'},
            'destino': {'tipo': 'ip', 'valor': '1.1.1.1'},
            'protocolo': 'tcp', 'puertos': [{'desde': 8000, 'hasta': 8000}],
            'registrar': False, 'comentario': '',
        }
        base.update(campos)
        return base

    def _configurar(self, reglas, grupos=None):
        self.r.cfg['firewall'] = {
            'version': 1, 'grupos': grupos or [], 'reglas': reglas}

    def test_conntrack_d_filtra_por_protocolo_puerto_y_destino(self):
        self._configurar([self._regla()])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        llamadas_ct = [c for c in self.llamadas if c and c[0] == 'conntrack']
        self.assertTrue(llamadas_ct, 'no se llamó a conntrack')
        for c in llamadas_ct:
            self.assertIn('-s', c)
            self.assertIn('192.168.50.100', c)
            self.assertIn('-p', c)
            self.assertIn('tcp', c)
            self.assertIn('--dport', c)
            self.assertIn('8000', c)
            self.assertIn('-d', c)
            self.assertIn('1.1.1.1', c)

    def test_conntrack_d_protocolo_tcp_udp_dos_llamadas(self):
        self._configurar([self._regla(protocolo='tcp_udp')])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        llamadas_ct = [c for c in self.llamadas if c and c[0] == 'conntrack']
        self.assertEqual(len(llamadas_ct), 2)
        protos = [c[c.index('-p') + 1] for c in llamadas_ct]
        self.assertEqual(sorted(protos), ['tcp', 'udp'])

    def test_conntrack_d_grupo_ip_recorre_miembros(self):
        grupos = [{'id': 'g_cd34ef56', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['192.168.50.10', '192.168.50.11']}]
        self._configurar(
            [self._regla(origen={'tipo': 'grupo', 'valor': 'g_cd34ef56'})],
            grupos)
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        origenes = {c[c.index('-s') + 1] for c in self.llamadas
                    if c and c[0] == 'conntrack' and '-s' in c}
        self.assertEqual(origenes, {'192.168.50.10', '192.168.50.11'})

    def test_conntrack_d_mac_resuelve_ip_con_ip_neigh(self):
        def _run(args, **kwargs):
            self.llamadas.append(list(args))
            if args and args[0] == 'ip' and args[1] == 'neigh':
                return subprocess.CompletedProcess(
                    args, 0,
                    stdout='192.168.50.100 dev lan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n',
                    stderr='')
            return _resultado_ok(args, **kwargs)

        self._configurar([self._regla(
            origen={'tipo': 'mac', 'valor': 'aa:bb:cc:dd:ee:01'})])
        with mock.patch('routerd.run', side_effect=_run):
            self.r._vaciar_conntrack_reglas_fw()
        llamadas_ct = [c for c in self.llamadas if c and c[0] == 'conntrack']
        self.assertTrue(llamadas_ct)
        for c in llamadas_ct:
            self.assertIn('192.168.50.100', c)

    def test_se_re_vacia_al_editar_la_regla(self):
        self._configurar([self._regla()])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        n_antes = len([c for c in self.llamadas if c and c[0] == 'conntrack'])
        self.assertGreater(n_antes, 0)
        # Segunda llamada sin cambiar la regla: NO debe repetir.
        self.llamadas.clear()
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        self.assertEqual(
            [c for c in self.llamadas if c and c[0] == 'conntrack'], [])
        # Editar la regla (mismo id, otro puerto): SÍ debe re-vaciar.
        self._configurar([self._regla(
            puertos=[{'desde': 9000, 'hasta': 9000}])])
        self.llamadas.clear()
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        llamadas_ct = [c for c in self.llamadas if c and c[0] == 'conntrack']
        self.assertTrue(llamadas_ct, 'editar la regla debe re-vaciar conntrack')
        for c in llamadas_ct:
            self.assertIn('9000', c)

    def test_no_vacia_reglas_permitir(self):
        self._configurar([self._regla(accion='permitir')])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        llamadas_ct = [c for c in self.llamadas if c and c[0] == 'conntrack']
        self.assertEqual(llamadas_ct, [])


if __name__ == '__main__':
    unittest.main()


class TestVaciarConntrackAgrupado(unittest.TestCase):
    """HIGH-A (segunda revisión Opus 2026-10-12): el vaciado de conntrack
    no puede ser combinatorio (origenes x protos x destinos x puertos).
    Se agrupa en el mínimo de llamadas (una por origen y protocolo, con
    rangos de puertos), con un TOPE de llamadas por ciclo y un tiempo
    total acotado muy por debajo del watchdog de 60 s. Si se supera el
    tope, vaciado más grueso por origen y aviso en el log. Nunca bloquea
    el ciclo."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='routerd-ct2-')
        self.r = _router(self.tmp)
        self.llamadas = []

    def _run_registrador(self, args, **kwargs):
        self.llamadas.append(list(args))
        return _resultado_ok(args, **kwargs)

    def _regla(self, **campos):
        base = {
            'id': 'r_ab12cd34', 'nombre': 'R', 'habilitada': True,
            'accion': 'bloquear',
            'origen': {'tipo': 'ip', 'valor': '192.168.50.100'},
            'destino': {'tipo': 'ip', 'valor': '1.1.1.1'},
            'protocolo': 'tcp', 'puertos': [{'desde': 8000, 'hasta': 8000}],
            'registrar': False, 'comentario': '',
        }
        base.update(campos)
        return base

    def _configurar(self, reglas, grupos=None):
        self.r.cfg['firewall'] = {
            'version': 1, 'grupos': grupos or [], 'reglas': reglas}

    def _ct(self):
        return [c for c in self.llamadas if c and c[0] == 'conntrack']

    def test_no_es_combinatorio_con_grupo_grande(self):
        # 20 origenes x 2 protos x 5 destinos x 5 puertos = 1000 llamadas
        # en el diseño viejo. El agrupado debe dejarlo en el orden de
        # origen x proto (o menos), nunca el producto cartesiano.
        grupos = [{'id': 'g_01234567', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['192.168.50.%d' % i for i in range(2, 22)]}]
        self._configurar([self._regla(
            origen={'tipo': 'grupo', 'valor': 'g_01234567'},
            destino={'tipo': 'grupo', 'valor': 'g_01234567'},
            protocolo='tcp_udp',
            puertos=[{'desde': 8000 + i, 'hasta': 8000 + i} for i in range(5)],
        )], grupos)
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        ct = self._ct()
        # Producto cartesiano puro serían 20*2*20*5 = 4000. El agrupado
        # debe estar muy por debajo (tope duro de la constante).
        self.assertLessEqual(len(ct), routerd.MAX_CONNTRACK_LLAMADAS_CICLO)
        self.assertLess(len(ct), 400, 'el vaciado sigue siendo combinatorio: %d llamadas' % len(ct))

    def test_agrupa_puertos_en_rangos(self):
        # Puertos contiguos 8000-8002 → un solo --dport 8000-8002.
        self._configurar([self._regla(
            puertos=[{'desde': 8000, 'hasta': 8002}])])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        ct = self._ct()
        self.assertEqual(len(ct), 1, ct)
        self.assertIn('8000-8002', ct[0])

    def test_tope_de_llamadas_por_ciclo(self):
        # 100 origenes con 2 protos: sin tope serían 200 llamadas.
        grupos = [{'id': 'g_01234567', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['10.0.%d.%d' % (i // 250, i % 250 + 2)
                                for i in range(100)]}]
        self._configurar([self._regla(
            origen={'tipo': 'grupo', 'valor': 'g_01234567'},
            destino={'tipo': 'cualquiera'}, protocolo='tcp_udp', puertos=[])],
            grupos)
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        ct = self._ct()
        self.assertLessEqual(len(ct), routerd.MAX_CONNTRACK_LLAMADAS_CICLO)

    def test_si_supera_tope_vacia_grueso_por_origen_y_avisa(self):
        # Con más orígenes que el tope, el vaciado cae a uno por origen
        # (sin filtro de proto/puerto/destino) y deja aviso en el log.
        grupos = [{'id': 'g_01234567', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['10.0.%d.%d' % (i // 250, i % 250 + 2)
                                for i in range(80)]}]
        self._configurar([self._regla(
            origen={'tipo': 'grupo', 'valor': 'g_01234567'},
            destino={'tipo': 'cualquiera'}, protocolo='tcp_udp',
            puertos=[{'desde': 1, 'hasta': 65535}])], grupos)
        avisos = []
        with mock.patch('routerd.run', side_effect=self._run_registrador), \
             mock.patch('routerd.LOG') as m_log:
            self.r._vaciar_conntrack_reglas_fw()
            for c in m_log.warning.call_args_list:
                avisos.append(str(c))
        ct = self._ct()
        self.assertLessEqual(len(ct), routerd.MAX_CONNTRACK_LLAMADAS_CICLO)
        # Vaciado grueso: cada llamada lleva -s pero ni -p ni --dport.
        for c in ct:
            self.assertIn('-s', c)
            self.assertNotIn('--dport', c)
        self.assertTrue(any('conntrack' in a.lower() or 'vaciado' in a.lower()
                            for a in avisos),
                        'no se avisó en el log al superar el tope: %r' % avisos)

    def test_tiempo_total_acotado(self):
        # Si cada llamada "tarda", el vaciado debe parar antes del
        # presupuesto de tiempo y NO lanzar excepción (nunca el ciclo).
        grupos = [{'id': 'g_01234567', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['10.0.%d.%d' % (i // 250, i % 250 + 2)
                                for i in range(40)]}]
        self._configurar([self._regla(
            origen={'tipo': 'grupo', 'valor': 'g_01234567'},
            destino={'tipo': 'cualquiera'}, protocolo='tcp_udp', puertos=[])],
            grupos)
        t0 = time.time()

        def _run_lento(args, **kwargs):
            self.llamadas.append(list(args))
            time.sleep(0.05)
            return _resultado_ok(args, **kwargs)

        with mock.patch('routerd.run', side_effect=_run_lento):
            self.r._vaciar_conntrack_reglas_fw()   # no debe lanzar
        self.assertLess(time.time() - t0, routerd.MAX_CONNTRACK_SEGUNDOS + 1.0)

    def test_cada_llamada_lleva_timeout_corto(self):
        self._configurar([self._regla()])
        with mock.patch('routerd.run', side_effect=self._run_registrador) as m_run:
            self.r._vaciar_conntrack_reglas_fw()
        for c in m_run.call_args_list:
            if c.args and c.args[0] and c.args[0][0] == 'conntrack':
                self.assertIn('timeout', c.kwargs)
                self.assertLessEqual(c.kwargs['timeout'], 5)

    def test_origen_cualquiera_usa_red_lan(self):
        # LOW-3: origen «cualquiera» → -s <red LAN>, nunca un conntrack -D
        # sin filtro (eso vaciaría también las conexiones del propio router).
        self._configurar([self._regla(origen={'tipo': 'cualquiera'})])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        ct = self._ct()
        self.assertTrue(ct)
        for c in ct:
            self.assertIn('-s', c)
            self.assertIn('192.168.50.0/24', c)

    def test_nunca_un_conntrack_d_sin_s(self):
        self._configurar([
            self._regla(id='r_aaaaaaaa', origen={'tipo': 'cualquiera'},
                        destino={'tipo': 'cualquiera'}, puertos=[]),
            self._regla(id='r_bbbbbbbb', origen={'tipo': 'red', 'valor': '0.0.0.0/0'},
                        destino={'tipo': 'cualquiera'}, puertos=[]),
        ])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        for c in self._ct():
            self.assertIn('-s', c, 'conntrack -D sin -s vaciaría las del router: %r' % c)

    def test_ips_desde_mac_ignora_vecinos_ipv6(self):
        # LOW-4: ip neigh también publica vecinos IPv6; sólo valen IPv4.
        def _run(args, **kwargs):
            self.llamadas.append(list(args))
            if args and args[0] == 'ip' and args[1] == 'neigh':
                return subprocess.CompletedProcess(
                    args, 0,
                    stdout=('fe80::1 dev lan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n'
                            '192.168.50.100 dev lan0 lladdr aa:bb:cc:dd:ee:02 REACHABLE\n'),
                    stderr='')
            return _resultado_ok(args, **kwargs)

        ips = self.r._ips_desde_mac(['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'])
        # No debe llamar a run todavía; probamos el parser con run simulado.
        with mock.patch('routerd.run', side_effect=_run):
            ips = self.r._ips_desde_mac(['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'])
        self.assertEqual(ips, ['192.168.50.100'])

    def test_registra_codigo_de_salida_de_conntrack_d(self):
        # LOW-4: el código de salida de cada conntrack -D queda en el log
        # (antes se silenciaba con comprobar=False y no se veía nada).
        def _run_fallo(args, **kwargs):
            self.llamadas.append(list(args))
            return subprocess.CompletedProcess(args, 1, stdout='',
                                               stderr='no such entry')
        self._configurar([self._regla()])
        with mock.patch('routerd.run', side_effect=_run_fallo), \
             mock.patch('routerd.LOG') as m_log:
            self.r._vaciar_conntrack_reglas_fw()
        textos = [str(c) for c in m_log.mock_calls]
        self.assertTrue(any('1' in t and ('conntrack' in t.lower() or 'código' in t.lower()
                                          or 'codigo' in t.lower() or 'returncode' in t.lower()
                                          or 'salida' in t.lower())
                            for t in textos),
                        'no se registró el código de salida de conntrack -D: %r' % textos)

    def test_huella_incluye_miembros_del_grupo(self):
        # LOW-2: si cambian los miembros del grupo (origen o destino), la
        # huella cambia y se re-vacía conntrack.
        grupos = [{'id': 'g_01234567', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['192.168.50.10']}]
        self._configurar([self._regla(
            origen={'tipo': 'grupo', 'valor': 'g_01234567'})], grupos)
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        n_antes = len(self._ct())
        self.assertGreater(n_antes, 0)
        # Mismo id de regla, mismos campos… pero el grupo gana un miembro.
        self.llamadas.clear()
        grupos[0]['miembros'] = ['192.168.50.10', '192.168.50.11']
        self._configurar([self._regla(
            origen={'tipo': 'grupo', 'valor': 'g_01234567'})], grupos)
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        self.assertTrue(self._ct(),
                        'cambiar los miembros del grupo debe re-vaciar conntrack')
        origenes = {c[c.index('-s') + 1] for c in self._ct() if '-s' in c}
        self.assertIn('192.168.50.11', origenes)

    def test_borrar_permitir_encima_de_bloquear_re_vacia(self):
        # LOW-2: al borrar un «permitir» que estaba por encima de un
        # «bloquear», el bloquear pasa a coger esas conexiones: hay que
        # re-vaciar conntrack de ese bloquear (su huella cambia).
        self._configurar([
            self._regla(id='r_permitir', accion='permitir',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
            self._regla(id='r_bloquear', accion='bloquear',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
        ])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        self.assertTrue(self._ct())
        self.llamadas.clear()
        # Se elimina el permitir (queda sólo el bloquear).
        self._configurar([
            self._regla(id='r_bloquear', accion='bloquear',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
        ])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        self.assertTrue(self._ct(),
                        'borrar un permitir por encima de un bloquear debe re-vaciar')

    def test_mover_permitir_debajo_de_bloquear_re_vacia(self):
        self._configurar([
            self._regla(id='r_permitir', accion='permitir',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
            self._regla(id='r_bloquear', accion='bloquear',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
        ])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        self.llamadas.clear()
        # El permitir pasa a estar DEBAJO del bloquear.
        self._configurar([
            self._regla(id='r_bloquear', accion='bloquear',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
            self._regla(id='r_permitir', accion='permitir',
                        origen={'tipo': 'ip', 'valor': '192.168.50.100'}),
        ])
        with mock.patch('routerd.run', side_effect=self._run_registrador):
            self.r._vaciar_conntrack_reglas_fw()
        self.assertTrue(self._ct(),
                        'mover un permitir por debajo de un bloquear debe re-vaciar')
