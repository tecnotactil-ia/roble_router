#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias de las 6 acciones fw_* del firewall (core/peticiones.py):
guardar/eliminar/mover/activar reglas, guardar/eliminar grupos, con TODAS sus
validaciones (límites, versión optimista, reglas prohibidas, ids generados
por el core).

Uso:  python3 -m unittest pruebas/test_peticiones_firewall.py -v
"""
import copy
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import peticiones  # noqa: E402


def _cfg():
    return {
        'modo': 'balanceo', 'modo_pesos': 'manual',
        'lan': {'interfaz': 'lan0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'},
        'wifi_wan': {'habilitada': True, 'interfaz': 'wlp3s0b1', 'ssid_bloqueadas': []},
        'wans': {}, 'reservas': [], 'etiquetas': {},
        'firewall': {'version': 1, 'grupos': [], 'reglas': []},
    }


def _peticion(accion, datos, usuario='admin'):
    return {'id': 'x', 'usuario': usuario, 'accion': accion, 'datos': datos}


def _regla_minima(**campos):
    base = {
        'nombre': 'Regla de prueba', 'habilitada': True, 'accion': 'bloquear',
        'origen': {'tipo': 'cualquiera'}, 'destino': {'tipo': 'cualquiera'},
        'protocolo': 'tcp', 'puertos': [], 'registrar': False, 'comentario': '',
    }
    base.update(campos)
    return base


def _grupo_minimo(**campos):
    base = {'nombre': 'Grupo', 'tipo': 'mac', 'miembros': []}
    base.update(campos)
    return base


class TestFwReglaGuardar(unittest.TestCase):
    def test_crear_regla_sin_id_genera_id_r_mas_8_hex(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima()}))
        self.assertTrue(ok, msg)
        self.assertIsNone(dhcp)
        self.assertEqual(len(cfg['firewall']['reglas']), 1)
        rid = cfg['firewall']['reglas'][0]['id']
        self.assertRegex(rid, r'^r_[0-9a-f]{8}$')
        self.assertEqual(cfg['firewall']['version'], 2)

    def test_crear_regla_no_toma_id_del_panel(self):
        # El panel no puede fijar la id: se ignora y se genera una nueva.
        cfg = _cfg()
        r = _regla_minima()
        r['id'] = 'r_elegidapanel'
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': r}))
        self.assertTrue(ok, msg)
        self.assertNotEqual(cfg['firewall']['reglas'][0]['id'], 'r_elegidapanel')
        self.assertRegex(cfg['firewall']['reglas'][0]['id'], r'^r_[0-9a-f]{8}$')

    def test_editar_regla_con_id_existente(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima()}))
        rid = cfg['firewall']['reglas'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(id=rid, nombre='Cambiada')}))
        self.assertTrue(ok, msg)
        self.assertEqual(len(cfg['firewall']['reglas']), 1)
        self.assertEqual(cfg['firewall']['reglas'][0]['nombre'], 'Cambiada')
        self.assertEqual(cfg['firewall']['version'], 3)

    def test_editar_regla_con_id_inexistente_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(id='r_00000000')}))
        self.assertFalse(ok)

    def test_version_incorrecta_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 99, 'regla': _regla_minima()}))
        self.assertFalse(ok)
        self.assertIn('cambió mientras editabas', msg)
        self.assertEqual(cfg['firewall']['reglas'], [])

    def test_limite_200_reglas(self):
        cfg = _cfg()
        cfg['firewall']['reglas'] = [
            _regla_minima(id='r_%08x' % i) for i in range(200)]
        cfg['firewall']['version'] = 5
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 5, 'regla': _regla_minima()}))
        self.assertFalse(ok)
        self.assertIn('200', msg)

    def test_posicion_inserta_en_el_lugar(self):
        cfg = _cfg()
        for i in range(3):
            peticiones.aplicar(cfg, _peticion(
                'fw_regla_guardar',
                {'version': cfg['firewall']['version'], 'regla': _regla_minima()}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': cfg['firewall']['version'], 'regla': _regla_minima(), 'posicion': 0}))
        self.assertTrue(ok, msg)
        self.assertEqual(len(cfg['firewall']['reglas']), 4)

    def test_nombre_largo_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(nombre='x' * 41)}))
        self.assertFalse(ok)

    def test_nombre_con_caracteres_no_admitidos_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(nombre='nombre;drop')}))
        self.assertFalse(ok)

    def test_nombre_vacio_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima(nombre='')}))
        self.assertFalse(ok)

    def test_nombre_valido_con_tildes_y_enye(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(nombre='Regla ñoño áéíóú')}))
        self.assertTrue(ok, msg)

    def test_nombre_de_solo_espacios_rechazado(self):
        # LOW (revisión Opus): un nombre de solo espacios no debe pasar.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima(nombre='   ')}))
        self.assertFalse(ok)

    def test_comentario_con_invisible_unicode_rechazado(self):
        # LOW: U+202E (RLO), U+2028 (separador de línea), U+0085 (NEL).
        for invisible in ('\u202e', '\u2028', '\u0085'):
            cfg = _cfg()
            ok, msg, _ = peticiones.aplicar(cfg, _peticion(
                'fw_regla_guardar',
                {'version': 1, 'regla': _regla_minima(
                    comentario='nota' + invisible + 'x')}))
            self.assertFalse(ok, 'debería rechazar U+%04X' % ord(invisible))

    def test_comentario_con_caracter_de_control_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(comentario='malo\x01bueno')}))
        self.assertFalse(ok)

    def test_comentario_largo_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(comentario='x' * 121)}))
        self.assertFalse(ok)

    def test_comentario_120_caracteres_aceptado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(comentario='x' * 120)}))
        self.assertTrue(ok, msg)

    def test_accion_invalida_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(accion='explotar')}))
        self.assertFalse(ok)

    def test_protocolo_invalido_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(protocolo='sctp')}))
        self.assertFalse(ok)

    def test_puertos_con_protocolo_cualquiera_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                protocolo='cualquiera', puertos=[{'desde': 80, 'hasta': 80}])}))
        self.assertFalse(ok)

    def test_puertos_con_protocolo_icmp_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                protocolo='icmp', puertos=[{'desde': 80, 'hasta': 80}])}))
        self.assertFalse(ok)

    def test_mas_de_15_puertos_rechazado(self):
        cfg = _cfg()
        puertos = [{'desde': i + 1, 'hasta': i + 1} for i in range(16)]
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(puertos=puertos)}))
        self.assertFalse(ok)
        self.assertIn('15', msg)

    def test_puerto_fuera_de_rango_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                puertos=[{'desde': 65536, 'hasta': 65536}])}))
        self.assertFalse(ok)

    def test_puerto_desde_mayor_que_hasta_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                puertos=[{'desde': 443, 'hasta': 80}])}))
        self.assertFalse(ok)

    def test_regla_contra_ip_del_router_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                destino={'tipo': 'ip', 'valor': '192.168.50.1'})}))
        self.assertFalse(ok)
        self.assertIn('router', msg.lower())

    def test_origen_contra_ip_del_router_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                origen={'tipo': 'ip', 'valor': '192.168.50.1'})}))
        self.assertFalse(ok)

    def test_bloquear_todo_sin_condiciones_rechazado(self):
        # destino red que contiene la LAN entera + bloquear + sin otra condición
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                origen={'tipo': 'cualquiera'},
                destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                protocolo='cualquiera', puertos=[])}))
        self.assertFalse(ok)
        self.assertIn('todos', msg.lower())

    def test_bloquear_todo_destino_cualquiera_rechazado(self):
        # MEDIUM-2: «cualquiera» equivale a 0.0.0.0/0.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                origen={'tipo': 'cualquiera'},
                destino={'tipo': 'cualquiera'},
                protocolo='cualquiera', puertos=[])}))
        self.assertFalse(ok)

    def test_rechazar_todo_sin_condiciones_rechazado(self):
        # MEDIUM-2: «rechazar» también corta el Internet de todos.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='rechazar',
                origen={'tipo': 'cualquiera'},
                destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                protocolo='cualquiera', puertos=[])}))
        self.assertFalse(ok)

    def test_bloquear_todo_origen_con_la_lan_entera_rechazado(self):
        # MEDIUM-2: un origen que contiene la LAN equivale a «cualquiera».
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                origen={'tipo': 'red', 'valor': '192.168.50.0/24'},
                destino={'tipo': 'cualquiera'},
                protocolo='cualquiera', puertos=[])}))
        self.assertFalse(ok)

    def test_bloquear_todo_origen_que_contiene_la_lan_rechazado(self):
        # MEDIUM-2: una red origen mayor que la LAN (que la contiene) también.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                origen={'tipo': 'red', 'valor': '192.168.0.0/16'},
                destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                protocolo='cualquiera', puertos=[])}))
        self.assertFalse(ok)

    def test_rechazar_todo_origen_con_la_lan_entera_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='rechazar',
                origen={'tipo': 'red', 'valor': '192.168.50.0/24'},
                destino={'tipo': 'cualquiera'},
                protocolo='cualquiera', puertos=[])}))
        self.assertFalse(ok)

    def test_bloquear_todo_con_origen_concreto_aceptado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                origen={'tipo': 'mac', 'valor': 'aa:bb:cc:dd:ee:01'},
                destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                protocolo='cualquiera', puertos=[])}))
        self.assertTrue(ok, msg)

    def test_bloquear_todo_con_protocolo_concreto_aceptado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                protocolo='tcp', puertos=[])}))
        self.assertTrue(ok, msg)

    def test_bloquear_todo_con_puertos_aceptado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                accion='bloquear',
                destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                protocolo='tcp', puertos=[{'desde': 443, 'hasta': 443}])}))
        self.assertTrue(ok, msg)

    def test_origen_fuera_de_lan_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                origen={'tipo': 'ip', 'valor': '10.0.0.99'})}))
        self.assertFalse(ok)

    def test_mac_solo_como_origen(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                destino={'tipo': 'mac', 'valor': 'aa:bb:cc:dd:ee:01'})}))
        self.assertFalse(ok)

    def test_campo_extra_en_regla_rechazado(self):
        cfg = _cfg()
        r = _regla_minima()
        r['extra'] = 1
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': r}))
        self.assertFalse(ok)

    def test_config_no_se_toca_si_falla(self):
        cfg = _cfg()
        antes = copy.deepcopy(cfg)
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima(nombre='')}))
        self.assertEqual(cfg, antes)

    def test_origen_tipo_invalido_rechazado(self):
        # LOW: origen "" o destino 0 no deben convertirse en «cualquiera».
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(origen='')}))
        self.assertFalse(ok)
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(destino=0)}))
        self.assertFalse(ok)

    def test_puertos_tipo_invalido_rechazado(self):
        # LOW: puertos False no debe convertirse en [].
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(puertos=False)}))
        self.assertFalse(ok)

    def test_posicion_al_editar_no_se_ignora(self):
        # LOW: al editar con «posicion», la regla debe moverse a esa posición.
        cfg = _cfg()
        for i in range(3):
            peticiones.aplicar(cfg, _peticion(
                'fw_regla_guardar',
                {'version': cfg['firewall']['version'], 'regla': _regla_minima()}))
        ids = [r['id'] for r in cfg['firewall']['reglas']]
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': cfg['firewall']['version'],
             'regla': _regla_minima(id=ids[2], nombre='Movida'),
             'posicion': 0}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['reglas'][0]['nombre'], 'Movida')


class TestFwReglaEliminar(unittest.TestCase):
    def test_eliminar_regla_existente(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima()}))
        rid = cfg['firewall']['reglas'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_eliminar', {'version': 2, 'id': rid}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['reglas'], [])
        self.assertEqual(cfg['firewall']['version'], 3)

    def test_eliminar_regla_inexistente_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_eliminar', {'version': 1, 'id': 'r_00000000'}))
        self.assertFalse(ok)

    def test_eliminar_sin_version_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_eliminar', {'id': 'r_00000000'}))
        self.assertFalse(ok)


class TestFwReglaMover(unittest.TestCase):
    def _cfg_con_tres(self):
        cfg = _cfg()
        ids = []
        for i in range(3):
            peticiones.aplicar(cfg, _peticion(
                'fw_regla_guardar',
                {'version': cfg['firewall']['version'], 'regla': _regla_minima()}))
            ids.append(cfg['firewall']['reglas'][-1]['id'])
        return cfg, ids

    def test_mover_a_primera_posicion(self):
        cfg, ids = self._cfg_con_tres()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_mover', {'version': cfg['firewall']['version'],
                               'id': ids[2], 'posicion': 0}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['reglas'][0]['id'], ids[2])

    def test_mover_a_ultima_posicion(self):
        cfg, ids = self._cfg_con_tres()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_mover', {'version': cfg['firewall']['version'],
                               'id': ids[0], 'posicion': 2}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['reglas'][2]['id'], ids[0])

    def test_mover_id_inexistente_rechazado(self):
        cfg, ids = self._cfg_con_tres()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_mover', {'version': cfg['firewall']['version'],
                               'id': 'r_00000000', 'posicion': 0}))
        self.assertFalse(ok)

    def test_mover_posicion_negativa_rechazada(self):
        cfg, ids = self._cfg_con_tres()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_mover', {'version': cfg['firewall']['version'],
                               'id': ids[0], 'posicion': -1}))
        self.assertFalse(ok)

    def test_mover_en_lista_vacia_mensaje_claro(self):
        # LOW: con la lista vacía no debe responder «entre 0 y -1».
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_mover', {'version': 1, 'id': 'r_00000000', 'posicion': 0}))
        self.assertFalse(ok)
        self.assertNotIn('-1', msg)

    def test_mover_posicion_fuera_de_rango_rechazada(self):
        cfg, ids = self._cfg_con_tres()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_mover', {'version': cfg['firewall']['version'],
                               'id': ids[0], 'posicion': 99}))
        self.assertFalse(ok)


class TestFwReglaActivar(unittest.TestCase):
    def test_desactivar_regla(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima()}))
        rid = cfg['firewall']['reglas'][0]['id']
        self.assertTrue(cfg['firewall']['reglas'][0]['habilitada'])
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_activar', {'version': 2, 'id': rid, 'habilitada': False}))
        self.assertTrue(ok, msg)
        self.assertFalse(cfg['firewall']['reglas'][0]['habilitada'])
        self.assertEqual(cfg['firewall']['version'], 3)

    def test_activar_regla(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima(habilitada=False)}))
        rid = cfg['firewall']['reglas'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_activar', {'version': 2, 'id': rid, 'habilitada': True}))
        self.assertTrue(ok, msg)
        self.assertTrue(cfg['firewall']['reglas'][0]['habilitada'])

    def test_activar_id_inexistente_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_activar', {'version': 1, 'id': 'r_00000000', 'habilitada': True}))
        self.assertFalse(ok)

    def test_activar_sin_habilitada_rechazada(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar', {'version': 1, 'regla': _regla_minima()}))
        rid = cfg['firewall']['reglas'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_activar', {'version': 2, 'id': rid}))
        self.assertFalse(ok)


class TestFwGrupoGuardar(unittest.TestCase):
    def test_crear_grupo_sin_id_genera_id_g_mas_8_hex(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo()}))
        self.assertTrue(ok, msg)
        self.assertEqual(len(cfg['firewall']['grupos']), 1)
        gid = cfg['firewall']['grupos'][0]['id']
        self.assertRegex(gid, r'^g_[0-9a-f]{8}$')
        self.assertEqual(cfg['firewall']['version'], 2)

    def test_crear_grupo_no_toma_id_del_panel(self):
        cfg = _cfg()
        g = _grupo_minimo()
        g['id'] = 'g_elegidapanel'
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': g}))
        self.assertTrue(ok, msg)
        self.assertNotEqual(cfg['firewall']['grupos'][0]['id'], 'g_elegidapanel')

    def test_editar_grupo_con_id_existente(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo()}))
        gid = cfg['firewall']['grupos'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 2, 'grupo': _grupo_minimo(id=gid, nombre='Cambiado')}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['grupos'][0]['nombre'], 'Cambiado')

    def test_limite_50_grupos(self):
        cfg = _cfg()
        cfg['firewall']['grupos'] = [
            _grupo_minimo(id='g_%08x' % i) for i in range(50)]
        cfg['firewall']['version'] = 3
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 3, 'grupo': _grupo_minimo()}))
        self.assertFalse(ok)
        self.assertIn('50', msg)

    def test_limite_256_miembros(self):
        cfg = _cfg()
        miembros = ['192.168.50.%d' % (i + 2) for i in range(257)]
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(tipo='ip', miembros=miembros)}))
        self.assertFalse(ok)
        self.assertIn('256', msg)

    def test_miembros_mac_validos(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='mac', miembros=['aa:bb:cc:dd:ee:01'])}))
        self.assertTrue(ok, msg)

    def test_miembro_mac_invalida_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='mac', miembros=['no-mac'])}))
        self.assertFalse(ok)

    def test_miembro_ip_invalida_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['no-ip'])}))
        self.assertFalse(ok)

    def test_tipo_invalido_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(tipo='raro')}))
        self.assertFalse(ok)

    def test_nombre_invalido_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(nombre='x' * 41)}))
        self.assertFalse(ok)

    def test_version_incorrecta_rechazada(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 99, 'grupo': _grupo_minimo()}))
        self.assertFalse(ok)
        self.assertIn('cambió mientras editabas', msg)

    def test_version_no_entera_en_config_se_normaliza(self):
        # LOW: si firewall.version llega como cadena en router.json, el
        # firewall no debe quedar bloqueado para siempre.
        cfg = _cfg()
        cfg['firewall']['version'] = '3'
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 3, 'grupo': _grupo_minimo()}))
        self.assertTrue(ok, msg)

    def test_miembros_duplicados_se_eliminan(self):
        # LOW: tras normalizar (minúsculas, - por :) pueden quedar duplicados.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='mac',
                miembros=['aa:bb:cc:dd:ee:01', 'AA-BB-CC-DD-EE-01'])}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['grupos'][0]['miembros'],
                         ['aa:bb:cc:dd:ee:01'])

    def test_colision_de_id_se_genera_de_nuevo(self):
        # LOW: si la id generada ya existe, se genera otra.
        cfg = _cfg()
        ids_generadas = iter(['r_aaaaaaaa', 'r_aaaaaaaa', 'r_bbbbbbbb'])
        original = peticiones._generar_id_regla
        peticiones._generar_id_regla = lambda: next(ids_generadas)
        try:
            cfg['firewall']['reglas'] = [
                {'id': 'r_aaaaaaaa', 'nombre': 'Previa', 'habilitada': True,
                 'accion': 'bloquear', 'origen': {'tipo': 'cualquiera'},
                 'destino': {'tipo': 'cualquiera'}, 'protocolo': 'tcp',
                 'puertos': [], 'registrar': False, 'comentario': ''}]
            cfg['firewall']['version'] = 2
            ok, msg, _ = peticiones.aplicar(cfg, _peticion(
                'fw_regla_guardar',
                {'version': 2, 'regla': _regla_minima()}))
            self.assertTrue(ok, msg)
            ids = [r['id'] for r in cfg['firewall']['reglas']]
            self.assertEqual(len(ids), len(set(ids)), 'ids duplicadas')
            self.assertIn('r_bbbbbbbb', ids)
        finally:
            peticiones._generar_id_regla = original

    def test_miembro_ip_grupo_fuera_de_lan_rechazado(self):
        # LOW/MEDIUM-A: la IP del router nunca es un miembro válido. Los
        # miembros fuera de la LAN SÍ se admiten al crear el grupo (puede
        # usarse como destino); la restricción de LAN se aplica al usarlo
        # como origen — ver TestGrupoIpPublicoMEDIUMA.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['10.0.0.99'])}))
        self.assertTrue(ok, msg)   # MEDIUM-A: destino admite públicos
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['192.168.50.1'])}))
        self.assertFalse(ok)       # la IP del router, nunca

    def test_cambiar_tipo_de_grupo_usado_como_destino_rechazado(self):
        # HIGH-3 (revisión Opus 2026-10-12): un grupo tipo ip usado como
        # destino no puede cambiar a mac — nft_conf lanza ValueError ("el
        # destino con grupo exige un grupo tipo ip") y el firewall se congela.
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['192.168.50.10'])}))
        gid = cfg['firewall']['grupos'][0]['id']
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                destino={'tipo': 'grupo', 'valor': gid})}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 3, 'grupo': _grupo_minimo(
                id=gid, tipo='mac', miembros=['aa:bb:cc:dd:ee:01'])}))
        self.assertFalse(ok)
        self.assertIn('destino', msg.lower())
        # El grupo sigue siendo tipo ip, intacto.
        self.assertEqual(cfg['firewall']['grupos'][0]['tipo'], 'ip')

    def test_cambiar_tipo_de_grupo_usado_como_origen_permitido(self):
        # El origen sí admite mac o ip; cambiar el tipo de un grupo que sólo
        # se usa como origen no rompe nft_conf.
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['192.168.50.10'])}))
        gid = cfg['firewall']['grupos'][0]['id']
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                origen={'tipo': 'grupo', 'valor': gid})}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 3, 'grupo': _grupo_minimo(
                id=gid, tipo='mac', miembros=['aa:bb:cc:dd:ee:01'])}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['grupos'][0]['tipo'], 'mac')


class TestFwGrupoEliminar(unittest.TestCase):
    def test_eliminar_grupo_no_usado(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo()}))
        gid = cfg['firewall']['grupos'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_eliminar', {'version': 2, 'id': gid}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['grupos'], [])

    def test_eliminar_grupo_en_uso_rechazado(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo(tipo='ip')}))
        gid = cfg['firewall']['grupos'][0]['id']
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                origen={'tipo': 'grupo', 'valor': gid})}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_eliminar', {'version': 3, 'id': gid}))
        self.assertFalse(ok)
        self.assertIn('grupo', msg.lower())

    def test_eliminar_grupo_en_uso_como_destino_rechazado(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo(tipo='ip')}))
        gid = cfg['firewall']['grupos'][0]['id']
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                destino={'tipo': 'grupo', 'valor': gid})}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_eliminar', {'version': 3, 'id': gid}))
        self.assertFalse(ok)

    def test_eliminar_grupo_inexistente_rechazado(self):
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_eliminar', {'version': 1, 'id': 'g_00000000'}))
        self.assertFalse(ok)


class TestAccionesRegistradas(unittest.TestCase):
    def test_las_seis_acciones_fw_estan_en_acciones(self):
        for a in ('fw_regla_guardar', 'fw_regla_eliminar', 'fw_regla_mover',
                  'fw_regla_activar', 'fw_grupo_guardar', 'fw_grupo_eliminar'):
            self.assertIn(a, peticiones.ACCIONES, 'falta la acción %s' % a)

    def test_version_optimista_en_las_seis(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo()}))
        gid = cfg['firewall']['grupos'][0]['id']
        for accion, datos in (
                ('fw_regla_guardar', {'version': 1, 'regla': _regla_minima()}),
                ('fw_regla_eliminar', {'version': 1, 'id': 'r_00000000'}),
                ('fw_regla_mover', {'version': 1, 'id': 'r_00000000', 'posicion': 0}),
                ('fw_regla_activar', {'version': 1, 'id': 'r_00000000', 'habilitada': True}),
                ('fw_grupo_guardar', {'version': 1, 'grupo': _grupo_minimo()}),
                ('fw_grupo_eliminar', {'version': 1, 'id': gid})):
            ok, msg, _ = peticiones.aplicar(cfg, _peticion(accion, datos))
            self.assertFalse(ok, 'la versión 1 ya no es válida para %s' % accion)
            self.assertIn('cambió mientras editabas', msg)


if __name__ == '__main__':
    unittest.main()


class TestGrupoIpPublicoMEDIUMA(unittest.TestCase):
    """MEDIUM-A (segunda revisión Opus 2026-10-12): los grupos ip deben
    admitir IPs/redes públicas cuando se usan como DESTINO; la restricción
    a la LAN sólo aplica a un grupo usado como ORIGEN — se valida al
    usarlo en una regla y al editar un grupo ya usado como origen."""

    def test_grupo_ip_destino_admite_ips_publicas(self):
        # Un grupo ip que se usa como destino puede tener miembros públicos.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['8.8.8.8', '1.1.1.1'])}))
        self.assertTrue(ok, msg)
        gid = cfg['firewall']['grupos'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                destino={'tipo': 'grupo', 'valor': gid})}))
        self.assertTrue(ok, msg)

    def test_grupo_ip_redes_publicas_como_destino(self):
        # También una red pública como destino (tipo red) pasa.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 1, 'regla': _regla_minima(
                destino={'tipo': 'red', 'valor': '8.8.8.0/24'})}))
        self.assertTrue(ok, msg)

    def test_grupo_ip_origen_con_ip_publica_rechazado_al_usarlo(self):
        # El mismo grupo, usado como ORIGEN, exige miembros en la LAN.
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['8.8.8.8'])}))
        gid = cfg['firewall']['grupos'][0]['id']
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                origen={'tipo': 'grupo', 'valor': gid})}))
        self.assertFalse(ok)
        self.assertIn('lan', msg.lower())

    def test_editar_grupo_usado_como_origen_con_ip_publica_rechazado(self):
        # Un grupo ya usado como ORIGEN no puede ganar miembros fuera de la LAN.
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['192.168.50.10'])}))
        gid = cfg['firewall']['grupos'][0]['id']
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                origen={'tipo': 'grupo', 'valor': gid})}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 3, 'grupo': _grupo_minimo(
                id=gid, tipo='ip', miembros=['192.168.50.10', '8.8.8.8'])}))
        self.assertFalse(ok)
        self.assertIn('lan', msg.lower())

    def test_editar_grupo_usado_como_destino_con_ip_publica_admitido(self):
        # Un grupo usado sólo como DESTINO sí admite miembros públicos al editar.
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['192.168.50.10'])}))
        gid = cfg['firewall']['grupos'][0]['id']
        peticiones.aplicar(cfg, _peticion(
            'fw_regla_guardar',
            {'version': 2, 'regla': _regla_minima(
                destino={'tipo': 'grupo', 'valor': gid})}))
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 3, 'grupo': _grupo_minimo(
                id=gid, tipo='ip', miembros=['8.8.8.8'])}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['firewall']['grupos'][0]['miembros'], ['8.8.8.8'])

    def test_crear_grupo_con_ip_publica_sin_regla_admitido(self):
        # Un grupo nuevo (aún sin usar) admite cualquier IPv4 válida salvo
        # la del router; la restricción de LAN se aplica al usarlo como origen.
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['203.0.113.7'])}))
        self.assertTrue(ok, msg)

    def test_ip_del_router_siempre_rechazada_como_miembro(self):
        # La IP del router nunca es un miembro válido (origen o destino).
        cfg = _cfg()
        ok, msg, _ = peticiones.aplicar(cfg, _peticion(
            'fw_grupo_guardar',
            {'version': 1, 'grupo': _grupo_minimo(
                tipo='ip', miembros=['192.168.50.1'])}))
        self.assertFalse(ok)
