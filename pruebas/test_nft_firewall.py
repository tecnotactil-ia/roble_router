#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias de la generación nft del firewall con reglas propias
(core/nft_conf.py): sets de grupos, reglas de usuario dentro de `reenvio`
en el lugar y orden del plan, validación de valores en defensa en
profundidad, y `nft -c -f` cuando el binario está disponible.

Uso:  python3 -m unittest pruebas/test_nft_firewall.py -v
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import nft_conf  # noqa: E402


def _cfg(firewall=None):
    return {
        'lan': {'interfaz': 'lan0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'},
        'dhcp': {'inicio': '192.168.50.100', 'fin': '192.168.50.200', 'lease': '12h'},
        'dns': ['1.1.1.1', '9.9.9.9'],
        'dominio': 'home.arpa',
        'reservas': [],
        'bloqueo': {'forzar_dns': False, 'bloquear_doh': False},
        'firewall': firewall if firewall is not None else {'version': 1, 'grupos': [], 'reglas': []},
    }


def _regla(**campos):
    base = {
        'id': 'r_ab12cd34', 'nombre': 'Regla de prueba', 'habilitada': True,
        'accion': 'bloquear',
        'origen': {'tipo': 'cualquiera'}, 'destino': {'tipo': 'cualquiera'},
        'protocolo': 'tcp', 'puertos': [], 'registrar': False, 'comentario': '',
    }
    base.update(campos)
    return base


def _grupo(**campos):
    base = {'id': 'g_ab12cd34', 'nombre': 'Grupo', 'tipo': 'mac', 'miembros': []}
    base.update(campos)
    return base


def _indices_reenvio(texto):
    """Devuelve (inicio, fin) de la cadena reenvio dentro del texto generado."""
    ini = texto.index('chain reenvio')
    fin = texto.index('\n  }', ini)
    return ini, fin


class TestGruposSets(unittest.TestCase):
    def test_sin_grupos_no_hay_sets_de_grupo(self):
        texto = nft_conf.generar(_cfg())
        self.assertNotIn('grp_', texto)

    def test_grupo_mac_genera_set_ether_addr_con_miembros(self):
        fw = {'version': 1, 'grupos': [
            {'id': 'g_ab12cd34', 'nombre': 'Niños', 'tipo': 'mac',
             'miembros': ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02']}],
            'reglas': []}
        texto = nft_conf.generar(_cfg(fw))
        self.assertIn('set grp_g_ab12cd34', texto)
        self.assertIn('type ether_addr', texto)
        self.assertIn('aa:bb:cc:dd:ee:01', texto)
        self.assertIn('aa:bb:cc:dd:ee:02', texto)

    def test_grupo_ip_genera_set_ipv4_addr(self):
        fw = {'version': 1, 'grupos': [
            {'id': 'g_cd34ef56', 'nombre': 'Servidores', 'tipo': 'ip',
             'miembros': ['192.168.50.10', '192.168.50.11']}],
            'reglas': []}
        texto = nft_conf.generar(_cfg(fw))
        self.assertIn('set grp_g_cd34ef56', texto)
        self.assertIn('type ipv4_addr', texto)
        self.assertIn('192.168.50.10', texto)

    def test_grupo_vacio_genera_set_sin_elements(self):
        fw = {'version': 1, 'grupos': [
            {'id': 'g_ab12cd34', 'nombre': 'Vacio', 'tipo': 'ip', 'miembros': []}],
            'reglas': []}
        texto = nft_conf.generar(_cfg(fw))
        self.assertIn('set grp_g_ab12cd34', texto)
        self.assertNotIn('elements', texto)

    def test_set_de_grupo_sin_flags_dinamicos(self):
        # El plan dice «flags vacíos»: los sets de grupos son estáticos,
        # poblados en la misma transacción que crea la tabla.
        fw = {'version': 1, 'grupos': [
            {'id': 'g_ab12cd34', 'nombre': 'G', 'tipo': 'ip',
             'miembros': ['192.168.50.10']}],
            'reglas': []}
        texto = nft_conf.generar(_cfg(fw))
        ini = texto.index('set grp_g_ab12cd34')
        bloque = texto[ini:texto.index('}', ini)]
        self.assertNotIn('dynamic', bloque)
        self.assertNotIn('timeout', bloque)


class TestOrdenReglas(unittest.TestCase):
    def test_regla_de_usuario_va_despues_de_doh_antes_del_accept(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(id='r_11111111', accion='bloquear')]}
        texto = nft_conf.generar(_cfg(fw))
        ini, fin = _indices_reenvio(texto)
        cadena = texto[ini:fin]
        i_fw = cadena.index('fw:r_11111111')
        i_est = cadena.index('ct state established')
        i_inv = cadena.index('ct state invalid')
        i_gws = cadena.index('wan_gws')
        i_acc = cadena.index('oifname @wan_ifs accept')
        self.assertGreater(i_fw, i_est, 'la regla va después de established')
        self.assertGreater(i_fw, i_inv, 'la regla va después de invalid')
        self.assertGreater(i_fw, i_gws, 'la regla va después de wan_gws')
        self.assertLess(i_fw, i_acc, 'la regla va antes del accept LAN→WAN')

    def test_regla_de_usuario_va_despues_del_bloqueo_dot(self):
        cfg = _cfg({'version': 1, 'grupos': [], 'reglas': [
            _regla(id='r_11111111', accion='bloquear')]})
        cfg['bloqueo'] = {'forzar_dns': False, 'bloquear_doh': True}
        texto = nft_conf.generar(cfg)
        ini, fin = _indices_reenvio(texto)
        cadena = texto[ini:fin]
        self.assertIn('dport 853', cadena)
        self.assertGreater(cadena.index('fw:r_11111111'), cadena.index('dport 853'))

    def test_reglas_respetan_el_orden_de_la_lista(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(id='r_aaaaaaaa'),
            _regla(id='r_bbbbbbbb'),
            _regla(id='r_cccccccc')]}
        texto = nft_conf.generar(_cfg(fw))
        ini, fin = _indices_reenvio(texto)
        cadena = texto[ini:fin]
        self.assertLess(cadena.index('fw:r_aaaaaaaa'), cadena.index('fw:r_bbbbbbbb'))
        self.assertLess(cadena.index('fw:r_bbbbbbbb'), cadena.index('fw:r_cccccccc'))

    def test_regla_deshabilitada_no_se_genera(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(id='r_11111111', habilitada=False),
            _regla(id='r_22222222', habilitada=True)]}
        texto = nft_conf.generar(_cfg(fw))
        self.assertNotIn('fw:r_11111111', texto)
        self.assertIn('fw:r_22222222', texto)


class TestFormatoRegla(unittest.TestCase):
    def _cadena(self, regla, grupos=None):
        fw = {'version': 1, 'grupos': grupos or [], 'reglas': [regla]}
        texto = nft_conf.generar(_cfg(fw))
        ini, fin = _indices_reenvio(texto)
        return texto[ini:fin]

    def test_todas_las_reglas_llevan_comment_fw_id(self):
        cadena = self._cadena(_regla(id='r_deadbeef'))
        self.assertIn('comment "fw:r_deadbeef"', cadena)

    def test_todas_las_reglas_llevan_contador(self):
        cadena = self._cadena(_regla(id='r_deadbeef'))
        self.assertIn('counter', cadena)

    def test_permitir_genera_accept(self):
        cadena = self._cadena(_regla(id='r_00000001', accion='permitir'))
        linea = [l for l in cadena.splitlines() if 'fw:r_00000001' in l][0]
        self.assertIn('accept', linea)
        self.assertNotIn('drop', linea)
        self.assertNotIn('reject', linea)

    def test_permitir_lleva_ip_saddr_red_y_oifname_wan_ifs(self):
        # MEDIUM-1 (revisión Opus 2026-10-12): «permitir» no debe saltarse las
        # condiciones del accept genérico LAN→WAN (ip saddr {red} oifname
        # @wan_ifs): sin ellas deja pasar a interfaces que no son WAN vivas,
        # sin NAT y con orígenes falsificados.
        cadena = self._cadena(_regla(id='r_00000011', accion='permitir'))
        linea = [l for l in cadena.splitlines() if 'fw:r_00000011' in l][0]
        self.assertIn('ip saddr 192.168.50.0/24', linea)
        self.assertIn('oifname @wan_ifs', linea)

    def test_bloquear_genera_drop(self):
        cadena = self._cadena(_regla(id='r_00000002', accion='bloquear'))
        self.assertIn('drop', cadena)
        self.assertNotIn('accept comment', cadena)

    def test_rechazar_tcp_genera_reject_con_tcp_reset(self):
        cadena = self._cadena(_regla(id='r_00000003', accion='rechazar', protocolo='tcp'))
        self.assertIn('reject with tcp reset', cadena)

    def test_rechazar_udp_genera_reject_con_icmpx(self):
        cadena = self._cadena(_regla(id='r_00000004', accion='rechazar', protocolo='udp'))
        self.assertIn('reject with icmpx admin-prohibited', cadena)

    def test_rechazar_tcp_udp_una_linea_por_protocolo_sin_conjunto(self):
        # HIGH-2 (revisión Opus 2026-10-12): con rechazar + tcp_udp no puede
        # quedar «meta l4proto { tcp, udp }» junto a «reject with tcp reset»
        # (nft: "you cannot use tcp reset with this protocol"). Una línea por
        # protocolo concreto.
        cadena = self._cadena(_regla(id='r_00000041', accion='rechazar', protocolo='tcp_udp'))
        self.assertNotIn('{ tcp, udp }', cadena)
        self.assertIn('reject with tcp reset', cadena)
        self.assertIn('reject with icmpx admin-prohibited', cadena)
        lineas = [l for l in cadena.splitlines() if 'fw:r_00000041' in l]
        self.assertEqual(len(lineas), 2)
        linea_tcp = next(l for l in lineas if 'tcp reset' in l)
        linea_udp = next(l for l in lineas if 'icmpx' in l)
        self.assertIn('meta l4proto tcp', linea_tcp)
        self.assertNotIn('meta l4proto udp', linea_tcp)
        self.assertNotIn('meta l4proto {', linea_tcp)
        self.assertIn('meta l4proto udp', linea_udp)
        self.assertNotIn('meta l4proto tcp', linea_udp)
        self.assertNotIn('meta l4proto {', linea_udp)

    def test_rechazar_tcp_udp_con_puertos_usa_dport_concreto(self):
        # HIGH-2: los puertos de la línea tcp deben ser «tcp dport» y los de
        # la línea udp «udp dport», nunca «th dport» (genérico).
        cadena = self._cadena(_regla(
            id='r_00000042', accion='rechazar', protocolo='tcp_udp',
            puertos=[{'desde': 53, 'hasta': 53}]))
        self.assertNotIn('th dport', cadena)
        self.assertNotIn('{ tcp, udp }', cadena)
        lineas = [l for l in cadena.splitlines() if 'fw:r_00000042' in l]
        self.assertEqual(len(lineas), 2)
        linea_tcp = next(l for l in lineas if 'tcp reset' in l)
        linea_udp = next(l for l in lineas if 'icmpx' in l)
        self.assertIn('tcp dport { 53 }', linea_tcp)
        self.assertNotIn('udp dport', linea_tcp)
        self.assertIn('udp dport { 53 }', linea_udp)
        self.assertNotIn('tcp dport', linea_udp)

    def test_registrar_true_anade_limit_y_log(self):
        cadena = self._cadena(_regla(id='r_00000005', registrar=True))
        self.assertIn('limit rate 5/minute', cadena)
        self.assertIn('log prefix "fw-r_00000005 "', cadena)

    def test_registrar_false_no_anade_log(self):
        cadena = self._cadena(_regla(id='r_00000006', registrar=False))
        linea = [l for l in cadena.splitlines() if 'fw:r_00000006' in l][0]
        self.assertNotIn('log prefix', linea)

    def test_registrar_log_va_en_linea_propia_antes_del_veredicto(self):
        cadena = self._cadena(_regla(id='r_00000007', registrar=True, accion='bloquear'))
        lineas = cadena.splitlines()
        i_log = [i for i, l in enumerate(lineas) if 'log prefix "fw-r_00000007 "' in l]
        i_drop = [i for i, l in enumerate(lineas) if 'fw:r_00000007' in l and ' drop' in l]
        self.assertEqual(len(i_log), 1)
        self.assertEqual(len(i_drop), 1)
        self.assertLess(i_log[0], i_drop[0], 'el log va antes del veredicto')

    def test_limit_nunca_comparte_linea_con_el_veredicto(self):
        # `limit` es una condición: junto al veredicto, pasado el límite el
        # paquete se saltaría el drop/reject y caería en el accept genérico.
        for accion in ('bloquear', 'rechazar', 'permitir'):
            for proto in ('tcp', 'udp', 'tcp_udp', 'cualquiera'):
                cadena = self._cadena(_regla(id='r_00000008', registrar=True, accion=accion, protocolo=proto))
                for l in cadena.splitlines():
                    if 'fw:r_00000008' in l or 'fw-r_00000008' in l:
                        self.assertFalse('limit rate' in l and
                                         any(v in l for v in (' drop', ' accept', ' reject')),
                                         l)


class TestMatchesRegla(unittest.TestCase):
    def _linea(self, regla, grupos=None):
        fw = {'version': 1, 'grupos': grupos or [], 'reglas': [regla]}
        texto = nft_conf.generar(_cfg(fw))
        ini, fin = _indices_reenvio(texto)
        return texto[ini:fin]

    def test_origen_mac_genera_ether_saddr(self):
        cadena = self._linea(_regla(origen={'tipo': 'mac', 'valor': 'aa:bb:cc:dd:ee:01'}))
        self.assertIn('ether saddr aa:bb:cc:dd:ee:01', cadena)

    def test_origen_ip_genera_ip_saddr(self):
        cadena = self._linea(_regla(origen={'tipo': 'ip', 'valor': '192.168.50.100'}))
        self.assertIn('ip saddr 192.168.50.100', cadena)

    def test_origen_red_genera_ip_saddr_cidr(self):
        cadena = self._linea(_regla(origen={'tipo': 'red', 'valor': '192.168.50.0/24'}))
        self.assertIn('ip saddr 192.168.50.0/24', cadena)

    def test_origen_cualquiera_no_fija_saddr(self):
        cadena = self._linea(_regla(origen={'tipo': 'cualquiera'}))
        linea = [l for l in cadena.splitlines() if 'fw:r_ab12cd34' in l][0]
        self.assertNotIn('ip saddr', linea)
        self.assertNotIn('ether saddr', linea)

    def test_destino_ip_genera_ip_daddr(self):
        cadena = self._linea(_regla(destino={'tipo': 'ip', 'valor': '10.0.0.1'}))
        self.assertIn('ip daddr 10.0.0.1', cadena)

    def test_destino_red_genera_ip_daddr_cidr(self):
        cadena = self._linea(_regla(destino={'tipo': 'red', 'valor': '0.0.0.0/0'}))
        self.assertIn('ip daddr 0.0.0.0/0', cadena)

    def test_origen_grupo_mac_usa_el_set(self):
        grupos = [{'id': 'g_ab12cd34', 'nombre': 'G', 'tipo': 'mac',
                   'miembros': ['aa:bb:cc:dd:ee:01']}]
        cadena = self._linea(_regla(origen={'tipo': 'grupo', 'valor': 'g_ab12cd34'}), grupos)
        self.assertIn('ether saddr @grp_g_ab12cd34', cadena)

    def test_destino_grupo_ip_usa_el_set(self):
        grupos = [{'id': 'g_cd34ef56', 'nombre': 'G', 'tipo': 'ip',
                   'miembros': ['192.168.50.10']}]
        cadena = self._linea(_regla(destino={'tipo': 'grupo', 'valor': 'g_cd34ef56'}), grupos)
        self.assertIn('ip daddr @grp_g_cd34ef56', cadena)

    def test_protocolo_tcp(self):
        cadena = self._linea(_regla(protocolo='tcp'))
        self.assertIn('meta l4proto tcp', cadena)

    def test_protocolo_udp(self):
        cadena = self._linea(_regla(protocolo='udp'))
        self.assertIn('meta l4proto udp', cadena)

    def test_protocolo_tcp_udp(self):
        cadena = self._linea(_regla(protocolo='tcp_udp'))
        self.assertIn('meta l4proto { tcp, udp }', cadena)

    def test_protocolo_icmp(self):
        # HIGH-1 (revisión Opus 2026-10-12): el nombre de protocolo de nft
        # es «icmp», no «ipv4-icmp» (ese no está en /etc/protocols y nft -c
        # responde "Could not resolve protocol name").
        cadena = self._linea(_regla(protocolo='icmp'))
        self.assertIn('meta l4proto icmp', cadena)
        self.assertNotIn('ipv4-icmp', cadena)

    def test_puertos_tcp(self):
        cadena = self._linea(_regla(
            protocolo='tcp',
            puertos=[{'desde': 80, 'hasta': 80}, {'desde': 443, 'hasta': 443}]))
        self.assertIn('tcp dport { 80, 443 }', cadena)

    def test_puertos_con_rango(self):
        cadena = self._linea(_regla(
            protocolo='tcp',
            puertos=[{'desde': 8000, 'hasta': 8010}]))
        self.assertIn('tcp dport { 8000-8010 }', cadena)

    def test_todas_las_reglas_de_reenvio_del_usuario_llevan_iifname_lan(self):
        cadena = self._linea(_regla(id='r_deadbeef'))
        linea = [l for l in cadena.splitlines() if 'fw:r_deadbeef' in l][0]
        self.assertIn('iifname "lan0"', linea)


class TestValidacionDefensaProfundidad(unittest.TestCase):
    """nft_conf valida TODO otra vez: ninguna cadena sin validar entra al .nft."""

    def test_mac_invalida_rechazada(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(origen={'tipo': 'mac', 'valor': 'no-es-una-mac'})]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_mac_con_caracteres_peligrosos_rechazada(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(origen={'tipo': 'mac', 'valor': 'aa:bb:cc:dd:ee:01; drop'})]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_ipv4_invalida_rechazada(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(destino={'tipo': 'ip', 'valor': '999.999.999.999'})]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_cidr_invalido_rechazado(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(destino={'tipo': 'red', 'valor': '192.168.50.0/99'})]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_puerto_fuera_de_rango_rechazado(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(puertos=[{'desde': 0, 'hasta': 80}])]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_puerto_hasta_menor_que_desde_rechazado(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(puertos=[{'desde': 443, 'hasta': 80}])]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_id_regla_invalida_rechazada(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(id='r_malicioso; drop')]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_id_grupo_invalida_rechazada(self):
        fw = {'version': 1, 'grupos': [
            {'id': 'g_x; flush ruleset', 'nombre': 'G', 'tipo': 'ip',
             'miembros': []}], 'reglas': []}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_miembro_mac_invalida_en_grupo_rechazada(self):
        fw = {'version': 1, 'grupos': [
            {'id': 'g_ab12cd34', 'nombre': 'G', 'tipo': 'mac',
             'miembros': ['zz:zz:zz:zz:zz:zz']}], 'reglas': []}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_miembro_ip_invalida_en_grupo_rechazada(self):
        fw = {'version': 1, 'grupos': [
            {'id': 'g_ab12cd34', 'nombre': 'G', 'tipo': 'ip',
             'miembros': ['no-ip']}], 'reglas': []}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_valor_de_grupo_desconocido_rechazado(self):
        # La regla apunta a un grupo que no existe en la lista de grupos.
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(origen={'tipo': 'grupo', 'valor': 'g_noexiste'})]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_tipo_origen_desconocido_rechazado(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(origen={'tipo': 'raro', 'valor': 'x'})]}
        with self.assertRaises(ValueError):
            nft_conf.generar(_cfg(fw))

    def test_comentario_no_aparece_en_el_texto_nft(self):
        # El comentario del admin no se interpola en el .nft (sólo el id).
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(comentario='nota privada del admin')]}
        texto = nft_conf.generar(_cfg(fw))
        self.assertNotIn('nota privada del admin', texto)

    def test_nombre_de_regla_no_aparece_en_el_texto_nft(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(nombre='Nombre visible')]}
        texto = nft_conf.generar(_cfg(fw))
        self.assertNotIn('Nombre visible', texto)


class TestNftCheck(unittest.TestCase):
    """Si hay binario `nft` en la máquina, el texto generado debe pasar
    `nft -c -f`. Se omite si no existe o si falla por permisos."""

    def _generar(self, fw):
        return nft_conf.generar(_cfg(fw))

    def _ejecutar_nft_check(self, texto):
        nft_bin = shutil.which('nft')
        if not nft_bin:
            self.skipTest('sin binario nft en esta máquina')
        fd, ruta = tempfile.mkstemp(suffix='.nft', prefix='prueba-fw-')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(texto)
            r = subprocess.run([nft_bin, '-c', '-f', ruta],
                               capture_output=True, text=True, timeout=10)
        except (PermissionError, OSError, subprocess.TimeoutExpired) as e:
            self.skipTest('nft -c no disponible: %s' % e)
        finally:
            try:
                os.unlink(ruta)
            except OSError:
                pass
        if r.returncode != 0 and ('Operation not permitted' in (r.stderr or '')
                                  or 'Permission denied' in (r.stderr or '')):
            self.skipTest('sin permisos para nft -c')
        return r

    def test_texto_sin_reglas_pasa_nft_check(self):
        r = self._ejecutar_nft_check(self._generar({'version': 1, 'grupos': [], 'reglas': []}))
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)

    def test_texto_con_reglas_y_grupos_pasa_nft_check(self):
        fw = {'version': 1,
              'grupos': [{'id': 'g_ab12cd34', 'nombre': 'Niños', 'tipo': 'mac',
                          'miembros': ['aa:bb:cc:dd:ee:01']},
                         {'id': 'g_cd34ef56', 'nombre': 'Serv', 'tipo': 'ip',
                          'miembros': ['192.168.50.10']}],
              'reglas': [
                  _regla(id='r_11111111', accion='bloquear',
                         origen={'tipo': 'mac', 'valor': 'aa:bb:cc:dd:ee:01'},
                         destino={'tipo': 'ip', 'valor': '10.0.0.1'},
                         protocolo='tcp', puertos=[{'desde': 443, 'hasta': 443}],
                         registrar=True),
                  _regla(id='r_22222222', accion='permitir',
                         origen={'tipo': 'grupo', 'valor': 'g_cd34ef56'},
                         destino={'tipo': 'red', 'valor': '0.0.0.0/0'},
                         protocolo='tcp_udp',
                         puertos=[{'desde': 80, 'hasta': 80}, {'desde': 8000, 'hasta': 8010}]),
                  _regla(id='r_33333333', accion='rechazar', protocolo='tcp'),
              ]}
        r = self._ejecutar_nft_check(self._generar(fw))
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)

    def test_texto_con_rechazar_tcp_udp_pasa_nft_check(self):
        fw = {'version': 1, 'grupos': [], 'reglas': [
            _regla(id='r_44444444', accion='rechazar', protocolo='tcp_udp')]}
        r = self._ejecutar_nft_check(self._generar(fw))
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)


if __name__ == '__main__':
    unittest.main()
