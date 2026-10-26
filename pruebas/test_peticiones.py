#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root, sin nft/ip/ssh) de
core/peticiones.py — en concreto de la acción nueva de la fase 4 (C):
`modo_pesos`. Se centra en la validación, que es lo único que le compete a
este módulo (la aplicación de verdad la hace routerd).

Uso:  python3 -m unittest pruebas/test_peticiones.py -v
  o:  python3 pruebas/test_peticiones.py
"""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import peticiones  # noqa: E402


def _cfg():
    # Config mínima, suficiente para aplicar(): sólo hace falta lo que cada
    # acción mira de verdad (modo_pesos no toca 'wans' ni 'lan').
    return {
        'modo': 'balanceo', 'modo_pesos': 'manual',
        'lan': {'interfaz': 'lan0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'},
        'wifi_wan': {'habilitada': True, 'interfaz': 'wlp3s0b1', 'ssid_bloqueadas': ['MI-WIFI']},
        'wans': {}, 'reservas': [], 'etiquetas': {},
    }


def _peticion(accion, datos, usuario='admin'):
    return {'id': 'x', 'usuario': usuario, 'accion': accion, 'datos': datos}


class TestModoPesos(unittest.TestCase):
    def test_auto_se_acepta_y_queda_en_la_config(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo_pesos', {'modo_pesos': 'auto'}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['modo_pesos'], 'auto')
        self.assertIsNone(dhcp)   # modo_pesos no afecta a dnsmasq

    def test_manual_se_acepta(self):
        cfg = _cfg()
        cfg['modo_pesos'] = 'auto'
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo_pesos', {'modo_pesos': 'manual'}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['modo_pesos'], 'manual')

    def test_valor_desconocido_rechazado(self):
        cfg = _cfg()
        antes = copy.deepcopy(cfg)
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo_pesos', {'modo_pesos': 'turbo'}))
        self.assertFalse(ok)
        self.assertEqual(cfg, antes)   # una petición inválida no toca la config

    def test_campo_ausente_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo_pesos', {}))
        self.assertFalse(ok)

    def test_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo_pesos', {'modo_pesos': 'auto', 'extra': 1}))
        self.assertFalse(ok)
        self.assertIn('no admitidos', msg)

    def test_tipo_no_string_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo_pesos', {'modo_pesos': 1}))
        self.assertFalse(ok)


class TestWifi(unittest.TestCase):
    """Validación de las acciones nuevas de la WAN Wi-Fi (wifi_agregar,
    wifi_eliminar, wifi_conectar, wifi_escanear, wifi_config). Estas cuatro
    primeras NUNCA deben mutar cfg (ni la clave ni nada de la red debe
    acabar en router.json) — es routerd quien ejecuta de verdad el cambio
    contra NetworkManager (ver peticiones.ACCIONES_WIFI_SISTEMA)."""

    # — wifi_agregar —
    def test_agregar_valido(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': 'password1', 'prioridad': 50}))
        self.assertTrue(ok, msg)
        self.assertIsNone(dhcp)
        self.assertEqual(cfg, _cfg())   # nunca toca cfg

    def test_agregar_red_abierta_valida(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'Abierta', 'clave': '', 'prioridad': 0}))
        self.assertTrue(ok, msg)

    def test_agregar_ssid_largo_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'x' * 33, 'clave': '', 'prioridad': 0}))
        self.assertFalse(ok)

    def test_agregar_ssid_vacio_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': '', 'clave': '', 'prioridad': 0}))
        self.assertFalse(ok)

    def test_agregar_ssid_con_caracter_de_control_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'mala\x01red', 'clave': '', 'prioridad': 0}))
        self.assertFalse(ok)
        self.assertIn('control', msg)

    def test_agregar_ssid_bloqueada_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MI-WIFI', 'clave': 'password1', 'prioridad': 0}))
        self.assertFalse(ok)
        self.assertIn('bloqueado', msg)

    def test_agregar_ssid_bloqueada_minusculas_rechazado(self):
        # Revisión Opus (ronda 2): la comparación se normaliza con
        # .strip().casefold() — "mi-wifi" también debe quedar bloqueado,
        # no sólo la grafía exacta "MI-WIFI" de ssid_bloqueadas.
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'mi-wifi', 'clave': 'password1', 'prioridad': 0}))
        self.assertFalse(ok)
        self.assertIn('bloqueado', msg)

    def test_agregar_ssid_bloqueada_con_espacio_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MI-WIFI ', 'clave': 'password1', 'prioridad': 0}))
        self.assertFalse(ok)
        self.assertIn('bloqueado', msg)

    def test_agregar_clave_7_caracteres_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': '1234567', 'prioridad': 0}))
        self.assertFalse(ok)

    def test_agregar_clave_64_caracteres_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': 'a' * 64, 'prioridad': 0}))
        self.assertFalse(ok)

    def test_agregar_clave_8_y_63_aceptadas(self):
        cfg = _cfg()
        ok, _, _ = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': '1' * 8, 'prioridad': 0}))
        self.assertTrue(ok)
        ok, _, _ = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': '1' * 63, 'prioridad': 0}))
        self.assertTrue(ok)

    def test_agregar_clave_no_ascii_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': 'ñññññññ1', 'prioridad': 0}))
        self.assertFalse(ok)

    def test_agregar_prioridad_fuera_de_rango_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': '', 'prioridad': 101}))
        self.assertFalse(ok)

    def test_agregar_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': '', 'prioridad': 0, 'extra': 1}))
        self.assertFalse(ok)
        self.assertIn('no admitidos', msg)

    def test_agregar_campo_faltante_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'wifi_agregar', {'ssid': 'MiRed', 'clave': ''}))
        self.assertFalse(ok)

    # — wifi_eliminar / wifi_conectar —
    def test_eliminar_valido(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_eliminar', {'ssid': 'MiRed'}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg, _cfg())

    def test_eliminar_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_eliminar', {'ssid': 'MiRed', 'clave': 'x'}))
        self.assertFalse(ok)

    def test_conectar_valido(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_conectar', {'ssid': 'MiRed'}))
        self.assertTrue(ok, msg)

    def test_conectar_sin_ssid_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_conectar', {}))
        self.assertFalse(ok)

    # — wifi_escanear —
    def test_escanear_valido(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_escanear', {}))
        self.assertTrue(ok, msg)

    def test_escanear_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_escanear', {'ssid': 'x'}))
        self.assertFalse(ok)

    # — wifi_config —
    def test_config_activa(self):
        cfg = _cfg()
        cfg['wifi_wan']['habilitada'] = False
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_config', {'habilitada': True}))
        self.assertTrue(ok, msg)
        self.assertTrue(cfg['wifi_wan']['habilitada'])
        self.assertIsNone(dhcp)

    def test_config_desactiva(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_config', {'habilitada': False}))
        self.assertTrue(ok, msg)
        self.assertFalse(cfg['wifi_wan']['habilitada'])

    def test_config_tipo_no_bool_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_config', {'habilitada': 1}))
        self.assertFalse(ok)

    def test_config_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('wifi_config', {'habilitada': True, 'extra': 1}))
        self.assertFalse(ok)

    def test_acciones_wifi_sistema_no_incluye_config(self):
        # wifi_config SÍ muta cfg (como modo_pesos); las otras cuatro, no.
        self.assertNotIn('wifi_config', peticiones.ACCIONES_WIFI_SISTEMA)
        self.assertEqual(peticiones.ACCIONES_WIFI_SISTEMA,
                          {'wifi_agregar', 'wifi_eliminar', 'wifi_conectar', 'wifi_escanear'})


class TestBloqueo(unittest.TestCase):
    """Validación de las acciones nuevas del bloqueador DNS (bloqueo_config,
    bloqueo_lista, bloqueo_actualizar, bloqueo_probar)."""

    def _datos_config(self, **cambios):
        datos = {'habilitado': True, 'listas': ['hagezi_pro', 'hagezi_tif'],
                  'forzar_dns': True, 'bloquear_doh': True,
                  'actualizar_h': 24, 'registro_dns_dias': 30}
        datos.update(cambios)
        return datos

    # — bloqueo_config —
    def test_config_valida(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_config', self._datos_config()))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['bloqueo']['listas'], ['hagezi_pro', 'hagezi_tif'])
        self.assertIsNone(dhcp)   # habilitado no cambió (ya era True por defecto)

    # — control de concurrencia optimista (petición del panel, ronda 3) —

    def test_config_con_version_correcta_se_aplica(self):
        import router_bloqueo
        cfg = _cfg()
        version = router_bloqueo.calcular_version_bloqueo(cfg.get('bloqueo') or {})
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(version=version)))
        self.assertTrue(ok, msg)

    def test_config_con_version_desactualizada_se_rechaza_sin_aplicar(self):
        cfg = _cfg()
        antes = copy.deepcopy(cfg)
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(version='0000000000000000')))
        self.assertFalse(ok)
        self.assertIn('cambió mientras editabas', msg)
        self.assertEqual(cfg, antes)   # nada se aplicó

    def test_config_version_mal_formada_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(version='no-es-hex')))
        self.assertFalse(ok)

    def test_config_sin_version_no_comprueba_nada(self):
        # 'version' es opcional: sin ella, se aplica igual (compatibilidad).
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_config', self._datos_config()))
        self.assertTrue(ok, msg)

    def test_config_version_cambia_tras_aplicar_bloqueo_config(self):
        import router_bloqueo
        cfg = _cfg()
        v1 = router_bloqueo.calcular_version_bloqueo(cfg.get('bloqueo') or {})
        peticiones.aplicar(cfg, _peticion('bloqueo_config', self._datos_config(listas=['hagezi_tif'])))
        v2 = router_bloqueo.calcular_version_bloqueo(cfg.get('bloqueo') or {})
        self.assertNotEqual(v1, v2)

    def test_config_version_no_cambia_con_bloqueo_lista(self):
        # bloqueo_lista sólo toca lista_blanca/lista_negra, que la
        # 'version' EXCLUYE a propósito — si no, cada bloqueo_lista
        # invalidaría cualquier bloqueo_config que el panel tuviera a
        # medio editar en otra pestaña.
        import router_bloqueo
        cfg = _cfg()
        v1 = router_bloqueo.calcular_version_bloqueo(cfg.get('bloqueo') or {})
        peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'x.example.com'}))
        v2 = router_bloqueo.calcular_version_bloqueo(cfg.get('bloqueo') or {})
        self.assertEqual(v1, v2)

    def test_config_lista_desconocida_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(listas=['hagezi_pro', 'no_existe'])))
        self.assertFalse(ok)
        self.assertIn('desconocida', msg)

    def test_config_campo_faltante_rechazado(self):
        cfg = _cfg()
        datos = self._datos_config()
        del datos['actualizar_h']
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_config', datos))
        self.assertFalse(ok)
        self.assertIn('Faltan campos', msg)

    def test_config_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(extra=1)))
        self.assertFalse(ok)

    def test_config_actualizar_h_fuera_de_rango_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(actualizar_h=5)))
        self.assertFalse(ok)
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(actualizar_h=169)))
        self.assertFalse(ok)

    def test_config_registro_dns_dias_fuera_de_rango_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(registro_dns_dias=0)))
        self.assertFalse(ok)
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(registro_dns_dias=366)))
        self.assertFalse(ok)

    def test_config_listas_no_lista_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(listas='hagezi_pro')))
        self.assertFalse(ok)

    def test_config_cambiar_habilitado_nunca_marca_cambio_dhcp(self):
        # M2: el servers-file del bloqueo se referencia SIEMPRE desde
        # dnsmasq_conf.py (exista lo que exista dentro) — ya no hace falta
        # ningún recargo 'dhcp' (restart de la LAN) por activar/desactivar
        # el bloqueo; es routerd quien decide, aparte, si hace falta
        # relanzar router-bloqueo.service.
        cfg = _cfg()
        cfg['bloqueo'] = {'habilitado': True, 'listas': [], 'lista_blanca': [], 'lista_negra': [],
                           'forzar_dns': True, 'bloquear_doh': True, 'actualizar_h': 24,
                           'registro_dns_dias': 30}
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(habilitado=False)))
        self.assertTrue(ok, msg)
        self.assertIsNone(dhcp)

    def test_config_preserva_listas_blanca_y_negra_existentes(self):
        cfg = _cfg()
        cfg['bloqueo'] = {'habilitado': True, 'listas': [], 'lista_blanca': ['bueno.com'],
                           'lista_negra': ['malo.com'], 'forzar_dns': True, 'bloquear_doh': True,
                           'actualizar_h': 24, 'registro_dns_dias': 30}
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_config', self._datos_config()))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['bloqueo']['lista_blanca'], ['bueno.com'])
        self.assertEqual(cfg['bloqueo']['lista_negra'], ['malo.com'])

    def test_config_duplicados_en_listas_se_unen(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_config', self._datos_config(listas=['hagezi_pro', 'hagezi_pro'])))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['bloqueo']['listas'], ['hagezi_pro'])

    # — bloqueo_lista —
    def test_lista_agregar_blanca(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'Bueno.Example.COM'}))
        self.assertTrue(ok, msg)
        self.assertIn('bueno.example.com', cfg['bloqueo']['lista_blanca'])
        self.assertIsNone(dhcp)

    def test_lista_agregar_negra(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'malo.example.com'}))
        self.assertTrue(ok, msg)
        self.assertIn('malo.example.com', cfg['bloqueo']['lista_negra'])

    def test_lista_negra_sufijo_publico_rechazado(self):
        # M5: "co.uk" entero en lista_negra se llevaría por delante medio
        # internet comercial del Reino Unido — rechazado.
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'co.uk'}))
        self.assertFalse(ok)
        self.assertIn('sufijo público', msg)

    def test_lista_negra_subdominio_de_sufijo_publico_aceptado(self):
        # Un sitio CONCRETO bajo un sufijo público sí se puede bloquear —
        # sólo se rechaza el sufijo PELADO.
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'malo.co.uk'}))
        self.assertTrue(ok, msg)

    def test_lista_negra_dominio_protegido_rechazado(self):
        # M5: nunca se puede bloquear algo que el propio router necesita.
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'github.com'}))
        self.assertFalse(ok)
        self.assertIn('protegido', msg)

    def test_lista_negra_subdominio_de_protegido_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'sub.raw.githubusercontent.com'}))
        self.assertFalse(ok)
        self.assertIn('protegido', msg)

    def test_lista_blanca_dominio_que_parece_protegido_se_acepta(self):
        # La guarda de "protegido" sólo se aplica a lista NEGRA — añadir a
        # lista BLANCA un dominio que ya está protegido es redundante pero
        # nunca peligroso, así que no se rechaza.
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'github.com'}))
        self.assertTrue(ok, msg)

    def test_lista_negra_dominio_de_la_propia_casa_rechazado(self):
        cfg = _cfg()
        cfg['dominio'] = 'lan.home.arpa'
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'nas.lan.home.arpa'}))
        self.assertFalse(ok)
        self.assertIn('protegido', msg)

    def test_lista_quitar(self):
        cfg = _cfg()
        cfg['bloqueo'] = {'habilitado': True, 'listas': [], 'lista_blanca': ['bueno.com'],
                           'lista_negra': [], 'forzar_dns': True, 'bloquear_doh': True,
                           'actualizar_h': 24, 'registro_dns_dias': 30}
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'quitar', 'dominio': 'bueno.com'}))
        self.assertTrue(ok, msg)
        self.assertNotIn('bueno.com', cfg['bloqueo']['lista_blanca'])

    def test_lista_quitar_inexistente_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'quitar', 'dominio': 'no-esta.com'}))
        self.assertFalse(ok)

    def test_lista_dominio_invalido_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'evil.com/'}))
        self.assertFalse(ok)

    def test_lista_tipo_invalido_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'gris', 'accion': 'agregar', 'dominio': 'x.example.com'}))
        self.assertFalse(ok)

    def test_lista_accion_invalida_rechazada(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'borrar', 'dominio': 'x.example.com'}))
        self.assertFalse(ok)

    def test_lista_agregar_duplicado_no_falla_ni_duplica(self):
        cfg = _cfg()
        peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'x.example.com'}))
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'negra', 'accion': 'agregar', 'dominio': 'x.example.com'}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg['bloqueo']['lista_negra'].count('x.example.com'), 1)

    def test_lista_limite_5000_entradas(self):
        cfg = _cfg()
        cfg['bloqueo'] = {'habilitado': True, 'listas': [],
                           'lista_blanca': ['d%d.example.com' % i for i in range(5000)],
                           'lista_negra': [], 'forzar_dns': True, 'bloquear_doh': True,
                           'actualizar_h': 24, 'registro_dns_dias': 30}
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(
            'bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'nuevo.example.com'}))
        self.assertFalse(ok)
        self.assertIn('máximo', msg)

    # — bloqueo_actualizar / bloqueo_probar (sólo validación; nunca mutan cfg) —
    def test_actualizar_valido_no_muta_cfg(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_actualizar', {}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg, _cfg())

    def test_actualizar_campo_extra_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_actualizar', {'x': 1}))
        self.assertFalse(ok)

    def test_actualizar_forzar_valido_no_muta_cfg(self):
        # BAJA4 (ronda 3).
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_actualizar', {'forzar': True}))
        self.assertTrue(ok, msg)
        self.assertIn('forzada', msg)
        self.assertEqual(cfg, _cfg())

    def test_actualizar_forzar_false_tambien_valido(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_actualizar', {'forzar': False}))
        self.assertTrue(ok, msg)
        self.assertNotIn('forzada', msg)

    def test_actualizar_forzar_no_bool_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_actualizar', {'forzar': 'si'}))
        self.assertFalse(ok)

    def test_probar_valido_no_muta_cfg(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_probar', {'dominio': 'example.com'}))
        self.assertTrue(ok, msg)
        self.assertEqual(cfg, _cfg())

    def test_probar_dominio_invalido_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_probar', {'dominio': 'evil.com/'}))
        self.assertFalse(ok)

    def test_probar_sin_dominio_rechazado(self):
        cfg = _cfg()
        ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('bloqueo_probar', {}))
        self.assertFalse(ok)

    def test_acciones_sistema_bloqueo(self):
        self.assertEqual(peticiones.ACCIONES_SISTEMA_BLOQUEO, {'bloqueo_actualizar', 'bloqueo_probar'})
        self.assertNotIn('bloqueo_config', peticiones.ACCIONES_SISTEMA_BLOQUEO)
        self.assertNotIn('bloqueo_lista', peticiones.ACCIONES_SISTEMA_BLOQUEO)

    # — BAJA14: sin router_bloqueo instalado, el resto del módulo sigue bien —
    def test_sin_router_bloqueo_las_demas_acciones_siguen_funcionando(self):
        original = peticiones.router_bloqueo
        peticiones.router_bloqueo = None
        try:
            cfg = _cfg()
            ok, msg, dhcp = peticiones.aplicar(cfg, _peticion('modo', {'modo': 'respaldo'}))
            self.assertTrue(ok, msg)
            for accion, datos in (
                ('bloqueo_config', self._datos_config()),
                ('bloqueo_lista', {'tipo': 'blanca', 'accion': 'agregar', 'dominio': 'x.example.com'}),
                ('bloqueo_actualizar', {}),
                ('bloqueo_probar', {'dominio': 'x.example.com'}),
            ):
                ok, msg, dhcp = peticiones.aplicar(cfg, _peticion(accion, datos))
                self.assertFalse(ok)
                self.assertIn('no está instalado', msg)
        finally:
            peticiones.router_bloqueo = original


if __name__ == '__main__':
    unittest.main()
