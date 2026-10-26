#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root) de
core/router_bloqueo.py: parseo de listas (basura, comentarios, mayúsculas,
IDN, inyección), lista blanca con subdominios, generación del servers-file
(M1/M2), validación/activación con dnsmasq --test + SIGHUP (M2), dominios
protegidos (M5), guarda de variación ±50% (M5), cota global (M4), caída de
descarga → usa caché, límite de tamaño, reintento por cambio de config (M3),
y bloqueo_probar (comprobar_dominio).

Uso:  python3 -m unittest pruebas/test_bloqueo.py -v
  o:  python3 pruebas/test_bloqueo.py
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import router_bloqueo as rb  # noqa: E402


# ───────────────────────────── normalizar_dominio ──────────────────────────

class TestNormalizarDominio(unittest.TestCase):
    def test_dominio_normal(self):
        self.assertEqual(rb.normalizar_dominio('ads.example.com'), 'ads.example.com')

    def test_mayusculas_se_normalizan(self):
        self.assertEqual(rb.normalizar_dominio('Tracker.EXAMPLE.net'), 'tracker.example.net')

    def test_punto_final_se_quita(self):
        self.assertEqual(rb.normalizar_dominio('example.com.'), 'example.com')

    def test_idn_se_convierte_a_punycode(self):
        self.assertEqual(rb.normalizar_dominio('café.example.com'), 'xn--caf-dma.example.com')

    def test_idn_ya_en_punycode_se_acepta(self):
        self.assertEqual(rb.normalizar_dominio('xn--caf-dma.example.com'), 'xn--caf-dma.example.com')

    def test_vacio_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio(''))
        self.assertIsNone(rb.normalizar_dominio('   '))

    def test_comentario_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('# un comentario'))

    def test_un_solo_nivel_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('localhost'))

    def test_ip_rechazada(self):
        self.assertIsNone(rb.normalizar_dominio('1.2.3.4'))

    def test_wildcard_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('*.example.com'))

    def test_barra_rechazada(self):
        self.assertIsNone(rb.normalizar_dominio('evil.com/'))

    def test_inyeccion_server_rechazada(self):
        self.assertIsNone(rb.normalizar_dominio('evil.com/'))
        self.assertIsNone(rb.normalizar_dominio('server=1.2.3.4'))

    def test_inyeccion_address_rechazada(self):
        self.assertIsNone(rb.normalizar_dominio('address=/x/1.2.3.4'))

    def test_espacio_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('evil.com 1.2.3.4'))

    def test_control_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('evil\x01.com'))

    def test_etiqueta_vacia_rechazada(self):
        self.assertIsNone(rb.normalizar_dominio('good..com'))

    def test_guion_al_inicio_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('-bad.com'))

    def test_guion_al_final_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('bad-.com'))

    def test_etiqueta_demasiado_larga_rechazada(self):
        self.assertIsNone(rb.normalizar_dominio('a' * 64 + '.com'))

    def test_no_string_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio(None))
        self.assertIsNone(rb.normalizar_dominio(123))

    def test_guion_bajo_rechazado(self):
        self.assertIsNone(rb.normalizar_dominio('_dmarc.example.com'))


class TestEsSufijoPublico(unittest.TestCase):
    def test_sufijo_pelado(self):
        self.assertTrue(rb.es_sufijo_publico('co.uk'))
        self.assertTrue(rb.es_sufijo_publico('com.es'))

    def test_subdominio_de_sufijo_publico_no_es_el_sufijo(self):
        self.assertFalse(rb.es_sufijo_publico('example.co.uk'))

    def test_dominio_normal_no_es_sufijo_publico(self):
        self.assertFalse(rb.es_sufijo_publico('example.com'))

    def test_none(self):
        self.assertFalse(rb.es_sufijo_publico(None))


# ──────────────────────────────── parsear_lista ─────────────────────────────

class TestParsearLista(unittest.TestCase):
    def test_lista_mixta(self):
        texto = (
            "# Título de la lista\n"
            "# Descripción...\n"
            "\n"
            "ads.example.com\n"
            "Tracker.EXAMPLE.net\n"
            "evil.com/\n"
            "server=1.2.3.4\n"
            "address=/x/1.2.3.4\n"
            "*.wild.com\n"
            "1.2.3.4\n"
            "café.example.com\n"
            "good..com\n"
            "-bad.com\n"
            "sub.ads.example.com\n"
        )
        dominios = rb.parsear_lista(texto)
        self.assertEqual(dominios, {
            'ads.example.com', 'tracker.example.net', 'sub.ads.example.com',
            'xn--caf-dma.example.com',
        })

    def test_texto_vacio(self):
        self.assertEqual(rb.parsear_lista(''), set())
        self.assertEqual(rb.parsear_lista(None), set())

    def test_duplicados_se_unen(self):
        texto = "a.example.com\nA.EXAMPLE.COM\na.example.com.\n"
        self.assertEqual(rb.parsear_lista(texto), {'a.example.com'})

    def test_limite_de_entradas(self):
        texto = '\n'.join('d%d.example.com' % i for i in range(100))
        self.assertEqual(len(rb.parsear_lista(texto, limite=10)), 10)

    def test_inyeccion_no_cuela_ni_mezclada_con_una_linea_valida(self):
        texto = "evil.com/\nserver=1.2.3.4\n#evil.com\naddress=/evil.com/1.2.3.4\n"
        self.assertEqual(rb.parsear_lista(texto), set())

    def test_streaming_no_materializa_splitlines(self):
        # M4: usa io.StringIO (streaming), no str.splitlines() — sanity
        # check funcional (el resultado debe ser idéntico de todas formas).
        texto = "a.example.com\nb.example.com\n"
        self.assertEqual(rb.parsear_lista(texto), {'a.example.com', 'b.example.com'})


# ───────────────────────────── aplicar_lista_blanca ────────────────────────

class TestListaBlanca(unittest.TestCase):
    def test_subdominio_tambien_se_quita(self):
        dominios = {'ads.example.com', 'sub.ads.example.com', 'other.com'}
        out = rb.aplicar_lista_blanca(dominios, ['example.com'])
        self.assertEqual(out, {'other.com'})

    def test_dominio_exacto(self):
        dominios = {'example.com', 'other.com'}
        out = rb.aplicar_lista_blanca(dominios, ['example.com'])
        self.assertEqual(out, {'other.com'})

    def test_lista_blanca_vacia_no_cambia_nada(self):
        dominios = {'a.com', 'b.com'}
        self.assertEqual(rb.aplicar_lista_blanca(dominios, []), dominios)

    def test_entrada_blanca_invalida_se_ignora(self):
        dominios = {'a.com'}
        out = rb.aplicar_lista_blanca(dominios, ['evil.com/', '*.x.com'])
        self.assertEqual(out, dominios)

    def test_no_afecta_a_dominios_hermanos(self):
        dominios = {'ads.example.com', 'ads.other.com'}
        out = rb.aplicar_lista_blanca(dominios, ['example.com'])
        self.assertEqual(out, {'ads.other.com'})


# ───────────────────────────── dominios protegidos (M5) ────────────────────

class TestDominiosProtegidos(unittest.TestCase):
    def test_hosts_del_catalogo_protegidos(self):
        protegidos = rb._dominios_protegidos()
        self.assertIn('raw.githubusercontent.com', protegidos)

    def test_github_y_letsencrypt_protegidos(self):
        protegidos = rb._dominios_protegidos()
        self.assertIn('github.com', protegidos)
        self.assertIn('letsencrypt.org', protegidos)
        self.assertIn('acme-v02.api.letsencrypt.org', protegidos)

    def test_arpa_y_home_arpa_ya_no_estan_aqui(self):
        # BAJA3 (ronda 3): "arpa"/"home.arpa" se quitaron de PROTEGIDOS —
        # ahora se gestionan de forma incondicional en dnsmasq_conf.py
        # (local=/home.arpa/, siempre presente, independiente del
        # bloqueador — ver test_dnsmasq_nft_bloqueo.py).
        protegidos = rb._dominios_protegidos()
        self.assertNotIn('arpa', protegidos)
        self.assertNotIn('home.arpa', protegidos)

    def test_dominio_de_la_casa_se_anade(self):
        protegidos = rb._dominios_protegidos('lan.home.arpa')
        self.assertIn('lan.home.arpa', protegidos)

    def test_sin_dominio_de_la_casa_no_falla(self):
        protegidos = rb._dominios_protegidos(None)
        self.assertIsInstance(protegidos, frozenset)


# ────────────────────────────── generar_servers_file (M1/M2) ───────────────

class TestGenerarServersFile(unittest.TestCase):
    def test_bloqueados_sin_direccion(self):
        texto = rb.generar_servers_file({'ads.example.com', 'bad.net'}, set())
        self.assertIn('server=/ads.example.com/\n', texto)
        self.assertIn('server=/bad.net/\n', texto)
        self.assertNotIn('server=/ads.example.com/#', texto)

    def test_excepciones_con_almohadilla(self):
        texto = rb.generar_servers_file({'example.com'}, {'bueno.example.com'})
        self.assertIn('server=/example.com/\n', texto)
        self.assertIn('server=/bueno.example.com/#\n', texto)

    def test_m1_excepcion_no_depende_de_estar_en_bloqueados(self):
        # El punto central de M1: una excepción se emite SIEMPRE, exista o
        # no ese dominio exacto en el conjunto bloqueado (el padre puede
        # estar bloqueado sin que el hijo aparezca nunca como entrada
        # literal — así "agujerea" el padre sin desbloquear a sus
        # hermanos; ver test_dnsmasq_real_* más abajo para la prueba E2E).
        texto = rb.generar_servers_file(set(), {'bueno.example.com'})
        self.assertIn('server=/bueno.example.com/#\n', texto)

    def test_exacta_en_ambos_conjuntos_no_se_bloquea(self):
        # Defensa contra la ambigüedad: si el MISMO dominio exacto está en
        # bloqueados Y en excepciones, gana la excepción (nunca se emite
        # la línea de bloqueo para ese dominio exacto).
        texto = rb.generar_servers_file({'x.com'}, {'x.com'})
        self.assertNotIn('server=/x.com/\n', texto)
        self.assertIn('server=/x.com/#\n', texto)

    def test_orden_determinista(self):
        t1 = rb.generar_servers_file({'b.com', 'a.com'}, {'c.com'})
        t2 = rb.generar_servers_file({'a.com', 'b.com'}, {'c.com'})
        self.assertEqual(t1, t2)

    def test_vacio_genera_solo_cabecera(self):
        texto = rb.generar_servers_file(set(), set())
        self.assertNotIn('server=', texto)
        self.assertTrue(texto.strip())

    def test_nunca_local(self):
        # servers-file de dnsmasq RECHAZA local=/address= — nunca debe
        # aparecer aquí.
        texto = rb.generar_servers_file({'ok.example.com'}, set())
        self.assertNotIn('local=', texto)
        self.assertNotIn('address=', texto)


# ──────────────── dnsmasq --test / SIGHUP real con servers-file (M2) ───────

@unittest.skipUnless(shutil.which('dnsmasq'), 'dnsmasq no está instalado en esta máquina')
class TestDnsmasqRealServersFile(unittest.TestCase):
    """Comprobación EMPÍRICA (no mock) de M1/M2: dnsmasq 2.93 admite
    servers-file=, lo valida con --test, y server=/x/# "agujerea" un padre
    bloqueado sin desbloquear a sus hermanos — en un dnsmasq real, nunca
    contra el servicio del sistema (puerto alto, proceso propio de la
    prueba)."""
    def test_dnsmasq_test_acepta_servers_file_generado(self):
        texto = rb.generar_servers_file({'ads.example.com'}, {'bueno.example.com'})
        tmp = tempfile.mkdtemp(prefix='bloqueo-dnsmasq-real-')
        try:
            ruta_servers = os.path.join(tmp, 'servers.conf')
            with open(ruta_servers, 'w') as f:
                f.write(texto)
            stub = os.path.join(tmp, 'stub.conf')
            with open(stub, 'w') as f:
                f.write('servers-file=%s\n' % ruta_servers)
            r = subprocess.run(['dnsmasq', '--test', '--conf-file=' + stub],
                                capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr or r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ───────────────────────── validación con dnsmasq --test ───────────────────

_subprocess_run_real = subprocess.run


def _run_solo_dnsmasq(args, **kwargs):
    """Deja pasar de verdad SÓLO las llamadas a `dnsmasq --test` (la
    validación real que queremos comprobar); cualquier otra cosa
    (`systemctl kill`/`systemctl is-active`) se simula sin tocar el sistema
    — en las pruebas de ESTA clase nunca hay un dnsmasq de verdad
    corriendo como servicio."""
    if args and args[0] == 'dnsmasq':
        return _subprocess_run_real(args, **kwargs)
    return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


@unittest.skipUnless(shutil.which('dnsmasq'), 'dnsmasq no está instalado en esta máquina')
class TestValidarYActivar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-test-')
        self.rutas = {'dnsmasq_bloqueo': os.path.join(self.tmp, 'dnsmasq-bloqueo.conf')}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_config_valida_se_activa_sin_gestionar_dnsmasq(self):
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok, msg)
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            self.assertIn('server=/ads.example.com/', f.read())

    def test_config_invalida_no_se_activa(self):
        # Nota (comprobado empíricamente): `dnsmasq --test` es MUY laxo con
        # el CONTENIDO de un servers-file (una línea que no es server=/
        # rev-server= simplemente se ignora, no hace fallar la validación
        # — a diferencia de un conf-file genérico). Para probar el camino
        # de "config inválida" de nuestro propio código, se simula un
        # `dnsmasq --test` que SÍ falla (una versión más estricta, o
        # cualquier otro motivo real de fallo).
        conf_mala = 'esto no es una directiva de dnsmasq valida en absoluto ======\n'
        with mock.patch('router_bloqueo.subprocess.run',
                         return_value=subprocess.CompletedProcess(['dnsmasq'], 1, stdout='', stderr='mal')):
            ok, msg = rb._validar_y_activar(conf_mala, self.rutas, gestionar_dnsmasq=False)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(self.rutas['dnsmasq_bloqueo']))

    def test_config_invalida_no_pisa_la_anterior(self):
        previa = rb.generar_servers_file({'previo.example.com'}, set())
        with open(self.rutas['dnsmasq_bloqueo'], 'w') as f:
            f.write(previa)
        with mock.patch('router_bloqueo.subprocess.run',
                         return_value=subprocess.CompletedProcess(['dnsmasq'], 1, stdout='', stderr='mal')):
            ok, msg = rb._validar_y_activar('esto no vale ======\n', self.rutas, gestionar_dnsmasq=False)
        self.assertFalse(ok)
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            self.assertIn('previo.example.com', f.read())

    def test_sin_cambios_no_hace_nada(self):
        # M2: comparación por hash — la segunda llamada con el MISMO
        # contenido no debe tocar el fichero (ni su mtime) ni intentar
        # validar/recargar de nuevo.
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        ok1, msg1 = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok1, msg1)
        mtime_antes = os.stat(self.rutas['dnsmasq_bloqueo']).st_mtime_ns
        with mock.patch('router_bloqueo.subprocess.run') as m:
            ok2, msg2 = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok2, msg2)
        self.assertIn('sin cambios', msg2)
        m.assert_not_called()   # ni siquiera se llamó a dnsmasq --test
        self.assertEqual(os.stat(self.rutas['dnsmasq_bloqueo']).st_mtime_ns, mtime_antes)

    def test_contenido_distinto_si_regenera(self):
        conf1 = rb.generar_servers_file({'a.example.com'}, set())
        conf2 = rb.generar_servers_file({'b.example.com'}, set())
        rb._validar_y_activar(conf1, self.rutas, gestionar_dnsmasq=False)
        ok, msg = rb._validar_y_activar(conf2, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok, msg)
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            contenido = f.read()
        self.assertIn('b.example.com', contenido)
        self.assertNotIn('a.example.com', contenido)

    # — gestionar_dnsmasq=True: dnsmasq --test real, el resto simulado —

    def test_gestionar_true_activo_tras_sighup(self):
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        centinela = rb.centinela_de_generacion('a' * 64)
        with mock.patch('router_bloqueo.subprocess.run', side_effect=_run_solo_dnsmasq), \
             mock.patch('router_bloqueo._dnsmasq_esta_activo', return_value=True), \
             mock.patch('router_bloqueo._consulta_dns_centinela', return_value=True) as m_centinela:
            ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=True,
                                             habilitado=True, centinela=centinela)
        self.assertTrue(ok, msg)
        self.assertEqual(msg, 'ok')
        m_centinela.assert_called_once_with(centinela)

    def test_gestionar_true_activo_pero_centinela_no_confirma(self):
        # M1 (ronda 4): "is-active" solo no basta — si el centinela de
        # ESTA generación no responde NXDOMAIN (sigue con la vieja), se
        # trata igual que "no activo" (rollback).
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        centinela = rb.centinela_de_generacion('b' * 64)
        with mock.patch('router_bloqueo.subprocess.run', side_effect=_run_solo_dnsmasq), \
             mock.patch('router_bloqueo._dnsmasq_esta_activo', return_value=True), \
             mock.patch('router_bloqueo._consulta_dns_centinela', return_value=False):
            ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=True,
                                             habilitado=True, centinela=centinela)
        self.assertFalse(ok)

    def test_deshabilitado_no_exige_centinela(self):
        # Sin bloqueo habilitado no hay nada que confirmar por DNS — basta
        # con que dnsmasq esté activo.
        conf = rb.generar_servers_file(set(), set())
        with mock.patch('router_bloqueo.subprocess.run', side_effect=_run_solo_dnsmasq), \
             mock.patch('router_bloqueo._dnsmasq_esta_activo', return_value=True), \
             mock.patch('router_bloqueo._consulta_dns_centinela') as m_centinela:
            ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=True, habilitado=False)
        self.assertTrue(ok, msg)
        m_centinela.assert_not_called()

    def test_gestionar_true_fallo_restaura_la_anterior(self):
        previa = rb.generar_servers_file({'previo.example.com'}, set())
        rb._validar_y_activar(previa, self.rutas, gestionar_dnsmasq=False)   # deja algo "anterior" activo
        nueva = rb.generar_servers_file({'nuevo.example.com'}, set())
        with mock.patch('router_bloqueo.subprocess.run', side_effect=_run_solo_dnsmasq), \
             mock.patch('router_bloqueo._dnsmasq_esta_activo', return_value=False):
            ok, msg = rb._validar_y_activar(nueva, self.rutas, gestionar_dnsmasq=True)
        self.assertFalse(ok)
        self.assertIn('restaurado', msg)
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            contenido = f.read()
        self.assertIn('previo.example.com', contenido)
        self.assertNotIn('nuevo.example.com', contenido)

    def test_gestionar_true_fallo_sin_anterior_deja_vacio(self):
        nueva = rb.generar_servers_file({'nuevo.example.com'}, set())
        with mock.patch('router_bloqueo.subprocess.run', side_effect=_run_solo_dnsmasq), \
             mock.patch('router_bloqueo._dnsmasq_esta_activo', return_value=False):
            ok, msg = rb._validar_y_activar(nueva, self.rutas, gestionar_dnsmasq=True)
        self.assertFalse(ok)
        self.assertIn('vacía', msg)
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            contenido = f.read()
        self.assertNotIn('nuevo.example.com', contenido)
        self.assertNotIn('server=', contenido)

    def test_timeout_expired_en_la_validacion_no_lanza(self):
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        with mock.patch('router_bloqueo.subprocess.run',
                         side_effect=subprocess.TimeoutExpired(cmd='dnsmasq', timeout=30)):
            ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=True)
        self.assertFalse(ok)
        self.assertIn('no se pudo validar', msg)
        # BAJA1: nunca debe quedar nada a medias ni lanzar hacia arriba.
        self.assertFalse(os.path.exists(self.rutas['dnsmasq_bloqueo']))

    def test_timeout_expired_en_el_sighup_no_lanza(self):
        conf = rb.generar_servers_file({'ads.example.com'}, set())

        def _falla_sighup(args, **kwargs):
            if args and args[0] == 'dnsmasq':
                return subprocess.run(args, **kwargs)
            raise subprocess.TimeoutExpired(cmd=args, timeout=10)

        with mock.patch('router_bloqueo.subprocess.run', side_effect=_falla_sighup), \
             mock.patch('router_bloqueo._dnsmasq_esta_activo', return_value=False):
            ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=True)
        self.assertFalse(ok)   # no está activo (nunca se pudo confirmar) → fallo normal, nunca una excepción

    # — M4 (ronda 3): validación DOBLE real (conf-file directo SÍ rechaza basura) —

    def test_garbage_rechazado_de_verdad_sin_mocks(self):
        # Comprobado empíricamente: `dnsmasq --test` sobre un servers-file
        # (vía stub) es MUY laxo (nunca rechaza basura), pero el MISMO
        # fichero validado directamente como --conf-file=<tmp> SÍ es
        # estricto. _validar_servers_file hace las DOS — sin mocks, con
        # dnsmasq de verdad.
        conf_mala = 'esto no es una directiva de dnsmasq valida en absoluto ======\n'
        ok, msg = rb._validar_y_activar(conf_mala, self.rutas, gestionar_dnsmasq=False)
        self.assertFalse(ok)
        self.assertIn('opción errónea', msg)
        self.assertFalse(os.path.exists(self.rutas['dnsmasq_bloqueo']))

    def test_servers_file_valido_sin_mocks(self):
        conf = rb.generar_servers_file({'ads.example.com'}, {'bueno.example.com'})
        ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok, msg)

    # — M2 (ronda 3): huella (ino/tamaño/mtime) además del hash —

    def test_fichero_tocado_por_fuera_no_se_confunde_con_sin_cambios(self):
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        ok1, msg1 = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok1, msg1)
        # Alguien AJENO (p. ej. routerd en fail-open) vacía el fichero
        # pero NO borra el '.hash' — si sólo comparásemos el hash del
        # CONTENIDO NUEVO contra el guardado, aquí no habría "cambio" que
        # detectar relativo al hash guardado (es el MISMO conf de antes);
        # la huella (mtime/ino/tamaño) debe detectar que el fichero activo
        # ya no es el que dejamos nosotros.
        with open(self.rutas['dnsmasq_bloqueo'], 'w') as f:
            f.write('# vaciado por fuera\n')
        ok2, msg2 = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok2, msg2)
        self.assertNotIn('sin cambios', msg2)   # se ha vuelto a activar de verdad
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            self.assertIn('ads.example.com', f.read())

    def test_hash_borrado_tambien_fuerza_reactivar(self):
        conf = rb.generar_servers_file({'ads.example.com'}, set())
        rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        os.unlink(self.rutas['dnsmasq_bloqueo'] + '.hash')
        ok, msg = rb._validar_y_activar(conf, self.rutas, gestionar_dnsmasq=False)
        self.assertTrue(ok, msg)
        self.assertNotIn('sin cambios', msg)


class TestPermisosLecturaDnsmasq(unittest.TestCase):
    """M4 (ronda 3): dnsmasq corre con --user=dnsmasq — necesita x en los
    directorios padres y r en el fichero; _asegurar_legible_por_dnsmasq
    debe CORREGIRLO, no sólo avisar."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-permisos-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_corrige_directorio_sin_x_para_otros(self):
        d = os.path.join(self.tmp, 'sub')
        os.makedirs(d)
        os.chmod(d, 0o700)   # sin "x" para grupo/otros
        ruta = os.path.join(d, 'f.conf')
        with open(ruta, 'w') as f:
            f.write('x')
        os.chmod(ruta, 0o600)
        rb._asegurar_legible_por_dnsmasq(ruta)
        self.assertTrue(os.stat(d).st_mode & 0o001)
        self.assertTrue(os.stat(ruta).st_mode & 0o004)

    def test_no_rompe_si_ya_estaba_bien(self):
        d = os.path.join(self.tmp, 'sub2')
        os.makedirs(d, mode=0o755)
        ruta = os.path.join(d, 'f.conf')
        with open(ruta, 'w') as f:
            f.write('x')
        os.chmod(ruta, 0o644)
        rb._asegurar_legible_por_dnsmasq(ruta)   # no debe lanzar ni empeorar nada
        self.assertTrue(os.stat(ruta).st_mode & 0o004)

    def test_fichero_inexistente_no_lanza(self):
        rb._asegurar_legible_por_dnsmasq(os.path.join(self.tmp, 'no-existe', 'f.conf'))   # no debe lanzar

    def test_directorio_gana_solo_el_bit_de_ejecucion_no_0755(self):
        # BAJA2 (ronda 4): nunca debe dar lectura/listado de más (0o755
        # entero) — sólo el bit de "atravesar" (0o001) que hace falta.
        d = os.path.join(self.tmp, 'sub3')
        os.makedirs(d)
        os.chmod(d, 0o700)   # sin "x" para grupo/otros, y sin "r"/"w" tampoco
        ruta = os.path.join(d, 'f.conf')
        with open(ruta, 'w') as f:
            f.write('x')
        os.chmod(ruta, 0o600)
        rb._asegurar_legible_por_dnsmasq(ruta)
        modo_dir = stat.S_IMODE(os.stat(d).st_mode)
        self.assertEqual(modo_dir, 0o701, 'sólo debía añadirse el bit de ejecución para "otros"')

    def test_avisa_una_sola_vez_por_ruta_si_chmod_falla(self):
        d = os.path.join(self.tmp, 'sub4')
        os.makedirs(d)
        os.chmod(d, 0o700)
        ruta = os.path.join(d, 'f.conf')
        with open(ruta, 'w') as f:
            f.write('x')
        os.chmod(ruta, 0o600)
        try:
            with mock.patch('router_bloqueo.os.chmod', side_effect=OSError('solo lectura')), \
                 mock.patch('router_bloqueo.os.access', return_value=False), \
                 mock.patch('router_bloqueo.LOG') as m_log:
                rb._asegurar_legible_por_dnsmasq(ruta)
                primeras = m_log.exception.call_count
                self.assertGreater(primeras, 0)
                rb._asegurar_legible_por_dnsmasq(ruta)   # 2ª vez: mismas rutas, ya avisadas
                self.assertEqual(m_log.exception.call_count, primeras,
                                  'no debe repetir el aviso para una ruta ya avisada')
        finally:
            rb._AVISADOS_PERMISOS.clear()   # no contaminar otros tests con rutas de este tmp


@unittest.skipUnless(shutil.which('dnsmasq'), 'dnsmasq no está instalado en esta máquina')
class TestConsultaDnsCentinela(unittest.TestCase):
    """M1 (ronda 4): comprobación funcional real — contra un dnsmasq de
    verdad en un puerto alto (nunca el servicio del sistema) — del
    centinela POR GENERACIÓN: distingue "ya cargó el servers-file nuevo"
    (NXDOMAIN para el centinela de ESA generación) de "sigue con el
    viejo" (127.0.0.9, la `address=` fija que lleva la conf de la LAN,
    nunca el servers-file del bloqueo). `--user=` sólo si se es root (si
    no, dnsmasq ni lo aceptaría); si se es root, se prueba con
    `--user=nobody` como en producción."""

    def _dnsmasq_temporal(self, tmp, puerto, servers_file_contenido):
        ruta_servers = os.path.join(tmp, 'servers.conf')
        with open(ruta_servers, 'w') as f:
            f.write(servers_file_contenido)
        ruta_main = os.path.join(tmp, 'main.conf')
        usuario = ['--user=nobody'] if os.geteuid() == 0 else []
        with open(ruta_main, 'w') as f:
            f.write('port=%d\ninterface=lo\nbind-interfaces\nno-resolv\nno-hosts\n'
                     'pid-file=%s/d.pid\n'
                     # La misma `address=` fija que dnsmasq_conf.py deja en
                     # la LAN base, incondicional — es lo que responde para
                     # un centinela que el servers-file del bloqueo
                     # TODAVÍA no bloquea (generación vieja/no cargada).
                     'address=/%s/%s\n'
                     'servers-file=%s\nlog-facility=%s/d.log\n'
                     % (puerto, tmp, rb.CENTINELA_BASE, '127.0.0.9', ruta_servers, tmp))
        return subprocess.Popen(['dnsmasq', '-k'] + usuario + ['--conf-file=' + ruta_main])

    def _esperar_puerto(self, puerto, intentos=10):
        for _ in range(intentos):
            if rb._consulta_dns_cruda('x.invalid', '127.0.0.1', puerto, timeout=1) is not None:
                return True
            time.sleep(0.3)
        return False

    def test_generacion_no_cargada_cae_al_address_fijo(self):
        tmp = tempfile.mkdtemp(prefix='bloqueo-centinela-')
        dominios1 = {'ads.example.com'}
        hash1 = hashlib.sha256(('\n'.join(sorted(dominios1)) + '|').encode()).hexdigest()
        centinela1 = rb.centinela_de_generacion(hash1)
        texto1 = rb.generar_servers_file(dominios1 | {centinela1}, set())
        proc = self._dnsmasq_temporal(tmp, 15791, texto1)
        try:
            self._esperar_puerto(15791)
            # La generación 1 SÍ está cargada: su propio centinela da NXDOMAIN.
            self.assertTrue(rb._consulta_dns_centinela(centinela1, puerto=15791, timeout_total_s=5, intentos=2))
            # Un centinela de OTRA generación (que este dnsmasq nunca ha
            # visto) NUNCA debe confirmar — cae al address= fijo
            # (127.0.0.9), no es NXDOMAIN.
            centinela_fantasma = rb.centinela_de_generacion('0' * 64)
            self.assertFalse(rb._consulta_dns_centinela(centinela_fantasma, puerto=15791,
                                                         timeout_total_s=5, intentos=2))
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_sighup_cambia_de_generacion_sin_reiniciar(self):
        # El caso central de M1: tras un SIGHUP de verdad (mismo pid), el
        # centinela de la generación VIEJA deja de confirmar y el de la
        # NUEVA empieza a confirmar — nunca al revés, nunca los dos a la
        # vez.
        tmp = tempfile.mkdtemp(prefix='bloqueo-centinela-sighup-')
        dominios1 = {'ads.example.com'}
        hash1 = hashlib.sha256(('\n'.join(sorted(dominios1)) + '|').encode()).hexdigest()
        centinela1 = rb.centinela_de_generacion(hash1)
        texto1 = rb.generar_servers_file(dominios1 | {centinela1}, set())
        ruta_servers = os.path.join(tmp, 'servers.conf')
        proc = self._dnsmasq_temporal(tmp, 15793, texto1)
        try:
            self._esperar_puerto(15793)
            pid_antes = proc.pid
            self.assertTrue(rb._consulta_dns_centinela(centinela1, puerto=15793, timeout_total_s=5, intentos=2))

            dominios2 = {'ads.example.com', 'tracker.example.com'}
            hash2 = hashlib.sha256(('\n'.join(sorted(dominios2)) + '|').encode()).hexdigest()
            centinela2 = rb.centinela_de_generacion(hash2)
            self.assertNotEqual(centinela1, centinela2)
            texto2 = rb.generar_servers_file(dominios2 | {centinela2}, set())
            with open(ruta_servers, 'w') as f:
                f.write(texto2)
            os.kill(pid_antes, 1)   # SIGHUP — nunca se reinicia el proceso
            self.assertEqual(proc.pid, pid_antes)   # mismo pid tras el SIGHUP

            self.assertTrue(rb._consulta_dns_centinela(centinela2, puerto=15793, timeout_total_s=10, intentos=3),
                             'el centinela de la generación NUEVA debería confirmar tras el SIGHUP')
            self.assertFalse(rb._consulta_dns_centinela(centinela1, puerto=15793, timeout_total_s=5, intentos=2),
                              'el centinela de la generación VIEJA ya NO debería confirmar')
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_sin_dnsmasq_escuchando_no_confirma(self):
        self.assertFalse(rb._consulta_dns_centinela(rb.centinela_de_generacion('a' * 64),
                                                     puerto=15799, timeout_total_s=2, intentos=1))


# ─────────────────────────── descarga con caché/fallback ──────────────────

class _RespuestaFalsa:
    def __init__(self, cuerpo=b'', cabeceras=None):
        self._cuerpo = cuerpo
        self.headers = cabeceras or {}
        self._leido = False

    def read(self, n=None):
        if self._leido:
            return b''
        self._leido = True
        return self._cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _OpenerFalso:
    """Sustituye al opener real (urllib.request.build_opener(...)): guarda
    la Request recibida (para comprobar sus cabeceras — BAJA4) y devuelve/
    lanza lo que diga el test."""
    def __init__(self, resultado=None, excepcion=None):
        self.resultado = resultado
        self.excepcion = excepcion
        self.peticiones = []

    def open(self, peticion, timeout=None):
        self.peticiones.append(peticion)
        if self.excepcion is not None:
            raise self.excepcion
        return self.resultado


class TestDescargarLista(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-cache-')
        self.rutas = {'cache_dir': self.tmp}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _parchear_opener(self, **kw):
        opener = _OpenerFalso(**kw)
        return mock.patch('router_bloqueo.urllib.request.build_opener', return_value=opener), opener

    def test_descarga_ok_se_cachea(self):
        cuerpo = b'ads.example.com\nbad.net\n'
        parche, opener = self._parchear_opener(
            resultado=_RespuestaFalsa(cuerpo, {'ETag': '"abc"', 'Last-Modified': 'hoy'}))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        self.assertEqual(texto, cuerpo.decode())
        self.assertFalse(de_cache)
        self.assertIsNone(error)
        with open(rb._ruta_cache(self.rutas, 'x')) as f:
            self.assertEqual(f.read(), cuerpo.decode())
        with open(rb._ruta_meta(self.rutas, 'x')) as f:
            meta = json.load(f)
        self.assertEqual(meta['etag'], '"abc"')

    def test_304_usa_la_cache(self):
        with open(rb._ruta_cache(self.rutas, 'x'), 'w') as f:
            f.write('cached.example.com\n')
        with open(rb._ruta_meta(self.rutas, 'x'), 'w') as f:
            json.dump({'etag': '"viejo"'}, f)
        parche, opener = self._parchear_opener(
            excepcion=urllib.error.HTTPError('u', 304, 'Not Modified', {}, None))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        self.assertEqual(texto, 'cached.example.com\n')
        self.assertTrue(de_cache)
        self.assertIsNone(error)

    def test_fallo_de_red_usa_la_cache_anterior(self):
        with open(rb._ruta_cache(self.rutas, 'x'), 'w') as f:
            f.write('cached.example.com\n')
        parche, opener = self._parchear_opener(excepcion=OSError('sin red'))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        self.assertEqual(texto, 'cached.example.com\n')
        self.assertTrue(de_cache)
        self.assertIsNotNone(error)

    def test_fallo_de_red_sin_cache_devuelve_nada(self):
        parche, opener = self._parchear_opener(excepcion=OSError('sin red'))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        self.assertIsNone(texto)
        self.assertFalse(de_cache)
        self.assertIsNotNone(error)

    def test_http_500_usa_la_cache_anterior(self):
        with open(rb._ruta_cache(self.rutas, 'x'), 'w') as f:
            f.write('cached.example.com\n')
        parche, opener = self._parchear_opener(
            excepcion=urllib.error.HTTPError('u', 500, 'Internal Error', {}, None))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        self.assertEqual(texto, 'cached.example.com\n')
        self.assertTrue(de_cache)
        self.assertIsNotNone(error)

    def test_limite_de_tamano_aborta_y_usa_cache(self):
        with open(rb._ruta_cache(self.rutas, 'x'), 'w') as f:
            f.write('cached.example.com\n')
        parche, opener = self._parchear_opener(resultado=_RespuestaFalsa(b'a' * 200))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas,
                                                          limite_bytes=100)
        self.assertEqual(texto, 'cached.example.com\n')
        self.assertTrue(de_cache)
        self.assertIn('límite', error)

    def test_limite_de_tamano_sin_cache_no_guarda_nada_parcial(self):
        parche, opener = self._parchear_opener(resultado=_RespuestaFalsa(b'a' * 200))
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas,
                                                          limite_bytes=100)
        self.assertIsNone(texto)
        self.assertFalse(os.path.exists(rb._ruta_cache(self.rutas, 'x')))

    def test_plazo_total_supera_y_usa_cache(self):
        # BAJA5: aunque cada lectura individual sea "instantánea", si el
        # reloj total supera deadline_total_s se aborta igual.
        with open(rb._ruta_cache(self.rutas, 'x'), 'w') as f:
            f.write('cached.example.com\n')

        class _RespuestaLenta(_RespuestaFalsa):
            def read(self, n=None):
                return b'x' * 10   # nunca vacío: fuerza a comprobar el plazo en cada vuelta

        parche, opener = self._parchear_opener(resultado=_RespuestaLenta())
        with parche:
            texto, de_cache, error = rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas,
                                                          deadline_total_s=0)
        self.assertEqual(texto, 'cached.example.com\n')
        self.assertTrue(de_cache)
        self.assertIn('plazo total', error)

    # — BAJA4: sin caché previa, nunca se manda If-None-Match/If-Modified-Since —

    def test_sin_cache_previa_no_manda_cabeceras_condicionales(self):
        parche, opener = self._parchear_opener(resultado=_RespuestaFalsa(b'a.example.com\n'))
        with parche:
            rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        self.assertEqual(len(opener.peticiones), 1)
        cabeceras = {k.lower() for k in opener.peticiones[0].headers}
        self.assertNotIn('if-none-match', cabeceras)
        self.assertNotIn('if-modified-since', cabeceras)

    def test_con_cache_previa_si_manda_cabeceras_condicionales(self):
        with open(rb._ruta_cache(self.rutas, 'x'), 'w') as f:
            f.write('cached.example.com\n')
        with open(rb._ruta_meta(self.rutas, 'x'), 'w') as f:
            json.dump({'etag': '"abc"', 'last_modified': 'ayer'}, f)
        parche, opener = self._parchear_opener(resultado=_RespuestaFalsa(b'a.example.com\n'))
        with parche:
            rb.descargar_lista('x', 'https://ejemplo.invalido/x.txt', self.rutas)
        cabeceras = {k.lower(): v for k, v in opener.peticiones[0].headers.items()}
        self.assertEqual(cabeceras.get('if-none-match'), '"abc"')
        self.assertEqual(cabeceras.get('if-modified-since'), 'ayer')


class TestRedirectHandlerHttpsSolo(unittest.TestCase):
    def test_redireccion_https_se_sigue(self):
        handler = rb._SoloHTTPSRedirectHandler()
        with mock.patch.object(urllib.request.HTTPRedirectHandler, 'redirect_request', return_value='ok'):
            resultado = handler.redirect_request(None, None, 301, 'msg', {}, 'https://ejemplo.invalido/otro')
        self.assertEqual(resultado, 'ok')

    def test_redireccion_http_se_rechaza(self):
        handler = rb._SoloHTTPSRedirectHandler()
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(None, None, 301, 'msg', {}, 'http://ejemplo.invalido/otro')


# ───────────────────────────── generar() de punta a punta ──────────────────

class TestGenerarOrquestacion(unittest.TestCase):
    def setUp(self):
        # Las listas de prueba son diminutas: sin esto la guarda de variación
        # (que solo actúa desde MINIMO_GUARDA_VARIACION dominios) no se ejercita.
        _p = mock.patch.object(rb, "MINIMO_GUARDA_VARIACION", 1)
        _p.start()
        self.addCleanup(_p.stop)
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-generar-')
        self.rutas = {
            'cache_dir': os.path.join(self.tmp, 'cache'),
            'dnsmasq_bloqueo': os.path.join(self.tmp, 'dnsmasq-bloqueo.conf'),
            'estado': os.path.join(self.tmp, 'bloqueo.json'),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _parchear_descargas(self, cuerpos):
        def falso(id_lista, url, rutas, **kw):
            cuerpo = cuerpos.get(id_lista, '')
            return cuerpo, False, None
        return mock.patch('router_bloqueo.descargar_lista', side_effect=falso)

    def _leer_conf(self):
        with open(self.rutas['dnsmasq_bloqueo']) as f:
            return f.read()

    def test_habilitado_combina_listas_blanca_y_negra(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], lista_blanca=['bueno.com'],
                    lista_negra=['extra.manual.com'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos = {'hagezi_pro': 'ads.bueno.com\nads.malo.com\nbueno.com\n'}
        with self._parchear_descargas(cuerpos):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        conf = self._leer_conf()
        # "bueno.com" y su subdominio "ads.bueno.com" NUNCA se bloquean
        # (lista blanca); "bueno.com" SÍ aparece, pero como EXCEPCIÓN (M1).
        self.assertNotIn('server=/bueno.com/\n', conf)
        self.assertIn('server=/bueno.com/#', conf)
        self.assertNotIn('server=/ads.bueno.com/', conf)
        self.assertIn('server=/ads.malo.com/\n', conf)
        self.assertIn('server=/extra.manual.com/\n', conf)
        self.assertEqual(estado['total_dominios'], 2 + 1)   # +1: centinela de esta generación, siempre presente si habilitado
        # M1 (ronda 4): el centinela ya no es un nombre fijo, es por
        # generación (g<hash8>.bloqueo-centinela...) — se comprueba con
        # un patrón, no con una constante.
        self.assertRegex(conf, r'server=/g[0-9a-f]{8}\.%s/\n' % re.escape(rb.CENTINELA_BASE))

    def test_bloquear_doh_anade_canario_y_lista_doh(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=[], lista_blanca=[], lista_negra=[],
                    bloquear_doh=True, _gestionar_dnsmasq=False)
        cuerpos = {'hagezi_doh': 'dns.doh-provider.example\n'}
        with self._parchear_descargas(cuerpos):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        conf = self._leer_conf()
        self.assertIn('server=/%s/\n' % rb.CANARIO_DOH, conf)
        self.assertIn('server=/dns.doh-provider.example/\n', conf)
        ids_listas = {l['id'] for l in estado['listas']}
        self.assertIn('hagezi_doh', ids_listas)

    def test_deshabilitado_genera_fichero_vacio(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, habilitado=False, listas=['hagezi_pro'], _gestionar_dnsmasq=False)
        with self._parchear_descargas({'hagezi_pro': 'ads.malo.com\n'}):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        conf = self._leer_conf()
        self.assertNotIn('server=', conf)
        self.assertEqual(estado['total_dominios'], 0)
        self.assertEqual(estado['listas'], [])

    def test_publica_estado_json_atomico(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=[], _gestionar_dnsmasq=False)
        with self._parchear_descargas({}):
            rb.generar(cfg, self.rutas)
        with open(self.rutas['estado']) as f:
            estado = json.load(f)
        self.assertIn('generado', estado)
        self.assertIn('siguiente', estado)
        self.assertIn('total_dominios', estado)

    # — M5: dominios protegidos nunca bloqueables, ni por lista_negra —

    def test_dominio_protegido_en_lista_negra_nunca_se_bloquea(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=[], lista_negra=['github.com'],
                    bloquear_doh=False, _gestionar_dnsmasq=False, _dominio_casa=None)
        with self._parchear_descargas({}):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        conf = self._leer_conf()
        self.assertNotIn('server=/github.com/\n', conf)
        self.assertIn('server=/github.com/#', conf)   # protegido: sigue resolviendo

    def test_sufijo_publico_en_lista_negra_se_ignora(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=[], lista_negra=['co.uk'],
                    bloquear_doh=False, _gestionar_dnsmasq=False)
        with self._parchear_descargas({}):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        conf = self._leer_conf()
        self.assertNotIn('co.uk', conf)   # ni bloqueado ni excepción: simplemente se descarta

    def test_dominio_de_la_casa_protegido(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False,
                    _gestionar_dnsmasq=False, _dominio_casa='lan.home.arpa')
        cuerpos = {'hagezi_pro': 'nas.lan.home.arpa\notro.malo.com\n'}
        with self._parchear_descargas(cuerpos):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        conf = self._leer_conf()
        self.assertNotIn('server=/nas.lan.home.arpa/\n', conf)
        self.assertIn('server=/otro.malo.com/\n', conf)

    # — M4: cota global —

    def test_cota_global_recorta_y_avisa(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(20))}
        with self._parchear_descargas(cuerpos), mock.patch('router_bloqueo.LIMITE_DOMINIOS_TOTAL', 5):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        # CENTINELA se añade DESPUÉS del recorte (nunca cuenta contra la
        # cota: es fijo y minúsculo) — por eso el total es cota+1, no cota.
        self.assertEqual(estado['total_dominios'], 5 + 1)
        self.assertTrue(estado.get('recortado'))
        self.assertIn('recortado', msg)

    def test_sin_superar_la_cota_no_avisa(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos = {'hagezi_pro': 'd1.example.com\nd2.example.com\n'}
        with self._parchear_descargas(cuerpos), mock.patch('router_bloqueo.LIMITE_DOMINIOS_TOTAL', 5):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        self.assertNotIn('recortado', estado)

    # — M5: guarda de variación ±50% —

    def test_variacion_grande_misma_lista_aborta(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos_base = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos_base):
            ok1, msg1, estado1 = rb.generar(cfg, self.rutas)
        self.assertTrue(ok1, msg1)
        self.assertEqual(estado1['total_dominios'], 100 + 1)   # +1: CENTINELA
        conf_antes = self._leer_conf()

        cuerpos_rotos = {'hagezi_pro': 'd0.example.com\n'}   # de 100 a 1: -99%
        with self._parchear_descargas(cuerpos_rotos):
            ok2, msg2, estado2 = rb.generar(cfg, self.rutas)
        self.assertFalse(ok2)
        self.assertIn('varía más de un 50', msg2)
        # La config activa NO cambió: se quedó la de la primera pasada.
        self.assertEqual(self._leer_conf(), conf_antes)

    def test_variacion_grande_con_cambio_de_listas_no_aborta(self):
        cfg1 = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos1 = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos1):
            rb.generar(cfg1, self.rutas)

        cfg2 = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_tif'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos2 = {'hagezi_tif': 'd0.example.com\n'}   # listas DISTINTAS: la variación es esperada
        with self._parchear_descargas(cuerpos2):
            ok, msg, estado = rb.generar(cfg2, self.rutas)
        self.assertTrue(ok, msg)
        self.assertEqual(estado['total_dominios'], 1 + 1)   # +1: CENTINELA

    def test_primera_pasada_nunca_aborta_por_variacion(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(5000))}
        with self._parchear_descargas(cuerpos):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        self.assertEqual(estado['total_dominios'], 5000 + 1)   # +1: CENTINELA

    def test_variacion_pequena_no_aborta(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos1 = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos1):
            rb.generar(cfg, self.rutas)
        cuerpos2 = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(110))}   # +10%
        with self._parchear_descargas(cuerpos2):
            ok, msg, estado = rb.generar(cfg, self.rutas)
        self.assertTrue(ok, msg)
        self.assertEqual(estado['total_dominios'], 110 + 1)   # +1: CENTINELA

    def test_reactivar_tras_deshabilitado_no_cuenta_como_variacion(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos):
            rb.generar(cfg, self.rutas)
        cfg_off = dict(cfg, habilitado=False)
        with self._parchear_descargas({}):
            rb.generar(cfg_off, self.rutas)   # no actualiza el "último" (habilitado=False)
        with self._parchear_descargas(cuerpos):
            ok, msg, estado = rb.generar(cfg, self.rutas)   # vuelve a activarse: mismo total de antes
        self.assertTrue(ok, msg)
        self.assertEqual(estado['total_dominios'], 100 + 1)   # +1: CENTINELA

    # — BAJA4 (ronda 3): forzar=True salta la guarda; 3 pasadas consecutivas
    # con un total parecido se aceptan solas —

    def test_forzar_salta_la_guarda(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos_base = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos_base):
            rb.generar(cfg, self.rutas)
        cuerpos_rotos = {'hagezi_pro': 'd0.example.com\n'}
        with self._parchear_descargas(cuerpos_rotos):
            ok, msg, estado = rb.generar(cfg, self.rutas, forzar=True)
        self.assertTrue(ok, msg)
        self.assertEqual(estado['total_dominios'], 1 + 1)   # +1: CENTINELA

    def test_tres_pasadas_consecutivas_parecidas_se_aceptan(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos_base = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos_base):
            rb.generar(cfg, self.rutas)
        cuerpos_nuevos = {'hagezi_pro': '\n'.join('x%d.example.com' % i for i in range(5))}   # -95%: dispara la guarda
        with self._parchear_descargas(cuerpos_nuevos):
            ok1, msg1, _ = rb.generar(cfg, self.rutas)
            ok2, msg2, _ = rb.generar(cfg, self.rutas)
            ok3, msg3, estado3 = rb.generar(cfg, self.rutas)
        self.assertFalse(ok1)
        self.assertFalse(ok2)
        self.assertTrue(ok3, msg3)   # la 3ª vez, con un total parecido, se acepta
        self.assertEqual(estado3['total_dominios'], 5 + 1)

    def test_total_distinto_cada_vez_nunca_se_acepta_solo(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos_base = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos_base):
            rb.generar(cfg, self.rutas)
        for n in (3, 7, 12):   # cada vez un total DISTINTO: nunca "converge"
            cuerpos = {'hagezi_pro': '\n'.join('x%d.example.com' % i for i in range(n))}
            with self._parchear_descargas(cuerpos):
                ok, msg, _ = rb.generar(cfg, self.rutas)
            self.assertFalse(ok)

    def test_pasada_normal_borra_la_variacion_pendiente(self):
        cfg = dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False, _gestionar_dnsmasq=False)
        cuerpos_base = {'hagezi_pro': '\n'.join('d%d.example.com' % i for i in range(100))}
        with self._parchear_descargas(cuerpos_base):
            rb.generar(cfg, self.rutas)
        with self._parchear_descargas({'hagezi_pro': 'x0.example.com\n'}):
            rb.generar(cfg, self.rutas)   # dispara la guarda una vez (veces=1)
        self.assertIsNotNone(rb._leer_variacion_pendiente(self.rutas))
        with self._parchear_descargas(cuerpos_base):
            ok, msg, _ = rb.generar(cfg, self.rutas, forzar=True)   # vuelve a lo normal (forzado)
        self.assertTrue(ok, msg)
        self.assertIsNone(rb._leer_variacion_pendiente(self.rutas))


class TestBarrerTemporalesYMarcadorForzar(unittest.TestCase):
    """BAJA5/BAJA4 (ronda 3)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-barrer-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tocar(self, nombre, antiguedad_s=0):
        ruta = os.path.join(self.tmp, nombre)
        with open(ruta, 'w') as f:
            f.write('x')
        if antiguedad_s:
            viejo = time.time() - antiguedad_s
            os.utime(ruta, (viejo, viejo))
        return ruta

    def test_barre_tmp_bloqueo_viejo(self):
        ruta = self._tocar('.tmp-bloqueo-abc123', antiguedad_s=3700)
        rb._barrer_temporales_viejos(self.tmp)
        self.assertFalse(os.path.exists(ruta))

    def test_barre_stub_viejo(self):
        ruta = self._tocar('.tmp-bloqueo-abc123.stub', antiguedad_s=3700)
        rb._barrer_temporales_viejos(self.tmp)
        self.assertFalse(os.path.exists(ruta))

    def test_no_barre_reciente(self):
        ruta = self._tocar('.tmp-bloqueo-reciente', antiguedad_s=10)
        rb._barrer_temporales_viejos(self.tmp)
        self.assertTrue(os.path.exists(ruta))

    def test_no_toca_ficheros_normales(self):
        ruta = self._tocar('hagezi_pro.txt', antiguedad_s=3700)
        rb._barrer_temporales_viejos(self.tmp)
        self.assertTrue(os.path.exists(ruta))

    def test_marcador_forzar_se_lee_y_se_borra(self):
        rutas = {'cache_dir': self.tmp}
        with open(rb._ruta_marcador_forzar(rutas), 'w') as f:
            f.write('1')
        self.assertTrue(rb._leer_y_borrar_marcador_forzar(rutas))
        self.assertFalse(os.path.exists(rb._ruta_marcador_forzar(rutas)))
        self.assertFalse(rb._leer_y_borrar_marcador_forzar(rutas))   # ya no está: una sola vez


# ───────────────────────────── comprobar_dominio ───────────────────────────

class TestComprobarDominio(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-probar-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cache(self, id_lista, dominios):
        with open(os.path.join(self.tmp, '%s.txt' % id_lista), 'w') as f:
            f.write('\n'.join(dominios) + '\n')

    def test_dominio_no_valido(self):
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO)}
        out = rb.comprobar_dominio('evil.com/', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])

    def test_lista_negra_manual(self):
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=[], bloquear_doh=False,
                                lista_negra=['manual.example.com'])}
        out = rb.comprobar_dominio('sub.manual.example.com', cfg, {'cache_dir': self.tmp})
        self.assertTrue(out['bloqueado'])
        self.assertEqual(out['lista'], 'lista_negra')

    def test_lista_blanca_gana_a_la_lista_de_bloqueo(self):
        self._cache('hagezi_pro', ['ads.example.com'])
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False,
                                lista_blanca=['example.com'])}
        out = rb.comprobar_dominio('ads.example.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])
        self.assertEqual(out['lista'], 'lista_blanca')

    def test_m1_hijo_en_lista_blanca_bajo_padre_bloqueado_no_se_bloquea(self):
        # El caso central de M1: la lista sólo trae "example.com" (el
        # padre), lista_blanca tiene "bueno.example.com" (un hijo más
        # específico) — debe decir la verdad: NO bloqueado.
        self._cache('hagezi_pro', ['example.com'])
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False,
                                lista_blanca=['bueno.example.com'])}
        self.assertTrue(rb.comprobar_dominio('otro.example.com', cfg, {'cache_dir': self.tmp})['bloqueado'])
        out = rb.comprobar_dominio('bueno.example.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])
        self.assertEqual(out['lista'], 'lista_blanca')

    def test_dominio_protegido_gana_a_lista_negra(self):
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=[], bloquear_doh=False,
                                lista_negra=['github.com'])}
        out = rb.comprobar_dominio('github.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])
        self.assertEqual(out['lista'], 'protegido')

    def test_subdominio_de_protegido_tambien_protegido(self):
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=[], bloquear_doh=False)}
        out = rb.comprobar_dominio('sub.raw.githubusercontent.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])
        self.assertEqual(out['lista'], 'protegido')

    def test_dominio_de_la_casa_protegido(self):
        cfg = {'dominio': 'lan.home.arpa',
               'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=[], bloquear_doh=False,
                                lista_negra=['nas.lan.home.arpa'])}
        out = rb.comprobar_dominio('nas.lan.home.arpa', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])
        self.assertEqual(out['lista'], 'protegido')

    def test_bloqueo_desactivado_nunca_bloquea(self):
        self._cache('hagezi_pro', ['ads.example.com'])
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, habilitado=False, listas=['hagezi_pro'], bloquear_doh=False)}
        out = rb.comprobar_dominio('ads.example.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])

    def test_canario_doh(self):
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=[], bloquear_doh=True)}
        out = rb.comprobar_dominio(rb.CANARIO_DOH, cfg, {'cache_dir': self.tmp})
        self.assertTrue(out['bloqueado'])
        self.assertEqual(out['lista'], 'canario_doh')

    def test_encontrado_en_lista_activa(self):
        self._cache('hagezi_tif', ['malware.evil.net'])
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_tif'], bloquear_doh=False)}
        out = rb.comprobar_dominio('sub.malware.evil.net', cfg, {'cache_dir': self.tmp})
        self.assertTrue(out['bloqueado'])
        self.assertEqual(out['lista'], 'hagezi_tif')

    def test_no_encontrado_en_ninguna_lista(self):
        self._cache('hagezi_tif', ['malware.evil.net'])
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_tif'], bloquear_doh=False)}
        out = rb.comprobar_dominio('bien.example.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])

    def test_lista_sin_cache_no_revienta(self):
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro'], bloquear_doh=False)}
        out = rb.comprobar_dominio('lo-que-sea.example.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])

    def test_id_fuera_de_catalogo_se_ignora(self):
        # BAJA8: nunca intenta abrir una caché para un id inventado.
        cfg = {'bloqueo': dict(rb.DEFECTO_BLOQUEO, listas=['no_existe_este_id'], bloquear_doh=False)}
        out = rb.comprobar_dominio('x.example.com', cfg, {'cache_dir': self.tmp})
        self.assertFalse(out['bloqueado'])


# ───────────────────── calcular_version_bloqueo (panel) ───────────────────

class TestCalcularVersionBloqueo(unittest.TestCase):
    def test_version_estable_para_el_mismo_contenido(self):
        bloqueo = dict(rb.DEFECTO_BLOQUEO)
        self.assertEqual(rb.calcular_version_bloqueo(bloqueo), rb.calcular_version_bloqueo(dict(bloqueo)))

    def test_version_cambia_si_cambia_listas(self):
        v1 = rb.calcular_version_bloqueo(dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_pro']))
        v2 = rb.calcular_version_bloqueo(dict(rb.DEFECTO_BLOQUEO, listas=['hagezi_tif']))
        self.assertNotEqual(v1, v2)

    def test_version_ignora_lista_blanca_y_negra(self):
        base = dict(rb.DEFECTO_BLOQUEO)
        v1 = rb.calcular_version_bloqueo(dict(base, lista_blanca=['a.com']))
        v2 = rb.calcular_version_bloqueo(dict(base, lista_blanca=['b.com'], lista_negra=['c.com']))
        self.assertEqual(v1, v2)

    def test_version_es_hex_de_16(self):
        import re as _re
        v = rb.calcular_version_bloqueo(rb.DEFECTO_BLOQUEO)
        self.assertTrue(_re.fullmatch(r'[0-9a-f]{16}', v))

    def test_version_vacio_no_lanza(self):
        self.assertIsNotNone(rb.calcular_version_bloqueo({}))
        self.assertIsNotNone(rb.calcular_version_bloqueo(None))


# ───────────────────────────── fase / main (BAJA3, M3) ─────────────────────

class TestFaseEfectiva(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-fase-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _escribir(self, nombre, contenido):
        ruta = os.path.join(self.tmp, nombre)
        with open(ruta, 'w') as f:
            f.write(contenido)
        return ruta

    def test_fichero_de_fase_manda(self):
        ruta_fase = self._escribir('fase', 'produccion')
        ruta_cfg = self._escribir('router.json', '{"fase": "preparacion"}')
        self.assertEqual(rb._fase_efectiva(ruta_fase, ruta_cfg), 'produccion')

    def test_sin_fichero_cae_a_router_json(self):
        ruta_fase = os.path.join(self.tmp, 'no-existe')
        ruta_cfg = self._escribir('router.json', '{"fase": "produccion"}')
        self.assertEqual(rb._fase_efectiva(ruta_fase, ruta_cfg), 'produccion')

    def test_sin_nada_es_preparacion(self):
        ruta_fase = os.path.join(self.tmp, 'no-existe')
        ruta_cfg = os.path.join(self.tmp, 'tampoco')
        self.assertEqual(rb._fase_efectiva(ruta_fase, ruta_cfg), 'preparacion')


class TestMainFaseYReintentos(unittest.TestCase):
    """main() fuera de producción no hace nada (BAJA3); con la config
    cambiando a mitad, repite la pasada hasta 3 veces (M3)."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bloqueo-main-')
        self.ruta_cfg = os.path.join(self.tmp, 'router.json')
        self.ruta_fase = os.path.join(self.tmp, 'fase')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _escribir_cfg(self, bloqueo):
        with open(self.ruta_cfg, 'w') as f:
            json.dump({'bloqueo': bloqueo, 'dominio': 'home.arpa'}, f)

    def test_fuera_de_produccion_no_llama_a_generar(self):
        with open(self.ruta_fase, 'w') as f:
            f.write('preparacion')
        self._escribir_cfg({'habilitado': True, 'listas': []})
        argv = ['router_bloqueo.py', '--config', self.ruta_cfg, '--fase', self.ruta_fase,
                '--raiz-datos', self.tmp]
        with mock.patch.object(sys, 'argv', argv), mock.patch('router_bloqueo.generar') as m_generar:
            rc = rb.main()
        self.assertEqual(rc, 0)
        m_generar.assert_not_called()

    def test_en_produccion_reintenta_si_la_config_cambia_a_mitad(self):
        with open(self.ruta_fase, 'w') as f:
            f.write('produccion')
        self._escribir_cfg({'habilitado': True, 'listas': []})
        llamadas = {'n': 0}

        def _generar_falso(cfg_bloqueo, rutas, forzar=False):
            llamadas['n'] += 1
            if llamadas['n'] == 1:
                # Simula que el buzón (vía routerd) cambió la config
                # MIENTRAS esta pasada estaba en marcha.
                self._escribir_cfg({'habilitado': True, 'listas': ['hagezi_pro']})
            return True, 'ok', {'total_dominios': 0}

        argv = ['router_bloqueo.py', '--config', self.ruta_cfg, '--fase', self.ruta_fase,
                '--raiz-datos', self.tmp]
        with mock.patch.object(sys, 'argv', argv), \
             mock.patch('router_bloqueo.generar', side_effect=_generar_falso), \
             mock.patch('router_bloqueo.escribir_oplog'):
            rc = rb.main()
        self.assertEqual(rc, 0)
        self.assertEqual(llamadas['n'], 2)   # cambió una vez → se repite una vez más, y ya coincide

    def test_en_produccion_nunca_mas_de_3_intentos(self):
        with open(self.ruta_fase, 'w') as f:
            f.write('produccion')
        self._escribir_cfg({'habilitado': True, 'listas': []})
        llamadas = {'n': 0}

        def _generar_falso(cfg_bloqueo, rutas, forzar=False):
            llamadas['n'] += 1
            self._escribir_cfg({'habilitado': True, 'listas': ['d%d' % llamadas['n']]})   # cambia SIEMPRE
            return True, 'ok', {'total_dominios': 0}

        argv = ['router_bloqueo.py', '--config', self.ruta_cfg, '--fase', self.ruta_fase,
                '--raiz-datos', self.tmp]
        with mock.patch.object(sys, 'argv', argv), \
             mock.patch('router_bloqueo.generar', side_effect=_generar_falso), \
             mock.patch('router_bloqueo.escribir_oplog'):
            rb.main()
        self.assertEqual(llamadas['n'], 3)   # nunca más de 3, aunque siga cambiando


if __name__ == '__main__':
    unittest.main()


class TestGuardaVariacionSoloListas(unittest.TestCase):
    """La guarda ±50% mira solo lo descargado, nunca la lista blanca/negra."""

    def test_minimo_por_defecto(self):
        self.assertGreaterEqual(rb.MINIMO_GUARDA_VARIACION, 1000)

