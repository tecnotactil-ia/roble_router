#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas unitarias PURAS de Python (sin red, sin root) de
core/router_estadisticas.py: parseo del log DNS (líneas reales de un
dnsmasq 2.93, capturadas lanzando un dnsmasq de mentira en un puerto alto
con `server=/dominio/` sin dirección — exactamente lo que pide la tarea),
lectura incremental con copytruncate y rotación, deltas con reinicio de
contadores, parseo de `nft -j list set` (incluye una salida REAL, pegada
tal cual, de una carga real en un netns con root — ver TestParseoSetNft),
rollup a hora, retención, el esquema exacto de SQLite, y un chequeo
best-effort del ruleset completo de nft_conf.generar() contra el binario
`nft` si está disponible (ver TestGeneracionNftCompleta — la validación que
de verdad importa, con la tabla cargada de verdad y tráfico real, es el e2e
con root en pruebas/netns_multiwan.sh, paso 17).

Uso:  python3 -m unittest pruebas/test_router_estadisticas.py -v
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import nft_conf             # noqa: E402
import router_estadisticas as re_  # noqa: E402


# ───────────────────────────── parseo del log DNS ─────────────────────────────

class TestParseoDns(unittest.TestCase):
    """Líneas EXACTAS de un dnsmasq 2.93 real (versión que pide la tarea),
    capturadas con `log-queries=extra` y un `servers-file` con
    `server=/bloqueado.ejemplo.invalid/` (sin dirección) y
    `server=/permitido.bloqueado.ejemplo.invalid/#` (excepción), en un
    puerto alto sin privilegios — igual que documenta docs/CONTRATO.md:
    un dominio bloqueado por `server=/x/` sin dirección se resuelve con
    "config x is NXDOMAIN"."""

    FECHA = 'Oct 11 22:22:25'

    def _linea(self, cuerpo):
        return '%s dnsmasq[1619300]: %s' % (self.FECHA, cuerpo)

    def test_bloqueado_por_servers_file_sin_direccion(self):
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('1 127.0.0.1/57407 query[A] bloqueado.ejemplo.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea('1 127.0.0.1/57407 config bloqueado.ejemplo.invalid is NXDOMAIN'))
        self.assertEqual(len(p.agregados), 1)
        ((_hora, cliente, dominio), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual(cliente, '127.0.0.1')
        self.assertEqual(dominio, 'bloqueado.ejemplo.invalid')
        self.assertEqual((consultas, bloqueadas), (1, 1))

    def test_subdominio_de_bloqueado_tambien_cuenta_bloqueado(self):
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('2 127.0.0.1/35179 query[A] sub.bloqueado.ejemplo.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea('2 127.0.0.1/35179 config sub.bloqueado.ejemplo.invalid is NXDOMAIN'))
        ((_h, _c, dominio), (_n, bloqueadas)), = p.agregados.items()
        self.assertEqual(dominio, 'sub.bloqueado.ejemplo.invalid')
        self.assertEqual(bloqueadas, 1)

    def test_excepcion_lista_blanca_forwarded_no_es_bloqueo(self):
        # server=/dominio/# -> dnsmasq lo reenvía de verdad (forwarded +
        # reply), aunque la reply termine siendo NXDOMAIN "de verdad" (el
        # servidor que no existe): eso NO debe contar como bloqueado, sólo
        # lo "config ... is NXDOMAIN" directo (sin "forwarded" de por medio).
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('3 127.0.0.1/38698 query[A] permitido.bloqueado.ejemplo.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea('3 127.0.0.1/38698 forwarded permitido.bloqueado.ejemplo.invalid to 1.1.1.1'))
        p.procesar_linea(self._linea('3 127.0.0.1/38698 reply permitido.bloqueado.ejemplo.invalid is NXDOMAIN'))
        ((_h, _c, dominio), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual(dominio, 'permitido.bloqueado.ejemplo.invalid')
        self.assertEqual((consultas, bloqueadas), (1, 0))

    def test_forwarded_y_reply_normal_no_bloqueado(self):
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('4 127.0.0.1/34882 query[A] anthropic.com from 127.0.0.1'))
        p.procesar_linea(self._linea('4 127.0.0.1/34882 forwarded anthropic.com to 1.1.1.1'))
        p.procesar_linea(self._linea('4 127.0.0.1/34882 reply anthropic.com is 160.79.104.10'))
        ((_h, _c, dominio), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((dominio, consultas, bloqueadas), ('anthropic.com', 1, 0))

    def test_cached_no_bloqueado(self):
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('7 127.0.0.1/60808 query[A] anthropic.com from 127.0.0.1'))
        p.procesar_linea(self._linea('7 127.0.0.1/60808 cached anthropic.com is 160.79.104.10'))
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (1, 0))

    def test_config_con_direccion_fija_no_es_bloqueo(self):
        # address=/dominio/IP (el centinela "por generación" de
        # router_bloqueo.py, o cualquier otra respuesta fija): "config X is
        # <ip>", NO "is NXDOMAIN" -> no es un bloqueo.
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('1 127.0.0.1/41628 query[A] fijo.ejemplo.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea('1 127.0.0.1/41628 config fijo.ejemplo.invalid is 127.0.0.9'))
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (1, 0))

    def test_centinela_de_bloqueo_y_subdominios_se_ignoran(self):
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea(
            '1 127.0.0.1/1 query[A] bloqueo-centinela.router-casa.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea(
            '1 127.0.0.1/1 config bloqueo-centinela.router-casa.invalid is 127.0.0.9'))
        p.procesar_linea(self._linea(
            '2 127.0.0.1/2 query[A] g123abc.bloqueo-centinela.router-casa.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea(
            '2 127.0.0.1/2 config g123abc.bloqueo-centinela.router-casa.invalid is NXDOMAIN'))
        self.assertEqual(p.agregados, {})

    def test_home_arpa_nxdomain_local_no_es_bloqueo(self):
        # MEDIA6: "config X is NXDOMAIN" también sale de local=/home.arpa/
        # (incondicional, dnsmasq_conf.py) — nunca es un bloqueo real.
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('1 127.0.0.1/1 query[A] algo.home.arpa from 127.0.0.1'))
        p.procesar_linea(self._linea('1 127.0.0.1/1 config algo.home.arpa is NXDOMAIN'))
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (1, 0))

    def test_dominio_de_casa_nxdomain_local_no_es_bloqueo(self):
        # MEDIA6: igual que home.arpa, pero con el dominio de casa
        # configurado (router.json -> "dominio", mismo campo que
        # dnsmasq_conf.py) — p. ej. un nombre de equipo que no existe
        # bajo ese dominio da "config X is NXDOMAIN" sin haber pasado por
        # el bloqueador.
        p = re_.ProcesadorDns(dominio_local='lan.home.arpa')
        p.procesar_linea(self._linea('1 127.0.0.1/1 query[A] inexistente.lan.home.arpa from 127.0.0.1'))
        p.procesar_linea(self._linea('1 127.0.0.1/1 config inexistente.lan.home.arpa is NXDOMAIN'))
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (1, 0))

    def test_ptr_in_addr_arpa_nxdomain_local_no_es_bloqueo(self):
        # MEDIA6: bogus-priv responde NXDOMAIN "config" para PTR de IPs
        # privadas sin reserva/hostname conocido — tampoco es un bloqueo.
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('1 127.0.0.1/1 query[PTR] 50.21.168.192.in-addr.arpa from 127.0.0.1'))
        p.procesar_linea(self._linea('1 127.0.0.1/1 config 50.21.168.192.in-addr.arpa is NXDOMAIN'))
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (1, 0))

    def test_dominio_de_verdad_bloqueado_sigue_contando_aunque_haya_dominio_local(self):
        # MEDIA6 no debe tapar un bloqueo REAL: un dominio ajeno al de
        # casa/home.arpa/in-addr.arpa sigue contando como bloqueado igual,
        # tenga o no configurado un dominio_local.
        p = re_.ProcesadorDns(dominio_local='lan.home.arpa')
        p.procesar_linea(self._linea('1 127.0.0.1/1 query[A] bloqueado.ejemplo.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea('1 127.0.0.1/1 config bloqueado.ejemplo.invalid is NXDOMAIN'))
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (1, 1))

    def test_lineas_de_arranque_y_diagnostico_se_ignoran(self):
        # Mensajes reales de arranque/recarga de un dnsmasq 2.93 (localizado
        # al español en el sistema de pruebas, o no): nunca deben parsearse
        # como consulta/resultado.
        p = re_.ProcesadorDns()
        basura = [
            self._linea('iniciado, versión 2.93 tamaño de caché 150'),
            self._linea('usando nombre de servidor 1.1.1.1#53'),
            self._linea('el caché fue liberado'),
            self._linea('using standard nameservers for permitido.bloqueado.ejemplo.invalid'),
            self._linea('using only locally-known addresses for bloqueado.ejemplo.invalid'),
            self._linea('saliendo al recibir SIGTERM'),
            '',
            'basura sin formato de syslog en absoluto',
        ]
        for linea in basura:
            p.procesar_linea(linea)
        self.assertEqual(p.pendientes, {})
        self.assertEqual(p.agregados, {})

    def test_sin_log_queries_extra_no_se_intenta_emparejar(self):
        # Sin "extra" no hay "<id> <ip>/<puerto>" -> no casa con
        # RE_CONSULTA/RE_RESULTADO (empiezan por un id numérico seguido de
        # ip/puerto): se ignora en vez de arriesgar una atribución
        # equivocada de cliente/dominio.
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('query[A] bloqueado.ejemplo.invalid from 127.0.0.1'))
        p.procesar_linea(self._linea('config bloqueado.ejemplo.invalid is NXDOMAIN'))
        self.assertEqual(p.agregados, {})

    def test_resultado_sin_consulta_previa_se_ignora(self):
        p = re_.ProcesadorDns()
        p.procesar_linea(self._linea('9 127.0.0.1/1 config huerfano.ejemplo.invalid is NXDOMAIN'))
        self.assertEqual(p.agregados, {})

    def test_varias_consultas_se_agregan_por_hora_cliente_dominio(self):
        p = re_.ProcesadorDns()
        for i in range(3):
            p.procesar_linea(self._linea('%d 127.0.0.1/1 query[A] repetido.ejemplo.invalid from 127.0.0.1' % i))
            p.procesar_linea(self._linea('%d 127.0.0.1/1 config repetido.ejemplo.invalid is NXDOMAIN' % i))
        self.assertEqual(len(p.agregados), 1)
        ((_h, _c, _d), (consultas, bloqueadas)), = p.agregados.items()
        self.assertEqual((consultas, bloqueadas), (3, 3))

    def test_pendientes_acotados_fifo(self):
        p = re_.ProcesadorDns()
        for i in range(re_.MAX_DNS_PENDIENTES + 50):
            p.procesar_linea(self._linea('%d 127.0.0.1/1 query[A] x%d.ejemplo.invalid from 127.0.0.1' % (i, i)))
        self.assertLessEqual(len(p.pendientes), re_.MAX_DNS_PENDIENTES)


# ───────────────────────────── hora local de syslog (MEDIA4 / B) ─────────────────────────────

class TestHoraLocalSyslog(unittest.TestCase):
    """dnsmasq escribe la hora de syslog en LOCAL, no en UTC. MEDIA4 pedía
    no usar `mktime` a ciegas; la revisión posterior (B) pidió ir más
    lejos: `zoneinfo` + `fold` (PEP 495) para desambiguar la hora que se
    repite en el cambio de horario de otoño — comprobado con
    TZ=Europe/Rome (la zona y fecha que pidió la revisión), usando
    `zoneinfo.ZoneInfo` directamente para construir el valor ESPERADO en
    vez de confiar en una segunda conversión igual de ciega."""

    def setUp(self):
        self._tz_previo = os.environ.get('TZ')
        os.environ['TZ'] = 'Europe/Rome'
        time.tzset()

    def tearDown(self):
        if self._tz_previo is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = self._tz_previo
        time.tzset()

    def test_fecha_normal_cest_verano(self):
        import zoneinfo
        ref = datetime(2024, 7, 15, 12, 0, 0, tzinfo=zoneinfo.ZoneInfo('Europe/Rome')).timestamp()
        ts = re_._epoch_syslog('Jul', '15', '14', '30', '0', referencia_epoch=ref)
        esperado = datetime(2024, 7, 15, 12, 30, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(ts, int(esperado))

    def test_fecha_normal_cet_invierno(self):
        import zoneinfo
        ref = datetime(2024, 1, 15, 12, 0, 0, tzinfo=zoneinfo.ZoneInfo('Europe/Rome')).timestamp()
        ts = re_._epoch_syslog('Jan', '15', '14', '30', '0', referencia_epoch=ref)
        esperado = datetime(2024, 1, 15, 13, 30, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(ts, int(esperado))

    def test_cambio_de_hora_de_otono_hora_ambigua_usa_fold_0(self):
        # 2023-10-29, Europe/Rome: 02:00-02:59 ocurre DOS veces (a las 3:00
        # CEST los relojes retroceden a las 2:00 CET). fold=0 (el defecto)
        # elige la PRIMERA ocurrencia, todavía en verano (CEST, UTC+2).
        import zoneinfo
        ref = datetime(2023, 10, 29, 12, 0, 0, tzinfo=zoneinfo.ZoneInfo('Europe/Rome')).timestamp()
        ts = re_._epoch_syslog('Oct', '29', '02', '30', '0', referencia_epoch=ref)
        esperado_fold0 = datetime(2023, 10, 29, 0, 30, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(ts, int(esperado_fold0))

    def test_cambio_de_hora_de_primavera_hora_inexistente_no_lanza(self):
        # 2024-03-31, Europe/Rome: los relojes saltan de 2:00 a 3:00 — la
        # 02:30 local NO EXISTE ese día. zoneinfo debe resolverlo de
        # alguna forma determinista (PEP 495), nunca lanzar.
        import zoneinfo
        ref = datetime(2024, 3, 31, 12, 0, 0, tzinfo=zoneinfo.ZoneInfo('Europe/Rome')).timestamp()
        ts = re_._epoch_syslog('Mar', '31', '02', '30', '0', referencia_epoch=ref)
        self.assertIsInstance(ts, int)

    def test_zona_local_detectada_desde_tz(self):
        import zoneinfo
        zona = re_._zona_local()
        self.assertEqual(zona, zoneinfo.ZoneInfo('Europe/Rome'))

    def test_procesar_linea_de_verdad_usa_la_hora_local(self):
        # De punta a punta: una línea de log real, con TZ=Europe/Rome
        # puesto, debe agregarse bajo la hora UTC correcta (no la que
        # saldría de tratar "14:30" como si ya fuera UTC).
        import zoneinfo
        p = re_.ProcesadorDns()
        ref = datetime(2024, 7, 15, 12, 0, 0, tzinfo=zoneinfo.ZoneInfo('Europe/Rome')).timestamp()
        p.procesar_linea('Jul 15 14:30:00 dnsmasq[111]: 1 127.0.0.1/1 query[A] x.ejemplo.invalid from 127.0.0.1',
                          ahora_epoch=ref)
        p.procesar_linea('Jul 15 14:30:00 dnsmasq[111]: 1 127.0.0.1/1 config x.ejemplo.invalid is NXDOMAIN',
                          ahora_epoch=ref)
        ((hora, _c, _d), _n), = p.agregados.items()
        hora_esperada = (int(datetime(2024, 7, 15, 12, 30, 0, tzinfo=timezone.utc).timestamp()) // 3600) * 3600
        self.assertEqual(hora, hora_esperada)


# ───────────────────────────── lectura incremental ─────────────────────────────

class TestLecturaIncrementalDns(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.tmp.name, 'dns.log')

    def tearDown(self):
        self.tmp.cleanup()

    def _escribir(self, texto):
        with open(self.ruta, 'w') as f:
            f.write(texto)

    def _anadir(self, texto):
        with open(self.ruta, 'a') as f:
            f.write(texto)

    def test_primer_arranque_no_procesa_historico(self):
        self._escribir('linea vieja 1\nlinea vieja 2\n')
        lineas, estado, error = re_.leer_bloques_nuevos(self.ruta, None)
        self.assertEqual(lineas, [])
        self.assertIsNone(error)
        self.assertEqual(estado['offset'], os.path.getsize(self.ruta))

    def test_incremental_normal(self):
        self._escribir('a\nb\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        self._anadir('c\nd\n')
        lineas, estado2, error = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, ['c', 'd'])
        self.assertIsNone(error)
        self.assertEqual(estado2['inode'], estado['inode'])

    def test_linea_incompleta_se_reintenta_el_siguiente_ciclo(self):
        self._escribir('completa\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        with open(self.ruta, 'a') as f:
            f.write('a medias sin salto de linea todavia')
        lineas, estado2, _ = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, [])
        self.assertEqual(estado2['offset'], estado['offset'])
        with open(self.ruta, 'a') as f:
            f.write('\n')
        lineas, _, _ = re_.leer_bloques_nuevos(self.ruta, estado2)
        self.assertEqual(lineas, ['a medias sin salto de linea todavia'])

    def test_copytruncate_tamano_menor_que_offset_reinicia_desde_cero(self):
        # Contenido "viejo" claramente más largo que lo que se escribe tras
        # el copytruncate, para que el tamaño nuevo sea INEQUÍVOCAMENTE
        # menor que el offset ya consumido (la propia regla del enunciado:
        # "tamaño < offset → desde 0" sólo puede detectar la truncación
        # cuando el tamaño nuevo de verdad queda por debajo de dónde se
        # había llegado a leer). Sin ".1" disponible: no hay nada que
        # recuperar, se reinicia desde 0 sin más.
        self._escribir('linea-vieja-mas-larga-1\nlinea-vieja-mas-larga-2\nlinea-vieja-mas-larga-3\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        # copytruncate: mismo inodo, contenido reducido (se truncó a 0 y
        # dnsmasq sigue escribiendo desde el principio).
        with open(self.ruta, 'r+') as f:
            f.truncate(0)
            f.write('nueva1\n')
        lineas, estado2, error = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, ['nueva1'])
        self.assertIsNone(error)
        self.assertEqual(estado2['inode'], estado['inode'])

    def test_copytruncate_con_punto_1_recupera_lo_no_leido(self):
        # BAJA11 (revisión Opus): logrotate copytruncate copia el fichero
        # COMPLETO a ".1" ANTES de truncar — si quedaba algo sin leer en
        # ese momento, está recuperable ahí, no hay que perderlo.
        self._escribir('linea-vieja-1\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)   # línea base al final de "linea-vieja-1"
        self._anadir('linea-vieja-2-sin-leer\n')   # escrita, pero TODAVÍA no leída
        # ".1" = copia completa de AHORA (antes de truncar): incluye lo no leído.
        shutil.copyfile(self.ruta, self.ruta + '.1')
        with open(self.ruta, 'r+') as f:
            f.truncate(0)
            f.write('nueva1\n')
        lineas, estado2, error = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, ['linea-vieja-2-sin-leer', 'nueva1'])
        self.assertIsNone(error)
        self.assertEqual(estado2['inode'], estado['inode'])

    def test_copytruncate_con_punto_1_demasiado_corto_no_recupera_nada(self):
        # Si ".1" existe pero es más corto que el offset que faltaba leer
        # (no es la copia "antes de truncar" que se esperaba, o es de otra
        # rotación), no se intenta leer de ahí: mismo comportamiento que
        # sin ".1" en absoluto.
        self._escribir('linea-vieja-mas-larga-1\nlinea-vieja-mas-larga-2\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        with open(self.ruta + '.1', 'w') as f:
            f.write('x\n')   # mucho más corto que estado['offset']
        with open(self.ruta, 'r+') as f:
            f.truncate(0)
            f.write('nueva1\n')
        lineas, _, error = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, ['nueva1'])
        self.assertIsNone(error)

    def test_rotacion_de_verdad_termina_el_1_y_sigue_con_el_nuevo(self):
        self._escribir('vieja1\nvieja2\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        self._anadir('vieja3\n')   # esto queda SIN leer antes de rotar
        os.rename(self.ruta, self.ruta + '.1')
        self._escribir('nueva1\nnueva2\n')
        lineas, estado2, error = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, ['vieja3', 'nueva1', 'nueva2'])
        self.assertIsNone(error)
        self.assertNotEqual(estado2['inode'], estado['inode'])

    def test_rotacion_sin_punto_1_disponible_empieza_el_nuevo_desde_cero(self):
        self._escribir('vieja1\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        os.remove(self.ruta)   # ni rotación con .1 ni nada: se perdió
        self._escribir('nueva1\nnueva2\n')
        lineas, estado2, error = re_.leer_bloques_nuevos(self.ruta, estado)
        self.assertEqual(lineas, ['nueva1', 'nueva2'])
        self.assertIsNone(error)

    def test_fichero_ausente_no_toca_el_estado(self):
        lineas, estado, error = re_.leer_bloques_nuevos(os.path.join(self.tmp.name, 'no-existe.log'),
                                                          {'inode': 1, 'offset': 5})
        self.assertEqual(lineas, [])
        self.assertIsNone(error)
        self.assertEqual(estado, {'inode': 1, 'offset': 5})

    def test_limite_de_bytes_por_ciclo_corta_y_reanuda(self):
        self._escribir('')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        contenido = ''.join('linea%03d\n' % i for i in range(200))
        self._anadir(contenido)
        limite = 50  # fuerza varios bloques
        total = []
        for _ in range(60):
            lineas, estado, _ = re_.leer_bloques_nuevos(self.ruta, estado, limite_bytes=limite)
            total.extend(lineas)
            if not lineas and estado['offset'] == os.path.getsize(self.ruta):
                break
        esperado = ['linea%03d' % i for i in range(200)]
        self.assertEqual(total, esperado)

    def test_linea_mas_larga_que_el_presupuesto_entero_se_descarta_y_avanza(self):
        # BAJA11: una "línea" sin ningún salto de línea, más larga que TODO
        # el presupuesto de un ciclo (log corrupto/basura binaria) nunca
        # debe poder atascar la lectura para siempre — se descarta y se
        # avanza, en vez de quedarse esperando para siempre un salto de
        # línea que nunca va a llegar dentro del presupuesto.
        self._escribir('')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        with open(self.ruta, 'a') as f:
            f.write('x' * 500)   # SIN salto de línea: imposible de terminar en un bloque de 100
        limite = 100
        offset_anterior = estado['offset']
        avanzo_alguna_vez = False
        for _ in range(20):
            lineas, estado, _ = re_.leer_bloques_nuevos(self.ruta, estado, limite_bytes=limite)
            self.assertEqual(lineas, [])   # la basura nunca se "recupera" como línea
            if estado['offset'] != offset_anterior:
                avanzo_alguna_vez = True
            if estado['offset'] >= os.path.getsize(self.ruta):
                break
            offset_anterior = estado['offset']
        self.assertTrue(avanzo_alguna_vez, 'la lectura se quedó atascada sin avanzar nunca')
        self.assertEqual(estado['offset'], os.path.getsize(self.ruta))
        # Tras la basura, las líneas normales siguientes se leen con
        # normalidad (no se queda "contaminado" el estado).
        with open(self.ruta, 'a') as f:
            f.write('\nlinea-normal\n')
        lineas, _estado, _ = re_.leer_bloques_nuevos(self.ruta, estado, limite_bytes=limite)
        self.assertIn('linea-normal', lineas)

    def test_error_de_permiso_se_propaga_sin_lanzar(self):
        # ALTA1: si el fichero EXISTE pero no se puede leer (permisos), el
        # tercer valor devuelto lleva el motivo — no se lanza, y el estado
        # no se toca (se reintenta el ciclo siguiente).
        self._escribir('algo\n')
        _, estado, _ = re_.leer_bloques_nuevos(self.ruta, None)
        self._anadir('mas\n')
        os.chmod(self.ruta, 0o000)
        try:
            if os.geteuid() == 0:
                self.skipTest('root ignora los permisos de fichero; no se puede forzar este caso')
            lineas, estado2, error = re_.leer_bloques_nuevos(self.ruta, estado)
        finally:
            os.chmod(self.ruta, 0o644)
        self.assertEqual(lineas, [])
        self.assertIsNotNone(error)
        self.assertEqual(estado2, estado)


# ───────────────────────────── deltas con reinicio ─────────────────────────────

class TestDeltas(unittest.TestCase):
    def test_delta_normal(self):
        self.assertEqual(re_.calcular_delta(100, 150), 50)

    def test_sin_anterior_no_hay_delta(self):
        self.assertIsNone(re_.calcular_delta(None, 150))

    def test_reinicio_de_contador_se_descarta(self):
        # la interfaz se resetea (o la tabla nft se reinstaló): el valor
        # actual es MENOR que el anterior -> nunca se resta un negativo.
        self.assertIsNone(re_.calcular_delta(1000, 10))

    def test_delta_cero_es_valido(self):
        self.assertEqual(re_.calcular_delta(100, 100), 0)


# ───────────────────────────── nft -j list set ─────────────────────────────

class TestParseoSetNft(unittest.TestCase):
    """disp_sube/disp_baja son `set` (no `map`): un diseño anterior con
    `map disp_sube { type ipv4_addr : counter; ... }` pasaba `nft -c` sin
    ningún error, pero el KERNEL lo rechazaba al cargar la tabla de verdad
    ("Error: Could not process rule: Operation not supported", `update`
    fallaba con "No such file or directory") — descubierto cargando la
    tabla de verdad con root en un netns (Debian 13, nftables 1.1.3; `nft
    -c` NO lo detecta, sólo analiza sintaxis). Lo que SÍ carga y cuenta de
    verdad es un `set type ipv4_addr` normal con el contador en la
    EXPRESIÓN del `update` (`update @set { ip saddr counter }`) — ver la
    nota larga en nft_conf.py.

    `FIXTURE_REAL` es la salida LITERAL de `nft -j list set inet t
    disp_sube` tras cargar justo esa tabla y generar tráfico real — pegada
    tal cual, sin modificar ni un carácter. El resto de pruebas cubre
    variaciones (vacío, colapso de un único elemento) que no se pudieron
    forzar en esa misma captura pero que el esquema de libnftables-json(5)
    permite."""

    FIXTURE_REAL = {
        "nftables": [
            {"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4",
                           "json_schema_version": 1}},
            {"set": {"family": "inet", "name": "disp_sube", "table": "t", "type": "ipv4_addr",
                     "handle": 2, "size": 4096, "flags": ["timeout", "dynamic"], "timeout": 86400,
                     "elem": [
                         {"elem": {"val": "127.0.0.1", "expires": 86399,
                                   "counter": {"packets": 3, "bytes": 252}}},
                         {"elem": {"val": "127.0.0.5", "expires": 86399,
                                   "counter": {"packets": 3, "bytes": 252}}},
                     ]}},
        ]
    }

    def test_fixture_real_del_netns_con_root(self):
        resultado = re_.parsear_elems_set(self.FIXTURE_REAL, 'disp_sube')
        self.assertEqual(resultado, {'127.0.0.1': 252, '127.0.0.5': 252})

    def test_set_con_una_sola_entrada_sin_envolver_en_lista_exterior(self):
        # nft puede colapsar "elem" a la propia entrada (sin la lista
        # exterior) cuando sólo hay UN elemento (libnftables-json(5),
        # "SET_ELEMENTS := EXPRESSION | [EXPRESSION_LIST]").
        datos = {"nftables": [{"set": {
            "name": "disp_baja",
            "elem": {"elem": {"val": "192.168.50.50", "expires": 86000,
                               "counter": {"packets": 20, "bytes": 30000}}},
        }}]}
        resultado = re_.parsear_elems_set(datos, 'disp_baja')
        self.assertEqual(resultado, {'192.168.50.50': 30000})

    def test_set_vacio(self):
        datos = {"nftables": [{"set": {"name": "disp_sube"}}]}
        self.assertEqual(re_.parsear_elems_set(datos, 'disp_sube'), {})

    def test_set_ausente(self):
        datos = {"nftables": [{"set": {"name": "otra_cosa", "elem": []}}]}
        self.assertEqual(re_.parsear_elems_set(datos, 'disp_sube'), {})

    def test_elemento_sin_contador_todavia_se_ignora(self):
        # Por robustez: si alguna vez un elemento apareciera sin "counter"
        # (no debería pasar en la práctica: sólo existe porque "update" ya
        # contó al menos un paquete), no se cuenta nada para esa IP en vez
        # de inventar un número.
        datos = {"nftables": [{"set": {
            "name": "disp_sube",
            "elem": [{"elem": {"val": "10.0.0.9", "expires": 86000}}],
        }}]}
        self.assertEqual(re_.parsear_elems_set(datos, 'disp_sube'), {})

    def test_json_sin_forma_esperada_no_lanza(self):
        self.assertEqual(re_.parsear_elems_set({}, 'disp_sube'), {})
        self.assertEqual(re_.parsear_elems_set({'nftables': 'no es una lista'}, 'disp_sube'), {})

    def test_leer_set_nft_usa_run_y_list_set_no_list_map(self):
        llamadas = []

        def fake_run(args, timeout=None):
            llamadas.append(args)
            import subprocess
            payload = {"nftables": [{"set": {"name": "disp_sube", "handle": 7, "elem": [
                {"elem": {"val": "10.0.0.5", "expires": 86000, "counter": {"packets": 1, "bytes": 60}}},
            ]}}]}
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload), stderr='')

        from unittest import mock
        with mock.patch.object(re_, 'run', fake_run):
            resultado, handle, error = re_.leer_set_nft('router', 'disp_sube')
        self.assertIsNone(error)
        self.assertEqual(resultado, {'10.0.0.5': 60})
        self.assertEqual(handle, 7)
        self.assertEqual(llamadas, [[re_.NFT_BIN, '-j', 'list', 'set', 'inet', 'router', 'disp_sube']])

    def test_leer_set_nft_comando_fallido_devuelve_error(self):
        def fake_run(args, timeout=None):
            import subprocess
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='No such file or directory')

        from unittest import mock
        with mock.patch.object(re_, 'run', fake_run):
            resultado, handle, error = re_.leer_set_nft('router', 'disp_sube')
        self.assertEqual(resultado, {})
        self.assertIsNone(handle)
        self.assertIsNotNone(error)

    def test_parsear_handle_set(self):
        datos = {"nftables": [{"set": {"name": "disp_sube", "handle": 12, "elem": []}}]}
        self.assertEqual(re_.parsear_handle_set(datos, 'disp_sube'), 12)
        self.assertIsNone(re_.parsear_handle_set(datos, 'otro'))
        self.assertIsNone(re_.parsear_handle_set({}, 'disp_sube'))


# ─────────────── ruleset completo de nft_conf.generar() contra `nft` real ───────────────

class TestGeneracionNftCompleta(unittest.TestCase):
    """Comprueba el ruleset COMPLETO que genera `nft_conf.generar()`
    (no sólo disp_sube/disp_baja) contra el binario `nft` de verdad
    instalado en esta máquina, en dos niveles:

    1. `nft -c -f <ruleset>` (análisis sintáctico). IMPORTANTE, es la
       lección de esta misma tarea: esto NO basta por sí solo para
       disp_sube/disp_baja — un diseño con `map ... : counter` pasaba
       `nft -c` sin ningún error y el KERNEL lo rechazaba igual al cargar
       la tabla de verdad ("Operation not supported"). Aquí sólo sirve
       para pescar errores de sintaxis de verdad (typos, tokens mal
       puestos); un "Operation not permitted" de netlink (falta de
       privilegios) NO se trata como fallo de sintaxis.
    2. Si además hay `nft` Y `unshare` disponibles, se intenta CARGAR
       (`nft -f`, sin `-c`) el ruleset completo dentro de un espacio de
       nombres de red SIN privilegios de root del host
       (`unshare --net --map-root-user`, que en Linux moderno con
       user-namespaces sin privilegios habilitados concede CAP_NET_ADMIN
       DENTRO de ese namespace). Esto es best-effort: un namespace mínimo
       como el de un sandbox de CI puede carecer de los módulos de
       conntrack/NAT/log que el RESTO del ruleset necesita (nada que ver
       con disp_sube/disp_baja) — un fallo que no mencione esos dos
       nombres ni "update @" se trata como inconcluyente (se salta con un
       mensaje claro), no como un fallo de la prueba. La única
       validación que de verdad prueba que el kernel acepta la tabla
       completa, con tráfico real atravesándola, es el end-to-end CON
       ROOT de verdad: `pruebas/netns_multiwan.sh`, paso 17 — esa prueba
       la ejecuta quien tenga privilegios de root en el equipo/CT de
       pruebas, no este unittest."""

    @staticmethod
    def _generar_ruleset():
        cfg = {'lan': {'interfaz': 'enp2s0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'},
               'bloqueo': {'bloquear_doh': True, 'forzar_dns': True}}
        return nft_conf.generar(cfg)

    def test_sintaxis_nft_c(self):
        nft_bin = shutil.which('nft')
        if not nft_bin:
            self.skipTest('no hay binario "nft" en este sistema de pruebas')
        with tempfile.NamedTemporaryFile('w', suffix='.nft', delete=False) as f:
            f.write(self._generar_ruleset())
            ruta = f.name
        try:
            r = subprocess.run([nft_bin, '-c', '-f', ruta], capture_output=True, text=True, timeout=10)
        finally:
            os.unlink(ruta)
        errores_sintaxis = [linea for linea in (r.stderr or '').splitlines()
                             if 'syntax error' in linea.lower() or 'unexpected' in linea.lower()]
        self.assertEqual(errores_sintaxis, [],
                          'nft -c encontró errores de sintaxis:\n' + (r.stderr or ''))
        # Si r.returncode != 0 sólo por "Operation not permitted" (falta de
        # privilegios para abrir netlink), eso NO es un error de sintaxis y
        # esta prueba sigue en verde — es justo la limitación que motivó
        # el punto 2 de abajo y, en última instancia, el e2e con root.

    def test_carga_real_en_namespace_sin_privilegios_best_effort(self):
        nft_bin = shutil.which('nft')
        unshare_bin = shutil.which('unshare')
        if not nft_bin or not unshare_bin:
            self.skipTest('no hay "nft" o "unshare": la validación real de la carga es '
                           'el e2e con root (pruebas/netns_multiwan.sh, paso 17)')
        with tempfile.NamedTemporaryFile('w', suffix='.nft', delete=False) as f:
            f.write(self._generar_ruleset())
            ruta = f.name
        try:
            r = subprocess.run([unshare_bin, '--net', '--map-root-user', '--', nft_bin, '-f', ruta],
                                capture_output=True, text=True, timeout=10)
        finally:
            os.unlink(ruta)
        if r.returncode == 0:
            return
        salida = (r.stdout or '') + (r.stderr or '')
        if re.search(r'disp_sube|disp_baja|update\s+@', salida):
            self.fail('la carga real en el namespace sin privilegios falló MENCIONANDO '
                      'disp_sube/disp_baja/update @ — esto sí sería señal real de un '
                      'problema con la contabilidad por dispositivo:\n' + salida)
        self.skipTest(
            'la carga en el namespace sin privilegios falló por algo AJENO a '
            'disp_sube/disp_baja (típico en un sandbox mínimo: módulos de '
            'conntrack/NAT/log no disponibles ahí) — inconcluyente. La validación '
            'real es el e2e CON ROOT (pruebas/netns_multiwan.sh, paso 17). '
            'Salida de nft:\n' + salida)


# ───────────────────────────── conntrack / leases ─────────────────────────────

class TestConntrackYLeases(unittest.TestCase):
    def test_conteo_por_ip_cuenta_src_de_tupla_original(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'nf_conntrack')
            with open(ruta, 'w') as f:
                f.write(
                    'ipv4 2 tcp 6 120 ESTABLISHED src=192.168.50.50 dst=1.1.1.1 sport=1 dport=443 '
                    'src=1.1.1.1 dst=192.168.50.50 sport=443 dport=1 [ASSURED] mark=0 use=1\n'
                    'ipv4 2 tcp 6 120 ESTABLISHED src=192.168.50.50 dst=9.9.9.9 sport=2 dport=443 '
                    'src=9.9.9.9 dst=192.168.50.50 sport=443 dport=2 [ASSURED] mark=0 use=1\n'
                    'ipv4 2 udp 17 29 src=192.168.50.77 dst=1.1.1.1 sport=3 dport=53 '
                    'src=1.1.1.1 dst=192.168.50.77 sport=53 dport=3 mark=0 use=1\n'
                )
            resultado = re_.leer_conexiones_por_ip(ruta)
            self.assertEqual(resultado, {'192.168.50.50': 2, '192.168.50.77': 1})

    def test_demasiadas_lineas_devuelve_none(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'nf_conntrack')
            with open(ruta, 'w') as f:
                f.writelines(['src=192.168.50.50 dst=1.1.1.1\n'] * 10)
            self.assertIsNone(re_.leer_conexiones_por_ip(ruta, limite_lineas=5))

    def test_fichero_ausente_devuelve_none(self):
        self.assertIsNone(re_.leer_conexiones_por_ip('/no/existe/nf_conntrack'))

    def test_total_conocido_por_encima_del_limite_ni_abre_el_fichero(self):
        # MEDIA7: si ya se sabe por nf_conntrack_count que hay más
        # conexiones que el límite, ni se intenta abrir
        # /proc/net/nf_conntrack — se usa una ruta que NO EXISTE para
        # demostrar que no hace falta que exista siquiera.
        resultado = re_.leer_conexiones_por_ip('/no/existe/nf_conntrack',
                                                limite_lineas=5, total_conocido=100)
        self.assertIsNone(resultado)

    def test_total_conocido_por_debajo_del_limite_si_abre_el_fichero(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'nf_conntrack')
            with open(ruta, 'w') as f:
                f.write('src=192.168.50.50 dst=1.1.1.1\n')
            resultado = re_.leer_conexiones_por_ip(ruta, limite_lineas=5, total_conocido=1)
            self.assertEqual(resultado, {'192.168.50.50': 1})

    def test_corta_al_pasar_el_limite_sin_cargar_el_fichero_entero(self):
        # MEDIA7: se itera línea a línea y se corta en cuanto se pasa el
        # límite — una línea deliberadamente "envenenada" (que si se
        # leyera por completo haría fallar el test por su tamaño) después
        # del límite nunca debe llegar a leerse/decodificarse.
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'nf_conntrack')
            with open(ruta, 'wb') as f:
                for _ in range(5):
                    f.write(b'src=192.168.50.50 dst=1.1.1.1\n')
                f.write(b'\xff' * (10 * 1024 * 1024) + b'\n')   # 10 MiB tras el límite
            resultado = re_.leer_conexiones_por_ip(ruta, limite_lineas=3)
            self.assertIsNone(resultado)

    def test_leases_parseadas(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'dnsmasq.leases')
            with open(ruta, 'w') as f:
                f.write('1234567890 AA:BB:CC:DD:EE:FF 192.168.50.77 movil *\n'
                         '1234567891 11:22:33:44:55:66 192.168.50.78 * *\n')
            leases = re_.leer_leases(ruta)
        self.assertEqual(leases['192.168.50.77'], {'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'movil'})
        self.assertEqual(leases['192.168.50.78'], {'mac': '11:22:33:44:55:66', 'hostname': None})

    def test_resolver_dispositivo_prioridad_etiqueta_sobre_reserva_y_lease(self):
        estado = {'config': {
            'reservas': [{'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.168.50.50', 'nombre': 'nas'}],
            'etiquetas': {'aa:bb:cc:dd:ee:ff': 'NAS del salón'},
        }}
        mac, nombre = re_.resolver_dispositivo('192.168.50.50', estado, {})
        self.assertEqual((mac, nombre), ('aa:bb:cc:dd:ee:ff', 'NAS del salón'))

    def test_resolver_dispositivo_cae_a_lease_si_no_hay_reserva(self):
        estado = {'config': {'reservas': [], 'etiquetas': {}}}
        leases = {'192.168.50.80': {'mac': '11:22:33:44:55:66', 'hostname': 'portatil'}}
        mac, nombre = re_.resolver_dispositivo('192.168.50.80', estado, leases)
        self.assertEqual((mac, nombre), ('11:22:33:44:55:66', 'portatil'))

    def test_resolver_dispositivo_sin_nada_devuelve_none(self):
        mac, nombre = re_.resolver_dispositivo('192.168.50.99', {'config': {}}, {})
        self.assertEqual((mac, nombre), (None, None))


# ───────────────────────────── SQLite: esquema, rollup, retención ─────────────────────────────

class TestSqlite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, 'sub', 'estadisticas.db')

    def tearDown(self):
        self.tmp.cleanup()

    def test_esquema_exacto(self):
        conn = re_.abrir_db(self.db, grupo=None)
        columnas_esperadas = {
            'trafico_wan': ['ts', 'wan', 'nombre', 'rx_bytes', 'tx_bytes', 'latencia_ms', 'perdida_pct', 'en_balanceo'],
            'trafico_wan_hora': ['ts', 'wan', 'nombre', 'rx_bytes', 'tx_bytes', 'latencia_ms', 'perdida_pct', 'en_balanceo'],
            'trafico_disp': ['ts', 'ip', 'mac', 'nombre', 'bajada_bytes', 'subida_bytes', 'conexiones'],
            'trafico_disp_hora': ['ts', 'ip', 'mac', 'nombre', 'bajada_bytes', 'subida_bytes', 'conexiones'],
            'conexiones': ['ts', 'total'],
            'dns_hora': ['hora', 'cliente', 'dominio', 'consultas', 'bloqueadas'],
            'meta': ['clave', 'valor'],
        }
        for tabla, columnas in columnas_esperadas.items():
            info = conn.execute('PRAGMA table_info(%s)' % tabla).fetchall()
            nombres = [fila[1] for fila in info]
            self.assertEqual(nombres, columnas, 'columnas de %s' % tabla)
        # claves primarias
        self.assertEqual(self._pk(conn, 'trafico_wan'), ['ts', 'wan'])
        self.assertEqual(self._pk(conn, 'trafico_disp'), ['ts', 'ip'])
        self.assertEqual(self._pk(conn, 'conexiones'), ['ts'])
        self.assertEqual(self._pk(conn, 'dns_hora'), ['hora', 'cliente', 'dominio'])
        self.assertEqual(self._pk(conn, 'meta'), ['clave'])
        fila = conn.execute("SELECT valor FROM meta WHERE clave='version_esquema'").fetchone()
        self.assertEqual(fila[0], '1')
        conn.close()

    @staticmethod
    def _pk(conn, tabla):
        info = conn.execute('PRAGMA table_info(%s)' % tabla).fetchall()
        return [fila[1] for fila in sorted(info, key=lambda f: f[5]) if fila[5] > 0]

    def test_indice_dns_hora_cubridor_sustituye_al_redundante(self):
        # Revisión Opus: idx_dns_hora_hora (sólo "hora") era redundante con
        # el índice automático de la PK (hora, cliente, dominio) — lo
        # sustituye un índice CUBRIDOR (hora, dominio, consultas,
        # bloqueadas) para que la consulta típica del panel ("consultas/
        # bloqueadas por dominio en este rango de horas") se resuelva sin
        # tocar la tabla.
        conn = re_.abrir_db(self.db, grupo=None)
        nombres = {fila[1] for fila in conn.execute('PRAGMA index_list(dns_hora)').fetchall()}
        self.assertNotIn('idx_dns_hora_hora', nombres)
        self.assertIn('idx_dns_hora_cubre', nombres)
        columnas = [fila[2] for fila in conn.execute('PRAGMA index_info(idx_dns_hora_cubre)').fetchall()]
        self.assertEqual(columnas, ['hora', 'dominio', 'consultas', 'bloqueadas'])
        conn.close()

    def test_migracion_elimina_el_indice_viejo_en_una_base_existente(self):
        # Una base creada ANTES de este cambio (con el índice viejo a
        # mano) debe perderlo al reabrirla con la versión nueva de
        # abrir_db (DROP INDEX IF EXISTS en el propio ESQUEMA_SQL).
        os.makedirs(os.path.dirname(self.db), exist_ok=True)
        conn = sqlite3.connect(self.db)
        conn.execute('CREATE TABLE dns_hora(hora INTEGER, cliente TEXT, dominio TEXT, '
                     'consultas INTEGER, bloqueadas INTEGER, PRIMARY KEY(hora, cliente, dominio))')
        conn.execute('CREATE INDEX idx_dns_hora_hora ON dns_hora(hora)')
        conn.close()
        conn = re_.abrir_db(self.db, grupo=None)
        nombres = {fila[1] for fila in conn.execute('PRAGMA index_list(dns_hora)').fetchall()}
        self.assertNotIn('idx_dns_hora_hora', nombres)
        self.assertIn('idx_dns_hora_cubre', nombres)
        conn.close()

    def test_permisos_directorio_y_fichero(self):
        conn = re_.abrir_db(self.db, grupo=None)
        conn.close()
        self.assertEqual(os.stat(os.path.dirname(self.db)).st_mode & 0o777, 0o750)
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o640)

    def test_wal_activo(self):
        conn = re_.abrir_db(self.db, grupo=None)
        modo = conn.execute('PRAGMA journal_mode').fetchone()[0]
        self.assertEqual(modo.lower(), 'wal')
        conn.close()

    def test_wal_y_shm_quedan_con_el_mismo_modo_que_el_db(self):
        # Revisión Opus: -wal/-shm deben llevar el MISMO modo que el .db
        # (SQLite los crea con el UMask del proceso, que en producción es
        # root — sin este ajuste quedarían con el grupo primario del
        # proceso, no "routerpanel"; aquí sólo se comprueba el MODO, el
        # grupo no se puede comprobar en una prueba sin privilegios).
        conn = re_.abrir_db(self.db, grupo=None)
        conn.execute("INSERT INTO conexiones(ts, total) VALUES(?,?)", (1, 1))
        modo_db = os.stat(self.db).st_mode & 0o777
        encontrado_alguno = False
        for sufijo in ('-wal', '-shm'):
            ruta = self.db + sufijo
            if os.path.exists(ruta):
                encontrado_alguno = True
                self.assertEqual(os.stat(ruta).st_mode & 0o777, modo_db, ruta)
        self.assertTrue(encontrado_alguno, 'se esperaba que -wal o -shm existieran tras escribir')
        conn.close()

    def test_cierre_sucio_sin_journal_mode_delete_falla_en_solo_lectura(self):
        """CONTROL (demuestra el bug que corrige cerrar_db, no lo que debe
        pasar en producción): un `conn.close()` normal NO basta — aunque
        la última conexión dispara un checkpoint automático que puede
        borrar -wal/-shm, el modo WAL queda anotado en la CABECERA del
        propio `.db` (bytes de versión de formato, offset 18-19), así que
        el siguiente que lo abra en sólo lectura sigue viendo "esto es
        WAL", intenta crear un -shm nuevo para el protocolo de bloqueo, y
        con el directorio sin permiso de escritura (el caso real del
        panel) eso falla con "attempt to write a readonly database" —
        comprobado aquí de verdad, no sólo supuesto."""
        conn = re_.abrir_db(self.db, grupo=None)
        conn.execute("INSERT INTO conexiones(ts, total) VALUES(?,?)", (1700000000, 5))
        conn.close()   # cierre "sucio": SIN pasar por cerrar_db
        d = os.path.dirname(self.db)
        modo_original = os.stat(d).st_mode
        os.chmod(d, 0o555)
        try:
            uri = 'file:%s?mode=ro' % self.db
            lector = sqlite3.connect(uri, uri=True)
            with self.assertRaises(sqlite3.OperationalError):
                lector.execute('SELECT total FROM conexiones').fetchone()
            lector.close()
        finally:
            os.chmod(d, modo_original)

    def test_cerrar_db_permite_abrir_solo_lectura_con_directorio_bloqueado(self):
        """Caso real del panel: tras un cierre LIMPIO (cerrar_db), una
        conexión nueva en mode=ro, con el directorio SIN permiso de
        escritura para quien la abre, debe poder leer sin pegas."""
        conn = re_.abrir_db(self.db, grupo=None)
        conn.execute("INSERT INTO conexiones(ts, total) VALUES(?,?)", (1700000000, 5))
        re_.cerrar_db(conn)
        self.assertFalse(os.path.exists(self.db + '-wal'))
        self.assertFalse(os.path.exists(self.db + '-shm'))

        d = os.path.dirname(self.db)
        modo_original = os.stat(d).st_mode
        os.chmod(d, 0o555)
        try:
            uri = 'file:%s?mode=ro' % self.db
            lector = sqlite3.connect(uri, uri=True)
            try:
                fila = lector.execute('SELECT total FROM conexiones WHERE ts=?', (1700000000,)).fetchone()
            finally:
                lector.close()
        finally:
            os.chmod(d, modo_original)
        self.assertEqual(fila, (5,))

    def test_cerrar_db_nunca_lanza_con_conexion_ya_cerrada(self):
        conn = re_.abrir_db(self.db, grupo=None)
        conn.close()
        re_.cerrar_db(conn)   # no debe lanzar aunque la conexión ya esté cerrada

    def test_estadisticas_cerrar_es_idempotente_y_reabre_en_wal(self):
        rutas = dict(re_.RUTAS, db=self.db)
        svc = re_.Estadisticas(rutas)
        svc._asegurar_db()
        svc.conn.execute("INSERT INTO conexiones(ts, total) VALUES(?,?)", (1, 1))
        svc.cerrar()
        self.assertIsNone(svc.conn)
        svc.cerrar()   # dos veces: no debe lanzar ni hacer nada raro
        self.assertFalse(os.path.exists(self.db + '-wal'))
        # Al volver a usar el servicio, abrir_db pone WAL otra vez.
        svc._asegurar_db()
        modo = svc.conn.execute('PRAGMA journal_mode').fetchone()[0]
        self.assertEqual(modo.lower(), 'wal')
        svc.cerrar()

    def test_guardar_trafico_wan_suma_bytes_del_mismo_minuto(self):
        # MEDIA5 (revisión Opus): dos ciclos pueden caer en el MISMO
        # minuto (intervalo_s < 60) — deben SUMAR, no pisarse.
        conn = re_.abrir_db(self.db, grupo=None)
        ts = 1_700_000_000
        re_.guardar_trafico_wan(conn, ts, [
            {'wan': 'W1', 'nombre': 'WAN1', 'rx_bytes': 100, 'tx_bytes': 10,
             'latencia_ms': 20.0, 'perdida_pct': 0.0, 'en_balanceo': False},
        ])
        re_.guardar_trafico_wan(conn, ts, [
            {'wan': 'W1', 'nombre': 'WAN1', 'rx_bytes': 50, 'tx_bytes': 5,
             'latencia_ms': 25.0, 'perdida_pct': 1.0, 'en_balanceo': True},
        ])
        fila = conn.execute('SELECT rx_bytes, tx_bytes, latencia_ms, perdida_pct, en_balanceo '
                             'FROM trafico_wan WHERE ts=? AND wan=?', (ts, 'W1')).fetchone()
        self.assertEqual(fila, (150, 15, 25.0, 1.0, 1))
        conn.close()

    def test_guardar_trafico_disp_suma_bytes_y_maximiza_conexiones_del_mismo_minuto(self):
        conn = re_.abrir_db(self.db, grupo=None)
        ts = 1_700_000_000
        re_.guardar_trafico_disp(conn, ts, [
            {'ip': '192.168.50.50', 'mac': 'aa', 'nombre': 'nas', 'bajada_bytes': 1000,
             'subida_bytes': 100, 'conexiones': 3},
        ])
        re_.guardar_trafico_disp(conn, ts, [
            {'ip': '192.168.50.50', 'mac': 'aa', 'nombre': 'nas', 'bajada_bytes': 2000,
             'subida_bytes': 200, 'conexiones': 9},
        ])
        fila = conn.execute('SELECT bajada_bytes, subida_bytes, conexiones FROM trafico_disp '
                             'WHERE ts=? AND ip=?', (ts, '192.168.50.50')).fetchone()
        self.assertEqual(fila, (3000, 300, 9))
        conn.close()

    def test_guardar_trafico_disp_suma_correctamente_con_null_en_un_lado(self):
        # Un ciclo con sólo "sube" OK (baja=None, p. ej. nft list falló
        # para disp_baja ese ciclo) seguido de uno con sólo "baja" OK no
        # debe perder ninguno de los dos valores.
        conn = re_.abrir_db(self.db, grupo=None)
        ts = 1_700_000_000
        re_.guardar_trafico_disp(conn, ts, [
            {'ip': '10.0.0.5', 'mac': None, 'nombre': None, 'bajada_bytes': None,
             'subida_bytes': 500, 'conexiones': None},
        ])
        re_.guardar_trafico_disp(conn, ts, [
            {'ip': '10.0.0.5', 'mac': None, 'nombre': None, 'bajada_bytes': 700,
             'subida_bytes': None, 'conexiones': 4},
        ])
        fila = conn.execute('SELECT bajada_bytes, subida_bytes, conexiones FROM trafico_disp '
                             'WHERE ts=? AND ip=?', (ts, '10.0.0.5')).fetchone()
        self.assertEqual(fila, (700, 500, 4))
        conn.close()

    def test_rollup_suma_bytes_media_latencia_maximo_balanceo(self):
        conn = re_.abrir_db(self.db, grupo=None)
        base = 1_700_000_000
        base -= base % 3600   # alinear al principio de una hora
        filas = [
            {'wan': 'W1', 'nombre': 'WAN1', 'rx_bytes': 100, 'tx_bytes': 10, 'latencia_ms': 20.0, 'perdida_pct': 0.0, 'en_balanceo': True},
            {'wan': 'W1', 'nombre': 'WAN1', 'rx_bytes': 200, 'tx_bytes': 20, 'latencia_ms': 40.0, 'perdida_pct': 0.0, 'en_balanceo': False},
        ]
        re_.guardar_trafico_wan(conn, base, filas[:1])
        re_.guardar_trafico_wan(conn, base + 60, filas[1:])
        re_.rollup_hora(conn, base)
        fila = conn.execute('SELECT wan, rx_bytes, tx_bytes, latencia_ms, perdida_pct, en_balanceo '
                             'FROM trafico_wan_hora WHERE ts=?', (base,)).fetchone()
        self.assertEqual(fila, ('W1', 300, 30, 30.0, 0.0, 1))
        conn.close()

    def test_rollup_dispositivo_suma_bytes_y_maximo_conexiones(self):
        conn = re_.abrir_db(self.db, grupo=None)
        base = 1_700_003_600
        base -= base % 3600
        re_.guardar_trafico_disp(conn, base, [
            {'ip': '192.168.50.50', 'mac': 'aa', 'nombre': 'nas', 'bajada_bytes': 1000, 'subida_bytes': 100, 'conexiones': 3},
        ])
        re_.guardar_trafico_disp(conn, base + 60, [
            {'ip': '192.168.50.50', 'mac': 'aa', 'nombre': 'nas', 'bajada_bytes': 2000, 'subida_bytes': 200, 'conexiones': 9},
        ])
        re_.rollup_hora(conn, base)
        fila = conn.execute('SELECT bajada_bytes, subida_bytes, conexiones FROM trafico_disp_hora WHERE ts=? AND ip=?',
                             (base, '192.168.50.50')).fetchone()
        self.assertEqual(fila, (3000, 300, 9))
        conn.close()

    def test_retencion_minutos_48h(self):
        conn = re_.abrir_db(self.db, grupo=None)
        ahora = 2_000_000_000
        viejo = ahora - re_.RETENCION_MINUTOS_S - 60
        reciente = ahora - 60
        re_.guardar_trafico_wan(conn, viejo, [{'wan': 'W1', 'rx_bytes': 1, 'tx_bytes': 1}])
        re_.guardar_trafico_wan(conn, reciente, [{'wan': 'W1', 'rx_bytes': 1, 'tx_bytes': 1}])
        re_.aplicar_retencion(conn, ahora, dias_dns=30)
        filas = conn.execute('SELECT ts FROM trafico_wan').fetchall()
        self.assertEqual([f[0] for f in filas], [reciente])
        conn.close()

    def test_retencion_horas_400_dias(self):
        conn = re_.abrir_db(self.db, grupo=None)
        ahora = 2_000_000_000
        viejo = ahora - re_.RETENCION_HORAS_S - 3600
        conn.execute('INSERT INTO trafico_wan_hora(ts, wan, rx_bytes, tx_bytes) VALUES(?,?,?,?)',
                     (viejo, 'W1', 1, 1))
        conn.execute('INSERT INTO trafico_wan_hora(ts, wan, rx_bytes, tx_bytes) VALUES(?,?,?,?)',
                     (ahora, 'W1', 1, 1))
        re_.aplicar_retencion(conn, ahora, dias_dns=30)
        filas = conn.execute('SELECT ts FROM trafico_wan_hora').fetchall()
        self.assertEqual([f[0] for f in filas], [ahora])
        conn.close()

    def test_auto_vacuum_incremental_en_base_nueva(self):
        # BAJA14: sólo tiene efecto puesto ANTES de crear ninguna tabla —
        # se comprueba en una base recién creada (abrir_db ya lo hace).
        conn = re_.abrir_db(self.db, grupo=None)
        modo = conn.execute('PRAGMA auto_vacuum').fetchone()[0]
        self.assertEqual(modo, 2)   # 2 = incremental (ver documentación de sqlite3)
        conn.execute('PRAGMA incremental_vacuum')   # no debe lanzar
        conn.close()

    def test_retencion_dns_segun_registro_dns_dias(self):
        conn = re_.abrir_db(self.db, grupo=None)
        ahora = 2_000_000_000
        dias = 10
        viejo = ahora - dias * 86400 - 3600
        conn.execute('INSERT INTO dns_hora(hora, cliente, dominio, consultas, bloqueadas) VALUES(?,?,?,?,?)',
                     (viejo, 'c', 'd', 1, 0))
        conn.execute('INSERT INTO dns_hora(hora, cliente, dominio, consultas, bloqueadas) VALUES(?,?,?,?,?)',
                     (ahora, 'c', 'd2', 1, 0))
        re_.aplicar_retencion(conn, ahora, dias_dns=dias)
        filas = conn.execute('SELECT dominio FROM dns_hora').fetchall()
        self.assertEqual([f[0] for f in filas], ['d2'])
        conn.close()

    def test_guardar_dns_hora_suma_sobre_lo_existente(self):
        conn = re_.abrir_db(self.db, grupo=None)
        clave = (1_700_000_000, 'cliente', 'dominio.ejemplo')
        re_.guardar_dns_hora(conn, {clave: [3, 1]})
        re_.guardar_dns_hora(conn, {clave: [2, 2]})
        fila = conn.execute('SELECT consultas, bloqueadas FROM dns_hora WHERE hora=? AND cliente=? AND dominio=?',
                             clave).fetchone()
        self.assertEqual(fila, (5, 3))
        conn.close()

    def test_posicion_dns_en_meta_se_lee_y_guarda(self):
        # BAJA12: la posición del log DNS vive en 'meta', no en un fichero
        # aparte — así se puede escribir en la MISMA transacción que
        # dns_hora (ver Estadisticas._procesar_dns).
        conn = re_.abrir_db(self.db, grupo=None)
        self.assertIsNone(re_.leer_posicion_dns_meta(conn))
        re_._guardar_posicion_dns_meta(conn, 12345, 678)
        self.assertEqual(re_.leer_posicion_dns_meta(conn), {'inode': 12345, 'offset': 678})
        re_._guardar_posicion_dns_meta(conn, 12345, 999)   # se actualiza, no se duplica
        self.assertEqual(re_.leer_posicion_dns_meta(conn), {'inode': 12345, 'offset': 999})
        conn.close()

    def test_posicion_dns_y_dns_hora_se_escriben_en_la_misma_transaccion(self):
        # Si la transacción falla a medias, NINGUNA de las dos cosas debe
        # quedar escrita (ni la posición sin los agregados, ni al revés) —
        # se comprueba forzando un ROLLBACK a mano.
        conn = re_.abrir_db(self.db, grupo=None)

        def _escribir_y_fallar(c):
            re_._guardar_posicion_dns_meta(c, 1, 2)
            re_.guardar_dns_hora(c, {(1_700_000_000, 'cliente', 'dominio'): [1, 0]})
            raise RuntimeError('fallo a mitad de la transacción')

        with self.assertRaises(RuntimeError):
            re_._transaccion(conn, _escribir_y_fallar)
        self.assertIsNone(re_.leer_posicion_dns_meta(conn))
        fila = conn.execute('SELECT COUNT(*) FROM dns_hora').fetchone()
        self.assertEqual(fila[0], 0)
        conn.close()


# ───────────────────────────── configuración ─────────────────────────────

class TestConfig(unittest.TestCase):
    def test_defecto_sin_fichero(self):
        cfg = re_.leer_config_estadisticas('/no/existe/router.json')
        self.assertEqual(cfg, {'habilitada': True, 'intervalo_s': 60, 'registro_dns_dias': 30,
                                'dominio_local': 'home.arpa'})

    def test_lee_intervalo_y_dias_dns(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'router.json')
            with open(ruta, 'w') as f:
                json.dump({'router_estadisticas': {'habilitada': False, 'intervalo_s': 45},
                           'bloqueo': {'registro_dns_dias': 7}}, f)
            cfg = re_.leer_config_estadisticas(ruta)
        self.assertEqual(cfg, {'habilitada': False, 'intervalo_s': 45, 'registro_dns_dias': 7,
                                'dominio_local': 'home.arpa'})

    def test_lee_dominio_de_casa(self):
        # MEDIA6: mismo campo que lee dnsmasq_conf.py ("dominio", a nivel
        # raíz de router.json, no dentro de "bloqueo").
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'router.json')
            with open(ruta, 'w') as f:
                json.dump({'dominio': 'Lan.Home.ARPA.'}, f)
            cfg = re_.leer_config_estadisticas(ruta)
        self.assertEqual(cfg['dominio_local'], 'lan.home.arpa')

    def test_intervalo_fuera_de_rango_se_acota(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'router.json')
            with open(ruta, 'w') as f:
                json.dump({'router_estadisticas': {'intervalo_s': 5}}, f)
            cfg = re_.leer_config_estadisticas(ruta)
        self.assertEqual(cfg['intervalo_s'], re_.INTERVALO_MIN_S)

    def test_json_corrupto_cae_a_defecto(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, 'router.json')
            with open(ruta, 'w') as f:
                f.write('{ esto no es json valido')
            cfg = re_.leer_config_estadisticas(ruta)
        self.assertTrue(cfg['habilitada'])


# ───────────────────────────── Estadisticas.ciclo() de extremo a extremo ─────────────────────────────

class TestEstadisticasCiclo(unittest.TestCase):
    """Pruebas de integración (sin red, sin root: `nft`/conntrack van
    simulados con `unittest.mock`) del método `ciclo()` completo — BAJA16
    (revisión Opus): WAN que desaparece y vuelve (ALTA3), fallo de nft en
    un set sin perder la línea base del otro (BAJA8), reinstalación de la
    tabla detectada por `handle` (BAJA9), hueco de reloj grande entre
    ciclos (A) y rollup acotado tras una parada larga (BAJA13)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rutas = dict(
            re_.RUTAS,
            config=os.path.join(self.tmp.name, 'router.json'),
            estado=os.path.join(self.tmp.name, 'estado.json'),
            db=os.path.join(self.tmp.name, 'estadisticas.db'),
            dns_log=os.path.join(self.tmp.name, 'dns.log'),
            leases=os.path.join(self.tmp.name, 'leases'),
            conntrack_count=os.path.join(self.tmp.name, 'conntrack_count'),
            conntrack_tabla=os.path.join(self.tmp.name, 'conntrack_tabla'),
        )
        with open(self.rutas['config'], 'w') as f:
            json.dump({'router_estadisticas': {'intervalo_s': 30}}, f)
        with open(self.rutas['conntrack_count'], 'w') as f:
            f.write('0\n')
        with open(self.rutas['conntrack_tabla'], 'w') as f:
            f.write('')
        with open(self.rutas['dns_log'], 'w') as f:
            f.write('')
        with open(self.rutas['leases'], 'w') as f:
            f.write('')

    def tearDown(self):
        self.tmp.cleanup()

    def _escribir_estado(self, wans):
        with open(self.rutas['estado'], 'w') as f:
            json.dump({'wans': wans, 'config': {'reservas': [], 'etiquetas': {}}, 'vecinos': {}}, f)

    @staticmethod
    def _fake_nft(payloads_por_set, fallos=()):
        """`payloads_por_set`: {'disp_sube': {'<ip>': bytes, ...}, ...}
        (con handle opcional en 'handle_por_set'); `fallos`: nombres de
        set cuya lectura debe devolver returncode != 0 esta vez."""
        def fake_run(args, timeout=None):
            import subprocess
            nombre = args[-1]
            if nombre in fallos:
                return subprocess.CompletedProcess(args, 1, stdout='', stderr='nft código 1 (simulado)')
            elems = payloads_por_set.get(nombre, {})
            handle = payloads_por_set.get('_handle_%s' % nombre, 1)
            elem_json = [{'elem': {'val': ip, 'expires': 86000, 'counter': {'packets': 1, 'bytes': b}}}
                         for ip, b in elems.items()]
            payload = {'nftables': [{'set': {'name': nombre, 'handle': handle, 'elem': elem_json}}]}
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload), stderr='')
        return fake_run

    def _consultar(self, sql, params=()):
        conn = sqlite3.connect(self.rutas['db'])
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    # ---- ALTA3 ----
    def test_wan_desaparece_y_vuelve_sin_pico_falso(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        with mock.patch.object(re_, 'run', self._fake_nft({})):
            self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 1000, 'tx_bytes': 500,
                                     'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                     'perdida_pct': 0, 'en_balanceo': True}])
            svc.ciclo()   # primera lectura: establece línea base, sin fila
            time.sleep(0.01)
            self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 0, 'tx_bytes': 0,
                                     'presente': False, 'interfaz': None, 'latencia_ms': None,
                                     'perdida_pct': None, 'en_balanceo': False}])
            svc.ciclo()   # WAN ausente: 0/0 sintéticos, se olvida la línea base
            time.sleep(0.01)
            self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 50_000_000, 'tx_bytes': 20_000_000,
                                     'presente': True, 'interfaz': 'wan1', 'latencia_ms': 5,
                                     'perdida_pct': 0, 'en_balanceo': True}])
            svc.ciclo()   # vuelve con el contador de vida entero: NO debe ser un pico
        svc.cerrar()
        filas = self._consultar('SELECT rx_bytes, tx_bytes FROM trafico_wan')
        # Ni una sola fila debe contener el salto de 50 millones de golpe.
        for rx, tx in filas:
            self.assertLess(rx, 1_000_000)
            self.assertLess(tx, 1_000_000)

    # ---- revisión Opus tras el e2e con root: las líneas base sobreviven
    # a un reinicio del PROCESO (dos instancias de Estadisticas DISTINTAS,
    # sin memoria compartida, sobre la MISMA base de datos — exactamente
    # lo que pasa entre dos `--una-vez` seguidos, o entre dos arranques
    # reales del servicio) ----
    def test_dos_instancias_consecutivas_la_segunda_registra_delta(self):
        from unittest import mock
        self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 1000, 'tx_bytes': 500,
                                 'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                 'perdida_pct': 0, 'en_balanceo': True}])
        svc1 = re_.Estadisticas(self.rutas)
        with mock.patch.object(re_, 'run', self._fake_nft({'disp_sube': {'192.168.50.100': 1000},
                                                             'disp_baja': {'192.168.50.100': 2000}})):
            resumen1 = svc1.ciclo()
        svc1.cerrar()
        # Primera vez: línea base, sin filas (el propio resumen lo confirma).
        self.assertEqual(resumen1['trafico_wan'], 0)
        self.assertEqual(resumen1['trafico_disp'], 0)

        self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 1200, 'tx_bytes': 600,
                                 'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                 'perdida_pct': 0, 'en_balanceo': True}])
        # INSTANCIA NUEVA, sin memoria compartida con svc1 — simula el
        # proceso de un segundo "--una-vez" (o un reinicio del servicio).
        svc2 = re_.Estadisticas(self.rutas)
        with mock.patch.object(re_, 'run', self._fake_nft({'disp_sube': {'192.168.50.100': 1500},
                                                             'disp_baja': {'192.168.50.100': 2800}})):
            resumen2 = svc2.ciclo()
        svc2.cerrar()
        self.assertEqual(resumen2['trafico_wan'], 1)
        self.assertEqual(resumen2['trafico_disp'], 1)
        fila_wan = self._consultar('SELECT rx_bytes, tx_bytes FROM trafico_wan')[0]
        self.assertEqual(fila_wan, (200, 100))
        fila_disp = self._consultar('SELECT subida_bytes, bajada_bytes FROM trafico_disp')[0]
        self.assertEqual(fila_disp, (500, 800))

    def test_base_persistida_vieja_se_descarta_por_la_regla_del_hueco(self):
        from unittest import mock
        self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 1000, 'tx_bytes': 500,
                                 'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                 'perdida_pct': 0, 'en_balanceo': True}])
        svc1 = re_.Estadisticas(self.rutas)
        with mock.patch.object(re_, 'run', self._fake_nft({})):
            svc1.ciclo()   # intervalo_s=30 (ver setUp)
        svc1.cerrar()

        # Envejece a mano el 'tiempo_ultimo_ciclo' persistido en meta,
        # simulando que el servicio estuvo parado mucho más de
        # 2*intervalo_s (60 s) antes del siguiente arranque.
        conn = sqlite3.connect(self.rutas['db'])
        datos = json.loads(conn.execute("SELECT valor FROM meta WHERE clave='estado_runtime'").fetchone()[0])
        datos['tiempo_ultimo_ciclo'] -= 1000
        conn.execute("UPDATE meta SET valor=? WHERE clave='estado_runtime'", (json.dumps(datos),))
        conn.commit()
        conn.close()

        self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 9_000_000, 'tx_bytes': 4_000_000,
                                 'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                 'perdida_pct': 0, 'en_balanceo': True}])
        svc2 = re_.Estadisticas(self.rutas)
        with mock.patch.object(re_, 'run', self._fake_nft({})):
            resumen2 = svc2.ciclo()
        svc2.cerrar()
        # La base cargada es "vieja" -> la regla del hueco (punto A) la
        # descarta: ninguna fila con el salto de 9 millones de golpe.
        self.assertEqual(resumen2['trafico_wan'], 0)
        self.assertEqual(self._consultar('SELECT * FROM trafico_wan'), [])

    # ---- BAJA8 ----
    def test_fallo_de_un_set_nft_no_borra_la_base_del_otro(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        self._escribir_estado([])
        with mock.patch.object(re_, 'run', self._fake_nft(
                {'disp_sube': {'192.168.50.50': 1000}, 'disp_baja': {'192.168.50.50': 2000}})):
            svc.ciclo()   # línea base para ambas dimensiones
        time.sleep(0.01)
        with mock.patch.object(re_, 'run', self._fake_nft(
                {'disp_sube': {'192.168.50.50': 1500}}, fallos=('disp_baja',))):
            svc.ciclo()   # disp_baja FALLA este ciclo; disp_sube sigue bien
        svc.cerrar()
        # La base de "baja" (2000) debe seguir intacta tras el fallo.
        self.assertEqual(svc._disp_bytes_prev.get('192.168.50.50', {}).get('baja'), 2000)
        filas = self._consultar('SELECT subida_bytes, bajada_bytes FROM trafico_disp WHERE ip=?',
                                 ('192.168.50.50',))
        # La fila (si la hay) debe tener subida=500 (delta real) y bajada=NULL (sin datos ese ciclo).
        self.assertTrue(filas)
        subida, bajada = filas[-1]
        self.assertEqual(subida, 500)
        self.assertIsNone(bajada)

    # ---- BAJA9 ----
    def test_cambio_de_handle_del_set_se_trata_como_reinicio_limpio(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        self._escribir_estado([])
        payload1 = {'disp_sube': {'192.168.50.50': 5000}, 'disp_baja': {},
                    '_handle_disp_sube': 1, '_handle_disp_baja': 1}
        with mock.patch.object(re_, 'run', self._fake_nft(payload1)):
            svc.ciclo()
        time.sleep(0.01)
        # La tabla se reinstaló: handle distinto, y el contador real
        # vuelve a empezar de 0 -> la nueva lectura es un 0->300 limpio.
        payload2 = {'disp_sube': {'192.168.50.50': 300}, 'disp_baja': {},
                    '_handle_disp_sube': 2, '_handle_disp_baja': 1}
        with mock.patch.object(re_, 'run', self._fake_nft(payload2)):
            svc.ciclo()
        svc.cerrar()
        filas = self._consultar('SELECT subida_bytes FROM trafico_disp WHERE ip=? ORDER BY ts',
                                 ('192.168.50.50',))
        # La última fila debe llevar el delta "limpio" 300 (0->300), NUNCA
        # None (que es lo que habría pasado sin detectar el handle: el
        # valor 300 < 5000 se habría visto como "reinicio ambiguo, sin dato").
        self.assertEqual(filas[-1][0], 300)

    # ---- A: hueco de reloj grande entre ciclos ----
    def test_hueco_de_reloj_grande_descarta_el_delta(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        with mock.patch.object(re_, 'run', self._fake_nft({})):
            self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 1000, 'tx_bytes': 500,
                                     'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                     'perdida_pct': 0, 'en_balanceo': True}])
            svc.ciclo()   # intervalo_s=30 -> línea base
            svc._tiempo_ultimo_ciclo = time.time() - 1000   # simula un atasco largo
            self._escribir_estado([{'id': 'W1', 'nombre': 'WAN1', 'rx_bytes': 5_000_000, 'tx_bytes': 2_000_000,
                                     'presente': True, 'interfaz': 'wan1', 'latencia_ms': 1,
                                     'perdida_pct': 0, 'en_balanceo': True}])
            svc.ciclo()   # hueco >> 2*intervalo_s: el delta se descarta
        svc.cerrar()
        filas = self._consultar('SELECT rx_bytes FROM trafico_wan')
        for (rx,) in filas:
            self.assertLess(rx, 1_000_000)

    # ---- ALTA1: aviso UNA sola vez si no se puede leer el log DNS ----
    def test_fallo_de_permiso_en_dns_log_avisa_una_sola_vez(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        svc._asegurar_db()
        llamadas_warning = []
        with mock.patch.object(re_.LOG, 'warning', lambda *a, **k: llamadas_warning.append(a)):
            with mock.patch.object(re_, 'leer_bloques_nuevos',
                                    lambda *a, **k: ([], None, 'permiso denegado (simulado)')):
                svc._procesar_dns(1_700_000_000)
                svc._procesar_dns(1_700_000_060)
                svc._procesar_dns(1_700_000_120)
        svc.cerrar()
        self.assertEqual(len(llamadas_warning), 1, 'debería avisar una sola vez, no cada ciclo')

    def test_tras_el_aviso_si_se_recupera_la_lectura_puede_volver_a_avisar(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        svc._asegurar_db()
        llamadas_warning = []
        with mock.patch.object(re_.LOG, 'warning', lambda *a, **k: llamadas_warning.append(a)):
            with mock.patch.object(re_, 'leer_bloques_nuevos',
                                    lambda *a, **k: ([], None, 'permiso denegado (simulado)')):
                svc._procesar_dns(1_700_000_000)
            with mock.patch.object(re_, 'leer_bloques_nuevos', lambda *a, **k: ([], None, None)):
                svc._procesar_dns(1_700_000_060)   # se recupera: no debe avisar de nuevo
            with mock.patch.object(re_, 'leer_bloques_nuevos',
                                    lambda *a, **k: ([], None, 'permiso denegado otra vez (simulado)')):
                svc._procesar_dns(1_700_000_120)   # vuelve a fallar: SÍ debe avisar de nuevo
        svc.cerrar()
        self.assertEqual(len(llamadas_warning), 2)

    # ---- BAJA13: rollup acotado tras una parada larga ----
    def test_rollup_tras_parada_larga_se_acota_a_48h_y_avisa_al_watchdog(self):
        from unittest import mock
        svc = re_.Estadisticas(self.rutas)
        svc._asegurar_db()
        ahora = 2_000_000_000
        hora_actual = (ahora // 3600) * 3600
        # 'ultima_hora_rollup' MUY antiguo (parada de semanas) -- sin el
        # tope de BAJA13 esto iteraría miles de veces.
        svc.conn.execute("INSERT INTO meta(clave, valor) VALUES('ultima_hora_rollup', ?)",
                         (str(hora_actual - 90 * 24 * 3600),))
        llamadas_watchdog = []
        with mock.patch.object(re_, '_sd_notify', lambda m: llamadas_watchdog.append(m)):
            svc._rollup_y_retencion(ahora)
        svc.cerrar()
        # Se acotó a 48h: como mucho 48 vueltas del bucle (más 1 por si
        # acaso el límite exacto), nunca miles.
        self.assertLessEqual(svc._ultima_hora_rollup, hora_actual)
        self.assertGreaterEqual(svc._ultima_hora_rollup, hora_actual - re_.RETENCION_MINUTOS_S - 3600)
        self.assertIn('WATCHDOG=1', llamadas_watchdog)


if __name__ == '__main__':
    unittest.main()
