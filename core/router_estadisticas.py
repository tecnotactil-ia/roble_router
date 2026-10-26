#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""router_estadisticas — recolector de series históricas para los gráficos
del panel (tráfico por WAN, tráfico/conexiones por dispositivo LAN, consultas
DNS por hora).

Por qué es un servicio APARTE de routerd (mismo motivo que router_adb.py):
este recolector ejecuta `nft -j list set ...`, abre y recorre
`/proc/net/nf_conntrack` y relee un log de varios MB cada minuto — nada de
eso debe poder retrasar el ciclo crítico de routerd (nftables/rutas/DHCP) ni
arriesgar SU watchdog. Proceso y systemd unit propios
(systemd/router-estadisticas.service), con su PROPIO sd_notify/watchdog.

Cada ciclo (router_estadisticas.intervalo_s de router.json, defecto y
recomendado 60 s):

1. Lee `/run/router/estado.json` (lo publica routerd) → por WAN: delta de
   rx_bytes/tx_bytes desde el ciclo anterior, SÓLO si la WAN está
   `presente` y tiene `interfaz` (si no, routerd publica un rx/tx
   "sintético" — normalmente 0 — que NO es una medición real: se ignora
   entero, y se olvida la línea base, para que al volver a estar presente
   no se cuente de golpe todo su contador de vida como tráfico de un solo
   minuto). Un delta negativo (o un cambio de `interfaz` bajo el mismo id)
   sólo puede ser un reinicio de los contadores — se descarta.
2. Lee `nft -j list set inet router disp_sube`/`disp_baja` (ver la nota
   larga en core/nft_conf.py: son `set` con un `counter` adjunto a cada
   elemento desde la EXPRESIÓN del `update` — NO un `map` con
   `type ipv4_addr : counter`, que pasa `nft -c` pero el kernel lo rechaza
   al cargar de verdad) → bytes acumulados por IP LAN; delta por IP. Un
   fallo de `nft` en UN set nunca toca las líneas base del OTRO (ni de él
   mismo): se limita a no aportar datos ese ciclo. Si el `handle` del set
   cambia (la tabla se reinstaló), el primer valor tras el cambio se trata
   como un 0→N limpio, no como "sin datos".
3. Asocia cada IP con su MAC/nombre: `estado.json` → `config.reservas`/
   `config.etiquetas` para los equipos con reserva, y
   `/var/lib/misc/dnsmasq.leases` (ya documentado en docs/CONTRATO.md como
   fichero que el panel puede leer) para cualquier otro — `estado.json` →
   `vecinos` va al revés (clave MAC, no IP) y no basta por sí solo.
4. Conexiones activas: total de `/proc/sys/net/netfilter/nf_conntrack_count`
   siempre; por dispositivo LAN sólo si ese total no es ya demasiado
   grande (si lo es, ni se abre `/proc/net/nf_conntrack`) y, si se abre,
   se itera línea a línea cortando en cuanto se pasa el límite — nunca se
   carga el fichero entero en memoria primero.
5. DNS: lectura INCREMENTAL de `/var/log/router/dns.log` por inodo+offset
   (persistido en la tabla `meta`, EN LA MISMA transacción que `dns_hora`
   — nunca puede quedar desincronizado de lo que ya se agregó), acotada a
   un máximo de MB por ciclo para que un pico de tráfico DNS nunca pueda
   comerse el watchdog. El primer arranque (sin posición previa) NO
   procesa el histórico: se coloca cerca del final del fichero. Los
   timestamps de dnsmasq son hora LOCAL del sistema, no UTC.
6. Escribe en SQLite (WAL, transacciones cortas — el panel lee en paralelo,
   sólo con permiso de lectura) en /var/lib/router/estadisticas/
   estadisticas.db, con el esquema documentado en docs/CONTRATO.md. Dos
   ciclos que caigan en el MISMO minuto (intervalo_s corto, reloj) SUMAN
   sus bytes en vez de pisarse.
7. Al cruzar una hora, agrega el minuto a *_hora; aplica la retención
   configurada; tras una parada larga, el ponerse al día de los rollups
   pendientes se acota a las últimas 48 h.

Uso:  router_estadisticas.py [--config /etc/router/router.json]
                              [--estado /run/router/estado.json]
                              [--db /var/lib/router/estadisticas/estadisticas.db]
                              [--dns-log /var/log/router/dns.log]
                              [--raiz-datos /ruta (pruebas)]
                              [--una-vez]
"""
import argparse
import ipaddress
import json
import logging
import os
import re
import signal
import socket as _socketmod
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import zoneinfo
from datetime import datetime, timezone

LOG = logging.getLogger('router_estadisticas')

RUTAS = {
    'config': '/etc/router/router.json',
    'estado': '/run/router/estado.json',
    'leases': '/var/lib/misc/dnsmasq.leases',
    'dns_log': '/var/log/router/dns.log',
    'db': '/var/lib/router/estadisticas/estadisticas.db',
    'conntrack_count': '/proc/sys/net/netfilter/nf_conntrack_count',
    'conntrack_tabla': '/proc/net/nf_conntrack',
}

NFT_BIN = 'nft'
GRUPO_PANEL = 'routerpanel'

INTERVALO_DEFECTO_S = 60
INTERVALO_MIN_S = 30
INTERVALO_MAX_S = 300

# Retención (spec): minutos 48h, horas de tráfico 400 días, dns_hora según
# bloqueo.registro_dns_dias (defecto 30, 1-365 — mismo rango que router_bloqueo).
RETENCION_MINUTOS_S = 48 * 3600
RETENCION_HORAS_S = 400 * 24 * 3600
DNS_DIAS_DEFECTO = 30
DOMINIO_LOCAL_DEFECTO = 'home.arpa'

# DNS: nunca procesar más de esto por ciclo (ni el histórico al primer
# arranque, ni un pico de tráfico): protege el watchdog.
LIMITE_MB_POR_CICLO = 8
LIMITE_BYTES_POR_CICLO = LIMITE_MB_POR_CICLO * 1024 * 1024
# Tamaño máximo de una línea del log que se admite leer entera (una línea
# más larga que esto se descarta sin intentar parsearla: nunca debe poder
# acumular un buffer sin límite si el fichero estuviera corrupto/truncado
# a medias).
MAX_LINEA_DNS = 4096
# Cuántas consultas "pendientes de respuesta" (vistas con `query[...]` pero
# todavía sin su línea de resultado con el mismo id) se recuerdan como
# máximo entre ciclos — más allá de esto se descartan las más antiguas
# (FIFO): nunca debe poder crecer sin límite si algo deja de emparejar.
MAX_DNS_PENDIENTES = 4000

# conntrack por dispositivo: si /proc/net/nf_conntrack tiene más líneas que
# esto, se considera "caro" ese ciclo y sólo se guarda el total.
LIMITE_LINEAS_CONNTRACK_DISPOSITIVO = 8000

CENTINELA_BLOQUEO = 'bloqueo-centinela.router-casa.invalid'

TIMEOUT_NFT = 10


def ahora_ts():
    return int(time.time())


def ahora_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


# ───────────────────────────── utilidades comunes ─────────────────────────────

def _sd_notify(mensaje):
    """sd_notify mínimo (mismo patrón que routerd/router_adb — M7): nunca
    lanza; sin Type=notify (pruebas, --una-vez) NOTIFY_SOCKET no existe y no
    hace nada."""
    socket_path = os.environ.get('NOTIFY_SOCKET')
    if not socket_path:
        return
    addr = ('\0' + socket_path[1:]) if socket_path.startswith('@') else socket_path
    try:
        with _socketmod.socket(_socketmod.AF_UNIX, _socketmod.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(mensaje.encode())
    except OSError:
        LOG.debug('sd_notify(%s) no se pudo enviar', mensaje, exc_info=True)


def _aplicar_permisos_dir(ruta, modo, grupo):
    """BAJA (no crítico): directorio del SQLite 0750 root:routerpanel para
    que el panel pueda abrir el fichero DENTRO sólo si también entra en el
    grupo — nunca debe poder tirar el ciclo (grupo ausente en pruebas/antes
    de crear el usuario del panel, permisos ya puestos por otra vía…)."""
    try:
        os.chmod(ruta, modo)
    except OSError:
        LOG.debug('no se pudo chmod %s', ruta, exc_info=True)
    if not grupo:
        return
    try:
        import grp
        os.chown(ruta, 0, grp.getgrnam(grupo).gr_gid)
    except (KeyError, PermissionError, OSError):
        LOG.debug('no se pudo chown %s a %s', ruta, grupo, exc_info=True)


def run(args, timeout=TIMEOUT_NFT):
    """Ejecuta un comando SIN shell. Nunca lanza: timeout/binario ausente se
    convierten en un CompletedProcess con returncode != 0 (mismo espíritu
    que routerd.run/router_adb.run)."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        salida = e.stdout if isinstance(e.stdout, str) else (e.stdout or b'').decode('utf-8', 'replace')
        error = e.stderr if isinstance(e.stderr, str) else (e.stderr or b'').decode('utf-8', 'replace')
        return subprocess.CompletedProcess(args, 124, stdout=salida, stderr=error or 'tiempo agotado')
    except OSError as e:
        return subprocess.CompletedProcess(args, 127, stdout='', stderr=str(e))


# ───────────────────────────── configuración ─────────────────────────────

def leer_config_estadisticas(ruta):
    """{'habilitada': bool, 'intervalo_s': number, 'registro_dns_dias': int,
    'dominio_local': str} de router.json → 'router_estadisticas' (intervalo),
    'bloqueo' (días de retención del DNS, MISMO campo que ya usa
    router_bloqueo.py) y 'dominio' (el dominio de casa, MISMO campo que lee
    dnsmasq_conf.py — MEDIA6: para no contar como "bloqueada" la NXDOMAIN
    local de ese dominio). Cualquier problema cae al defecto campo a campo;
    este servicio nunca debe quedarse parado por un router.json inválido."""
    defecto = {'habilitada': True, 'intervalo_s': INTERVALO_DEFECTO_S,
               'registro_dns_dias': DNS_DIAS_DEFECTO, 'dominio_local': DOMINIO_LOCAL_DEFECTO}
    try:
        with open(ruta) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return dict(defecto)
    if not isinstance(cfg, dict):
        return dict(defecto)
    out = dict(defecto)
    seccion = cfg.get('router_estadisticas')
    if isinstance(seccion, dict):
        habilitada = seccion.get('habilitada', True)
        if isinstance(habilitada, bool):
            out['habilitada'] = habilitada
        intervalo = seccion.get('intervalo_s', INTERVALO_DEFECTO_S)
        if isinstance(intervalo, (int, float)) and not isinstance(intervalo, bool) and intervalo > 0:
            out['intervalo_s'] = max(INTERVALO_MIN_S, min(INTERVALO_MAX_S, intervalo))
    bloqueo = cfg.get('bloqueo')
    if isinstance(bloqueo, dict):
        dias = bloqueo.get('registro_dns_dias')
        if isinstance(dias, (int, float)) and not isinstance(dias, bool):
            out['registro_dns_dias'] = max(1, min(365, int(dias)))
    dominio = cfg.get('dominio')
    if isinstance(dominio, str) and dominio.strip():
        out['dominio_local'] = dominio.strip().rstrip('.').lower()
    return out


def leer_estado(ruta):
    """dict de estado.json, o None si no se puede leer/parsear — nunca
    lanza. El llamador debe tratar None como «este ciclo no hay nada que
    hacer» (routerd puede estar reescribiéndolo, o no haber arrancado
    todavía)."""
    try:
        with open(ruta) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ──────────────────────── deltas con reinicio de contadores ────────────────────────

def calcular_delta(anterior, actual):
    """Delta entre dos lecturas acumulativas (bytes de una interfaz, bytes
    de un contador de nft…). Devuelve None si no se puede calcular un delta
    válido: no hay lectura anterior, o el contador bajó (sólo puede ser un
    reinicio — de la interfaz, o de la tabla nftables entera al
    reinstalarse) — en ese caso el llamador debe tratar `actual` como una
    NUEVA línea base, nunca restar un negativo ni inventarse un cero."""
    if anterior is None or actual is None:
        return None
    if actual < anterior:
        return None
    return actual - anterior


# ──────────────────────────── nft -j list set ────────────────────────────
#
# IMPORTANTE (corregido tras probarlo de verdad en un kernel real, no sólo
# con `nft -c`): disp_sube/disp_baja son `set` (NO `map`). Un diseño
# anterior con `map disp_sube { type ipv4_addr : counter; ... }` pasaba
# `nft -c` sin ningún error, pero el KERNEL lo rechazaba al cargar la tabla
# de verdad ("Error: Could not process rule: Operation not supported", y el
# propio `update` fallaba con "No such file or directory") — `nft -c` sólo
# analiza sintaxis, no basta para esta clase de construcción. Lo que SÍ
# carga y cuenta de verdad (comprobado cargando la tabla con root en un
# netns, Debian 13/nftables 1.1.3, y repetido de forma independiente aquí
# con nftables 1.1.7 — ver pruebas/netns_multiwan.sh paso 17) es un `set`
# normal (`type ipv4_addr`, sin concatenar `counter` en el tipo) con el
# contador añadido en la EXPRESIÓN del `update`:
#   set disp_sube { type ipv4_addr; flags dynamic, timeout; timeout 1d; size 4096; }
#   update @disp_sube { ip saddr counter }
# Ver la nota larga en core/nft_conf.py.

def leer_set_nft(tabla, nombre, nft_bin=NFT_BIN):
    """(dict IP->bytes_acumulados, handle_o_None, error_o_None) de
    `nft -j list set inet <tabla> <nombre>`. error no-None sólo si el
    comando falló de verdad (binario ausente, timeout, JSON inválido,
    tabla/set ausente) — un set vacío es un resultado válido (dict vacío,
    sin error): la tabla puede acabar de reinstalarse, o todos los
    elementos pueden haber expirado (timeout 1d sin tráfico nuevo).
    `handle` (BAJA9) identifica la INSTANCIA del set en el kernel: cambia
    si la tabla se destruyó y se recreó, aunque el nombre sea el mismo —
    el llamador lo usa para saber con certeza que los contadores volvieron
    a cero, en vez de fiarse sólo de que el valor haya bajado."""
    r = run([nft_bin, '-j', 'list', 'set', 'inet', tabla, nombre])
    if r.returncode != 0:
        return {}, None, (r.stderr or r.stdout or 'nft código %d' % r.returncode).strip()
    try:
        datos = json.loads(r.stdout or '{}')
    except ValueError as e:
        return {}, None, 'JSON de nft ilegible: %s' % e
    return parsear_elems_set(datos, nombre), parsear_handle_set(datos, nombre), None


def _encontrar_set(json_nft, nombre_set):
    """El objeto `set` crudo (dict) de la salida de `nft -j list set ...`
    cuyo nombre sea `nombre_set`, o None si no aparece."""
    objetos = json_nft.get('nftables') if isinstance(json_nft, dict) else None
    if not isinstance(objetos, list):
        return None
    for obj in objetos:
        if not isinstance(obj, dict):
            continue
        s = obj.get('set')
        if isinstance(s, dict) and s.get('name') == nombre_set:
            return s
    return None


def parsear_handle_set(json_nft, nombre_set):
    """El `handle` (entero) del set, o None si no aparece — ver BAJA9 en
    `leer_set_nft`."""
    s = _encontrar_set(json_nft, nombre_set)
    if s is None:
        return None
    h = s.get('handle')
    return h if isinstance(h, int) and not isinstance(h, bool) else None


def _un_elem_set(entrada):
    """De una entrada de `elem` de un `set` con contador por elemento,
    devuelve (ip_str_o_None, bytes_o_None). La forma real (comprobada con
    un `nft -j list set` de verdad, nftables 1.1.3/1.1.7, sobre un set
    alimentado con `update @set { ip saddr counter }`) es SIEMPRE
    `{"elem": {"val": "<ip>", "expires": N, "counter": {"packets": N,
    "bytes": N}}}` — nunca el par [clave, dato] de un mapa (esto es un
    `set`, no un `map`: no hay valor separado de la clave, el contador es
    un atributo MÁS del propio elemento). Se admite también el string
    suelto "<ip>" (elemento sin contador, por robustez ante una versión de
    nft que lo representara distinto) — en ese caso no hay bytes que
    contar, se devuelve (ip, None) y el llamador lo descarta."""
    if isinstance(entrada, dict) and isinstance(entrada.get('elem'), dict):
        cuerpo = entrada['elem']
        val = cuerpo.get('val')
        ip = val if isinstance(val, str) else None
        contador = cuerpo.get('counter')
        bytes_ = contador.get('bytes') if isinstance(contador, dict) else None
        bytes_ = bytes_ if isinstance(bytes_, (int, float)) and not isinstance(bytes_, bool) else None
        return ip, bytes_
    if isinstance(entrada, str):
        return entrada, None
    return None, None


def parsear_elems_set(json_nft, nombre_set):
    """dict IP->bytes de la salida JSON de `nft -j list set ...` para el
    set `nombre_set`. Robusto a: el set no aparece (vacío o nombre
    distinto) -> {}; `elem` ausente (set recién creado o sin elementos
    vivos — todos expiraron) -> {}; UN solo elemento, que nft puede
    colapsar fuera de la lista exterior (ver libnftables-json(5),
    "SET_ELEMENTS := EXPRESSION | [EXPRESSION_LIST]")."""
    s = _encontrar_set(json_nft, nombre_set)
    if s is None:
        return {}
    elem = s.get('elem')
    if elem is None:
        return {}
    entradas = elem if isinstance(elem, list) else [elem]
    resultado = {}
    for entrada in entradas:
        ip, bytes_ = _un_elem_set(entrada)
        if ip is not None and bytes_ is not None:
            resultado[ip] = bytes_
    return resultado


# ──────────────────────────── conntrack ────────────────────────────

def leer_conexiones_total(ruta=None):
    """Entero de /proc/sys/net/netfilter/nf_conntrack_count, o None si no
    se puede leer (módulo no cargado, sin permisos…) — nunca lanza."""
    ruta = ruta or RUTAS['conntrack_count']
    try:
        with open(ruta) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


RE_SRC = re.compile(r'\bsrc=(\d{1,3}(?:\.\d{1,3}){3})\b')


def leer_conexiones_por_ip(ruta=None, limite_lineas=LIMITE_LINEAS_CONNTRACK_DISPOSITIVO,
                            total_conocido=None):
    """dict IP->número_de_conexiones de /proc/net/nf_conntrack, contando
    sólo la IP de ORIGEN de la tupla ORIGINAL de cada línea (el primer
    "src=" — la del dispositivo LAN cuando la conexión salió de la LAN
    hacia una WAN). Devuelve None (no {}) si el fichero es ilegible o tiene
    más de `limite_lineas` líneas: "caro este ciclo, sólo el total" — {}
    es un resultado válido distinto (fichero vacío/sin conexiones).

    MEDIA7: si ya se conoce `total_conocido` (de
    /proc/sys/net/netfilter/nf_conntrack_count, mucho más barato de leer)
    y ya supera el límite, ni se ABRE `/proc/net/nf_conntrack` — y si se
    abre, se itera línea a línea cortando en cuanto se pasa el límite, en
    vez de cargar el fichero entero en memoria con `readlines()` primero
    para recién entonces comprobar cuántas líneas tenía."""
    if total_conocido is not None and total_conocido > limite_lineas:
        return None
    ruta = ruta or RUTAS['conntrack_tabla']
    resultado = {}
    contador = 0
    try:
        with open(ruta, 'r', errors='replace') as f:
            for linea in f:
                contador += 1
                if contador > limite_lineas:
                    LOG.info('nf_conntrack tiene más de %d líneas: este ciclo sólo se guarda el total',
                             limite_lineas)
                    return None
                m = RE_SRC.search(linea)
                if not m:
                    continue
                ip = m.group(1)
                resultado[ip] = resultado.get(ip, 0) + 1
    except OSError:
        return None
    return resultado


# ──────────────────────── asociar IP -> MAC/nombre ────────────────────────

def leer_leases(ruta=None):
    """dict IP -> {'mac': str, 'hostname': str_o_None} de
    /var/lib/misc/dnsmasq.leases (formato dnsmasq: "expiry mac ip hostname
    client-id", un registro por línea; "hostname" es "*" si el cliente no
    mandó uno). Nunca lanza: fichero ausente/ilegible -> {}."""
    ruta = ruta or RUTAS['leases']
    resultado = {}
    try:
        with open(ruta, 'r', errors='replace') as f:
            lineas = f.readlines()
    except OSError:
        return resultado
    for linea in lineas:
        partes = linea.split()
        if len(partes) < 4:
            continue
        _expira, mac, ip, hostname = partes[0], partes[1], partes[2], partes[3]
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        resultado[ip] = {'mac': mac.lower(), 'hostname': None if hostname == '*' else hostname}
    return resultado


def resolver_dispositivo(ip, cfg_estado, leases):
    """(mac_o_None, nombre_o_None) para una IP LAN. Orden de preferencia
    para el nombre: etiqueta puesta a mano (config.etiquetas, por MAC) >
    nombre de la reserva DHCP (config.reservas) > hostname del lease DHCP
    (dnsmasq.leases) > None. `estado.json` -> `vecinos` no sirve aquí: va
    al revés (clave MAC, no IP) — ver docs/CONTRATO.md."""
    config = (cfg_estado or {}).get('config') or {}
    reservas = {r.get('ip'): r for r in (config.get('reservas') or []) if isinstance(r, dict)}
    etiquetas = config.get('etiquetas') or {}

    mac = None
    nombre = None
    reserva = reservas.get(ip)
    if reserva:
        mac = (reserva.get('mac') or '').lower() or None
        nombre = reserva.get('nombre')
    lease = leases.get(ip)
    if mac is None and lease:
        mac = lease.get('mac')
    if nombre is None and lease:
        nombre = lease.get('hostname')
    if mac and isinstance(etiquetas.get(mac), str) and etiquetas[mac]:
        nombre = etiquetas[mac]
    return mac, nombre


# ──────────────────────── parseo del log DNS (incremental) ────────────────────────

_MESES = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
          'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}

# dnsmasq (probado de verdad con un dnsmasq 2.93 real, LC_MESSAGES en
# español: los mensajes de arranque/diagnóstico SÍ se traducen, pero el
# propio timestamp de syslog y las líneas por consulta -query/config/
# forwarded/reply/cached- son SIEMPRE en inglés/formato fijo, sin
# traducir) escribe en log-facility con cabecera de syslog clásica:
#   "Oct 11 22:22:25 dnsmasq[1619300]: <cuerpo>"
RE_LINEA_SYSLOG = re.compile(
    r'^(?P<mes>[A-Za-z]{3})\s+(?P<dia>\d{1,2})\s+(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+'
    r'dnsmasq\[\d+\]:\s+(?P<cuerpo>.*)$')

# Con log-queries=extra (lo que pide dnsmasq_conf.py cuando el dnsmasq
# instalado lo admite — ver RUTAS/_admite_log_queries_extra en routerd.py),
# cada línea de consulta/resultado lleva "<id> <ip>/<puerto> ...", lo que
# permite emparejar la respuesta con su pregunta por el id. Sin "extra" (un
# dnsmasq más viejo) no hay id ni cliente en estas líneas — ese caso NO se
# intenta emparejar, simplemente no se puede atribuir la consulta a un
# cliente ni distinguir bloqueo de forma fiable; se ignoran en vez de
# arriesgar una atribución equivocada.
RE_CONSULTA = re.compile(
    r'^(?P<id>\d+)\s+(?P<cliente>[0-9A-Fa-f.:]+)/\d+\s+query\[(?P<tipo>[A-Za-z0-9]+)\]\s+'
    r'(?P<dominio>\S+)\s+from\s+(?P<cliente2>[0-9A-Fa-f.:]+)\s*$')
RE_RESULTADO = re.compile(
    r'^(?P<id>\d+)\s+(?P<cliente>[0-9A-Fa-f.:]+)/\d+\s+'
    r'(?P<tag>config|forwarded|reply|cached)\s+(?P<dominio>\S+)\s+'
    r'(?:is\s+(?P<resultado>.+?)|to\s+(?P<servidor>\S+))\s*$')


def _es_centinela(dominio):
    d = dominio.rstrip('.').lower()
    return d == CENTINELA_BLOQUEO or d.endswith('.' + CENTINELA_BLOQUEO)


# MEDIA6: "config X is NXDOMAIN" no sólo sale del servers-file del
# bloqueador — dnsmasq usa exactamente la misma línea de log para CUALQUIER
# resolución "local" sin dirección: el dominio de casa (`local=/<dominio>/`
# en dnsmasq_conf.py), `local=/home.arpa/` (incondicional, ver
# dnsmasq_conf.py), y `bogus-priv` (PTR de las redes privadas RFC1918/
# ULA — *.in-addr.arpa/*.ip6.arpa para esos rangos). Ninguno de esos es un
# dominio "bloqueado" por el usuario; contarlos como tal infla
# artificialmente `bloqueadas`. Lo ideal sería mirar el servers-file activo
# del bloqueador y repetir su criterio de especificidad — caro para lo que
# aporta aquí — así que, como permite la propia revisión ("si es caro, la
# exclusión basta"), se excluyen estos dominios fijos/el de casa en vez de
# eso: en la práctica el servers-file de router_bloqueo.py NUNCA contiene
# estos nombres (son los PROTEGIDOS_FIJOS de ese módulo), así que la
# exclusión no puede ocultar un bloqueo de verdad.
_SUFIJOS_LOCALES_FIJOS = ('home.arpa', 'in-addr.arpa', 'ip6.arpa')


def _es_dominio_local_sin_bloqueo(dominio, dominio_casa):
    d = dominio.rstrip('.').lower()
    sufijos = _SUFIJOS_LOCALES_FIJOS
    if dominio_casa:
        sufijos = sufijos + (dominio_casa.rstrip('.').lower(),)
    for base in sufijos:
        if base and (d == base or d.endswith('.' + base)):
            return True
    return False


def _zona_local():
    """El huso horario del SISTEMA como `zoneinfo.ZoneInfo` (con sus
    reglas de horario de verano completas), o None si no se puede
    determinar. MEDIA4/B (revisión Opus): NO basta con `datetime.
    timestamp()` sobre un naive (eso pasa por el `mktime` de la libc, cuyo
    comportamiento ante la hora AMBIGUA del cambio de hora de otoño —esa
    hora que se repite dos veces, una en verano y otra en invierno— es
    dependiente de la plataforma/libc e ignora `fold`); con un
    `zoneinfo.ZoneInfo` de verdad + `tzinfo`/`fold` explícitos en el
    `datetime`, PEP 495 SÍ se aplica de forma consistente y portable.

    Primero mira `$TZ` (lo que tendría puesto el proceso, p. ej. en una
    prueba); si no, sigue el enlace `/etc/localtime` (la forma estándar en
    Linux de saber la zona configurada: suele apuntar a algo como
    `/usr/share/zoneinfo/Europe/Rome`, de donde se recorta el nombre de
    zona IANA)."""
    tz_env = os.environ.get('TZ')
    if tz_env:
        try:
            return zoneinfo.ZoneInfo(tz_env)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            pass
    try:
        ruta = os.path.realpath('/etc/localtime')
        _, _, nombre = ruta.partition('/zoneinfo/')
        if nombre:
            return zoneinfo.ZoneInfo(nombre)
    except (OSError, zoneinfo.ZoneInfoNotFoundError, ValueError):
        pass
    return None


def _epoch_syslog(mes, dia, hh, mm, ss, referencia_epoch=None):
    """epoch UTC de una marca de tiempo de syslog SIN año (sólo mes/día/
    hora) — dnsmasq la escribe en hora LOCAL del sistema, no en UTC (como
    cualquier syslog clásico). Se construye un `datetime` con `tzinfo` =
    la zona local de verdad (`_zona_local()`) y `fold=0` explícito —
    `fold` es lo que PEP 495 usa para desambiguar la hora que se repite
    en el cambio de horario de otoño (p. ej. 02:30 en Europe/Rome ocurre
    dos veces un día de finales de octubre: una todavía en verano/CEST,
    otra ya en invierno/CET); `fold=0` elige la PRIMERA ocurrencia
    (todavía en verano) — es la única convención posible sin más
    información en el propio log, pero al menos es DETERMINISTA y
    correcta para el resto del año, a diferencia de dejar que `mktime`
    decida. Si no se pudo determinar la zona del sistema, cae al naive
    `.timestamp()` de siempre (mejor una conversión aproximada que
    ninguna).

    `referencia_epoch` (por defecto, ahora mismo) se usa para: (a) saber
    qué AÑO poner —en hora LOCAL, por si el año cambia cerca de
    medianoche— y (b) decidir si hay que restarle uno porque la fecha
    resultante quedó más de un día en el FUTURO (cruce de Nochevieja: el
    log sigue en diciembre con el año ya adelantado)."""
    mes_n = _MESES.get(mes)
    if mes_n is None:
        return None
    ref_epoch = referencia_epoch if referencia_epoch is not None else time.time()
    zona = _zona_local()
    if zona is not None:
        anio_ref = datetime.fromtimestamp(ref_epoch, tz=zona).year
    else:
        anio_ref = datetime.fromtimestamp(ref_epoch).year   # último recurso: hora local "ingenua"
    try:
        if zona is not None:
            candidato = datetime(anio_ref, mes_n, int(dia), int(hh), int(mm), int(ss), tzinfo=zona, fold=0)
        else:
            candidato = datetime(anio_ref, mes_n, int(dia), int(hh), int(mm), int(ss))
        ts = candidato.timestamp()
    except (ValueError, OverflowError, OSError):
        return None
    if ts > ref_epoch + 86400:
        try:
            candidato = candidato.replace(year=anio_ref - 1)
            ts = candidato.timestamp()
        except (ValueError, OverflowError, OSError):
            return None
    return int(ts)


class ProcesadorDns:
    """Estado del emparejamiento query<->resultado por id, a través de
    varios bloques/ciclos (una consulta y su resultado pueden quedar en
    bloques de lectura distintos si el ciclo se corta por el límite de
    MB). `agregados`: {(hora_epoch, cliente, dominio): [consultas, bloqueadas]}.

    `dominio_local` (MEDIA6) es el dominio de casa configurado — se
    reasigna cada ciclo desde `Estadisticas.cfg` (puede cambiar si el
    admin lo edita), nunca se fija sólo al construir el objeto."""

    def __init__(self, dominio_local=None):
        self.pendientes = {}   # id -> (cliente, dominio)
        self.agregados = {}
        self.dominio_local = dominio_local

    def _recordar_pendiente(self, id_, cliente, dominio):
        self.pendientes[id_] = (cliente, dominio)
        if len(self.pendientes) > MAX_DNS_PENDIENTES:
            # FIFO: en Python 3.7+ los dicts conservan el orden de
            # inserción — se descarta la más antigua.
            self.pendientes.pop(next(iter(self.pendientes)))

    def _sumar(self, ts, cliente, dominio, bloqueada):
        if _es_centinela(dominio):
            return
        hora = (ts // 3600) * 3600
        clave = (hora, cliente, dominio.rstrip('.').lower())
        fila = self.agregados.setdefault(clave, [0, 0])
        fila[0] += 1
        if bloqueada:
            fila[1] += 1

    def procesar_linea(self, linea, ahora_epoch=None):
        """Procesa una línea CRUDA del log (con su cabecera de syslog).
        Nunca lanza: cualquier línea que no case con el formato esperado
        (mensajes de arranque/diagnóstico, basura, DHCP) se ignora."""
        if len(linea) > MAX_LINEA_DNS:
            return
        m = RE_LINEA_SYSLOG.match(linea)
        if not m:
            return
        ts = _epoch_syslog(m.group('mes'), m.group('dia'), m.group('hh'), m.group('mm'), m.group('ss'),
                            referencia_epoch=ahora_epoch)
        if ts is None:
            return
        cuerpo = m.group('cuerpo')
        mq = RE_CONSULTA.match(cuerpo)
        if mq:
            self._recordar_pendiente(mq.group('id'), mq.group('cliente'), mq.group('dominio'))
            return
        mr = RE_RESULTADO.match(cuerpo)
        if not mr:
            return
        id_ = mr.group('id')
        pendiente = self.pendientes.pop(id_, None)
        if pendiente is None:
            # resultado sin la consulta correspondiente en este proceso
            # (quedó en un ciclo/arranque anterior, o es un dnsmasq sin
            # "extra" cuyo id no habíamos visto) -> no se puede atribuir
            # con garantías; se ignora en vez de adivinar el cliente/dominio.
            return
        cliente, dominio = pendiente
        bloqueada = (mr.group('tag') == 'config' and (mr.group('resultado') or '').strip() == 'NXDOMAIN'
                     and not _es_dominio_local_sin_bloqueo(dominio, self.dominio_local))
        self._sumar(ts, cliente, dominio, bloqueada)


# ──────────────────────── posición incremental del log DNS ────────────────────────

def _stat_o_none(ruta):
    try:
        return os.stat(ruta)
    except OSError:
        return None


def _leer_bytes(ruta, offset, presupuesto):
    """(bytes_leidos_o_None, error_o_None). None en el primer elemento
    significa que `open`/`seek`/`read` fallaron de verdad (típicamente
    permisos) — nunca una excepción sin capturar."""
    try:
        with open(ruta, 'rb') as f:
            f.seek(offset)
            return f.read(presupuesto), None
    except OSError as e:
        return None, str(e)


def _leer_desde(ruta, offset, presupuesto):
    """Lee líneas completas de `ruta` desde `offset` hasta agotar
    `presupuesto` bytes o llegar a EOF. Devuelve (lineas, presupuesto_restante,
    error_o_None) — usado sólo para "terminar" un fichero viejo (rotación o
    copytruncate con `.1` disponible), donde no hace falta recordar el
    offset final (ese fichero no se vuelve a tocar)."""
    leido, error = _leer_bytes(ruta, offset, presupuesto)
    if leido is None:
        return [], presupuesto, error
    presupuesto -= len(leido)
    # La última línea puede estar incompleta (cortada por el límite o por
    # EOF a medias de una escritura) — se descarta sin más: era el fichero
    # viejo, no se volverá a leer.
    lineas = [trozo.decode('utf-8', 'replace') for trozo in leido.split(b'\n')[:-1]]
    return lineas, max(0, presupuesto), None


def _leer_desde_con_offset(ruta, offset, presupuesto):
    """Como `_leer_desde`, pero además calcula el offset EXACTO (relativo al
    principio del fichero) de justo después de la última línea completa
    leída — para poder reanudar ahí el ciclo siguiente sin perder ni
    repetir una línea incompleta. Devuelve (lineas, presupuesto_restante,
    offset_nuevo, error_o_None).

    BAJA11: si se agota TODO el presupuesto de este bloque sin encontrar ni
    un solo salto de línea, NO es la misma situación que "la última línea
    está a medias, todavía escribiéndose" (eso sólo pasa al llegar a EOF
    SIN agotar el presupuesto) — es una línea más larga que el presupuesto
    entero de un ciclo (log corrupto, basura binaria…). Quedarse esperando
    a que "termine" bloquearía la lectura del resto del fichero para
    siempre; se descarta ese tramo entero y se avanza el offset igual."""
    leido, error = _leer_bytes(ruta, offset, presupuesto)
    if leido is None:
        return [], presupuesto, offset, error
    consumido = len(leido)
    presupuesto_restante = max(0, presupuesto - consumido)
    ultimo_salto = leido.rfind(b'\n')
    if ultimo_salto == -1:
        if consumido >= presupuesto and consumido > 0:
            return [], presupuesto_restante, offset + consumido, None
        return [], presupuesto_restante, offset, None   # EOF a medias: se reintenta igual
    lineas = [t.decode('utf-8', 'replace') for t in leido[:ultimo_salto].split(b'\n')]
    return lineas, presupuesto_restante, offset + ultimo_salto + 1, None


def leer_bloques_nuevos(ruta_log, estado_previo, limite_bytes=LIMITE_BYTES_POR_CICLO):
    """(lineas_nuevas, estado_nuevo, error_o_None). `estado_previo` es
    {'inode','offset'} o None (primer arranque de verdad: nunca procesa el
    histórico, se posiciona al final). `error_o_None` (ALTA1) sólo se
    rellena cuando el fichero EXISTE pero no se puede leer de verdad
    (típicamente permisos: este servicio necesita estar en el grupo del
    propietario del log, o CAP_DAC_READ_SEARCH — ver
    systemd/router-estadisticas.service) — el llamador debe avisar de esto
    UNA sola vez, no en cada ciclo; que el fichero simplemente no exista
    todavía (rotación en curso, arranque antes de que dnsmasq lo cree) NO
    es un error.

    Casos cubiertos:

    - Fichero ausente este ciclo -> ([], estado_previo, None): no se toca
      el estado, se reintenta el ciclo siguiente.
    - Mismo inodo, tamaño >= offset -> incremental normal.
    - Mismo inodo, tamaño < offset -> copytruncate: si "<ruta>.1" (la copia
      que logrotate toma ANTES de truncar) todavía llega al menos hasta el
      offset que faltaba leer, se recupera ese tramo de ahí (BAJA11 — antes
      se descartaba sin más, perdiendo líneas que SÍ estaban disponibles);
      luego se reinicia desde 0 en el fichero ya truncado.
    - Inodo distinto -> rotación "de verdad" (sin copytruncate): si
      "<ruta>.1" tiene el inodo VIEJO, se termina de leer desde el offset
      viejo hasta su EOF (dentro del mismo presupuesto de bytes) y LUEGO se
      sigue con el fichero nuevo desde 0; si no hay ".1" con ese inodo (ya
      comprimido, o logrotate no deja ".1" sin comprimir), se empieza el
      nuevo fichero desde 0 sin más."""
    try:
        st = os.stat(ruta_log)
    except FileNotFoundError:
        return [], estado_previo, None
    except OSError as e:
        return [], estado_previo, str(e)

    if estado_previo is None:
        # Primer arranque de verdad: no hay nada persistido. Nos colocamos
        # cerca del final (el propio tamaño actual) — "cerca" y no
        # "exactamente" no importa aquí: es simplemente la línea base.
        return [], {'inode': st.st_ino, 'offset': st.st_size}, None

    presupuesto = limite_bytes
    lineas = []

    if estado_previo['inode'] != st.st_ino:
        ruta_vieja = ruta_log + '.1'
        st_vieja = _stat_o_none(ruta_vieja)
        if st_vieja is not None and st_vieja.st_ino == estado_previo['inode']:
            nuevas, presupuesto, _err_viejo = _leer_desde(ruta_vieja, estado_previo['offset'], presupuesto)
            lineas.extend(nuevas)
        # Se continúa con el fichero NUEVO desde el principio, tenga o no
        # quedado presupuesto.
        nuevas, presupuesto, offset_nuevo, error = _leer_desde_con_offset(ruta_log, 0, presupuesto)
        lineas.extend(nuevas)
        return lineas, {'inode': st.st_ino, 'offset': offset_nuevo}, error

    offset_inicio = estado_previo['offset']
    if st.st_size < offset_inicio:
        # BAJA11: copytruncate -- antes de asumir que lo no leído se perdió
        # sin remedio, comprueba si ".1" todavía tiene ese tramo.
        ruta_vieja = ruta_log + '.1'
        st_vieja = _stat_o_none(ruta_vieja)
        if st_vieja is not None and st_vieja.st_size >= offset_inicio:
            nuevas, presupuesto, _err_viejo = _leer_desde(ruta_vieja, offset_inicio, presupuesto)
            lineas.extend(nuevas)
        offset_inicio = 0
    nuevas, _presupuesto, offset_nuevo, error = _leer_desde_con_offset(ruta_log, offset_inicio, presupuesto)
    lineas.extend(nuevas)
    return lineas, {'inode': st.st_ino, 'offset': offset_nuevo}, error


# ──────────────────────────── SQLite ────────────────────────────

ESQUEMA_SQL = '''
CREATE TABLE IF NOT EXISTS trafico_wan(
  ts INTEGER NOT NULL, wan TEXT NOT NULL, nombre TEXT,
  rx_bytes INTEGER, tx_bytes INTEGER,
  latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER,
  PRIMARY KEY(ts, wan)
);
CREATE TABLE IF NOT EXISTS trafico_wan_hora(
  ts INTEGER NOT NULL, wan TEXT NOT NULL, nombre TEXT,
  rx_bytes INTEGER, tx_bytes INTEGER,
  latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER,
  PRIMARY KEY(ts, wan)
);
CREATE TABLE IF NOT EXISTS trafico_disp(
  ts INTEGER NOT NULL, ip TEXT NOT NULL, mac TEXT, nombre TEXT,
  bajada_bytes INTEGER, subida_bytes INTEGER, conexiones INTEGER,
  PRIMARY KEY(ts, ip)
);
CREATE TABLE IF NOT EXISTS trafico_disp_hora(
  ts INTEGER NOT NULL, ip TEXT NOT NULL, mac TEXT, nombre TEXT,
  bajada_bytes INTEGER, subida_bytes INTEGER, conexiones INTEGER,
  PRIMARY KEY(ts, ip)
);
CREATE TABLE IF NOT EXISTS conexiones(ts INTEGER PRIMARY KEY, total INTEGER);
CREATE TABLE IF NOT EXISTS dns_hora(
  hora INTEGER NOT NULL, cliente TEXT NOT NULL, dominio TEXT NOT NULL,
  consultas INTEGER NOT NULL DEFAULT 0, bloqueadas INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hora, cliente, dominio)
);
CREATE TABLE IF NOT EXISTS meta(clave TEXT PRIMARY KEY, valor TEXT);

CREATE INDEX IF NOT EXISTS idx_trafico_wan_ts ON trafico_wan(ts);
CREATE INDEX IF NOT EXISTS idx_trafico_wan_hora_ts ON trafico_wan_hora(ts);
CREATE INDEX IF NOT EXISTS idx_trafico_disp_ts ON trafico_disp(ts);
CREATE INDEX IF NOT EXISTS idx_trafico_disp_ip ON trafico_disp(ip, ts);
CREATE INDEX IF NOT EXISTS idx_trafico_disp_hora_ts ON trafico_disp_hora(ts);
CREATE INDEX IF NOT EXISTS idx_trafico_disp_hora_ip ON trafico_disp_hora(ip, ts);
-- idx_dns_hora_hora (sólo "hora") era redundante: el índice automático de
-- la PK (hora, cliente, dominio) ya sirve para filtrar por "hora" sola
-- (es su columna más a la izquierda) — se sustituye por uno CUBRIDOR que
-- además evita tocar la tabla en la consulta típica del panel ("para este
-- rango de horas, consultas/bloqueadas por dominio"): con (hora, dominio,
-- consultas, bloqueadas) sqlite puede resolverla leyendo SÓLO el índice.
DROP INDEX IF EXISTS idx_dns_hora_hora;
CREATE INDEX IF NOT EXISTS idx_dns_hora_cubre ON dns_hora(hora, dominio, consultas, bloqueadas);
CREATE INDEX IF NOT EXISTS idx_dns_hora_cliente ON dns_hora(cliente, hora);
'''


def _igualar_permisos_wal(ruta_db, modo, grupo):
    """Los ficheros `-wal`/`-shm` de un SQLite en WAL deben llevar el
    MISMO modo/grupo que el `.db` (0640 root:routerpanel) — si no, el
    panel (sólo está en el grupo `routerpanel`, sin permiso de escritura
    en el directorio) no puede ni abrir la base MIENTRAS este servicio
    sigue en marcha: incluso una conexión de sólo lectura en modo WAL
    necesita poder mapear `-shm`, y SQLite crea los ficheros nuevos con el
    UMask del proceso (root; ver `UMask=` en el `.service` — 0027 deja
    0640/0750 por defecto, pero esto no depende de que nadie haya puesto
    bien ese UMask) y con el GRUPO primario del proceso (root), no
    `routerpanel` — sin este ajuste el panel se quedaría fuera aunque el
    modo (0640) ya saliera bien.

    Se llama cada vez que se abre la base (`abrir_db`), no sólo la primera
    vez: tras un cierre limpio (`cerrar_db`: `journal_mode=DELETE` borra
    `-wal`/`-shm` del todo) el siguiente arranque los vuelve a crear de
    cero, con el UMask de ESE arranque. Que el fichero todavía no exista
    (aún no hubo ninguna escritura real) no es un error."""
    for sufijo in ('-wal', '-shm'):
        ruta = ruta_db + sufijo
        try:
            os.chmod(ruta, modo)
        except OSError:
            continue
        if grupo:
            try:
                import grp
                os.chown(ruta, 0, grp.getgrnam(grupo).gr_gid)
            except (KeyError, PermissionError, OSError):
                LOG.debug('no se pudo chown %s a %s', ruta, grupo, exc_info=True)


def abrir_db(ruta, grupo=GRUPO_PANEL):
    """Conexión sqlite3 con WAL + esquema creado si falta. El directorio y
    el fichero quedan 0750/0640 root:routerpanel (BAJA: si el grupo no
    existe —pruebas, instalación sin panel todavía— se deja sólo el chmod,
    nunca se lanza por eso); lo mismo para `-wal`/`-shm` en cuanto existen
    (ver `_igualar_permisos_wal`). BAJA14: `auto_vacuum=INCREMENTAL` SÓLO
    tiene efecto puesto ANTES de crear ninguna tabla (en una base ya
    existente habría que hacer un `VACUUM` completo, caro — no se intenta:
    las bases de antes de este cambio se quedan en `auto_vacuum=NONE`, lo
    de siempre, nunca peor que antes)."""
    d = os.path.dirname(ruta)
    nuevo_dir = not os.path.isdir(d)
    os.makedirs(d, exist_ok=True)
    if nuevo_dir:
        _aplicar_permisos_dir(d, 0o750, grupo)
    nuevo_fichero = not os.path.exists(ruta)
    conn = sqlite3.connect(ruta, isolation_level=None)   # autocommit; usamos BEGIN explícito
    if nuevo_fichero:
        conn.execute('PRAGMA auto_vacuum=INCREMENTAL')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.executescript(ESQUEMA_SQL)
    conn.execute("INSERT OR IGNORE INTO meta(clave, valor) VALUES('version_esquema', '1')")
    if nuevo_fichero:
        try:
            os.chmod(ruta, 0o640)
            if grupo:
                import grp
                os.chown(ruta, 0, grp.getgrnam(grupo).gr_gid)
        except (KeyError, PermissionError, OSError):
            LOG.debug('no se pudieron aplicar permisos a %s', ruta, exc_info=True)
    # Lo de arriba (nuevo_fichero) sólo cubre el .db; -wal/-shm los acaba de
    # crear PRAGMA journal_mode=WAL/el INSERT de justo encima, y hay que
    # igualarlos CADA vez que se abre (ver docstring de la función).
    _igualar_permisos_wal(ruta, 0o640, grupo)
    return conn


def cerrar_db(conn):
    """Al apagarse de forma limpia (SIGTERM, o el final de un `--una-vez`):
    vacía el WAL en el fichero principal y pasa a `journal_mode=DELETE`
    ANTES de cerrar la conexión — nunca se deja la base en WAL al salir.

    Por qué: el panel abre `estadisticas.db` en SOLO LECTURA y sin permiso
    de escritura en `/var/lib/router/estadisticas` (0750 root:routerpanel
    — el panel está en el grupo, pero el directorio no le da `w`). Eso es
    SEGURO mientras este servicio sigue vivo (los `-wal`/`-shm` ya existen,
    con el modo/grupo correctos — ver `_igualar_permisos_wal`), pero en el
    hueco entre dos arranques (parada por mantenimiento, actualización, un
    `systemctl restart`…) hay que dejar la base en un estado que el panel
    pueda abrir igual.

    IMPORTANTE (comprobado con un `sqlite3.connect` de verdad, no sólo
    leído en la documentación): un simple `conn.close()` NO basta, aunque
    la ÚLTIMA conexión al cerrarse ya dispara un checkpoint automático que
    puede incluso borrar `-wal`/`-shm` del disco — el modo WAL queda
    "pegado" en la CABECERA del propio fichero `.db` (los bytes de versión
    de formato de lectura/escritura, offset 18-19), así que el PRÓXIMO que
    lo abra (el panel, en modo lectura) sigue viendo "este fichero es WAL"
    y necesita crear un `-shm` nuevo para el protocolo de bloqueo —cosa
    que `mode=ro` más un directorio sin `w` le impiden— y falla con
    "attempt to write a readonly database" IGUAL que si el `-wal` se
    hubiera quedado a medias, aunque ya no exista ningún `-wal`/`-shm` en
    el directorio. Lo único que de verdad lo arregla es pasar la conexión
    a `journal_mode=DELETE` ANTES de cerrar: eso reescribe esa cabecera a
    "fichero normal" (vuelve a poner esos bytes en modo rollback-journal),
    y SÍ dispara el `wal_checkpoint` + borra `-wal`/`-shm` de verdad.

    Nunca lanza: un fallo aquí no debe impedir que el proceso termine."""
    try:
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        conn.execute('PRAGMA journal_mode=DELETE')
    except sqlite3.Error:
        LOG.exception('no se pudo volcar el WAL al cerrar la base')
    try:
        conn.close()
    except sqlite3.Error:
        pass


def _transaccion(conn, fn, *args, **kwargs):
    """Ejecuta `fn(conn, *args, **kwargs)` dentro de una transacción CORTA
    propia (BEGIN IMMEDIATE…COMMIT/ROLLBACK) — nunca una transacción gigante
    para todo el ciclo: el panel lee en paralelo (WAL) y no debe esperar
    más de lo imprescindible por cada tabla."""
    conn.execute('BEGIN IMMEDIATE')
    try:
        fn(conn, *args, **kwargs)
    except Exception:
        conn.execute('ROLLBACK')
        raise
    else:
        conn.execute('COMMIT')


def guardar_trafico_wan(conn, ts, filas):
    """MEDIA5: dos ciclos pueden caer en el MISMO minuto (intervalo_s < 60,
    o sólo un pequeño desajuste de reloj) — un simple INSERT OR REPLACE
    PISARÍA el primero en vez de sumarlo, perdiendo esos bytes. rx_bytes/
    tx_bytes (deltas) se SUMAN; latencia_ms/perdida_pct son instantáneas
    (se queda con la del ciclo más reciente); en_balanceo = MÁXIMO (si
    estuvo en balanceo en CUALQUIER momento del minuto, se marca); nombre
    = el más reciente no nulo."""
    conn.executemany(
        'INSERT INTO trafico_wan(ts, wan, nombre, rx_bytes, tx_bytes, latencia_ms, perdida_pct, en_balanceo) '
        'VALUES(?,?,?,?,?,?,?,?) '
        'ON CONFLICT(ts, wan) DO UPDATE SET '
        'nombre = COALESCE(excluded.nombre, nombre), '
        'rx_bytes = COALESCE(rx_bytes, 0) + COALESCE(excluded.rx_bytes, 0), '
        'tx_bytes = COALESCE(tx_bytes, 0) + COALESCE(excluded.tx_bytes, 0), '
        'latencia_ms = excluded.latencia_ms, '
        'perdida_pct = excluded.perdida_pct, '
        'en_balanceo = MAX(COALESCE(en_balanceo, excluded.en_balanceo), COALESCE(excluded.en_balanceo, en_balanceo))',
        [(ts, f['wan'], f.get('nombre'), f.get('rx_bytes'), f.get('tx_bytes'),
          f.get('latencia_ms'), f.get('perdida_pct'), int(bool(f.get('en_balanceo')))) for f in filas])


def guardar_trafico_disp(conn, ts, filas):
    """MEDIA5: mismo motivo que guardar_trafico_wan — bajada_bytes/
    subida_bytes se SUMAN; conexiones (spec: "máximo") usa el mismo truco
    MAX(COALESCE(...)) para que un NULL de un lado no "gane" sobre un
    número real del otro."""
    conn.executemany(
        'INSERT INTO trafico_disp(ts, ip, mac, nombre, bajada_bytes, subida_bytes, conexiones) '
        'VALUES(?,?,?,?,?,?,?) '
        'ON CONFLICT(ts, ip) DO UPDATE SET '
        'mac = COALESCE(excluded.mac, mac), '
        'nombre = COALESCE(excluded.nombre, nombre), '
        'bajada_bytes = COALESCE(bajada_bytes, 0) + COALESCE(excluded.bajada_bytes, 0), '
        'subida_bytes = COALESCE(subida_bytes, 0) + COALESCE(excluded.subida_bytes, 0), '
        'conexiones = MAX(COALESCE(conexiones, excluded.conexiones), COALESCE(excluded.conexiones, conexiones))',
        [(ts, f['ip'], f.get('mac'), f.get('nombre'), f.get('bajada_bytes'), f.get('subida_bytes'),
          f.get('conexiones')) for f in filas])


def guardar_conexiones(conn, ts, total):
    if total is None:
        return
    conn.execute('INSERT OR REPLACE INTO conexiones(ts, total) VALUES(?,?)', (ts, total))


def guardar_dns_hora(conn, agregados):
    """`agregados`: {(hora, cliente, dominio): [consultas, bloqueadas]} ->
    UPSERT que SUMA (no reemplaza) sobre lo que ya hubiera para esa hora
    (varios ciclos dentro de la misma hora van sumando)."""
    if not agregados:
        return
    conn.executemany(
        'INSERT INTO dns_hora(hora, cliente, dominio, consultas, bloqueadas) VALUES(?,?,?,?,?) '
        'ON CONFLICT(hora, cliente, dominio) DO UPDATE SET '
        'consultas = consultas + excluded.consultas, bloqueadas = bloqueadas + excluded.bloqueadas',
        [(h, c, d, n, b) for (h, c, d), (n, b) in agregados.items()])


def leer_posicion_dns_meta(conn):
    """BAJA12: la posición (inodo+offset) del log DNS vive en la tabla
    `meta` (clave 'dns_posicion'), NO en un fichero JSON aparte — así se
    puede actualizar en la MISMA transacción que `dns_hora` (ver
    `Estadisticas._procesar_dns`): si el proceso muere a medias, o las dos
    cosas quedan escritas, o ninguna — nunca "ya conté estas líneas pero
    se me olvidó apuntar hasta dónde" (reprocesaría y duplicaría al
    reiniciar) ni "apunté hasta dónde pero no llegué a contar" (perdería
    esas líneas para siempre)."""
    fila = conn.execute("SELECT valor FROM meta WHERE clave='dns_posicion'").fetchone()
    if not fila:
        return None
    try:
        d = json.loads(fila[0])
    except (TypeError, ValueError):
        return None
    if isinstance(d, dict) and isinstance(d.get('inode'), int) and isinstance(d.get('offset'), int):
        return d
    return None


def _guardar_posicion_dns_meta(conn, inode, offset):
    conn.execute(
        "INSERT INTO meta(clave, valor) VALUES('dns_posicion', ?) "
        "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor",
        (json.dumps({'inode': inode, 'offset': offset}),))


def leer_estado_runtime_meta(conn):
    """Revisión Opus (tras el e2e con root): las líneas base de WAN/
    dispositivo (y el `handle` de los sets nft — BAJA9) SÓLO vivían en
    memoria del proceso. Cada `--una-vez` (y cada reinicio real del
    servicio: crash, OOM, `systemctl restart`…) es un proceso NUEVO, así
    que la base se perdía siempre — comprobado de verdad en el e2e con
    root: la segunda pasada de `--una-vez` no tenía base y no calculaba
    ningún delta. Se persisten en `meta` (clave 'estado_runtime', JSON)
    junto con el reloj REAL del último ciclo que las calculó
    (`tiempo_ultimo_ciclo`) — al cargarlas en el arranque siguiente, la
    propia regla del "hueco de reloj grande" (punto A, `Estadisticas.
    ciclo`) ya decide si son demasiado viejas para fiarse de ellas (más de
    2×`intervalo_s`): no hace falta un chequeo de antigüedad aparte aquí.

    Devuelve un dict con las claves que haya podido validar
    ('tiempo_ultimo_ciclo', 'wan_prev', 'disp_prev', 'disp_handle') — cada
    una por separado, nunca todo o nada: un campo corrupto no debe tirar
    los demás."""
    fila = conn.execute("SELECT valor FROM meta WHERE clave='estado_runtime'").fetchone()
    if not fila:
        return {}
    try:
        d = json.loads(fila[0])
    except (TypeError, ValueError):
        return {}
    if not isinstance(d, dict):
        return {}
    out = {}
    if isinstance(d.get('tiempo_ultimo_ciclo'), (int, float)) and not isinstance(d.get('tiempo_ultimo_ciclo'), bool):
        out['tiempo_ultimo_ciclo'] = d['tiempo_ultimo_ciclo']
    if isinstance(d.get('wan_prev'), dict):
        out['wan_prev'] = d['wan_prev']
    if isinstance(d.get('disp_prev'), dict):
        out['disp_prev'] = d['disp_prev']
    if isinstance(d.get('disp_handle'), dict):
        out['disp_handle'] = d['disp_handle']
    return out


def _guardar_estado_runtime_meta(conn, tiempo_ultimo_ciclo, wan_prev, disp_prev, disp_handle):
    conn.execute(
        "INSERT INTO meta(clave, valor) VALUES('estado_runtime', ?) "
        "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor",
        (json.dumps({'tiempo_ultimo_ciclo': tiempo_ultimo_ciclo, 'wan_prev': wan_prev,
                     'disp_prev': disp_prev, 'disp_handle': disp_handle}),))


def rollup_hora(conn, inicio_hora):
    """Agrega a trafico_wan_hora/trafico_disp_hora el tramo [inicio_hora,
    inicio_hora+3600) de las tablas por minuto: suma de bytes, MEDIA de
    latencia/pérdida, MÁXIMO de en_balanceo (¿estuvo en balanceo en algún
    momento de la hora?) para WAN; MÁXIMO de conexiones para dispositivo
    (spec: "conexiones = máximo"). No falla si no hay filas ese tramo (no
    inserta nada)."""
    fin_hora = inicio_hora + 3600
    conn.execute(
        'INSERT OR REPLACE INTO trafico_wan_hora(ts, wan, nombre, rx_bytes, tx_bytes, latencia_ms, perdida_pct, en_balanceo) '
        'SELECT ?, wan, MAX(nombre), SUM(rx_bytes), SUM(tx_bytes), AVG(latencia_ms), AVG(perdida_pct), MAX(en_balanceo) '
        'FROM trafico_wan WHERE ts >= ? AND ts < ? GROUP BY wan',
        (inicio_hora, inicio_hora, fin_hora))
    conn.execute(
        'INSERT OR REPLACE INTO trafico_disp_hora(ts, ip, mac, nombre, bajada_bytes, subida_bytes, conexiones) '
        'SELECT ?, ip, MAX(mac), MAX(nombre), SUM(bajada_bytes), SUM(subida_bytes), MAX(conexiones) '
        'FROM trafico_disp WHERE ts >= ? AND ts < ? GROUP BY ip',
        (inicio_hora, inicio_hora, fin_hora))


def aplicar_retencion(conn, ts, dias_dns):
    conn.execute('DELETE FROM trafico_wan WHERE ts < ?', (ts - RETENCION_MINUTOS_S,))
    conn.execute('DELETE FROM trafico_disp WHERE ts < ?', (ts - RETENCION_MINUTOS_S,))
    conn.execute('DELETE FROM conexiones WHERE ts < ?', (ts - RETENCION_MINUTOS_S,))
    conn.execute('DELETE FROM trafico_wan_hora WHERE ts < ?', (ts - RETENCION_HORAS_S,))
    conn.execute('DELETE FROM trafico_disp_hora WHERE ts < ?', (ts - RETENCION_HORAS_S,))
    conn.execute('DELETE FROM dns_hora WHERE hora < ?', (ts - dias_dns * 86400,))


# ──────────────────────────── el recolector ────────────────────────────

class Estadisticas:
    def __init__(self, rutas):
        self.rutas = rutas
        self.cfg = {'habilitada': True, 'intervalo_s': INTERVALO_DEFECTO_S,
                    'registro_dns_dias': DNS_DIAS_DEFECTO, 'dominio_local': DOMINIO_LOCAL_DEFECTO}
        self.conn = None
        self._wan_bytes_prev = {}     # id_wan -> {'rx','tx','interfaz'}
        self._disp_bytes_prev = {}    # ip -> {'sube': bytes, 'baja': bytes}
        self._disp_set_handle = {}    # 'sube'/'baja' -> último handle visto
        self._dns_estado = None
        self._dns_estado_cargado = False   # ver _procesar_dns: se carga de meta la 1a vez
        self._dns = ProcesadorDns()
        self._ultima_hora_rollup = None
        self._ultimo_dia_vacuum = None
        self._aviso_dns_log_fallo = False   # ALTA1: WARNING una sola vez, no cada ciclo
        self._tiempo_ultimo_ciclo = None    # reloj REAL (no `ts`) del ciclo anterior — ver ciclo()
        self._estado_runtime_cargado = False   # ver _cargar_estado_runtime: se carga de meta la 1a vez
        self.parar = threading.Event()

    def _asegurar_db(self):
        if self.conn is None:
            self.conn = abrir_db(self.rutas['db'])

    def cerrar(self):
        """Cierre LIMPIO (SIGTERM, fin de `--una-vez`) — ver `cerrar_db`
        para el motivo. Idempotente: llamarlo dos veces (o sin haber
        llegado a abrir la base nunca, p. ej. `router_estadisticas.
        habilitada=False` desde el primer ciclo) no hace nada la segunda
        vez ni lanza."""
        if self.conn is not None:
            cerrar_db(self.conn)
            self.conn = None

    def _cargar_estado_runtime(self):
        """Recupera las líneas base de WAN/dispositivo (y el reloj del
        último ciclo, y el `handle` de los sets nft) tras un reinicio del
        proceso — ver `leer_estado_runtime_meta`. Se llama UNA sola vez,
        la primera vez que hay una conexión abierta (igual que la posición
        del log DNS); si no hay nada persistido (primer arranque de
        verdad), no cambia nada."""
        datos = leer_estado_runtime_meta(self.conn)
        if 'tiempo_ultimo_ciclo' in datos:
            self._tiempo_ultimo_ciclo = datos['tiempo_ultimo_ciclo']
        if 'wan_prev' in datos:
            self._wan_bytes_prev = datos['wan_prev']
        if 'disp_prev' in datos:
            self._disp_bytes_prev = datos['disp_prev']
        if 'disp_handle' in datos:
            self._disp_set_handle = datos['disp_handle']

    def _guardar_estado_runtime(self, conn):
        _guardar_estado_runtime_meta(conn, self._tiempo_ultimo_ciclo, self._wan_bytes_prev,
                                      self._disp_bytes_prev, self._disp_set_handle)

    # ---- WAN ----
    def _procesar_wans(self, ts, estado, demasiado_tiempo=False):
        filas = []
        vistos = set()
        for w in (estado or {}).get('wans', []) or []:
            wid = w.get('id')
            if not wid:
                continue
            vistos.add(wid)
            interfaz = w.get('interfaz')
            presente = w.get('presente')
            if not presente or not interfaz:
                # ALTA3: routerd publica rx_bytes/tx_bytes "sintéticos"
                # (normalmente 0) para una WAN ausente o sin medir todavía
                # — tratarlos como lectura real metería un pico falso
                # (0 -> contador de vida entero) en cuanto la WAN vuelva.
                # Se olvida la línea base: el primer ciclo tras volver es
                # "primera vez" (sin delta), no un salto gigante.
                self._wan_bytes_prev.pop(wid, None)
                continue
            rx, tx = w.get('rx_bytes'), w.get('tx_bytes')
            anterior = self._wan_bytes_prev.get(wid)
            if anterior is not None and anterior.get('interfaz') != interfaz:
                # Cambió de interfaz bajo el mismo id (otro teléfono, u
                # otro nombre de interfaz para el mismo): los contadores
                # del kernel son de OTRO dispositivo, no sirven de línea base.
                anterior = None
            drx = calcular_delta(anterior.get('rx') if anterior else None, rx)
            dtx = calcular_delta(anterior.get('tx') if anterior else None, tx)
            if isinstance(rx, (int, float)) and isinstance(tx, (int, float)):
                self._wan_bytes_prev[wid] = {'rx': rx, 'tx': tx, 'interfaz': interfaz}
            if demasiado_tiempo:
                # A (revisión Opus): el ciclo anterior fue hace MUCHO más
                # de lo normal (routerd/estado.json atascados varios
                # minutos) — el delta acumulado en todo ese hueco NO debe
                # meterse entero en esta única fila de 60 s (parecería un
                # pico de N veces el tráfico real de un minuto). Se
                # descarta el delta; la línea base de arriba YA se
                # actualizó al valor actual, así que el ciclo SIGUIENTE
                # (si vuelve a la cadencia normal) sigue siendo correcto.
                drx = dtx = None
            if drx is not None or dtx is not None:
                filas.append({'wan': wid, 'nombre': w.get('nombre'),
                               'rx_bytes': drx or 0, 'tx_bytes': dtx or 0,
                               'latencia_ms': w.get('latencia_ms'), 'perdida_pct': w.get('perdida_pct'),
                               'en_balanceo': w.get('en_balanceo')})
        for wid in set(self._wan_bytes_prev) - vistos:
            self._wan_bytes_prev.pop(wid, None)
        if filas:
            _transaccion(self.conn, guardar_trafico_wan, ts, filas)
        return len(filas)

    # ---- dispositivos LAN (nft + conntrack + mac/nombre) ----
    def _procesar_dispositivos(self, ts, estado, tabla_nft, nft_bin, demasiado_tiempo=False):
        sube, handle_sube, err1 = leer_set_nft(tabla_nft, 'disp_sube', nft_bin)
        sube_ok = err1 is None
        if err1:
            LOG.warning('nft list set disp_sube: %s', err1)
        baja, handle_baja, err2 = leer_set_nft(tabla_nft, 'disp_baja', nft_bin)
        baja_ok = err2 is None
        if err2:
            LOG.warning('nft list set disp_baja: %s', err2)

        conexiones_total = leer_conexiones_total(self.rutas.get('conntrack_count'))
        guardar_conexiones(self.conn, ts, conexiones_total)
        conexiones_ip = leer_conexiones_por_ip(self.rutas.get('conntrack_tabla'),
                                                total_conocido=conexiones_total)

        leases = leer_leases(self.rutas.get('leases'))

        # BAJA9: si el handle del set cambió desde el último ciclo con
        # lectura válida, la tabla se reinstaló: los contadores volvieron
        # a 0 de verdad -> la primera lectura tras el reinicio es un delta
        # limpio (0 -> N), no "sin datos" (se fuerza la línea base a 0
        # para esa dimensión, en vez de a None/ausente).
        for dim, handle, ok in (('sube', handle_sube, sube_ok), ('baja', handle_baja, baja_ok)):
            if not ok:
                continue
            anterior_handle = self._disp_set_handle.get(dim)
            if anterior_handle is not None and handle is not None and handle != anterior_handle:
                for v in self._disp_bytes_prev.values():
                    if dim in v:
                        v[dim] = 0
            self._disp_set_handle[dim] = handle

        # BAJA8: un fallo de nft en UNA dimensión no debe borrar las bases
        # de la OTRA (ni de ésta): sólo se tocan/consultan las dimensiones
        # que se leyeron con éxito este ciclo.
        ips_relevantes = set(self._disp_bytes_prev)
        if sube_ok:
            ips_relevantes |= set(sube)
        if baja_ok:
            ips_relevantes |= set(baja)

        filas = []
        for ip in ips_relevantes:
            anterior = self._disp_bytes_prev.get(ip, {})
            nuevo = dict(anterior)
            d_sube = None
            if sube_ok:
                d_sube = calcular_delta(anterior.get('sube'), sube.get(ip))
                if ip in sube:
                    nuevo['sube'] = sube[ip]
                else:
                    nuevo.pop('sube', None)
            d_baja = None
            if baja_ok:
                d_baja = calcular_delta(anterior.get('baja'), baja.get(ip))
                if ip in baja:
                    nuevo['baja'] = baja[ip]
                else:
                    nuevo.pop('baja', None)
            if nuevo:
                self._disp_bytes_prev[ip] = nuevo
            else:
                self._disp_bytes_prev.pop(ip, None)
            if demasiado_tiempo:
                # A (revisión Opus): mismo motivo que en _procesar_wans —
                # un hueco mucho más largo de lo normal desde el ciclo
                # anterior metería el tráfico de varios minutos en una
                # sola fila de 60 s (pico falso). Se descarta el delta; la
                # línea base ya quedó actualizada arriba.
                d_sube = None
                d_baja = None
            if d_sube is None and d_baja is None:
                continue
            mac, nombre = resolver_dispositivo(ip, estado, leases)
            filas.append({'ip': ip, 'mac': mac, 'nombre': nombre,
                           'subida_bytes': d_sube, 'bajada_bytes': d_baja,
                           'conexiones': (conexiones_ip.get(ip) if conexiones_ip is not None else None)})
        if filas:
            _transaccion(self.conn, guardar_trafico_disp, ts, filas)
        return len(filas), conexiones_total is not None

    # ---- DNS ----
    def _procesar_dns(self, ts):
        if not self._dns_estado_cargado:
            # BAJA12: la posición persistida vive en 'meta', no en un
            # fichero aparte — sólo se puede leer una vez que self.conn
            # existe (por eso no se hace en __init__).
            self._dns_estado = leer_posicion_dns_meta(self.conn)
            self._dns_estado_cargado = True
        self._dns.dominio_local = self.cfg.get('dominio_local')

        lineas, nuevo_estado, error = leer_bloques_nuevos(self.rutas['dns_log'], self._dns_estado)
        if error:
            if not self._aviso_dns_log_fallo:
                LOG.warning('no se pudo leer %s: %s (¿falta SupplementaryGroups=dnsmasq o '
                            'CAP_DAC_READ_SEARCH en el .service?)', self.rutas['dns_log'], error)
                self._aviso_dns_log_fallo = True
        else:
            self._aviso_dns_log_fallo = False

        ahora_epoch = time.time()
        for linea in lineas:
            self._dns.procesar_linea(linea, ahora_epoch=ahora_epoch)

        hay_posicion_nueva = nuevo_estado != self._dns_estado
        n_entradas = len(self._dns.agregados)
        if self._dns.agregados or hay_posicion_nueva:
            agregados = self._dns.agregados

            def _escribir(conn):
                # BAJA12: posición + agregados en la MISMA transacción.
                if hay_posicion_nueva:
                    _guardar_posicion_dns_meta(conn, nuevo_estado['inode'], nuevo_estado['offset'])
                guardar_dns_hora(conn, agregados)

            _transaccion(self.conn, _escribir)
            self._dns.agregados = {}
        self._dns_estado = nuevo_estado
        return n_entradas

    # ---- rollup + retención ----
    def _rollup_y_retencion(self, ts):
        hora_actual = (ts // 3600) * 3600
        if self._ultima_hora_rollup is None:
            fila = self.conn.execute("SELECT valor FROM meta WHERE clave='ultima_hora_rollup'").fetchone()
            self._ultima_hora_rollup = int(fila[0]) if fila else hora_actual - 3600
        # BAJA13: tras una parada larga no se intenta poner al día TODAS
        # las horas perdidas (podrían ser miles, y bloquear el ciclo
        # entero) — se acota a las últimas RETENCION_MINUTOS_S (48h: más
        # atrás no habría datos por minuto de los que agregar nada, ya los
        # habría borrado la propia retención) y se avisa al watchdog en
        # cada vuelta del bucle.
        limite_antiguedad = hora_actual - RETENCION_MINUTOS_S
        hora = max(self._ultima_hora_rollup, limite_antiguedad)
        while hora < hora_actual:
            _transaccion(self.conn, rollup_hora, hora)
            hora += 3600
            _sd_notify('WATCHDOG=1')
        if hora != self._ultima_hora_rollup:
            self._ultima_hora_rollup = hora
            self.conn.execute(
                "INSERT INTO meta(clave, valor) VALUES('ultima_hora_rollup', ?) "
                "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor", (str(hora),))
        _transaccion(self.conn, aplicar_retencion, ts, self.cfg.get('registro_dns_dias', DNS_DIAS_DEFECTO))

        # BAJA14: auto_vacuum=INCREMENTAL (puesto en abrir_db sólo para
        # bases NUEVAS) no libera páginas por sí solo — hay que pedirlo
        # explícitamente; una vez al día basta (la retención de arriba es
        # lo que deja páginas libres que compactar).
        dia_actual = ts // 86400
        if self._ultimo_dia_vacuum != dia_actual:
            try:
                self.conn.execute('PRAGMA incremental_vacuum')
            except sqlite3.Error:
                LOG.exception('PRAGMA incremental_vacuum falló')
            self._ultimo_dia_vacuum = dia_actual

    def ciclo(self, nft_bin=NFT_BIN, tabla_nft='router'):
        """Devuelve un resumen `{'trafico_wan': N, 'trafico_disp': N,
        'conexiones': 0|1, 'dns_hora': N}` de filas guardadas este ciclo
        (revisión Opus, tras el e2e con root: `--una-vez` necesitaba dejar
        constancia de algo más que silencio en el log) — `None` si el
        servicio está deshabilitado (`router_estadisticas.habilitada`) y
        este ciclo no hizo nada en absoluto."""
        self.cfg = leer_config_estadisticas(self.rutas['config'])
        if not self.cfg.get('habilitada', True):
            return None
        self._asegurar_db()
        if not self._estado_runtime_cargado:
            # Revisión Opus (tras el e2e con root): las líneas base de
            # WAN/dispositivo vivían SÓLO en memoria — cada reinicio del
            # proceso (incluido cada `--una-vez`, comprobado de verdad en
            # el e2e: la segunda pasada no tenía base y no calculaba
            # ningún delta) las perdía. Se recuperan de 'meta' aquí, antes
            # del chequeo del hueco de reloj de abajo (que ya decide si
            # son demasiado viejas para fiarse de ellas).
            self._cargar_estado_runtime()
            self._estado_runtime_cargado = True
        ts = (ahora_ts() // 60) * 60

        # A (revisión Opus): si ha pasado MUCHO más tiempo del normal
        # desde el ciclo anterior (routerd/estado.json atascados, el
        # propio proceso durmiendo más de la cuenta, o simplemente un
        # reinicio tras mucho rato parado…), los deltas de WAN/
        # dispositivo de ESTE ciclo cubrirían varios minutos de golpe — se
        # descartan (ver _procesar_wans/_procesar_dispositivos) en vez de
        # meter ese tráfico entero en una única fila de 60 s (parecería un
        # pico de N veces lo real). Se usa el reloj REAL (time.time()),
        # no `ts` (que ya viene redondeado al minuto y no refleja huecos
        # menores de 60 s con la precisión que hace falta aquí) — y, tras
        # cargar el estado de arriba, puede venir de un proceso ANTERIOR,
        # no sólo de este mismo.
        intervalo_s = self.cfg.get('intervalo_s', INTERVALO_DEFECTO_S) or INTERVALO_DEFECTO_S
        ahora_real = time.time()
        demasiado_tiempo = False
        if self._tiempo_ultimo_ciclo is not None:
            transcurrido = ahora_real - self._tiempo_ultimo_ciclo
            if transcurrido > 2 * intervalo_s:
                demasiado_tiempo = True
                LOG.warning('han pasado %.0f s desde el ciclo anterior (> 2x intervalo_s=%s s): '
                            'se descartan los deltas de WAN/dispositivo de este ciclo',
                            transcurrido, intervalo_s)
        self._tiempo_ultimo_ciclo = ahora_real

        estado = leer_estado(self.rutas['estado'])
        _sd_notify('WATCHDOG=1')
        n_wan = 0
        if estado is not None:
            n_wan = self._procesar_wans(ts, estado, demasiado_tiempo=demasiado_tiempo)
        _sd_notify('WATCHDOG=1')
        n_disp, conexiones_escrita = self._procesar_dispositivos(
            ts, estado, tabla_nft, nft_bin, demasiado_tiempo=demasiado_tiempo)
        _sd_notify('WATCHDOG=1')
        n_dns = self._procesar_dns(ts)
        _sd_notify('WATCHDOG=1')

        def _escribir_meta_final(conn):
            actualizar_meta(conn, ts)
            self._guardar_estado_runtime(conn)

        _transaccion(self.conn, _escribir_meta_final)
        self._rollup_y_retencion(ts)
        _sd_notify('WATCHDOG=1')
        return {'trafico_wan': n_wan, 'trafico_disp': n_disp,
                'conexiones': 1 if conexiones_escrita else 0, 'dns_hora': n_dns}

    def bucle(self, nft_bin=NFT_BIN, tabla_nft='router'):
        notificado = False
        while not self.parar.is_set():
            t0 = time.time()
            try:
                self.ciclo(nft_bin=nft_bin, tabla_nft=tabla_nft)
            except Exception:   # nunca puede morir por un ciclo raro (H5)
                LOG.exception('error en el ciclo de router_estadisticas')
            if not notificado:
                _sd_notify('READY=1')
                notificado = True
            _sd_notify('WATCHDOG=1')
            intervalo = float(self.cfg.get('intervalo_s', INTERVALO_DEFECTO_S) or INTERVALO_DEFECTO_S)
            restante = max(1.0, intervalo - (time.time() - t0))
            paso_s = 15
            while restante > 0 and not self.parar.is_set():
                paso = min(paso_s, restante)
                if self.parar.wait(paso):
                    break
                restante -= paso
                _sd_notify('WATCHDOG=1')
        # Parada limpia (SIGTERM): ver cerrar_db — nunca se sale dejando la
        # base en WAL.
        self.cerrar()


def actualizar_meta(conn, ts):
    conn.execute("INSERT INTO meta(clave, valor) VALUES('ultimo_ts', ?) "
                 "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor", (str(ts),))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', default=RUTAS['config'])
    ap.add_argument('--estado', default=RUTAS['estado'])
    ap.add_argument('--db', default=RUTAS['db'])
    ap.add_argument('--dns-log', default=RUTAS['dns_log'])
    ap.add_argument('--leases', default=RUTAS['leases'])
    ap.add_argument('--conntrack-count', default=RUTAS['conntrack_count'])
    ap.add_argument('--conntrack-tabla', default=RUTAS['conntrack_tabla'])
    ap.add_argument('--nft-bin', default=NFT_BIN)
    ap.add_argument('--tabla-nft', default='router')
    # BAJA16: igual que routerd.py --raiz-datos — prefijo para todas las
    # rutas de DATOS (no --config, que sigue siendo su propia ruta
    # explícita; --estado SÍ se prefija, como en routerd). Pensado para
    # pruebas/netns_multiwan.sh, que ya usa este patrón con routerd.py.
    # conntrack_count/conntrack_tabla son rutas de /proc REALES del
    # namespace de red (no datos de fichero de este programa): nunca se
    # prefijan.
    ap.add_argument('--raiz-datos', help='prefijo para las rutas de datos (pruebas)')
    ap.add_argument('--una-vez', action='store_true')
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', stream=sys.stdout)
    rutas = dict(RUTAS, config=a.config, estado=a.estado, db=a.db, dns_log=a.dns_log,
                 leases=a.leases, conntrack_count=a.conntrack_count, conntrack_tabla=a.conntrack_tabla)
    if a.raiz_datos:
        for k in ('estado', 'leases', 'dns_log', 'db'):
            rutas[k] = os.path.join(a.raiz_datos, rutas[k].lstrip('/'))
    svc = Estadisticas(rutas)
    signal.signal(signal.SIGTERM, lambda *_: svc.parar.set())
    if a.una_vez:
        resumen = svc.ciclo(nft_bin=a.nft_bin, tabla_nft=a.tabla_nft)
        svc.cerrar()   # --una-vez también es una parada limpia: ver cerrar_db
        # Revisión Opus (tras el e2e con root): sin esto, un --una-vez que
        # no escribiera nada (p. ej. sin línea base todavía) dejaba el log
        # del e2e totalmente vacío y no había forma de distinguir "no pasó
        # nada" de "algo falló en silencio" sólo con la salida estándar
        # (ésta, por `logging.basicConfig`, va a stdout). Se imprime a
        # STDERR a propósito, para que no se confunda con el log normal.
        if resumen is None:
            print('RESUMEN --una-vez: deshabilitado (router_estadisticas.habilitada=false)',
                  file=sys.stderr)
        else:
            print('RESUMEN --una-vez: ' + ' '.join('%s=%d' % (k, v) for k, v in sorted(resumen.items())),
                  file=sys.stderr)
    else:
        svc.bucle(nft_bin=a.nft_bin, tabla_nft=a.tabla_nft)


if __name__ == '__main__':
    main()
