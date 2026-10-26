#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""router_bloqueo — bloqueador de anuncios, rastreadores y amenazas por DNS.

Proceso APARTE de routerd (mismo patrón que router_adb.py), pero ONESHOT: no
tiene bucle propio. Lo lanza systemd/router-bloqueo.timer cada
`bloqueo.actualizar_h` horas, y routerd «a demanda» (acción de buzón
`bloqueo_actualizar`, vía `systemctl --no-block start router-bloqueo.service`
— ver docs/CONTRATO.md). Lee `/etc/router/router.json` DIRECTAMENTE (como
router_adb.py: no comparte el proceso de routerd, así un fallo de red
descargando una lista de millones de dominios nunca puede arriesgar el
watchdog de routerd ni el ciclo de nftables/rutas/DHCP).

Revisión Opus (ronda 2) — cambios de fondo respecto a la primera versión:

- El fichero activo (`dnsmasq-bloqueo.conf`) ahora es un `servers-file=` de
  dnsmasq, NO un `conf-file=` genérico: sólo admite líneas `server=`, pero a
  cambio dnsmasq lo RELEE con un simple SIGHUP (comprobado empíricamente con
  dnsmasq 2.93: `--servers-file=X` + `kill -HUP` limpia la caché y aplica el
  cambio) — nunca hace falta un restart completo, que cortaría el DHCP un
  instante. Bloquear ahora es `server=/dominio/` (sin dirección: dnsmasq no
  tiene a quién preguntar y responde NXDOMAIN); permitir una excepción
  (lista blanca, o un dominio protegido) es `server=/dominio/#` ("usa los
  servidores normales para este dominio") — dnsmasq aplica SIEMPRE la
  coincidencia más específica sin importar el orden de las líneas, así que
  un hijo en la lista blanca "agujerea" un padre bloqueado sin desbloquear
  a sus hermanos (comprobado empíricamente).
- Dominios protegidos fijos en código (nunca bloqueables, pase lo que pase
  en las listas o en lista_negra): lo que el propio router necesita para
  funcionar.
- Cota global de dominios (no por lista), guarda de variación ±50% entre
  pasadas (salvo la primera o un cambio de listas elegidas), y reintento de
  la pasada entera si la sección `bloqueo` de router.json cambia mientras
  se estaba ejecutando.

Qué hace, en una pasada (repetida hasta 3 veces si la config cambia a
mitad — ver `main()`):

1. Si la fase no es "producción" (mismo fichero `/etc/router/fase` que lee
   routerd), no hace nada y termina con éxito.
2. Por cada id de `bloqueo.listas` (y además `hagezi_doh` si
   `bloqueo.bloquear_doh`, aunque no esté en `listas` — ver CATALOGO):
   descarga la URL fija del catálogo por HTTPS (TLS verificado, sólo sigue
   redirecciones HTTPS, timeout + plazo total por lista, límite de tamaño
   MIENTRAS se descarga, User-Agent propio, caché en disco con
   ETag/If-Modified-Since). Si la descarga falla, se usa la caché anterior
   de esa lista (si la hay); si no hay caché, esa lista queda sin dominios
   esta vez (nunca tira el proceso entero).
3. Cada línea descargada se valida con una regex estricta de dominio
   (`normalizar_dominio`), en streaming (nunca se materializa toda la
   lista de líneas en memoria de golpe): nunca se copia una línea cruda a
   la config final — comentarios, basura, mayúsculas, IDN (se convierte a
   punycode) e intentos de inyección se descartan sin afectar al resto.
4. Se unen todas las listas (set, sin duplicados, cota global de 1 500 000
   dominios), se añaden los de `bloqueo.lista_negra` (salvo sufijos
   públicos de dos etiquetas tipo co.uk, y salvo que sean un dominio
   protegido), se quitan los dominios protegidos y los de
   `bloqueo.lista_blanca` (y sus subdominios), y si `bloqueo.bloquear_doh`
   se añade el canario de Firefox `use-application-dns.net`.
5. Guarda de sentido común: si el total varía más de un ±50% respecto a la
   última pasada CON ÉXITO (y las listas elegidas no han cambiado), se
   aborta sin tocar nada — podría ser una lista rota devolviendo basura.
6. Se genera el `servers-file`, se valida con `dnsmasq --test` sobre un
   fichero de prueba mínimo (`servers-file=<temporal>`) ANTES de activarlo;
   si el contenido es idéntico al ya activo (comparación por hash, nunca
   leyendo el fichero entero), no se hace nada. Se activa con dos renames
   atómicos (nunca se lee el fichero anterior en memoria para poder
   restaurarlo) y un `systemctl kill -s HUP dnsmasq`; si tras eso dnsmasq
   no está activo, se restaura el anterior, o si eso también falla, se
   deja vacío (nunca a medias).
7. Se publica `/run/router/bloqueo.json` (ver docs/CONTRATO.md).

Con `bloqueo.habilitado = false`: se genera un `servers-file` VACÍO (sólo la
cabecera) — nunca se borra el fichero ni se deja a medias; routerd lo
referencia SIEMPRE (`servers-file=...`), exista lo que exista dentro.

Uso:  router_bloqueo.py [--config /etc/router/router.json]
                        [--fase /etc/router/fase] [--raiz-datos DIR]
"""
import argparse
import grp
import hashlib
import io
import json
import logging
import os
import random
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

LOG = logging.getLogger('router_bloqueo')

RUTAS = {
    'config': '/etc/router/router.json',
    'fase': '/etc/router/fase',
    'cache_dir': '/var/lib/router/bloqueo',
    'dnsmasq_bloqueo': '/var/lib/router/bloqueo/dnsmasq-bloqueo.conf',
    'estado': '/run/router/bloqueo.json',
    'oplog': '/var/log/router/operaciones.log',
}

# Canario DoH de Firefox (RFC-ish de facto): si esta consulta devuelve
# NXDOMAIN, Firefox NO activa DNS-over-HTTPS automático.
CANARIO_DOH = 'use-application-dns.net'

# ──────────────────────────────── catálogo ─────────────────────────────────
_BASE = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/%s-onlydomains.txt'

CATALOGO = {
    'hagezi_light': {
        'nombre': 'HaGeZi Light',
        'descripcion': 'Lo mínimo: anuncios y rastreadores básicos, muy pocos falsos positivos.',
        'url': _BASE % 'light',
    },
    'hagezi_multi': {
        'nombre': 'HaGeZi Multi',
        'descripcion': 'Equilibrio entre Light y Pro: anuncios, rastreadores y telemetría habituales.',
        'url': _BASE % 'multi',
    },
    'hagezi_pro': {
        'nombre': 'HaGeZi Pro',
        'descripcion': 'Más agresiva: anuncios, rastreadores, telemetría y afiliados. Recomendada por defecto.',
        'url': _BASE % 'pro',
    },
    'hagezi_pro_plus': {
        'nombre': 'HaGeZi Pro++',
        'descripcion': 'Como Pro, más agresiva aún (más listas de terceros incluidas): más riesgo de falsos positivos.',
        'url': _BASE % 'pro.plus',
    },
    'hagezi_tif': {
        'nombre': 'HaGeZi Threat Intelligence Feeds',
        'descripcion': 'Amenazas: malware, phishing, cryptojacking, servidores de mando y control '
                       '(versión «medium», ~600 mil dominios: la completa pasa de 2 millones y no '
                       'cabe en un router doméstico).',
        # La «tif» completa (~2 M de dominios, 34 MB) supera la cota global
        # LIMITE_DOMINIOS_TOTAL y se descarga mal por las líneas móviles.
        'url': _BASE % 'tif.medium',
    },
    'hagezi_doh': {
        'nombre': 'HaGeZi DNS-over-HTTPS/TLS/QUIC',
        'descripcion': 'Servidores DNS cifrados públicos conocidos (para que bloquear_doh no se pueda rodear).',
        'url': _BASE % 'doh',
    },
    'hagezi_nsfw': {
        'nombre': 'HaGeZi NSFW',
        'descripcion': 'Contenido para adultos (opcional).',
        'url': _BASE % 'nsfw',
    },
    'hagezi_gambling': {
        'nombre': 'HaGeZi Apuestas',
        'descripcion': 'Sitios de apuestas y juego online.',
        'url': _BASE % 'gambling',
    },
}

LIMITE_DESCARGA_BYTES = 50 * 1024 * 1024
TIMEOUT_DESCARGA_S = 30          # límite por operación de socket individual
INTENTOS_DESCARGA = 3
DEADLINE_TOTAL_S = 300           # BAJA5: límite de reloj TOTAL por lista (conexión + todas las lecturas)
USER_AGENT = 'router-casa-bloqueo/1.0 (+https://github.com/hagezi/dns-blocklists; uso domestico)'

# M4: cota GLOBAL (no por lista) tras unir todas las listas — una portátil
# con ~2 GB de RAM no debe poder quedarse sin memoria por una combinación
# de listas enorme. Si se recorta, se avisa (estado.json + oplog).
LIMITE_DOMINIOS_TOTAL = 1_500_000

DEFECTO_BLOQUEO = {
    'habilitado': True, 'listas': ['hagezi_pro', 'hagezi_tif'],
    'lista_blanca': [], 'lista_negra': [],
    'forzar_dns': True, 'bloquear_doh': True,
    'actualizar_h': 24, 'registro_dns_dias': 30,
}

# M5: dominios que el router NUNCA debe bloquear, pase lo que pase en las
# listas o en lista_negra — lo que el propio router necesita para
# funcionar: descargar las listas de HaGeZi (+ sus hosts), el ACME de
# IONOS/Let's Encrypt para el certificado del panel, los repositorios de
# Debian, NTP. Se añaden también, en _dominios_protegidos(), los hosts
# reales de CATALOGO (por si cambian las URLs) y el dominio de la casa
# configurado en router.json (cfg['dominio']).
#
# Revisión Opus (ronda 3, BAJA3): "home.arpa"/"arpa" YA NO viven aquí —
# protegerlos vía este mecanismo (pensado para "hosts con los que el
# router habla", no para higiene general de DNS) era la capa equivocada.
# El espacio reservado "arpa" (RFC 8375: home.arpa y cualquier *.arpa) se
# gestiona ahora de forma incondicional en dnsmasq_conf.py
# (`local=/home.arpa/`, siempre presente, independiente de si el
# bloqueador está activo) — ni se puede "desproteger" apagando el
# bloqueo, ni depende de que esté en esta lista.
PROTEGIDOS_FIJOS = frozenset({
    'raw.githubusercontent.com', 'github.com',
    'api.hosting.ionos.com',
    'acme-v02.api.letsencrypt.org', 'letsencrypt.org',
    'deb.debian.org', 'security.debian.org', 'debian.org',
    'pool.ntp.org', 'ntp.org',
    'time.cloudflare.com',
})

# M1 (ronda 4): centinela POR GENERACIÓN, no uno fijo — un centinela FIJO
# no distingue "dnsmasq ya cargó el servers-file nuevo" de "todavía tiene
# el viejo" cuando AMBAS generaciones bloquean el MISMO nombre fijo (las
# dos responderían NXDOMAIN, dando un falso "confirmado" aunque el SIGHUP
# no hubiera hecho nada de verdad). La base (".invalid", RFC 2606: un TLD
# que nunca debe resolver de verdad en ningún sitio, sin riesgo de
# colisión) lleva una `address=.../127.0.0.9` FIJA e incondicional en
# dnsmasq_conf.py (routerd) — RUTA_DNSMASQ_BLOQUEO nunca la toca. Cada
# pasada de router_bloqueo añade SÓLO al servers-file de ESA generación un
# `server=/g<hash8>.<CENTINELA_BASE>/` (bloqueado) específico de ese
# hash — dnsmasq aplica la coincidencia MÁS ESPECÍFICA, así que:
#   - si la generación NUEVA ya está cargada: g<hash8-nuevo>... → NXDOMAIN
#     (el server= específico de esta generación gana).
#   - si sigue la VIEJA (no tiene ese hash concreto bloqueado): cae al
#     `address=` genérico de dnsmasq_conf.py → responde 127.0.0.9.
# _consulta_dns_centinela() usa justo esa distinción tras el SIGHUP.
CENTINELA_BASE = 'bloqueo-centinela.router-casa.invalid'
CENTINELA_IP_VIEJA = '127.0.0.9'   # debe coincidir con el `address=` de dnsmasq_conf.py


def centinela_de_generacion(hash_generacion):
    """Nombre del centinela específico de ESTA generación (primeros 8
    caracteres del hash de su contenido real — dominios + excepciones,
    ANTES de añadir el propio centinela, para que el hash no dependa de
    sí mismo)."""
    return 'g%s.%s' % (hash_generacion[:8], CENTINELA_BASE)

# M5: sufijos públicos de dos etiquetas más habituales (NO es la Public
# Suffix List completa, que tiene miles de entradas — es una barrera de
# sentido común): bloquear uno de éstos en lista_negra se llevaría por
# delante prácticamente cualquier sitio comercial de ese país.
SUFIJOS_PUBLICOS_DOS_ETIQUETAS = frozenset({
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
    'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
    'com.mx', 'com.br', 'com.ar', 'com.co', 'com.pe', 'com.ve',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in', 'co.il', 'co.th', 'co.id',
    'com.cn', 'com.tw', 'com.hk', 'com.sg', 'com.my', 'com.ph', 'com.pk',
    'com.tr', 'com.ua', 'com.pl',
})

# Etiqueta DNS: 1-63 caracteres, alfanumérico, guion NUNCA al principio/fin.
RE_ETIQUETA = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')

# H4 (inyección): cualquier línea con espacio/control o alguno de estos
# caracteres se descarta ENTERA antes de tocar nada más.
_CARACTERES_PROHIBIDOS = re.compile(r'[\s\x00-\x1f\x7f/\\=;,*?#\'"`$|&<>%@:]')


def ahora_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def escribir_atomico(ruta, texto, modo=0o644):
    """Mismo patrón que routerd.escribir_atomico/router_adb.escribir_atomico:
    temporal exclusivo en el mismo directorio + fsync + rename atómico."""
    d = os.path.dirname(ruta)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, modo)
        os.replace(tmp, ruta)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def escribir_oplog(ruta, usuario, accion, datos, ok, mensaje):
    """Copiado de router_adb.escribir_oplog (mismo fichero y formato que el
    oplog de routerd — ver docs/CONTRATO.md)."""
    try:
        texto_datos = json.dumps(datos, ensure_ascii=False)
    except (TypeError, ValueError):
        texto_datos = None
    if texto_datos is None or len(texto_datos.encode('utf-8')) > 2048:
        datos = {'_recortado': True}
    linea = json.dumps({'fecha': ahora_iso(), 'usuario': usuario, 'accion': accion,
                        'datos': datos, 'ok': ok, 'mensaje': mensaje}, ensure_ascii=False)
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(ruta, flags, 0o644)
    try:
        os.write(fd, (linea + '\n').encode('utf-8'))
    finally:
        os.close(fd)
    (LOG.info if ok else LOG.warning)('%s: %s', accion, mensaje)


# ──────────────────────────── configuración ────────────────────────────

def _fase_efectiva(ruta_fase, ruta_config):
    """BAJA3: igual que routerd._fase_efectiva — fichero de fase primero;
    si no existe o no tiene un valor reconocido, la "fase" de router.json
    por compatibilidad; si tampoco, "preparacion" (nunca "produccion" por
    defecto: mejor no hacer nada que tocar algo fuera de producción)."""
    try:
        with open(ruta_fase) as f:
            contenido = f.read().strip()
        if contenido in ('preparacion', 'produccion'):
            return contenido
    except OSError:
        pass
    try:
        with open(ruta_config) as f:
            cfg = json.load(f)
        if isinstance(cfg, dict):
            valor = cfg.get('fase')
            if valor in ('preparacion', 'produccion'):
                return valor
    except (OSError, ValueError):
        pass
    return 'preparacion'


def leer_config_bloqueo(ruta):
    """{'habilitado', 'listas', 'lista_blanca', 'lista_negra', 'forzar_dns',
    'bloquear_doh', 'actualizar_h', 'registro_dns_dias', '_gestionar_dnsmasq',
    '_dominio_casa'} de router.json → 'bloqueo' (+ 'dominio' para los
    dominios protegidos). Cualquier problema (fichero ausente, JSON roto,
    forma rara, tipos equivocados) cae al defecto campo a campo — nunca se
    cae TODO el bloqueo por un router.json con un campo suelto mal
    escrito."""
    try:
        with open(ruta) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    seccion = cfg.get('bloqueo')
    if not isinstance(seccion, dict):
        seccion = {}
    out = dict(DEFECTO_BLOQUEO)
    if isinstance(seccion.get('habilitado'), bool):
        out['habilitado'] = seccion['habilitado']
    if isinstance(seccion.get('listas'), list):
        out['listas'] = [x for x in seccion['listas'] if isinstance(x, str)]
    if isinstance(seccion.get('lista_blanca'), list):
        out['lista_blanca'] = [x for x in seccion['lista_blanca'] if isinstance(x, str)][:5000]
    if isinstance(seccion.get('lista_negra'), list):
        out['lista_negra'] = [x for x in seccion['lista_negra'] if isinstance(x, str)][:5000]
    if isinstance(seccion.get('forzar_dns'), bool):
        out['forzar_dns'] = seccion['forzar_dns']
    if isinstance(seccion.get('bloquear_doh'), bool):
        out['bloquear_doh'] = seccion['bloquear_doh']
    actualizar_h = seccion.get('actualizar_h')
    if isinstance(actualizar_h, (int, float)) and not isinstance(actualizar_h, bool):
        out['actualizar_h'] = max(6, min(168, int(actualizar_h)))
    dias = seccion.get('registro_dns_dias')
    if isinstance(dias, (int, float)) and not isinstance(dias, bool):
        out['registro_dns_dias'] = max(1, min(365, int(dias)))
    gestionar_dnsmasq = cfg.get('gestionar_dnsmasq', True)
    out['_gestionar_dnsmasq'] = bool(gestionar_dnsmasq) if isinstance(gestionar_dnsmasq, bool) else True
    out['_dominio_casa'] = cfg.get('dominio') if isinstance(cfg.get('dominio'), str) else None
    return out


def _hash_bloqueo(ruta_config):
    """M3: huella de la sección 'bloqueo' + 'dominio' de router.json, para
    detectar si alguien (el buzón, vía routerd) la cambió MIENTRAS esta
    pasada estaba en marcha (una descarga de varios MiB puede tardar).
    None si no se puede calcular (fichero ilegible): en ese caso main() no
    reintenta (no tiene sentido repetir si ni siquiera se pudo leer)."""
    try:
        with open(ruta_config) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(cfg, dict):
        return None
    try:
        return hashlib.sha256(
            json.dumps({'bloqueo': cfg.get('bloqueo'), 'dominio': cfg.get('dominio')},
                       sort_keys=True, ensure_ascii=False).encode('utf-8')
        ).hexdigest()
    except (TypeError, ValueError):
        return None


def calcular_version_bloqueo(bloqueo):
    """sha256 hex, recortado a 16 caracteres, de la sección 'bloqueo' SIN
    `lista_blanca`/`lista_negra` — esas se gestionan aparte, una a una
    (`bloqueo_lista`), y cambian con mucha frecuencia; incluirlas haría que
    la "version" cambiara en cada bloqueo_lista, invalidando de inmediato
    cualquier formulario `bloqueo_config` que el panel tuviera a medio
    editar sin que el admin hubiera tocado nada de ESE formulario.

    Control de concurrencia optimista (routerd.publicar() la expone en
    `estado.json` → `config.bloqueo_version`; `bloqueo_config` acepta un
    campo opcional `version` y compara contra ÉSTA MISMA función —
    compartida para que publicar y validar nunca puedan desincronizarse):
    el panel manda la version que vio al abrir el formulario; si alguien
    más cambió algo relevante mientras tanto, se rechaza en vez de
    pisarlo silenciosamente."""
    relevante = {k: v for k, v in (bloqueo or {}).items() if k not in ('lista_blanca', 'lista_negra')}
    try:
        serializado = json.dumps(relevante, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        serializado = repr(sorted(relevante.items()))
    return hashlib.sha256(serializado.encode('utf-8')).hexdigest()[:16]


# ───────────────────────────── parseo de dominios ───────────────────────────

def normalizar_dominio(crudo):
    """Devuelve el dominio normalizado (minúsculas, punycode, sin punto
    final) o None si `crudo` no es, de verdad, un único dominio válido.

    NUNCA copia la línea tal cual: sólo el resultado de esta función (o
    nada) llega a la config final. Rechaza: líneas vacías/comentario,
    cualquier carácter de los de `_CARACTERES_PROHIBIDOS` (espacio, control,
    '/', '=', '*', '#'... — bloquea de raíz cualquier intento de inyección
    de una directiva de dnsmasq), etiquetas vacías/demasiado largas, un
    único «dominio» todo numérico (es una IP, no un nombre), y cualquier
    cosa que no se pueda codificar en punycode (IDN roto)."""
    if not isinstance(crudo, str):
        return None
    cruda = crudo.strip()
    if not cruda or cruda.startswith('#'):
        return None
    if _CARACTERES_PROHIBIDOS.search(cruda):
        return None
    dominio = cruda.rstrip('.')
    if not dominio:
        return None
    try:
        dominio = dominio.encode('idna').decode('ascii').lower()
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return None
    if not (1 <= len(dominio) <= 253):
        return None
    etiquetas = dominio.split('.')
    if len(etiquetas) < 2:
        return None
    for et in etiquetas:
        if not RE_ETIQUETA.fullmatch(et):
            return None
    if etiquetas[-1].isdigit():   # "1.2.3.4": es una IP, no un dominio
        return None
    return dominio


def es_sufijo_publico(dominio):
    """M5: ¿`dominio` (ya normalizado) es ÉL MISMO uno de los sufijos
    públicos de dos etiquetas más habituales (co.uk, com.es...)? No mira
    si ES SUBDOMINIO de uno (eso es normal y válido, p. ej.
    "ads.example.co.uk"); sólo rechaza el sufijo PELADO, que es lo que de
    verdad arrasaría medio país si se bloqueara."""
    return dominio is not None and dominio in SUFIJOS_PUBLICOS_DOS_ETIQUETAS


def parsear_lista(texto, limite=2_000_000):
    """set() de dominios válidos de `texto` (una lista HaGeZi 'wildcard
    domains', una línea por dominio, '#' = comentario).

    M4: itera con `io.StringIO` (streaming, una línea a la vez) en vez de
    `str.splitlines()` (que materializa TODAS las líneas en una lista de
    golpe) — con una lista de ~2 millones de líneas, en una portátil de
    ~2 GB de RAM, la diferencia importa. Nunca lanza: cada línea se valida
    POR SEPARADO con normalizar_dominio() — basura, comentarios, mayúsculas,
    IDN o un intento de inyección se descartan sin afectar al resto del
    fichero. `limite` es una cota POR LISTA defensiva (la cota de verdad,
    GLOBAL tras unir todas las listas, es LIMITE_DOMINIOS_TOTAL — ver
    `generar()`)."""
    dominios = set()
    if not texto:
        return dominios
    for linea in io.StringIO(texto):
        d = normalizar_dominio(linea)
        if d:
            dominios.add(d)
            if len(dominios) >= limite:
                break
    return dominios


def _sufijos(dominio):
    """[dominio, padre, abuelo, ..., tld] — todos los dominios "ancestros"
    (incluido él mismo), del más al menos específico."""
    partes = dominio.split('.')
    return ['.'.join(partes[i:]) for i in range(len(partes))]


def aplicar_lista_blanca(dominios, lista_blanca):
    """Quita de `dominios` cualquier entrada que sea, o sea subdominio de,
    alguna de `lista_blanca`. O(n·profundidad), no O(n·len(lista_blanca)).

    Esto cubre "blanquear un dominio Y TODOS sus subdominios" (cuando la
    entrada blanca es más genérica que lo bloqueado). El caso contrario —
    blanquear un hijo más específico que lo que aparece bloqueado (p. ej.
    la lista sólo trae "example.com" y se quiere exceptuar
    "bueno.example.com" sin desbloquear el resto de example.com) NO lo
    resuelve esto (quitar "example.com" entero del conjunto desbloquearía
    TODO) — para eso están las líneas `server=/dominio/#` que
    `generar_servers_file()` añade SIEMPRE, una por cada entrada de
    lista_blanca, independientemente de lo que haya en `dominios` (M1)."""
    blancos = {d for d in (normalizar_dominio(b) for b in lista_blanca) if d}
    if not blancos:
        return set(dominios)
    return {d for d in dominios if not any(s in blancos for s in _sufijos(d))}


def _dominios_protegidos(dominio_casa=None):
    """M5: conjunto de dominios que el router NUNCA debe bloquear. Incluye
    PROTEGIDOS_FIJOS, los hosts REALES de CATALOGO (por si cambian las
    URLs) y el dominio de la casa (router.json → "dominio") con todos sus
    subdominios — bloquearlo rompería la resolución de los propios equipos
    de la LAN."""
    fijos = set(PROTEGIDOS_FIJOS)
    for info in CATALOGO.values():
        try:
            host = urllib.parse.urlparse(info['url']).hostname
        except ValueError:
            host = None
        if host:
            fijos.add(host.lower())
    if dominio_casa:
        d = normalizar_dominio(dominio_casa)
        if d:
            fijos.add(d)
    return frozenset(fijos)


def generar_servers_file(dominios_bloqueados, excepciones):
    """Texto del `servers-file` de dnsmasq — SÓLO `server=` (un
    `servers-file=` de dnsmasq únicamente admite --server/--rev-server,
    nunca local=/address=; es, a cambio, la única forma de que dnsmasq
    relea el fichero con un simple SIGHUP sin cortar el DHCP — comprobado
    empíricamente con dnsmasq 2.93).

    - `server=/dominio/` (sin dirección): dnsmasq no tiene a quién
      preguntar por ese dominio y responde NXDOMAIN de inmediato — bloquea
      también los subdominios (mismo comportamiento que local=).
    - `server=/dominio/#` (M1): "usa los servidores normales para este
      dominio" — permite "agujerear" un dominio concreto aunque un
      ancestro suyo esté bloqueado más arriba; dnsmasq SIEMPRE aplica la
      coincidencia MÁS ESPECÍFICA, sin importar el orden de las líneas en
      el fichero (comprobado empíricamente). Se emite una de éstas por
      cada entrada de `excepciones` (lista blanca + dominios protegidos),
      exista o no ese dominio exacto en `dominios_bloqueados`.

    Orden determinista (sorted): mismo conjunto de entrada → mismo fichero
    byte a byte (para las pruebas, y para no disparar una recarga de
    dnsmasq por un cambio que no es de verdad un cambio)."""
    bloqueados = {d for d in dominios_bloqueados if d not in excepciones}
    lineas = [
        '# Generado por router_bloqueo — NO editar a mano.',
        '# %d dominios bloqueados (NXDOMAIN); %d excepciones.' % (len(bloqueados), len(excepciones)),
    ]
    lineas += ['server=/%s/' % d for d in sorted(bloqueados)]
    lineas += ['server=/%s/#' % d for d in sorted(excepciones)]
    return '\n'.join(lineas) + '\n'


# ───────────────────────────── descarga con caché ───────────────────────────

class _SoloHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """BAJA5: nunca sigue una redirección que no sea https:// — HaGeZi es
    https de punta a punta; una redirección a http (MITM, DNS envenenado,
    un proxy raro) nunca debe seguirse a ciegas."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith('https://'):
            raise urllib.error.URLError('redirección no-HTTPS rechazada: %s' % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ruta_cache(rutas, id_lista):
    return os.path.join(rutas['cache_dir'], '%s.txt' % id_lista)


def _ruta_meta(rutas, id_lista):
    return os.path.join(rutas['cache_dir'], '.%s.meta.json' % id_lista)


def descargar_lista(id_lista, url, rutas, timeout=TIMEOUT_DESCARGA_S, limite_bytes=LIMITE_DESCARGA_BYTES,
                     deadline_total_s=DEADLINE_TOTAL_S):
    """Descarga la lista `id_lista` desde `url`, con caché ETag/
    If-Modified-Since en disco (`<cache_dir>/<id_lista>.txt`). Devuelve
    (texto, de_cache: bool, error: str|None).

    - TLS verificado (ssl.create_default_context()), sólo redirecciones
      HTTPS (BAJA5), timeout por operación Y un plazo total por lista
      (BAJA5: conexión + todas las lecturas, para que una conexión lenta
      "goteando" bytes no pueda alargarse indefinidamente pese a que cada
      lectura individual sea rápida).
    - El límite de tamaño se aplica MIENTRAS se descarga, no después de
      tenerlo entero en memoria.
    - BAJA4: las cabeceras condicionales (If-None-Match/If-Modified-Since)
      sólo se añaden si YA había una caché de contenido Y de metadatos — no
      tiene sentido (ni es correcto) condicionar contra un ETag de una
      lista que nunca se llegó a descargar de verdad.
    - Nunca lanza: cualquier fallo de red/TLS/HTTP cae a la caché anterior
      con un error descrito; sin caché anterior, texto=None (esa lista
      queda sin dominios esta vez, no tira el proceso)."""
    t_inicio = time.monotonic()
    ruta_cache = _ruta_cache(rutas, id_lista)
    ruta_meta = _ruta_meta(rutas, id_lista)
    previo = None
    try:
        with open(ruta_cache, 'r', encoding='utf-8', errors='replace') as f:
            previo = f.read()
    except OSError:
        previo = None
    meta = None
    if previo is not None:   # BAJA4: sin caché de contenido, no hay nada que condicionar
        try:
            with open(ruta_meta) as f:
                meta = json.load(f)
        except (OSError, ValueError):
            meta = None
    cabeceras = {'User-Agent': USER_AGENT}
    if isinstance(meta, dict):
        if meta.get('etag'):
            cabeceras['If-None-Match'] = meta['etag']
        if meta.get('last_modified'):
            cabeceras['If-Modified-Since'] = meta['last_modified']
    peticion = urllib.request.Request(url, headers=cabeceras)
    contexto = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=contexto), _SoloHTTPSRedirectHandler())
    try:
        with opener.open(peticion, timeout=timeout) as resp:
            trozos, leido = [], 0
            while True:
                if time.monotonic() - t_inicio > deadline_total_s:
                    raise TimeoutError('%s superó el plazo total de %ds' % (url, deadline_total_s))
                trozo = resp.read(65536)
                if not trozo:
                    break
                leido += len(trozo)
                if leido > limite_bytes:
                    return previo, previo is not None, ('%s supera el límite de %d MiB' %
                                                          (url, limite_bytes // (1024 * 1024)))
                trozos.append(trozo)
            crudo = b''.join(trozos)
            texto = crudo.decode('utf-8', 'replace')
            nuevo_etag = resp.headers.get('ETag')
            nuevo_lm = resp.headers.get('Last-Modified')
    except TimeoutError as e:
        return previo, previo is not None, str(e)
    except urllib.error.HTTPError as e:
        if e.code == 304:   # no ha cambiado desde la última vez: la caché sigue siendo buena
            if previo is not None:
                return previo, True, None
            return None, False, 'sin caché previa y el servidor respondió 304 (no modificado)'
        return previo, previo is not None, 'HTTP %s descargando %s' % (e.code, url)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return previo, previo is not None, 'fallo descargando %s: %s' % (url, e)
    # Éxito: caché nueva (atómica) + sus metadatos para la próxima vez.
    try:
        escribir_atomico(ruta_cache, texto)
        escribir_atomico(ruta_meta, json.dumps({'etag': nuevo_etag, 'last_modified': nuevo_lm}, ensure_ascii=False))
    except OSError:
        LOG.exception('no se pudo guardar la caché de %s', id_lista)
    return texto, False, None


# ─────────────────────── validación y activación en dnsmasq ────────────────

def _dnsmasq_esta_activo(reintentos=3, espera=0.3):
    """BAJA12: 'active' SÍ, pero también 'activating'/'reloading' —
    sistemd puede reportar esos estados un instante tras un SIGHUP/start
    sin que sea un fallo real; tratarlos como caída dispara un oplog falso
    y un restart innecesario. Reintenta un par de veces (systemd tarda un
    pelín en reflejar el nuevo estado tras el kill -HUP).

    M4 (ronda 3): esto por sí solo NO basta para confirmar que dnsmasq
    recogió la config nueva de verdad — sólo dice que el PROCESO sigue
    vivo. Ver `_consulta_dns_centinela` para la comprobación funcional
    real que se hace ADEMÁS de esto."""
    for intento in range(reintentos):
        try:
            r = subprocess.run(['systemctl', 'is-active', 'dnsmasq'], capture_output=True, text=True, timeout=10)
        except Exception:
            return False
        if r.stdout.strip() in ('active', 'activating', 'reloading'):
            return True
        if intento < reintentos - 1:
            time.sleep(espera)
    return False


def _consulta_dns_cruda(dominio, servidor, puerto, timeout):
    """Una única consulta UDP cruda (sin pasar por el resolver de Python)
    por `dominio` tipo A. Devuelve el RCODE (0-15) de la respuesta, o None
    si no hubo respuesta/la cabecera no encaja. Nunca lanza."""
    qid = random.randint(0, 65535)
    cabecera = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    pregunta = (b''.join(struct.pack('B', len(e)) + e.encode() for e in dominio.split('.'))
                + b'\x00' + struct.pack('>HH', 1, 1))
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(cabecera + pregunta, (servidor, puerto))
        datos, _ = s.recvfrom(512)
        if len(datos) >= 4 and datos[0:2] == cabecera[0:2]:
            return datos[3] & 0x0f
    except OSError:
        pass
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
    return None


def _consulta_dns_centinela(centinela, servidor='127.0.0.1', puerto=53, timeout_total_s=20, intentos=3):
    """M1 (ronda 4): comprobación FUNCIONAL real tras el SIGHUP — pregunta
    DE VERDAD al dnsmasq local por el centinela DE ESTA GENERACIÓN
    (`centinela_de_generacion(hash)`, ver `generar`) y exige NXDOMAIN.
    Mucho más de fiar que 'systemctl is-active' (que sólo demuestra que el
    PROCESO sigue vivo) Y que un centinela FIJO (que no distinguiría
    "ya cargó la config nueva" de "sigue con la vieja" si ambas lo
    bloquean igual): NXDOMAIN para ESTE hash en concreto sólo puede venir
    de la generación que lo incluye; si dnsmasq sigue con la anterior, cae
    al `address=.../127.0.0.9` genérico de dnsmasq_conf.py.

    Reintenta durante hasta `timeout_total_s` (por defecto 20 s — un
    servers-file de 1,5 millones de líneas puede tardar unos segundos en
    terminar de leerse tras el SIGHUP, sobre todo en una portátil modesta).
    Socket UDP crudo. Nunca lanza."""
    inicio = time.monotonic()
    timeout_por_intento = max(1, timeout_total_s / max(1, intentos))
    for intento in range(intentos):
        restante = timeout_total_s - (time.monotonic() - inicio)
        if restante <= 0:
            break
        rcode = _consulta_dns_cruda(centinela, servidor, puerto, timeout=min(timeout_por_intento, restante))
        if rcode == 3:
            return True
        if intento < intentos - 1:
            time.sleep(min(0.5, max(0.0, timeout_total_s - (time.monotonic() - inicio))))
    return False


_AVISADOS_PERMISOS = set()   # BAJA2 (ronda 4): un aviso por ruta, nunca uno por ciclo


def _asegurar_legible_por_dnsmasq(ruta):
    """M4 (ronda 3): dnsmasq corre con --user=dnsmasq (uid ajeno a root):
    necesita 'x' en TODOS los directorios padres de `ruta` para poder
    atravesarlos, y 'r' en el propio fichero (para "otros", o para el
    grupo de dnsmasq si existe) — si falta cualquiera de los dos,
    `open()` le falla aunque el fichero en sí ya sea 0644. Se CORRIGE (no
    sólo se avisa). Nunca lanza (H5); cualquier fallo se registra una
    vez y se sigue (mejor intentarlo que no arrancar).

    BAJA2 (ronda 4):
    - A los directorios sólo se les da el bit de EJECUCIÓN para "otros"
      (0o001 — "atravesar", lo mínimo que hace falta para que dnsmasq
      pueda bajar por el camino), nunca 0o755 entero — eso daría además
      lectura y listado del directorio a cualquiera, que no hace falta
      para nada aquí.
    - Si el chmod falla (sistema de ficheros de sólo lectura, permiso
      denegado...), se avisa COMO MUCHO una vez por ruta (nunca en cada
      ciclo del timer) — y, antes de avisar, se comprueba con
      `os.access()` si el problema sigue siendo real: podría ya estar
      bien por otra vía (p. ej. el instalador dejó el bit puesto de
      antemano, y lo que falló fue sólo el propio chmod, no el acceso en
      sí). NOTA: `os.access()` aquí es sólo un best-effort de cara al
      AVISO, nunca la fuente de verdad de si dnsmasq (un uid distinto)
      podrá leer esto — un proceso privilegiado (root) puede ver más
      acceso del que tendría dnsmasq de verdad (man 2 access, regla para
      procesos con UID real 0); la fuente de verdad sigue siendo la
      comprobación de bits de más abajo, que es la que decide si hace
      falta el chmod en absoluto.
    - En producción, lo correcto es que el INSTALADOR deje los permisos
      bien desde el principio (esta función es sólo un respaldo en
      caliente, no el sitio donde debería decidirse la política de
      permisos del paquete)."""
    try:
        gid_dnsmasq = grp.getgrnam('dnsmasq').gr_gid
    except KeyError:
        gid_dnsmasq = None
    partes = ruta.split('/')
    actual = ''
    for parte in partes[1:-1]:
        actual += '/' + parte
        try:
            st = os.stat(actual)
        except OSError:
            continue
        if stat.S_IMODE(st.st_mode) & 0o001:   # ya atravesable por "otros": nada que hacer
            continue
        try:
            os.chmod(actual, stat.S_IMODE(st.st_mode) | 0o001)
        except OSError:
            if actual not in _AVISADOS_PERMISOS and not os.access(actual, os.X_OK):
                LOG.exception('no se pudo corregir los permisos de %s (dnsmasq podría no poder '
                               'atravesar este directorio) — el instalador debería dejar los '
                               'permisos correctos desde el principio', actual)
            _AVISADOS_PERMISOS.add(actual)
    try:
        st = os.stat(ruta)
    except OSError:
        return
    modo = stat.S_IMODE(st.st_mode)
    legible = bool(modo & 0o004) or (gid_dnsmasq is not None and st.st_gid == gid_dnsmasq and bool(modo & 0o040))
    if legible:
        return
    try:
        os.chmod(ruta, modo | 0o004)
    except OSError:
        if ruta not in _AVISADOS_PERMISOS and not os.access(ruta, os.R_OK):
            LOG.exception('no se pudo corregir los permisos de %s (dnsmasq podría no poder leerlo) '
                           '— el instalador debería dejar los permisos correctos desde el principio', ruta)
        _AVISADOS_PERMISOS.add(ruta)


def _huella(ruta):
    """M2 (ronda 3): (ino, tamaño, mtime_ns) de `ruta`, o None si no
    existe. Se guarda junto al hash para detectar si ALGUIEN AJENO (p. ej.
    routerd vaciando el fichero en fail-open) tocó el fichero activo desde
    la última vez que ESTE módulo lo escribió — un hash de CONTENIDO por
    sí solo no lo distingue (si el contenido nuevo "coincide por casualidad"
    con un hash viejo guardado, activaría el camino de "sin cambios" sobre
    un fichero que en realidad otro proceso puso ahí)."""
    try:
        st = os.stat(ruta)
    except OSError:
        return None
    return {'ino': st.st_ino, 'size': st.st_size, 'mtime_ns': st.st_mtime_ns}


def _validar_servers_file(tmp):
    """M4 (ronda 3): dos validaciones distintas, complementarias —
    comprobado empíricamente que son necesarias las DOS:
    - `--conf-file=<tmp>` directamente: las líneas `server=` son válidas
      TAMBIÉN fuera de un servers-file, y esta validación SÍ es estricta
      (rechaza basura real: "opción errónea at line N").
    - `--conf-file=<stub con servers-file=tmp>`: confirma que dnsmasq
      ACEPTA de verdad el fichero como servers-file (ese parser es mucho
      más laxo con el contenido — no basta por sí solo para detectar
      basura, por eso se hace TAMBIÉN la de arriba).
    Devuelve (ok, mensaje_error_o_cadena_vacia)."""
    stub = tmp + '.stub'
    try:
        r1 = subprocess.run(['dnsmasq', '--test', '--conf-file=' + tmp],
                             capture_output=True, text=True, timeout=30)
        with open(stub, 'w') as f:
            f.write('servers-file=%s\n' % tmp)
        r2 = subprocess.run(['dnsmasq', '--test', '--conf-file=' + stub],
                             capture_output=True, text=True, timeout=30)
    finally:
        try:
            os.unlink(stub)
        except OSError:
            pass
    if r1.returncode != 0:
        return False, (r1.stderr or r1.stdout).strip()
    if r2.returncode != 0:
        return False, (r2.stderr or r2.stdout).strip()
    return True, ''


def _validar_y_activar(conf_nueva, rutas, gestionar_dnsmasq, habilitado=True, centinela=None):
    """Escribe `conf_nueva` en un TEMPORAL, la valida con `dnsmasq --test`
    DOS veces (`_validar_servers_file` — M4) y SÓLO entonces la activa. Si
    el contenido es IDÉNTICO al ya activo Y el fichero activo no ha
    cambiado por fuera desde la última vez que este módulo lo escribió
    (hash + huella ino/tamaño/mtime — M2: así no se confunde con un
    fichero que, por ejemplo, routerd vació en fail-open), no hace nada.
    Activa con DOS renames atómicos (mover el actual a `.anterior`, luego
    el nuevo a su sitio): nunca lee el contenido anterior en memoria sólo
    para poder restaurarlo — restaurar es, de nuevo, un rename.

    M2: la activación es un `systemctl kill -s HUP dnsmasq` (nunca un
    restart completo — un servers-file se relee con SIGHUP, comprobado
    empíricamente; así nunca se corta el DHCP). M1/M4: tras el SIGHUP, NO
    se confía sólo en `systemctl is-active` — se exige además una
    respuesta NXDOMAIN de verdad a una consulta DNS real por el
    `centinela` DE ESTA GENERACIÓN (si se pasa uno Y `habilitado`). Si
    cualquiera de las dos comprobaciones falla, se restaura lo anterior;
    si eso también falla (BAJA1/BAJA2/M6), se deja el fichero VACÍO en vez
    de a medias o borrado — routerd lo referencia siempre, nunca debe
    faltar.

    Devuelve (ok: bool, mensaje: str)."""
    destino = rutas['dnsmasq_bloqueo']
    ruta_hash = destino + '.hash'
    hash_nuevo = hashlib.sha256(conf_nueva.encode('utf-8')).hexdigest()
    meta_hash = None
    try:
        with open(ruta_hash) as f:
            meta_hash = json.load(f)
    except (OSError, ValueError):
        meta_hash = None
    huella_actual = _huella(destino)
    if (isinstance(meta_hash, dict) and meta_hash.get('hash') == hash_nuevo and huella_actual is not None
            and all(meta_hash.get(k) == huella_actual.get(k) for k in ('ino', 'size', 'mtime_ns'))):
        return True, 'sin cambios (mismo contenido que la pasada anterior)'

    d = os.path.dirname(destino)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-bloqueo-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(conf_nueva)
            f.flush()
            os.fsync(f.fileno())
        valido, error = _validar_servers_file(tmp)
    except Exception as e:   # BAJA1: nunca debe poder lanzar hacia arriba
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False, 'no se pudo validar la nueva config: %s' % e
    if not valido:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False, 'servers-file no válido, se mantiene el anterior: %s' % error

    os.chmod(tmp, 0o644)
    anterior_bak = destino + '.anterior'
    habia_anterior = os.path.exists(destino)
    if habia_anterior:
        try:
            os.replace(destino, anterior_bak)
        except OSError:
            habia_anterior = False
    os.replace(tmp, destino)
    _asegurar_legible_por_dnsmasq(destino)   # M4: antes del HUP, nunca después
    try:
        huella_nueva = _huella(destino) or {}
        escribir_atomico(ruta_hash, json.dumps(dict(huella_nueva, hash=hash_nuevo), ensure_ascii=False))
    except OSError:
        LOG.exception('no se pudo guardar %s', ruta_hash)

    if not gestionar_dnsmasq:
        # Pruebas en netns (mismo escape que routerd: 'gestionar_dnsmasq').
        if habia_anterior:
            try:
                os.unlink(anterior_bak)
            except OSError:
                pass
        return True, 'config preparada (dnsmasq no se gestiona en este entorno)'

    try:
        subprocess.run(['systemctl', 'kill', '-s', 'HUP', 'dnsmasq'], capture_output=True, timeout=10)
    except Exception:   # BAJA1
        LOG.exception('no se pudo enviar SIGHUP a dnsmasq')

    confirmado = _dnsmasq_esta_activo()
    if confirmado and habilitado and centinela:
        # M1/M4: "is-active" no demuestra que recogiera la config NUEVA —
        # sólo la consulta DNS real al centinela DE ESTA GENERACIÓN lo
        # demuestra (NXDOMAIN = cargada; 127.0.0.9 = sigue la anterior).
        confirmado = _consulta_dns_centinela(centinela)
    if confirmado:
        if habia_anterior:
            try:
                os.unlink(anterior_bak)
            except OSError:
                pass
        return True, 'ok'

    # No confirmado (ni "activo", ni, si tocaba, el centinela): se
    # restaura lo anterior (otro rename, nunca se leyó su contenido) o, si
    # no había nada que restaurar o restaurarlo también falla, se deja
    # VACÍO (M6/BAJA2): nunca a medias, nunca sin fichero — routerd lo
    # referencia siempre.
    try:
        if not habia_anterior:
            raise OSError('no había una config anterior que restaurar')
        os.replace(anterior_bak, destino)
        try:
            os.unlink(ruta_hash)   # el hash/huella guardados ya no corresponden al fichero activo
        except OSError:
            pass
        subprocess.run(['systemctl', 'kill', '-s', 'HUP', 'dnsmasq'], capture_output=True, timeout=10)
        return False, 'dnsmasq no confirmó la config nueva: se ha restaurado la config anterior'
    except Exception:   # BAJA1
        LOG.exception('no se pudo restaurar la config anterior de bloqueo')
        try:
            escribir_atomico(destino, generar_servers_file(set(), set()))
            os.unlink(ruta_hash)
        except OSError:
            pass
        try:
            subprocess.run(['systemctl', 'kill', '-s', 'HUP', 'dnsmasq'], capture_output=True, timeout=10)
        except Exception:
            LOG.exception('no se pudo ni dejar vacía la config de bloqueo')
        return False, ('dnsmasq no confirmó la config nueva; tampoco se pudo restaurar la '
                        'config anterior: se ha dejado vacía')


# ────────────────────────────── orquestación ───────────────────────────────

def _ruta_ultimo(rutas):
    return os.path.join(rutas['cache_dir'], '.ultimo.json')


MINIMO_GUARDA_VARIACION = 1000


def _leer_ultimo(rutas):
    try:
        with open(_ruta_ultimo(rutas)) as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get('total'), int) and isinstance(d.get('listas'), list):
            return d
    except (OSError, ValueError):
        pass
    return None


def _guardar_ultimo(rutas, total, ids):
    try:
        escribir_atomico(_ruta_ultimo(rutas), json.dumps({'total': total, 'listas': sorted(ids)}, ensure_ascii=False))
    except OSError:
        LOG.exception('no se pudo guardar %s', _ruta_ultimo(rutas))


# BAJA4: seguimiento de "pasadas consecutivas con un total parecido pero
# que dispararían la guarda ±50%" — si se repite 3 veces, probablemente no
# sea una lista rota puntual sino un cambio real (HaGeZi reestructuró una
# lista grande), y se acepta en vez de bloquear la actualización para
# siempre.
def _ruta_variacion_pendiente(rutas):
    return os.path.join(rutas['cache_dir'], '.variacion_pendiente.json')


def _leer_variacion_pendiente(rutas):
    try:
        with open(_ruta_variacion_pendiente(rutas)) as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get('total'), int) and isinstance(d.get('veces'), int):
            return d
    except (OSError, ValueError):
        pass
    return None


def _guardar_variacion_pendiente(rutas, total, veces):
    try:
        escribir_atomico(_ruta_variacion_pendiente(rutas),
                         json.dumps({'total': total, 'veces': veces}, ensure_ascii=False))
    except OSError:
        LOG.exception('no se pudo guardar %s', _ruta_variacion_pendiente(rutas))


def _borrar_variacion_pendiente(rutas):
    try:
        os.unlink(_ruta_variacion_pendiente(rutas))
    except OSError:
        pass


def generar(cfg_bloqueo, rutas, forzar=False):
    """Hace todo el trabajo de UNA pasada: descarga/parsea cada lista
    habilitada, construye el conjunto final de dominios bloqueados, genera
    y valida el servers-file, lo activa, y publica el estado. Nunca lanza
    — cualquier fallo queda en el resultado/estado, nunca tira el proceso.

    `forzar=True` (BAJA4 — acción de buzón `bloqueo_actualizar` con
    `{"forzar": true}`): se SALTA la guarda de variación ±50% para esta
    pasada (el admin pide explícitamente aplicar lo que haya, pase lo que
    pase) — el resultado, si tiene éxito, se convierte en la nueva línea
    base para la próxima comparación.

    Devuelve (ok, mensaje, estado_dict)."""
    os.makedirs(rutas['cache_dir'], exist_ok=True)
    habilitado = bool(cfg_bloqueo.get('habilitado', True))
    ids = list(dict.fromkeys(cfg_bloqueo.get('listas') or []))   # sin duplicados, orden estable
    if cfg_bloqueo.get('bloquear_doh') and 'hagezi_doh' not in ids:
        ids.append('hagezi_doh')

    resultado_listas = []
    dominios = set()
    total_listas = 0
    recortado_global = False
    if habilitado:
        for id_lista in ids:
            info = CATALOGO.get(id_lista)
            if info is None:
                resultado_listas.append({'id': id_lista, 'nombre': id_lista, 'dominios': 0,
                                          'actualizada': None, 'error': 'id de catálogo desconocido'})
                continue
            # Las líneas móviles a veces se quedan "colgadas" a mitad de una
            # descarga grande (visto en producción con la de 34 MB): cada
            # reintento abre una conexión nueva, que el balanceo puede mandar
            # por otra línea.
            for intento in range(INTENTOS_DESCARGA):
                texto, de_cache, error = descargar_lista(id_lista, info['url'], rutas)
                if error is None or intento == INTENTOS_DESCARGA - 1:
                    break
                LOG.warning('descarga de %s fallida (%s): reintento %d de %d',
                            id_lista, error, intento + 2, INTENTOS_DESCARGA)
            if texto is None:
                resultado_listas.append({'id': id_lista, 'nombre': info['nombre'], 'dominios': 0,
                                          'actualizada': None, 'error': error or 'sin datos'})
                continue
            parciales = parsear_lista(texto)
            dominios |= parciales
            resultado_listas.append({
                'id': id_lista, 'nombre': info['nombre'], 'dominios': len(parciales),
                'actualizada': ahora_iso(),
                'error': ('caché anterior: %s' % error) if (de_cache and error) else None,
            })
        # M4: cota GLOBAL (no por lista) — truncado determinista (orden
        # alfabético), nunca "lo que caiga primero del set desordenado".
        if len(dominios) > LIMITE_DOMINIOS_TOTAL:
            dominios = set(sorted(dominios)[:LIMITE_DOMINIOS_TOTAL])
            recortado_global = True
        # La guarda de variación compara SOLO lo descargado: cambiar la
        # lista blanca o negra es una decisión del usuario, no una lista rota.
        total_listas = len(dominios)
        for cruda in cfg_bloqueo.get('lista_negra') or []:
            n = normalizar_dominio(cruda)
            if n and not es_sufijo_publico(n):   # M5: defensa en profundidad (peticiones.py ya lo valida)
                dominios.add(n)
        protegidos = _dominios_protegidos(cfg_bloqueo.get('_dominio_casa'))
        dominios = aplicar_lista_blanca(dominios, protegidos)   # M5: nunca bloqueables
        dominios = aplicar_lista_blanca(dominios, cfg_bloqueo.get('lista_blanca') or [])

    # M5: guarda de variación — si las listas elegidas son las MISMAS que
    # la última pasada con éxito y el total cambia más de un ±50%, algo
    # huele mal (una lista rota devolviendo basura, un recorte de red a
    # medias que coló...); se aborta SIN TOCAR NADA de lo ya activo.
    # BAJA4: salvo que `forzar` lo salte, o que ya lleve 3 pasadas
    # consecutivas con un total aproximadamente igual (entonces se acepta:
    # probablemente sea un cambio real, no un bache puntual).
    ids_ordenados = sorted(ids)
    ultimo = _leer_ultimo(rutas)
    # Por debajo de MINIMO_GUARDA_VARIACION dominios la proporción no
    # significa nada (una lista de 2 que pasa a 1 ya es un 50%).
    if (not forzar and habilitado and ultimo and ultimo.get('listas') == ids_ordenados
            and ultimo.get('total', 0) >= MINIMO_GUARDA_VARIACION):
        variacion = abs(total_listas - ultimo['total']) / ultimo['total']
        if variacion > 0.5:
            pendiente = _leer_variacion_pendiente(rutas)
            aproximado = (pendiente is not None
                          and abs(total_listas - pendiente['total']) <= max(1, 0.02 * pendiente['total']))
            veces = (pendiente['veces'] + 1) if aproximado else 1
            if veces >= 3:
                LOG.info('el total bloqueado lleva %d pasadas consecutivas en ~%d: se acepta como '
                         'cambio real (no se aborta)', veces, total_listas)
                _borrar_variacion_pendiente(rutas)
                # sigue adelante con normalidad (no se aborta esta pasada)
            else:
                _guardar_variacion_pendiente(rutas, total_listas, veces)
                msg = ('el total de dominios bloqueados varía más de un 50%% respecto a la última '
                       'pasada (%d → %d) sin haber cambiado las listas elegidas: se mantiene la '
                       'config anterior por seguridad (podría ser una lista rota; se aceptará sola '
                       'si se repite 3 veces, o con bloqueo_actualizar {"forzar": true})'
                       % (ultimo['total'], total_listas))
                LOG.error(msg)
                estado = {'habilitado': habilitado, 'listas': resultado_listas, 'total_dominios': len(dominios),
                          'generado': ahora_iso(), 'siguiente': _calcular_siguiente(cfg_bloqueo),
                          'activo': False, 'error': msg}
                try:
                    escribir_atomico(rutas['estado'], json.dumps(estado, ensure_ascii=False, indent=1))
                except OSError:
                    LOG.exception('no se pudo publicar %s', rutas['estado'])
                return False, msg, estado
        else:
            _borrar_variacion_pendiente(rutas)   # ya no hay una variación grande pendiente de confirmar
    elif forzar:
        _borrar_variacion_pendiente(rutas)

    excepciones = (cfg_bloqueo.get('lista_blanca') or []) if habilitado else []
    excepciones_norm = {d for d in (normalizar_dominio(x) for x in excepciones) if d}
    protegidos_norm = _dominios_protegidos(cfg_bloqueo.get('_dominio_casa')) if habilitado else frozenset()
    if habilitado and cfg_bloqueo.get('bloquear_doh'):
        dominios.add(CANARIO_DOH)
    # M1 (ronda 4): centinela POR GENERACIÓN — su nombre depende del
    # contenido REAL de esta pasada (dominios + excepciones), calculado
    # ANTES de añadirlo él mismo (si no, el hash dependería de sí mismo).
    centinela = None
    if habilitado:
        huella_generacion = hashlib.sha256(
            ('\n'.join(sorted(dominios)) + '|' + '\n'.join(sorted(excepciones_norm | protegidos_norm)))
            .encode('utf-8')
        ).hexdigest()
        centinela = centinela_de_generacion(huella_generacion)
        dominios.add(centinela)
    texto = generar_servers_file(dominios, excepciones_norm | protegidos_norm)
    ok, msg = _validar_y_activar(texto, rutas, cfg_bloqueo.get('_gestionar_dnsmasq', True), habilitado, centinela)
    if ok and habilitado:
        _guardar_ultimo(rutas, total_listas, ids)
    if recortado_global:
        msg = (msg + ' — AVISO: el total de dominios superó %d y se ha recortado'
               % LIMITE_DOMINIOS_TOTAL)

    estado = {
        'habilitado': habilitado,
        'listas': resultado_listas,
        'total_dominios': len(dominios),
        'generado': ahora_iso(),
        'siguiente': _calcular_siguiente(cfg_bloqueo),
        'activo': ok,
    }
    if recortado_global:
        estado['recortado'] = True
    if not ok:
        estado['error'] = msg
    try:
        escribir_atomico(rutas['estado'], json.dumps(estado, ensure_ascii=False, indent=1))
    except OSError:
        LOG.exception('no se pudo publicar %s', rutas['estado'])
    return ok, msg, estado


def _calcular_siguiente(cfg_bloqueo):
    try:
        horas = max(6, min(168, int(cfg_bloqueo.get('actualizar_h', 24))))
        return (datetime.now(timezone.utc) + timedelta(hours=horas)).isoformat(timespec='seconds')
    except (TypeError, ValueError):
        return None


# ───────────────────────── consulta sin red (bloqueo_probar) ───────────────

def _linea_a_dominio_rapido(linea):
    """Versión LIGERA de normalizar_dominio para escanear cachés grandes
    en una consulta puntual (bloqueo_probar): sólo quita comentarios/
    blancos y pasa a minúsculas — la validación estricta ya se hizo al
    GENERAR la config; aquí sólo se busca una coincidencia."""
    s = linea.strip()
    if not s or s[0] == '#':
        return None
    return s.lower()


def _dominio_en_cache(sufijos, ruta_cache):
    """¿Alguno de `sufijos` aparece en el fichero de caché de una lista?
    Streaming (nunca carga el fichero entero en memoria): basta para una
    consulta puntual, no se repite en cada ciclo."""
    try:
        with open(ruta_cache, 'r', encoding='utf-8', errors='replace') as f:
            for linea in f:
                d = _linea_a_dominio_rapido(linea)
                if d and d in sufijos:
                    return True
    except OSError:
        return False
    return False


def comprobar_dominio(dominio_crudo, cfg, rutas):
    """¿Bloquearía el router este dominio ahora mismo? Consulta SÓLO lo ya
    generado/cacheado en disco (nunca hace una petición de red).

    M1: "decir la verdad" significa seguir EXACTAMENTE el mismo criterio
    que dnsmasq aplicaría de verdad con el servers-file (coincidencia MÁS
    ESPECÍFICA gana, sin importar de qué "categoría" venga) — por eso se
    recorren los sufijos del dominio del MÁS al MENOS específico y, en
    cada nivel, se comprueba protegido → lista negra → lista blanca →
    catálogo, devolviendo en el primer acierto. Un dominio protegido (M5)
    siempre gana, incluso si coincide exactamente con una entrada de
    lista_negra (un error del admin no debe poder desproteger algo que el
    propio router necesita).

    Devuelve {'bloqueado': bool, 'razon': str, 'lista': str|None}."""
    dominio = normalizar_dominio(dominio_crudo)
    if dominio is None:
        return {'bloqueado': False, 'razon': 'no es un nombre de dominio válido', 'lista': None}
    bloqueo = dict(DEFECTO_BLOQUEO, **(cfg.get('bloqueo') or {}))
    sufijos = _sufijos(dominio)   # del más al menos específico

    protegidos = _dominios_protegidos(cfg.get('dominio'))
    negra = {d for d in (normalizar_dominio(x) for x in (bloqueo.get('lista_negra') or [])) if d}
    blanca = {d for d in (normalizar_dominio(x) for x in (bloqueo.get('lista_blanca') or [])) if d}

    habilitado = bool(bloqueo.get('habilitado', True))
    bloquear_doh = bool(bloqueo.get('bloquear_doh'))

    # BAJA8: sólo ids que de verdad están en el catálogo (nunca se intenta
    # abrir una caché para un id inventado/obsoleto).
    ids = [i for i in dict.fromkeys(bloqueo.get('listas') or []) if i in CATALOGO]
    if bloquear_doh and 'hagezi_doh' not in ids and 'hagezi_doh' in CATALOGO:
        ids.append('hagezi_doh')
    cache_dir = rutas.get('cache_dir', RUTAS['cache_dir'])

    # Primera pasada: protegido es un VETO ABSOLUTO — gana en cualquier
    # nivel de especificidad, no sólo cuando coincide al mismo nivel que
    # una entrada de lista_negra. Así se refleja lo que generar() hace de
    # verdad: aplicar_lista_blanca(dominios, protegidos) quita del
    # conjunto bloqueado cualquier protegido O SUBDOMINIO SUYO, incluso si
    # llegó ahí vía lista_negra — una entrada negra más específica que el
    # ancestro protegido NO debe poder "ganarle" por especificidad.
    for s in sufijos:
        if s in protegidos:
            return {'bloqueado': False, 'razon': 'es un dominio protegido (necesario para el propio router)',
                    'lista': 'protegido'}

    # Segunda pasada: entre negra/blanca/canario, sí gana el más
    # específico (igual que dnsmasq con server=/.../ vs server=/.../#).
    for s in sufijos:
        if s in negra:
            return {'bloqueado': True, 'razon': 'está en la lista negra manual', 'lista': 'lista_negra'}
        if s in blanca:
            return {'bloqueado': False, 'razon': 'está en la lista blanca manual', 'lista': 'lista_blanca'}
        if habilitado and bloquear_doh and s == CANARIO_DOH:
            return {'bloqueado': True, 'razon': 'canario de DNS-over-HTTPS (bloquear_doh activo)',
                    'lista': 'canario_doh'}

    if not habilitado:
        return {'bloqueado': False, 'razon': 'el bloqueo está desactivado', 'lista': None}

    sufijos_set = set(sufijos)
    for id_lista in ids:
        ruta_cache = os.path.join(cache_dir, '%s.txt' % id_lista)
        if _dominio_en_cache(sufijos_set, ruta_cache):
            nombre = CATALOGO.get(id_lista, {}).get('nombre', id_lista)
            return {'bloqueado': True, 'razon': 'está en la lista «%s»' % nombre, 'lista': id_lista}

    return {'bloqueado': False, 'razon': 'no aparece en ninguna lista activa', 'lista': None}


# ───────────────────────────────── main ────────────────────────────────────

def _ruta_marcador_forzar(rutas):
    return os.path.join(rutas['cache_dir'], '.forzar')


def _leer_y_borrar_marcador_forzar(rutas):
    """BAJA4: `bloqueo_actualizar {"forzar": true}` deja este marcador
    (routerd, ver _ejecutar_accion_bloqueo) ANTES de lanzar el servicio.
    Se lee y se borra SIEMPRE aquí, de una sola vez — nunca debe poder
    quedar forzando pasadas futuras indefinidamente."""
    ruta = _ruta_marcador_forzar(rutas)
    existe = os.path.exists(ruta)
    if existe:
        try:
            os.unlink(ruta)
        except OSError:
            LOG.exception('no se pudo borrar el marcador de forzado %s', ruta)
    return existe


def _barrer_temporales_viejos(cache_dir, limite_s=3600):
    """BAJA5: al arrancar, barre temporales huérfanos de una pasada
    anterior que no llegó a terminar (routerd/systemd mató el proceso a
    mitad, un corte de luz...) — `.tmp-bloqueo-*` (de `_validar_y_activar`)
    y `*.stub` (de `_validar_servers_file`), de más de `limite_s` (1 hora
    por defecto). Nunca lanza; nunca toca nada más reciente que eso (una
    pasada CONCURRENTE de verdad no debería poder darse — router-bloqueo
    es oneshot — pero por si acaso)."""
    try:
        nombres = os.listdir(cache_dir)
    except OSError:
        return
    limite = time.time() - limite_s
    for nombre in nombres:
        if not (nombre.startswith('.tmp-bloqueo-') or nombre.endswith('.stub')):
            continue
        ruta = os.path.join(cache_dir, nombre)
        try:
            if os.stat(ruta).st_mtime < limite:
                os.unlink(ruta)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', default=RUTAS['config'])
    ap.add_argument('--fase', default=RUTAS['fase'])
    ap.add_argument('--raiz-datos', help='prefijo para todas las rutas de datos (pruebas)')
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', stream=sys.stdout)
    rutas = dict(RUTAS, config=a.config, fase=a.fase)
    if a.raiz_datos:
        for k in ('cache_dir', 'dnsmasq_bloqueo', 'estado', 'oplog'):
            rutas[k] = os.path.join(a.raiz_datos, rutas[k].lstrip('/'))

    # BAJA3: fuera de producción, no se toca nada (ni siquiera se
    # descarga) — igual que routerd mientras la portátil sigue vigilando
    # la migración.
    fase = _fase_efectiva(rutas['fase'], rutas['config'])
    if fase != 'produccion':
        LOG.info('fase=%s: el bloqueador DNS no hace nada fuera de producción', fase)
        return 0

    os.makedirs(rutas['cache_dir'], exist_ok=True)
    _barrer_temporales_viejos(rutas['cache_dir'])
    forzar = _leer_y_borrar_marcador_forzar(rutas)
    if forzar:
        LOG.info('bloqueo_actualizar con forzar=true: se salta la guarda de variación ±50%% esta pasada')

    # M3: si la sección 'bloqueo' de router.json cambia MIENTRAS esta
    # pasada estaba en marcha (el buzón, vía routerd, puede haber aplicado
    # un bloqueo_config/bloqueo_lista nuevo durante una descarga larga), se
    # repite la pasada entera — hasta 3 veces.
    ok, msg, estado = False, 'sin ejecutar', {}
    for intento in range(1, 4):
        hash_antes = _hash_bloqueo(rutas['config'])
        cfg_bloqueo = leer_config_bloqueo(rutas['config'])
        ok, msg, estado = generar(cfg_bloqueo, rutas, forzar=forzar)
        hash_despues = _hash_bloqueo(rutas['config'])
        if hash_antes is None or hash_despues is None or hash_antes == hash_despues:
            break
        LOG.info('la configuración de bloqueo cambió durante la pasada (intento %d/3): se repite', intento)

    escribir_oplog(rutas['oplog'], 'sistema', 'bloqueo_actualizado',
                    {'total_dominios': estado.get('total_dominios')}, ok, msg)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
