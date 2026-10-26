#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""routerd — núcleo de un router doméstico multi-WAN (Debian 13, root).

Qué hace, en un bucle de unos segundos:

1. Descubre las WAN: interfaces de tethering USB de los teléfonos (drivers
   rndis_host / cdc_ncm / cdc_ether / ipheth). El nombre de la interfaz cambia
   (usb0, enx…): la identidad estable de una WAN es el NÚMERO DE SERIE USB del
   teléfono, y si no lo hay, el nombre de la interfaz.
2. Para cada WAN con IP y gateway (los pone NetworkManager por DHCP del
   teléfono) mantiene su tabla de rutas propia y sus reglas:
       ip rule fwmark <marca> lookup <tabla>     (tráfico de la LAN balanceado)
       ip rule from <ip-de-la-wan> lookup <tabla> (respuestas y comprobaciones)
3. Comprueba Internet DE VERDAD por cada WAN (ping marcado con la marca de esa
   WAN a destinos públicos), con histéresis: cae tras N fallos seguidos y
   vuelve tras M éxitos. Detectar el USB no es tener Internet.
4. Decide qué WAN entran en el balanceo (habilitada + con Internet; en modo
   «respaldo», sólo la de mejor prioridad que funcione) y reescribe la cadena
   nftables `elegir_wan` con un mapa de pesos (numgen) de forma atómica. La
   marca se guarda en conntrack: una conexión no cambia de WAN a mitad.
5. Publica /run/router/estado.json para el panel y atiende el buzón de
   peticiones del panel (validación estricta; nunca shell). Ver docs/CONTRATO.md.

Fases (N1: /etc/router/fase — SU PROPIO fichero, no router.json; routerd lo
LEE en cada ciclo pero nunca lo escribe, sólo lo escribe router_migrar; si no
existe, se usa la "fase" de router.json por compatibilidad con instalaciones
viejas, y si tampoco hay eso, "preparacion"):
  - "preparacion": SÓLO observa (descubre, comprueba, publica estado). No toca
    nftables, ni dnsmasq, ni reglas de rutas. Es la fase segura para poner el
    routerd en marcha sin cambiar la red que ya funciona: no puede cortar el
    acceso por el que se administra la máquina.
  - "produccion": instala las tablas nftables del router, las rutas por WAN y
    gestiona dnsmasq. Se pasa a esta fase sólo en la migración.

Uso:  routerd.py [--config /etc/router/router.json] [--fase /etc/router/fase]
                  [--una-vez]
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timezone

LOG = logging.getLogger('routerd')

DRIVERS_TETHER = {'rndis_host', 'cdc_ncm', 'cdc_ether', 'ipheth', 'cdc_mbim'}
TABLA_BASE = 100          # tabla de rutas de la WAN n = 100 + n (n = 1..)
MARCA_BASE = 0x100        # marca de la WAN n = 0x100 + n
PRIO_REGLA_MARCA = 1000   # prioridad de las ip rule fwmark
PRIO_REGLA_ORIGEN = 1100  # prioridad de las ip rule from
USUARIO_PANEL = 'routerpanel'   # propietario esperado de las peticiones del buzón (H4)

# HIGH-A (segunda revisión Opus 2026-10-12): el vaciado de conntrack de las
# reglas firewall no puede ser combinatorio (origenes x protos x destinos x
# puertos) ni acercarse al watchdog de 60 s del ciclo (WatchdogSec=60).
# Se agrupa en el mínimo de llamadas (una por origen y protocolo, con
# rangos de puertos) y, aun así, hay un TOPE de llamadas por ciclo y un
# presupuesto de tiempo total. Si se supera el tope, el vaciado cae a uno
# más grueso por origen (sin proto/puerto/destino) y se avisa en el log.
MAX_CONNTRACK_LLAMADAS_CICLO = 32
MAX_CONNTRACK_SEGUNDOS = 3.0
MAX_CONNTRACK_TIMEOUT_S = 2

CONFIG_DEFECTO = {
    # N1: la fase ya NO vive aquí, sino en su propio fichero
    # (/etc/router/fase, ver RUTAS['fase'] y Router._fase_efectiva()). Se
    # sigue aceptando "fase" en un router.json leído de disco sólo por
    # compatibilidad (instalaciones viejas), nunca se pone aquí por defecto.
    'modo': 'balanceo',
    # Fase 4 (A): "auto" calcula el peso de cada WAN solo con lo que ya se
    # mide (latencia/pérdida — H2: la capacidad NO entra en el cálculo, ver
    # puntuacion_calidad()); "manual" usa el "peso" que pone el admin en
    # cada WAN, igual que antes de esta fase.
    'modo_pesos': 'auto',
    # La LAN donde vive el router. Para equipos con IP fija fuera del rango
    # DHCP (192.168.50.100-192.168.50.250), con gateway e IP del router en
    # 192.168.50.1; ajusta red/ip/interfaz a tu instalación.
    'lan': {'interfaz': 'eth0', 'red': '192.168.50.0/24', 'ip': '192.168.50.1'},
    # Rango DHCP dentro de la LAN (el .0/.1 y las IP fijas NO entran aquí).
    'dhcp': {'inicio': '192.168.50.100', 'fin': '192.168.50.250', 'lease': '12h'},
    'dns': ['1.1.1.1', '9.9.9.9'],
    'dominio': 'lan.home.arpa',   # dominio DNS local que anuncia dnsmasq
    'monitor': {'destinos': ['1.1.1.1', '8.8.8.8'], 'intervalo_s': 5,
                'fallos_caida': 3, 'exitos_alta': 2},
    # Interfaces que NUNCA son WAN aunque el driver lo parezca: la loopback,
    # la interfaz de la propia LAN y bridges/contenedores típicos.
    'ignorar_interfaces': ['lo', 'eth0', 'docker0'],
    # Interfaces que se tratan como WAN aunque su driver no sea de tethering:
    # una salida por cable (módem, ONT de fibra, otro router) y, en las
    # pruebas con netns, las interfaces simuladas.
    'wan_forzadas': [],
    # WAN Wi-Fi: usar la tarjeta Wi-Fi como CLIENTE de otro punto de acceso
    # (un hotspot de teléfono, por ejemplo) y traer esa conexión a la LAN
    # como una WAN más (balanceo, pesos auto, monitor, firewall, NAT).
    #
    #   'habilitada': False por defecto; hay que activarla a propósito.
    #   'interfaz': el nombre de la tarjeta Wi-Fi (se ve con `nmcli d`).
    #       Un interfaz VACÍA significa "WAN Wi-Fi desactivada": aunque
    #       'habilitada' sea True no se descubre, no se usa nunca esa
    #       interfaz y las acciones wifi_* del panel se rechazan. Aquí va
    #       vacía por defecto: pon el nombre de TU tarjeta si la vas a usar.
    #   'ssid_bloqueadas': redes Wi-Fi a las que la tarjeta nunca debe
    #       conectarse como WAN, típicamente el SSID de la propia LAN, para
    #       no crear un bucle (el AP de la LAN es otro equipo).
    'wifi_wan': {'habilitada': False, 'interfaz': '', 'ssid_bloqueadas': []},
    # Modo punto de acceso Wi-Fi (AP1, ver core/wifi_ap.py): la MISMA tarjeta
    # publicando la red a los clientes de casa en vez de salir por otro AP.
    # Es EXCLUYENTE con wifi_wan (una tarjeta no puede ser AP y WAN a la
    # vez): al cargar la config, _resolver_conflicto_wifi_ap() deja la WAN
    # Wi-Fi como deshabilitada si las dos usan la misma interfaz.
    #   'habilitado': False por defecto; hay que activarlo a propósito.
    #   'interfaz': el nombre de la tarjeta Wi-Fi (se ve con `nmcli d`).
    #       Una interfaz VACÍA significa "AP desactivado", igual que en
    #       wifi_wan: no se ejecuta nada por él.
    #   'pais'/'canal': van a la config de hostapd (country_code/channel).
    # El SSID y la clave NO viven aquí: viven en /etc/router/hostapd.conf
    # (0600 root, lo escribe wifi_ap.py; wifi_ap.leer_ssid() muestra el SSID
    # sin la clave).
    'wifi_ap': {'habilitado': False, 'interfaz': '', 'pais': 'ES', 'canal': 6},
    # Activación con vuelta atrás (ver core/router_migrar.py): nombres de los
    # perfiles NetworkManager que usa la activación. 'perfil_lan' es el
    # perfil que levanta la IP del router en la LAN (lo crea el instalador:
    # IP fija, SIN gateway, autoconnect=no). 'perfil_wifi' y 'wifi_interfaz'
    # son la WAN Wi-Fi opcional: si ENTRE AMBOS está vacío, la activación se
    # salta TODOS los pasos Wi-Fi (no apaga ni reconecta la radio, no hace
    # ping por Wi-Fi). Rellena los dos sólo si vas a usar WAN Wi-Fi.
    'activacion': {'perfil_lan': 'LAN-ROUTER', 'perfil_wifi': '', 'wifi_interfaz': ''},
    'wans': {},        # id -> {nombre, habilitada, peso, prioridad, n}
    'reservas': [],    # [{mac, ip, nombre}]
    'etiquetas': {},   # mac -> etiqueta
    # Bloqueador DNS de anuncios/rastreadores/amenazas (HaGeZi) — ver
    # core/router_bloqueo.py y docs/CONTRATO.md. Las URLs NUNCA viven aquí
    # (sólo ids del catálogo fijo en código, router_bloqueo.CATALOGO):
    # "listas" es la selección del admin, "lista_blanca"/"lista_negra" las
    # excepciones manuales. _fusionar_con_defecto() ya hace un merge normal
    # de este dict (no está en la excepción de 'wans'/'etiquetas'), así que
    # un router.json existente que sólo tenga alguno de estos campos
    # conserva el resto con su valor por defecto.
    'bloqueo': {
        'habilitado': True, 'listas': ['hagezi_pro', 'hagezi_tif'],
        'lista_blanca': [], 'lista_negra': [],
        'forzar_dns': True, 'bloquear_doh': True,
        'actualizar_h': 24, 'registro_dns_dias': 30,
    },
}

RUTAS = {
    'config': '/etc/router/router.json',
    'fase': '/etc/router/fase',      # N1: escrito SÓLO por router_migrar
    # Marcador de migración en curso (router_migrar.py: MARCADOR). Mientras
    # exista, la máquina está en plena vigilancia (puede deshacerse en
    # cualquier momento): routerd NO debe tocar nada Wi-Fi mientras tanto
    # (ver Router._wifi_permitida). routerd nunca lo escribe ni lo borra.
    'migracion_pendiente': '/etc/router/migracion-pendiente',
    'estado': '/run/router/estado.json',
    'firewall': '/run/router/firewall.txt',
    'buzon': '/var/lib/router/solicitudes',
    'respuestas': '/var/lib/router/respuestas',
    'oplog': '/var/log/router/operaciones.log',
    'nft_base': '/etc/router/nftables/router.nft',
    'dnsmasq_lan': '/etc/dnsmasq.d/10-router-lan.conf',
    'dnsmasq_reservas': '/etc/router/dhcp-reservas.conf',
    # Bloqueador DNS: lo escribe/actualiza router_bloqueo.py (oneshot
    # aparte); routerd sólo LEE 'dnsmasq_bloqueo' (para decidir si lo
    # referencia desde dnsmasq_lan) y 'bloqueo_estado'/'bloqueo_cache'
    # (bloqueo_probar, sin red). routerd nunca escribe dentro de
    # 'bloqueo_cache'.
    'dnsmasq_bloqueo': '/var/lib/router/bloqueo/dnsmasq-bloqueo.conf',
    'bloqueo_cache': '/var/lib/router/bloqueo',
    'bloqueo_estado': '/run/router/bloqueo.json',
    # M2 (ronda 4): nivel de backoff del fail-open del DNS + hora de la
    # última salida — sobrevive a un reinicio de routerd (ver
    # Router._guardar_estado_fail_open/_cargar_estado_fail_open).
    'bloqueo_fail_open_estado': '/run/router/dns_emergencia.json',
    'logrotate_dns': '/etc/logrotate.d/router-dns',
    # BAJA7: drop-in de router-bloqueo.timer (OnUnitActiveSec = bloqueo.actualizar_h).
    'bloqueo_timer_dropin': '/etc/systemd/system/router-bloqueo.timer.d/override.conf',
    'grupo_panel': 'routerpanel',
    # Perfiles NM propios de la WAN Wi-Fi (WAN-wifi-<slug>.nmconnection, 0600
    # root): así la clave nunca pasa por argv/ps (ver generar_keyfile_wifi).
    'nm_system_connections': '/etc/NetworkManager/system-connections',
}


PROTOCOLO_PROPIO = 99   # N13: las ip rule que pone este programa se etiquetan así

# M1 (ronda 3, fail-open): tiempo ESTABLE (dnsmasq activo sin recaer) que
# hace falta para salir de fail-open de verdad — empieza en 30 min y se
# dobla con cada recaída (backoff exponencial), hasta un tope de 24 h.
BLOQUEO_ESTABLE_BASE_S = 1800
BLOQUEO_ESTABLE_MAX_S = 24 * 3600
BLOQUEO_BACKOFF_NIVEL_MAX = 6   # 1800 * 2**6 = 115200s > tope: ya lo acota min()
# M2 (ronda 4): el nivel de backoff ya NO se resetea a 0 al salir de
# fail-open — recaer dentro de esta ventana desde la ÚLTIMA salida sube
# un nivel (sospechoso: parecía curado y no lo estaba); sólo baja un
# nivel tras llevar FUERA de fail-open, sano, seguido, este otro tiempo.
BLOQUEO_RECAIDA_VENTANA_S = 24 * 3600
BLOQUEO_SANO_PARA_BAJAR_S = 24 * 3600

# Ronda 4 (e2e, fallo intermitente del paso 2): una WAN no entra en el
# balanceo hasta llevar, al menos, este número de ciclos SEGUIDOS con
# enlace válido comprobado (EstadoWan.muestras_validas) — evita que
# "parpadee" dentro y fuera del balanceo mientras todavía está
# calentando (acabada de descubrir/reconectada), y de paso evita que H7
# haga un `conntrack -D` prematuro sobre su marca justo cuando empieza a
# recibir tráfico de verdad.
MUESTRAS_MINIMAS_BALANCEO = 3

# ─────────────── pesos automáticos por calidad (fase 4, A) ───────────────
# Peso efectivo (1..100) de cada WAN cuando modo_pesos == "auto". Una WAN
# viva no debería bajar de PESO_MIN_SUELO (sigue recibiendo un pequeño % de
# conexiones nuevas, por si la "buena" se cae de repente), salvo que esté
# realmente mal (mucha pérdida o mucha latencia): ahí el suelo es casi 0.
PESO_MIN_SUELO = 5.0
PESO_MIN_DEGRADADO = 1.0
UMBRAL_PERDIDA_CRITICA_PCT = 30.0
UMBRAL_LATENCIA_CRITICA_MS = 1500.0
# Suavizado exponencial: cada ciclo el peso avanza como mucho ALPHA de la
# distancia que le falta hasta la puntuación "bruta" de ese ciclo, y nunca
# más de CAMBIO_MAX_POR_CICLO puntos — así un pico aislado de latencia no
# hace que el reparto oscile de golpe de ciclo en ciclo.
SUAVIZADO_ALPHA = 0.3
CAMBIO_MAX_POR_CICLO = 20.0
# El peso que de verdad llega a la tabla nftables (y que se publica como
# "peso_efectivo") sólo se actualiza cuando el suavizado se ha alejado más
# de esto del último valor aplicado: evita reescribir nft cada 5 s por un
# vaivén de 1-2 puntos que no cambia nada en la práctica.
UMBRAL_REESCRITURA_NFT = 5.0


def puntuacion_calidad(latencia_ms, perdida_pct, capacidad_bps):
    """Puntuación de calidad de una WAN para el reparto automático (A).

    puntuación = capacidad / (1 + latencia_ms/100) * (1 - pérdida/100)²

    - capacidad: H2 — se probó a usar aquí la "capacidad estimada" (el
      máximo de rx_bps+tx_bps visto recientemente), pero eso crea un bucle
      de realimentación: la WAN que YA está recibiendo más tráfico mide más
      capacidad, lo que la hace "puntuar" más alto, lo que le da más peso
      todavía — se queda con todo el reparto aunque su latencia/pérdida no
      lo justifiquen. Por eso `_actualizar_pesos_efectivos` llama a esta
      función SIEMPRE con `capacidad_bps=None` (de ahí el `capacidad_bps if
      capacidad_bps else 1.0` de abajo: con None, capacidad queda fija en
      1.0 y el resultado depende sólo de latencia y pérdida). El parámetro
      se mantiene por si algún día se mide la capacidad de otra forma que
      no dependa del reparto ya aplicado (p. ej. un test de velocidad
      puntual), pero hoy nadie debe pasarle un valor real.
    - 1 / (1 + latencia/100): penaliza la latencia de forma continua y
      suave (100 ms la deja a la mitad, 400 ms a un quinto…), sin un corte
      brusco que haga saltar el peso de golpe.
    - (1 − pérdida)²: la pérdida penaliza AL CUADRADO porque para llamadas
      y juego duele mucho más que la latencia (un 20% de pérdida deja sólo
      0.64 de puntuación, no 0.8) y porque ya es en sí un síntoma más grave
      que ir simplemente despacio.
    """
    capacidad = capacidad_bps if capacidad_bps else 1.0
    perdida_frac = max(0.0, min(1.0, perdida_pct / 100.0))
    return capacidad / (1.0 + latencia_ms / 100.0) * (1.0 - perdida_frac) ** 2


def _es_regla_propia(r):
    """N13: ¿esta ip rule (de `ip -j rule show`) la puso este programa?
    Así el barrido/desinstalar puede distinguirlas de una regla ajena que
    por casualidad caiga en el mismo rango de prioridades (900-1199) y
    nunca la toca."""
    return r.get('protocol') in (PROTOCOLO_PROPIO, str(PROTOCOLO_PROPIO))


def ahora_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _sd_notify(mensaje):
    """sd_notify mínimo, sin python-systemd (M7): un datagrama con el
    protocolo de notificación de systemd a $NOTIFY_SOCKET. Si no hay
    Type=notify (pruebas, ejecución a mano con --una-vez) esa variable no
    existe y esto no hace nada; cualquier fallo de socket se ignora — el
    watchdog nunca puede ser motivo para tirar el ciclo."""
    socket_path = os.environ.get('NOTIFY_SOCKET')
    if not socket_path:
        return
    import socket as _socket
    addr = ('\0' + socket_path[1:]) if socket_path.startswith('@') else socket_path
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(mensaje.encode())
    except OSError:
        LOG.debug('sd_notify(%s) no se pudo enviar', mensaje, exc_info=True)


def _redactar_datos(datos):
    """Nunca se debe escribir una clave Wi-Fi en claro en el oplog (ni en
    ningún otro sitio que la eco-ee): si 'datos' trae un campo 'clave'
    (wifi_agregar), se sustituye por "***" antes de registrar nada. Devuelve
    un dict nuevo; nunca muta el que recibe (ese es el que de verdad se usó
    para aplicar la petición)."""
    if isinstance(datos, dict) and 'clave' in datos:
        datos = dict(datos, clave='***')
    return datos


def run(args, entrada=None, comprobar=True, timeout=15):
    """Ejecuta un comando SIN shell (lista de argumentos fija).

    H5: un comando que se cuelga (p. ej. un `nft`/`ip` esperando un recurso
    bloqueado) no debe tirar el ciclo entero con una excepción sin capturar.
    Si agota el tiempo: con comprobar=True se convierte en RuntimeError (como
    cualquier otro fallo); con comprobar=False se devuelve un resultado con
    returncode != 0 para que el llamador lo trate igual que cualquier error.
    """
    try:
        r = subprocess.run(args, input=entrada, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        if comprobar:
            raise RuntimeError('%s → agotado el tiempo (%ss)' % (' '.join(args), timeout)) from e
        salida = e.stdout if isinstance(e.stdout, str) else (e.stdout or b'').decode('utf-8', 'replace')
        error = e.stderr if isinstance(e.stderr, str) else (e.stderr or b'').decode('utf-8', 'replace')
        return subprocess.CompletedProcess(args, 124, stdout=salida, stderr=error or 'agotado el tiempo')
    except OSError as e:
        # N6: binario ausente (o sin permiso de ejecución…) — nunca debe
        # tirar el ciclo entero con una excepción sin capturar; se trata
        # igual que cualquier otro fallo del comando (127 = «comando no
        # encontrado», el mismo código que usa la shell para esto).
        if comprobar:
            raise RuntimeError('%s → %s' % (' '.join(args), e)) from e
        return subprocess.CompletedProcess(args, 127, stdout='', stderr=str(e))
    if comprobar and r.returncode != 0:
        raise RuntimeError('%s → %s' % (' '.join(args), (r.stderr or r.stdout).strip()))
    return r


def escribir_atomico(ruta, texto, modo=0o644, grupo=None, fsync_dir=False):
    d = os.path.dirname(ruta)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())    # H6: que el contenido esté en disco antes del rename
        os.chmod(tmp, modo)
        if grupo:
            try:
                import grp
                os.chown(tmp, 0, grp.getgrnam(grupo).gr_gid)
            except (KeyError, PermissionError):
                pass
        os.replace(tmp, ruta)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if fsync_dir:
        # fsync del directorio: en caso de corte de luz, que el rename (el
        # nuevo nombre apuntando al fichero) también quede persistido, no
        # sólo el contenido del fichero (H6: router.json es config crítica).
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


# ───────────────────────────── configuración ─────────────────────────────

TIPOS_CONFIG = {
    'fase': str, 'modo': str, 'modo_pesos': str, 'lan': dict, 'dhcp': dict, 'dns': list,
    'monitor': dict, 'ignorar_interfaces': list, 'wan_forzadas': list, 'wifi_wan': dict,
    'wifi_ap': dict,
    'activacion': dict,
    'wans': dict, 'reservas': list, 'etiquetas': dict, 'bloqueo': dict,
}


def _forma_valida(leido):
    """Comprobación básica de tipos (H6): un router.json con, por ejemplo,
    "wans" como lista en vez de diccionario reventaría más adelante en
    cualquier sitio que haga cfg['wans'].items() — mejor rechazarlo aquí."""
    if not isinstance(leido, dict):
        return False
    return all(not (k in leido and not isinstance(leido[k], tipo)) for k, tipo in TIPOS_CONFIG.items())


def _resolver_conflicto_wifi_ap(cfg):
    """AP1: una tarjeta Wi-Fi no puede ser punto de acceso Y cliente WAN a
    la vez. Si wifi_ap está habilitado y su interfaz coincide con la de
    wifi_wan (no vacía en los dos lados), la WAN Wi-Fi se queda como
    DESHABILITADA en la config en memoria — SIN escribir router.json: en
    disco sigue lo que el admin puso (y puede corregirlo), aquí sólo deja
    de usarse la WAN y queda el AP."""
    ap = cfg.get('wifi_ap') or {}
    wan = cfg.get('wifi_wan') or {}
    ap_if = (ap.get('interfaz') or '').strip()
    wan_if = (wan.get('interfaz') or '').strip()
    if ap.get('habilitado') and ap_if and wan_if == ap_if:
        LOG.error('wifi_ap y wifi_wan usan la misma tarjeta (%s): la WAN '
                  'Wi-Fi se queda DESHABILITADA (una tarjeta no puede ser '
                  'AP y WAN a la vez); corrige router.json si una de las '
                  'dos no es lo que querías', ap_if)
        cfg['wifi_wan'] = dict(wan, habilitada=False)
    return cfg


def _fusionar_con_defecto(leido):
    cfg = copy.deepcopy(CONFIG_DEFECTO)
    for k, v in leido.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict) and k not in ('wans', 'etiquetas'):
            cfg[k].update(v)
        else:
            cfg[k] = v
    # Normalización de la config cargada: sólo reglas en memoria, router.json
    # no se toca aquí (se reescribe, si cabe, más adelante por _guardar_config).
    _resolver_conflicto_wifi_ap(cfg)
    return cfg


def cargar_config(ruta, anterior=None):
    """Carga router.json → (cfg, válida).

    H6: si el fichero no se puede parsear, no es un dict o tiene tipos
    básicos equivocados, NO se pierde la configuración en memoria que ya
    funcionaba. Se intenta primero `router.json`, luego `router.json.bak`
    (una copia de la última config buena que guardar_config va dejando) y,
    si ninguno sirve, se mantiene `anterior` (la que ya había en memoria) o,
    si no hay ninguna todavía (primer arranque), la de defecto. `válida` es
    False cuando se ha caído a `anterior`/defecto: el llamador no debe
    guardar esa config encima de router.json (vería bien lo que ya hay)."""
    for candidato in (ruta, ruta + '.bak'):
        try:
            with open(candidato) as f:
                leido = json.load(f)
        except FileNotFoundError:
            continue
        except (ValueError, OSError) as e:
            LOG.error('%s ilegible (%s)', candidato, e)
            continue
        if not _forma_valida(leido):
            LOG.error('%s no tiene la forma esperada de router.json: se descarta', candidato)
            continue
        if candidato != ruta:
            LOG.warning('%s no se pudo usar: se ha cargado %s en su lugar', ruta, candidato)
        return _fusionar_con_defecto(leido), True
    if anterior is not None:
        LOG.error('%s (ni su copia .bak) se pudo cargar: se mantiene la última '
                  'configuración buena en memoria', ruta)
        return anterior, False
    LOG.warning('sin %s ni %s utilizables: se usa la configuración por defecto '
               '(no se guardará sobre router.json hasta tener una config válida)', ruta, ruta + '.bak')
    return copy.deepcopy(CONFIG_DEFECTO), False


def guardar_config(ruta, cfg):
    """H6: antes de reemplazar router.json, se copia el actual a .bak (si lo
    hay) — es la red de seguridad que usa cargar_config() cuando el de verdad
    se corrompe. fsync de fichero y directorio: que una config que el panel
    acaba de pedir no se pierda si hay un corte justo después."""
    try:
        with open(ruta, 'rb') as f:
            actual = f.read()
    except OSError:
        actual = None
    if actual is not None:
        escribir_atomico(ruta + '.bak', actual.decode('utf-8'), fsync_dir=True)
    escribir_atomico(ruta, json.dumps(cfg, indent=2, ensure_ascii=False) + '\n', fsync_dir=True)


# ───────────────────────────── descubrimiento ─────────────────────────────

def _leer(ruta, defecto=None):
    try:
        with open(ruta) as f:
            return f.read().strip()
    except OSError:
        return defecto


def _driver(ifname):
    try:
        return os.path.basename(os.readlink('/sys/class/net/%s/device/driver' % ifname))
    except OSError:
        return None


def _usb_info(ifname):
    """(serie, 'Fabricante Modelo') del dispositivo USB padre de la interfaz."""
    try:
        d = os.path.realpath('/sys/class/net/%s/device' % ifname)
    except OSError:
        return None, None
    # Subir por el árbol hasta el nodo del dispositivo USB (tiene idVendor).
    for _ in range(6):
        if os.path.exists(os.path.join(d, 'idVendor')):
            serie = _leer(os.path.join(d, 'serial'))
            fab = _leer(os.path.join(d, 'manufacturer'), '') or ''
            prod = _leer(os.path.join(d, 'product'), '') or ''
            # Muchos teléfonos repiten la marca en el producto («TCL» + «TCL 50…»).
            nombre = (prod if fab and prod.lower().startswith(fab.lower()) else (fab + ' ' + prod)).strip() or None
            return serie, nombre
        d = os.path.dirname(d)
    return None, None


def _ipv4_y_gateway(ifname):
    ip = gw = None
    r = run(['ip', '-j', '-4', 'addr', 'show', 'dev', ifname], comprobar=False)
    try:
        for a in json.loads(r.stdout or '[]'):
            for info in a.get('addr_info', []):
                if info.get('family') == 'inet':
                    ip = '%s/%s' % (info['local'], info['prefixlen'])
                    break
    except ValueError:
        pass
    # El gateway lo pone NetworkManager en la tabla main (DHCP del teléfono).
    r = run(['ip', '-j', '-4', 'route', 'show', 'default', 'dev', ifname], comprobar=False)
    try:
        rutas = json.loads(r.stdout or '[]')
        if rutas:
            gw = rutas[0].get('gateway')
    except ValueError:
        pass
    if ip and not gw:
        # Sin ruta por defecto (p. ej. NM con never-default): el teléfono es el
        # .1/.129 de su red; probamos con la puerta que anuncia el DHCP en NM.
        r = run(['nmcli', '-g', 'IP4.GATEWAY', 'device', 'show', ifname], comprobar=False)
        cand = (r.stdout or '').strip()
        if cand and cand != '--':
            gw = cand
    return ip, gw


def _nmcli_lectura(args, breaker=None, timeout=4):
    """Ejecuta una llamada de SÓLO LECTURA a nmcli respetando un "breaker"
    de ciclo (revisión Opus, punto 6): si `breaker` es un dict y ya trae
    `{'agotado': True}` (una lectura previa este mismo ciclo agotó el
    tiempo), no se intenta ninguna lectura wifi más — mejor servir datos
    algo viejos que arriesgar el ciclo entero por una tarjeta/nmcli que no
    contesta. Nunca lanza; devuelve None si no se intenta o si falla."""
    if breaker is not None and breaker.get('agotado'):
        return None
    try:
        r = run(args, comprobar=False, timeout=timeout)
    except Exception:
        LOG.exception('fallo inesperado ejecutando %s', ' '.join(args))
        return None
    if r.returncode == 124 and breaker is not None:
        breaker['agotado'] = True
    return r


def _wifi_conexion_activa_info(ifname, breaker=None):
    """(uuid_activo, nombre_perfil, ssid) de la conexión activa en
    `ifname` ahora mismo, o (None, None, None) si no está conectada o nmcli
    no está disponible/falla (pruebas en netns sin tarjeta real, o sin
    NetworkManager). Nunca lanza (requisito: si el código depende de nmcli
    para el SSID, que falle en blando). El SSID se lee con `nmcli -g`, que
    también escapa ':'/'\\' igual que `-t` (punto 7 de la revisión): se
    desescapa con _parsear_linea_nmcli_t."""
    r = _nmcli_lectura(['nmcli', '-g', 'GENERAL.CONNECTION,GENERAL.CON-UUID', 'device', 'show', ifname], breaker)
    if r is None:
        return None, None, None
    lineas = (r.stdout or '').splitlines()
    nombre = lineas[0].strip() if len(lineas) > 0 else ''
    uuid_activo = lineas[1].strip() if len(lineas) > 1 else ''
    if not nombre or nombre == '--' or not uuid_activo or uuid_activo == '--':
        return None, None, None
    ssid = nombre
    r2 = _nmcli_lectura(['nmcli', '-g', '802-11-wireless.ssid', 'connection', 'show', nombre], breaker)
    if r2 is not None:
        texto = (r2.stdout or '').strip()
        if texto:
            ssid = _parsear_linea_nmcli_t(texto)[0] or nombre
    return uuid_activo, nombre, ssid


def _wifi_conexion_activa(ifname, breaker=None):
    """SSID al que está asociada `ifname` ahora mismo, o None."""
    _, _, ssid = _wifi_conexion_activa_info(ifname, breaker)
    return ssid


def descubrir_wans(cfg, permitir_wifi=True, breaker=None):
    """Lista de interfaces WAN presentes: [{ifname, id, telefono, ip, gw}].

    Incluye, además del tethering USB de siempre, la WAN Wi-Fi (cliente de
    un hotspot de teléfono, cfg['wifi_wan']) si está habilitada, la
    interfaz existe Y `permitir_wifi` es True: se trata aparte (nunca por
    DRIVERS_TETHER, aquí NO hace falta que el driver sea de tethering — en
    pruebas puede ser hasta un veth) y con id estable "wifi-<interfaz>";
    'telefono' aquí es el SSID conectado (o None).

    `permitir_wifi=False` (revisión Opus, punto 2): en fase preparación, o
    mientras haya una migración en curso (Router._wifi_permitida), routerd
    NO debe tocar nada Wi-Fi — ni siquiera descubrirla (cero llamadas a
    nmcli, cero entrada en la lista); lo decide el llamador (Router.ciclo),
    nunca este módulo por su cuenta."""
    wifi_cfg = cfg.get('wifi_wan') or {}
    wifi_if = wifi_cfg.get('interfaz')
    ignorar = set(cfg.get('ignorar_interfaces') or []) | {cfg['lan']['interfaz']}
    forzadas = set(cfg.get('wan_forzadas') or [])
    out = []
    for ifname in sorted(os.listdir('/sys/class/net')):
        if wifi_if and ifname == wifi_if:
            continue   # la WAN Wi-Fi se trata aparte, más abajo
        if ifname in ignorar and ifname not in forzadas:
            continue
        if ifname not in forzadas and _driver(ifname) not in DRIVERS_TETHER:
            continue
        serie, telefono = _usb_info(ifname)
        ip, gw = _ipv4_y_gateway(ifname)
        oper = _leer('/sys/class/net/%s/operstate' % ifname, 'unknown')
        out.append({'ifname': ifname, 'id': serie or ifname, 'telefono': telefono,
                    'ip': ip, 'gw': gw, 'operstate': oper, 'es_wifi': False})
    if (permitir_wifi and wifi_cfg.get('habilitada') and wifi_if
            and os.path.exists('/sys/class/net/%s' % wifi_if)):
        ip, gw = _ipv4_y_gateway(wifi_if)
        oper = _leer('/sys/class/net/%s/operstate' % wifi_if, 'unknown')
        uuid_activo, perfil_activo, ssid = _wifi_conexion_activa_info(wifi_if, breaker)
        out.append({'ifname': wifi_if, 'id': 'wifi-%s' % wifi_if, 'telefono': ssid,
                    'ip': ip, 'gw': gw, 'operstate': oper, 'es_wifi': True,
                    'uuid_activo': uuid_activo, 'perfil_activo': perfil_activo})
    return out


# ───────────────────────────── WAN Wi-Fi: perfiles NM ─────────────────────

RE_SLUG_NO_ALFANUM = re.compile(r'[^a-z0-9]+')


def _slug_wifi(ssid):
    """Slug ASCII seguro de un SSID, para el nombre del perfil NM
    (WAN-wifi-<slug>) y el nombre del fichero keyfile. Se añade un sufijo
    corto (hash del SSID real) para que dos SSID distintos que se queden en
    el mismo slug tras quitar acentos/símbolos (p. ej. "Café" y "Cafe") no
    colisionen en el mismo perfil."""
    base = unicodedata.normalize('NFKD', ssid).encode('ascii', 'ignore').decode('ascii').lower()
    base = RE_SLUG_NO_ALFANUM.sub('-', base).strip('-') or 'red'
    sufijo = hashlib.sha1(ssid.encode('utf-8')).hexdigest()[:8]
    return '%s-%s' % (base[:40], sufijo)


def nombre_perfil_wifi(ssid):
    """Nombre del perfil NM (connection.id) propio de routerd para ese SSID.
    SIEMPRE empieza por "WAN-wifi-": es la marca que permite borrar sólo
    perfiles propios (wifi_eliminar) sin tocar ningún otro perfil NM."""
    return 'WAN-wifi-%s' % _slug_wifi(ssid)


def _ssid_bytes_keyfile(ssid):
    """SSID como lista de bytes decimales separados por ';' (formato keyfile
    de NetworkManager para 'ssid' como array de uint8): es la forma SEGURA
    de escribir cualquier SSID (con ';', '=', espacios, UTF-8 raro…) sin
    tener que escapar nada ni arriesgarse a romper el fichero .ini."""
    return ''.join('%d;' % b for b in ssid.encode('utf-8'))


# UUID5 (revisión Opus, punto 9): estable por SSID (no uuid4 al azar en cada
# llamada) — así "wifi_agregar" sobre un SSID que ya existía REEMPLAZA el
# mismo connection.uuid en vez de crear uno nuevo cada vez (ghosts en NM).
_UUID_NAMESPACE_WIFI = uuid.UUID('b9f7b7d0-6e1a-4e9a-9c7d-7a7e9a5b9c01')


def _uuid_wifi(ssid):
    return str(uuid.uuid5(_UUID_NAMESPACE_WIFI, 'router-casa:wifi-wan:%s' % ssid))


def _escapar_valor_keyfile(v):
    """Escapa un valor para una línea 'clave=valor' de un fichero keyfile
    de NetworkManager/GLib (GKeyFile) — revisión Opus, punto 5: '\\' se
    duplica (si no, GLib lo interpretaría como el inicio de un escape), y un
    espacio en los EXTREMOS del valor se escribe '\\s' (si no, GLib podría
    no conservarlo al leer la línea). No hace falta escapar nada más (';',
    '=', '#', '[' sólo tienen significado especial al principio de una
    línea entera o como separador clave=valor, nunca dentro de un valor)."""
    cuerpo = v.replace('\\', '\\\\')
    if v[:1] == ' ':
        cuerpo = '\\s' + cuerpo[1:]
    if v[-1:] == ' ':
        cuerpo = ('\\s' if len(v) == 1 else cuerpo[:-1] + '\\s')
    return cuerpo


def generar_keyfile_wifi(ssid, clave, prioridad, interfaz):
    """(nombre_perfil, texto_keyfile) de un perfil WAN-wifi-* propio de
    routerd para que esa red Wi-Fi actúe como una WAN más.

    - route-metric=750 e ignore-auto-dns=true: no debe competir con la ruta
      ni el DNS por defecto de la LAN/otras WAN — routerd gestiona sus
      propias tablas de rutas, igual que con el tethering USB.
    - Sin clave → red abierta: no se escribe ninguna sección
      [wifi-security] (si se escribiera con key-mgmt vacío, NetworkManager
      la trataría como mal configurada).
    - La clave sólo vive AQUÍ, en el fichero 0600 root que escribe el
      llamador (escribir_atomico) — nunca en router.json/estado.json/log.
    """
    lineas = [
        '[connection]',
        'id=%s' % nombre_perfil_wifi(ssid),
        'uuid=%s' % _uuid_wifi(ssid),
        'type=wifi',
        'interface-name=%s' % interfaz,
        'autoconnect=true',
        'autoconnect-priority=%d' % int(prioridad),
        '',
        '[wifi]',
        'mode=infrastructure',
        'ssid=%s' % _ssid_bytes_keyfile(ssid),
        'hidden=false',
        '',
    ]
    if clave:
        lineas += ['[wifi-security]', 'key-mgmt=wpa-psk', 'psk=%s' % _escapar_valor_keyfile(clave), '']
    lineas += [
        '[ipv4]',
        'method=auto',
        'route-metric=750',
        'ignore-auto-dns=true',
        '',
        '[ipv6]',
        'method=disabled',
        '',
    ]
    return nombre_perfil_wifi(ssid), '\n'.join(lineas)


def _parsear_linea_nmcli_t(linea):
    """Separa una línea de `nmcli -t -f a,b,c ...` en sus campos, respetando
    el escape de nmcli: ':' literal dentro de un campo se escribe '\\:' (y
    '\\' literal, '\\\\') y no debe partir la línea ahí."""
    campos = []
    actual = []
    i = 0
    while i < len(linea):
        ch = linea[i]
        if ch == '\\' and i + 1 < len(linea):
            actual.append(linea[i + 1])
            i += 2
            continue
        if ch == ':':
            campos.append(''.join(actual))
            actual = []
            i += 1
            continue
        actual.append(ch)
        i += 1
    campos.append(''.join(actual))
    return campos


def parsear_escaneo_wifi(texto):
    """[{ssid, senal, seguridad, canal}] de la salida de
    `nmcli -t -f SSID,SIGNAL,SECURITY,CHAN device wifi list`. Una línea con
    menos campos de los esperados (versión rara de nmcli, línea vacía) se
    descarta en vez de reventar."""
    redes = []
    for linea in texto.splitlines():
        if not linea:
            continue
        campos = _parsear_linea_nmcli_t(linea)
        if len(campos) < 4:
            continue
        ssid, senal, seguridad, canal = campos[0], campos[1], campos[2], campos[3]
        try:
            senal_i = int(senal)
        except ValueError:
            senal_i = 0
        redes.append({'ssid': ssid, 'senal': senal_i, 'seguridad': seguridad or '--', 'canal': canal})
    return redes


# ───────────────────────────── estado por WAN ─────────────────────────────

class EstadoWan:
    def __init__(self):
        self.internet = False
        self.fallos = 0
        self.exitos = 0
        self.latencias = []
        self.perdidas = []
        self.ultimo_cambio = ahora_iso()
        self.rx = self.tx = None
        self.rx_bps = self.tx_bps = 0
        self.t_bytes = None
        self.capacidades = []    # (A) muestras recientes de rx_bps+tx_bps, para estimar capacidad
        self.peso_efectivo = None   # (A) peso suavizado; lo publica estado.json
        # Ronda 4 (e2e, fallo intermitente del paso 2): cuántos ciclos
        # SEGUIDOS lleva esta WAN con enlace válido (ip, gateway,
        # operstate up/unknown) y, por tanto, con un ping de verdad
        # intentado — ver MUESTRAS_MINIMAS_BALANCEO/wans_activas(). Nunca
        # se resetea a 0 por un solo fallo de ping (eso ya lo gestiona
        # e.fallos/e.internet con su propia histéresis): esto es sólo un
        # "lleva ya un rato siendo comprobada de verdad", no "está sana".
        self.muestras_validas = 0


_AVISADO_PING_SIN_TIME = set()   # M2: interfaces ya avisadas (una vez cada una)
_SIN_SSID_PREVIO = object()   # centinela: "nunca visto", distinto de None (= "visto pero desconectado")


def _normalizar_ssid_bloqueo(ssid):
    """.strip().casefold(): "MI-WIFI ", "mi-wifi" o "Mi-Wifi"
    cuentan como la misma red bloqueada que "MI-WIFI" — misma
    normalización que peticiones.py (y que debe aplicar el panel al
    pintarlo), para que el admin nunca pueda colarse por un espacio o una
    mayúscula de más."""
    return ssid.strip().casefold()


def _ssid_esta_bloqueada(ssid, ssid_bloqueadas):
    normalizadas = {_normalizar_ssid_bloqueo(s) for s in (ssid_bloqueadas or [])}
    return _normalizar_ssid_bloqueo(ssid) in normalizadas


def ping(destino, ifname, marca, cuenta=3, intervalo=0.2, timeout_s=2):
    """(mediana_ms_o_None, pérdida_pct_0_100) de `cuenta` pings rápidos.

    A: antes era 1 ping por ciclo; con varios (-c 3 -i 0.2, por defecto) y
    la MEDIANA en vez de la media se filtra mejor un pico aislado, sin
    alargar el ciclo — con 0.2 s entre paquetes los 3 tardan como mucho
    ~1 s en el peor caso, bien por debajo del intervalo de ciclo (segundos).
    Ping sigue ligado a la interfaz y con la marca de la WAN (-m): en
    producción, la cadena de salida respeta esa marca y el paquete sale por
    la tabla de esa WAN, no por la ruta por defecto.

    M2: se fuerza `LC_ALL=C` (vía `env`) porque el texto de salida de
    `ping` depende del locale del sistema — con uno distinto del inglés el
    «time=» que busca el regex de abajo podría no aparecer nunca, y la WAN
    se vería con 100% de pérdida estando en realidad viva. Como red de
    seguridad adicional: si `ping` termina con éxito (returncode 0 — para
    `ping` eso significa que llegó al menos una respuesta) pero aun así no
    se encuentra ningún «time=» (formato de salida inesperado, versión rara
    de `ping`…), se considera la línea viva con latencia desconocida (None)
    y pérdida 0, en vez de 100% de pérdida; se avisa por log una sola vez
    por interfaz, para que quede constancia sin inundar el log cada ciclo.
    """
    args = ['env', 'LC_ALL=C', 'ping', '-n', '-c', str(cuenta), '-i', str(intervalo),
            '-W', str(timeout_s), '-I', ifname]
    if marca:
        args += ['-m', str(marca)]
    args.append(destino)
    # run() ya convierte un timeout en returncode 124 (sin «time=» → 100%).
    r = run(args, comprobar=False, timeout=timeout_s + cuenta * intervalo + 3)
    tiempos = [float(m) for m in re.findall(r'time=([\d.]+)', r.stdout)]
    if not tiempos:
        if r.returncode == 0:
            if ifname not in _AVISADO_PING_SIN_TIME:
                LOG.warning('ping a %s por %s: returncode 0 pero sin ningún «time=» en la '
                            'salida (formato inesperado) — se asume la línea viva', destino, ifname)
                _AVISADO_PING_SIN_TIME.add(ifname)
            return None, 0.0
        return None, 100.0
    perdida = round((cuenta - len(tiempos)) * 100.0 / cuenta, 1)
    return statistics.median(tiempos), perdida


# ───────────────────────────── el demonio ─────────────────────────────

class Router:
    def __init__(self, rutas):
        self.rutas = rutas
        self.cfg = None
        # H6: hasta que se cargue con éxito una config de verdad (de disco,
        # suya o del .bak), no se guarda nada encima de router.json — así no
        # se puede pisar una config buena con el defecto por un fallo de
        # lectura transitorio en el primer arranque.
        self.permitir_guardar = False
        self.cfg = self._cargar_config()
        self.fase = 'preparacion'   # N1: se recalcula en cada ciclo desde RUTAS['fase']
        self.estados = {}          # id -> EstadoWan
        self.presentes = {}        # id -> info de descubrimiento
        self._redes_wan = {}       # id -> red (ip/máscara) de la última vez (LOW)
        self._avisado_solape = set()   # ids ya avisados de que su red choca con la LAN
        self._avisado_bucle_wifi = set()   # ids de WAN Wi-Fi ya avisadas de bucle (una vez por evento)
        self._radio_wifi_aplicada = None   # última lectura/aplicación de "nmcli radio wifi" (True/False/None)
        self._radio_wifi_ultima_lectura = 0.0   # time.time() de la última resincronización (punto 3)
        self._wifi_permitida_anterior = None    # último valor de _wifi_permitida() (para detectar el cambio)
        self._wifi_breaker = {}            # {'agotado': bool} del ciclo en curso (punto 6)
        self._wifi_escaneo = []            # última lista de redes vistas (wifi_escanear)
        self._wifi_escaneo_ts = None
        self._wifi_escaneo_pendiente = False        # rescan lanzado, resultado aún no leído (no bloqueante)
        self._wifi_escaneo_pendiente_desde = None
        self._wifi_redes_cache = []        # redes guardadas (WAN-wifi-*): caché, no una lectura por ciclo
        self._wifi_redes_cache_ts = 0.0
        self._wifi_ssid_anterior = {}      # wid -> último SSID visto (detectar cambio de hotspot, punto 10)
        self.anteriores_activas = set()   # {n} de las WAN que estaban en el balanceo (H7)
        self.inicio = time.time()
        self.ultima_firma_balanceo = None
        self._pesos_nft = {}       # (A) wid -> último peso efectivo aplicado a la tabla nft
        self._rapida_n = None     # M1: histéresis — `n` de la WAN que hoy usa elegir_wan_rt
        self.base_instalada = False
        self.base_texto = None
        self._firewall_error = None   # N9: mensaje publicado en estado.json si no hay base instalada
        self._dnsmasq_inactivo_avisado = False   # N7: oplog una vez, no cada ciclo
        self._dnsmasq_test_error_previo = None   # L1: oplog una vez por error, no cada ciclo
        self._arranque_limpio_hecho = False   # barrido de estado al primer ciclo en producción (LOW)
        self._dnsmasq_log_extra = None    # caché: ¿el dnsmasq instalado admite log-queries=extra? (None = aún no se sabe)
        self._logrotate_dns_error_previo = None   # oplog una vez por error, no cada ciclo
        # — M6/M1 (ronda 3): fail-open del bloqueador DNS, con histéresis y
        # backoff exponencial —
        self._dnsmasq_fallos_consecutivos = 0   # arranques fallidos seguidos de dnsmasq
        self._bloqueo_fail_open = False         # True tras 3 fallos: servers-file vacío, sin log, sin redirigir_dns
        self._bloqueo_fail_open_avisado = False   # oplog una vez al entrar, una vez al salir
        self._bloqueo_activo_desde = None        # time.time() de cuándo volvió a verse activo (None = aún no)
        # M2 (ronda 4): nivel/salida_desde se cargan de disco justo debajo
        # (sobreviven a un reinicio de routerd) — aquí sólo el valor por
        # defecto si no hay nada guardado (primer arranque, o /run limpio
        # tras un reboot).
        self._bloqueo_backoff_nivel = 0          # sube con cada recaída; YA NO se resetea a 0 al salir
        self._bloqueo_fail_open_desde = None     # time.time() de cuándo se entró (informativo, estado.json)
        self._bloqueo_salida_desde = None        # time.time() de la ÚLTIMA vez que se salió de fail-open
        self._cargar_estado_fail_open()
        # — BAJA7/BAJA1/BAJA2: drop-in del timer de router-bloqueo.timer (actualizar_h) —
        self._bloqueo_timer_h_aplicado = None
        self._bloqueo_timer_error_previo = None   # BAJA2: oplog una vez por error, no cada ciclo
        # — BAJA8: máx 2 bloqueo_probar de verdad ejecutadas por ciclo —
        self._bloqueo_probar_ejecutadas = 0
        # — BAJA10/11: último forzar_dns/bloquear_doh aplicado, para saber
        # cuándo hace falta vaciar conntrack al activarlos de nuevo —
        self._forzar_dns_anterior = None
        self._bloquear_doh_anterior = None
        # Firewall con reglas propias: (id, huella) de reglas bloquear/
        # rechazar cuyo origen ya se ha vaciado de conntrack (para no repetir
        # el -D en cada reinstalación — sólo al aplicar por primera vez una
        # regla de este tipo, o al EDITARLA: la huella cambia y se re-vacía).
        self._fw_conntrack_flushed = set()
        # — AP1 (wifi_ap): caché ≥30 s de las lecturas caras del estado
        # del AP (systemctl is-active + iw station dump): publicar() corre
        # cada ~5 s y no debe lanzarlas cada vez — el ciclo no puede
        # alargarse sin tope por un comando lento (misma idea que
        # MAX_CONNTRACK_*).
        self._wifi_ap_cache = None    # {'ts': float, 'interfaz': str, 'datos': dict}
        self.parar = threading.Event()

    # — configuración —
    def _cargar_config(self):
        nuevo, valida = cargar_config(self.rutas['config'], anterior=self.cfg)
        if valida:
            self.permitir_guardar = True
        return nuevo

    def _guardar_config(self):
        if not self.permitir_guardar:
            LOG.error('me niego a guardar router.json: todavía no se ha podido cargar '
                      'una configuración válida de disco (H6)')
            return False
        # N1: "fase" ya no se guarda en router.json (vive en RUTAS['fase'],
        # y el único que la escribe es router_migrar) — si viene de una
        # config vieja que todavía la tenía, no se vuelve a escribir aquí.
        cfg_a_guardar = {k: v for k, v in self.cfg.items() if k != 'fase'}
        guardar_config(self.rutas['config'], cfg_a_guardar)
        return True

    def _fase_efectiva(self):
        """N1: la fase se lee de su propio fichero en cada ciclo; routerd
        NUNCA lo escribe, sólo router_migrar. Si no existe (o no tiene un
        valor reconocido), se usa la "fase" de router.json por
        compatibilidad con instalaciones viejas; si tampoco hay eso,
        "preparacion"."""
        try:
            with open(self.rutas['fase']) as f:
                contenido = f.read().strip()
            if contenido in ('preparacion', 'produccion'):
                return contenido
        except OSError:
            pass
        return self.cfg.get('fase') or 'preparacion'

    # — configuración de las WAN —
    def _asegurar_wan_en_config(self, w):
        """Da de alta la WAN en la config si es nueva. Devuelve su entrada,
        o None si no hay hueco (LOW: antes `next(...)` sin defecto lanzaba
        StopIteration y tiraba el ciclo entero)."""
        wans = self.cfg.setdefault('wans', {})
        if w['id'] not in wans:
            usados = {v.get('n') for v in wans.values()}
            n = next((i for i in range(1, 100) if i not in usados), None)
            if n is None:
                self.oplog('sistema', 'wan_sin_hueco', {'wan': w['id'], 'interfaz': w['ifname']}, False,
                           'No hay hueco libre para una línea nueva (máximo 99 WAN): '
                           '%s no se añade' % w['ifname'])
                return None
            nombre = 'Wi-Fi' if w.get('es_wifi') else 'WAN%d' % n
            wans[w['id']] = {'nombre': nombre, 'habilitada': True, 'peso': 50,
                             'prioridad': n, 'n': n}
            self._guardar_config()
            self.oplog('sistema', 'wan_nueva', {'wan': w['id'], 'interfaz': w['ifname']}, True,
                       'Nueva línea detectada: %s (%s)' % (wans[w['id']]['nombre'], w['ifname']))
        return wans[w['id']]

    def produccion(self):
        return self.fase == 'produccion'

    # — WAN Wi-Fi: cuándo se le permite tocar algo —
    def _wifi_permitida(self):
        """False en fase preparación, o mientras haya una migración de
        router_migrar.py en curso (su marcador de vigilancia): en ninguno
        de esos dos casos routerd debe tocar NADA Wi-Fi — ni descubrirla, ni
        la radio, ni la guarda anti-bucle (revisión Opus, punto 2). La
        tarjeta Wi-Fi puede estar todavía usándose para la conexión a
        Internet del propio equipo (preparación) o a punto de que
        router_migrar la reconecte si deshace la migración."""
        if not self.produccion():
            return False
        return not os.path.exists(self.rutas.get('migracion_pendiente', RUTAS['migracion_pendiente']))

    # — WAN Wi-Fi: anti-bucle y radio —
    def _wifi_guardia_bucle(self, w):
        """Razón (str) por la que esta WAN Wi-Fi NO debe entrar en el
        balanceo, o None si está bien. Conectarse al SSID de la propia casa,
        acabar en la misma red (o con la misma puerta) que la LAN, o tener
        activo un perfil NM que no sea propio (WAN-wifi-*) crearía un bucle
        o se saldría del control de routerd — en producción sólo se admiten
        los perfiles que ha creado wifi_agregar. Nunca lanza: usa sólo lo
        que YA se ha leído de /sys y de nmcli este mismo ciclo."""
        bloqueadas = (self.cfg.get('wifi_wan') or {}).get('ssid_bloqueadas') or []
        if w.get('telefono') and _ssid_esta_bloqueada(w['telefono'], bloqueadas):
            return 'conectada a «%s» (SSID bloqueado: crearía un bucle con la propia LAN)' % w['telefono']
        perfil_activo = w.get('perfil_activo')
        if perfil_activo and not perfil_activo.startswith('WAN-wifi-'):
            return ('conectada con un perfil ajeno («%s», no WAN-wifi-*): en producción sólo se '
                    'admiten los perfiles propios' % perfil_activo)
        lan = self.cfg['lan']
        if w.get('ip'):
            try:
                red_tel = ipaddress.ip_interface(w['ip']).network
                lan_red = ipaddress.ip_network(lan['red'])
            except ValueError:
                red_tel = lan_red = None
            if red_tel is not None and lan_red is not None and red_tel.overlaps(lan_red):
                return 'su red (%s) coincide con la de la LAN' % red_tel
        if w.get('gw') and w['gw'] == lan['ip']:
            return 'su puerta de enlace es la IP del propio router'
        return None

    def _wifi_desconectar_por_bucle(self, w):
        """Aplica de verdad la guarda anti-bucle (revisión Opus, punto 4):
        en vez de `nmcli device disconnect` (que deja el dispositivo
        "unmanaged" un rato y bloquea su autoconnect normal), se baja la
        CONEXIÓN activa (`nmcli connection down <uuid>`) — y si ese perfil
        es ajeno (no WAN-wifi-*), además se le quita el autoconnect, para
        que NetworkManager no vuelva a asociarse sola la próxima vez. Si no
        hay conexión activa que bajar (p. ej. una interfaz de pruebas sin
        gestionar por NM), no se intenta nada. Nunca lanza."""
        uuid_activo = w.get('uuid_activo')
        if not uuid_activo:
            return
        try:
            run(['nmcli', 'connection', 'down', uuid_activo], comprobar=False, timeout=10)
            perfil_activo = w.get('perfil_activo')
            if perfil_activo and not perfil_activo.startswith('WAN-wifi-'):
                run(['nmcli', 'connection', 'modify', uuid_activo, 'connection.autoconnect', 'no'],
                    comprobar=False, timeout=10)
        except Exception:
            LOG.exception('no se pudo desconectar %s tras detectar un bucle', w.get('ifname'))

    def _radio_wifi_real(self):
        """Estado REAL de la radio Wi-Fi ahora mismo (True/False), leído de
        verdad con `nmcli radio wifi`, o None si no se puede saber (nmcli
        ausente/falla). Se usa para resincronizar la caché cada ~60 s
        (revisión Opus, punto 3): algo o alguien (el propio usuario desde
        el móvil/GUI de NM) puede haber cambiado la radio sin pasar por
        aquí, y sin esto la caché se quedaría desfasada para siempre."""
        r = _nmcli_lectura(['env', 'LC_ALL=C', 'nmcli', 'radio', 'wifi'], self._wifi_breaker)
        if r is None or r.returncode != 0:
            return None
        txt = (r.stdout or '').strip().lower()
        if txt == 'enabled':
            return True
        if txt == 'disabled':
            return False
        return None

    def _aplicar_radio_wifi(self):
        """Enciende o apaga la radio Wi-Fi según wifi_wan.habilitada, pero
        SÓLO cuando de verdad hace falta — nunca en cada ciclo a lo bruto —
        y SÓLO si la interfaz configurada existe de verdad — así una
        interfaz de pruebas (netns, sin tarjeta real) o sin wifi_wan
        configurada no toca para nada la radio Wi-Fi real de la máquina.
        Cada ~60 s (o la primera vez) se resincroniza con el estado REAL
        (punto 3): si alguien cambió la radio por fuera, aquí se entera
        antes de decidir si hace falta tocarla. Nunca lanza (watchdog): un
        fallo de nmcli se registra y se reintenta en el ciclo siguiente."""
        if not self.cfg.get('gestionar_radio_wifi', True):
            # Pruebas en netns (pruebas/netns_multiwan.sh): nmcli habla con
            # NetworkManager por D-Bus, que NO está aislado por el netns —
            # sin esta válvula de escape, una prueba automática podría
            # encender/apagar la radio Wi-Fi REAL de la máquina que la
            # ejecuta. Mismo patrón que 'gestionar_dnsmasq' (asegurar_dnsmasq).
            return
        wifi_cfg = self.cfg.get('wifi_wan') or {}
        interfaz = wifi_cfg.get('interfaz')
        if not interfaz or not os.path.exists('/sys/class/net/%s' % interfaz):
            return
        ahora = time.time()
        if self._radio_wifi_aplicada is None or (ahora - self._radio_wifi_ultima_lectura) >= 60:
            real = self._radio_wifi_real()
            self._radio_wifi_ultima_lectura = ahora
            if real is not None:
                self._radio_wifi_aplicada = real
        deseado = bool(wifi_cfg.get('habilitada'))
        if deseado == self._radio_wifi_aplicada:
            return
        try:
            r = run(['nmcli', 'radio', 'wifi', 'on' if deseado else 'off'], comprobar=False, timeout=10)
        except Exception:
            LOG.exception('no se pudo cambiar el estado de la radio wifi')
            return
        if r.returncode == 0:
            self._radio_wifi_aplicada = deseado
        else:
            LOG.warning('nmcli radio wifi %s → código %d: %s', 'on' if deseado else 'off',
                        r.returncode, (r.stderr or r.stdout).strip())

    # — bloqueador DNS: acciones del buzón de "sistema" (nunca mutan cfg) —
    def _ejecutar_accion_bloqueo(self, accion, d):
        """Ejecuta de verdad una acción bloqueo_* de sistema, ya validada
        por peticiones.py (ver ACCIONES_SISTEMA_BLOQUEO): a diferencia de
        bloqueo_config/bloqueo_lista, estas NUNCA mutan cfg.

        - bloqueo_actualizar: lanza router-bloqueo.service EN SEGUNDO PLANO
          (`systemctl --no-block start`, que sólo encola el trabajo y
          vuelve al instante — nunca bloquea este ciclo de routerd
          esperando a que una descarga de varios MiB termine). BAJA4
          (ronda 3): con `datos.forzar=true`, deja ANTES un marcador de
          un solo uso (`<bloqueo_cache>/.forzar`) que router_bloqueo.py
          lee y borra al arrancar, para saltarse la guarda de variación
          ±50% en esa pasada.
        - bloqueo_probar: consulta router_bloqueo.comprobar_dominio(), que
          sólo lee ficheros ya generados en disco — nunca hace una
          petición de red.

        Nunca lanza: un fallo aquí es un «ok=False» normal (H5)."""
        try:
            if accion == 'bloqueo_actualizar':
                if d.get('forzar'):
                    try:
                        escribir_atomico(os.path.join(self.rutas.get('bloqueo_cache', RUTAS['bloqueo_cache']),
                                                        '.forzar'), '1\n')
                    except OSError:
                        LOG.exception('no se pudo dejar el marcador de forzado para router_bloqueo')
                run(['systemctl', '--no-block', 'start', 'router-bloqueo.service'], comprobar=False)
                msg = 'Actualización de las listas de bloqueo solicitada'
                if d.get('forzar'):
                    msg += ' (forzada)'
                return True, msg
            if accion == 'bloqueo_probar':
                import router_bloqueo
                info = router_bloqueo.comprobar_dominio(d.get('dominio'), self.cfg,
                                                          {'cache_dir': self.rutas.get('bloqueo_cache',
                                                                                        RUTAS['bloqueo_cache'])})
                etiqueta = 'BLOQUEADO' if info['bloqueado'] else 'NO bloqueado'
                return True, '%s: %s' % (etiqueta, info['razon'])
            return False, 'acción de bloqueo desconocida'
        except Exception as e:
            LOG.exception('error ejecutando la acción de bloqueo %s', accion)
            return False, 'error interno ejecutando %s: %s' % (accion, e)

    # — WAN Wi-Fi: acciones del buzón que tocan NetworkManager de verdad —
    def _ejecutar_accion_wifi(self, accion, d):
        """Ejecuta de verdad una acción wifi_* ya validada por peticiones.py
        (d viene de ahí: ssid/clave/prioridad ya dentro de los rangos
        admitidos). Aquí sí se toca el sistema (nmcli, ficheros de
        NetworkManager) — nunca se guarda nada de esto en router.json (la
        clave NUNCA debe acabar ahí, ver docs/CONTRATO.md). Nunca lanza: un
        fallo aquí es un «ok=False» normal, no debe tirar el ciclo (H5).
        Si la Wi-Fi no está permitida ahora (preparación / migración en
        curso, punto 2), se rechaza sin tocar nada. Igual si no hay interfaz
        Wi-Fi configurada (wifi_wan.interfaz vacía = WAN Wi-Fi desactivada):
        nunca se llama a nmcli con un nombre de interfaz vacío."""
        if not self._wifi_permitida():
            return False, 'La WAN Wi-Fi no está disponible ahora (fase de preparación o migración en curso)'
        if not ((self.cfg.get('wifi_wan') or {}).get('interfaz') or ''):
            return False, 'La WAN Wi-Fi está desactivada: no hay interfaz Wi-Fi configurada (wifi_wan.interfaz vacía)'
        try:
            if accion == 'wifi_agregar':
                ok, msg = self._wifi_agregar(d['ssid'], d['clave'], d['prioridad'])
            elif accion == 'wifi_eliminar':
                ok, msg = self._wifi_eliminar(d['ssid'])
            elif accion == 'wifi_conectar':
                ok, msg = self._wifi_conectar(d['ssid'])
            elif accion == 'wifi_escanear':
                ok, msg = self._wifi_escanear()
            else:
                return False, 'acción wifi desconocida'
        except Exception as e:
            LOG.exception('error ejecutando la acción wifi %s', accion)
            return False, 'error interno ejecutando %s: %s' % (accion, e)
        if ok and accion in ('wifi_agregar', 'wifi_eliminar'):
            self._wifi_redes_cache_ts = 0.0   # punto 6: refresca la caché de redes guardadas YA
        return ok, msg

    def _wifi_agregar(self, ssid, clave, prioridad):
        interfaz = (self.cfg.get('wifi_wan') or {}).get('interfaz') or ''
        nombre, texto = generar_keyfile_wifi(ssid, clave, prioridad, interfaz)
        ruta = os.path.join(self.rutas['nm_system_connections'], nombre + '.nmconnection')
        try:
            escribir_atomico(ruta, texto, modo=0o600, fsync_dir=True)
        except OSError as e:
            LOG.error('no se pudo escribir el perfil wifi %s: %s', nombre, e)
            return False, 'no se pudo guardar el perfil de la red Wi-Fi'
        r = run(['nmcli', 'connection', 'load', ruta], comprobar=False, timeout=10)
        if r.returncode != 0:
            # Punto 5: si nmcli no lo aceptó, el keyfile no debe quedarse
            # huérfano en disco (con la clave dentro) sin ningún perfil NM
            # que lo respalde.
            try:
                os.unlink(ruta)
            except OSError:
                pass
            return False, 'nmcli no aceptó el perfil: %s' % (r.stderr or r.stdout).strip()
        return True, 'Red Wi-Fi «%s» guardada' % ssid

    def _wifi_eliminar(self, ssid):
        nombre = nombre_perfil_wifi(ssid)
        if not nombre.startswith('WAN-wifi-'):
            return False, 'nombre de perfil inesperado'   # defensivo; nunca debería pasar
        r = _nmcli_lectura(['nmcli', '-g', 'NAME', 'connection', 'show'], self._wifi_breaker)
        nombres = (r.stdout or '').splitlines() if r is not None else []
        if nombre not in nombres:
            return False, 'No hay ninguna red Wi-Fi guardada con ese SSID'
        rd = run(['nmcli', 'connection', 'delete', nombre], comprobar=False, timeout=10)
        if rd.returncode != 0:   # punto 8: comprobar el returncode del delete
            return False, 'No se pudo eliminar «%s»: %s' % (ssid, (rd.stderr or rd.stdout).strip())
        ruta = os.path.join(self.rutas['nm_system_connections'], nombre + '.nmconnection')
        try:
            os.unlink(ruta)
        except OSError:
            pass
        return True, 'Red Wi-Fi «%s» eliminada' % ssid

    def _wifi_conectar(self, ssid):
        """`nmcli -w 10 connection up`: si se agota esa espera (el teléfono
        puede tardar en aceptar la conexión), NO se trata como fallo
        definitivo — se responde ok «conectando…» (punto 6) y el panel verá
        el resultado de verdad en estado.json en los ciclos siguientes."""
        nombre = nombre_perfil_wifi(ssid)
        t0 = time.time()
        r = run(['nmcli', '-w', '10', 'connection', 'up', nombre], comprobar=False, timeout=14)
        tardo = time.time() - t0
        if r.returncode == 0:
            return True, 'Conectando a «%s»' % ssid
        if r.returncode == 124 or tardo >= 9:
            return True, 'Conectando a «%s»… (puede tardar unos segundos más)' % ssid
        return False, 'No se pudo conectar a «%s»: %s' % (ssid, (r.stderr or r.stdout).strip())

    def _wifi_escanear(self):
        """Lanza el rescan y responde YA (punto 6): un rescan de verdad
        puede tardar varios segundos, más de lo que el panel espera por la
        respuesta del buzón (~6 s, ver panel/routerpanel/buzon.py). Nunca
        bloquea aquí: la lista de resultados se lee sola en un ciclo
        posterior (_wifi_recoger_escaneo_pendiente), cuando el rescan ya ha
        tenido tiempo de terminar."""
        interfaz = (self.cfg.get('wifi_wan') or {}).get('interfaz') or ''
        run(['nmcli', 'device', 'wifi', 'rescan', 'ifname', interfaz], comprobar=False, timeout=4)
        self._wifi_escaneo_pendiente = True
        self._wifi_escaneo_pendiente_desde = time.time()
        return True, 'Escaneo lanzado; los resultados aparecerán en unos segundos'

    def _wifi_recoger_escaneo_pendiente(self):
        """Lee la lista de redes vistas tras un wifi_escanear, una vez que
        el rescan lanzado ha tenido unos segundos para terminar (punto 6:
        nunca se bloquea esperando al rescan). Se intenta una sola vez por
        petición; si falla o agota el tiempo, queda para el próximo
        wifi_escanear que pida el panel."""
        if not self._wifi_escaneo_pendiente:
            return
        if time.time() - (self._wifi_escaneo_pendiente_desde or 0) < 3:
            return
        self._wifi_escaneo_pendiente = False
        interfaz = (self.cfg.get('wifi_wan') or {}).get('interfaz') or ''
        r = _nmcli_lectura(['env', 'LC_ALL=C', 'nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY,CHAN',
                            'device', 'wifi', 'list', 'ifname', interfaz, '--rescan', 'no'],
                           self._wifi_breaker)
        if r is None or r.returncode != 0:
            return
        bloqueadas = (self.cfg.get('wifi_wan') or {}).get('ssid_bloqueadas') or []
        vistos = {}
        for red in parsear_escaneo_wifi(r.stdout):
            ssid = red['ssid']
            if not ssid:
                continue
            anterior = vistos.get(ssid)
            if anterior is None or red['senal'] > anterior['senal']:
                vistos[ssid] = dict(red, bloqueada=_ssid_esta_bloqueada(ssid, bloqueadas))
        self._wifi_escaneo = sorted(vistos.values(), key=lambda r: -r['senal'])[:40]
        self._wifi_escaneo_ts = ahora_iso()

    def _wifi_redes_guardadas(self):
        """[{ssid, prioridad}] de los perfiles propios (WAN-wifi-*) ya
        guardados, para el panel (estado.json). Nunca la clave: aquí no se
        pide `--show-secrets`, así que nmcli nunca la devuelve. El SSID
        viene de `nmcli -g`, que escapa igual que `-t` (punto 7): se
        desescapa con _parsear_linea_nmcli_t."""
        out = []
        r = _nmcli_lectura(['nmcli', '-t', '-f', 'NAME,TYPE', 'connection', 'show'], self._wifi_breaker)
        for linea in (r.stdout or '').splitlines() if r is not None else []:
            campos = _parsear_linea_nmcli_t(linea)
            if len(campos) < 2:
                continue
            nombre, tipo = campos[0], campos[1]
            if not nombre.startswith('WAN-wifi-') or tipo not in ('wifi', '802-11-wireless'):
                continue
            r_ssid = _nmcli_lectura(['nmcli', '-g', '802-11-wireless.ssid', 'connection', 'show', nombre],
                                     self._wifi_breaker)
            ssid = nombre
            if r_ssid is not None:
                texto = (r_ssid.stdout or '').strip()
                if texto:
                    ssid = _parsear_linea_nmcli_t(texto)[0] or nombre
            r_prio = _nmcli_lectura(['nmcli', '-g', 'connection.autoconnect-priority', 'connection', 'show', nombre],
                                     self._wifi_breaker)
            try:
                prioridad = int((r_prio.stdout or '').strip()) if r_prio is not None else 0
            except ValueError:
                prioridad = 0
            out.append({'ssid': ssid, 'prioridad': prioridad})
        return out

    def _wifi_redes_guardadas_cache(self):
        """Caché de _wifi_redes_guardadas(): se refresca sólo cada ~60 s, o
        justo después de un wifi_agregar/wifi_eliminar (punto 6) — nunca en
        cada publicación de estado.json (cada ~5 s)."""
        ahora = time.time()
        if ahora - self._wifi_redes_cache_ts >= 60:
            try:
                self._wifi_redes_cache = self._wifi_redes_guardadas()
            except Exception:
                LOG.exception('no se pudieron listar las redes Wi-Fi guardadas')
            self._wifi_redes_cache_ts = ahora
        return self._wifi_redes_cache

    def _wifi_senal_actual(self, ifname):
        """Nivel de señal (0-100) de la red Wi-Fi conectada ahora en
        `ifname`, o None (sin conexión, o nmcli no disponible/falla)."""
        r = _nmcli_lectura(['nmcli', '-t', '-f', 'ACTIVE,SIGNAL', 'device', 'wifi', 'list',
                            'ifname', ifname, '--rescan', 'no'], self._wifi_breaker)
        for linea in (r.stdout or '').splitlines() if r is not None else []:
            campos = _parsear_linea_nmcli_t(linea)
            if len(campos) >= 2 and campos[0] == 'yes':
                try:
                    return int(campos[1])
                except ValueError:
                    return None
        return None

    # — rutas por WAN (sólo producción) —
    def _rutas_wan(self, w, c):
        n = c['n']
        tabla, marca = TABLA_BASE + n, MARCA_BASE + n
        if not (w['ip'] and w['gw']):
            run(['ip', 'route', 'flush', 'table', str(tabla)], comprobar=False)
            self._redes_wan.pop(w['id'], None)
            return
        red = str(ipaddress.ip_interface(w['ip']).network)
        # LOW: si el teléfono ha vuelto con otra IP/subred (p. ej. otra red
        # móvil, otro operador), la tabla de esa WAN puede tener rutas de la
        # subred VIEJA que ya no tienen sentido (y que nft -c no detectaría).
        anterior = self._redes_wan.get(w['id'])
        if anterior is not None and anterior != red:
            run(['ip', 'route', 'flush', 'table', str(tabla)], comprobar=False)
        self._redes_wan[w['id']] = red
        run(['ip', 'route', 'replace', red, 'dev', w['ifname'], 'table', str(tabla)], comprobar=False)
        run(['ip', 'route', 'replace', 'default', 'via', w['gw'], 'dev', w['ifname'],
             'table', str(tabla)])
        self._regla(['fwmark', hex(marca), 'lookup', str(tabla)], PRIO_REGLA_MARCA + n)
        ip = w['ip'].split('/')[0]
        self._regla(['from', ip, 'lookup', str(tabla)], PRIO_REGLA_ORIGEN + n)

    def _regla(self, selector, prio):
        """Deja exactamente una regla con esa prioridad y ese selector.

        N13: se etiqueta con protocol 99 al crearla, y tanto la comparación
        con lo que ya hay como el borrado exigen ese mismo protocolo — así
        nunca se pisa ni se borra una regla ajena que por casualidad use la
        misma prioridad."""
        actual = run(['ip', '-j', 'rule', 'show', 'pref', str(prio)], comprobar=False).stdout
        try:
            existentes = json.loads(actual or '[]')
        except ValueError:
            existentes = []
        deseada = ' '.join(selector)
        for r in existentes:
            if not _es_regla_propia(r):
                continue
            texto = []
            if r.get('src') and r.get('src') != 'all':
                texto += ['from', r['src']]
            if r.get('fwmark'):
                texto += ['fwmark', r['fwmark']]
            texto += ['lookup', str(r.get('table'))]
            if ' '.join(texto) == deseada:
                return
        run(['ip', 'rule', 'del', 'pref', str(prio), 'protocol', str(PROTOCOLO_PROPIO)], comprobar=False)
        run(['ip', 'rule', 'add'] + selector + ['pref', str(prio), 'protocol', str(PROTOCOLO_PROPIO)])

    def _limpiar_wan(self, c):
        n = c['n']
        run(['ip', 'rule', 'del', 'pref', str(PRIO_REGLA_MARCA + n)], comprobar=False)
        run(['ip', 'rule', 'del', 'pref', str(PRIO_REGLA_ORIGEN + n)], comprobar=False)
        run(['ip', 'route', 'flush', 'table', str(TABLA_BASE + n)], comprobar=False)

    # — comprobación de Internet —
    def comprobar(self, w, c):
        """H5: se lanza en un hilo por WAN; si una revienta (p. ej. un `ip`
        que agota el tiempo y aquí sí comprobar=True), que quede en el log y
        las demás WAN sigan comprobándose — no puede tirar el ciclo entero."""
        try:
            self._comprobar(w, c)
        except Exception:
            LOG.exception('error comprobando la WAN %s (%s)', w['id'], w.get('ifname'))

    def _comprobar(self, w, c):
        mon = self.cfg['monitor']
        e = self.estados.setdefault(w['id'], EstadoWan())
        ok_lat = None
        perdida_ciclo = 100.0
        if w['ip'] and w['gw'] and w['operstate'] in ('up', 'unknown'):
            e.muestras_validas += 1   # ronda 4: lleva otro ciclo más con enlace válido comprobado
            marca = (MARCA_BASE + c['n']) if self.produccion() else None
            for destino in mon['destinos']:
                ok_lat, perdida_ciclo = ping(destino, w['ifname'], marca)
                if perdida_ciclo < 100.0:
                    break
        else:
            # Sin enlace válido (IP/gateway perdidos un momento): al volver
            # tiene que calentar otra vez — las 3 muestras son SEGUIDAS.
            e.muestras_validas = 0
        # A: ahora la pérdida es la de verdad de ESTE ciclo (0-100%, según
        # cuántos de los pings rápidos han contestado), no sólo 0/100 según
        # si hubo "algún" ping bueno — hace la puntuación más fina. LOW:
        # misma ventana de 10 muestras que e.latencias (antes 20) — no
        # tiene sentido que la pérdida "recuerde" el doble de ciclos que la
        # latencia al calcular la misma puntuación.
        e.perdidas = (e.perdidas + [perdida_ciclo])[-10:]
        # El ciclo es bueno si contestó algún ping, aunque no se haya podido
        # leer la latencia (red de seguridad M2 de ping(): latencia None con
        # pérdida 0). Sólo las latencias conocidas entran en la ventana.
        if perdida_ciclo < 100.0:
            if ok_lat is not None:
                e.latencias = (e.latencias + [ok_lat])[-10:]
            e.exitos += 1
            e.fallos = 0
            if not e.internet and e.exitos >= int(mon['exitos_alta']):
                e.internet = True
                e.ultimo_cambio = ahora_iso()
                self.oplog('sistema', 'wan_estado', {'wan': w['id']}, True,
                           '%s recupera Internet' % c['nombre'])
        else:
            e.fallos += 1
            e.exitos = 0
            if e.internet and e.fallos >= int(mon['fallos_caida']):
                e.internet = False
                e.ultimo_cambio = ahora_iso()
                self.oplog('sistema', 'wan_estado', {'wan': w['id']}, False,
                           '%s sin Internet (%d fallos seguidos)' % (c['nombre'], e.fallos))
        # tráfico
        rx = _leer('/sys/class/net/%s/statistics/rx_bytes' % w['ifname'])
        tx = _leer('/sys/class/net/%s/statistics/tx_bytes' % w['ifname'])
        t = time.time()
        if rx is not None and tx is not None:
            rx, tx = int(rx), int(tx)
            if e.t_bytes and e.rx is not None and t > e.t_bytes:
                dt = t - e.t_bytes
                e.rx_bps = max(0, int((rx - e.rx) * 8 / dt))
                e.tx_bps = max(0, int((tx - e.tx) * 8 / dt))
                # A: sólo se guarda muestra cuando hay un delta real (no en
                # la primera medida, que no tiene con qué compararse). H2:
                # YA NO se usa para puntuar (puntuacion_calidad() siempre
                # recibe capacidad=None) — se guarda sólo para mostrarla en
                # el panel (rx_bps/tx_bps ya la reflejan de todas formas).
                e.capacidades = (e.capacidades + [e.rx_bps + e.tx_bps])[-10:]
            e.rx, e.tx, e.t_bytes = rx, tx, t

    # — balanceo —
    def wans_activas(self):
        """[(c, w)] que entran en el balanceo según modo, habilitación e
        Internet. Ronda 4: además, `e.muestras_validas >=
        MUESTRAS_MINIMAS_BALANCEO` — nunca entra "recién descubierta",
        aunque el primer ping le saliera bien (ver la constante, arriba)."""
        cand = []
        for wid, w in self.presentes.items():
            c = self.cfg['wans'].get(wid)
            e = self.estados.get(wid)
            if (c and c.get('habilitada') and e and e.internet and w['ip'] and w['gw']
                    and e.muestras_validas >= MUESTRAS_MINIMAS_BALANCEO):
                cand.append((c, w))
        if self.cfg.get('modo') == 'respaldo' and cand:
            mejor = min(cand, key=lambda cw: (cw[0].get('prioridad', 9), cw[0]['n']))
            return [mejor]
        return cand

    # — pesos automáticos por calidad (fase 4, A) —
    def _actualizar_pesos_efectivos(self):
        """Calcula el peso EFECTIVO de cada WAN presente — el que de verdad
        decide elegir_wan y el que se publica en estado.json.

        - modo_pesos == "manual": el peso efectivo ES el que puso el admin
          (cfg['wans'][wid]['peso']), igual que antes de esta fase. Decisión
          deliberada y simple (documentada en el enunciado de la tarea): en
          auto, ese peso manual se IGNORA del todo, no se usa ni como
          multiplicador.
        - modo_pesos == "auto" (por defecto): se deriva SÓLO de latencia y
          pérdida —ver puntuacion_calidad()—, normalizando la mejor WAN
          presente a 100 y las demás proporcionalmente, con suelo y
          suavizado (ver las constantes PESO_MIN_*, SUAVIZADO_ALPHA,
          CAMBIO_MAX_POR_CICLO más arriba). H2: la capacidad observada
          (e.capacidades, máximo de rx_bps+tx_bps reciente) YA NO entra en
          la puntuación — crea un bucle de realimentación (la WAN con más
          tráfico mide más capacidad, puntúa más alto y se queda con todo
          el reparto) — por eso aquí se llama a puntuacion_calidad() con
          capacidad=None siempre; e.capacidades se sigue guardando (en
          _comprobar) sólo para mostrarla en el panel (rx_bps/tx_bps), no
          para pesar nada. self._pesos_nft (lo publicado como
          peso_efectivo) sólo se actualiza cuando el valor suavizado se
          aleja más de UMBRAL_REESCRITURA_NFT puntos del último aplicado,
          para no reescribir la tabla nft por un vaivén de un par de
          puntos. El "techo" que normaliza a 100 sólo mira WAN habilitadas
          (LOW): una WAN deshabilitada con muy buena puntuación no debe
          rebajar el peso relativo de las que sí están en el balanceo.
        """
        auto = self.cfg.get('modo_pesos', 'auto') == 'auto'
        puntuaciones = {}
        for wid, c in self.cfg.get('wans', {}).items():
            e = self.estados.get(wid)
            if wid not in self.presentes or e is None:
                continue
            if not auto:
                e.peso_efectivo = float(c.get('peso', 50))
                self._pesos_nft[wid] = e.peso_efectivo
                continue
            if not e.internet:
                # Sin Internet no entra en el balanceo (wans_activas ya la
                # descarta); se deja el último peso conocido sin tocar, en
                # vez de mandar al panel un 0 que no cuenta nada nuevo.
                continue
            lat = statistics.median(e.latencias) if e.latencias else None
            perdida = sum(e.perdidas) / len(e.perdidas) if e.perdidas else 0.0
            # H2: capacidad=None siempre — ver docstring arriba y la de
            # puntuacion_calidad().
            punt = puntuacion_calidad(lat, perdida, None) if lat is not None else None
            puntuaciones[wid] = (punt, lat, perdida, bool(c.get('habilitada', True)))
        if not auto:
            return
        # LOW: el techo que normaliza a 100 sólo considera WAN habilitadas.
        techo = max((p for p, _, _, habilitada in puntuaciones.values() if p is not None and habilitada),
                    default=None)
        for wid, (p, lat, perdida, _habilitada) in puntuaciones.items():
            e = self.estados[wid]
            if p is None or not techo:
                bruto = 50.0   # todavía sin ningún ping bueno esta vuelta: ni mejor ni peor que las demás
            else:
                bruto = 100.0 * p / techo
            degradada = (perdida > UMBRAL_PERDIDA_CRITICA_PCT or
                         (lat is not None and lat > UMBRAL_LATENCIA_CRITICA_MS))
            suelo = PESO_MIN_DEGRADADO if degradada else PESO_MIN_SUELO
            bruto = max(suelo, min(100.0, bruto))
            anterior = e.peso_efectivo if e.peso_efectivo is not None else bruto
            paso = max(-CAMBIO_MAX_POR_CICLO, min(CAMBIO_MAX_POR_CICLO, SUAVIZADO_ALPHA * (bruto - anterior)))
            e.peso_efectivo = max(suelo, min(100.0, anterior + paso))
            aplicado = self._pesos_nft.get(wid)
            if aplicado is None or abs(e.peso_efectivo - aplicado) > UMBRAL_REESCRITURA_NFT:
                self._pesos_nft[wid] = e.peso_efectivo

    def _peso_nft(self, wid, c):
        """Peso (entero >=1) que se escribe en el mapa de elegir_wan para la
        WAN `wid`: el último efectivo aplicado (self._pesos_nft), o el peso
        manual si todavía no se ha calculado ninguno (arranque)."""
        peso = self._pesos_nft.get(wid)
        if peso is None:
            peso = c.get('peso', 50)
        return max(1, int(round(peso)))

    def _elegir_wan_rapida(self, activas):
        """B/M1 (fase 4): número `n` de la WAN que usa elegir_wan_rt para el
        tráfico UDP en tiempo real (voz, vídeo, juego).

        M1: ya no se elige sólo por la latencia más baja — se usa
        puntuacion_calidad(lat, perdida, None) (latencia Y pérdida, sin
        capacidad — H2) para no mandar la voz/vídeo a una WAN con poca
        latencia pero mucha pérdida. Se excluyen las WAN DEGRADADAS
        (pérdida > UMBRAL_PERDIDA_CRITICA_PCT o latencia >
        UMBRAL_LATENCIA_CRITICA_MS) siempre que quede alguna alternativa
        sana; si todas están degradadas, se elige entre ellas igualmente
        (mejor una mala que ninguna).

        Con HISTÉRESIS (self._rapida_n): la WAN rápida sólo cambia si la
        actual deja de estar activa o pasa a degradada, o si la candidata
        mejora CLARAMENTE (latencia nueva < 0.7 × la actual Y al menos 30 ms
        menos; o, sin dato de latencia comparable, una puntuación bastante
        mejor — equivalente aproximado de esa misma mejora). Así un vaivén
        de unos pocos ms entre dos líneas parecidas no hace cambiar de WAN
        en tiempo real en mitad de una llamada entre ciclos (la afinidad de
        conntrack protege la llamada YA en curso, pero sin histéresis la
        PRÓXIMA llamada nueva podría ir de un lado a otro sin necesidad)."""
        if not activas:
            self._rapida_n = None
            return None
        datos = {}   # n -> (lat_o_None, perdida, puntuacion_o_None, degradada)
        for c, w in activas:
            e = self.estados.get(w['id'])
            lat = statistics.median(e.latencias) if e and e.latencias else None
            perdida = (sum(e.perdidas) / len(e.perdidas)) if e and e.perdidas else 0.0
            punt = puntuacion_calidad(lat, perdida, None) if lat is not None else None
            degradada = (perdida > UMBRAL_PERDIDA_CRITICA_PCT or
                         (lat is not None and lat > UMBRAL_LATENCIA_CRITICA_MS))
            datos[c['n']] = (lat, perdida, punt, degradada)

        sanas = [n for n, (_, _, _, degradada) in datos.items() if not degradada]
        universo = sanas or list(datos)
        con_punt = [(datos[n][2], n) for n in universo if datos[n][2] is not None]
        if con_punt:
            _mejor_punt, mejor_n = max(con_punt)
        else:
            # Nadie tiene todavía una latencia medida: una cualquiera (la de
            # menor n) es mejor que ninguna.
            mejor_n = min(universo)

        actual_n = self._rapida_n
        if actual_n is None or actual_n not in datos:
            self._rapida_n = mejor_n
            return mejor_n
        lat_actual, _perdida_actual, punt_actual, degradada_actual = datos[actual_n]
        # Sólo se huye de una WAN degradada si hay alguna sana; si todas lo
        # están, se aplica la histéresis normal para no ir y venir entre dos
        # líneas malas en cada ciclo.
        if degradada_actual and sanas:
            self._rapida_n = mejor_n
            return mejor_n
        if mejor_n == actual_n:
            return actual_n

        lat_mejor, _perdida_mejor, punt_mejor, _degradada_mejor = datos[mejor_n]
        mejora_clara = False
        if lat_mejor is not None and lat_actual is not None:
            mejora_clara = lat_mejor < 0.7 * lat_actual and (lat_actual - lat_mejor) > 30.0
        # La puntuación (latencia + pérdida) también cuenta: misma latencia
        # pero mucha menos pérdida es una mejora clara para la voz.
        if not mejora_clara and punt_mejor is not None and punt_actual is not None and punt_actual > 0:
            # Puntuación claramente mejor (mismo margen 0.7 que la latencia).
            mejora_clara = punt_mejor > punt_actual / 0.7
        if mejora_clara:
            self._rapida_n = mejor_n
            return mejor_n
        return actual_n

    def _texto_poblacion_sets(self):
        """Ronda 4 (e2e, fallo intermitente del paso 2): líneas nft para
        rellenar wan_ifs/wan_gws con lo que YA se conoce de self.presentes
        — se añaden a la MISMA transacción que instala/reinstala la tabla
        base (ver instalar_base()), para que nunca quede una ventana con
        esos sets recién creados y vacíos entre eso y que
        aplicar_balanceo() los repueble de verdad más adelante en el
        ciclo. Mismo criterio que reglas_balanceo() usa para wan_ifs
        (cualquier WAN presente con IP, no sólo las "activas" — el NAT/
        forward de salida no depende de estar en el balanceo)."""
        ifs = sorted({w['ifname'] for w in self.presentes.values() if w['ip']})
        gws = sorted({w['gw'] for w in self.presentes.values() if w['gw']})
        lineas = []
        if ifs:
            lineas.append('add element inet router wan_ifs { %s }' % ', '.join('"%s"' % i for i in ifs))
        if gws:
            lineas.append('add element inet router wan_gws { %s }' % ', '.join(gws))
        return ('\n'.join(lineas) + '\n') if lineas else ''

    def reglas_balanceo(self, activas):
        """Contenido nft que reescribe elegir_wan (mapa de pesos, A) y
        elegir_wan_rt (WAN de menor latencia para UDP en tiempo real, B)."""
        lineas = ['flush chain inet router elegir_wan',
                  'table inet router {', '  chain elegir_wan {']
        if activas:
            pesos = {w['id']: self._peso_nft(w['id'], c) for c, w in activas}
            total = sum(pesos.values())
            tramos, ini = [], 0
            for c, w in sorted(activas, key=lambda cw: cw[0]['n']):
                fin = ini + pesos[w['id']] - 1
                tramos.append('%d-%d : %s' % (ini, fin, hex(MARCA_BASE + c['n'])))
                ini = fin + 1
            lineas.append('    meta mark set numgen random mod %d map { %s }' % (total, ', '.join(tramos)))
            lineas.append('    ct mark set meta mark')
        else:
            # Sin ninguna WAN operativa: la conexión sigue la tabla main (si NM
            # tiene alguna ruta); no se marca para que no se quede atada.
            lineas.append('    meta mark set 0')
        lineas += ['  }', '}']
        # B: la misma idea para la WAN de menor latencia, pero sin mapa de
        # pesos — una sola marca fija (la afinidad de conntrack hace que un
        # cambio de WAN rápida sólo afecte a conexiones NUEVAS, nunca a una
        # llamada ya en curso).
        # _rapida_n se actualiza aquí, antes de saber si `nft -f` funciona; si
        # fallase, la firma distinta hace que se reintente en el siguiente ciclo.
        rapida_n = self._elegir_wan_rapida(activas)
        lineas += ['flush chain inet router elegir_wan_rt',
                   'table inet router {', '  chain elegir_wan_rt {']
        if rapida_n is not None:
            lineas.append('    meta mark set %s' % hex(MARCA_BASE + rapida_n))
            lineas.append('    ct mark set meta mark')
        else:
            lineas.append('    meta mark set 0')
        lineas += ['  }', '}']
        # Interfaces WAN válidas para forward/NAT.
        ifs = sorted({w['ifname'] for _, w in activas} |
                     {w['ifname'] for w in self.presentes.values() if w['ip']})
        lineas.append('flush set inet router wan_ifs')
        if ifs:
            lineas.append('add element inet router wan_ifs { %s }' % ', '.join('"%s"' % i for i in ifs))
        gws = sorted({w['gw'] for w in self.presentes.values() if w['gw']})
        lineas.append('flush set inet router wan_gws')
        if gws:
            lineas.append('add element inet router wan_gws { %s }' % ', '.join(gws))
        return '\n'.join(lineas) + '\n'

    def aplicar_balanceo(self):
        activas = self.wans_activas()
        actuales = {c['n'] for c, _ in activas}
        # H7: una WAN que SALE del balanceo (pierde Internet, se deshabilita,
        # el modo respaldo la deja fuera) puede tener conexiones ya abiertas
        # atadas a ella en conntrack (afinidad de conexión). Si no se tiran,
        # se quedan muertas en vez de rehacerse por otra WAN.
        #
        # N8: primero se aplica el mapa NUEVO (nft) y DESPUÉS se tira
        # conntrack de las que salen — al revés habría una ventana sin mapa
        # nuevo y sin las conexiones viejas, con el tráfico yendo a una WAN
        # indefinida mientras tanto.
        salieron = self.anteriores_activas - actuales
        texto = self.reglas_balanceo(activas)
        if texto != self.ultima_firma_balanceo:
            try:
                run(['nft', '-c', '-f', '-'], entrada=texto)
                run(['nft', '-f', '-'], entrada=texto)
                self.ultima_firma_balanceo = texto
                # LOW: el peso que se muestra en el log es el EFECTIVO
                # aplicado de verdad (_peso_nft) — en modo auto c['peso'] es
                # el manual, que ahí se ignora del todo, y mostrarlo
                # engañaría sobre qué reparto se acaba de instalar.
                LOG.info('balanceo: %s',
                         ', '.join('%s(p%s)' % (c['nombre'], self._peso_nft(w['id'], c)) for c, w in activas)
                         or 'ninguna WAN')
            except RuntimeError as e:
                LOG.error('no se pudo aplicar el balanceo: %s', e)
        if salieron and self.produccion():
            for n in salieron:
                run(['conntrack', '-D', '--mark', hex(MARCA_BASE + n)], comprobar=False)
        # H6/N6: se actualiza siempre, aunque conntrack falle (binario
        # ausente, tabla vacía…) — si no, se reintentaría cada ciclo y de
        # paso se perdería de vista qué WAN han salido de verdad.
        self.anteriores_activas = actuales

    def instalar_base(self):
        """Genera e instala las tablas nftables del router (nft_conf.py) y la
        regla de rutas común. Se rehace si cambia la config que las define.
        Se valida con `nft -c -f` sobre un TEMPORAL antes de tocar
        nft_base: si el fichero es inválido, ni siquiera se renombra encima
        del que ya hay en disco (H5) — importa porque
        router-firewall-arranque.service (M2) aplica ese fichero tal cual al
        arrancar, antes de que routerd llegue a correr."""
        import nft_conf
        # BAJA1 (ronda 4): mientras se está en fail-open NO se reinstala el
        # firewall sólo por reinstalar — pero SIEMPRE se comprueba que la
        # tabla "inet router" sigue existiendo (si no, se reinstala aunque
        # el texto generado no haya cambiado). Antes había aquí un atajo
        # que, mientras durase el fail-open, se saltaba ESTA comprobación
        # entera (no sólo el texto) — así que si alguien borraba la tabla a
        # mano durante un fail-open largo, el firewall se quedaba sin
        # reinstalar hasta salir de fail-open del todo. Ahora basta con la
        # comprobación de la tabla (de siempre, justo abajo) + comparar
        # `texto == self.base_texto` (más abajo): fail-open ya fuerza
        # `self.base_texto = None` al entrar/recaer, así que la primera
        # vuelta en fail-open reinstala una vez (con forzar_dns=False) y
        # las siguientes no reinstalan más mientras nada cambie — sin
        # necesitar un flag aparte.
        # M1 (de siempre): si alguien ha borrado la tabla a mano (p. ej.
        # `nft flush ruleset` por error), base_instalada dice que ya está
        # puesta pero no lo está: hay que reinstalar aunque el texto
        # generado no cambie.
        if self.base_instalada and run(['nft', 'list', 'table', 'inet', 'router'],
                                        comprobar=False).returncode != 0:
            LOG.warning('la tabla "inet router" ha desaparecido: se reinstala el firewall base')
            self.base_instalada = False
        bloqueo_cfg = self.cfg.get('bloqueo') or {}
        forzar_dns_deseado = bool(bloqueo_cfg.get('forzar_dns', True))
        bloquear_doh_deseado = bool(bloqueo_cfg.get('bloquear_doh', True))
        cfg_para_nft = self.cfg
        if self._bloqueo_fail_open:
            # M6 (fail-open): tras varios arranques fallidos seguidos de
            # dnsmasq, se desactiva la cadena redirigir_dns (si el propio
            # forzar_dns tuviera algo que ver con lo que está rompiendo
            # dnsmasq, mejor no insistir) hasta que vuelva a estar activo.
            # Nunca se muta self.cfg de verdad por esto — sólo la COPIA que
            # ve nft_conf.generar() para esta instalación.
            cfg_para_nft = copy.deepcopy(self.cfg)
            cfg_para_nft.setdefault('bloqueo', {})['forzar_dns'] = False
            forzar_dns_deseado = False
        try:
            texto = nft_conf.generar(cfg_para_nft)
        except (ValueError, KeyError) as e:
            LOG.error('config de firewall no válida, NO se instala: %s', e)
            self._firewall_error = 'config de firewall no válida: %s' % e
            return
        if self.base_instalada and texto == self.base_texto:
            return
        d = os.path.dirname(self.rutas['nft_base'])
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-nft-')
        # Ronda 4 (e2e, fallo intermitente del paso 2): reinstalar la tabla
        # (aquí, SIEMPRE que se llega hasta este punto) la recrea con
        # wan_ifs/wan_gws VACÍOS — si sólo se repoblaran más adelante en
        # este mismo ciclo (aplicar_balanceo, al final), habría una
        # ventana real sin reenvío/NAT para cualquier paquete que llegara
        # justo entonces. Se rellenan aquí, en la MISMA transacción nft
        # que crea la tabla, con el mejor dato disponible ya (self.presentes
        # de la vuelta anterior) — aplicar_balanceo() los sobrescribirá de
        # todas formas en cuanto conozca las WAN de ESTE ciclo. `texto`
        # (sin esto) sigue siendo lo que se compara/guarda en
        # self.base_texto: la población de los sets cambia con la
        # topología, no con la política del firewall, y no debe forzar
        # una reinstalación en cada vuelta por sí sola.
        texto_a_aplicar = texto + self._texto_poblacion_sets()
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(texto_a_aplicar)
                f.flush()
                os.fsync(f.fileno())
            run(['nft', '-c', '-f', tmp])
        except RuntimeError as e:
            os.unlink(tmp)
            LOG.error('firewall base no válido, NO se instala: %s', e)
            self._firewall_error = 'firewall base no válido: %s' % e
            return
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.rutas['nft_base'])
        try:
            run(['nft', '-f', self.rutas['nft_base']])
        except RuntimeError as e:
            LOG.error('firewall base validado pero no se pudo aplicar: %s', e)
            self._firewall_error = 'firewall base validado pero no se pudo aplicar: %s' % e
            return
        self.base_instalada, self.base_texto = True, texto
        self._firewall_error = None   # N9: ya instalado; se limpia el error anterior, si lo había
        self.ultima_firma_balanceo = None   # la cadena elegir_wan vuelve vacía
        # Lo que tiene ruta directa en main (LAN, red de cada teléfono) se
        # resuelve en main antes que en las tablas por WAN: sin esto, una
        # conexión marcada para la WAN2 hacia el teléfono de la WAN1 saldría
        # por la puerta equivocada.
        self._regla(['lookup', 'main', 'suppress_prefixlength', '0'], 900)
        # BAJA10/11: al ACTIVARSE forzar_dns/bloquear_doh (transición de
        # False/desconocido a True — nunca al desactivarse), se vacía el
        # conntrack de lo que esas reglas nuevas deben empezar a coger YA:
        # una conexión UDP/53 o TCP/UDP 853 que ya estuviera "established"
        # desde ANTES de instalar la regla seguiría pasando de largo (el
        # "ct state established accept" de siempre) hasta que expirase por
        # sí sola, dejando un hueco de minutos en el que forzar_dns/
        # bloquear_doh no se aplica de verdad a esas conexiones concretas.
        if forzar_dns_deseado and self._forzar_dns_anterior is False:
            run(['conntrack', '-D', '-p', 'udp', '--dport', '53'], comprobar=False)
            run(['conntrack', '-D', '-p', 'tcp', '--dport', '53'], comprobar=False)
        if bloquear_doh_deseado and self._bloquear_doh_anterior is False:
            run(['conntrack', '-D', '-p', 'tcp', '--dport', '853'], comprobar=False)
            run(['conntrack', '-D', '-p', 'udp', '--dport', '853'], comprobar=False)
        self._forzar_dns_anterior = forzar_dns_deseado
        self._bloquear_doh_anterior = bloquear_doh_deseado
        # Firewall con reglas propias (FIREWALL_PLAN.md): al aplicar una
        # regla bloquear/rechazar, se vacía de conntrack las conexiones del
        # origen para que el bloqueo valga YA (igual que DNS/DoT más arriba).
        # Sólo se hace UNA vez por regla (ids en self._fw_conntrack_flushed);
        # si la regla se deshabilita o se borra, se olvida para que al
        # reactivarla se vuelva a vaciar.
        self._vaciar_conntrack_reglas_fw()

    def _origenes_conntrack_regla(self, regla, grupos_por_id):
        """Devuelve la lista de IPs/redes origen para `conntrack -D -s` de una
        regla (MEDIUM-3). ip/red → la propia; grupo ip → cada miembro;
        mac (o grupo mac) → la IP resuelta con `ip neigh`; cualquiera → la
        red LAN (LOW-3: nunca un conntrack -D sin -s, que vaciaría también
        las conexiones del propio router). Nunca devuelve []: siempre hay
        un -s que acota el vaciado."""
        origen = regla.get('origen') or {}
        tipo = origen.get('tipo')
        if tipo == 'ip':
            return [str(origen.get('valor'))]
        if tipo == 'red':
            return [str(origen.get('valor'))]
        if tipo == 'mac':
            return self._ips_desde_mac([str(origen.get('valor'))]) or \
                [str(ipaddress.ip_network(self.cfg['lan']['red']))]
        if tipo == 'grupo':
            g = grupos_por_id.get(origen.get('valor'))
            if g is None:
                return [str(ipaddress.ip_network(self.cfg['lan']['red']))]
            miembros = [str(m) for m in (g.get('miembros') or [])]
            if g.get('tipo') == 'ip':
                return miembros or [str(ipaddress.ip_network(self.cfg['lan']['red']))]
            return self._ips_desde_mac(miembros) or \
                [str(ipaddress.ip_network(self.cfg['lan']['red']))]
        # «cualquiera»: -s <red LAN>, nunca un vaciado sin filtro.
        return [str(ipaddress.ip_network(self.cfg['lan']['red']))]

    def _ips_desde_mac(self, macs):
        """Resuelve MACs a IPs con `ip neigh` (MEDIUM-3). Devuelve sólo las
        IPv4 encontradas; los vecinos IPv6 se ignoran (LOW-4). Si `ip neigh`
        falla o no hay vecinos, []."""
        ips = []
        try:
            r = run(['ip', 'neigh', 'show'], comprobar=False)
        except Exception:
            return []
        if r.returncode != 0:
            return []
        for linea in (r.stdout or '').splitlines():
            partes = linea.split()
            if not partes:
                continue
            direccion = partes[0]
            # LOW-4: ip neigh publica también vecinos IPv6; sólo valen IPv4.
            if ':' in direccion:
                continue
            try:
                i_lladdr = partes.index('lladdr')
            except ValueError:
                continue
            if i_lladdr + 1 < len(partes) and partes[i_lladdr + 1].lower() in macs:
                ips.append(direccion)
        return ips

    def _huella_regla_conntrack(self, regla, grupos_por_id, ids_permitir_previos):
        """Huella estable de los campos de una regla que afectan al vaciado
        de conntrack (MEDIUM-3): al editar la regla (misma id, huella
        distinta) se vuelve a vaciar. Se usa como segunda parte de la clave
        de self._fw_conntrack_flushed.

        LOW-2: incluye los miembros resueltos del grupo (si el grupo gana o
        pierde miembros hay que re-vaciar) y las ids de las reglas «permitir»
        que van por encima de esta — si se borra o se mueve un permitir que
        eclipsaba a este bloquear, la huella cambia y se re-vacía."""
        origen = regla.get('origen') or {}
        destino = regla.get('destino') or {}
        partes = [
            str(origen.get('tipo')), str(origen.get('valor')),
            str(destino.get('tipo')), str(destino.get('valor')),
            str(regla.get('protocolo')),
            ','.join('%d-%d' % (p.get('desde'), p.get('hasta'))
                     for p in (regla.get('puertos') or [])),
        ]
        # LOW-2: miembros del grupo (origen y destino) en la huella.
        for ep in (origen, destino):
            if ep.get('tipo') == 'grupo':
                g = grupos_por_id.get(ep.get('valor'))
                miembros = sorted(str(m) for m in ((g or {}).get('miembros') or []))
                partes.append('m:' + ','.join(miembros))
        # LOW-2: qué permitir nos eclipsaban (ids, en orden de la lista).
        partes.append('p:' + ','.join(ids_permitir_previos))
        return '|'.join(partes)

    def _rangos_puertos_conntrack(self, puertos):
        """Fusiona los rangos de puertos de una regla en el mínimo de tramos
        contiguos (HIGH-A): 8000-8001 y 8002-8002 → un solo 8000-8002."""
        tramos = sorted(
            (int(p.get('desde')), int(p.get('hasta')))
            for p in (puertos or []) if p.get('desde') is not None)
        fusionados = []
        for desde, hasta in tramos:
            if fusionados and desde <= fusionados[-1][1] + 1:
                fusionados[-1] = (fusionados[-1][0], max(fusionados[-1][1], hasta))
            else:
                fusionados.append((desde, hasta))
        return fusionados

    def _planificar_conntrack_regla(self, regla, grupos_por_id):
        """Construye el mínimo de llamadas `conntrack -D` para una regla
        bloquear/rechazar (HIGH-A). Una por origen y protocolo; destino y
        puertos sólo se añaden si no multiplican las llamadas. Devuelve una
        lista de listas de argumentos."""
        origenes = self._origenes_conntrack_regla(regla, grupos_por_id)
        protos = {'tcp': ['tcp'], 'udp': ['udp'], 'icmp': ['icmp'],
                  'tcp_udp': ['tcp', 'udp']}.get(regla.get('protocolo'), [])
        destino = regla.get('destino') or {}
        destinos = []
        if destino.get('tipo') == 'ip':
            destinos = [str(destino.get('valor'))]
        elif destino.get('tipo') == 'red':
            destinos = [str(destino.get('valor'))]
        elif destino.get('tipo') == 'grupo':
            g = grupos_por_id.get(destino.get('valor'))
            if g is not None and g.get('tipo') == 'ip':
                destinos = [str(m) for m in (g.get('miembros') or [])]
        rangos = self._rangos_puertos_conntrack(regla.get('puertos'))
        if not origenes:
            origenes = [str(ipaddress.ip_network(self.cfg['lan']['red']))]
        if not protos:
            protos = [None]
        llamadas = []
        for s in origenes:
            for p in protos:
                # Preciso sólo si un único destino y un único rango: así no
                # se multiplica el número de llamadas (HIGH-A).
                if len(destinos) <= 1 and len(rangos) <= 1:
                    args = ['conntrack', '-D', '-s', s]
                    if p is not None:
                        args += ['-p', p]
                    if destinos:
                        args += ['-d', destinos[0]]
                    if rangos:
                        lo, hi = rangos[0]
                        args += ['--dport', str(lo) if lo == hi else '%d-%d' % (lo, hi)]
                    llamadas.append(args)
                else:
                    # Agrupado: una por origen y protocolo, sin filtro de
                    # puerto/destino (conntrack no acepta listas de destinos).
                    llamadas.append(['conntrack', '-D', '-s', s]
                                    + (['-p', p] if p is not None else []))
        return llamadas

    def _vaciar_conntrack_reglas_fw(self):
        """Vacía conntrack para las conexiones que cada regla bloquear/
        rechazar habilitada debe empezar a coger YA (MEDIUM-3). HIGH-A: el
        vaciado se agrupa en el mínimo de llamadas (una por origen y
        protocolo, con rangos de puertos), con TOPE de llamadas por ciclo y
        presupuesto de tiempo muy por debajo del watchdog de 60 s. Si se
        supera el tope, vaciado más grueso por origen (sin proto/puerto/
        destino) y aviso en el log. Nunca bloquea el ciclo: cada llamada
        lleva timeout corto y se corta al agotar el presupuesto. LOW-2: la
        huella incluye los miembros del grupo y las ids de los «permitir»
        que iban por encima. LOW-4: el código de salida de cada conntrack -D
        queda en el log. Nunca se emite un conntrack -D sin -s."""
        fw = self.cfg.get('firewall') or {}
        reglas = fw.get('reglas') or []
        grupos_por_id = {g.get('id'): g for g in (fw.get('grupos') or [])}
        vivas = set()
        t_inicio = time.monotonic()
        llamadas_hechas = 0
        # Reglas «permitir» vistas hasta ahora (en orden de la lista): su
        # presencia forma parte de la huella de los bloquear posteriores.
        ids_permitir_previos = []
        for regla in reglas:
            rid = regla.get('id')
            accion = regla.get('accion')
            if accion == 'permitir' and regla.get('habilitada', True) and rid:
                ids_permitir_previos.append(str(rid))
            if not rid or not regla.get('habilitada', True):
                continue
            if accion not in ('bloquear', 'rechazar'):
                continue
            clave = (rid, self._huella_regla_conntrack(
                regla, grupos_por_id, ids_permitir_previos))
            vivas.add(clave)
            if clave in self._fw_conntrack_flushed:
                continue
            llamadas = self._planificar_conntrack_regla(regla, grupos_por_id)
            # HIGH-A: tope de llamadas — si el plan se pasa, vaciado más
            # grueso por origen y aviso.
            if len(llamadas) > MAX_CONNTRACK_LLAMADAS_CICLO:
                origenes = self._origenes_conntrack_regla(regla, grupos_por_id)
                llamadas = [['conntrack', '-D', '-s', s] for s in origenes]
                if len(llamadas) > MAX_CONNTRACK_LLAMADAS_CICLO:
                    llamadas = llamadas[:MAX_CONNTRACK_LLAMADAS_CICLO]
                LOG.warning(
                    'firewall %s: vaciado de conntrack agrupado por origen '
                    '(se superó el tope de %d llamadas); %d llamadas planificadas',
                    rid, MAX_CONNTRACK_LLAMADAS_CICLO, len(llamadas))
            for args in llamadas:
                if llamadas_hechas >= MAX_CONNTRACK_LLAMADAS_CICLO:
                    LOG.warning(
                        'firewall: tope de %d llamadas de conntrack -D por ciclo '
                        'alcanzado; el resto queda para el siguiente ciclo',
                        MAX_CONNTRACK_LLAMADAS_CICLO)
                    break
                if time.monotonic() - t_inicio >= MAX_CONNTRACK_SEGUNDOS:
                    LOG.warning(
                        'firewall: presupuesto de %.1fs de vaciado de conntrack '
                        'agotado; el resto queda para el siguiente ciclo',
                        MAX_CONNTRACK_SEGUNDOS)
                    break
                r = run(args, comprobar=False, timeout=MAX_CONNTRACK_TIMEOUT_S)
                llamadas_hechas += 1
                # LOW-4: el código de salida queda en el log (antes se
                # silenciaba con comprobar=False y no se veía nada).
                if r.returncode == 0:
                    LOG.debug('conntrack -D → código de salida 0 (%s)',
                              ' '.join(args[1:]))
                else:
                    LOG.warning('conntrack -D %s → código de salida %d: %s',
                                ' '.join(args[1:]), r.returncode,
                                (r.stderr or '').strip())
            else:
                # Sólo se marca como vaciada si se completó el plan entero.
                self._fw_conntrack_flushed.add(clave)
                continue
            # Se cortó por tope/tiempo: NO se marca, para retomarla luego.
        # Reglas deshabilitadas, borradas o editadas: se olvidan para que al
        # volver a activarlas (o al editarlas) se vuelva a vaciar.
        self._fw_conntrack_flushed &= vivas

    def _validar_fw_con_nft(self):
        """HIGH-3: valida que la config de firewall actual genera un texto
        nft que `nft -c -f` acepta. Devuelve (ok, mensaje). Se llama desde
        atender_buzon ANTES de _guardar_config para las acciones fw_*: si
        el texto es inválido, la petición se responde con error y la config
        no se guarda (el llamador recarga la anterior de disco)."""
        import nft_conf
        try:
            texto = nft_conf.generar(self.cfg)
        except (ValueError, KeyError) as e:
            return False, 'config de firewall no válida: %s' % e
        d = os.path.dirname(self.rutas['nft_base'])
        try:
            os.makedirs(d, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-nft-val-')
        except OSError as e:
            return False, 'no se pudo preparar la validación nft: %s' % e
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(texto)
                f.flush()
                os.fsync(f.fileno())
            run(['nft', '-c', '-f', tmp])
        except RuntimeError as e:
            return False, 'nft rechaza la configuración: %s' % e
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return True, ''

    # — estado para el panel —
    def _config_para_panel(self):
        """`config` de estado.json: copia de lo editable de router.json,
        para pintar formularios. `bloqueo_version` (petición del panel,
        ronda 3): huella de la sección 'bloqueo' SIN lista_blanca/
        lista_negra — control de concurrencia optimista para
        bloqueo_config (ver router_bloqueo.calcular_version_bloqueo,
        compartida con peticiones.py para que publicar y validar nunca
        puedan calcular la "version" de dos formas distintas).
        `firewall` (FIREWALL_PLAN.md): copia de la sección firewall +
        `firewall_error` (str|null) + `firewall_aciertos` ({id: paquetes})
        leído de los contadores de cada regla en nft."""
        config = {k: self.cfg[k] for k in ('lan', 'dhcp', 'dns', 'monitor', 'reservas', 'etiquetas')}
        bloqueo = self.cfg.get('bloqueo') or {}
        config['bloqueo'] = bloqueo
        try:
            import router_bloqueo
            config['bloqueo_version'] = router_bloqueo.calcular_version_bloqueo(bloqueo)
        except Exception:
            LOG.exception('no se pudo calcular bloqueo_version')
            config['bloqueo_version'] = None
        firewall = copy.deepcopy(self.cfg.get('firewall') or {'version': 1, 'grupos': [], 'reglas': []})
        firewall.setdefault('version', 1)
        firewall.setdefault('grupos', [])
        firewall.setdefault('reglas', [])
        firewall['firewall_error'] = self._firewall_error
        firewall['firewall_aciertos'] = self._leer_aciertos_firewall()
        config['firewall'] = firewall
        return config

    def _leer_aciertos_firewall(self):
        """Lee los contadores de cada regla de usuario en `reenvio`
        (`nft -j list chain inet router reenvio`) y devuelve
        {id_regla: paquetes}. Tolerante a errores: si nft falla, no está
        instalado o la salida no se puede parsear, devuelve {} sin tirar el
        ciclo. Timeout corto (3 s) para no alargar la publicación."""
        try:
            r = run(['nft', '-j', 'list', 'chain', 'inet', 'router', 'reenvio'],
                    comprobar=False, timeout=3)
            if r.returncode != 0:
                return {}
            datos = json.loads(r.stdout or '{}')
        except Exception:
            return {}
        aciertos = {}
        try:
            for entrada in datos.get('nftables') or []:
                regla = entrada.get('rule')
                if not isinstance(regla, dict):
                    continue
                comentario = regla.get('comment') or ''
                if not comentario.startswith('fw:'):
                    continue
                rid = comentario[3:]
                paquetes = 0
                for expr in regla.get('expr') or []:
                    contador = expr.get('counter') if isinstance(expr, dict) else None
                    if isinstance(contador, dict):
                        paquetes += int(contador.get('packets', 0))
                aciertos[rid] = paquetes
        except Exception:
            LOG.exception('no se pudieron leer los contadores del firewall')
        return aciertos

    def _estado_wifi_ap(self):
        """AP1: sección 'wifi_ap' de estado.json, para el panel. Con el AP
        DESHABILITADO (o con 'interfaz' vacía, que cuenta como desactivado
        igual que en wifi_wan) sólo se publica {'habilitado': False} y no
        se ejecuta NADA por él. Con el AP habilitado:
            {'habilitado': True, 'interfaz', 'ssid' (se lee de la config de
             hostapd con wifi_ap.leer_ssid, SIN la clave),
             'activo' (¿está vivo router-ap.service?),
             'clientes' (número de estaciones conectadas, wifi_ap.clientes)}
        Las lecturas que cuestan procesos externos (systemctl is-active, iw
        station dump) van CACHÉADAS durante 30 s y con timeout: nunca
        bloquean el ciclo, ni aunque el comando se cuelgue. Nunca lanza:
        un fallo deja None/''/False en la sección, no tira publicar()."""
        ap = self.cfg.get('wifi_ap') or {}
        if not ap.get('habilitado') or not (ap.get('interfaz') or '').strip():
            return {'habilitado': False}
        interfaz = ap.get('interfaz').strip()
        cache = self._wifi_ap_cache
        if (cache and cache.get('interfaz') == interfaz
                and time.time() - cache.get('ts', 0.0) < 30.0):
            return copy.deepcopy(cache['datos'])
        datos = {'habilitado': True, 'interfaz': interfaz,
                 'ssid': '', 'activo': False, 'clientes': None}
        try:
            import wifi_ap
        except ImportError:
            LOG.error('wifi_ap.habilitado pero el módulo wifi_ap no se pudo importar')
        else:
            try:
                datos['ssid'] = wifi_ap.leer_ssid() or ''
            except Exception:
                LOG.exception('no se pudo leer el SSID del AP (wifi_ap.leer_ssid)')
            try:
                datos['clientes'] = len(wifi_ap.clientes(interfaz))
            except Exception:
                LOG.exception('no se pudieron contar los clientes del AP (wifi_ap.clientes)')
        try:
            r = run(['systemctl', 'is-active', 'router-ap.service'], comprobar=False, timeout=5)
            datos['activo'] = (r.stdout or '').strip() == 'active'
        except Exception:
            LOG.exception('no se pudo consultar si el AP está activo (router-ap.service)')
        self._wifi_ap_cache = {'ts': time.time(), 'interfaz': interfaz,
                               'datos': copy.deepcopy(datos)}
        return datos

    def publicar(self):
        lan = self.cfg['lan']
        wans = []
        ids = set(self.cfg['wans']) | set(self.presentes)
        activas = {c['n'] for c, _ in self.wans_activas()}
        for wid in sorted(ids, key=lambda i: self.cfg['wans'].get(i, {}).get('n', 99)):
            c = self.cfg['wans'].get(wid, {})
            w = self.presentes.get(wid)
            e = self.estados.get(wid) or EstadoWan()
            lat = round(sum(e.latencias) / len(e.latencias), 1) if e.latencias else None
            wans.append({
                'id': wid, 'nombre': c.get('nombre', wid),
                'interfaz': w['ifname'] if w else None,
                'telefono': w['telefono'] if w else None,
                'ip': w['ip'] if w else None, 'gateway': w['gw'] if w else None,
                'tethering': bool(w and w['ip'] and w['gw']),
                'internet': bool(w and e.internet),
                'latencia_ms': lat if w else None,
                'perdida_pct': round(sum(e.perdidas) / len(e.perdidas)) if (w and e.perdidas) else None,
                'habilitada': bool(c.get('habilitada', True)),
                # En preparación nada se balancea de verdad (no hay nftables).
                'en_balanceo': self.produccion() and c.get('n') in activas,
                'peso': c.get('peso', 50), 'prioridad': c.get('prioridad', 1),
                # A: el peso que de verdad usa (o usaría) elegir_wan — en
                # manual es el 'peso' de arriba; en auto, el calculado.
                'peso_efectivo': (round(self._pesos_nft[wid]) if wid in self._pesos_nft
                                  else c.get('peso', 50)) if w else None,
                'rx_bytes': e.rx or 0, 'tx_bytes': e.tx or 0,
                'rx_bps': e.rx_bps, 'tx_bps': e.tx_bps,
                'ultimo_cambio': e.ultimo_cambio, 'presente': bool(w),
            })
        lan_ip = None
        r = run(['ip', '-j', '-4', 'addr', 'show', 'dev', lan['interfaz']], comprobar=False)
        try:
            for a in json.loads(r.stdout or '[]'):
                for i in a.get('addr_info', []):
                    lan_ip = '%s/%s' % (i['local'], i['prefixlen'])
        except ValueError:
            pass
        vecinos = {}
        r = run(['ip', '-j', 'neigh', 'show', 'dev', lan['interfaz']], comprobar=False)
        try:
            red = ipaddress.ip_network(lan['red'])
            for v in json.loads(r.stdout or '[]'):
                if v.get('lladdr') and ipaddress.ip_address(v['dst']) in red:
                    vecinos[v['lladdr'].lower()] = (v.get('state') or ['?'])[0]
        except ValueError:
            pass
        servicios = {
            'dnsmasq': run(['systemctl', 'is-active', 'dnsmasq'], comprobar=False).stdout.strip(),
            'nftables_router': run(['nft', 'list', 'table', 'inet', 'router'], comprobar=False).returncode == 0,
            'balanceo': bool(activas) and self.produccion(),
            'routerd': 'active',
        }
        # N9: en producción sin el firewall base instalado se falla cerrado
        # (ni rutas por WAN ni dnsmasq ese ciclo) — el panel necesita verlo.
        if self.produccion() and not self.base_instalada and self._firewall_error:
            servicios['firewall_error'] = self._firewall_error
        # M6/M1 (ronda 3): fail-open del bloqueador DNS — el panel debe
        # poder avisar de que el servers-file está vacío/sin log/sin
        # forzar_dns a propósito (no es un fallo de router.json ni algo
        # que el admin tenga que "arreglar" con el panel: se resuelve solo
        # en cuanto dnsmasq lleve el tiempo estable que toque). Siempre
        # presente (nunca se omite la clave) para que el panel no tenga
        # que comprobar su existencia.
        dns_emergencia = {
            'activo': self._bloqueo_fail_open,
            'desde': (datetime.fromtimestamp(self._bloqueo_fail_open_desde, timezone.utc).isoformat(timespec='seconds')
                      if self._bloqueo_fail_open_desde else None),
            'motivo': ('dnsmasq lleva varios arranques fallidos seguidos: servers-file vaciado, '
                       'log de consultas DNS y forzar_dns desactivados hasta que se estabilice'
                       if self._bloqueo_fail_open else None),
            # M2 (ronda 4): nivel de backoff (sube con cada recaída dentro
            # de 24 h desde la última salida, baja uno tras 24 h sanas
            # seguidas) y cuándo fue la última salida — persisten en
            # RUTAS['bloqueo_fail_open_estado'], sobreviven a un reinicio
            # de routerd.
            'nivel_backoff': self._bloqueo_backoff_nivel,
            'salida_anterior': (datetime.fromtimestamp(self._bloqueo_salida_desde, timezone.utc)
                                 .isoformat(timespec='seconds') if self._bloqueo_salida_desde else None),
        }
        wifi_cfg = self.cfg.get('wifi_wan') or {}
        wifi_if = wifi_cfg.get('interfaz')
        wifi_w = self.presentes.get('wifi-%s' % wifi_if) if wifi_if else None
        redes_guardadas, senal = [], None
        # Punto 2: en preparación o con una migración en curso no se toca
        # NADA Wi-Fi, ni siquiera estas lecturas de sólo-consulta. Punto 6:
        # redes guardadas con caché (no una lectura nmcli en cada
        # publicación, cada ~5 s).
        if self._wifi_permitida():
            try:
                redes_guardadas = self._wifi_redes_guardadas_cache()
            except Exception:
                LOG.exception('no se pudieron listar las redes Wi-Fi guardadas')
            if wifi_w and wifi_if:
                try:
                    senal = self._wifi_senal_actual(wifi_if)
                except Exception:
                    LOG.exception('no se pudo leer la señal Wi-Fi actual')
        estado_wifi = {
            'habilitada': bool(wifi_cfg.get('habilitada')),
            'interfaz': wifi_if,
            'presente': bool(wifi_if and os.path.exists('/sys/class/net/%s' % wifi_if)),
            'radio': self._radio_wifi_aplicada,
            'conectada_a': wifi_w['telefono'] if wifi_w else None,
            'senal': senal,
            'redes': redes_guardadas,
            'escaneo': self._wifi_escaneo,
            'escaneo_ts': self._wifi_escaneo_ts,
            'bloqueadas': list(wifi_cfg.get('ssid_bloqueadas') or []),
        }
        estado = {
            'generado': ahora_iso(), 'uptime_s': int(float((_leer('/proc/uptime', '0') or '0').split()[0])),
            'fase': self.fase, 'modo': self.cfg.get('modo'),
            'modo_pesos': self.cfg.get('modo_pesos', 'auto'),
            'lan': {'interfaz': lan['interfaz'], 'ip': lan_ip,
                    'activa': bool(lan_ip and lan_ip.split('/')[0] == lan['ip'])},
            'servicios': servicios,
            'internet': any(x['internet'] for x in wans),
            'wans': wans,
            # 'lan' = la red CONFIGURADA (aunque el RJ45 aún no esté levantado):
            # el panel valida reservas y rangos contra ella.
            'config': self._config_para_panel(),
            'vecinos': vecinos,
            'wifi': estado_wifi,
            'wifi_ap': self._estado_wifi_ap(),
            'dns_emergencia': dns_emergencia,
        }
        escribir_atomico(self.rutas['estado'], json.dumps(estado, ensure_ascii=False, indent=1))
        # C1: el NAT ya vive dentro de «inet router» (nat_salida); ya no hay
        # tabla «ip router_nat» que listar aparte.
        fw = run(['nft', 'list', 'table', 'inet', 'router'], comprobar=False)
        texto = fw.stdout if fw.returncode == 0 else \
            '# El firewall del router no está instalado (fase: %s).\n' % self.fase
        escribir_atomico(self.rutas['firewall'], texto)

    # — registro —
    def oplog(self, usuario, accion, datos, ok, mensaje):
        # H4: una petición maliciosa/rota podría traer un «datos» enorme;
        # nunca escribir eso tal cual en el oplog (crecimiento sin límite,
        # ficheros de registro inmanejables).
        try:
            texto_datos = json.dumps(datos, ensure_ascii=False)
        except (TypeError, ValueError):
            texto_datos = None
        if texto_datos is None or len(texto_datos.encode('utf-8')) > 2048:
            datos = {'_recortado': True}
        linea = json.dumps({'fecha': ahora_iso(), 'usuario': usuario, 'accion': accion,
                            'datos': datos, 'ok': ok, 'mensaje': mensaje}, ensure_ascii=False)
        os.makedirs(os.path.dirname(self.rutas['oplog']), exist_ok=True)
        with open(self.rutas['oplog'], 'a') as f:
            f.write(linea + '\n')
        (LOG.info if ok else LOG.warning)('%s: %s', accion, mensaje)

    # — buzón de peticiones —
    def _uid_routerpanel(self):
        """uid esperado del propietario de las peticiones del buzón (H4): el
        del usuario 'routerpanel' si existe en el sistema; si no (pruebas en
        netns, sin ese usuario) el propietario del propio directorio del
        buzón, que en pruebas lo crea quien lanza routerd."""
        try:
            import pwd
            return pwd.getpwnam(USUARIO_PANEL).pw_uid
        except KeyError:
            pass
        except Exception:
            LOG.exception('no se pudo resolver el uid de %s', USUARIO_PANEL)
        try:
            return os.stat(self.rutas['buzon']).st_uid
        except OSError:
            return None

    def _leer_peticion_segura(self, ruta, uid_esperado):
        """Abre y lee una petición del buzón sin fiarse de nada (H4): nunca
        sigue un symlink, exige fichero regular sin hardlinks extra, del
        propietario esperado y de hasta 64 KiB; lee como máximo 64 KiB.
        Devuelve (peticion_o_None, error_o_None)."""
        try:
            fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as e:
            return None, 'no se pudo abrir la petición: %s' % e
        try:
            try:
                st = os.fstat(fd)
            except OSError as e:
                return None, 'no se pudo inspeccionar la petición: %s' % e
            if not stat.S_ISREG(st.st_mode):
                return None, 'la petición no es un fichero regular'
            if st.st_nlink != 1:
                return None, 'la petición tiene enlaces adicionales (nlink=%d)' % st.st_nlink
            if uid_esperado is not None and st.st_uid != uid_esperado:
                return None, 'la petición no es del propietario esperado (uid=%d)' % st.st_uid
            limite = 64 * 1024
            if st.st_size > limite:
                return None, 'la petición supera %d KiB' % (limite // 1024)
            trozos, leido = [], 0
            while leido <= limite:
                trozo = os.read(fd, 65536)
                if not trozo:
                    break
                trozos.append(trozo)
                leido += len(trozo)
            crudo = b''.join(trozos)[:limite]
        finally:
            os.close(fd)
        try:
            return json.loads(crudo.decode('utf-8')), None
        except (ValueError, UnicodeDecodeError) as e:
            return None, 'Petición ilegible: %s' % e

    def atender_buzon(self):
        import peticiones
        buzon = self.rutas['buzon']
        try:
            nombres = sorted(n for n in os.listdir(buzon) if re.fullmatch(r'[0-9a-f-]{36}\.json', n))
        except FileNotFoundError:
            return
        # L2: como mucho 10 peticiones por ciclo — con el buzón muy lleno,
        # el resto espera al ciclo siguiente en vez de alargar éste sin
        # límite (publicar/atender otras cosas también tiene que poder
        # correr en cada vuelta).
        nombres = nombres[:10]
        # H4: se «reclama» cada petición moviéndola aquí ANTES de procesarla
        # — si routerd muriera a mitad, no queda a medias en el buzón que lee
        # también el panel. El directorio es 0700 de root: ni el panel (sin
        # privilegios) puede tocar lo que ya se está procesando.
        procesando = os.path.join(buzon, 'procesando')
        try:
            os.makedirs(procesando, mode=0o700, exist_ok=True)
            os.chmod(procesando, 0o700)
        except OSError:
            LOG.exception('no se pudo preparar %s', procesando)
            return
        uid_esperado = self._uid_routerpanel()
        recargas = set()   # L2: tipos de recarga de dnsmasq pendientes del lote ('dhcp'/'reservas')
        wifi_sistema_ejecutada = False   # punto 6: máx 1 acción wifi_* de sistema por ciclo
        bloqueo_probar_ejecutadas = 0    # BAJA8: máx 2 bloqueo_probar de verdad por ciclo
        bloqueo_regenerar = False   # ¿alguna bloqueo_config/bloqueo_lista de este lote cambió algo relevante?
        for nombre in nombres:
            _sd_notify('WATCHDOG=1')   # punto 6: un lote de hasta 10 peticiones no debe parecer colgado
            origen = os.path.join(buzon, nombre)
            reclamada = os.path.join(procesando, nombre)
            pid = nombre[:-5]
            pet, ok, msg = None, False, 'error interno'
            es_wifi_sistema = False
            es_bloqueo_sistema = False
            # L3: TODO lo que puede fallar al atender esta petición — leerla,
            # aplicarla, dejar escrita la config de dnsmasq y guardar
            # router.json — vive en este único try. Si algo de eso lanza una
            # excepción que no se esperaba, NO puede dejar la petición a
            # medias en procesando/ sin respuesta: por eso se captura aquí,
            # no sólo alrededor de peticiones.aplicar().
            try:
                pet, error = self._leer_peticion_segura(origen, uid_esperado)
                if pet is None:
                    msg = error or 'Petición ilegible'
                elif (isinstance(pet, dict) and pet.get('accion') in peticiones.ACCIONES_WIFI_SISTEMA
                        and wifi_sistema_ejecutada):
                    # Punto 6 (watchdog): sólo UNA acción wifi_* de verdad
                    # (nmcli/keyfile) por ciclo — las demás, aunque ya
                    # estuvieran en el buzón, se dejan SIN reclamar ni
                    # responder: el panel las verá "pendiente" y routerd las
                    # recogerá en el ciclo siguiente.
                    continue
                elif (isinstance(pet, dict) and pet.get('accion') == 'bloqueo_probar'
                        and bloqueo_probar_ejecutadas >= 2):
                    # BAJA8: como mucho DOS bloqueo_probar de verdad por
                    # ciclo (son baratas — leer unos ficheros de caché —
                    # pero un panel que lance muchas a la vez no debe poder
                    # alargar un ciclo de routerd sin límite); el resto
                    # queda pendiente para el ciclo siguiente, igual que el
                    # límite de las acciones wifi_* de sistema.
                    continue
                else:
                    es_wifi_sistema = isinstance(pet, dict) and pet.get('accion') in peticiones.ACCIONES_WIFI_SISTEMA
                    es_bloqueo_sistema = (isinstance(pet, dict)
                                           and pet.get('accion') in peticiones.ACCIONES_SISTEMA_BLOQUEO)
                    try:
                        os.rename(origen, reclamada)
                    except OSError as e:
                        msg = 'no se pudo reclamar la petición: %s' % e
                    else:
                        if not isinstance(pet, dict):
                            msg = 'Petición mal formada'
                        else:
                            # BAJA13: la comparación de qué cambió de
                            # verdad en 'bloqueo' (para decidir si hace
                            # falta relanzar router-bloqueo.service) se hace
                            # con el ANTES de aplicar() — que muta self.cfg
                            # en memoria para las acciones que no son de
                            # sistema.
                            anterior_bloqueo = dict(self.cfg.get('bloqueo') or {})
                            # HIGH-3: snapshot de la config antes de mutarla,
                            # para poder volver a la anterior si la validación
                            # nft de las acciones fw_* falla (más fiable que
                            # recargar de disco: la config en memoria es la
                            # verdad hasta que se guarda).
                            cfg_previo_fw = (copy.deepcopy(self.cfg)
                                             if pet.get('accion') in peticiones.ACCIONES_FIREWALL
                                             else None)
                            ok, msg, cambio_dhcp = peticiones.aplicar(self.cfg, pet)
                            # Acciones wifi_*: peticiones.py sólo VALIDA (ssid,
                            # clave, prioridad dentro de rango) — nunca toca el
                            # sistema ni guarda la clave en cfg (nunca debe
                            # acabar en router.json). Si la validación pasó,
                            # aquí es donde de verdad se escribe el perfil NM
                            # y se llama a nmcli; el ok/mensaje de verdad es
                            # el de esta ejecución, no el de la validación.
                            if ok and es_wifi_sistema:
                                ok, msg = self._ejecutar_accion_wifi(pet['accion'], pet.get('datos') or {})
                                wifi_sistema_ejecutada = True
                            elif ok and es_bloqueo_sistema:
                                # bloqueo_actualizar/bloqueo_probar: igual que
                                # las wifi_* de sistema, peticiones.py sólo
                                # VALIDA; aquí es donde de verdad se lanza la
                                # actualización o se consulta lo generado.
                                ok, msg = self._ejecutar_accion_bloqueo(pet['accion'], pet.get('datos') or {})
                                if pet['accion'] == 'bloqueo_probar':
                                    bloqueo_probar_ejecutadas += 1   # BAJA8
                            # HIGH-3 (revisión Opus 2026-10-12): las acciones
                            # fw_* se validan generando el texto nft y
                            # pasando `nft -c -f` sobre un temporal ANTES de
                            # guardar la config. Si falla: ok=False con el
                            # error y la config en memoria vuelve a la
                            # anterior (snapshot de más arriba).
                            if ok and pet['accion'] in peticiones.ACCIONES_FIREWALL:
                                # Sólo el FALLO sustituye el mensaje: en caso de
                                # éxito se conserva el de peticiones.aplicar()
                                # («Regla … guardada»), que es el que ve el panel.
                                ok_nft, msg_nft = self._validar_fw_con_nft()
                                if not ok_nft:
                                    ok, msg = False, msg_nft
                                    if cfg_previo_fw is not None:
                                        self.cfg = cfg_previo_fw
                            if ok and cambio_dhcp:
                                # L2: se valida y se deja escrita ya, pero la
                                # recarga de verdad (restart/HUP) se agrupa
                                # al final del lote, una sola vez.
                                ok2, msg2 = self.aplicar_dnsmasq(cambio_dhcp, recargar=False)
                                if ok2:
                                    recargas.add(cambio_dhcp)
                                else:
                                    ok = False
                                    msg = msg + ' — pero dnsmasq no aceptó la configuración: ' + msg2
                            # Punto 11: las acciones wifi_*/bloqueo_* de
                            # sistema NUNCA mutan cfg (ver peticiones.py) —
                            # ni guardar router.json ni resetear la firma de
                            # balanceo tiene sentido para ellas (y sólo sería
                            # trabajo de más en cada wifi_escanear/conectar/
                            # bloqueo_probar).
                            if es_wifi_sistema or es_bloqueo_sistema:
                                pass
                            elif ok:
                                self._guardar_config()
                                self.ultima_firma_balanceo = None   # pesos/modo pueden haber cambiado
                                if pet['accion'] == 'bloqueo_lista':
                                    # bloqueo_lista SIEMPRE cambia el
                                    # conjunto de dominios (añade/quita una
                                    # entrada de lista_blanca/lista_negra):
                                    # siempre hace falta regenerar.
                                    bloqueo_regenerar = True
                                elif pet['accion'] == 'bloqueo_config':
                                    # BAJA13: bloqueo_config también puede
                                    # tocar sólo forzar_dns/actualizar_h/
                                    # registro_dns_dias — campos que NO
                                    # afectan al conjunto de dominios
                                    # bloqueados (forzar_dns es nft, lo
                                    # recoge solo instalar_base() en el
                                    # siguiente ciclo; actualizar_h y
                                    # registro_dns_dias no tocan listas).
                                    # Sólo se relanza router-bloqueo.service
                                    # si de verdad cambió 'listas',
                                    # 'bloquear_doh' o 'habilitado'.
                                    nuevo_bloqueo = self.cfg.get('bloqueo') or {}
                                    if any(anterior_bloqueo.get(c) != nuevo_bloqueo.get(c)
                                           for c in ('listas', 'bloquear_doh', 'habilitado')):
                                        bloqueo_regenerar = True
                            else:
                                # H3(d)/H6: la config nueva no vale, no se
                                # guarda nada; se recarga la buena de disco
                                # (descarta la mutación en memoria que hizo
                                # peticiones.aplicar()).
                                self.cfg = self._cargar_config()
            except Exception as e:   # H4/L3: una petición NUNCA debe quedar sin respuesta
                LOG.exception('error inesperado atendiendo la petición %s', pid)
                ok, msg = False, 'error interno: %s' % e
            datos_pet = (pet or {}).get('datos', {}) if isinstance(pet, dict) else {}
            self.oplog(str((pet or {}).get('usuario', '?') if isinstance(pet, dict) else '?')[:40],
                       str((pet or {}).get('accion', '?') if isinstance(pet, dict) else '?')[:40],
                       _redactar_datos(datos_pet), ok, msg)
            escribir_atomico(os.path.join(self.rutas['respuestas'], pid + '.json'),
                             json.dumps({'id': pid, 'ok': ok, 'mensaje': msg, 'aplicado': ahora_iso()},
                                        ensure_ascii=False),
                             modo=0o640, grupo=self.rutas['grupo_panel'])
            # Se borra siempre, esté donde esté: en el buzón original (no se
            # llegó a reclamar) o ya reclamada (procesando/). El PANEL nunca
            # borra nada (ver docs/CONTRATO.md): sólo lee; es routerd quien
            # retira las respuestas viejas (_limpiar_respuestas_viejas, 1 h).
            for r in (origen, reclamada):
                try:
                    os.unlink(r)
                except OSError:
                    pass
        # L2: una única recarga de dnsmasq al final del lote — restart si
        # alguna petición tocó rango DHCP/DNS (no basta un HUP), HUP si sólo
        # tocaron reservas.
        if 'dhcp' in recargas:
            run(['systemctl', 'restart', 'dnsmasq'], comprobar=False)
        elif 'reservas' in recargas:
            run(['systemctl', 'kill', '-s', 'HUP', 'dnsmasq'], comprobar=False)
        if bloqueo_regenerar:
            # --no-block: sólo encola el trabajo (oneshot) y vuelve al
            # instante — nunca debe poder alargar este ciclo de routerd
            # esperando a que router-bloqueo.service termine de descargar y
            # parsear varios MiB de listas.
            run(['systemctl', '--no-block', 'start', 'router-bloqueo.service'], comprobar=False)

    def _detectar_soporte_log_extra(self):
        """¿El dnsmasq instalado admite `log-queries=extra` (>= 2.86: más
        detalle por consulta —cliente, si se resolvió o se bloqueó— que
        hace falta para las estadísticas de DNS del panel)? Se comprueba
        UNA sola vez por proceso (se cachea en self._dnsmasq_log_extra):
        nunca debe poder tirar el DHCP/DNS de la LAN por esto, así que si
        no lo admite (versión más vieja) se cae a 'log-queries' simple en
        vez de dejar que `dnsmasq --test` rechace TODA la config de la LAN
        por una sola línea."""
        if self._dnsmasq_log_extra is not None:
            return self._dnsmasq_log_extra
        fd, tmp = tempfile.mkstemp(prefix='.tmp-dnsmasq-probe-')
        try:
            os.write(fd, b'log-queries=extra\n')
            os.close(fd)
            r = run(['dnsmasq', '--test', '--conf-file=' + tmp], comprobar=False)
            self._dnsmasq_log_extra = (r.returncode == 0)
        except Exception:
            LOG.exception('no se pudo comprobar si dnsmasq admite log-queries=extra')
            self._dnsmasq_log_extra = False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return self._dnsmasq_log_extra

    def _asegurar_log_dns(self):
        """dnsmasq corre con --user=dnsmasq (privilegios caídos tras ligar
        el puerto 53, ver /lib/systemd/system/dnsmasq.service de Debian):
        sin esto, /var/log/router (0755 root:root, lo crea LogsDirectory=
        de routerd.service) no deja que dnsmasq ESCRIBA su propio log de
        consultas (log-facility=/var/log/router/dns.log — dnsmasq_conf.py,
        para las estadísticas del panel). No hace falta abrir el
        DIRECTORIO a escritura de grupo/otros: basta con que el FICHERO ya
        exista con el propietario correcto antes de que dnsmasq lo abra en
        modo apéndice. Nunca lanza (H5): sin el usuario 'dnsmasq' (pruebas,
        instalación distinta) se deja como está — dnsmasq seguiría sin
        poder escribir el log, pero no debe tirar el ciclo por eso."""
        if not self.cfg.get('gestionar_dnsmasq', True):   # pruebas en netns
            return
        import dnsmasq_conf
        ruta = dnsmasq_conf.RUTA_LOG_DNS
        try:
            if not os.path.exists(ruta):
                os.makedirs(os.path.dirname(ruta), exist_ok=True)
                with open(ruta, 'a'):
                    pass
                os.chmod(ruta, 0o640)
            try:
                import pwd
                info = pwd.getpwnam('dnsmasq')
                os.chown(ruta, info.pw_uid, info.pw_gid)
            except KeyError:
                pass   # sin ese usuario (pruebas, instalación sin el paquete de Debian)
        except OSError:
            LOG.exception('no se pudo preparar %s para que dnsmasq escriba su log', ruta)

    def _generar_logrotate_dns(self):
        """Contenido de /etc/logrotate.d/router-dns: copytruncate (igual
        que systemd/logrotate-router para operaciones.log — dnsmasq tiene
        el fichero abierto en apéndice todo el tiempo, no lo reabre por
        señal) y `rotate` = bloqueo.registro_dns_dias (1-365) de
        router.json, para que el panel pueda ajustar cuánto se conserva el
        historial de consultas DNS sin tocar ficheros a mano."""
        dias = (self.cfg.get('bloqueo') or {}).get('registro_dns_dias', 30)
        try:
            dias = max(1, min(365, int(dias)))
        except (TypeError, ValueError):
            dias = 30
        return (
            '# Generado por routerd — NO editar a mano (se reescribe desde el panel).\n'
            '/var/log/router/dns.log {\n'
            '    daily\n'
            '    rotate %d\n'
            '    compress\n'
            '    copytruncate\n'
            '    missingok\n'
            '    notifempty\n'
            # BAJA9: tope de tamaño además del diario — con mucho tráfico
            # DNS, "diario" solo podría dejar crecer el fichero mucho en un
            # día; se complementa con router-logrotate-dns.timer (cada
            # hora, systemd/router-logrotate-dns.{service,timer}), que es
            # quien de verdad hace que este tope se compruebe con esa
            # frecuencia (logrotate normal sólo corre una vez al día,
            # vía cron.daily).
            '    maxsize 200M\n'
            '}\n' % dias)

    def asegurar_logrotate_dns(self):
        if not self.cfg.get('gestionar_dnsmasq', True):   # pruebas en netns
            return
        ruta = self.rutas.get('logrotate_dns', RUTAS['logrotate_dns'])
        nuevo = self._generar_logrotate_dns()
        if _leer(ruta) == nuevo.strip():
            return
        try:
            escribir_atomico(ruta, nuevo)
            self._logrotate_dns_error_previo = None
        except OSError as e:
            if str(e) != self._logrotate_dns_error_previo:
                LOG.exception('no se pudo escribir %s', ruta)
                self._logrotate_dns_error_previo = str(e)

    def aplicar_dnsmasq(self, cambio='dhcp', recargar=True):
        """Regenera la config de dnsmasq de la LAN y la valida ANTES de
        tocar nada más (H3/H6): si `dnsmasq --test` falla, se restaura lo
        que había y NO se recarga el servicio ni se guarda router.json (eso
        último lo decide el llamador, que no debe guardar si esto falla).
        En preparación sólo la deja escrita en /etc/router/staged/.

        `cambio`:
          'reservas' — sólo cambiaron las reservas (dhcp-hostsfile): un
                       SIGHUP basta, dnsmasq lo relee solo.
          'dhcp'     — rango DHCP o servidores DNS (dhcp-range=/server=):
                       un SIGHUP NO los relee, hace falta reiniciar (H3b).

        `recargar=False` (L2): valida y deja escrita la config, pero NO
        toca el servicio — para atender_buzon(), que agrupa el
        restart/HUP de todo un lote de peticiones en una sola recarga al
        final en vez de una por petición.
        """
        self._asegurar_servers_file_bloqueo()   # M2: debe existir SIEMPRE antes de --test
        import dnsmasq_conf
        conf, reservas = dnsmasq_conf.generar(
            self.cfg,
            log_queries_extra=self._detectar_soporte_log_extra(),
            desactivar_log=self._bloqueo_fail_open)
        destino_conf = self.rutas['dnsmasq_lan'] if self.produccion() else '/etc/router/staged/10-router-lan.conf'
        previo_conf = _leer(destino_conf)
        previo_reservas = _leer(self.rutas['dnsmasq_reservas'])
        escribir_atomico(self.rutas['dnsmasq_reservas'], reservas)
        # Nombres de los equipos con reserva (addn-hosts, mismo directorio).
        escribir_atomico(os.path.join(os.path.dirname(self.rutas['dnsmasq_reservas']), 'hosts-reservas'),
                         dnsmasq_conf.generar_hosts(self.cfg))
        escribir_atomico(destino_conf, conf)
        if not self.produccion():
            return True, 'configuración preparada (fase de preparación: dnsmasq no se recarga)'
        # En Debian el servicio añade /etc/dnsmasq.d (via /etc/default/dnsmasq):
        # sin --conf-dir, --test no vería nuestra config y siempre diría «OK».
        r = run(['dnsmasq', '--test', '--conf-file=/etc/dnsmasq.conf',
                 '--conf-dir=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new'], comprobar=False)
        if r.returncode != 0:
            # La config nueva no vale: se deja todo como estaba.
            if previo_conf is not None:
                escribir_atomico(destino_conf, previo_conf + '\n')
            elif os.path.exists(destino_conf):
                os.unlink(destino_conf)
            if previo_reservas is not None:
                escribir_atomico(self.rutas['dnsmasq_reservas'], previo_reservas + '\n')
            return False, (r.stderr or r.stdout).strip()
        if recargar:
            if cambio == 'reservas':
                run(['systemctl', 'kill', '-s', 'HUP', 'dnsmasq'], comprobar=False)
            else:
                run(['systemctl', 'restart', 'dnsmasq'], comprobar=False)
        return True, 'ok'

    # — limpieza de estado al arrancar (LOW) —
    def _barrido_arranque(self):
        """Al arrancar en producción, deja en estado limpio lo que pudiera
        quedar de un routerd anterior con otra configuración de WAN: ip
        rules 900–1199 y tablas de rutas 101–199. desinstalar() hace una
        limpieza parecida pero sólo para las WAN que sigan en la config
        ACTUAL; aquí se barre todo el rango, esté o no esa WAN hoy en
        router.json (p. ej. si se ha borrado una línea a mano)."""
        reglas = run(['ip', '-j', 'rule', 'show'], comprobar=False).stdout
        try:
            for r in json.loads(reglas or '[]'):
                # N13: sólo las reglas PROPIAS (protocol 99) dentro del rango.
                if _es_regla_propia(r) and 900 <= int(r.get('priority', 0)) < 1200:
                    run(['ip', 'rule', 'del', 'pref', str(r['priority']), 'protocol', str(PROTOCOLO_PROPIO)],
                        comprobar=False)
        except (ValueError, TypeError):
            pass
        for n in range(1, 100):
            run(['ip', 'route', 'flush', 'table', str(TABLA_BASE + n)], comprobar=False)

    # — registro: limpieza de respuestas viejas (M7) —
    def _limpiar_respuestas_viejas(self):
        """L3: el PANEL nunca borra nada (contrato: sólo lee, ver
        docs/CONTRATO.md); es routerd quien retira aquí las respuestas que
        ya nadie ha venido a leer (el panel se reinicia, pierde la
        petición…), para que no se queden para siempre en
        /var/lib/router/respuestas. Fuera las de más de 1 hora."""
        try:
            nombres = os.listdir(self.rutas['respuestas'])
        except FileNotFoundError:
            return
        limite = time.time() - 3600
        for nombre in nombres:
            ruta = os.path.join(self.rutas['respuestas'], nombre)
            try:
                if os.stat(ruta).st_mtime < limite:
                    os.unlink(ruta)
            except OSError:
                pass

    def _barrer_tmp_viejos_buzon(self):
        """Ficheros "*.json.tmp" abandonados en el buzón (revisión Opus,
        punto 12): el panel escribe ahí antes del rename atómico
        (escribir_peticion en panel/routerpanel/buzon.py); si se cae a
        mitad (el worker gunicorn muere, un corte de luz…) ese temporal se
        queda huérfano para siempre si nadie lo barre. Se borran los de más
        de 5 minutos, con las MISMAS precauciones que
        _leer_peticion_segura: nunca se sigue un symlink (O_NOFOLLOW) y
        sólo se toca un fichero REGULAR sin enlaces adicionales — nunca
        algo que no sea exactamente lo que el nombre sugiere."""
        try:
            nombres = os.listdir(self.rutas['buzon'])
        except FileNotFoundError:
            return
        limite = time.time() - 300
        for nombre in nombres:
            if not nombre.endswith('.json.tmp'):
                continue
            ruta = os.path.join(self.rutas['buzon'], nombre)
            try:
                st = os.lstat(ruta)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mtime >= limite:
                continue
            try:
                fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                continue
            os.close(fd)   # confirma (O_NOFOLLOW) que de verdad es el fichero regular que el lstat vio
            try:
                os.unlink(ruta)
            except OSError:
                pass

    # — bucle —
    def ciclo(self):
        self.cfg = self._cargar_config()
        self.fase = self._fase_efectiva()   # N1: de /etc/router/fase; routerd nunca la escribe
        # Punto 2: NADA Wi-Fi fuera de producción, y nunca mientras haya una
        # migración en curso (router_migrar.py puede deshacerla en
        # cualquier momento). Punto 6: breaker de lecturas nmcli, uno nuevo
        # cada ciclo (si una lectura agota el tiempo, las demás de ESTE
        # ciclo se saltan; el siguiente ciclo vuelve a intentarlo todo).
        permitir_wifi = self._wifi_permitida()
        if permitir_wifi != self._wifi_permitida_anterior:
            self._radio_wifi_aplicada = None   # fuerza una resincronización real al volver a permitirse
            self._wifi_permitida_anterior = permitir_wifi
        self._wifi_breaker = {}
        if permitir_wifi:
            try:
                self._aplicar_radio_wifi()
            except Exception:
                LOG.exception('error gestionando la radio wifi')
        if self.produccion():
            if not self._arranque_limpio_hecho:
                self._barrido_arranque()
                self._arranque_limpio_hecho = True
            # H5: lo primero del ciclo en producción, antes de tocar rutas
            # por WAN ni de hacer ningún ping — si el firewall base no está,
            # todo lo demás es secundario.
            self.instalar_base()
        encontrados = descubrir_wans(self.cfg, permitir_wifi=permitir_wifi, breaker=self._wifi_breaker)
        lan_red = ipaddress.ip_network(self.cfg['lan']['red'])
        nuevos = {}
        for w in encontrados:
            if w.get('es_wifi'):
                # Punto 10: si cambió el SSID (otro hotspot) desde el ciclo
                # anterior, no debe arrastrar la latencia/pérdida/peso del
                # hotspot anterior — se resetea como una WAN nueva.
                anterior_ssid = self._wifi_ssid_anterior.get(w['id'], _SIN_SSID_PREVIO)
                actual_ssid = w.get('telefono')
                if anterior_ssid is not _SIN_SSID_PREVIO and anterior_ssid != actual_ssid:
                    self.estados.pop(w['id'], None)
                    self._pesos_nft.pop(w['id'], None)
                self._wifi_ssid_anterior[w['id']] = actual_ssid
                try:
                    razon = self._wifi_guardia_bucle(w)
                except Exception:
                    LOG.exception('error en la guarda anti-bucle de la WAN Wi-Fi %s', w['ifname'])
                    razon = None
                if razon:
                    if w['id'] not in self._avisado_bucle_wifi:
                        self.oplog('sistema', 'wifi_bucle', {'wan': w['id'], 'interfaz': w['ifname']},
                                   False, 'WAN Wi-Fi fuera del balanceo: %s' % razon)
                        self._avisado_bucle_wifi.add(w['id'])
                    self._wifi_desconectar_por_bucle(w)
                    w = dict(w, ip=None, gw=None)
                else:
                    self._avisado_bucle_wifi.discard(w['id'])
            if w['ip']:
                try:
                    red_tel = ipaddress.ip_interface(w['ip']).network
                except ValueError:
                    red_tel = None
                if red_tel is not None and red_tel.overlaps(lan_red):
                    # LOW: una subred de teléfono que coincide con la LAN
                    # confundiría las rutas (¿es 192.168.50.5 un vecino de la
                    # LAN o algo detrás del teléfono?): no se usa como WAN.
                    if w['id'] not in self._avisado_solape:
                        self.oplog('sistema', 'wan_solape_lan', {'wan': w['id'], 'interfaz': w['ifname']},
                                   False, 'el teléfono usa una subred que choca con la LAN: '
                                          'reactiva el tethering')
                        self._avisado_solape.add(w['id'])
                    w = dict(w, ip=None, gw=None)
                else:
                    self._avisado_solape.discard(w['id'])
            c = self._asegurar_wan_en_config(w)
            if c is None:          # LOW: sin hueco libre, ya se ha avisado por oplog
                continue
            nuevos[w['id']] = w
            # N9: sin el firewall base instalado se falla cerrado — no se
            # ponen rutas por WAN ese ciclo (mejor sin ruta que con una ruta
            # suelta sin el cortafuegos/NAT que la hace segura).
            if self.produccion() and self.base_instalada:
                try:
                    self._rutas_wan(w, c)
                except Exception:
                    LOG.exception('error en las rutas de la WAN %s (%s)', w['id'], w['ifname'])
        retirados = set(self.presentes) - set(nuevos)
        for wid in retirados:
            c = self.cfg.get('wans', {}).get(wid)
            if self.produccion() and c:
                try:
                    self._limpiar_wan(c)
                    # H7: que las conexiones que tenía esta WAN se rehagan por otra.
                    run(['conntrack', '-D', '--mark', hex(MARCA_BASE + c['n'])], comprobar=False)
                except Exception:
                    LOG.exception('error retirando la WAN %s', wid)
            if c:
                self.oplog('sistema', 'wan_retirada', {'wan': wid}, True,
                           '%s desconectada' % c['nombre'])
            # M3: que al volver se compruebe desde cero (sin arrastrar
            # fallos/éxitos/latencias de la vez anterior).
            self.estados.pop(wid, None)
            self._redes_wan.pop(wid, None)
            # LOW: si no, al volver esa WAN arrastraría el último peso
            # efectivo (quizá muy alto) aplicado antes de irse, en vez de
            # arrancar como las demás (sin dato hasta el próximo ciclo).
            self._pesos_nft.pop(wid, None)
            self._wifi_ssid_anterior.pop(wid, None)
        self.presentes = nuevos
        # Comprobaciones en paralelo (una WAN lenta no frena a las demás).
        hilos = [threading.Thread(target=self.comprobar, args=(w, self.cfg['wans'][w['id']]))
                 for w in nuevos.values()]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        # A: con las comprobaciones de este ciclo ya hechas (latencia,
        # pérdida), se recalcula el peso efectivo de cada WAN — tanto si se
        # va a balancear de verdad (producción) como si no (preparación),
        # porque publicar() ya lo muestra siempre. LOW: en try/except
        # propio — un fallo aquí (p. ej. un dato corrupto) no puede tirar
        # el resto del ciclo (balanceo, dnsmasq, publicar...).
        try:
            self._actualizar_pesos_efectivos()
        except Exception:
            LOG.exception('error actualizando los pesos automáticos')
        if self.produccion():
            # N9: fallar cerrado — sin el firewall base instalado no se
            # gestiona el balanceo ni dnsmasq ese ciclo; el error ya ha
            # quedado en self._firewall_error y se publica en estado.json.
            if self.base_instalada:
                # Un fallo inesperado del balanceo no debe saltarse dnsmasq,
                # el buzón ni la publicación del estado en este ciclo.
                try:
                    self.aplicar_balanceo()
                except Exception:
                    LOG.exception('error aplicando el balanceo')
                self.asegurar_dnsmasq()
        else:
            self.desinstalar()
        if permitir_wifi:
            try:
                self._wifi_recoger_escaneo_pendiente()
            except Exception:
                LOG.exception('error recogiendo el escaneo wifi pendiente')
        self.atender_buzon()
        self.publicar()
        self._limpiar_respuestas_viejas()
        self._barrer_tmp_viejos_buzon()

    def asegurar_dnsmasq(self):
        """En producción, la config de dnsmasq de la LAN debe ser la generada
        desde router.json (al entrar en producción o si alguien la tocó).
        Cualquier diferencia aquí puede incluir el rango DHCP o el DNS, así
        que se trata como 'dhcp' (reinicio completo, no SIGHUP — H3).

        N7: además del CONTENIDO, se comprueba que el SERVICIO esté activo
        — puede haberlo parado alguien (o haber fallado al arrancar el
        sistema) sin que cambie nada de la config. L1: si `dnsmasq --test`
        sigue fallando con el MISMO error ciclo tras ciclo, sólo se avisa
        por oplog una vez, no en cada vuelta."""
        if not self.cfg.get('gestionar_dnsmasq', True):   # pruebas en netns
            return
        self._asegurar_servers_file_bloqueo()   # M2: debe existir SIEMPRE
        self._asegurar_log_dns()
        self.asegurar_logrotate_dns()
        self._asegurar_timer_bloqueo()   # BAJA7
        import dnsmasq_conf
        conf, _ = dnsmasq_conf.generar(
            self.cfg,
            log_queries_extra=self._detectar_soporte_log_extra(),
            desactivar_log=self._bloqueo_fail_open)
        if _leer(self.rutas['dnsmasq_lan']) != conf.strip():
            ok, msg = self.aplicar_dnsmasq('dhcp')
            activo_ya = self._dnsmasq_activo_o_transicionando()
            if ok:
                self._dnsmasq_test_error_previo = None
                self.oplog('sistema', 'dnsmasq', {}, True, 'DHCP/DNS de la LAN activado')
            elif activo_ya:
                # M3 (ronda 3): la config NUEVA no vale (dnsmasq --test la
                # rechazó), pero dnsmasq SIGUE activo con la de antes — eso
                # es un problema de la config nueva (routerd/el admin), no
                # de dnsmasq en sí; cuenta como NEUTRO, no como un fallo
                # de verdad (nunca debe empujar hacia fail-open por esto).
                if msg != self._dnsmasq_test_error_previo:
                    self.oplog('sistema', 'dnsmasq', {}, False,
                               'DHCP/DNS de la LAN NO se actualiza (la config nueva no es válida), '
                               'pero dnsmasq sigue activo con la anterior: ' + msg)
                    self._dnsmasq_test_error_previo = msg
            elif msg != self._dnsmasq_test_error_previo:
                self.oplog('sistema', 'dnsmasq', {}, False, 'DHCP/DNS de la LAN NO activado: ' + msg)
                self._dnsmasq_test_error_previo = msg
            self._dnsmasq_inactivo_avisado = False
            if ok and activo_ya:
                self._registrar_dnsmasq_recuperado()
            elif not ok and not activo_ya:
                self._registrar_dnsmasq_fallo()
            # ok=False pero activo_ya=True → neutro: ni fallo ni recuperación.
            return
        # N7: contenido correcto, pero el SERVICIO puede estar caído sin que
        # cambie nada de lo anterior (lo paró alguien a mano, falló al
        # arrancar…). BAJA12: 'activating'/'reloading' cuentan como "sigue
        # vivo", no como una caída (evita un oplog falso y un restart de
        # más justo después de un SIGHUP/start normal).
        if self._dnsmasq_activo_o_transicionando():
            self._dnsmasq_inactivo_avisado = False
            self._registrar_dnsmasq_recuperado()
            return
        r = run(['systemctl', 'start', 'dnsmasq'], comprobar=False)
        ok = r.returncode == 0 and self._dnsmasq_activo_o_transicionando()
        if not self._dnsmasq_inactivo_avisado:
            self.oplog('sistema', 'dnsmasq', {}, ok,
                       'dnsmasq estaba inactivo: %s' %
                       ('arrancado' if ok else 'no se pudo arrancar: ' + (r.stderr or r.stdout).strip()))
            self._dnsmasq_inactivo_avisado = True
        if ok:
            self._registrar_dnsmasq_recuperado()
        else:
            self._registrar_dnsmasq_fallo()

    def _dnsmasq_activo_o_transicionando(self):
        """BAJA12: 'active' SÍ, pero también 'activating'/'reloading' — no
        es un fallo real, sólo un instante de transición (tras un start o
        un SIGHUP) que systemd puede seguir reportando un momento."""
        estado = run(['systemctl', 'is-active', 'dnsmasq'], comprobar=False).stdout.strip()
        return estado in ('active', 'activating', 'reloading')

    # — M2: el servers-file del bloqueador SIEMPRE debe existir —
    def _asegurar_servers_file_bloqueo(self):
        """routerd referencia `servers-file=...` incondicionalmente desde
        dnsmasq_conf.py: si el fichero no existe (primer arranque, antes de
        que router-bloqueo.service haya corrido nunca; o tras un fail-open
        que lo dejó vacío a propósito), `dnsmasq --test`/el arranque real
        fallan con "no se puede leer...". Aquí sólo se crea VACÍO si falta
        — generar contenido de verdad es tarea exclusiva de
        router_bloqueo.py, nunca de routerd."""
        ruta = self.rutas.get('dnsmasq_bloqueo', RUTAS['dnsmasq_bloqueo'])
        if os.path.exists(ruta):
            return
        try:
            escribir_atomico(ruta, '# router_bloqueo todavía no ha generado nada — vacío.\n')
        except OSError:
            LOG.exception('no se pudo crear %s vacío', ruta)

    # — M6/M1 (ronda 3): fail-open del bloqueador, con histéresis y backoff —
    def _bloqueo_estable_requerido_s(self):
        """M1: cuánto tiempo SEGUIDO tiene que llevar dnsmasq activo (sin
        recaer) para que se dé por buena la recuperación — empieza en
        BLOQUEO_ESTABLE_BASE_S (30 min) y se DOBLA con cada recaída
        (_bloqueo_backoff_nivel), hasta BLOQUEO_ESTABLE_MAX_S (24 h)."""
        return min(BLOQUEO_ESTABLE_MAX_S, BLOQUEO_ESTABLE_BASE_S * (2 ** self._bloqueo_backoff_nivel))

    def _registrar_dnsmasq_fallo(self):
        """M3: el llamador (asegurar_dnsmasq) SÓLO debe llamar a esto
        cuando dnsmasq de verdad no está activo — un `dnsmasq --test`
        fallido con dnsmasq SIGUIENDO activo es "neutro", no un fallo (ver
        asegurar_dnsmasq). M1: si ya se estaba en fail-open y se había
        llegado a ver activo un rato (_bloqueo_activo_desde no es None),
        esto es una RECAÍDA — backoff exponencial: la próxima vez hará
        falta más tiempo estable antes de volver a salir."""
        self._dnsmasq_fallos_consecutivos += 1
        if self._bloqueo_fail_open:
            if self._bloqueo_activo_desde is not None:
                self._bloqueo_backoff_nivel = min(self._bloqueo_backoff_nivel + 1, BLOQUEO_BACKOFF_NIVEL_MAX)
                self._bloqueo_activo_desde = None
                LOG.warning('dnsmasq ha recaído estando en fail-open: backoff a nivel %d (%d s estables '
                            'antes de poder salir)', self._bloqueo_backoff_nivel, self._bloqueo_estable_requerido_s())
                self._guardar_estado_fail_open()
            return
        if self._dnsmasq_fallos_consecutivos < 3:
            return
        self._bloqueo_fail_open = True
        self._bloqueo_activo_desde = None
        ahora = time.time()
        self._bloqueo_fail_open_desde = ahora
        # M2 (ronda 4): recaída dentro de BLOQUEO_RECAIDA_VENTANA_S (24 h)
        # desde la ÚLTIMA SALIDA de fail-open → sube un nivel (parecía
        # curado y no lo estaba) — el nivel ya NO se había resetado al
        # salir la vez anterior, así que esto se ACUMULA entre episodios.
        if (self._bloqueo_salida_desde is not None
                and ahora - self._bloqueo_salida_desde < BLOQUEO_RECAIDA_VENTANA_S):
            self._bloqueo_backoff_nivel = min(self._bloqueo_backoff_nivel + 1, BLOQUEO_BACKOFF_NIVEL_MAX)
            LOG.warning('recaída en fail-open a los %d s de la última salida (<24h): backoff a '
                        'nivel %d (%d s estables antes de poder salir)',
                        int(ahora - self._bloqueo_salida_desde), self._bloqueo_backoff_nivel,
                        self._bloqueo_estable_requerido_s())
        self._guardar_estado_fail_open()
        ruta_bloqueo = self.rutas.get('dnsmasq_bloqueo', RUTAS['dnsmasq_bloqueo'])
        try:
            escribir_atomico(ruta_bloqueo,
                              '# fail-open (routerd): dnsmasq lleva varios arranques fallidos — '
                              'servers-file vaciado por seguridad.\n')
        except OSError:
            LOG.exception('no se pudo vaciar el servers-file del bloqueo en fail-open')
        try:
            # M2 (ronda 3): si no se borra, router_bloqueo.py podría ver
            # que el hash de SU próximo contenido "coincide" con el que
            # había guardado de ANTES de este vaciado (si por casualidad
            # generara lo mismo que ya tenía) y concluir "sin cambios" —
            # sin activar de verdad el fichero que routerd acaba de vaciar
            # aquí. Borrar el hash fuerza a que la próxima pasada de
            # router_bloqueo SIEMPRE reactive de verdad.
            os.unlink(ruta_bloqueo + '.hash')
        except OSError:
            pass
        # Fuerza a instalar_base() a reinstalar el firewall SIN
        # redirigir_dns (forzar_dns) en el próximo ciclo, y a
        # asegurar_dnsmasq() a regenerar la LAN sin log — ambos miran
        # self._bloqueo_fail_open/comparan contra lo ya instalado.
        self.base_texto = None
        if not self._bloqueo_fail_open_avisado:
            self.oplog('sistema', 'bloqueo_fail_open', {}, False,
                       'dnsmasq lleva %d arranques fallidos seguidos: se desactivan temporalmente '
                       'el servers-file del bloqueo, el log de consultas DNS y forzar_dns, hasta '
                       'que dnsmasq lleve %d min activo sin interrupción'
                       % (self._dnsmasq_fallos_consecutivos, self._bloqueo_estable_requerido_s() // 60))
            self._bloqueo_fail_open_avisado = True

    def _registrar_dnsmasq_recuperado(self):
        """M1: salir de fail-open no es inmediato — hace falta verlo activo
        SEGUIDO durante `_bloqueo_estable_requerido_s()` (histéresis; nunca
        menos de 30 min, hasta 24 h si ha ido recayendo). Mientras tanto se
        sigue en fail-open (sin tocar nft/conntrack de más — ver
        instalar_base) pero sin contar esto como un fallo nuevo.

        M2 (ronda 4): esta función se llama en CADA ciclo sano, estando o
        no en fail-open — así que, fuera de fail-open, es también el sitio
        donde el nivel de backoff BAJA (nunca al salir de golpe: sólo tras
        llevar BLOQUEO_SANO_PARA_BAJAR_S, 24 h, seguidas sin volver a
        entrar en fail-open desde la última salida)."""
        self._dnsmasq_fallos_consecutivos = 0
        if not self._bloqueo_fail_open:
            self._bajar_nivel_si_lleva_sano()
            return
        ahora = time.time()
        if self._bloqueo_activo_desde is None:
            self._bloqueo_activo_desde = ahora   # acaba de volver a verse activo: empieza a contar
            return
        if ahora - self._bloqueo_activo_desde < self._bloqueo_estable_requerido_s():
            return   # todavía no lleva el tiempo estable que toca
        # Estable el tiempo requerido de verdad: SALE de fail-open.
        self._bloqueo_fail_open = False
        self._bloqueo_fail_open_avisado = False
        self._bloqueo_activo_desde = None
        self._bloqueo_fail_open_desde = None
        # M2 (ronda 4): el nivel YA NO se resetea a 0 aquí — sólo se
        # guarda la hora de ESTA salida; el nivel bajará solo, un paso
        # cada vez, tras 24 h sanas seguidas sin recaer (ver
        # _bajar_nivel_si_lleva_sano, arriba).
        self._bloqueo_salida_desde = ahora
        self._guardar_estado_fail_open()
        self.base_texto = None   # reinstala YA el firewall con redirigir_dns de vuelta
        # M2 (ronda 3): no esperar hasta la próxima actualizar_h — se pide
        # YA una pasada real (no bloqueante: sólo encola el trabajo).
        run(['systemctl', '--no-block', 'start', 'router-bloqueo.service'], comprobar=False)
        self.oplog('sistema', 'bloqueo_fail_open', {}, True,
                   'dnsmasq lleva activo y estable el tiempo necesario: se restablecen el log de '
                   'consultas DNS y forzar_dns, y se ha pedido a router-bloqueo.service que '
                   'regenere el servers-file real ahora mismo (nivel de backoff: %d, bajará solo '
                   'tras 24 h sanas sin recaer)' % self._bloqueo_backoff_nivel)

    def _bajar_nivel_si_lleva_sano(self):
        """M2 (ronda 4): fuera de fail-open, cada BLOQUEO_SANO_PARA_BAJAR_S
        (24 h) seguidas sin volver a entrar en fail-open, baja un nivel de
        backoff (nunca de golpe a 0 — así una recaída posterior no vuelve
        a empezar siempre desde el nivel más bajo). Reinicia el cronómetro
        tras cada bajada, para que la siguiente baja de nivel exija otras
        24 h sanas."""
        if self._bloqueo_backoff_nivel <= 0 or self._bloqueo_salida_desde is None:
            return
        ahora = time.time()
        if ahora - self._bloqueo_salida_desde < BLOQUEO_SANO_PARA_BAJAR_S:
            return
        self._bloqueo_backoff_nivel -= 1
        self._bloqueo_salida_desde = ahora
        LOG.info('24 h sanas sin recaer en fail-open: baja el nivel de backoff a %d',
                 self._bloqueo_backoff_nivel)
        self._guardar_estado_fail_open()

    # M2 (ronda 4): nivel de backoff + hora de la última salida de
    # fail-open, persistidos en RUTAS['bloqueo_fail_open_estado'] —
    # sobreviven a un reinicio de routerd (si no, un routerd que se cae y
    # se reinicia justo durante una recaída "olvidaría" cuántas veces ha
    # recaído ya, y volvería a probar con el tiempo estable mínimo).
    def _guardar_estado_fail_open(self):
        ruta = self.rutas.get('bloqueo_fail_open_estado', RUTAS['bloqueo_fail_open_estado'])
        estado = {
            'nivel': self._bloqueo_backoff_nivel,
            'salida_desde': (datetime.fromtimestamp(self._bloqueo_salida_desde, timezone.utc)
                              .isoformat(timespec='seconds') if self._bloqueo_salida_desde else None),
        }
        try:
            escribir_atomico(ruta, json.dumps(estado, ensure_ascii=False, indent=1))
        except OSError:
            LOG.exception('no se pudo guardar %s', ruta)

    def _cargar_estado_fail_open(self):
        ruta = self.rutas.get('bloqueo_fail_open_estado', RUTAS['bloqueo_fail_open_estado'])
        try:
            with open(ruta) as f:
                estado = json.load(f)
            self._bloqueo_backoff_nivel = min(BLOQUEO_BACKOFF_NIVEL_MAX, max(0, int(estado.get('nivel', 0))))
            salida = estado.get('salida_desde')
            self._bloqueo_salida_desde = datetime.fromisoformat(salida).timestamp() if salida else None
        except (OSError, ValueError, TypeError, KeyError):
            pass   # sin estado previo (primer arranque, o /run limpio tras reboot): nivel 0, normal

    # — BAJA7: drop-in del timer con bloqueo.actualizar_h —
    def _generar_timer_bloqueo(self, horas):
        """BAJA1: los `OnUnitActiveSec=` de un .timer son ADITIVOS (varias
        líneas = varios disparos), no "la última gana" — así que un
        drop-in que sólo pusiera `OnUnitActiveSec=%dh` no SUSTITUIRÍA el
        `OnUnitActiveSec=24h` de la unidad principal, lo ACUMULARÍA (el
        timer dispararía en los dos). La línea vacía `OnUnitActiveSec=`
        reinicia la lista a cero ANTES de poner el valor de verdad —
        documentado en systemd.timer(5) para las directivas de este tipo."""
        return '[Timer]\nOnUnitActiveSec=\nOnUnitActiveSec=%dh\n' % horas

    def _asegurar_timer_bloqueo(self):
        """Regenera `/etc/systemd/system/router-bloqueo.timer.d/override.conf`
        (OnUnitActiveSec) cuando `bloqueo.actualizar_h` cambia, y recarga
        systemd — así el panel puede ajustar cada cuánto se actualizan las
        listas sin editar la unidad a mano.

        BAJA2: la comparación es por CONTENIDO del fichero (no sólo un
        entero en memoria — tras un reinicio de routerd, `
        _bloqueo_timer_h_aplicado` vuelve a `None` y sin esto se
        reescribiría + `daemon-reload` en el primer ciclo aunque el
        drop-in de disco ya fuera el correcto); el directorio se crea solo
        (`escribir_atomico` ya hace `os.makedirs`); un fallo de escritura
        se registra una sola vez, no en cada ciclo.

        Repite la misma guarda 'gestionar_dnsmasq' que su llamador
        (asegurar_dnsmasq) por si alguna vez se llama aparte (pruebas): sin
        ella, una prueba podría acabar llamando a `systemctl daemon-reload`
        de verdad."""
        if not self.cfg.get('gestionar_dnsmasq', True):
            return
        horas = (self.cfg.get('bloqueo') or {}).get('actualizar_h', 24)
        try:
            horas = max(6, min(168, int(horas)))
        except (TypeError, ValueError):
            horas = 24
        ruta = self.rutas.get('bloqueo_timer_dropin', RUTAS['bloqueo_timer_dropin'])
        contenido = self._generar_timer_bloqueo(horas)
        if _leer(ruta) == contenido.strip():
            self._bloqueo_timer_h_aplicado = horas
            self._bloqueo_timer_error_previo = None
            return
        try:
            escribir_atomico(ruta, contenido)
            run(['systemctl', 'daemon-reload'], comprobar=False)
            self._bloqueo_timer_h_aplicado = horas
            self._bloqueo_timer_error_previo = None
        except OSError as e:
            if str(e) != self._bloqueo_timer_error_previo:
                LOG.exception('no se pudo escribir %s', ruta)
                self._bloqueo_timer_error_previo = str(e)

    def desinstalar(self):
        """Vuelta a preparación (o rollback de la migración): quita SÓLO lo que
        pone el router — sus tablas nftables, sus reglas de rutas y tablas por
        WAN, y su config de dnsmasq — y deja la red como antes. Idempotente:
        si no hay nada del router, no hace nada."""
        # Nota de rendimiento: desinstalar() se llama en TODOS los ciclos
        # mientras se está en preparación, así que tiene que ser barato en
        # el caso normal (nada que limpiar) — sólo un «nft list» y un «ip
        # rule show». El barrido completo de las 99 tablas de rutas (LOW)
        # es cosa de _barrido_arranque(), que sólo se ejecuta UNA VEZ al
        # entrar en producción, no aquí.
        hubo = False
        # «ip router_nat» ya no la crea nft_conf.generar() (C1: el NAT vive
        # ahora dentro de «inet router», ver nat_salida) — se sigue buscando
        # aquí sólo para limpiarla si queda de una instalación vieja.
        for familia, tabla in (('inet', 'router'), ('ip', 'router_nat')):
            if run(['nft', 'list', 'table', familia, tabla], comprobar=False).returncode == 0:
                run(['nft', 'destroy', 'table', familia, tabla], comprobar=False)
                hubo = True
        reglas = run(['ip', '-j', 'rule', 'show'], comprobar=False).stdout
        try:
            for r in json.loads(reglas or '[]'):
                # N13: sólo las reglas PROPIAS (protocol 99) dentro del rango.
                if _es_regla_propia(r) and 900 <= int(r.get('priority', 0)) < 1200:
                    run(['ip', 'rule', 'del', 'pref', str(r['priority']), 'protocol', str(PROTOCOLO_PROPIO)],
                        comprobar=False)
                    hubo = True
        except (ValueError, TypeError):
            pass
        if hubo:
            for c in self.cfg.get('wans', {}).values():
                run(['ip', 'route', 'flush', 'table', str(TABLA_BASE + c['n'])], comprobar=False)
        if self.cfg.get('gestionar_dnsmasq', True) and os.path.exists(self.rutas['dnsmasq_lan']):
            os.unlink(self.rutas['dnsmasq_lan'])
            run(['systemctl', 'restart', 'dnsmasq'], comprobar=False)
            hubo = True
        if hubo:
            self.base_instalada, self.base_texto = False, None
            self.ultima_firma_balanceo = None
            self.oplog('sistema', 'preparacion', {}, True,
                       'Router en preparación: cortafuegos, rutas por WAN y DHCP retirados')

    def bucle(self):
        notificado_listo = False
        while not self.parar.is_set():
            t0 = time.time()
            try:
                self.ciclo()
            except Exception:   # el router no puede morir por un ciclo raro
                LOG.exception('error en el ciclo')
            # El tiempo de ciclo queda en el log para poder comprobar que
            # ninguna fase (p. ej. el vaciado de conntrack del firewall)
            # se acerca al watchdog de 60 s.
            # En producción sólo se registra si el ciclo es lento (>5 s) para
            # no llenar el journal con una línea cada pocos segundos; la
            # prueba e2e lo fuerza con ROUTER_LOG_CICLO=1.
            dur = time.time() - t0
            if dur > 5 or os.environ.get('ROUTER_LOG_CICLO') == '1':
                (LOG.warning if dur > 5 else LOG.info)('ciclo completado en %.2fs', dur)
            # M7: Type=notify + WatchdogSec=60 en routerd.service. READY=1
            # una vez (ya hemos dado al menos una vuelta al bucle, haya ido
            # bien o mal); WATCHDOG=1 en cada vuelta — si el bucle se
            # colgara de verdad (no una excepción, que ya se captura arriba,
            # sino un cuelgue real), systemd lo nota y reinicia el servicio.
            if not notificado_listo:
                _sd_notify('READY=1')
                notificado_listo = True
            _sd_notify('WATCHDOG=1')
            espera = max(1.0, float(self.cfg['monitor'].get('intervalo_s', 5)) - (time.time() - t0))
            self.parar.wait(espera)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', default=RUTAS['config'])
    # N1: --fase es una ruta explícita, igual que --config (y NO se mueve
    # con --raiz-datos): es un fichero de "configuración" (quién manda en
    # la fase), no un dato de ejecución del propio routerd. Las pruebas en
    # netns (pruebas/netns_multiwan.sh) la pasan aparte, junto a --config.
    ap.add_argument('--fase', default=RUTAS['fase'])
    ap.add_argument('--estado', default=RUTAS['estado'])
    ap.add_argument('--raiz-datos', help='prefijo para todas las rutas de datos (pruebas)')
    ap.add_argument('--una-vez', action='store_true')
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', stream=sys.stdout)
    rutas = dict(RUTAS, config=a.config, fase=a.fase, estado=a.estado)
    if a.raiz_datos:
        for k in ('estado', 'firewall', 'buzon', 'respuestas', 'oplog', 'dnsmasq_reservas', 'nft_base',
                  'dnsmasq_lan', 'nm_system_connections', 'migracion_pendiente',
                  'dnsmasq_bloqueo', 'bloqueo_cache', 'bloqueo_estado', 'logrotate_dns',
                  'bloqueo_timer_dropin', 'bloqueo_fail_open_estado'):
            rutas[k] = os.path.join(a.raiz_datos, rutas[k].lstrip('/'))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    r = Router(rutas)
    signal.signal(signal.SIGTERM, lambda *_: r.parar.set())
    if a.una_vez:
        r.ciclo()
    else:
        r.bucle()


if __name__ == '__main__':
    main()
