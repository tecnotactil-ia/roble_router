#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""router_adb — vigilante que mantiene SIEMPRE activo el «compartir Internet
por USB» (tethering) de los teléfonos Android conectados al router, por ADB.

Por qué existe este servicio APARTE de routerd: tras un corte de luz la
portátil-router rearranca y el teléfono Android vuelve a modo "solo carga"
(deja de compartir). routerd ya tiene su propio watchdog y su propio ciclo
crítico (nftables, rutas, DHCP) — meterle aquí comandos ADB (que pueden
tardar, colgarse, o hacer que la conexión USB se caiga un instante al
cambiar de función) sería arriesgar ese watchdog por algo que no tiene nada
que ver con enrutar paquetes. Este módulo es, a propósito, un proceso y un
systemd unit distintos (systemd/router-adb.service), con su PROPIO
sd_notify/watchdog.

Diseño CONSERVADOR (revisión Opus — nunca se manda una orden al teléfono
"a la primera", y nunca más rápido de lo imprescindible):

1. `adb devices` (sólo lectura, LC_ALL=C, timeout 5 s; HOME/ANDROID_USER_HOME
   los pone systemd — ver systemd/router-adb.service, NUNCA /root) — lista de
   teléfonos con su estado (device / unauthorized / offline / sin permisos /
   otro). Cualquier línea que no sea un teléfono de verdad (cabecera, líneas
   del demonio adb, basura) se ignora; el serial se valida con una regex
   estricta (RE_SERIAL) antes de usarlo en NINGÚN comando.
2. Para cada teléfono en estado "device": `svc usb getFunctions` (sólo
   lectura). Si la lectura FALLA, no se hace nada en absoluto (ni orden, ni
   contar como fallo, ni tocar "compartiendo", ni oplog) — se mantiene lo
   último que se supo con certeza. Si la lectura es válida y dice que NO
   comparte, sólo se actúa (setFunctions) tras UMBRAL_LECTURAS_NO_COMPARTE
   (3) lecturas válidas seguidas diciendo lo mismo, y comprobando antes
   `getprop sys.boot_completed == "1"` (si el teléfono todavía está
   arrancando, no se toca nada ese ciclo). Tras cada intento, un cooldown
   que empieza en 60 s y se DOBLA cada vez que el anterior no cuajó, hasta
   un tope de 30 min (NIVELES_BACKOFF_S) — durante el cooldown nunca se
   manda una segunda orden. El fallback alterna rndis↔ncm y recuerda cuál
   funcionó por serial (ver `elegir_candidata`).
3. Además de lo que diga `getFunctions`, se comprueba de verdad que exista
   CUALQUIER interfaz de red en el PROPIO portátil (sin filtrar por driver:
   da igual cómo se llame, lo que importa es el serie) cuyo dispositivo USB
   padre tenga ese mismo número de serie (mismo recorrido de /sys que
   routerd._usb_info, pero a la inversa). Si adb dice "comparte" (rndis o
   ncm) y SÍ hay interfaz: comparte de verdad. Si adb dice "comparte" pero
   NO hay interfaz: nunca se manda ninguna orden (sería inútil: el teléfono
   ya cree que está compartiendo) — sólo se anota en `ultima_accion`/
   `ultimo_error` y se avisa una vez por el oplog. `setFunctions` SÓLO se
   intenta cuando adb dice que NO hay ni rndis ni ncm (la guarda de 3
   lecturas + cooldown de más arriba).
4. Nunca se ejecuta en el teléfono nada que no sea getFunctions,
   setFunctions, getprop de modelo/versión y getprop sys.boot_completed.
5. El estado de cada serial (cooldown, nivel de backoff, qué función
   funcionó…) sobrevive a que el teléfono desaparezca un rato de
   `adb devices` (USB flojo, reinicio corto…): sólo se olvida tras
   TTL_AUSENCIA_S (30 min) sin verse.
6. Publica /run/router/adb.json (atómico, 0644) — formato documentado en
   docs/CONTRATO.md — y añade una línea al oplog de routerd
   (/var/log/router/operaciones.log, accion="adb_tether") SÓLO cuando algo
   cambia: se empieza a compartir, se deja de compartir, aparece un
   teléfono sin autorizar (con el mensaje claro de qué hacer), o adb dice
   que un teléfono comparte pero no aparece su interfaz en el router.

Uso:  router_adb.py [--config /etc/router/router.json]
                     [--estado /run/router/adb.json]
                     [--oplog /var/log/router/operaciones.log] [--una-vez]
"""
import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

LOG = logging.getLogger('router_adb')

RUTAS = {
    'config': '/etc/router/router.json',
    'estado': '/run/router/adb.json',
    'oplog': '/var/log/router/operaciones.log',
}

ADB_BIN = '/usr/bin/adb'

# H5 (misma idea que routerd): un serial que no venga de un teléfono de
# verdad (línea manipulada, basura de la salida de `adb devices`) no debe
# llegar NUNCA a un argumento de `adb -s <serial> ...`. Los seriales USB
# reales son alfanuméricos (a veces con '.', '_', '-'); cualquier otra cosa
# (espacios, ':', '/', '$', ';', backticks…) se rechaza entero.
RE_SERIAL = re.compile(r'^[A-Za-z0-9._-]{1,64}$')

# MEDIA7: `getFunctions` sólo puede devolver nombres de función USB de
# verdad (rndis, ncm, mtp, adb, acm…) — cualquier token que no case con esto
# se descarta en vez de propagarse tal cual a estado.json.
RE_TOKEN_FUNCION = re.compile(r'^[a-z_]{1,16}$')

FUNCIONES_TETHER = {'rndis', 'ncm'}

TIMEOUT_DEVICES = 5
TIMEOUT_SHELL = 8

# ALTA2 (revisión Opus): nunca se actúa a la primera. Hacen falta N lecturas
# VÁLIDAS consecutivas (nunca fallidas: eso lo filtra ALTA1 antes de llegar
# aquí) diciendo "no comparte" antes de mandar la primera orden; el mismo
# umbral se reutiliza para la comprobación de la interfaz de kernel (MEDIA8).
UMBRAL_LECTURAS_NO_COMPARTE = 3
# Cooldown tras cada intento: empieza en 60 s y se dobla cada vez que el
# anterior no cuajó, con tope en 30 min.
NIVELES_BACKOFF_S = [60, 120, 240, 480, 960, 1800]
# ALTA3: un serial ausente de `adb devices` NO se olvida al primer ciclo
# (USB flojo, reinicio corto…) — sólo tras media hora sin verse.
TTL_AUSENCIA_S = 30 * 60
# MEDIA5: un ciclo con muchos teléfonos lentos no debe poder comerse el
# watchdog (60 s) — pasado este tiempo, los que falten se dejan "pendientes"
# para el ciclo siguiente en vez de seguir procesando.
DURACION_MAX_CICLO_S = 25
# MEDIA5: intervalo_s de router.json siempre acotado a este rango.
INTERVALO_MIN_S = 5
INTERVALO_MAX_S = 30
# MEDIA5: paso de la espera "troceada" entre ciclos (nunca dormir de una
# sola vez más de esto sin poder reaccionar a una parada/avisar al watchdog).
PASO_ESPERA_S = 5
# MEDIA7: longitud máxima de un texto que viene del teléfono (modelo/versión).
MAX_TEXTO_DISPOSITIVO = 64

ESTADOS_CONOCIDOS = ('device', 'unauthorized', 'offline', 'bootloader', 'recovery', 'sideload', 'host')


def ahora_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _sd_notify(mensaje):
    """sd_notify mínimo (copiado de routerd._sd_notify — M7): nunca lanza ni
    debe poder tirar el ciclo; si no hay Type=notify (pruebas, --una-vez a
    mano) NOTIFY_SOCKET no existe y esto no hace nada."""
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


def escribir_atomico(ruta, texto, modo=0o644):
    """Mismo patrón que routerd.escribir_atomico: temporal exclusivo en el
    mismo directorio + fsync + rename atómico, para que el panel nunca vea
    un /run/router/adb.json a medio escribir."""
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
    """Añade una línea al oplog de routerd (mismo formato: fecha, usuario,
    accion, datos, ok, mensaje — ver docs/CONTRATO.md).

    H4 (igual que routerd.oplog): `datos` nunca se escribe si pesa más de
    2048 bytes como JSON (se sustituye por un marcador) — una línea de
    oplog nunca debe poder crecer sin límite.

    BAJA9 (revisión Opus): se abre con O_APPEND (dos procesos distintos
    —routerd y este— escriben el mismo fichero, y O_APPEND es lo que
    garantiza que un write() no se entrelace a medias con el del otro),
    O_NOFOLLOW (nunca seguir un symlink puesto ahí por alguien más: si
    operaciones.log resultara ser un enlace, se prefiere fallar en vez de
    escribir donde no toca) y O_CLOEXEC (que un `adb`/`svc` lanzado con
    subprocess no herede este descriptor abierto)."""
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
    (LOG.info if ok else LOG.warning)('adb_tether: %s', mensaje)


# ───────────────────────────── configuración ─────────────────────────────

def leer_config_adb(ruta):
    """{'habilitada': bool, 'intervalo_s': number} de router.json →
    'adb_tether'. Cualquier problema (fichero ausente, JSON roto, forma
    rara) cae al defecto (habilitada=True, intervalo_s=10) — este servicio
    NUNCA debe quedarse parado por una router.json inválida; prefiere
    seguir vigilando con el defecto a no vigilar nada.

    MEDIA5: `intervalo_s` siempre se acota a [INTERVALO_MIN_S,
    INTERVALO_MAX_S] — ni un valor absurdamente bajo (machacar adb/el
    teléfono) ni absurdamente alto (watchdog, reacción lenta tras un
    corte) puede colarse desde router.json."""
    defecto = {'habilitada': True, 'intervalo_s': 10}
    try:
        with open(ruta) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return dict(defecto)
    if not isinstance(cfg, dict):
        return dict(defecto)
    seccion = cfg.get('adb_tether')
    if not isinstance(seccion, dict):
        return dict(defecto)
    habilitada = seccion.get('habilitada', True)
    intervalo = seccion.get('intervalo_s', 10)
    if not isinstance(habilitada, bool):
        habilitada = True
    if isinstance(intervalo, bool) or not isinstance(intervalo, (int, float)) or intervalo <= 0:
        intervalo = 10
    intervalo = max(INTERVALO_MIN_S, min(INTERVALO_MAX_S, intervalo))
    return {'habilitada': habilitada, 'intervalo_s': intervalo}


# ──────────────────────────── ejecución de adb ────────────────────────────

def _entorno():
    """Entorno para los comandos adb: fuerza LC_ALL=C (para que el parseo de
    getFunctions/getprop no dependa del locale del sistema).

    ALTA4 (revisión Opus): a propósito NO se fuerza aquí HOME ni
    ANDROID_USER_HOME — deben venir ya puestos en el entorno real del
    proceso. En producción los pone systemd/router-adb.service, apuntando
    al StateDirectory propio de este servicio (/var/lib/router-adb), NUNCA
    /root (con ProtectHome=yes eso ni siquiera sería escribible, y aunque
    lo fuera, este servicio no debe depender de la clave adb de root)."""
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    return env


def run(args, timeout=TIMEOUT_SHELL):
    """Ejecuta un comando SIN shell (lista fija de argumentos) — mismo
    espíritu que routerd.run, reimplementado aquí a propósito (M7: este
    módulo no importa routerd, para no acoplar dos servicios/watchdogs
    distintos). Nunca lanza: un timeout o un binario ausente se convierten
    en un CompletedProcess con returncode != 0, igual que cualquier otro
    fallo del comando — así el llamador siempre trata todo con el mismo
    camino (nunca una excepción sin capturar que tire el ciclo). Las
    pruebas sustituyen esta función entera (`mock.patch('router_adb.run')`)
    por un `adb` de mentira."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=_entorno())
    except subprocess.TimeoutExpired as e:
        salida = e.stdout if isinstance(e.stdout, str) else (e.stdout or b'').decode('utf-8', 'replace')
        error = e.stderr if isinstance(e.stderr, str) else (e.stderr or b'').decode('utf-8', 'replace')
        return subprocess.CompletedProcess(args, 124, stdout=salida, stderr=error or 'tiempo agotado')
    except OSError as e:
        return subprocess.CompletedProcess(args, 127, stdout='', stderr=str(e))


def adb_devices():
    """(texto_stdout, error_o_None) de `adb devices`. error no-None sólo si
    el comando en sí falló (binario ausente, timeout) — nunca por la lista
    estar vacía (0 teléfonos es un resultado válido)."""
    r = run([ADB_BIN, 'devices'], timeout=TIMEOUT_DEVICES)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or 'adb devices: código %d' % r.returncode).strip()
    return r.stdout or '', None


def adb_shell(serial, *comando):
    """Ejecuta `adb -s <serial> shell <comando>`. El serial SIEMPRE debe
    venir ya validado por RE_SERIAL antes de llegar aquí — esta función no
    vuelve a comprobarlo porque todas sus llamadoras reciben el serial de
    `parsear_adb_devices`, que ya lo filtró."""
    r = run([ADB_BIN, '-s', serial, 'shell'] + list(comando), timeout=TIMEOUT_SHELL)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or 'adb shell código %d' % r.returncode).strip()
    return (r.stdout or '').strip(), None


def adb_get_functions(serial):
    """(lista_de_funciones_en_minusculas, error_o_None). Única lectura
    permitida del estado de tethering USB. MEDIA7: cualquier token que no
    case con RE_TOKEN_FUNCION (basura, mayúsculas raras, símbolos) se
    descarta en vez de propagarse."""
    # `svc usb getFunctions` escribe su respuesta en STDERR (probado en un
    # TCL con Android 16: stdout vacío, stderr "rndis"), así que hay que mirar
    # las dos salidas, descartando las líneas del propio cliente adb
    # ("* daemon not running…"). Una respuesta sin ninguna función
    # reconocible es una lectura NO válida (devuelve error), nunca "no
    # comparte": así un cambio de formato jamás provoca un setFunctions.
    r = run([ADB_BIN, '-s', serial, 'shell', 'svc', 'usb', 'getFunctions'],
            timeout=TIMEOUT_SHELL)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or 'adb shell código %d' % r.returncode).strip()
    lineas = [l.strip() for l in ((r.stdout or '') + '\n' + (r.stderr or '')).splitlines()]
    lineas = [l for l in lineas if l and not l.startswith('*')]
    crudos = (f.strip().lower() for l in lineas for f in l.split(','))
    funciones = sorted({f for f in crudos if RE_TOKEN_FUNCION.fullmatch(f)})
    if not funciones:
        return None, 'getFunctions sin respuesta reconocible'
    return funciones, None


def adb_set_functions(serial, funcion):
    """Pide activar `funcion` ('rndis' o 'ncm'). La conexión adb puede
    caerse un instante al cambiar la función USB del teléfono — es normal
    y NO se trata como error aquí: se devuelve igualmente (ok, err) para
    que quien llama decida, pero el bucle principal nunca lo escribe en el
    oplog ni lo cuenta como un fallo "serio" por sí solo (el cooldown/
    backoff se basa en si en los siguientes ciclos sigue sin compartir, no
    en si esta orden devolvió 0)."""
    _, err = adb_shell(serial, 'svc', 'usb', 'setFunctions', funcion)
    return err is None, err


def adb_getprop(serial, propiedad):
    salida, err = adb_shell(serial, 'getprop', propiedad)
    if salida is None:
        return None, err
    return salida.strip() or None, None


def adb_boot_completed(serial):
    """ALTA2: True sólo si `getprop sys.boot_completed` devuelve EXACTAMENTE
    "1". Si la lectura falla, False (no boot_listo) — nunca se actúa "por si
    acaso" cuando no se puede confirmar que el sistema del teléfono ya
    arrancó del todo."""
    salida, err = adb_shell(serial, 'getprop', 'sys.boot_completed')
    if salida is None:
        return False, err
    return salida.strip() == '1', None


def _sanear_texto(valor, maximo=MAX_TEXTO_DISPOSITIVO):
    """MEDIA7: cualquier texto que venga del teléfono (modelo, versión de
    Android) se limpia de caracteres de control y se recorta a `maximo`
    antes de publicarse en adb.json — nunca se propaga tal cual."""
    if valor is None:
        return None
    limpio = ''.join(c for c in valor if c.isprintable()).strip()[:maximo]
    return limpio or None


# ─────────────────────── parseo de `adb devices` ───────────────────────

def parsear_adb_devices(texto):
    """[{serial, estado}] de la salida de `adb devices`.

    Robusto a: la línea de cabecera ("List of devices attached"), líneas
    del demonio ("* daemon not running; starting now…"), líneas vacías, y
    cualquier serial que no case con RE_SERIAL (se descarta entero, nunca
    se intenta "limpiarlo" — más vale ignorar un teléfono raro que arriesgar
    que ese texto llegue a un argumento de adb). El estado "no permissions"
    es el único de dos palabras; el resto de estados se toma como la
    primera palabra tras el serial, y si no es uno de los conocidos se
    normaliza a "desconocido" en vez de inventarse nada."""
    dispositivos = []
    for linea in (texto or '').splitlines():
        linea = linea.rstrip()
        if not linea or linea.startswith('*') or linea.startswith('List of devices') \
                or linea.startswith('adb server'):
            continue
        partes = linea.split(None, 1)
        if len(partes) < 2:
            continue
        serial, resto = partes[0], partes[1].strip()
        if not RE_SERIAL.match(serial):
            LOG.warning('adb devices: serial con forma inesperada ignorado (%r)', serial)
            continue
        if resto.startswith('no permissions'):
            estado = 'no permissions'
        else:
            primera = resto.split()[0] if resto.split() else ''
            estado = primera if primera in ESTADOS_CONOCIDOS else 'desconocido'
        dispositivos.append({'serial': serial, 'estado': estado})
    return dispositivos


# ──────────────────── interfaz de kernel por serial (MEDIA8) ────────────────────

def _leer_sysfs(ruta):
    try:
        with open(ruta) as f:
            return f.read().strip()
    except OSError:
        return None


def _interfaz_tether_para_serial(serial, raiz='/sys/class/net'):
    """Nombre de la interfaz de red CUYO dispositivo USB padre tiene este
    número de serie, o None si no existe ninguna. Mismo recorrido que
    routerd._usb_info (subir por /sys/class/net/<if>/device hasta encontrar
    el nodo con 'idVendor'), pero partiendo del serial en vez de la
    interfaz — aquí lo que importa es confirmar que el KERNEL, no sólo adb,
    ve de verdad el tethering.

    Revisión Opus (ronda 3): a propósito NO se filtra por driver (ni
    rndis_host/cdc_ncm/cdc_ether ni ningún otro) — lo único que importa es
    que el serie del dispositivo USB coincida; filtrar por driver sólo
    arriesgaría descartar una interfaz real por un nombre de driver que no
    se tuvo en cuenta (kernels/módulos distintos). `raiz` es parametrizable
    para las pruebas (un /sys de mentira)."""
    try:
        interfaces = os.listdir(raiz)
    except OSError:
        return None
    for ifname in sorted(interfaces):
        try:
            d = os.path.realpath(os.path.join(raiz, ifname, 'device'))
        except OSError:
            continue
        for _ in range(6):
            if os.path.exists(os.path.join(d, 'idVendor')):
                if _leer_sysfs(os.path.join(d, 'serial')) == serial:
                    return ifname
                break
            nuevo = os.path.dirname(d)
            if nuevo == d:
                break
            d = nuevo
    return None


# ──────────────────────── decisión (pura, sin adb) ────────────────────────

def elegir_candidata(estado_serial):
    """Qué función USB probar esta vez para este serial: la última que
    funcionó si todavía no se ha intentado nada en este episodio; si no,
    alterna rndis↔ncm en cada intento nuevo (fallback pedido: "prueba rndis
    y si no cuaja, intenta ncm")."""
    probando = estado_serial.get('funcion_probando')
    funciona = estado_serial.get('funcion_funciona')
    if probando is None:
        return funciona or 'rndis'
    return 'ncm' if probando == 'rndis' else 'rndis'


def decidir_accion(estado_serial, funciones, ahora_ts):
    """Pura (no ejecuta nada): decide si hay que intentar activar el
    tethering AHORA. MUTA `estado_serial` pero nunca llama a adb.

    Dos guardas conservadoras (ALTA2, revisión Opus):
    1) sólo se actúa tras UMBRAL_LECTURAS_NO_COMPARTE lecturas VÁLIDAS
       consecutivas que digan "no comparte" (nunca a la primera) — así un
       hueco de un ciclo (p. ej. justo tras reconectar el USB) no dispara
       una orden de más.
    2) tras cada intento, un cooldown que empieza en 60 s y se DOBLA cada
       vez que el anterior no ha cuajado (visto en un ciclo posterior), con
       tope en 30 min — mientras el cooldown esté activo nunca se manda una
       segunda orden, por muchas lecturas "no comparte" que se acumulen
       entretanto (esas lecturas siguen contando para la guarda 1, pero no
       se actúa hasta que el cooldown termine).

    Devuelve (compartiendo: bool, candidata_o_None: str|None,
    descripcion: str). `candidata` no-None significa "el llamador debe
    comprobar boot_completed y, si está listo, mandar setFunctions con
    esto AHORA" — confirmar el intento es responsabilidad del llamador, vía
    `confirmar_intento()` (nunca aquí, porque si boot_completed no está
    listo no debe consumirse ni el cooldown ni el nivel de backoff)."""
    estado_serial.setdefault('lecturas_no_comparte', 0)
    estado_serial.setdefault('nivel_backoff', 0)
    compartiendo = bool(set(funciones) & FUNCIONES_TETHER)
    if compartiendo:
        estado_serial['lecturas_no_comparte'] = 0
        estado_serial['nivel_backoff'] = 0
        # BAJA-MEDIA (revisión Opus, ronda 3): al volver a compartir de
        # verdad se olvida qué función se estaba "probando" — ese episodio
        # de intentos ya terminó con éxito; el próximo que haga falta
        # empieza de cero (o, si se recuerda cuál funcionó, por ésa).
        estado_serial['funcion_probando'] = None
        if 'rndis' in funciones:
            estado_serial['funcion_funciona'] = 'rndis'
        elif 'ncm' in funciones:
            estado_serial['funcion_funciona'] = 'ncm'
        return True, None, 'compartiendo por USB (%s)' % '/'.join(sorted(set(funciones) & FUNCIONES_TETHER))

    estado_serial['lecturas_no_comparte'] += 1
    ultimo = estado_serial.get('ultimo_intento_ts')
    if ultimo is not None:
        cooldown = estado_serial.get('cooldown_actual_s') or NIVELES_BACKOFF_S[0]
        restante = cooldown - (ahora_ts - ultimo)
        if restante > 0:
            return False, None, 'en cooldown tras el último intento (%.0fs restantes)' % restante
    if estado_serial['lecturas_no_comparte'] < UMBRAL_LECTURAS_NO_COMPARTE:
        return (False, None,
                'confirmando que no comparte (%d/%d lecturas válidas)' %
                (estado_serial['lecturas_no_comparte'], UMBRAL_LECTURAS_NO_COMPARTE))
    candidata = elegir_candidata(estado_serial)
    return False, candidata, 'listo para activar compartir USB (%s)' % candidata


def confirmar_intento(estado_serial, candidata, ahora_ts):
    """Se llama SÓLO después de mandar de verdad `setFunctions candidata`
    (nunca si sys.boot_completed no estaba listo — en ese caso no se
    consume ni el cooldown ni el nivel de backoff, se reintenta en el
    siguiente ciclo): fija el cooldown que corresponde a ESTE intento (el
    nivel vigente antes de escalarlo) y sube el nivel para el próximo,
    hasta el tope de NIVELES_BACKOFF_S."""
    nivel = min(estado_serial.get('nivel_backoff', 0), len(NIVELES_BACKOFF_S) - 1)
    estado_serial['cooldown_actual_s'] = NIVELES_BACKOFF_S[nivel]
    estado_serial['funcion_probando'] = candidata
    estado_serial['ultimo_intento_ts'] = ahora_ts
    estado_serial['lecturas_no_comparte'] = 0
    estado_serial['nivel_backoff'] = min(nivel + 1, len(NIVELES_BACKOFF_S) - 1)


# ───────────────────────────── el vigilante ─────────────────────────────

class AdbTether:
    def __init__(self, rutas):
        self.rutas = rutas
        self.cfg = {'habilitada': True, 'intervalo_s': 10}
        self._estado = {}   # serial -> ver _estado_inicial()
        self._previo = {}   # serial -> {estado_adb, compartiendo} del último ciclo publicado (para el oplog)
        self.parar = threading.Event()

    @staticmethod
    def _estado_inicial():
        return {
            'lecturas_no_comparte': 0, 'nivel_backoff': 0, 'cooldown_actual_s': None,
            'ultimo_intento_ts': None, 'funcion_probando': None, 'funcion_funciona': None,
            'ultimo_error': None, 'modelo': None, 'android': None,
            'compartiendo': False, 'funciones': [], 'interfaz': None, 'visto_ts': None,
            'ultima_accion': '',
        }

    def _oplog(self, serial, ok, mensaje):
        escribir_oplog(self.rutas['oplog'], 'sistema', 'adb_tether', {'serial': serial}, ok, mensaje)

    def _detectar_cambio(self, serial, estado_adb, compartiendo, modelo, sin_interfaz=False):
        """Escribe al oplog SÓLO si algo cambió desde el último ciclo (H4:
        nunca una línea por ciclo, que inundaría /var/log/router) — ver
        docs/CONTRATO.md. Cuatro eventos: aparece un teléfono sin autorizar
        (mensaje con la instrucción exacta para el usuario), se empieza a
        compartir, se deja de compartir (para que quede constancia de la
        regresión, no sólo de la recuperación), o adb dice que comparte
        pero no aparece ninguna interfaz en el router (revisión Opus, ronda
        3 — MEDIA: se avisa una sola vez, nunca se manda ninguna orden por
        esto)."""
        anterior = self._previo.get(serial) or {}
        nombre = modelo or serial
        era_unauthorized = anterior.get('estado_adb') == 'unauthorized'
        if estado_adb == 'unauthorized' and not era_unauthorized:
            self._oplog(serial, False,
                        'Teléfono no autorizado detectado (%s): Acepta «Permitir depuración USB» '
                        'en el teléfono' % serial)
        if compartiendo and not anterior.get('compartiendo'):
            self._oplog(serial, True, 'Activado compartir Internet por USB en %s (%s)' % (nombre, serial))
        elif anterior.get('compartiendo') and not compartiendo and 'compartiendo' in anterior:
            self._oplog(serial, False, 'Se ha dejado de compartir Internet por USB en %s (%s)' % (nombre, serial))
        if sin_interfaz and not anterior.get('sin_interfaz'):
            self._oplog(serial, False,
                        'El teléfono %s dice que comparte pero no aparece ninguna interfaz en el '
                        'router: revisa el cable/puerto USB' % nombre)
        self._previo[serial] = {'estado_adb': estado_adb, 'compartiendo': compartiendo, 'sin_interfaz': sin_interfaz}

    def _procesar(self, serial, estado_adb, ahora_ts):
        est = self._estado.setdefault(serial, self._estado_inicial())
        est['visto_ts'] = ahora_ts
        modelo = est.get('modelo')
        android = est.get('android')
        funciones = est.get('funciones', [])
        interfaz = est.get('interfaz')
        compartiendo = est.get('compartiendo', False)
        accion = est.get('ultima_accion') or ''
        sin_interfaz = False

        if estado_adb == 'device':
            # MEDIA5: modelo/versión se leen UNA sola vez por serial (se
            # cachean); nunca cambian mientras el teléfono sigue siendo el
            # mismo, no hace falta gastar un comando adb en cada ciclo.
            if est.get('modelo') is None:
                valor, _ = adb_getprop(serial, 'ro.product.model')
                est['modelo'] = _sanear_texto(valor)
            if est.get('android') is None:
                valor, _ = adb_getprop(serial, 'ro.build.version.release')
                est['android'] = _sanear_texto(valor)
            modelo, android = est.get('modelo'), est.get('android')

            funciones_leidas, err_lectura = adb_get_functions(serial)
            if funciones_leidas is None:
                # ALTA1 (revisión Opus): la lectura falló -> NO SE HACE NADA:
                # ni se manda ninguna orden, ni cuenta como lectura válida
                # (no toca 'lecturas_no_comparte'), ni cambia "compartiendo"
                # (se mantiene lo último publicado), ni se escribe nada al
                # oplog (al no cambiar compartiendo, _detectar_cambio no
                # dispara nada). Sólo se anota el error, para depurar.
                est['ultimo_error'] = err_lectura
                funciones = est.get('funciones', [])
                interfaz = est.get('interfaz')
                compartiendo = est.get('compartiendo', False)
                accion = est.get('ultima_accion') or 'lectura de getFunctions fallida (sin cambios)'
            else:
                est['ultimo_error'] = None
                funciones = funciones_leidas
                interfaz = _interfaz_tether_para_serial(serial)
                adb_dice_comparte = bool(set(funciones) & FUNCIONES_TETHER)

                if adb_dice_comparte and not interfaz:
                    # MEDIA (revisión Opus, ronda 3): adb dice "rndis/ncm"
                    # pero el kernel del propio router no ve NINGUNA
                    # interfaz con ese serie — mandar setFunctions aquí
                    # sería inútil (el teléfono ya cree que está
                    # compartiendo) y podría incluso empeorarlo. Nunca se
                    # actúa en este caso: sólo se anota y se avisa una vez.
                    compartiendo = False
                    sin_interfaz = True
                    accion = 'el teléfono dice que comparte pero no aparece interfaz en el router'
                    est['ultimo_error'] = accion
                else:
                    # adb_dice_comparte and interfaz -> compartiendo de
                    # verdad (decidir_accion lo confirma sin mandar nada).
                    # not adb_dice_comparte -> flujo normal: 3 lecturas
                    # válidas + cooldown antes de intentar setFunctions.
                    compartiendo, candidata, accion = decidir_accion(est, funciones, ahora_ts)
                    if candidata:
                        # ALTA2: exigir sys.boot_completed==1 antes de actuar.
                        boot_listo, err_boot = adb_boot_completed(serial)
                        if boot_listo:
                            adb_set_functions(serial, candidata)
                            confirmar_intento(est, candidata, ahora_ts)
                            accion = 'activando compartir USB (%s)' % candidata
                        elif err_boot is None:
                            accion = 'esperando a que el teléfono termine de arrancar (sys.boot_completed != 1)'
                        else:
                            accion = 'no se pudo comprobar sys.boot_completed: %s' % err_boot

                est['funciones'] = funciones
                est['interfaz'] = interfaz
                est['compartiendo'] = compartiendo
        elif estado_adb in ('offline', 'desconocido'):
            # BAJA (revisión Opus, ronda 3): perder adb (offline) o ver un
            # estado que no se reconoce NO significa que el teléfono haya
            # dejado de compartir de verdad — sólo que no se puede
            # confirmar nada ahora mismo. Se conserva lo último sabido, sin
            # oplog (no es un cambio real, es "no se puede saber").
            compartiendo = est.get('compartiendo', False)
            funciones = est.get('funciones', [])
            interfaz = est.get('interfaz')
            accion = 'fuera de línea' if estado_adb == 'offline' else 'estado adb desconocido: %s' % estado_adb
        else:
            # unauthorized, no permissions, bootloader, recovery, sideload,
            # host: ninguno de estos admite `shell` normal — no hay forma
            # de confirmar tethering, así que se fuerza a False (a
            # diferencia de offline/desconocido, aquí sí se sabe con
            # certeza que no se puede estar compartiendo por ADB).
            funciones, interfaz, compartiendo = [], None, False
            est['funciones'], est['interfaz'], est['compartiendo'] = [], None, False
            if estado_adb == 'unauthorized':
                accion = 'sin autorizar: acepta la depuración USB en el teléfono'
            elif estado_adb == 'no permissions':
                accion = 'sin permisos (revisa las reglas udev / el grupo plugdev)'
            else:
                accion = 'estado adb: %s' % estado_adb

        est['ultima_accion'] = accion
        self._detectar_cambio(serial, estado_adb, compartiendo, modelo, sin_interfaz)

        return {
            'serial': serial, 'modelo': modelo, 'android': android, 'estado_adb': estado_adb,
            'funciones': funciones, 'interfaz': interfaz, 'compartiendo': compartiendo,
            'ultima_accion': accion, 'ultimo_error': est.get('ultimo_error'), 'ts': ahora_iso(),
        }

    def _entrada_diferida(self, serial, estado_adb):
        """MEDIA5: este teléfono se queda sin procesar este ciclo porque ya
        se agotó el tiempo máximo (DURACION_MAX_CICLO_S) — se publica lo
        último que se sabía de él, marcado como pendiente, en vez de
        omitirlo (el panel no debe ver desaparecer un teléfono sólo porque
        había demasiados ese ciclo)."""
        est = self._estado.get(serial) or {}
        return {
            'serial': serial, 'modelo': est.get('modelo'), 'android': est.get('android'),
            'estado_adb': estado_adb, 'funciones': est.get('funciones', []),
            'interfaz': est.get('interfaz'), 'compartiendo': est.get('compartiendo', False),
            'ultima_accion': 'pendiente: se saltó este ciclo por falta de tiempo (demasiados teléfonos)',
            'ultimo_error': est.get('ultimo_error'), 'ts': ahora_iso(),
        }

    def _aplicar_ttl_ausencia(self, vistos, ahora_ts):
        """ALTA3: un serial que ya no aparece en `adb devices` NO se olvida
        de inmediato (eso perdería el cooldown/nivel de backoff acumulado
        por un USB flojo o un reinicio corto) — sólo tras TTL_AUSENCIA_S sin
        verse."""
        for serial in list(self._estado):
            if serial in vistos:
                continue
            visto_ts = self._estado[serial].get('visto_ts')
            if visto_ts is None or (ahora_ts - visto_ts) >= TTL_AUSENCIA_S:
                self._estado.pop(serial, None)
                self._previo.pop(serial, None)

    def _publicar(self, resultado):
        escribir_atomico(self.rutas['estado'], json.dumps(resultado, ensure_ascii=False, indent=2) + '\n')

    def ciclo(self):
        self.cfg = leer_config_adb(self.rutas['config'])
        if not self.cfg.get('habilitada', True):
            self._publicar([])
            return
        salida, err = adb_devices()
        if salida is None:
            LOG.warning('adb devices falló: %s', err)
            return
        entradas = parsear_adb_devices(salida)
        ahora_ts = time.time()
        vistos = {d['serial'] for d in entradas}
        resultado = []
        for d in entradas:
            # MEDIA5: tope de duración por ciclo — si ya se ha gastado
            # demasiado tiempo (muchos teléfonos, alguno lento), los que
            # falten se dejan "pendientes" para el ciclo siguiente en vez
            # de arriesgar el watchdog de systemd.
            if (time.time() - ahora_ts) >= DURACION_MAX_CICLO_S:
                resultado.append(self._entrada_diferida(d['serial'], d['estado']))
            else:
                resultado.append(self._procesar(d['serial'], d['estado'], ahora_ts))
            # MEDIA5: un ping de watchdog TRAS CADA TELÉFONO, no sólo al
            # final del ciclo — un lote largo de teléfonos lentos no debe
            # poder parecer colgado.
            _sd_notify('WATCHDOG=1')
        self._aplicar_ttl_ausencia(vistos, ahora_ts)
        self._publicar(resultado)

    def bucle(self):
        notificado = False
        while not self.parar.is_set():
            t0 = time.time()
            try:
                self.ciclo()
            except Exception:   # este vigilante tampoco puede morir por un ciclo raro (H5)
                LOG.exception('error en el ciclo de router_adb')
            if not notificado:
                _sd_notify('READY=1')
                notificado = True
            _sd_notify('WATCHDOG=1')
            intervalo = float(self.cfg.get('intervalo_s', 10) or 10)
            restante = max(1.0, intervalo - (time.time() - t0))
            # MEDIA5: espera "troceada" en pasos cortos (nunca duerme de una
            # sola vez más de PASO_ESPERA_S) — reacciona antes a una parada
            # y avisa al watchdog también mientras está ocioso, no sólo
            # entre ciclos.
            while restante > 0 and not self.parar.is_set():
                paso = min(PASO_ESPERA_S, restante)
                if self.parar.wait(paso):
                    break
                restante -= paso
                _sd_notify('WATCHDOG=1')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', default=RUTAS['config'])
    ap.add_argument('--estado', default=RUTAS['estado'])
    ap.add_argument('--oplog', default=RUTAS['oplog'])
    ap.add_argument('--una-vez', action='store_true')
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', stream=sys.stdout)
    rutas = dict(RUTAS, config=a.config, estado=a.estado, oplog=a.oplog)
    t = AdbTether(rutas)
    signal.signal(signal.SIGTERM, lambda *_: t.parar.set())
    if a.una_vez:
        t.ciclo()
    else:
        t.bucle()


if __name__ == '__main__':
    main()
