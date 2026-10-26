#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""router-migrar — la máquina pasa a ser el router de la LAN, con vuelta atrás.

Orden completo de la activación (de punta a punta):

 0. COMPROBACIONES PREVIAS (N4, función `comprobaciones_previas()`): el
    perfil NetworkManager de la LAN (activacion.perfil_lan de router.json)
    existe con autoconnect=no, sin gateway propio y la dirección correcta;
    `arping` es el de iputils; están los binarios nft/ip/conntrack/dnsmasq/
    nmcli/arping; dnsmasq está enabled; nftables.service NO está enabled; no
    hay ya una `table ip filter`; Docker no está enabled; routerd está
    activo. Si falla cualquiera, se aborta sin tocar nada. El admin puede
    repasar esta misma lista a mano con `router-migrar --comprobar` (sólo
    imprime ✔/✘, no cambia nada) antes de lanzar la activación de verdad.
 1. ESPERA a que el RJ45 (lan.interfaz de router.json) tenga enlace y a que
    NADIE más tenga la IP del router (lan.ip, arping -D): mientras otro
    equipo (el que tenga ya la IP del router) conteste, NO se toca nada —
    dos equipos con la misma IP tumbarían la red. SÓLO si la WAN Wi-Fi está
    configurada (activacion.perfil_wifi Y activacion.wifi_interfaz
    rellenos) se comprueba ADemás si por el Wi-Fi sigue vivo otro equipo con
    la misma IP.
 2. Condiciones OK: se escribe el marcador persistente
    `/etc/router/migracion-pendiente` (N2) y se programa, con `systemd-run`,
    un deshacer automático INDEPENDIENTE (`router-deshacer`, a los 30 min) —
    ANTES de activar nada, para que la vuelta atrás no dependa de que este
    proceso siga vivo (un corte de luz, un `kill -9`…). Si no se puede
    escribir el marcador o programar el temporizador, se aborta sin activar.
 3. ACTIVA: el perfil de la LAN (lan.ip/prefijo en lan.interfaz); si hay
    WAN Wi-Fi configurada, se apaga el Wi-Fi (down + autoconnect no + radio
    wifi off, N5) — si seguía asociado a otro punto de acceso quedaría en la
    misma red que el RJ45 recién activado; `/etc/router/fase` →
    "produccion" (N1: ya no vive dentro de router.json; routerd la lee de
    ese fichero en cada ciclo e instala cortafuegos, NAT, balanceo y
    DHCP/DNS); ARP gratuito en lan.interfaz (L5) para que los vecinos
    olviden la MAC del equipo que antes tenía esa IP.
 4. VIGILA 30 min: si vuelve a aparecer otro equipo con la IP del router
    (por ARP, o por el Wi-Fi si está configurado), o si nadie confirma
    (router-migrar --confirmar) a tiempo, DESHACE (ver más abajo). El
    temporizador independiente del paso 2 hace lo mismo aunque este proceso
    no llegue a ejecutar este bucle.
 5. CONFIRMADO (`router-migrar --confirmar`, sólo válido si hay una
    activación en curso): cancela el temporizador de deshacer, borra el
    marcador y deja el perfil de la LAN con autoconexión (sobrevive a
    reinicios).

DESHACER (automático al final de la vigilancia, por el temporizador
independiente, por detectar un duplicado, o a mano con --deshacer): fase
"preparacion" (routerd retira todo lo suyo; si no lo confirma en 60 s, se
fuerza aquí mismo — N12), perfil de la LAN abajo y sin autoconexión, si hay
WAN Wi-Fi configurada se reconecta el Wi-Fi (radio on + autoconnect yes +
con up, N5), marcador borrado y temporizador cancelado. Cada paso va por
separado (N2): que uno falle no impide que los demás se intenten —
deshacer() tiene que llegar siempre al final. `--deshacer` a mano para
además el servicio router-migracion y el propio temporizador
router-deshacer.

Si la máquina se REINICIA con una activación sin confirmar (el marcador
sigue en disco), `router-migracion-arranque.service` lanza este script con
`--al-arrancar` en cada arranque: si el marcador existe, deshace — así un
reinicio durante la vigilancia vuelve a preparación y reactiva el Wi-Fi sin
esperar a que nadie se dé cuenta.

MODO PUNTO DE ACCESO Wi-Fi (sección "wifi_ap" de router.json, AP1, ver
core/wifi_ap.py y systemd/router-ap.service): con el AP configurado la LAN
es un puente NetworkManager «br-lan» (perfil LAN-ROUTER, tipo bridge, más
un perfil esclavo por el puerto de cable — activacion.puerto_cable — si lo
hay) y lan.interfaz apunta a br-lan, así que dnsmasq, nftables y las
estadísticas no cambian nada. La tarjeta del AP la saca NetworkManager de
su gestión (`nmcli device set ... managed no`; runtime al encender, y
91-router-ap.conf al CONFIRMAR para que persista tras un reinicio) y la
levanta hostapd con `bridge=br-lan` en su config (unidad router-ap.service:
el hostapd.service de Debian viene enmascarado, no se usa; la config
/etc/router/hostapd.conf, 0600 con la clave dentro, la escribe wifi_ap.py).
El AP SÓLO existe con el router ACTIVADO: lo enciende el paso 3 de la
activación (encender_ap) y lo apaga la vuelta atrás ANTES de bajar el
perfil de la LAN (apagar_ap). Una tarjeta no puede ser AP y WAN a la vez:
si wifi_ap y wifi_wan apuntan a la misma interfaz, la WAN Wi-Fi se trata
como deshabilitada (misma regla que aplica routerd al cargar la config).

Estado legible en /run/router/migracion.json y en el journal
(journalctl -u router-migracion).

Uso:  router-migrar               # (lo lanza el servicio) espera, activa y vigila
      router-migrar --confirmar   # da por buena la activación en curso
      router-migrar --deshacer    # vuelta atrás manual inmediata (+ para los servicios)
      router-migrar --al-arrancar # (lo lanza router-migracion-arranque.service)
      router-migrar --comprobar   # sólo imprime la lista ✔/✘ de comprobaciones previas
"""
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

# wifi_ap.py es el módulo de apoyo del modo punto de acceso (AP1): genera y
# valida /etc/router/hostapd.conf, mira si la tarjeta admite modo AP… En
# producción todos los módulos del núcleo viven juntos (/usr/local/lib/router
# y el propio router-migrar corre desde ahí en la unidad systemd), así que se
# importa como uno cualquiera; si faltara (instalación a medias) queda None y
# las comprobaciones previas abortan la activación con AP antes de tocar nada.
try:
    import wifi_ap
except ImportError:
    # router-migrar también se instala como /usr/local/sbin/router-migrar
    # (--confirmar/--deshacer a mano, el temporizador router-deshacer): desde
    # ese camino no ve los módulos de /usr/local/lib/router — se añade y se
    # reintenta una vez.
    try:
        sys.path.append('/usr/local/lib/router')
        import wifi_ap
    except ImportError:
        wifi_ap = None

CONFIG = '/etc/router/router.json'
FASE_RUTA = '/etc/router/fase'                       # N1: la fase vive aquí, no en router.json
MARCADOR = '/etc/router/migracion-pendiente'          # N2: vuelta atrás independiente del proceso
ESTADO = '/run/router/migracion.json'
ESTADO_ROUTERD = '/run/router/estado.json'            # lo publica routerd (RUTAS['estado'] por defecto)
CONFIRMADA = '/run/router/migracion-confirmada'
UNIDAD_DESHACER = 'router-deshacer'
# N2: ruta del propio script, tal como debe quedar instalada, para que el
# temporizador independiente pueda invocarlo sin depender de este proceso.
EJECUTABLE = '/usr/local/sbin/router-migrar'
ESPERA_MAX_S = 3 * 3600      # tiempo máximo esperando a que quede libre la IP del router
VIGILANCIA_S = 30 * 60       # tiempo para confirmar antes de deshacer

# Sección "activacion" de router.json: opcional. Con la sección ausente, o
# con un campo suelto, estos son los valores por defecto:
DEFECTO_ACTIVACION = {'perfil_lan': 'LAN-ROUTER', 'perfil_wifi': '', 'wifi_interfaz': ''}
# Y estos, de última red de seguridad, si el propio router.json no se puede
# leer (deben coincidir con CONFIG_DEFECTO de routerd.py):
DEFECTO_LAN = {'interfaz': 'eth0', 'ip': '192.168.50.1', 'red': '192.168.50.0/24'}

# Valores REALES de esta instalación, llenados al arrancar por
# cargar_configuracion() leyendo /etc/router/router.json (ver más abajo).
LAN_IF = DEFECTO_LAN['interfaz']
LAN_IP = DEFECTO_LAN['ip']
LAN_PREFIJO = 24                    # de lan.red ("192.168.50.0/24" → 24)
PERFIL = DEFECTO_ACTIVACION['perfil_lan']   # nombre del perfil NM de la LAN
PERFIL_WIFI = ''                    # nombre del perfil NM de la WAN Wi-Fi (opcional)
WIFI_IF = ''                        # interfaz de la WAN Wi-Fi (opcional)
WIFI_ACTIVA = False                 # True sólo si PERFIL_WIFI y WIFI_IF están rellenos
CONFIG_LAN_OK = False               # router.json legible con lan.interfaz y lan.ip

# Modo punto de acceso Wi-Fi (AP1): el AP sólo existe con el router ACTIVADO
# — lo enciende la activación (encender_ap, tras levantar el perfil de la
# LAN) y lo apaga la vuelta atrás ANTES de bajar el perfil (apagar_ap). El
# SSID y la clave NO viven en router.json: en /etc/router/hostapd.conf (0600,
# lo escribe wifi_ap.py). CONF_NM_AP mantiene la tarjeta fuera de
# NetworkManager una vez confirmada la activación (sobrevive a reinicios).
CONF_NM_AP = (wifi_ap.CONF_NM_AP if wifi_ap
              else '/etc/NetworkManager/conf.d/91-router-ap.conf')
PUERTO_CABLE = ''                   # activacion.puerto_cable: puerto cableado esclavo del puente (opcional)
AP_IF = ''                          # wifi_ap.interfaz: la tarjeta del punto de acceso
AP_ACTIVO = False                   # True sólo si wifi_ap.habilitado y wifi_ap.interfaz
IF_ENLACE = LAN_IF                  # por dónde se ve el "cable": el puerto de cable si hay puente, si no la LAN


def _leer_router_json(ruta=None):
    """Contenido (dict) de router.json, o {} si no se puede leer/parsear.
    Nunca lanza: la activación no puede quedar a merced de un JSON roto."""
    if ruta is None:
        ruta = CONFIG
    try:
        with open(ruta) as f:
            leido = json.load(f)
    except (OSError, ValueError) as e:
        print('AVISO: no se pudo leer %s (%s: %s)' % (ruta, type(e).__name__, e), file=sys.stderr, flush=True)
        return {}
    return leido if isinstance(leido, dict) else {}


def cargar_configuracion(ruta=None):
    """Llena las constantes de arriba (LAN_IF, LAN_IP, LAN_PREFIJO, PERFIL,
    PERFIL_WIFI, WIFI_IF, WIFI_ACTIVA, PUERTO_CABLE, AP_IF, AP_ACTIVO,
    IF_ENLACE) desde router.json:

    - lan.interfaz / lan.ip (acepta "192.168.50.1" o "192.168.50.1/24": el
      prefijo se quita) / el prefijo sale de lan.red.
    - activacion.perfil_lan / activacion.perfil_wifi /
      activacion.wifi_interfaz — sección opcional, con los defectos de
      DEFECTO_ACTIVACION si falta la sección o algún campo (los vacíos
      cuentan como "no configurado"). Con perfil_wifi o wifi_interfaz
      vacíos, WIFI_ACTIVA es False y se SALTAN todos los pasos Wi-Fi.
    - activacion.puerto_cable (opcional, vacío por defecto): el puerto
      cableado esclavo del puente br-lan cuando la LAN es un puente por el
      modo AP. IF_ENLACE = PUERTO_CABLE or LAN_IF: es donde hay carrier de
      verdad y donde se corre arping (br-lan no tiene carrier hasta que
      algún puerto está arriba).
    - wifi_ap.habilitado / wifi_ap.interfaz: el modo AP (AP1). AP_ACTIVO
      queda True sólo con los DOS rellenos; sin uno de ellos no se toca
      nada del AP. Una tarjeta no puede ser AP y WAN a la vez: si la del
      AP coincide con la de la WAN Wi-Fi, ésta se considera deshabilitada
      (si no, desconectar_wifi() apagaría la radio y el AP entero).

    CONFIG_LAN_OK queda en False si router.json no se puede leer o le falta
    lan.interfaz o lan.ip: comprobaciones_previas() lo convierte en un ✘ y
    la activación se aborta en vez de seguir con los valores por defecto.
    Devuelve el diccionario resumen (útil también para los tests)."""
    global LAN_IF, LAN_IP, LAN_PREFIJO, PERFIL, PERFIL_WIFI, WIFI_IF, WIFI_ACTIVA
    global CONFIG_LAN_OK, PUERTO_CABLE, AP_IF, AP_ACTIVO, IF_ENLACE
    if ruta is None:
        ruta = CONFIG
    leido = _leer_router_json(ruta)
    lan = leido.get('lan') if isinstance(leido.get('lan'), dict) else {}
    CONFIG_LAN_OK = bool(str(lan.get('interfaz') or '').strip()) and bool(str(lan.get('ip') or '').strip())

    interfaz = str(lan.get('interfaz') or '').strip() or DEFECTO_LAN['interfaz']
    ip = str(lan.get('ip') or '').strip()
    if '/' in ip:
        ip = ip.split('/')[0].strip()
    ip = ip or DEFECTO_LAN['ip']
    red = str(lan.get('red') or '').strip()
    prefijo = LAN_PREFIJO
    if red:
        try:
            prefijo = ipaddress.ip_network(red, strict=False).prefixlen
        except ValueError:
            prefijo = LAN_PREFIJO
    else:
        prefijo = LAN_PREFIJO

    act = leido.get('activacion') if isinstance(leido.get('activacion'), dict) else {}
    perfil = str(act.get('perfil_lan') or '').strip() or DEFECTO_ACTIVACION['perfil_lan']
    perfil_wifi = str(act.get('perfil_wifi') or '').strip()
    wifi_if = str(act.get('wifi_interfaz') or '').strip()
    # WIFI_ACTIVA sólo si ambos están; con cualquiera vacío no se toca NADA
    # Wi-Fi (no apagar/encender radio, no ping por Wi-Fi, no reconectar).
    wifi_activa = bool(perfil_wifi) and bool(wifi_if)

    LAN_IF, LAN_IP, LAN_PREFIJO = interfaz, ip, prefijo
    PERFIL, PERFIL_WIFI, WIFI_IF, WIFI_ACTIVA = perfil, perfil_wifi, wifi_if, wifi_activa

    # — modo punto de acceso Wi-Fi (AP1) —
    ap = leido.get('wifi_ap') if isinstance(leido.get('wifi_ap'), dict) else {}
    ap_if = str(ap.get('interfaz') or '').strip()
    ap_activo = bool(ap.get('habilitado')) and bool(ap_if)
    # Una tarjeta no puede ser AP y WAN a la vez (misma regla que aplica
    # routerd al normalizar la config que carga): si coincide, la WAN
    # Wi-Fi se queda fuera — si no, desconectar_wifi() de la activación
    #              (radio off) apagaría también el AP que se va a levantar.
    if ap_activo and wifi_if and wifi_if == ap_if:
        print('AVISO: wifi_ap y wifi_wan usan la misma tarjeta (%s): la WAN '
              'Wi-Fi se trata como deshabilitada.' % ap_if,
              file=sys.stderr, flush=True)
        wifi_activa = False
        PERFIL_WIFI, WIFI_IF, WIFI_ACTIVA = '', '', False
    puerto_cable = str(act.get('puerto_cable') or '').strip()

    PUERTO_CABLE, AP_IF, AP_ACTIVO = puerto_cable, ap_if, ap_activo
    IF_ENLACE = PUERTO_CABLE or LAN_IF
    return {'lan_if': LAN_IF, 'lan_ip': LAN_IP, 'prefijo': LAN_PREFIJO,
            'perfil': PERFIL, 'perfil_wifi': PERFIL_WIFI,
            'wifi_if': WIFI_IF, 'wifi_activa': WIFI_ACTIVA,
            'if_enlace': IF_ENLACE, 'puerto_cable': PUERTO_CABLE,
            'ap_if': AP_IF, 'ap_activo': AP_ACTIVO}


def log(msg, **extra):
    print(msg, flush=True)
    os.makedirs(os.path.dirname(ESTADO), exist_ok=True)
    datos = {'fecha': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'mensaje': msg}
    datos.update(extra)
    tmp = ESTADO + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(datos, f, ensure_ascii=False)
    os.replace(tmp, ESTADO)


def run(args, timeout=30):
    """N2: nunca deja escapar una excepción — un comando colgado
    (TimeoutExpired) o un binario ausente (OSError) se convierte en un
    CompletedProcess con returncode != 0, igual que cualquier otro fallo del
    comando. Así cada llamador puede mirar sólo `.returncode` sin tener que
    envolver cada `run(...)` en su propio try/except."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        salida = e.stdout if isinstance(e.stdout, str) else (e.stdout or b'').decode('utf-8', 'replace')
        error = e.stderr if isinstance(e.stderr, str) else (e.stderr or b'').decode('utf-8', 'replace')
        return subprocess.CompletedProcess(args, 124, stdout=salida,
                                            stderr=error or 'agotado el tiempo (%ss)' % timeout)
    except OSError as e:
        return subprocess.CompletedProcess(args, 127, stdout='', stderr=str(e))


def _paso(descripcion, funcion, *args, **kwargs):
    """N2: cada paso de activación o deshacer va por separado — que uno
    falle con una excepción de verdad (no sólo un código de error de un
    comando, que ya devuelve run() sin lanzar nada) no debe impedir que los
    siguientes se ejecuten. Fundamental en deshacer(): tiene que llegar
    siempre al final."""
    try:
        return funcion(*args, **kwargs)
    except Exception as e:
        log('Fallo en el paso «%s» (se continúa): %s' % (descripcion, e))
        return None


def _escribir_atomico(ruta, texto):
    """Escritura atómica con fsync de fichero y directorio (N1/N2): un corte
    de luz justo después no debe dejar la fase o el marcador a medias, ni
    perder el rename aunque el contenido ya esté en disco."""
    d = os.path.dirname(ruta)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, ruta)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _solo_ap():
    """Modo SÓLO-AP (AP1): punto de acceso activo y la LAN es el puente
    br-lan SIN puerto de cable. No hay cable por donde pueda haber otro
    router con la misma IP, así que la activación NO debe bloquearse:
    enlace() responde True sin mirar sysfs y otro_tiene_la_ip() responde
    False sin ejecutar arping (con puente sin puertos, arping no tendría
    por dónde preguntar — y su “no se sabe” se trata como ocupada: nunca
    se activaría, lo que deja el AP inaccesible para siempre)."""
    return AP_ACTIVO and LAN_IF == 'br-lan' and not PUERTO_CABLE


def enlace():
    """¿Hay enlace por donde de verdad se conecta la casa? Sin puente es la
    propia LAN; con puente (modo AP) es el puerto de cable esclavo
    (IF_ENLACE): el puente br-lan en sí no tiene carrier hasta que algún
    puerto está arriba, así que mirar su /carrier no sirve. En modo
    SÓLO-AP no hay cable que mirar: True siempre (ver _solo_ap)."""
    if _solo_ap():
        return True
    try:
        with open('/sys/class/net/%s/carrier' % IF_ENLACE) as f:
            return f.read().strip() == '1'
    except OSError:
        return False


def otro_tiene_la_ip():
    """Código de `arping -D`: 0 = la IP está libre (nadie contesta),
    1 = ocupada (alguien contesta: dirección duplicada). N4: cualquier OTRO
    código (fallo del comando, interfaz sin enlace, arping ausente…) NO
    significa "libre": significa que no se sabe, y aquí eso se trata igual
    que "ocupada" — nunca se activa por una duda.

    Con puente (modo AP) el arping va por el PUERTO DE CABLE (IF_ENLACE),
    no por el puente. En modo SÓLO-AP no se ejecuta nada: no hay cable por
    donde otro router pueda contestar el ARP (ver _solo_ap)."""
    if _solo_ap():
        return False
    r = run(['arping', '-D', '-q', '-c', '3', '-w', '4', '-I', IF_ENLACE, LAN_IP], timeout=10)
    if r.returncode not in (0, 1):
        # No es «ocupada» de verdad: arping falló. Se sigue tratando como
        # ocupada (nunca se activa por una duda), pero queda el motivo real.
        print('AVISO: arping -D en %s devolvió %s (no se sabe si la IP %s está libre): %s'
              % (LAN_IF, r.returncode, LAN_IP, (r.stderr or '').strip()[:200]), flush=True)
    return r.returncode != 0


def router_viejo_por_wifi():
    """N4: señal adicional SÓLO si la WAN Wi-Fi está configurada (su
    interfaz apunta a una red donde otro equipo pueda tener la IP del
    router): si contesta por ICMP en esa interfaz, ese equipo sigue vivo,
    aunque por el RJ45 todavía no se vea nada raro por ARP. Con el Wi-Fi
    vacío (activacion.perfil_wifi o wifi_interfaz vacíos) esta comprobación
    no tiene sentido: devuelve False enseguida."""
    if not WIFI_ACTIVA:
        return False
    r = run(['ping', '-c', '1', '-W', '1', '-I', WIFI_IF, LAN_IP], timeout=5)
    return r.returncode == 0


def desconectar_wifi():
    """Al activar el perfil de la LAN la máquina podría quedar con dos
    interfaces en la MISMA red (el RJ45 recién activado y el Wi-Fi, si
    seguía asociado a otro punto de acceso en esa red): doble interfaz en
    el mismo L2 da líos de ARP/rutas. N5: además de bajar el perfil y
    quitarle el autoconnect, se apaga la radio Wi-Fi entera (nmcli radio
    wifi off) — así no se asocia sola a NINGUNA red mientras la máquina
    hace de router. SÓLO si hay WAN Wi-Fi configurada: con
    activacion.perfil_wifi o wifi_interfaz vacíos no se toca nada de
    Wi-Fi."""
    if not WIFI_ACTIVA:
        return
    for args in (['nmcli', 'con', 'down', PERFIL_WIFI],
                 ['nmcli', 'con', 'mod', PERFIL_WIFI, 'connection.autoconnect', 'no'],
                 ['nmcli', 'radio', 'wifi', 'off']):
        r = run(args)
        if r.returncode != 0:
            log('Aviso al apagar el Wi-Fi («%s»): código %d: %s' %
                (' '.join(args), r.returncode, (r.stderr or r.stdout).strip()))


def encender_ap():
    """Enciende el punto de acceso Wi-Fi (AP1, sólo si está configurado): la
    tarjeta sale de la gestión de NetworkManager (`nmcli device set ...
    managed no`) y hostapd la levanta como AP colgado del puente br-lan
    (bridge= en su config), desde la unidad router-ap.service propia — el
    hostapd.service de Debian viene enmascarado, y NetworkManager no puede
    gestionar una tarjeta mientras hostapd la usa. Se llama tras levantar
    el perfil de la LAN: el AP sólo existe con el router ACTIVADO, y
    hostapd necesita el puente ya en pie. Fallo de nmcli/systemctl = aviso
    en el log, sin saltar los pasos siguientes (los pasos de la activación
    ya van por separado con _paso; estos avisos sólo dicen por qué falló)."""
    if not AP_ACTIVO:
        return
    for args in (['nmcli', 'device', 'set', AP_IF, 'managed', 'no'],
                 ['systemctl', 'start', 'router-ap.service']):
        r = run(args)
        if r.returncode != 0:
            log('Aviso al encender el AP («%s»): código %d: %s' %
                (' '.join(args), r.returncode, (r.stderr or r.stdout).strip()))


def apagar_ap():
    """Apaga el punto de acceso Wi-Fi (AP1, vuelta atrás): la unidad queda
    parada y sin habilitación, el fichero 91-router-ap.conf se borra (la
    tarjeta vuelve a ser de NetworkManager tras recargar la config) y el
    dispositivo vuelve a estar gestionado por NM. Cada paso se intenta sin
    saltar el siguiente: la vuelta atrás tiene que llegar siempre al final
    (N2). Nada que hacer si no hay AP configurado."""
    if not AP_ACTIVO:
        return
    run(['systemctl', 'disable', '--now', 'router-ap.service'])
    if os.path.exists(CONF_NM_AP):
        try:
            os.unlink(CONF_NM_AP)
        except OSError as e:
            log('No se pudo borrar %s: %s' % (CONF_NM_AP, e))
    run(['nmcli', 'general', 'reload', 'conf'])   # se ignoran los fallos: sólo relee la config
    r = run(['nmcli', 'device', 'set', AP_IF, 'managed', 'yes'])
    if r.returncode != 0:
        log('Aviso al devolver %s a NetworkManager: código %d: %s' %
            (AP_IF, r.returncode, (r.stderr or r.stdout).strip()))


def confirmar_ap():
    """AP1, sólo una vez CONFIRMADA la activación: se deja puesto lo que
    hace que el AP vuelva solo tras un reinicio — 91-router-ap.conf mantiene
    la tarjeta fuera de NetworkManager todo el tiempo (escritura atómica)
    y la unidad router-ap.service queda habilitada. No hace nada si no hay
    AP configurado."""
    if not AP_ACTIVO:
        return
    _escribir_atomico(CONF_NM_AP, '[keyfile]\nunmanaged-devices=interface-name:%s\n' % AP_IF)
    r = run(['systemctl', 'enable', 'router-ap.service'])
    if r.returncode != 0:
        log('No se pudo habilitar %s: %s' %
            ('router-ap.service', (r.stderr or r.stdout).strip()))


def reconectar_wifi():
    """Vuelta atrás: la máquina deja de ser el router y vuelve a necesitar
    su conexión Wi-Fi. N5: primero la radio (por si se apagó del todo al
    activar), luego el autoconnect, luego el perfil. SÓLO si hay WAN Wi-Fi
    configurada; con activacion.perfil_wifi o wifi_interfaz vacíos no se
    toca nada de Wi-Fi."""
    if not WIFI_ACTIVA:
        return
    for args in (['nmcli', 'radio', 'wifi', 'on'],
                 ['nmcli', 'con', 'mod', PERFIL_WIFI, 'connection.autoconnect', 'yes'],
                 ['nmcli', 'con', 'up', PERFIL_WIFI]):
        r = run(args)
        if r.returncode != 0:
            log('Aviso al reconectar el Wi-Fi («%s»): código %d: %s' %
                (' '.join(args), r.returncode, (r.stderr or r.stdout).strip()))


def arp_gratuito():
    """L5: tras activar el perfil de la LAN, un ARP gratuito para que los
    clientes de la LAN actualicen su caché y dejen de mandar tráfico a la
    MAC del equipo que antes tenía la IP del router para lan.ip."""
    r = run(['arping', '-U', '-c', '3', '-I', LAN_IF, LAN_IP], timeout=15)
    if r.returncode != 0:
        log('Aviso: el ARP gratuito no se pudo mandar (código %d): %s' %
            (r.returncode, (r.stderr or r.stdout).strip()))


def poner_fase(fase):
    """N1: la fase vive en su propio fichero — routerd NUNCA lo escribe,
    router_migrar es el único que lo hace. Escritura atómica con fsync."""
    _escribir_atomico(FASE_RUTA, fase + '\n')


def escribir_marcador():
    """N2: marcador persistente con la fecha límite, escrito ANTES de
    activar nada — la vuelta atrás (temporizador independiente o
    router-migracion-arranque.service tras un reinicio) no depende de que
    este proceso siga vivo."""
    limite = datetime.now(timezone.utc) + timedelta(seconds=VIGILANCIA_S)
    _escribir_atomico(MARCADOR, 'limite=%s\n' % limite.isoformat(timespec='seconds'))


def borrar_marcador():
    try:
        os.unlink(MARCADOR)
    except OSError:
        pass


def programar_deshacer():
    """N2: temporizador systemd INDEPENDIENTE de este proceso: pasados
    VIGILANCIA_S ejecuta `router-migrar --deshacer` por su cuenta aunque
    este proceso haya muerto (corte de luz, kill -9…). Devuelve True si se
    pudo programar."""
    r = run(['systemd-run', '--unit=%s' % UNIDAD_DESHACER,
             '--on-active=%dmin' % (VIGILANCIA_S // 60),
             EJECUTABLE, '--deshacer'], timeout=15)
    if r.returncode != 0:
        log('No se pudo programar el deshacer automático independiente (systemd-run): %s' %
            (r.stderr or r.stdout).strip())
        return False
    return True


def cancelar_deshacer_programado():
    run(['systemctl', 'stop', '%s.timer' % UNIDAD_DESHACER], timeout=15)


def _migracion_en_curso():
    """N12: --confirmar sólo vale si hay una activación de verdad en curso:
    el marcador persistente, o el propio estado (migracion.json) diciendo
    "vigilando" (por si, en alguna carrera rara, el marcador ya no está pero
    el proceso sigue vigilando)."""
    if os.path.exists(MARCADOR):
        return True
    try:
        with open(ESTADO) as f:
            e = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(e, dict) and e.get('fase') == 'vigilando'


def _esperar_o_forzar_retirada():
    """N12: en vez de un sleep(8) a ciegas, se espera (hasta 60 s) a que
    estado.json confirme que routerd ya retiró su fase de producción
    (nftables, rutas, dnsmasq). Si no llega a tiempo (routerd caído, ciclo
    muy largo…) se fuerza aquí mismo: destruir la tabla nftables del router
    y borrar las ip rule que puso (protocol 99, prioridades 900-1199) —
    justo lo que hace routerd.desinstalar(), por si no llega a correr."""
    limite = time.time() + 60
    while time.time() < limite:
        try:
            with open(ESTADO_ROUTERD) as f:
                e = json.load(f)
            if (isinstance(e, dict) and e.get('fase') == 'preparacion'
                    and not e.get('servicios', {}).get('nftables_router')):
                return
        except (OSError, ValueError):
            pass
        time.sleep(2)
    log('routerd no confirmó la vuelta a preparación en 60 s: se fuerza el desmontaje.')
    run(['nft', 'destroy', 'table', 'inet', 'router'], timeout=15)
    _borrar_ip_rules_propias()


def _borrar_ip_rules_propias():
    """N13: sólo se borran las ip rule PROPIAS (protocol 99, el mismo que
    pone routerd — ver `_regla()` en routerd.py) dentro del rango de
    prioridades 900-1199; nunca una regla ajena que coincida por casualidad
    con ese rango."""
    r = run(['ip', '-j', 'rule', 'show'], timeout=15)
    try:
        reglas = json.loads(r.stdout or '[]')
    except ValueError:
        reglas = []
    for regla in reglas:
        prio = regla.get('priority')
        if prio is None or regla.get('protocol') not in (99, '99'):
            continue
        if 900 <= int(prio) < 1200:
            run(['ip', 'rule', 'del', 'pref', str(prio), 'protocol', '99'], timeout=15)


def deshacer(motivo):
    """Vuelta atrás común, la use quien la use: la vigilancia de este mismo
    proceso, el temporizador independiente router-deshacer,
    router-migracion-arranque.service tras un reinicio, o un admin con
    --deshacer. N2: cada paso por separado — que uno falle no impide que
    los demás se intenten; esta función tiene que llegar siempre al
    final."""
    log('DESHACIENDO la activación: %s' % motivo, fase='deshecha')
    _paso('fase preparación', poner_fase, 'preparacion')
    _paso('esperar (o forzar) que routerd retire sus reglas', _esperar_o_forzar_retirada)
    # AP1: el AP va FUERA ANTES del perfil de la LAN — hostapd está colgado
    # del puente br-lan, que queda sin IP al bajar el perfil: apagarlo antes
    # deja los clientes Wi-Fi desconectados de la LAN de forma limpia, no
    # sostenidos por una red que ya no existe.
    _paso('apagar el punto de acceso Wi-Fi', apagar_ap)
    _paso('perfil de la LAN abajo', lambda: run(['nmcli', 'con', 'down', PERFIL]))
    _paso('perfil de la LAN sin autoconexión',
          lambda: run(['nmcli', 'con', 'mod', PERFIL, 'connection.autoconnect', 'no']))
    _paso('reconectar el Wi-Fi', reconectar_wifi)
    _paso('borrar el marcador de activación pendiente', borrar_marcador)
    _paso('cancelar el temporizador de deshacer', cancelar_deshacer_programado)
    log('Activación deshecha (%s). La máquina vuelve a preparación.' % motivo, fase='deshecha')


def confirmar():
    """N12: sólo vale si hay una activación en curso. Hace YA lo que hacía
    falta (cancela el temporizador, borra el marcador, deja autoconexión) y
    por último marca CONFIRMADA para que, si el proceso original sigue
    vigilando, salga limpio."""
    if not _migracion_en_curso():
        sys.exit('No hay ninguna activación en curso (ni marcador ni fase "vigilando"): nada que confirmar.')
    _paso('cancelar el temporizador de deshacer', cancelar_deshacer_programado)
    _paso('borrar el marcador de activación pendiente', borrar_marcador)
    _paso('perfil de la LAN con autoconexión (sobrevive a reinicios)',
          lambda: run(['nmcli', 'con', 'mod', PERFIL, 'connection.autoconnect', 'yes']))
    # AP1: confirmando, el AP deja de ser pasajero — la tarjeta queda fuera
    # de NetworkManager también tras un reinicio (91-router-ap.conf, atómica)
    # y la unidad router-ap.service habilitada.
    _paso('configuración permanente del AP (conf NM + unidad habilitada)', confirmar_ap)
    if os.path.exists(CONFIRMADA):
        os.unlink(CONFIRMADA)
    open(CONFIRMADA, 'w').close()
    print('Confirmación registrada: activación dada por buena.')


def al_arrancar():
    """N2: lanzado por router-migracion-arranque.service en cada arranque.
    Si hay un marcador de activación pendiente (no se llegó a confirmar ni a
    deshacer antes de que la máquina se reiniciara — p. ej. un corte de luz
    durante la vigilancia), la vuelta atrás no puede depender de que el
    proceso anterior siguiera vivo: se deshace aquí, de cero."""
    if not os.path.exists(MARCADOR):
        return 0
    deshacer('la máquina se reinició con una activación sin confirmar (%s)' % MARCADOR)
    return 0


def _nmcli_valor(campo, perfil=PERFIL):
    r = run(['nmcli', '-g', campo, 'connection', 'show', perfil], timeout=10)
    if r.returncode != 0:
        return None
    return (r.stdout or '').strip()


def comprobaciones_previas():
    """N4: condiciones que deben cumplirse ANTES de esperar y de activar
    nada; no cambian durante la espera (al revés que otro_tiene_la_ip() o
    router_viejo_por_wifi()), así que se comprueban una sola vez. Sirven
    tanto para abortar principal() como para `--comprobar` (lista ✔/✘ para
    que el admin la repase a mano).

    Devuelve [(ok: bool, descripcion: str), ...]."""
    cargar_configuracion()
    resultados = []

    def chk(desc, ok):
        resultados.append((bool(ok), desc))

    chk('%s se lee y tiene lan.interfaz y lan.ip' % CONFIG, CONFIG_LAN_OK)
    existe = run(['nmcli', '-g', 'connection.autoconnect', 'connection', 'show', PERFIL],
                 timeout=10).returncode == 0
    chk('el perfil %s existe' % PERFIL, existe)
    if existe:
        autoconnect = _nmcli_valor('connection.autoconnect')
        gateway = _nmcli_valor('ipv4.gateway')
        direcciones = (_nmcli_valor('ipv4.addresses') or '')
        primera = direcciones.split('|')[0].split(',')[0].strip()
        chk('%s tiene autoconnect=no' % PERFIL, autoconnect == 'no')
        chk('%s no tiene gateway propio' % PERFIL, (gateway or '').strip() in ('', '--'))
        chk('%s tiene la dirección %s/%s' % (PERFIL, LAN_IP, LAN_PREFIJO),
            primera == '%s/%s' % (LAN_IP, LAN_PREFIJO))
    else:
        chk('%s tiene autoconnect=no' % PERFIL, False)
        chk('%s no tiene gateway propio' % PERFIL, False)
        chk('%s tiene la dirección %s/%s' % (PERFIL, LAN_IP, LAN_PREFIJO), False)

    r = run(['arping', '-V'], timeout=5)
    chk('arping es el de iputils (arping -V)', 'iputils' in ((r.stdout or '') + (r.stderr or '')))

    for binario in ('nft', 'ip', 'conntrack', 'dnsmasq', 'nmcli', 'arping'):
        chk('existe el binario %s' % binario, shutil.which(binario) is not None)

    r = run(['systemctl', 'is-enabled', 'dnsmasq'], timeout=10)
    chk('dnsmasq está enabled', (r.stdout or '').strip() == 'enabled')

    r = run(['systemctl', 'is-enabled', 'nftables'], timeout=10)
    chk('nftables.service NO está enabled', (r.stdout or '').strip() != 'enabled')

    r = run(['nft', 'list', 'table', 'ip', 'filter'], timeout=10)
    chk('no existe ya una "table ip filter"', r.returncode != 0)

    r = run(['systemctl', 'is-enabled', 'docker'], timeout=10)
    chk('docker NO está enabled', (r.stdout or '').strip() != 'enabled')

    r = run(['systemctl', 'is-active', 'routerd'], timeout=10)
    chk('routerd está activo', (r.stdout or '').strip() == 'active')

    # — AP1: modo punto de acceso (sólo si está configurado) —
    if AP_ACTIVO:
        conf_hostapd = wifi_ap.CONF_HOSTAPD if wifi_ap else '/etc/router/hostapd.conf'
        puente = wifi_ap.PUENTE_LAN if wifi_ap else 'br-lan'
        chk('existe /usr/sbin/hostapd', os.path.exists('/usr/sbin/hostapd'))
        chk('existe la config del AP (%s)' % conf_hostapd, os.path.exists(conf_hostapd))
        chk('existe la tarjeta del AP (%s)' % AP_IF,
            os.path.exists('/sys/class/net/%s' % AP_IF))
        soporta = (wifi_ap.soporta_ap(AP_IF) if wifi_ap else None)
        # None = «no se puede saber» se acepta: iw ausente, phy raro… pero
        # un False claro (la tarjeta no trae modo AP) aborta: la activación
        # iría a un AP que nunca se levantará.
        chk('la tarjeta Wi-Fi %s admite modo AP' % AP_IF, soporta is not False)
        chk('la LAN vive en el puente %s (br-lan)' % puente, LAN_IF == puente)
    if PUERTO_CABLE:
        chk('existe el puerto de cable %s (esclavo del puente de la LAN)' % PUERTO_CABLE,
            os.path.exists('/sys/class/net/%s' % PUERTO_CABLE))

    return resultados


def verificar_previas():
    resultados = comprobaciones_previas()
    fallos = [desc for ok, desc in resultados if not ok]
    return resultados, fallos


def comprobar_cli():
    resultados, fallos = verificar_previas()
    for ok, desc in resultados:
        print(('✔ ' if ok else '✘ ') + desc)
    return 1 if fallos else 0


def principal():
    cargar_configuracion()
    if os.path.exists(CONFIRMADA):
        os.unlink(CONFIRMADA)

    _, fallos = verificar_previas()
    if fallos:
        log('Comprobaciones previas fallidas: no se toca nada.\n - ' + '\n - '.join(fallos),
            fase='cancelada')
        return 1

    log('Esperando: enlace en %s y que ningún otro equipo tenga la IP %s…' % (LAN_IF, LAN_IP),
        fase='esperando')
    t0 = time.time()
    while True:
        if time.time() - t0 > ESPERA_MAX_S:
            log('Se agotó la espera (3 h) sin poder activar: no se ha tocado nada.', fase='cancelada')
            return 1
        if not enlace():
            time.sleep(3)
            continue
        if otro_tiene_la_ip() or router_viejo_por_wifi():
            log('El RJ45 tiene enlace pero otro equipo sigue respondiendo con %s: espero.' % LAN_IP,
                fase='esperando')
            time.sleep(5)
            continue
        # Dos comprobaciones seguidas sin respuesta, por si el otro equipo
        # estaba reiniciando o con el cable al aire.
        time.sleep(5)
        if not enlace() or otro_tiene_la_ip() or router_viejo_por_wifi():
            continue
        break

    log('Condiciones OK: preparando la vuelta atrás antes de activar.', fase='activando')
    # N2: el marcador y el temporizador independiente se dejan ANTES de
    # tocar nada: si no se pueden dejar, no hay red de seguridad y no se
    # activa nada (al revés que los pasos DESPUÉS de activar, que ya están
    # cubiertos por ese mismo marcador/temporizador y por tanto sólo
    # registran el fallo y siguen — N2).
    try:
        escribir_marcador()
    except OSError as e:
        log('No se pudo escribir el marcador de activación pendiente: %s — no se activa nada.' % e,
            fase='fallida')
        return 1
    if not programar_deshacer():
        log('No se pudo programar el deshacer automático independiente: no se activa nada.',
            fase='fallida')
        borrar_marcador()
        return 1

    r = run(['nmcli', 'con', 'up', PERFIL], timeout=60)
    if r.returncode != 0:
        log('No se pudo activar %s: %s' % (PERFIL, (r.stderr or r.stdout).strip()), fase='fallida')
        borrar_marcador()
        cancelar_deshacer_programado()
        return 1

    _paso('apagar el Wi-Fi (down + autoconnect no + radio off)', desconectar_wifi)
    _paso('encender el punto de acceso Wi-Fi', encender_ap)
    _paso('fase producción', poner_fase, 'produccion')
    _paso('ARP gratuito en %s' % LAN_IF, arp_gratuito)
    log('Router ACTIVO. Vigilando %d min: confirma con «router-migrar --confirmar».' % (VIGILANCIA_S // 60),
        fase='vigilando')

    fin = time.time() + VIGILANCIA_S
    while time.time() < fin:
        if os.path.exists(CONFIRMADA):
            log('Activación CONFIRMADA: la máquina es el router de la LAN (sobrevive a reinicios).',
                fase='confirmada')
            return 0
        if enlace() and (otro_tiene_la_ip() or router_viejo_por_wifi()):
            deshacer('ha vuelto a aparecer otro equipo con la IP %s' % LAN_IP)
            return 2
        time.sleep(5)
    deshacer('nadie confirmó en %d min' % (VIGILANCIA_S // 60))
    return 3


if __name__ == '__main__':
    cargar_configuracion()
    if os.geteuid() != 0:
        sys.exit('router-migrar necesita root')
    if '--comprobar' in sys.argv:
        sys.exit(comprobar_cli())
    elif '--confirmar' in sys.argv:
        confirmar()
    elif '--deshacer' in sys.argv:
        deshacer('vuelta atrás manual')
        # N12: --deshacer a mano para además los servicios de la activación
        # (que el admin no se quede con el servicio "vigilando" para
        # siempre, ni con un temporizador suelto).
        _paso('parar router-migracion.service', lambda: run(['systemctl', 'stop', 'router-migracion.service']))
        _paso('parar el temporizador %s' % UNIDAD_DESHACER,
              lambda: run(['systemctl', 'stop', '%s.timer' % UNIDAD_DESHACER]))
    elif '--al-arrancar' in sys.argv:
        sys.exit(al_arrancar())
    else:
        sys.exit(principal())
