#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wifi_ap — modo punto de acceso Wi-Fi de Roble Router (AP1).

Diseño (probado a mano en una VM con mac80211_hwsim): con el AP configurado
la LAN es un puente NetworkManager «br-lan» (perfil LAN-ROUTER, tipo bridge,
más un perfil esclavo por el puerto de cable si lo hay) y lan.interfaz de
router.json apunta a br-lan, así que dnsmasq, nftables y las estadísticas no
cambian nada. La tarjeta Wi-Fi NO la gestiona NetworkManager
(`nmcli device set <if> managed no`, runtime; 91-router-ap.conf al
confirmar, para que persista): la levanta hostapd con `bridge=br-lan` en su
config, desde la unidad router-ap.service (el hostapd.service de Debian
viene enmascarado: no se usa). El AP sólo existe con el router ACTIVADO:
lo enciende router-migrar al activar y lo apaga al deshacer.

Este módulo sólo toca ficheros y consultas de lectura:
  /etc/router/hostapd.conf                     la config de hostapd (0600:
                                               SSID y clave viven aquí, no
                                               en router.json)
  /etc/NetworkManager/conf.d/91-router-ap.conf [keyfile] unmanaged-devices=
                                               (la escribe router-migrar al
                                               confirmar)

Uso (lo lanza el instalador):
  python3 wifi_ap.py escribir --interfaz wlan0 --ssid "Mi Red" --pais ES --canal 6
      (la clave entra por stdin, NUNCA por argv/ps; sale 2 con los errores
       en stderr si los datos no validan)
  python3 wifi_ap.py soporta-ap wlan0        → imprime si / no / desconocido
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

PUENTE_LAN = 'br-lan'                            # el nombre del puente de la LAN
CONF_HOSTAPD = '/etc/router/hostapd.conf'         # config de hostapd (0600, aquí vive la clave)
CONF_NM_AP = '/etc/NetworkManager/conf.d/91-router-ap.conf'
UNIDAD_AP = 'router-ap.service'                   # unidad propia: hostapd.service viene enmascarado

# Interfaz: nombre de interfaz de red válido y corto (15 caracteres, el
# límite de ifnames). Como los nombres de usuario/ruta en peticiones.py,
# se compone con clases ASCII explícitas (re.UNICODE no es lo que queremos).
RE_INTERFAZ = re.compile(r'[A-Za-z0-9_.-]{1,15}')
# País ISO 3166-1 alfa-2 (hostapd pide dos letras mayúsculas).
RE_PAIS = re.compile(r'[A-Z]{2}')
# Clave WPA2: 8..63 caracteres ASCII imprimibles (sin saltos de línea,
# nunca llega por argv pero sí por stdin: ni su resumen se escribe en log).
RE_CLAVE_WPA = re.compile(r'[ -~]{8,63}')


def validar(interfaz, ssid, clave, pais, canal):
    """Comprueba los datos del punto de acceso y devuelve la lista de
    errores (vacía = todo bien). No ejecuta NADA: es la misma validación
    (idéntica lista de reglas) que usan generar_hostapd_conf() y el CLI
    `escribir`."""
    errores = []
    interfaz = str(interfaz or '')
    ssid = str(ssid or '')
    clave = str(clave or '')
    pais = str(pais or '')

    if not interfaz:
        errores.append('interfaz: no puede estar vacía')
    elif not RE_INTERFAZ.fullmatch(interfaz):
        errores.append('interfaz: sólo letras, dígitos, punto, guion y '
                       'guion bajo, máximo 15 caracteres')

    # 32 BYTES de UTF-8 es el límite del 802.11, no 32 caracteres: un SSID
    # con acentos gasta más de un byte por letra.
    if not ssid:
        errores.append('ssid: no puede estar vacío')
    elif not 1 <= len(ssid.encode('utf-8')) <= 32:
        errores.append('ssid: ocupa %d bytes (UTF-8): el límite es 32'
                       % len(ssid.encode('utf-8')))
    elif any(not c.isprintable() for c in ssid):
        errores.append('ssid: no puede llevar saltos de línea ni caracteres '
                       'de control')

    if not 8 <= len(clave) <= 63:
        errores.append('clave: WPA2-PSK pide entre 8 y 63 caracteres')
    elif not RE_CLAVE_WPA.fullmatch(clave):
        errores.append('clave: sólo caracteres ASCII imprimibles (sin '
                       'saltos de línea)')

    if not RE_PAIS.fullmatch(pais):
        errores.append('pais: dos letras MAYÚSCULAS (ISO 3166-1 alfa-2, '
                       'p. ej. ES)')

    try:
        canal_n = int(str(canal).strip())
    except (TypeError, ValueError):
        canal_n = None
    if canal_n is None or not 1 <= canal_n <= 13:
        errores.append('canal: tiene que ser un entero entre 1 y 13 '
                       '(banda de 2,4 GHz)')
    return errores


def _ssid_formato_hostapd(ssid):
    """El SSID en el formato que hostapd espera en `ssid2=`: P"texto" si
    se puede representar tal cual entre comillas (caracteres imprimibles,
    sin comillas ni contrabarras) y hexadecimal si no — así admite
    CUALQUIER carácter, incluidas comillas y no-ASCII. `utf8_ssid=1` en la
    config hace que hostapd anuncie el SSID como UTF-8."""
    datos = ssid.encode('utf-8')
    if all(c.isprintable() and c not in '"\\' for c in ssid):
        return 'P"%s"' % ssid
    return datos.hex()


def _ssid_de_hostapd(valor):
    """La vuelta atrás de _ssid_formato_hostapd(): recupera el SSID desde
    la línea `ssid2=` (P"texto" con escapes o hexadecimal). '' si no se
    puede interpretar. Nunca lanza."""
    valor = (valor or '').strip()
    if valor.startswith('P"') and valor.endswith('"') and len(valor) >= 3:
        ssid = valor[2:-1].replace('\\"', '"').replace('\\\\', '\\')
        return ssid
    if re.fullmatch(r'[0-9A-Fa-f]+', valor or '') and len(valor) % 2 == 0:
        try:
            return bytes.fromhex(valor).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return ''
    return ''


def generar_hostapd_conf(interfaz, ssid, clave, pais, canal):
    """Texto de /etc/router/hostapd.conf a partir de los mismos datos que
    valida. Lanza ValueError si `validar` no los acepta: nunca se genera
    una config con datos malos (la validación es UNA sola, la de validar())."""
    errores = validar(interfaz, ssid, clave, pais, canal)
    if errores:
        raise ValueError('datos de AP inválidos (%s)' % '; '.join(errores))
    canal = int(str(canal).strip())
    return '\n'.join([
        '# hostapd.conf — generado por Roble Router (core/wifi_ap.py).',
        '# NO editar a mano: se regenera a partir de /etc/router/router.json',
        '# (wifi_ap) y la clave entra aparte. La clave es secreta: 0600 root.',
        '',
        '# el puente de la LAN: los clientes Wi-Fi entran en la misma LAN que los del cable',
        'interface=%s' % interfaz,
        'bridge=%s' % PUENTE_LAN,
        'driver=nl80211',
        'ctrl_interface=/run/hostapd',
        '',
        '# el SSID en formato ssid2= (P"..." o hex) para admitir cualquier carácter',
        'ssid2=%s' % _ssid_formato_hostapd(ssid),
        'utf8_ssid=1',
        '',
        '# 802.11d con el código del país y el canal (2,4 GHz)',
        'country_code=%s' % pais,
        'ieee80211d=1',
        'hw_mode=g',
        'channel=%d' % canal,
        'ieee80211n=1',
        'wmm_enabled=1',
        '',
        '# WPA2-PSK (CCMP), nada de WPA1 ni de claves abiertas',
        'auth_algs=1',
        'wpa=2',
        'wpa_key_mgmt=WPA-PSK',
        'rsn_pairwise=CCMP',
        'wpa_passphrase=%s' % clave,
    ]) + '\n'


def escribir_hostapd_conf(texto, ruta=CONF_HOSTAPD):
    """Deja `texto` en `ruta` (por defecto /etc/router/hostapd.conf), de
    forma ATÓMICA (fichero temporal + rename) y con 0600: la clave de la
    red Wi-Fi es un secreto y vive ahí, sólo de root."""
    d = os.path.dirname(ruta)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-hostapd-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, ruta)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # fsync del directorio: que el rename también quede en disco (H6).
    dfd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def leer_ssid(ruta=CONF_HOSTAPD):
    """SSID actual, reconstruido de la línea ssid2= de la config de
    hostapd, para mostrarlo en el panel SIN la clave. '' (nunca lanza) si
    el fichero no existe o no se puede interpretar."""
    try:
        with open(ruta) as f:
            for linea in f:
                linea = linea.rstrip('\n').rstrip('\r')
                if linea.startswith('ssid2='):
                    return _ssid_de_hostapd(linea[len('ssid2='):])
    except OSError:
        pass
    return ''


def soporta_ap(interfaz):
    """¿La tarjeta Wi-Fi admite el modo AP? True / False, o None cuando no
    se puede saber (no existe la interfaz, no hay phy, iw falla, salida
    ilegible…). Míralo en `iw phy <phy> info`: el phy sale de la sysfs de
    la interfaz (/sys/class/net/<if>/phy80211/name)."""
    try:
        with open('/sys/class/net/%s/phy80211/name' % interfaz) as f:
            phy = f.read().strip()
    except OSError:
        return None
    if not phy:
        return None
    try:
        r = subprocess.run(['iw', 'phy', phy, 'info'],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    en_modos = False           # dentro de "Supported interface modes:"
    hay_seccion = False
    for linea in (r.stdout or '').splitlines():
        if not en_modos:
            if 'Supported interface modes' in linea:
                en_modos = True
                hay_seccion = True
            continue
        if linea and not linea[0].isspace():
            break              # empieza otra sección: la lista se acabó
        modo = linea.strip()
        # "* AP" es el modo que necesita hostapd ("* AP/VLAN" también vale:
        # es el mismo más capacidad de bridges por VLAN).
        if modo == '* AP' or modo.startswith('* AP/VLAN'):
            return True
    return False if hay_seccion else None


def clientes(interfaz):
    """MACs de las estaciones conectadas al AP, desde
    `iw dev <if> station dump` (líneas «Station <mac> (on <if>)»). Lista
    vacía ante cualquier error (comando ausente, interfaz sin AP…). Nunca
    lanza: lo llama el ciclo de routerd en cada publicación de estado, para
    contar los clientes del panel."""
    try:
        r = subprocess.run(['iw', 'dev', interfaz, 'station', 'dump'],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    macs = []
    for linea in (r.stdout or '').splitlines():
        trozos = linea.split()
        # Station 10:a5:d0:3c:ef:12 (on wlan0)
        if (len(trozos) >= 4 and trozos[0] == 'Station'
                and trozos[2] == '(on' and trozos[3].strip(')') == interfaz):
            macs.append(trozos[1])
    return macs


def _cli_escribir(args):
    """CLI `escribir`: genera y deja la config del AP. La CLAVE entra por
    stdin — nunca por argv/ps, donde cualquier proceso de la máquina la
    vería (mismo motivo que las claves Wi-Fi de la WAN en keyfiles NM)."""
    ap = argparse.ArgumentParser(
        prog='wifi_ap.py escribir', description='escribe /etc/router/hostapd.conf')
    ap.add_argument('--interfaz', required=True)
    ap.add_argument('--ssid', required=True)
    ap.add_argument('--pais', required=True)
    ap.add_argument('--canal', required=True)
    a = ap.parse_args(args)
    clave = sys.stdin.read().rstrip('\r\n')     # sólo el salto final del pipe
    errores = validar(a.interfaz, a.ssid, clave, a.pais, a.canal)
    if errores:
        for e in errores:
            sys.stderr.write('ERROR: %s\n' % e)
        return 2
    texto = generar_hostapd_conf(a.interfaz, a.ssid, clave, a.pais, a.canal)
    escribir_hostapd_conf(texto, CONF_HOSTAPD)
    return 0


def _cli_soporta(args):
    """CLI `soporta-ap`: imprime si/no/desconocido, para que el instalador
    o el admin sepan antes de configurar si la tarjeta sirve de AP."""
    if len(args) != 1:
        sys.stderr.write('uso: wifi_ap.py soporta-ap <interfaz>\n')
        return 2
    soporta = soporta_ap(args[0])
    sys.stdout.write('si\n' if soporta
                     else ('no\n' if soporta is False else 'desconocido\n'))
    return 0


def main(argv):
    if argv[:1] == ['escribir']:
        return _cli_escribir(argv[1:])
    if argv[:1] == ['soporta-ap']:
        return _cli_soporta(argv[1:])
    sys.stderr.write('uso: wifi_ap.py escribir --interfaz X --ssid S --pais ES --canal 6   '
                     '(la clave entra por stdin)\n'
                     '      wifi_ap.py soporta-ap <interfaz>\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
