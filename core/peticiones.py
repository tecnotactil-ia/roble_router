# -*- coding: utf-8 -*-
"""Validación y aplicación de las peticiones del panel (docs/CONTRATO.md).

Todo lo que llega del panel se trata como NO confiable: se valida campo a
campo con listas blancas y rangos, y sólo entonces se toca la configuración
en memoria. Aquí no se ejecuta nada del sistema: routerd guarda la config y,
si hace falta, regenera dnsmasq (con su propia validación previa).

aplicar(cfg, peticion) -> (ok, mensaje, cambia_dhcp)

`cambia_dhcp` ya NO es un bool: dnsmasq necesita un recargo distinto según
qué cambió (H3). Valores:
  None       — nada que afecte a dnsmasq.
  'reservas' — sólo cambian las reservas DHCP (dhcp-hostsfile): basta un
               SIGHUP (`systemctl kill -s HUP dnsmasq`), que dnsmasq relee.
  'dhcp'     — cambia el rango DHCP o los servidores DNS (dhcp-range= o
               server=): un SIGHUP NO los relee, hace falta
               `systemctl restart dnsmasq`.
"""
import ipaddress
import re
import secrets

# BAJA14: import PEREZOSO/con fallback — peticiones.py NUNCA debe dejar de
# funcionar ENTERO (wan_actualizar, modo, reservas, wifi_*...) sólo porque
# falte este módulo (instalación a medias, actualización incompleta). Si
# falta, las 4 acciones bloqueo_* del buzón se rechazan con un mensaje
# claro (ver las comprobaciones `if router_bloqueo is None` más abajo) en
# vez de poder tirar la importación de este fichero entero.
#
# INSTALACIÓN: core/router_bloqueo.py debe copiarse a
# /usr/local/lib/router/ junto con el resto de core/*.py (ver
# systemd/router-bloqueo.{service,timer}) — es el módulo que de verdad
# descarga/aplica las listas; sin él, el bloqueador DNS simplemente no
# existe en este router (las demás funciones siguen intactas).
try:
    import router_bloqueo  # catálogo de listas de bloqueo DNS y normalizar_dominio() (sin red, sin disco)
except ImportError:
    router_bloqueo = None

# H4: re.fullmatch en vez de .match + "^...$" — con "$" un '\n' final cuela
# (pasaría una validación de nombre con un salto de línea pegado al final).
# \w también se cambia por clases ASCII explícitas: \w con re.UNICODE (el
# modo por defecto en Python 3) admite letras Unicode y dígitos de cualquier
# alfabeto, que no es lo que queremos en nombres, usuarios o leases.
RE_NOMBRE_WAN = re.compile(r'[A-Za-z0-9_ .-]{1,32}')
RE_HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?')
RE_MAC = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')
RE_LEASE = re.compile(r'[0-9]{1,4}[mh]')
RE_USUARIO = re.compile(r'[A-Za-z0-9_.@-]{1,40}')
# Wi-Fi WAN (clienta de un hotspot de teléfono): ssid sin caracteres de
# control (0x00-0x1f, 0x7f — \x80-\xff sí se admiten, un SSID puede ser
# UTF-8 "raro"); clave vacía (abierta) o 8-63 ASCII imprimibles (WPA-PSK).
RE_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
RE_CLAVE_WIFI = re.compile(r'[\x20-\x7e]{8,63}')
# Firewall con reglas propias (FIREWALL_PLAN.md): nombres con tildes y ñ
# admitidos, ids generadas por el core (nunca por el panel).
RE_NOMBRE_FW = re.compile(r'[A-Za-z0-9_ .áéíóúñÁÉÍÓÚÑ-]{1,40}')
# LOW (revisión Opus 2026-10-12): además de los controles ASCII, el
# comentario no admite invisibles Unicode (RLO/LRE/RLE, separadores de
# línea, zero-width, BOM, C1) — RE_CONTROL sólo cubre ASCII.
RE_CONTROL_FW = re.compile(
    r'[\x00-\x1f\x7f\u0080-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e'
    r'\u2066-\u2069\ufeff]')
RE_ID_REGLA_FW = re.compile(r'r_[0-9a-f]{8}')
RE_ID_GRUPO_FW = re.compile(r'g_[0-9a-f]{8}')
MAX_REGLAS_FW = 200
MAX_GRUPOS_FW = 50
MAX_MIEMBROS_GRUPO = 256
MAX_PUERTOS_REGLA = 15
COMENTARIO_FW_MAX = 120


class Invalida(ValueError):
    pass


def _bool(v, campo):
    if isinstance(v, bool):
        return v
    raise Invalida('«%s» debe ser verdadero o falso' % campo)


def _int(v, campo, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise Invalida('«%s» debe ser un entero entre %d y %d' % (campo, lo, hi))
    return v


def _ipv4(v, campo):
    try:
        ip = ipaddress.IPv4Address(str(v))
    except (ipaddress.AddressValueError, ValueError):
        raise Invalida('«%s» no es una IPv4 válida' % campo)
    return ip


def _ip_lan(v, campo, cfg):
    ip = _ipv4(v, campo)
    red = ipaddress.ip_network(cfg['lan']['red'])
    if ip not in red or ip in (red.network_address, red.broadcast_address) \
            or str(ip) == cfg['lan']['ip']:
        raise Invalida('«%s» debe estar dentro de %s y no ser la del router, la red ni el broadcast'
                       % (campo, red))
    return ip


def _mac(v):
    mac = str(v).strip().lower().replace('-', ':')
    if not RE_MAC.fullmatch(mac):
        raise Invalida('MAC no válida')
    if int(mac.split(':')[0], 16) & 1:
        raise Invalida('MAC multicast no admitida')
    return mac


def _solo(datos, permitidos):
    sobra = set(datos) - set(permitidos)
    if sobra:
        raise Invalida('campos no admitidos: %s' % ', '.join(sorted(sobra)))


def _ssid(v, campo='ssid'):
    if not isinstance(v, str):
        raise Invalida('«%s» debe ser una cadena' % campo)
    if RE_CONTROL.search(v):
        raise Invalida('«%s» no puede tener caracteres de control' % campo)
    try:
        n = len(v.encode('utf-8'))
    except UnicodeEncodeError:
        raise Invalida('«%s» no es UTF-8 válido' % campo)
    if not 1 <= n <= 32:
        raise Invalida('«%s»: 1-32 bytes UTF-8' % campo)
    return v


def _normalizar_ssid_bloqueo(ssid):
    """Normalización para comparar SSID contra la lista de bloqueados:    .strip().casefold() — así "MI-WIFI ", "mi-wifi" o "Mi-Wifi"
    cuentan como la misma red bloqueada que "MI-WIFI" (el panel aplica
    la misma normalización al pintar el aviso)."""
    return ssid.strip().casefold()


def _ssid_no_bloqueada(cfg, ssid):
    bloqueadas = {_normalizar_ssid_bloqueo(s) for s in (cfg.get('wifi_wan') or {}).get('ssid_bloqueadas') or []}
    if _normalizar_ssid_bloqueo(ssid) in bloqueadas:
        raise Invalida('Ese SSID está bloqueado (crearía un bucle con la propia LAN)')


def _clave_wifi(v):
    if not isinstance(v, str):
        raise Invalida('«clave» debe ser una cadena')
    if v == '':
        return v   # red abierta
    if not RE_CLAVE_WIFI.fullmatch(v):
        raise Invalida('«clave»: vacía (red abierta) o 8-63 caracteres ASCII imprimibles')
    return v


def aplicar(cfg, pet):
    if not isinstance(pet, dict) or not isinstance(pet.get('datos'), dict):
        return False, 'Petición mal formada', None
    usuario = pet.get('usuario')
    if not isinstance(usuario, str) or not RE_USUARIO.fullmatch(usuario):
        return False, 'Usuario no válido en la petición', None
    accion, d = pet.get('accion'), pet['datos']
    fn = ACCIONES.get(accion)
    if fn is None:
        return False, 'Acción no admitida', None
    try:
        msg, dhcp = fn(cfg, d)
    except Invalida as e:
        return False, str(e), None
    return True, msg, dhcp


def _wan_actualizar(cfg, d):
    _solo(d, ('wan', 'nombre', 'habilitada', 'peso', 'prioridad'))
    wid = d.get('wan')
    if not isinstance(wid, str) or wid not in cfg.get('wans', {}):
        raise Invalida('Línea WAN desconocida')
    w = cfg['wans'][wid]
    nuevo = dict(w)
    if 'nombre' in d:
        if not isinstance(d['nombre'], str) or not RE_NOMBRE_WAN.fullmatch(d['nombre']):
            raise Invalida('Nombre: 1-32 letras, números, espacios, punto o guion')
        nuevo['nombre'] = d['nombre']
    if 'habilitada' in d:
        nuevo['habilitada'] = _bool(d['habilitada'], 'habilitada')
    if 'peso' in d:
        nuevo['peso'] = _int(d['peso'], 'peso', 1, 100)
    if 'prioridad' in d:
        nuevo['prioridad'] = _int(d['prioridad'], 'prioridad', 1, 9)
    if not nuevo['habilitada'] and not any(v.get('habilitada') for k, v in cfg['wans'].items() if k != wid):
        raise Invalida('No se puede deshabilitar la única línea habilitada')
    cfg['wans'][wid] = nuevo
    return 'Línea %s actualizada' % nuevo['nombre'], None


def _modo(cfg, d):
    _solo(d, ('modo',))
    if d.get('modo') not in ('balanceo', 'respaldo'):
        raise Invalida('Modo: «balanceo» o «respaldo»')
    cfg['modo'] = d['modo']
    return 'Modo cambiado a %s' % d['modo'], None


def _modo_pesos(cfg, d):
    # Fase 4 (C): "auto" calcula el peso de cada WAN con lo que ya se mide
    # (latencia/pérdida — H2: la capacidad NO entra en el cálculo); "manual"
    # usa el "peso" que pone el admin en cada WAN con wan_actualizar, como
    # hasta ahora. routerd es quien de verdad aplica el cambio en el ciclo
    # siguiente.
    _solo(d, ('modo_pesos',))
    if d.get('modo_pesos') not in ('auto', 'manual'):
        raise Invalida('modo_pesos: «auto» o «manual»')
    cfg['modo_pesos'] = d['modo_pesos']
    return 'Modo de pesos cambiado a %s' % d['modo_pesos'], None


def _reserva_agregar(cfg, d):
    _solo(d, ('mac', 'ip', 'nombre'))
    mac = _mac(d.get('mac'))
    ip = str(_ip_lan(d.get('ip'), 'ip', cfg))
    nombre = str(d.get('nombre', '')).strip().lower()
    if not RE_HOST.fullmatch(nombre):
        raise Invalida('Nombre: 1-40 minúsculas, números o guion (sin guion al inicio/fin)')
    for r in cfg['reservas']:
        if r['mac'] == mac:
            raise Invalida('Esa MAC ya tiene reserva (%s)' % r['ip'])
        if r['ip'] == ip:
            raise Invalida('Esa IP ya está reservada para %s' % r['mac'])
        if r['nombre'] == nombre:
            raise Invalida('Ese nombre ya está en uso')
    cfg['reservas'].append({'mac': mac, 'ip': ip, 'nombre': nombre})
    return 'Reserva %s → %s creada' % (mac, ip), 'reservas'


def _reserva_eliminar(cfg, d):
    _solo(d, ('mac',))
    mac = _mac(d.get('mac'))
    antes = len(cfg['reservas'])
    cfg['reservas'] = [r for r in cfg['reservas'] if r['mac'] != mac]
    if len(cfg['reservas']) == antes:
        raise Invalida('No hay reserva para esa MAC')
    return 'Reserva de %s eliminada' % mac, 'reservas'


def _etiquetar(cfg, d):
    _solo(d, ('mac', 'etiqueta'))
    mac = _mac(d.get('mac'))
    et = d.get('etiqueta', '')
    if not isinstance(et, str) or len(et) > 60 or not et.isprintable():
        raise Invalida('Etiqueta: hasta 60 caracteres imprimibles')
    et = et.strip()
    if et:
        cfg['etiquetas'][mac] = et
    else:
        cfg['etiquetas'].pop(mac, None)
    return 'Etiqueta guardada', None


def _dhcp_rango(cfg, d):
    _solo(d, ('inicio', 'fin', 'lease'))
    ini = _ip_lan(d.get('inicio'), 'inicio', cfg)
    fin = _ip_lan(d.get('fin'), 'fin', cfg)
    if not ini < fin:
        raise Invalida('El inicio del rango debe ser menor que el fin')
    lease = str(d.get('lease', '12h'))
    if not RE_LEASE.fullmatch(lease):
        raise Invalida('Lease: número seguido de m o h (p. ej. 12h)')
    n, u = int(lease[:-1]), lease[-1]
    if (u == 'm' and n < 2) or (u == 'h' and not 1 <= n <= 168):
        raise Invalida('Lease entre 2 minutos y 168 horas')
    cfg['dhcp'] = {'inicio': str(ini), 'fin': str(fin), 'lease': lease}
    return 'Rango DHCP %s – %s (%s)' % (ini, fin, lease), 'dhcp'


def _dns(cfg, d):
    _solo(d, ('servidores',))
    s = d.get('servidores')
    if not isinstance(s, list) or not 1 <= len(s) <= 4:
        raise Invalida('Entre 1 y 4 servidores DNS')
    ips = []
    for i, v in enumerate(s):
        ip = _ipv4(v, 'servidor %d' % (i + 1))
        if not ip.is_global:
            raise Invalida('El servidor %s no es una IP pública' % ip)
        ips.append(str(ip))
    cfg['dns'] = ips
    return 'Servidores DNS: %s' % ', '.join(ips), 'dhcp'


def _monitor(cfg, d):
    _solo(d, ('destinos', 'intervalo_s', 'fallos_caida', 'exitos_alta'))
    dest = d.get('destinos')
    if not isinstance(dest, list) or not 1 <= len(dest) <= 4:
        raise Invalida('Entre 1 y 4 destinos de comprobación')
    ips = []
    for i, v in enumerate(dest):
        ip = _ipv4(v, 'destino %d' % (i + 1))
        if not ip.is_global:
            raise Invalida('El destino %s no es una IP pública' % ip)
        ips.append(str(ip))
    cfg['monitor'] = {
        'destinos': ips,
        'intervalo_s': _int(d.get('intervalo_s'), 'intervalo_s', 3, 60),
        'fallos_caida': _int(d.get('fallos_caida'), 'fallos_caida', 1, 10),
        'exitos_alta': _int(d.get('exitos_alta'), 'exitos_alta', 1, 10),
    }
    return 'Monitorización actualizada', None


def _wifi_config(cfg, d):
    _solo(d, ('habilitada',))
    if 'habilitada' not in d:
        raise Invalida('Falta el campo «habilitada»')
    habilitada = _bool(d['habilitada'], 'habilitada')
    cfg.setdefault('wifi_wan', {})['habilitada'] = habilitada
    return 'WAN Wi-Fi %s' % ('activada' if habilitada else 'desactivada'), None


# wifi_agregar/wifi_eliminar/wifi_conectar/wifi_escanear: a diferencia de
# las demás acciones, estas NO tocan `cfg` (nada de esto debe acabar en
# router.json — la clave en particular NUNCA, ver docs/CONTRATO.md). Aquí
# sólo se VALIDA con el mismo rigor que las demás; es routerd quien, tras
# ver que la validación pasó, ejecuta de verdad el cambio en
# NetworkManager (ver ACCIONES_WIFI_SISTEMA más abajo y
# Router._ejecutar_accion_wifi en routerd.py).
def _validar_wifi_agregar(cfg, d):
    _solo(d, ('ssid', 'clave', 'prioridad'))
    if not {'ssid', 'clave', 'prioridad'} <= set(d):
        raise Invalida('Faltan campos: ssid, clave y prioridad son obligatorios')
    ssid = _ssid(d['ssid'])
    _ssid_no_bloqueada(cfg, ssid)
    _clave_wifi(d['clave'])
    _int(d['prioridad'], 'prioridad', 0, 100)
    return 'Red Wi-Fi «%s» validada' % ssid, None


def _validar_wifi_eliminar(cfg, d):
    _solo(d, ('ssid',))
    if 'ssid' not in d:
        raise Invalida('Falta el campo «ssid»')
    ssid = _ssid(d['ssid'])
    return 'Eliminación de «%s» validada' % ssid, None


def _validar_wifi_conectar(cfg, d):
    _solo(d, ('ssid',))
    if 'ssid' not in d:
        raise Invalida('Falta el campo «ssid»')
    ssid = _ssid(d['ssid'])
    return 'Conexión a «%s» validada' % ssid, None


def _validar_wifi_escanear(cfg, d):
    _solo(d, ())
    return 'Escaneo validado', None


# ─────────────────────── bloqueador DNS (anuncios/amenazas) ───────────────

def _bloqueo_config(cfg, d):
    """Reemplaza ENTERA la sección 'bloqueo' de cfg salvo lista_blanca/
    lista_negra (esas se gestionan aparte, una a una, con _bloqueo_lista:
    nunca se pisan al cambiar el resto de la configuración desde este
    formulario). Las URLs NUNCA vienen de aquí: 'listas' son sólo ids que
    tienen que estar en el catálogo fijo (router_bloqueo.CATALOGO).

    `version` (opcional, petición del panel): la `bloqueo_version` que el
    panel vio en estado.json → config al abrir el formulario (hex, 16
    caracteres — ver router_bloqueo.calcular_version_bloqueo). Si viene y
    no coincide con la ACTUAL, se rechaza SIN aplicar nada — alguien más
    (otra pestaña, otro admin) cambió la configuración mientras se
    editaba; mejor avisar que pisarlo en silencio (concurrencia
    optimista)."""
    if router_bloqueo is None:
        raise Invalida('El módulo de bloqueo DNS no está instalado en este router')
    campos = ('habilitado', 'listas', 'forzar_dns', 'bloquear_doh', 'actualizar_h', 'registro_dns_dias')
    _solo(d, campos + ('version',))
    faltan = set(campos) - set(d)
    if faltan:
        raise Invalida('Faltan campos: %s' % ', '.join(sorted(faltan)))
    anterior = cfg.get('bloqueo') or {}
    if 'version' in d:
        version = d['version']
        if not isinstance(version, str) or not re.fullmatch(r'[0-9a-f]{16}', version):
            raise Invalida('«version» debe ser una cadena hexadecimal de 16 caracteres')
        if version != router_bloqueo.calcular_version_bloqueo(anterior):
            raise Invalida('La configuración cambió mientras editabas; recarga la página')
    habilitado = _bool(d['habilitado'], 'habilitado')
    listas = d['listas']
    if not isinstance(listas, list) or not all(isinstance(x, str) for x in listas):
        raise Invalida('«listas» debe ser una lista de identificadores del catálogo')
    catalogo = set(router_bloqueo.CATALOGO)
    desconocidas = sorted(set(listas) - catalogo)
    if desconocidas:
        raise Invalida('Lista(s) desconocida(s) del catálogo: %s' % ', '.join(desconocidas))
    forzar_dns = _bool(d['forzar_dns'], 'forzar_dns')
    bloquear_doh = _bool(d['bloquear_doh'], 'bloquear_doh')
    actualizar_h = _int(d['actualizar_h'], 'actualizar_h', 6, 168)
    registro_dns_dias = _int(d['registro_dns_dias'], 'registro_dns_dias', 1, 365)
    cfg['bloqueo'] = {
        'habilitado': habilitado,
        'listas': sorted(dict.fromkeys(listas)),
        'lista_blanca': list(anterior.get('lista_blanca') or []),
        'lista_negra': list(anterior.get('lista_negra') or []),
        'forzar_dns': forzar_dns,
        'bloquear_doh': bloquear_doh,
        'actualizar_h': actualizar_h,
        'registro_dns_dias': registro_dns_dias,
    }
    # M2: el servers-file del bloqueo se referencia SIEMPRE desde
    # dnsmasq_conf.py, pase lo que pase con 'habilitado' — ya NO hace
    # falta ningún recargo 'dhcp' (restart) de la LAN por esto; sólo si
    # 'forzar_dns' (nft) cambia lo recoge solo instalar_base() en el
    # siguiente ciclo (compara el texto generado). routerd decide por su
    # cuenta (comparando 'listas'/'bloquear_doh'/'habilitado' antes y
    # después — BAJA13) si hace falta relanzar router-bloqueo.service.
    return 'Configuración de bloqueo actualizada', None


def _bloqueo_lista(cfg, d):
    """Agrega/quita UN dominio de la lista blanca o negra manual. Nunca
    toca el resto de 'bloqueo' (listas/forzar_dns/...): a diferencia de
    _bloqueo_config, esta acción es segura de repetir muchas veces seguidas
    (el panel la llama una vez por dominio)."""
    if router_bloqueo is None:
        raise Invalida('El módulo de bloqueo DNS no está instalado en este router')
    _solo(d, ('tipo', 'accion', 'dominio'))
    if d.get('tipo') not in ('blanca', 'negra'):
        raise Invalida('«tipo»: «blanca» o «negra»')
    if d.get('accion') not in ('agregar', 'quitar'):
        raise Invalida('«accion»: «agregar» o «quitar»')
    dominio = router_bloqueo.normalizar_dominio(d.get('dominio'))
    if dominio is None:
        raise Invalida('«dominio» no es un nombre de dominio válido')
    # M5: nunca se puede añadir a lista NEGRA un sufijo público de dos
    # etiquetas (co.uk, com.es...) ni un dominio protegido (lo que el
    # propio router necesita para funcionar) — router_bloqueo.generar()
    # ya los filtra de todas formas (defensa en profundidad), pero
    # rechazarlo aquí evita que el admin crea que "ya está bloqueado"
    # cuando en realidad nunca lo estará.
    if d['tipo'] == 'negra' and d['accion'] == 'agregar':
        if router_bloqueo.es_sufijo_publico(dominio):
            raise Invalida('«%s» es un sufijo público (como co.uk/com.es): bloquearlo entero '
                           'afectaría a demasiados sitios ajenos' % dominio)
        protegidos = router_bloqueo._dominios_protegidos(cfg.get('dominio'))
        if any(s in protegidos for s in router_bloqueo._sufijos(dominio)):
            raise Invalida('«%s» es un dominio protegido (necesario para el propio router): '
                           'nunca se puede bloquear' % dominio)
    clave = 'lista_blanca' if d['tipo'] == 'blanca' else 'lista_negra'
    bloqueo = dict(cfg.get('bloqueo') or {})
    lista = list(bloqueo.get(clave) or [])
    if d['accion'] == 'agregar':
        if dominio not in lista:
            if len(lista) >= 5000:
                raise Invalida('Esa lista ya tiene el máximo de 5000 entradas')
            lista.append(dominio)
    else:
        if dominio not in lista:
            raise Invalida('Ese dominio no estaba en la lista %s' % d['tipo'])
        lista.remove(dominio)
    bloqueo[clave] = lista
    cfg['bloqueo'] = bloqueo
    verbo = 'agregado a' if d['accion'] == 'agregar' else 'quitado de'
    return 'Dominio «%s» %s la lista %s' % (dominio, verbo, d['tipo']), None


# bloqueo_actualizar/bloqueo_probar: igual que las acciones wifi_* de
# sistema, aquí SÓLO se valida (nunca mutan cfg); es routerd quien, tras
# ver que la validación pasó, ejecuta de verdad la actualización (lanzar
# router-bloqueo.service) o la consulta (leer los ficheros generados, sin
# red) — ver ACCIONES_SISTEMA_BLOQUEO y Router._ejecutar_accion_bloqueo.
def _validar_bloqueo_actualizar(cfg, d):
    if router_bloqueo is None:
        raise Invalida('El módulo de bloqueo DNS no está instalado en este router')
    # BAJA4 (ronda 3): 'forzar' opcional — salta la guarda de variación
    # ±50% de router_bloqueo.generar() para ESTA pasada (el admin pide
    # explícitamente aplicar lo que haya, pase lo que pase).
    _solo(d, ('forzar',))
    if 'forzar' in d:
        _bool(d['forzar'], 'forzar')
    msg = 'Actualización de las listas de bloqueo solicitada'
    if d.get('forzar'):
        msg += ' (forzada: se salta la guarda de variación)'
    return msg, None


def _validar_bloqueo_probar(cfg, d):
    if router_bloqueo is None:
        raise Invalida('El módulo de bloqueo DNS no está instalado en este router')
    _solo(d, ('dominio',))
    if 'dominio' not in d:
        raise Invalida('Falta el campo «dominio»')
    dominio = router_bloqueo.normalizar_dominio(d.get('dominio'))
    if dominio is None:
        raise Invalida('«dominio» no es un nombre de dominio válido')
    return 'Comprobación de «%s» validada' % dominio, None


# ─────────────────────── firewall con reglas propias (FIREWALL_PLAN.md) ───────────────────────

def _firewall_seccion(cfg):
    """Devuelve la sección 'firewall' de cfg, creándola vacía si no existe
    (compatibilidad con router.json anteriores a esta fase).
    LOW: si «version» llega como cadena u otro tipo no entero desde
    router.json, se normaliza a entero — si no, el control de concurrencia
    optimista bloquearía el firewall para siempre."""
    fw = cfg.get('firewall')
    if fw is None:
        fw = {'version': 1, 'grupos': [], 'reglas': []}
        cfg['firewall'] = fw
    fw.setdefault('version', 1)
    fw.setdefault('grupos', [])
    fw.setdefault('reglas', [])
    v = fw.get('version')
    if isinstance(v, bool) or not isinstance(v, int):
        try:
            fw['version'] = int(v)
        except (TypeError, ValueError):
            fw['version'] = 1
    return fw


def _generar_id_regla():
    return 'r_' + secrets.token_hex(4)


def _generar_id_grupo():
    return 'g_' + secrets.token_hex(4)


def _generar_id_regla_unica(existentes):
    """Genera una id de regla que no esté ya en `existentes` (LOW: evita la
    colisión si por casualidad sale una id repetida)."""
    rid = _generar_id_regla()
    while rid in existentes:
        rid = _generar_id_regla()
    return rid


def _generar_id_grupo_unica(existentes):
    gid = _generar_id_grupo()
    while gid in existentes:
        gid = _generar_id_grupo()
    return gid


def _version_fw(fw, d):
    """Control de concurrencia optimista: la versión que el panel vio al
    abrir el formulario debe coincidir con la actual. Si no, se rechaza
    ENTERA sin aplicar nada (igual que bloqueo_config)."""
    if 'version' not in d:
        raise Invalida('Falta el campo «version»')
    v = d['version']
    if isinstance(v, bool) or not isinstance(v, int):
        raise Invalida('«version» debe ser un entero')
    if v != fw['version']:
        raise Invalida('La configuración cambió mientras editabas; recarga la página')


def _nombre_fw(v):
    if not isinstance(v, str) or not RE_NOMBRE_FW.fullmatch(v):
        raise Invalida('Nombre: 1-40 letras, números, espacios, punto, guion, tildes o ñ')
    if not v.strip():
        raise Invalida('Nombre: no puede ser solo espacios')
    return v


def _comentario_fw(v):
    if v is None:
        return ''
    if not isinstance(v, str) or len(v) > COMENTARIO_FW_MAX:
        raise Invalida('Comentario: hasta %d caracteres' % COMENTARIO_FW_MAX)
    if RE_CONTROL_FW.search(v):
        raise Invalida('El comentario no puede tener caracteres de control')
    return v


def _bool_fw(v, campo='habilitada'):
    return _bool(v, campo)


def _validar_mac_miembro(v):
    return _mac(v)


def _validar_ip_miembro(v):
    return str(_ipv4(v, 'miembro'))


def _miembros_grupo(tipo, miembros, cfg=None, exigir_lan=False):
    if not isinstance(miembros, list):
        raise Invalida('«miembros» debe ser una lista')
    if len(miembros) > MAX_MIEMBROS_GRUPO:
        raise Invalida('Máximo %d miembros por grupo' % MAX_MIEMBROS_GRUPO)
    # LOW: tras normalizar (minúsculas, - por :) pueden quedar duplicados;
    # se eliminan para no mandar sets con miembros repetidos a nft.
    vistos = set()
    salida = []
    for m in miembros:
        if tipo == 'mac':
            valor = _validar_mac_miembro(m)
        else:
            valor = _validar_ip_miembro(m)
            # MEDIUM-A: la IP del router nunca es un miembro válido (origen
            # o destino). La restricción a la LAN sólo aplica cuando el
            # grupo se usa como ORIGEN (exigir_lan=True): los grupos usados
            # como destino admiten IPs/redes públicas.
            if cfg is not None:
                ip = ipaddress.IPv4Address(valor)
                if str(ip) == cfg['lan']['ip']:
                    raise Invalida('El miembro %s no puede ser la IP del router' % valor)
                if exigir_lan:
                    red = ipaddress.ip_network(cfg['lan']['red'])
                    if ip not in red:
                        raise Invalida('El miembro %s debe estar dentro de la LAN '
                                       '(el grupo se usa como origen)' % valor)
        if valor not in vistos:
            vistos.add(valor)
            salida.append(valor)
    return salida


def _miembros_en_lan(g, cfg):
    """MEDIUM-A: comprueba que todos los miembros de un grupo ip estén en
    la LAN y no sean la IP del router. Se llama al usar un grupo como
    ORIGEN en una regla y al editar un grupo ya usado como origen."""
    if not cfg or g.get('tipo') != 'ip':
        return
    red = ipaddress.ip_network(cfg['lan']['red'])
    for m in g.get('miembros') or []:
        try:
            ip = ipaddress.IPv4Address(str(m))
        except (ipaddress.AddressValueError, ValueError):
            continue
        if str(ip) == cfg['lan']['ip']:
            raise Invalida('El miembro %s no puede ser la IP del router' % m)
        if ip not in red:
            raise Invalida('El miembro %s del grupo «%s» debe estar dentro de la '
                           'LAN (el grupo se usa como origen)'
                           % (m, g.get('nombre', g.get('id', '?'))))


def _validar_endpoint(ep, cfg, grupos_por_id, es_origen):
    """Valida origen/destino: {tipo, valor?}. El origen debe estar en la LAN
    salvo «cualquiera»; el MAC sólo tiene sentido como origen; el grupo de
    destino debe ser tipo ip. La IP del router (lan.ip) no se puede usar."""
    if not isinstance(ep, dict):
        raise Invalida('origen/destino debe ser un objeto')
    tipo = ep.get('tipo')
    if tipo == 'cualquiera':
        return {'tipo': 'cualquiera'}
    if tipo == 'mac':
        if not es_origen:
            raise Invalida('un MAC sólo tiene sentido como origen')
        return {'tipo': 'mac', 'valor': _mac(ep.get('valor'))}
    if tipo == 'ip':
        ip = _ipv4(ep.get('valor'), 'valor')
        if str(ip) == cfg['lan']['ip']:
            raise Invalida('No se puede crear una regla contra la IP del router')
        if es_origen and ip not in ipaddress.ip_network(cfg['lan']['red']):
            raise Invalida('El origen debe estar dentro de la LAN')
        return {'tipo': 'ip', 'valor': str(ip)}
    if tipo == 'red':
        try:
            red = ipaddress.ip_network(str(ep.get('valor')), strict=True)
        except (ValueError, TypeError):
            raise Invalida('«valor» no es una red CIDR válida')
        if not isinstance(red, ipaddress.IPv4Network):
            raise Invalida('Sólo se admiten redes IPv4')
        lan_ip = ipaddress.IPv4Address(cfg['lan']['ip'])
        # «contra la IP del router»: sólo cuando el destino ES la IP del
        # router (ip exacta o /32). Un rango que simplemente la incluye
        # (0.0.0.0/0, la LAN entera) no es «contra la IP del router» — ese
        # caso lo cubre la regla de «bloquear-todo sin condiciones».
        if red.prefixlen == 32 and lan_ip in red:
            raise Invalida('No se puede crear una regla contra la IP del router')
        if es_origen:
            lan_red = ipaddress.ip_network(cfg['lan']['red'])
            if not red.subnet_of(lan_red) and red != lan_red:
                raise Invalida('El origen debe estar dentro de la LAN')
        return {'tipo': 'red', 'valor': str(red)}
    if tipo == 'grupo':
        gid = ep.get('valor')
        if not isinstance(gid, str) or not RE_ID_GRUPO_FW.fullmatch(gid):
            raise Invalida('«valor» debe ser la id de un grupo')
        g = grupos_por_id.get(gid)
        if g is None:
            raise Invalida('Grupo desconocido: %s' % gid)
        if not es_origen and g.get('tipo') != 'ip':
            raise Invalida('El destino con grupo exige un grupo tipo ip')
        # MEDIUM-A: la restricción a la LAN sólo aplica a un grupo usado
        # como ORIGEN. Un grupo destino admite IPs/redes públicas.
        if es_origen:
            _miembros_en_lan(g, cfg)
        return {'tipo': 'grupo', 'valor': gid}
    raise Invalida('Tipo de origen/destino no válido: %r' % tipo)


def _validar_puertos(puertos, protocolo):
    if puertos is None:
        return []
    if not isinstance(puertos, list):
        raise Invalida('«puertos» debe ser una lista')
    if not puertos:
        return []
    if len(puertos) > MAX_PUERTOS_REGLA:
        raise Invalida('Máximo %d rangos de puertos' % MAX_PUERTOS_REGLA)
    if protocolo not in ('tcp', 'udp', 'tcp_udp'):
        raise Invalida('Los puertos sólo aplican a protocolo tcp, udp o tcp_udp')
    salida = []
    for p in puertos:
        if not isinstance(p, dict) or set(p) != {'desde', 'hasta'}:
            raise Invalida('Cada puerto debe ser {desde, hasta}')
        desde = _int(p['desde'], 'desde', 1, 65535)
        hasta = _int(p['hasta'], 'hasta', 1, 65535)
        if desde > hasta:
            raise Invalida('El puerto «desde» no puede ser mayor que «hasta»')
        salida.append({'desde': desde, 'hasta': hasta})
    return salida


def _origen_cubre_lan(origen, cfg):
    """True si el origen abarca a TODOS los clientes de la LAN. En la
    protección «bloquear-todo» se trata igual que «cualquiera» (MEDIUM-2):
    una regla así corta el Internet de todos igual que un origen vacío."""
    tipo = origen.get('tipo')
    if tipo == 'cualquiera':
        return True
    if tipo == 'red':
        lan_red = ipaddress.ip_network(cfg['lan']['red'])
        origen_red = ipaddress.ip_network(origen['valor'])
        return lan_red.subnet_of(origen_red)
    return False


def _destino_cubre_internet(destino):
    """True si el destino abarca todo Internet (prefijo 0 o «cualquiera»).
    MEDIUM-2: la protección «bloquear-todo» mira si el destino cubre
    Internet, no si contiene la LAN — bloquear hacia una red interna con
   creto no corta el Internet de nadie."""
    tipo = destino.get('tipo')
    if tipo == 'cualquiera':
        return True
    if tipo == 'red':
        return ipaddress.ip_network(destino['valor']).prefixlen == 0
    return False


def _validar_regla_campos(r, cfg, grupos_por_id, exige_id):
    """Valida campo a campo una regla. Devuelve la regla normalizada.
    `exige_id`: True para edición (la id debe existir), False para creación
    (la id se IGNORA si llega — la genera el core, nunca el panel)."""
    if not isinstance(r, dict):
        raise Invalida('«regla» debe ser un objeto')
    permitidos = {'id', 'nombre', 'habilitada', 'accion', 'origen', 'destino',
                  'protocolo', 'puertos', 'registrar', 'comentario'}
    _solo(r, permitidos)
    rid = r.get('id')
    if exige_id:
        if not isinstance(rid, str) or not RE_ID_REGLA_FW.fullmatch(rid):
            raise Invalida('«id» de regla no válida')
    # La id se genera siempre en creación: el panel no puede fijarla.
    nombre = _nombre_fw(r.get('nombre'))
    habilitada = _bool_fw(r.get('habilitada', True))
    accion = r.get('accion')
    if accion not in ('permitir', 'bloquear', 'rechazar'):
        raise Invalida('«accion»: permitir, bloquear o rechazar')
    # LOW: origen/destino/puertos vacíos o de tipo inválido no se convierten
    # silenciosamente en «cualquiera»/[] — se exige dict o list, o None.
    origen_raw = r.get('origen')
    if origen_raw is None:
        origen = {'tipo': 'cualquiera'}
    else:
        origen = _validar_endpoint(origen_raw, cfg, grupos_por_id, True)
    destino_raw = r.get('destino')
    if destino_raw is None:
        destino = {'tipo': 'cualquiera'}
    else:
        destino = _validar_endpoint(destino_raw, cfg, grupos_por_id, False)
    protocolo = r.get('protocolo', 'cualquiera')
    if protocolo not in ('cualquiera', 'tcp', 'udp', 'tcp_udp', 'icmp'):
        raise Invalida('«protocolo»: cualquiera, tcp, udp, tcp_udp o icmp')
    puertos_raw = r.get('puertos')
    if puertos_raw is None:
        puertos = []
    else:
        puertos = _validar_puertos(puertos_raw, protocolo)
    registrar = _bool(r.get('registrar', False), 'registrar')
    comentario = _comentario_fw(r.get('comentario', ''))
    # «bloquear-todo sin condiciones» (MEDIUM-2): acción bloquear o rechazar
    # con destino que cubre Internet (cualquiera o 0.0.0.0/0) y origen que
    # cubre la LAN entera (cualquiera o una red que la contiene), sin
    # protocolo ni puertos — cortaría el Internet de todos.
    if accion in ('bloquear', 'rechazar') \
            and _destino_cubre_internet(destino) \
            and _origen_cubre_lan(origen, cfg) \
            and protocolo == 'cualquiera' and not puertos:
        raise Invalida('Bloquear o rechazar todo el tráfico sin condiciones cortaría el '
                       'Internet de todos; añade origen, protocolo o puertos')
    return {
        'id': rid if exige_id else None,   # se rellena después en creación
        'nombre': nombre, 'habilitada': habilitada, 'accion': accion,
        'origen': origen, 'destino': destino,
        'protocolo': protocolo, 'puertos': puertos,
        'registrar': registrar, 'comentario': comentario,
    }


def _fw_regla_guardar(cfg, d):
    _solo(d, ('version', 'regla', 'posicion'))
    fw = _firewall_seccion(cfg)
    _version_fw(fw, d)
    r = d.get('regla')
    grupos_por_id = {g['id']: g for g in fw['grupos']}
    rid = r.get('id') if isinstance(r, dict) else None
    # Sólo se edita si la id tiene el formato estricto Y ya existe. Una id
    # con otra grafía (o inexistente) se ignora y se crea una regla nueva:
    # las ids las genera SIEMPRE el core, nunca el panel.
    es_edicion = isinstance(rid, str) and RE_ID_REGLA_FW.fullmatch(rid) is not None
    if es_edicion:
        existente = next((x for x in fw['reglas'] if x['id'] == rid), None)
        if existente is None:
            raise Invalida('No existe ninguna regla con esa id')
        nueva = _validar_regla_campos(r, cfg, grupos_por_id, exige_id=True)
        nueva['id'] = rid
        posicion = fw['reglas'].index(existente)
        fw['reglas'][posicion] = nueva
        # LOW: «posicion» al editar mueve la regla a esa posición en vez de
        # ignorarse en silencio.
        pos = d.get('posicion')
        if pos is not None:
            pos = _int(pos, 'posicion', 0, len(fw['reglas']) - 1)
            fw['reglas'].insert(pos, fw['reglas'].pop(fw['reglas'].index(nueva)))
    else:
        if len(fw['reglas']) >= MAX_REGLAS_FW:
            raise Invalida('Máximo %d reglas' % MAX_REGLAS_FW)
        nueva = _validar_regla_campos(r, cfg, grupos_por_id, exige_id=False)
        nueva['id'] = _generar_id_regla_unica({x['id'] for x in fw['reglas']})
        pos = d.get('posicion')
        if pos is not None:
            pos = _int(pos, 'posicion', 0, len(fw['reglas']))
            fw['reglas'].insert(pos, nueva)
        else:
            fw['reglas'].append(nueva)
    fw['version'] += 1
    return 'Regla «%s» guardada' % nueva['nombre'], None


def _fw_regla_eliminar(cfg, d):
    _solo(d, ('version', 'id'))
    fw = _firewall_seccion(cfg)
    _version_fw(fw, d)
    rid = d.get('id')
    if not isinstance(rid, str) or not RE_ID_REGLA_FW.fullmatch(rid):
        raise Invalida('«id» de regla no válida')
    antes = len(fw['reglas'])
    fw['reglas'] = [r for r in fw['reglas'] if r['id'] != rid]
    if len(fw['reglas']) == antes:
        raise Invalida('No existe ninguna regla con esa id')
    fw['version'] += 1
    return 'Regla eliminada', None


def _fw_regla_mover(cfg, d):
    _solo(d, ('version', 'id', 'posicion'))
    fw = _firewall_seccion(cfg)
    _version_fw(fw, d)
    rid = d.get('id')
    if not isinstance(rid, str) or not RE_ID_REGLA_FW.fullmatch(rid):
        raise Invalida('«id» de regla no válida')
    if not fw['reglas']:
        raise Invalida('No hay reglas que mover')
    pos = _int(d.get('posicion'), 'posicion', 0, len(fw['reglas']) - 1)
    idx = next((i for i, r in enumerate(fw['reglas']) if r['id'] == rid), None)
    if idx is None:
        raise Invalida('No existe ninguna regla con esa id')
    regla = fw['reglas'].pop(idx)
    fw['reglas'].insert(pos, regla)
    fw['version'] += 1
    return 'Regla movida', None


def _fw_regla_activar(cfg, d):
    _solo(d, ('version', 'id', 'habilitada'))
    fw = _firewall_seccion(cfg)
    _version_fw(fw, d)
    rid = d.get('id')
    if not isinstance(rid, str) or not RE_ID_REGLA_FW.fullmatch(rid):
        raise Invalida('«id» de regla no válida')
    habilitada = _bool(d.get('habilitada'), 'habilitada')
    for r in fw['reglas']:
        if r['id'] == rid:
            r['habilitada'] = habilitada
            fw['version'] += 1
            return 'Regla %s' % ('activada' if habilitada else 'desactivada'), None
    raise Invalida('No existe ninguna regla con esa id')


def _fw_grupo_guardar(cfg, d):
    _solo(d, ('version', 'grupo'))
    fw = _firewall_seccion(cfg)
    _version_fw(fw, d)
    g = d.get('grupo')
    if not isinstance(g, dict):
        raise Invalida('«grupo» debe ser un objeto')
    _solo(g, ('id', 'nombre', 'tipo', 'miembros'))
    gid = g.get('id')
    # Mismo criterio que las reglas: sólo se edita si la id tiene formato
    # estricto Y ya existe; si no, se crea uno nuevo (la id la genera el core).
    es_edicion = isinstance(gid, str) and RE_ID_GRUPO_FW.fullmatch(gid) is not None
    if es_edicion:
        existente = next((x for x in fw['grupos'] if x['id'] == gid), None)
        if existente is None:
            raise Invalida('No existe ningún grupo con esa id')
    else:
        if len(fw['grupos']) >= MAX_GRUPOS_FW:
            raise Invalida('Máximo %d grupos' % MAX_GRUPOS_FW)
    nombre = _nombre_fw(g.get('nombre'))
    tipo = g.get('tipo')
    if tipo not in ('mac', 'ip'):
        raise Invalida('«tipo»: mac o ip')
    # MEDIUM-A: un grupo usado como ORIGEN por alguna regla sólo admite
    # miembros de la LAN; un grupo destino (o sin usar) admite públicos.
    usado_como_origen = any(
        (r.get('origen') or {}).get('tipo') == 'grupo'
        and (r.get('origen') or {}).get('valor') == gid
        for r in fw['reglas']) if es_edicion else False
    miembros = _miembros_grupo(tipo, g.get('miembros') or [], cfg,
                               exigir_lan=usado_como_origen)
    # HIGH-3: cambiar el tipo de un grupo que alguna regla use como DESTINO
    # rompe la generación nft (el destino con grupo exige tipo ip) y congela
    # el firewall. Se rechaza aquí, antes de tocar nada.
    if es_edicion and tipo != existente.get('tipo'):
        for r in fw['reglas']:
            destino = r.get('destino') or {}
            if destino.get('tipo') == 'grupo' and destino.get('valor') == gid:
                raise Invalida('No se puede cambiar el tipo del grupo «%s»: la regla '
                               '«%s» (%s) lo usa como destino; elimina o cambia esa '
                               'regla primero'
                               % (nombre, r.get('nombre', r.get('id')), r.get('id')))
    nuevo = {
        'id': gid if es_edicion else _generar_id_grupo_unica({x['id'] for x in fw['grupos']}),
        'nombre': nombre, 'tipo': tipo, 'miembros': miembros,
    }
    if es_edicion:
        posicion = fw['grupos'].index(existente)
        fw['grupos'][posicion] = nuevo
    else:
        fw['grupos'].append(nuevo)
    fw['version'] += 1
    return 'Grupo «%s» guardado' % nombre, None


def _fw_grupo_eliminar(cfg, d):
    _solo(d, ('version', 'id'))
    fw = _firewall_seccion(cfg)
    _version_fw(fw, d)
    gid = d.get('id')
    if not isinstance(gid, str) or not RE_ID_GRUPO_FW.fullmatch(gid):
        raise Invalida('«id» de grupo no válida')
    existente = next((x for x in fw['grupos'] if x['id'] == gid), None)
    if existente is None:
        raise Invalida('No existe ningún grupo con esa id')
    # No se puede borrar un grupo que alguna regla use (origen o destino).
    for r in fw['reglas']:
        origen = (r.get('origen') or {}).get('valor')
        destino = (r.get('destino') or {}).get('valor')
        if (r.get('origen') or {}).get('tipo') == 'grupo' and origen == gid \
                or (r.get('destino') or {}).get('tipo') == 'grupo' and destino == gid:
            raise Invalida('El grupo «%s» está en uso por la regla «%s» (%s): '
                           'elimina o cambia esa regla primero'
                           % (existente.get('nombre', gid), r.get('nombre', r.get('id')), r.get('id')))
    fw['grupos'] = [g for g in fw['grupos'] if g['id'] != gid]
    fw['version'] += 1
    return 'Grupo «%s» eliminado' % existente.get('nombre', gid), None


ACCIONES = {
    'wan_actualizar': _wan_actualizar,
    'modo': _modo,
    'modo_pesos': _modo_pesos,
    'reserva_agregar': _reserva_agregar,
    'reserva_eliminar': _reserva_eliminar,
    'dispositivo_etiquetar': _etiquetar,
    'dhcp_rango': _dhcp_rango,
    'dns': _dns,
    'monitor': _monitor,
    'wifi_config': _wifi_config,
    'wifi_agregar': _validar_wifi_agregar,
    'wifi_eliminar': _validar_wifi_eliminar,
    'wifi_conectar': _validar_wifi_conectar,
    'wifi_escanear': _validar_wifi_escanear,
    'bloqueo_config': _bloqueo_config,
    'bloqueo_lista': _bloqueo_lista,
    'bloqueo_actualizar': _validar_bloqueo_actualizar,
    'bloqueo_probar': _validar_bloqueo_probar,
    'fw_regla_guardar': _fw_regla_guardar,
    'fw_regla_eliminar': _fw_regla_eliminar,
    'fw_regla_mover': _fw_regla_mover,
    'fw_regla_activar': _fw_regla_activar,
    'fw_grupo_guardar': _fw_grupo_guardar,
    'fw_grupo_eliminar': _fw_grupo_eliminar,
}

# Subconjunto de ACCIONES que, una vez validadas aquí, routerd ejecuta de
# verdad contra NetworkManager (nunca mutan `cfg`: ver el comentario de
# arriba). routerd.atender_buzon() mira este conjunto para saber cuándo
# debe sustituir el (ok, msg) de la validación por el de la ejecución real.
ACCIONES_WIFI_SISTEMA = frozenset({'wifi_agregar', 'wifi_eliminar', 'wifi_conectar', 'wifi_escanear'})

# Mismo patrón que ACCIONES_WIFI_SISTEMA, para el bloqueador DNS: estas dos
# nunca mutan cfg, routerd las ejecuta de verdad tras la validación (ver
# Router._ejecutar_accion_bloqueo). A diferencia de las wifi_*, no están
# sujetas al límite de "una por ciclo" (son baratas: lanzar un systemctl
# --no-block, o leer unos ficheros de caché en disco).
ACCIONES_SISTEMA_BLOQUEO = frozenset({'bloqueo_actualizar', 'bloqueo_probar'})

# Acciones del firewall con reglas propias (FIREWALL_PLAN.md). Tras
# aplicarlas, routerd debe validar el texto nft generado con `nft -c -f`
# ANTES de guardar la config (HIGH-3 de la revisión Opus 2026-10-12): si la
# validación falla, la petición se responde con error y la config en
# memoria vuelve a la anterior — el panel nunca recibe un «guardada» que
# luego no se puede instalar.
ACCIONES_FIREWALL = frozenset({
    'fw_regla_guardar', 'fw_regla_eliminar', 'fw_regla_mover',
    'fw_regla_activar', 'fw_grupo_guardar', 'fw_grupo_eliminar',
})
