# -*- coding: utf-8 -*-
"""Genera las tablas nftables del router a partir de router.json.

Sólo toca SU tabla (`inet router`): nunca `flush ruleset`, así no se lleva
por delante tablas de otros (p. ej. las de Docker). El fichero empieza con
`destroy table inet router` y la vuelve a crear: nft lo aplica en UNA
transacción, o todo o nada. También se destruye `ip router_nat` si existe,
sólo para limpiar instalaciones viejas (C1: esa tabla separada ya no se usa,
el NAT vive ahora dentro de `inet router` — ver nat_salida más abajo).

Cadenas:
  entrada  (input, policy drop)   administración sólo desde la LAN.
  reenvio  (forward, policy drop) LAN → WAN válidas; la LAN no llega a los
                                  teléfonos (wan_gws); nada entra desde WAN.
  marcar   (prerouting mangle)    conexión nueva de la LAN → elegir_wan_rt
                                  (UDP en tiempo real) o elegir_wan (el
                                  resto); la marca se guarda en conntrack
                                  (afinidad).
  marcar_salida (output route)    lo mismo para el tráfico del propio router
                                  (DNS hacia fuera, actualizaciones). Los
                                  pings de comprobación ya llevan su marca.
  clamp_mss (forward mangle)      ajusta el MSS hacia las WAN (PPPoE/tethering
                                  con MTU reducida: sin esto algunos TCP se
                                  cuelgan en vez de fragmentar).
  elegir_wan                      la reescribe routerd según las WAN vivas
                                  (mapa de pesos: fase 4, A).
  elegir_wan_rt                   la reescribe routerd con la WAN de menor
                                  latencia, para UDP en tiempo real —voz,
                                  vídeo, juego— salvo DNS (53) y QUIC (443),
                                  que van por el reparto normal (fase 4, B).
  nat_salida (postrouting nat)    masquerade de TODO lo que sale por una WAN,
                                  sea de la LAN o del propio router. Antes el
                                  masquerade sólo miraba `ip saddr {red}`: el
                                  tráfico del propio router (que la tabla main
                                  no reescribe) salía sin enmascarar si la WAN
                                  elegida por marcar_salida no era la de la
                                  ruta por defecto (C1). Al vivir en `inet
                                  router` y mirar sólo la interfaz de salida,
                                  cubre ambos orígenes.
  redirigir_dns (prerouting nat)  bloqueo.forzar_dns: lo que entra por la LAN
                                  con destino udp/tcp:53 que no sea YA el
                                  propio router se redirige (REDIRECT) al
                                  dnsmasq local — así un equipo que intente
                                  saltarse el bloqueo poniendo 8.8.8.8 a mano
                                  sigue resolviendo contra el router. Prioridad
                                  "dstnat" (-100): nftables la ejecuta DESPUÉS
                                  de "marcar" (mangle, -150) dentro del mismo
                                  hook prerouting, pero no hay conflicto: el
                                  destino ya cambia a local ANTES de que se
                                  decida la ruta, y la tabla "local" (prioridad
                                  0 de `ip rule`) siempre gana a las reglas
                                  propias de este programa (900-1199), así que
                                  la marca que "marcar" ya hubiera puesto (con
                                  el destino original, antes del REDIRECT) no
                                  llega a influir en nada.
  (en "reenvio")                  bloqueo.bloquear_doh: además del bloqueo por
                                  nombre de dominio (lista hagezi_doh, ver
                                  router_bloqueo.py), se corta DoT de verdad:
                                  LAN → WAN a tcp/udp 853 se rechaza (DoH va
                                  por 443, normal, no se puede diferenciar por
                                  puerto — de eso se encarga la lista de
                                  dominios). Las líneas se insertan ANTES del
                                  accept genérico LAN→WAN de "reenvio", nunca
                                  después (si no, ese accept ya habría dejado
                                  pasar la conexión).
  contabilidad_disp (forward      Contabilidad de tráfico por dispositivo LAN
    filter + 10, policy accept)   (router_estadisticas.py) — cadena base
                                  APARTE, 10 unidades DESPUÉS de "reenvio" en
                                  el MISMO hook: sólo ve tráfico que
                                  "reenvio" ya aceptó de verdad (si "reenvio"
                                  dice drop, el paquete nunca llega aquí —
                                  ver la nota larga más abajo).

Contabilidad de tráfico por dispositivo LAN (router_estadisticas.py, fase de
estadísticas del panel): dos sets dinámicos `disp_sube`/`disp_baja`
(IPv4, con un contador por elemento), alimentados con `update` en una
cadena base APARTE (`contabilidad_disp`, ver tabla de cadenas arriba) —
BAJA10 (revisión Opus): registrada en el MISMO hook "forward" que
"reenvio" pero con prioridad "filter + 10" (10 unidades DESPUÉS). Varias
cadenas base en un mismo hook se recorren TODAS en orden de prioridad para
cada paquete, pero si una de prioridad menor ya dijo "drop", el recorrido
del hook entero se para ahí — así, poniendo la contabilidad DESPUÉS de
"reenvio", sólo cuenta tráfico que "reenvio" aceptó de verdad (ni lo que
iba a `wan_gws`, ni `ct state invalid`, ni el DoT bloqueado por
`bloquear_doh`), sin tener que repetir ninguna de esas condiciones aquí.
Un diseño anterior ponía estas dos líneas al PRINCIPIO de la propia
"reenvio" (antes incluso de "ct state established,related accept", para
no perderse el tráfico de una conexión ya abierta) — funcionaba, pero
también contaba paquetes que esa misma cadena acababa descartando más
abajo; con una cadena de prioridad mayor se cuenta EXACTAMENTE lo
aceptado, sin ese matiz. `update` sigue sin ser un veredicto (no acepta/
descarta/marca nada), así que esto no cambia en nada el filtrado ni las
marcas de balanceo de "reenvio"/"marcar".

  `update @disp_sube { ip saddr counter }`  — paquetes que ENTRAN por la LAN
    (iifname LAN, ip saddr en la red LAN): bytes de SUBIDA del dispositivo.
  `update @disp_baja { ip daddr counter }`  — paquetes que SALEN hacia la LAN
    (oifname LAN, ip daddr en la red LAN): bytes de BAJADA del dispositivo.

Por qué son `set` con `counter` en la EXPRESIÓN del `update`, y NO un `map`
`type ipv4_addr : counter` (el primer diseño que se probó aquí): un `map`
así declarado pasa `nft -c` sin ningún error — el analizador sintáctico lo
acepta perfectamente — pero el KERNEL lo rechaza al cargarlo de verdad:
"Error: Could not process rule: Operation not supported" al instalar la
tabla, y el propio `update` falla con "No such file or directory". Esto NO
lo detecta `nft -c` (que sólo analiza sintaxis + hace un chequeo de caché,
sin instalar nada) — se descubrió instalando la tabla de verdad en un netns
con root (Debian 13, nftables 1.1.3), que es la única validación que de
verdad prueba esto; **`nft -c` es necesario pero NO suficiente para esta
clase de construcción** — ver la prueba de extremo a extremo con root en
`pruebas/netns_multiwan.sh` (paso 17), que es la que de verdad lo confirma
instalado y con contadores reales, no sólo con sintaxis válida.

Lo que SÍ carga y cuenta de verdad (comprobado, con contadores reales tras
tráfico real): declarar el `set` con su tipo normal, SIN concatenar
`counter` en el `type`, y poner `counter` como palabra suelta dentro de la
expresión del `update` — nftables adjunta ahí un objeto con estado
(idéntico mecanismo que el statement `counter` en una regla normal, pero
aquí ligado al elemento del set en vez de a la regla) sin que el propio
`set` necesite declarar ese tipo de valor:

  set disp_sube { type ipv4_addr; flags dynamic, timeout; timeout 1d; size 4096; }
  update @disp_sube { ip saddr counter }

Se leen con `nft -j list set inet router disp_sube`/`disp_baja` (son
`set`, no `map` — al final SÍ es "list set", la petición original tenía
razón en la forma, sólo hacía falta encontrar la sintaxis de `update` que
el kernel admite de verdad).

`flags dynamic, timeout; timeout 1d; size 4096`: igual que cualquier otro
set alimentado desde la ruta de paquetes (ver SET STATEMENT del manual de
`nft`) — `dynamic` porque se añade desde una regla, `timeout` + `size`
obligatorios por lo mismo (evitan que crezca sin límite). El contador de
cada IP se PIERDE cuando el elemento expira (pasado `timeout` sin tráfico
nuevo que lo refresque: al reaparecer se crea de cero) y también cada vez
que routerd reinstala la tabla entera (todo `destroy table inet router` +
recrear, que es como se aplica siempre un cambio de `router.json`) —
router_estadisticas.py trata ambos casos igual que un reinicio de los
contadores de una interfaz (delta negativo o IP desaparecida → se descarta
esa muestra y se vuelve a tomar como línea base, nunca un delta negativo
"real").
"""
import ipaddress
import re

RE_IF = re.compile(r'^[a-zA-Z0-9_.-]{1,15}$')
# Defensa en profundidad: las ids de reglas/grupos del firewall se generan
# como r_+8 hex / g_+8 hex (nunca por el panel). Cualquier otra grafía se
# rechaza ANTES de interpolarla en el texto .nft.
RE_ID_REGLA = re.compile(r'^r_[0-9a-f]{8}$')
RE_ID_GRUPO = re.compile(r'^g_[0-9a-f]{8}$')
RE_MAC_NFT = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')


def _if(nombre):
    if not RE_IF.match(nombre):
        raise ValueError('nombre de interfaz no válido: %r' % nombre)
    return '"%s"' % nombre


def _mac_nft(v):
    """Valida una MAC antes de interpolarla en el .nft (sólo minúsculas,
    formato aa:bb:cc:dd:ee:ff — sin comillas, sin caracteres raros)."""
    mac = str(v).strip().lower().replace('-', ':')
    if not RE_MAC_NFT.fullmatch(mac):
        raise ValueError('MAC no válida para nft: %r' % v)
    return mac


def _ipv4_nft(v):
    try:
        ip = ipaddress.IPv4Address(str(v))
    except (ipaddress.AddressValueError, ValueError):
        raise ValueError('IPv4 no válida para nft: %r' % v)
    return str(ip)


def _cidr_nft(v):
    try:
        red = ipaddress.ip_network(str(v), strict=True)
    except (ValueError, TypeError):
        raise ValueError('red CIDR no válida para nft: %r' % v)
    if not isinstance(red, ipaddress.IPv4Network):
        raise ValueError('sólo se admite IPv4 en el firewall: %r' % v)
    return str(red)


def _puerto_nft(v):
    try:
        n = int(v)
    except (ValueError, TypeError):
        raise ValueError('puerto no válido: %r' % v)
    if not 1 <= n <= 65535:
        raise ValueError('puerto fuera de rango (1-65535): %r' % v)
    return n


def _id_regla_nft(v):
    if not RE_ID_REGLA.fullmatch(str(v)):
        raise ValueError('id de regla no válida para nft: %r' % v)
    return str(v)


def _id_grupo_nft(v):
    if not RE_ID_GRUPO.fullmatch(str(v)):
        raise ValueError('id de grupo no válida para nft: %r' % v)
    return str(v)


# ─────────────────── firewall con reglas propias (plan FIREWALL_PLAN.md) ───────────────────

def _generar_sets_grupos(firewall):
    """Genera los `set` de cada grupo (uno por grupo, tipo ether_addr o
    ipv4_addr, flags vacíos — estáticos, poblados en la misma transacción).
    Valida TODO en defensa en profundidad: ninguna cadena sin validar llega
    al texto .nft."""
    lineas = []
    for g in firewall.get('grupos') or []:
        gid = _id_grupo_nft(g.get('id'))
        tipo = g.get('tipo')
        if tipo == 'mac':
            tipo_nft = 'ether_addr'
            miembros = [_mac_nft(m) for m in (g.get('miembros') or [])]
        elif tipo == 'ip':
            tipo_nft = 'ipv4_addr'
            miembros = [_ipv4_nft(m) for m in (g.get('miembros') or [])]
        else:
            raise ValueError('tipo de grupo no válido: %r' % tipo)
        linea = '  set grp_%s {\n    type %s\n' % (gid, tipo_nft)
        if miembros:
            linea += '    elements = { %s }\n' % ', '.join(miembros)
        linea += '  }'
        lineas.append(linea)
    return '\n'.join(lineas)


def _match_origen(origen, grupos_por_id):
    """Construye el match de origen nft. Devuelve una cadena vacía para
    «cualquiera». Valida MAC/IPv4/CIDR/id de grupo."""
    tipo = origen.get('tipo')
    if tipo == 'cualquiera':
        return ''
    if tipo == 'mac':
        return 'ether saddr %s' % _mac_nft(origen.get('valor'))
    if tipo == 'ip':
        return 'ip saddr %s' % _ipv4_nft(origen.get('valor'))
    if tipo == 'red':
        return 'ip saddr %s' % _cidr_nft(origen.get('valor'))
    if tipo == 'grupo':
        gid = _id_grupo_nft(origen.get('valor'))
        g = grupos_por_id.get(gid)
        if g is None:
            raise ValueError('grupo de origen desconocido: %s' % gid)
        if g.get('tipo') == 'mac':
            return 'ether saddr @grp_%s' % gid
        return 'ip saddr @grp_%s' % gid
    raise ValueError('tipo de origen no válido: %r' % tipo)


def _match_destino(destino, grupos_por_id):
    """Construye el match de destino nft (sin MAC: un mac sólo tiene sentido
    como origen). Valida IPv4/CIDR/id de grupo."""
    tipo = destino.get('tipo')
    if tipo == 'cualquiera':
        return ''
    if tipo == 'ip':
        return 'ip daddr %s' % _ipv4_nft(destino.get('valor'))
    if tipo == 'red':
        return 'ip daddr %s' % _cidr_nft(destino.get('valor'))
    if tipo == 'grupo':
        gid = _id_grupo_nft(destino.get('valor'))
        g = grupos_por_id.get(gid)
        if g is None:
            raise ValueError('grupo de destino desconocido: %s' % gid)
        if g.get('tipo') != 'ip':
            raise ValueError('el destino con grupo exige un grupo tipo ip: %s' % gid)
        return 'ip daddr @grp_%s' % gid
    raise ValueError('tipo de destino no válido: %r' % tipo)


def _match_protocolo_y_puertos(regla, proto_forzado=None):
    """Construye el match de protocolo y puertos. Los puertos sólo aplican a
    tcp/udp/tcp_udp (y son de destino). Devuelve una lista de trozos.
    `proto_forzado` sustituye al protocolo de la regla: lo usa «rechazar»
    con tcp_udp/cualquiera para generar una línea por protocolo concreto
    (HIGH-2: con `meta l4proto { tcp, udp }` junto a `reject with tcp reset`
    nft responde "you cannot use tcp reset with this protocol")."""
    trozos = []
    proto = proto_forzado or regla.get('protocolo')
    puertos = regla.get('puertos') or []
    if proto == 'tcp':
        trozos.append('meta l4proto tcp')
    elif proto == 'udp':
        trozos.append('meta l4proto udp')
    elif proto == 'tcp_udp':
        trozos.append('meta l4proto { tcp, udp }')
    elif proto == 'icmp':
        # HIGH-1: el nombre en /etc/protocols es «icmp»; «ipv4-icmp» no
        # existe y nft -c lo rechaza ("Could not resolve protocol name").
        trozos.append('meta l4proto icmp')
    elif proto == 'cualquiera':
        pass
    else:
        raise ValueError('protocolo no válido: %r' % proto)
    if puertos:
        if proto not in ('tcp', 'udp', 'tcp_udp'):
            raise ValueError('los puertos sólo aplican a tcp/udp/tcp_udp')
        partes = []
        for p in puertos:
            d = _puerto_nft(p.get('desde'))
            h = _puerto_nft(p.get('hasta'))
            if d > h:
                raise ValueError('puerto desde > hasta: %r' % p)
            partes.append(str(d) if d == h else '%d-%d' % (d, h))
        if proto == 'tcp':
            trozos.append('tcp dport { %s }' % ', '.join(partes))
        elif proto == 'udp':
            trozos.append('udp dport { %s }' % ', '.join(partes))
        else:
            trozos.append('th dport { %s }' % ', '.join(partes))
    return trozos


def _veredicto_rechazar(proto):
    """Devuelve (lista_de_pares) para la acción «rechazar»: para TCP se usa
    `reject with tcp reset` (respuesta inmediata, como hace entrada con la
    LAN) y para el resto `reject with icmpx admin-prohibited`. Con protocolo
    tcp_udp o cualquiera hacen falta DOS líneas (una por familia), igual que
    el patrón de entrada — cada línea lleva el mismo comment para poder
    localizar la regla."""
    if proto == 'tcp':
        return [(None, 'reject with tcp reset')]
    if proto == 'udp':
        return [(None, 'reject with icmpx admin-prohibited')]
    if proto == 'icmp':
        return [(None, 'reject with icmpx admin-prohibited')]
    if proto == 'tcp_udp':
        return [('tcp', 'reject with tcp reset'),
                ('udp', 'reject with icmpx admin-prohibited')]
    if proto == 'cualquiera':
        return [('tcp', 'reject with tcp reset'),
                (None, 'reject with icmpx admin-prohibited')]
    raise ValueError('protocolo no válido para rechazar: %r' % proto)


def _lineas_regla(regla, grupos_por_id, LAN, red_lan):
    """Genera las líneas nft de UNA regla de usuario dentro de reenvio.
    Devuelve una lista de cadenas (1 línea normalmente; 2 para rechazar con
    protocolo mixto). Validación completa: ninguna cadena sin validar llega
    al texto .nft. `red_lan` es la CIDR de la LAN (str) — la usa «permitir»
    para no saltarse las condiciones del accept genérico (MEDIUM-1)."""
    rid = _id_regla_nft(regla.get('id'))
    if not regla.get('habilitada', True):
        return []
    accion = regla.get('accion')
    if accion not in ('permitir', 'bloquear', 'rechazar'):
        raise ValueError('acción no válida: %r' % accion)
    partes_base = ['iifname %s' % LAN]
    m_origen = _match_origen(regla.get('origen') or {'tipo': 'cualquiera'}, grupos_por_id)
    if m_origen:
        partes_base.append(m_origen)
    m_destino = _match_destino(regla.get('destino') or {'tipo': 'cualquiera'}, grupos_por_id)
    if m_destino:
        partes_base.append(m_destino)
    # MEDIUM-1: «permitir» no debe saltarse las condiciones del accept
    # genérico LAN→WAN (ip saddr {red} oifname @wan_ifs): sin ellas, un
    # permitir amplio deja pasar a interfaces que no son WAN vivas, sin NAT
    # y con orígenes falsificados. Se añaden SÓLO a la acción permitir.
    if accion == 'permitir':
        partes_base.append('ip saddr %s' % _cidr_nft(red_lan))
        partes_base.append('oifname @wan_ifs')
    # `limit` es una CONDICIÓN de la regla, no un modificador del log: puesto
    # en la misma línea que el veredicto, al pasar de 5/minuto la regla dejaría
    # de casar y el paquete caería en el accept genérico LAN→WAN (un bloqueo
    # con registro filtraría tráfico). Por eso el registro va en su PROPIA
    # línea, sin veredicto, y la línea con el veredicto no lleva `limit`.
    registro = bool(regla.get('registrar'))
    comentario = ' comment "fw:%s"' % rid
    if accion == 'permitir':
        veredictos = [(None, 'accept')]
    elif accion == 'bloquear':
        veredictos = [(None, 'drop')]
    else:
        veredictos = _veredicto_rechazar(regla.get('protocolo'))
    lineas = []
    for proto_extra, veredicto in veredictos:
        # HIGH-2: para cada línea se reconstruye el match de protocolo/puertos
        # con el protocolo CONCRETO de esa línea (proto_forzado), sustituyendo
        # el conjunto { tcp, udp } por tcp o udp y usando tcp dport/udp dport
        # en lugar de th dport — nft rechaza «reject with tcp reset» si queda
        # una condición de protocolo que no es tcp.
        trozos = list(partes_base)
        trozos.extend(_match_protocolo_y_puertos(regla, proto_forzado=proto_extra))
        if registro:
            lineas.append('    %s limit rate 5/minute log prefix "fw-%s " level info' % (' '.join(trozos), rid))
        lineas.append('    %s counter %s%s' % (' '.join(trozos), veredicto, comentario))
    return lineas


def _generar_reglas_usuario(firewall, LAN, red_lan):
    """Genera las líneas de las reglas del usuario dentro de reenvio, en el
    orden de la lista (primera que casa gana). Sólo reglas habilitadas."""
    grupos = firewall.get('grupos') or []
    grupos_por_id = {_id_grupo_nft(g.get('id')): g for g in grupos}
    lineas = []
    for regla in firewall.get('reglas') or []:
        lineas.extend(_lineas_regla(regla, grupos_por_id, LAN, red_lan))
    return '\n'.join(lineas)


def generar(cfg):
    lan = cfg['lan']
    LAN = _if(lan['interfaz'])
    red = ipaddress.ip_network(lan['red'])
    ip_router = ipaddress.IPv4Address(lan['ip'])
    extra = [_if(i) for i in cfg.get('admin_extra_interfaces', [])]
    admin_extra = ''
    if extra:
        admin_extra = ('    # Acceso administrativo temporal (migración)\n'
                       '    iifname { %s } tcp dport { 22, 80, 443 } accept\n' % ', '.join(extra))
    bloqueo = cfg.get('bloqueo') or {}
    doh_extra = ''
    if bloqueo.get('bloquear_doh', True):
        doh_extra = (f'    # bloqueo.bloquear_doh: corta DoT (853) desde la LAN hacia las WAN.\n'
                     f'    iifname {LAN} ip saddr {red} tcp dport 853 reject with tcp reset\n'
                     f'    iifname {LAN} ip saddr {red} udp dport 853 reject with icmpx admin-prohibited\n')
    # Firewall con reglas propias (FIREWALL_PLAN.md): sets de grupos y reglas
    # de usuario dentro de reenvio, después de established/invalid/wan_gws/DoT
    # y antes del accept genérico LAN→WAN. Validación en defensa en
    # profundidad: nada sin validar llega al texto .nft.
    firewall = cfg.get('firewall') or {}
    sets_grupos = _generar_sets_grupos(firewall)
    reglas_usuario = _generar_reglas_usuario(firewall, LAN, str(red))
    if reglas_usuario:
        reglas_usuario = reglas_usuario + '\n'
    redirigir_dns = ''
    if bloqueo.get('forzar_dns', True):
        redirigir_dns = f'''
  # bloqueo.forzar_dns: cualquier DNS que entre por la LAN y no vaya ya al
  # router se redirige a dnsmasq — ver nota "redirigir_dns" en la cabecera.
  chain redirigir_dns {{
    type nat hook prerouting priority dstnat; policy accept;
    # BAJA10: ip daddr/redirect son literales IPv4 — explícito con "meta
    # nfproto ipv4" (la tabla es "inet", dual-stack) para que nunca se
    # intente evaluar esta cadena sobre un paquete IPv6 (dnsmasq en la LAN
    # sólo sirve IPv4 hoy; sin esto nft podría comportarse de forma rara
    # ante tráfico v6 inesperado).
    meta nfproto ipv4
    iifname != {LAN} return
    ip daddr {ip_router} return
    udp dport 53 redirect to :53
    tcp dport 53 redirect to :53
  }}
'''
    return f'''#!/usr/sbin/nft -f
# Router de casa — generado por routerd desde /etc/router/router.json.
# NO editar a mano: se regenera. Sólo toca las tablas del router.
destroy table inet router
destroy table ip router_nat

table inet router {{
  # Interfaces WAN vivas y gateways de los teléfonos (los mantiene routerd).
  set wan_ifs {{ type ifname; }}
  set wan_gws {{ type ipv4_addr; }}

  # Contabilidad de tráfico por dispositivo LAN (router_estadisticas.py) —
  # ver nota larga en la cabecera del módulo: el contador se añade en la
  # EXPRESIÓN del "update" ("ip saddr counter"), nunca en el "type" del set
  # (un `map type ipv4_addr : counter` pasa `nft -c` pero el KERNEL lo
  # rechaza al cargar: "Operation not supported" — comprobado en un netns
  # real con root, no sólo con el analizador sintáctico). Se leen con
  # `nft -j list set inet router disp_sube`/`disp_baja`.
  set disp_sube {{
    type ipv4_addr
    flags dynamic, timeout
    timeout 1d
    size 4096
  }}
  set disp_baja {{
    type ipv4_addr
    flags dynamic, timeout
    timeout 1d
    size 4096
  }}
{sets_grupos}

  # Reparto de conexiones nuevas entre WAN (lo reescribe routerd).
  chain elegir_wan {{
    meta mark set 0
  }}

  # WAN de menor latencia, para el tráfico UDP en tiempo real (fase 4, B;
  # lo reescribe routerd junto con elegir_wan).
  chain elegir_wan_rt {{
    meta mark set 0
  }}

  chain entrada {{
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    # ICMP útil (diagnóstico y PMTU), limitado
    ip protocol icmp icmp type {{ echo-request, destination-unreachable, time-exceeded, parameter-problem }} limit rate 20/second accept
    meta l4proto ipv6-icmp accept
    # Respuestas DHCP de los teléfonos a NetworkManager: sólo desde las WAN,
    # nunca desde la LAN (ahí el DHCP lo da dnsmasq, no un servidor externo).
    iifname != {LAN} udp sport 67 udp dport 68 accept
    # Servicios para la LAN: DNS y DHCP
    iifname {LAN} udp dport {{ 53, 67 }} accept
    iifname {LAN} tcp dport 53 accept
    # Administración (SSH y panel HTTP→HTTPS) SÓLO desde la LAN
    iifname {LAN} ip saddr {red} tcp dport {{ 22, 80, 443 }} accept
{admin_extra}    # Desde la LAN, lo no permitido se RECHAZA (respuesta inmediata): un
    # descarte silencioso deja al navegador colgado hasta agotar el tiempo.
    iifname {LAN} ip saddr {red} meta l4proto tcp reject with tcp reset
    iifname {LAN} ip saddr {red} reject with icmpx admin-prohibited
    # Todo lo demás (incluido cualquier intento desde las WAN) se descarta
    limit rate 5/minute log prefix "router-entrada-drop " level info
    counter drop
  }}

  chain reenvio {{
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    # La LAN no administra los teléfonos ni sus redes
    iifname {LAN} ip daddr @wan_gws drop
{doh_extra}{reglas_usuario}    # LAN → Internet por las WAN válidas
    iifname {LAN} ip saddr {red} oifname @wan_ifs accept
    limit rate 5/minute log prefix "router-reenvio-drop " level info
    counter drop
  }}

  # Contabilidad de tráfico por dispositivo LAN (router_estadisticas.py) —
  # ver la nota larga en la cabecera del módulo. BAJA10 (revisión Opus):
  # cadena base APARTE, con su PROPIA prioridad "filter + 10" (10 unidades
  # DESPUÉS de "reenvio", que está en la "filter" de siempre, 0) — varias
  # cadenas base en el MISMO hook se recorren todas en orden de prioridad,
  # pero si una de prioridad menor (aquí, "reenvio") ya dijo "drop", el
  # paquete NUNCA llega a las de prioridad mayor (ahí se para el recorrido
  # del hook entero) — así esta cadena sólo ve tráfico que "reenvio" YA
  # aceptó de verdad (ni los paquetes hacia wan_gws, ni los de estado
  # invalid, ni el DoT bloqueado por bloquear_doh cuentan aquí), sin tener
  # que duplicar ninguna de esas condiciones. `policy accept`: esta cadena
  # nunca decide nada por sí misma, sólo cuenta.
  chain contabilidad_disp {{
    type filter hook forward priority filter + 10; policy accept;
    iifname {LAN} ip saddr {red} update @disp_sube {{ ip saddr counter }}
    oifname {LAN} ip daddr {red} update @disp_baja {{ ip daddr counter }}
  }}

  chain marcar {{
    type filter hook prerouting priority mangle; policy accept;
    iifname != {LAN} return
    # No balancear lo que va a una IP local, broadcast o multicast: eso no
    # sale por ninguna WAN y balancearlo sólo le pone una marca que luego
    # nadie necesita (y que podría liarse con el NAT de salida).
    fib daddr type {{ local, broadcast, multicast }} return
    ip daddr {red} return
    # B: voz/vídeo/juego son UDP y sufren mucho si caen en la línea con más
    # latencia; una conexión NUEVA de UDP —salvo DNS (53, va al propio
    # router) y QUIC (443, es navegación web normal)— se manda a la WAN de
    # menor latencia en vez de al reparto aleatorio. La afinidad de
    # conntrack de siempre hace el resto: una llamada ya en curso no cambia
    # de WAN aunque elegir_wan_rt cambie de destino entre medias.
    #
    # H1: con `jump` se vuelve a esta cadena después de elegir_wan_rt, y la
    # siguiente línea («ct state new jump elegir_wan») sigue viendo
    # ct state new == true: entraba también en elegir_wan y pisaba la marca
    # ya puesta por elegir_wan_rt (la WAN rápida se quedaba sin efecto). Con
    # `goto` la cadena destino NO vuelve aquí: al acabar esa cadena se
    # aplica directamente la política de la base (accept) con la marca ya
    # puesta, y la segunda línea ni se evalúa para ese paquete.
    ct state new udp dport != {{ 53, 443 }} goto elegir_wan_rt
    ct state new goto elegir_wan
    meta mark set ct mark
  }}

  chain marcar_salida {{
    type route hook output priority mangle; policy accept;
    # Los pings de comprobación ya salen con la marca de su WAN (-m)
    meta mark != 0 return
    ip daddr {{ 127.0.0.0/8, {red} }} return
    fib daddr type {{ local, broadcast, multicast }} return
    # B/H1: mismo criterio (y mismo arreglo de goto) que en marcar, para el
    # tráfico propio del router.
    ct state new udp dport != {{ 53, 443 }} goto elegir_wan_rt
    ct state new goto elegir_wan
    meta mark set ct mark
  }}

  chain clamp_mss {{
    type filter hook forward priority mangle; policy accept;
    # MTU reducida típica del tethering: sin esto hay TCP que se cuelga en
    # vez de fragmentar o pedir un MSS menor (C1).
    oifname @wan_ifs tcp flags syn tcp option maxseg size set rt mtu
  }}

  chain nat_salida {{
    type nat hook postrouting priority srcnat; policy accept;
    # Enmascara TODO lo que sale por una WAN (LAN y tráfico propio del
    # router): antes el NAT sólo miraba `ip saddr {red}` y el tráfico propio
    # —cuya IP origen la elige la tabla main, no esta tabla— salía sin
    # enmascarar si tocaba una WAN distinta de la de la ruta por defecto (C1).
    meta nfproto ipv4 oifname @wan_ifs masquerade
  }}
{redirigir_dns}}}
'''
