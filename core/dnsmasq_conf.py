# -*- coding: utf-8 -*-
"""Genera la configuración de dnsmasq de la LAN a partir de router.json.

Sólo valores ya validados (peticiones.py) llegan aquí; aun así cada línea se
construye a partir de tipos concretos (IPs parseadas, MAC normalizada) para
que nada de texto libre acabe dentro del fichero de dnsmasq.

dnsmasq escucha SOLO en la interfaz LAN (y en lo para el propio router):
`bind-dynamic` + `interface=` + `except-interface` de las WAN no hace falta
porque con `interface=` explícita no escucha en ninguna otra.
"""
import ipaddress
import re


RUTA_DNSMASQ_BLOQUEO = '/var/lib/router/bloqueo/dnsmasq-bloqueo.conf'
RUTA_LOG_DNS = '/var/log/router/dns.log'

# M1 (ronda 4): base del centinela "por generación" de router_bloqueo.py
# (debe coincidir EXACTAMENTE con router_bloqueo.CENTINELA_BASE/
# CENTINELA_IP_VIEJA — duplicado a propósito, como RUTA_DNSMASQ_BLOQUEO
# más abajo: dnsmasq_conf.py no importa router_bloqueo, se mantienen
# independientes). Esta línea vive aquí, en la LAN BASE, incondicional
# (nunca depende de si el bloqueo está habilitado): da una respuesta FIJA
# (127.0.0.9, nunca una IP real) para CUALQUIER nombre bajo esa base que
# no tenga ya un `server=` más específico en el servers-file del bloqueo
# — así una consulta por el centinela de una generación que dnsmasq TODAVÍA
# no ha cargado cae aquí (127.0.0.9 = "sigue la vieja"), mientras que la
# generación que SÍ está cargada tiene su propio `server=/g<hash>.../`
# (sin dirección = NXDOMAIN = "ya está la nueva"), más específico y que
# por tanto gana.
CENTINELA_BASE = 'bloqueo-centinela.router-casa.invalid'
CENTINELA_IP_VIEJA = '127.0.0.9'


def generar(cfg, log_queries_extra=True, desactivar_log=False):
    """`log_queries_extra`/`desactivar_log` son banderas de ENTORNO, no de
    `cfg` (H6: esta función sigue siendo pura — nada de tocar disco ni
    subprocess aquí): las decide el llamador (routerd).

    Revisión Opus (ronda 2, M2): `servers-file=` se referencia SIEMPRE,
    incondicionalmente — ya NO hay un "existe_bloqueo" que decida si se
    incluye o no. routerd GARANTIZA que ese fichero existe siempre (lo crea
    vacío si falta, antes de generar esta config — ver
    Router._asegurar_servers_file_bloqueo), así que esta función ya no
    necesita saberlo: `dnsmasq --test` nunca falla por un `servers-file=`
    ausente si routerd ha hecho bien su trabajo, y mantener aquí un flip
    condicional sólo añadía una superficie más donde poder desincronizarse.

    `desactivar_log` (M6, fail-open): si dnsmasq lleva varios arranques
    fallidos seguidos, routerd puede pedir una config SIN `log-queries`/
    `log-facility` — por si el problema fuera, precisamente, no poder
    escribir ese log (p. ej. /var/log/router con permisos raros)."""
    lan = cfg['lan']
    red = ipaddress.ip_network(lan['red'])
    ip_router = ipaddress.IPv4Address(lan['ip'])
    ini = ipaddress.IPv4Address(cfg['dhcp']['inicio'])
    fin = ipaddress.IPv4Address(cfg['dhcp']['fin'])
    assert ini in red and fin in red and ip_router in red
    lease = cfg['dhcp']['lease']
    dns = [str(ipaddress.IPv4Address(s)) for s in cfg['dns']]
    dominio = str(cfg.get('dominio') or 'home.arpa').lower()
    if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', dominio):
        raise ValueError('dominio no válido: %r' % dominio)

    lineas = [
        '# Generado por routerd — NO editar a mano (se reescribe desde el panel).',
        '# DHCP y DNS de la LAN de casa. Sólo escucha en la LAN y en lo.',
        'interface=%s' % lan['interfaz'],
        'interface=lo',
        'bind-dynamic',
        'no-dhcp-interface=lo',
        # El DNS del router: sin /etc/resolv.conf (lo gestiona NM y en la LAN
        # nueva apunta a sí mismo); reenvía a los servidores configurados.
        'no-resolv',
    ] + ['server=%s' % s for s in dns] + [
        'domain-needed',
        'bogus-priv',
        'cache-size=1000',
        # home.arpa (RFC 8375): el espacio reservado para redes domésticas
        # (home.arpa y cualquier *.arpa) se trata SIEMPRE como propio, de
        # forma incondicional — nunca se reenvía hacia fuera ni depende de
        # que el bloqueador DNS esté activo (revisión Opus, ronda 3,
        # BAJA3: antes vivía como entrada fija en
        # router_bloqueo.PROTEGIDOS_FIJOS, que era la capa equivocada —
        # esto es higiene general de DNS, no "un host con el que el router
        # habla"). No evita que el admin configure un dominio de casa que
        # sea literalmente "home.arpa" (sería un duplicado inocuo: dnsmasq
        # no se queja de un `local=` repetido).
        'local=/home.arpa/',
        # M1 (ronda 4): respuesta FIJA para el centinela "por generación"
        # del bloqueador (ver router_bloqueo.py y la nota de arriba) —
        # incondicional, independiente de si el bloqueo está habilitado.
        'address=/%s/%s' % (CENTINELA_BASE, CENTINELA_IP_VIEJA),
        # Dominio de la casa (router.json → "dominio"): los equipos se resuelven
        # como <nombre>.<dominio> y el router como router.<dominio>. Sólo
        # existe dentro de casa (no hay registros públicos con ese nombre).
        # No un TLD real como «casa» que un registro público podría llegar
        # a delegar (filtración/colisión de nombres) — por eso el defecto,
        # si no se configura nada, es el propio "home.arpa".
        'domain=%s' % dominio,
        'local=/%s/' % dominio,
        'host-record=router.%s,%s' % (dominio, ip_router),
        'expand-hosts',
        # DHCP
        'dhcp-authoritative',
        'dhcp-range=%s,%s,%s,%s,%s' % (lan['interfaz'], ini, fin, red.netmask, lease),
        'dhcp-option=option:router,%s' % ip_router,
        'dhcp-option=option:dns-server,%s' % ip_router,
        'dhcp-hostsfile=/etc/router/dhcp-reservas.conf',
        # Los equipos con reserva se resuelven por nombre SIEMPRE (no sólo
        # cuando ya pidieron IP): fichero de hosts que dnsmasq relee con HUP.
        'addn-hosts=/etc/router/hosts-reservas',
        'dhcp-leasefile=/var/lib/misc/dnsmasq.leases',
        'log-dhcp',
    ]
    if not desactivar_log:
        lineas += [
            # Bloqueador DNS (bloqueo): consultas para las estadísticas del
            # panel (dominio, cliente, si se resolvió o se bloqueó por
            # NXDOMAIN) — 'extra' añade el cliente y el resultado por
            # consulta cuando el dnsmasq instalado lo admite (>= 2.86); si
            # no, se cae a 'log-queries' simple (routerd lo detecta UNA vez,
            # nunca aquí). BAJA9: log-async=25 — hasta 25 líneas de log en
            # un búfer async, para que escribir el log nunca pueda retrasar
            # una respuesta DNS real.
            'log-queries=extra' if log_queries_extra else 'log-queries',
            'log-async=25',
            'log-facility=%s' % RUTA_LOG_DNS,
        ]
    # M2: el servers-file del bloqueador SIEMPRE se referencia, exista lo
    # que exista dentro (routerd garantiza que el fichero existe — vacío si
    # el bloqueo está deshabilitado, o si routerd ha entrado en fail-open
    # tras varios arranques fallidos de dnsmasq — ver
    # Router._asegurar_servers_file_bloqueo). Un `servers-file=` que no
    # exista hace fallar `dnsmasq --test` igual que un `conf-file=`
    # ausente; por eso NUNCA es routerd quien decide aquí si lo incluye o
    # no, sólo si el FICHERO tiene contenido o está vacío.
    lineas.append('servers-file=%s' % RUTA_DNSMASQ_BLOQUEO)
    reservas = ['# Reservas DHCP (generado por routerd): mac,ip,nombre']
    for r in cfg.get('reservas', []):
        mac = r['mac'].lower()
        ip = ipaddress.IPv4Address(r['ip'])
        assert ip in red
        reservas.append('%s,%s,%s' % (mac, ip, r['nombre']))
    return '\n'.join(lineas) + '\n', '\n'.join(reservas) + '\n'


def generar_hosts(cfg):
    """Fichero hosts (addn-hosts) con «ip nombre.dominio nombre» de cada reserva."""
    dominio = str(cfg.get('dominio') or 'home.arpa').lower()
    red = ipaddress.ip_network(cfg['lan']['red'])
    lineas = ['# Generado por routerd: nombres de los equipos con reserva DHCP']
    for r in cfg.get('reservas', []):
        ip = ipaddress.IPv4Address(r['ip'])
        assert ip in red
        lineas.append('%s %s.%s %s' % (ip, r['nombre'], dominio, r['nombre']))
    return '\n'.join(lineas) + '\n'
