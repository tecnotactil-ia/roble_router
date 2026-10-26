#!/usr/bin/env bash
# instalar.sh — instalación genérica de Roble Router en Debian 13 (root).
#
# Instala el núcleo (core/*.py), las unidades de systemd, el panel Flask y el
# nginx como proxy HTTPS, creando /etc/router/router.json desde tus respuestas.
# En fase "preparacion" routerd SÓLO observa: no cambia la red, así que
# instalarlo desde una sesión SSH no corta el acceso.
#
#   - Idempotente: lo puedes ejecutar dos veces (no pisa router.json si ya
#     existe, no duplica perfiles, no re-pregunta si pasas --si).
#   - --actualizar: sólo re-copia el código (core + panel) y reinicia los
#     servicios; no pregunta nada y no toca router.json ni nginx.
#   - La ACTIVACIÓN de verdad (la máquina pasa a ser el router de la LAN) es
#     un paso manual posterior: `sudo router-migrar --comprobar`, luego
#     `sudo systemctl start router-migracion` (ver el resumen del final).
#
# Uso:  sudo bash instalar.sh                    # interactivo
#       sudo bash instalar.sh --si               # todos los valores por defecto
#       sudo bash instalar.sh --forzar           # instala aunque no sea Debian 13
#       sudo bash instalar.sh --actualizar       # sólo código + reinicio de servicios
#       sudo bash instalar.sh --lan-if eth0 --lan-ip 192.168.50.1 \
#            --dhcp-inicio 192.168.50.100 --dhcp-fin 192.168.50.250 \
#            --dominio lan.home.arpa --wifi-if '' --wan-cable eth1 \
#            --admin admin --admin-clave-fichero /root/clave.txt
#
# Modo de la tarjeta Wi-Fi (--wifi-modo ninguno|ap|wan):
#   ninguno  la tarjeta Wi-Fi no se usa (defecto con --si; sólo WAN cableada).
#   wan      la tarjeta es CLIENTE de otra red Wi-Fi y sale a Internet por
#            ella (WAN Wi-Fi; equivalente a --wifi-if X).
#   ap       la tarjeta es PUNTO DE ACCESO para la LAN: los móviles y
#            portátiles de casa se conectan por Wi-Fi. La LAN pasa a ser el
#            puente NM «br-lan» (perfiles LAN-ROUTER + LAN-ROUTER-cable) y
#            hostapd levanta el AP dentro del puente con router-ap.service;
#            se ENCIENDE al activar (router-migrar), no en la instalación.
#            Requiere una tarjeta con modo AP (iw list → «Supported interface
#            modes» con "* AP") y sólo se usa 2,4 GHz (canales 1..13).
#
# Opciones del punto de acceso (la tarjeta se indica con --wifi-if y el
# puerto de cable de la LAN con --lan-if, igual que en los otros modos):
#       --ap-ssid S                 SSID del AP
#       --ap-clave-fichero fichero  clave WPA2: primera línea del fichero
#       --ap-pais ES                país (ISO 3166, defecto ES)
#       --ap-canal 6                canal 2,4 GHz, 1..13 (defecto 6)
#       --sin-cable-lan             modo SÓLO AP: el puente br-lan no lleva
#                                   puerto de cable (la LAN es sólo Wi-Fi)
#
# Ejemplo de AP (con puerto de cable en la LAN):  sudo bash instalar.sh \
#       --wifi-modo ap --ap-ssid CasaWiFi --ap-pais ES --ap-canal 6 \
#       --admin admin --admin-clave-fichero /root/clave.txt
#
# Compatibilidad: --wifi-if X sin --wifi-modo sigue significando «wan» (lo de
# siempre). Cambiar de modo en una instalación existente: repite la
# instalación pasando --wifi-modo (y las --ap-* si vas a «ap»): con fase
# «preparacion» se reescribe lo del modo y se recrean los perfiles NM; con
# fase «produccion» se aborta: ejecuta antes «sudo router-migrar --deshacer».
set -euo pipefail

BASE=$(cd "$(dirname "$0")" && pwd)
SI=0
FORZAR=0
ACTUALIZAR=0
LAN_IF=''
LAN_IP=''
DHCP_INICIO=''
DHCP_FIN=''
DOMINIO=''
WIFI_IF=''
WAN_CABLE=''
ADMIN=''
CLAVE_FICH=''
WIFI_MODO=''
WIFI_MODO_EXPLICITO=0
AP_IF=''
AP_SSID=''
AP_CLAVE_FICH=''
AP_PAIS='ES'
AP_CANAL=6
PUERTO_CABLE=''
SIN_CABLE_LAN=0
CLAVE_AP=''
HOSTAPD_HECHO=0

PAQUETES=(
    nftables dnsmasq network-manager nginx python3 python3-venv iproute2
    conntrack iputils-arping iputils-ping openssl adb logrotate dnsutils
    hostapd iw util-linux
)

nsay() { echo "instalar: $*"; }
morir() { echo "instalar: ERROR: $*" >&2; exit 1; }
avisar() { echo "instalar: AVISO: $*" >&2; }

# ───────────────────────── argumentos ─────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --si) SI=1 ;;
        --forzar) FORZAR=1 ;;
        --actualizar) ACTUALIZAR=1 ;;
        --lan-if) LAN_IF=${2:?}; shift ;;
        --lan-ip) LAN_IP=${2:?}; shift ;;
        --dhcp-inicio) DHCP_INICIO=${2:?}; shift ;;
        --dhcp-fin) DHCP_FIN=${2:?}; shift ;;
        --dominio) DOMINIO=${2:?}; shift ;;
        --wifi-if) WIFI_IF=${2?}; shift ;;
        --wan-cable) WAN_CABLE=${2?}; shift ;;
        --admin) ADMIN=${2:?}; shift ;;
        --admin-clave-fichero) CLAVE_FICH=${2:?}; shift ;;
        --wifi-modo) WIFI_MODO=${2:?}; WIFI_MODO_EXPLICITO=1; shift ;;
        --ap-ssid) AP_SSID=${2:?}; shift ;;
        --ap-clave-fichero) AP_CLAVE_FICH=${2:?}; shift ;;
        --ap-pais) AP_PAIS=${2:?}; shift ;;
        --ap-canal) AP_CANAL=${2:?}; shift ;;
        --sin-cable-lan) SIN_CABLE_LAN=1 ;;
        *) morir "opción desconocida: $1 (ver cabecera del script)" ;;
    esac
    shift
done

# ───────────────────────── requisitos básicos ─────────────────────────
[ "$(id -u)" = 0 ] || morir "hay que ejecutarlo como root (sudo)"

es_debian_13() {
    local version_id=''
    [ -r /etc/os-release ] && version_id=$(. /etc/os-release; echo "${VERSION_ID:-}")
    [ "$version_id" = 13 ]
}
if ! es_debian_13; then
    if [ "$FORZAR" = 1 ]; then
        avisar "esa máquina no es Debian 13 (o no se pudo saber): continúas por --forzar"
    else
        morir "esto está pensado para Debian 13 (VERSION_ID=13). Si el sistema es otro y quiere intentarlo, pasa --forzar sabiendo que no está probado ahí."
    fi
fi

[ -f "$BASE/core/routerd.py" ] && [ -f "$BASE/panel/wsgi.py" ] \
    || morir "no estoy en la raíz del repo (falta core/routerd.py o panel/wsgi.py en $BASE)"

# ───────────────────────── modo --actualizar ─────────────────────────
if [ "$ACTUALIZAR" = 1 ]; then
    nsay "modo --actualizar: sólo código (core + panel) y reinicio de servicios"
    install -d -m 0755 /usr/local/lib/router
    install -m 0755 -o root -g root "$BASE"/core/*.py /usr/local/lib/router/
    rm -f /usr/local/lib/router/acme_ionos.py   # versión privada: nunca se instala
    install -d -m 0755 /usr/local/sbin
    install -m 0755 -o root -g root "$BASE/core/router_migrar.py" /usr/local/sbin/router-migrar
    systemd_unidades_solo_codigo() {
        for unidad in "$BASE"/systemd/*.service "$BASE"/systemd/*.timer; do
            case "$(basename "$unidad")" in router-certbot.service|router-certbot.timer) continue ;; esac
            install -m 0644 -o root -g root "$unidad" /etc/systemd/system/
        done
    }
    systemd_unidades_solo_codigo
    systemctl daemon-reload
    for servicio in routerd router-panel router-estadisticas; do
        systemctl restart "$servicio"
    done
    nsay "actualización hecha (router.json, certificados y nginx NO se han tocado)."
    exit 0
fi

# ───────────────────────── utilidades Python (validaciones) ─────────────────────────
ip_valida() { python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }

red_de_24() {   # red /24 de una IP de router: 192.168.50.1 → 192.168.50.0
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1]+"/24", strict=False).network_address)' "$1"
}

# ───────────────────────── detección y preguntas ─────────────────────────
primer_cableada() {
    # primera interfaz física con enlace, descartando loopback, radio,
    # bridges y virtuales de contenedores
    for i in $(ip -o link show | awk -F': ' '{print $2}' | grep -v '@'); do
        case "$i" in lo|wl*|ww*|virbr*|docker*|br-*|veth*|tun*|tap*|tailscale*) continue ;; esac
        [ "$(cat "/sys/class/net/$i/carrier" 2>/dev/null)" = 1 ] && { echo "$i"; return 0; }
    done
    return 1
}

primera_wifi() {
    # primera interfaz con Wi-Fi (/sys/class/net/*/wireless), para el defecto
    # de la interfaz del punto de acceso
    local d i
    for d in /sys/class/net/*/wireless; do
        [ -e "$d" ] || continue
        i=${d%/wireless}
        echo "${i##*/}"
        return 0
    done
    return 1
}

preguntar() {   # preguntar <NOMBRE_VAR> <texto> <defecto> → imprime el valor
    local var=$1 texto=$2 defecto=$3 resp
    [ -n "${!var}" ] && { echo "${!var}"; return 0; }
    if [ "$SI" = 1 ] || [ ! -t 0 ]; then
        echo "$defecto"
        return 0
    fi
    read -r -p "$texto [$defecto]: " resp
    echo "${resp:-$defecto}"
}

contrasena_interactiva() {   # imprime la contraseña (≥12 chars, dos veces, sin eco)
    local clave1 clave2
    while :; do
        read -r -s -p "Contraseña del admin del panel (mínimo 12 caracteres): " clave1
        echo
        read -r -s -p "Repite la contraseña: " clave2
        echo
        if [ ${#clave1} -lt 12 ]; then
            echo "demasiado corta (mínimo 12 caracteres): otra vez."
            continue
        fi
        if [ "$clave1" != "$clave2" ]; then
            echo "no coinciden: otra vez."
            continue
        fi
        printf '%s' "$clave1"
        return 0
    done
}

contrasena_ap_interactiva() {   # imprime la clave WPA2 del AP (mínimo 8, dos veces, sin eco)
    local clave1 clave2
    while :; do
        read -r -s -p "Clave WPA2 del punto de acceso (mínimo 8 caracteres): " clave1
        echo
        read -r -s -p "Repite la clave: " clave2
        echo
        if [ ${#clave1} -lt 8 ]; then
            echo "demasiado corta (mínimo 8 caracteres): otra vez."
            continue
        fi
        if [ "$clave1" != "$clave2" ]; then
            echo "no coinciden: otra vez."
            continue
        fi
        printf '%s' "$clave1"
        return 0
    done
}

nsay "--- Configuración (ENTER acepta el valor por defecto) ---"
CANDIDATO_IF=$(primer_cableada || true)

# ¿Qué hace la tarjeta Wi-Fi? Compatibilidad: --wifi-if X sin --wifi-modo
# siempre ha significado «wan».
if [ -z "$WIFI_MODO" ] && [ -n "$WIFI_IF" ]; then
    WIFI_MODO='wan'
fi
WIFI_MODO=$(preguntar WIFI_MODO "¿Qué hace la tarjeta Wi-Fi? (ninguno / ap / wan)" "${WIFI_MODO:-ninguno}")
case "$WIFI_MODO" in
    ninguno|ap|wan) ;;
    *) morir "wifi-modo no válido: «$WIFI_MODO» (ninguno / ap / wan)" ;;
esac
if [ "$SIN_CABLE_LAN" = 1 ] && [ "$WIFI_MODO" != ap ]; then
    morir "--sin-cable-lan sólo tiene sentido con --wifi-modo ap"
fi

case "$WIFI_MODO" in
    wan)
        # La tarjeta Wi-Fi sale a Internet como CLIENTE de otra red (WAN Wi-Fi).
        nsay "modo Wi-Fi: wan (WAN Wi-Fi: cliente de otra red)."
        WIFI_IF=$(preguntar WIFI_IF "Interfaz Wi-Fi para WAN Wi-Fi opcional (vacía = no la uso)" "${WIFI_IF:-}")
        WIFI_IF=$(echo "$WIFI_IF" | head -n1)
        AP_IF=''
        ;;
    ap)
        # La tarjeta Wi-Fi es PUNTO DE ACCESO: los clientes de casa se
        # conectan por Wi-Fi a la LAN. La gestiona hostapd (router-ap.service),
        # NO NetworkManager: NM deja de manejarla y el AP se enciende al
        # ACTIVAR (router-migrar), no ahora.
        nsay "modo Wi-Fi: ap (punto de acceso)."
        # --wifi-if también vale para nombrar la tarjeta del AP.
        AP_IF=$(preguntar AP_IF "Interfaz Wi-Fi para el punto de acceso" "${AP_IF:-${WIFI_IF:-$(primera_wifi || true)}}")
        WIFI_IF=''
        AP_IF=$(echo "$AP_IF" | head -n1)
        [ -n "$AP_IF" ] || morir "no se detectó ninguna interfaz Wi-Fi (revísalo con «iw dev»)"
        [ -d "/sys/class/net/$AP_IF" ] || morir "la interfaz Wi-Fi «$AP_IF» no existe"
        AP_SSID=$(preguntar AP_SSID "SSID del punto de acceso" "${AP_SSID:-RobleRouter}")
        [ -n "$AP_SSID" ] || morir "el SSID del AP no puede estar vacío"
        AP_PAIS=$(preguntar AP_PAIS "País del AP (dos letras mayúsculas, ISO 3166)" "${AP_PAIS:-ES}")
        case "$AP_PAIS" in [A-Z][A-Z]) ;; *) morir "el país del AP deben ser DOS LETRAS MAYÚSCULAS: «$AP_PAIS»" ;; esac
        AP_CANAL=$(preguntar AP_CANAL "Canal Wi-Fi del AP (1..13, 2,4 GHz)" "${AP_CANAL:-6}")
        case "$AP_CANAL" in ''|*[!0-9]*) morir "el canal del AP debe ser un número del 1 al 13: «$AP_CANAL»" ;; esac
        [ "$AP_CANAL" -ge 1 ] && [ "$AP_CANAL" -le 13 ] || morir "el canal del AP debe estar entre 1 y 13"
        if [ -n "$AP_CLAVE_FICH" ]; then
            [ -r "$AP_CLAVE_FICH" ] || morir "no puedo leer --ap-clave-fichero $AP_CLAVE_FICH"
            CLAVE_AP=$(head -n1 "$AP_CLAVE_FICH")
        elif [ -t 0 ]; then
            nsay "La clave WPA2 del punto de acceso se pide dos veces, sin eco."
            CLAVE_AP=$(contrasena_ap_interactiva)
        else
            morir "sin terminal: usa --ap-clave-fichero para la clave del punto de acceso"
        fi
        [ ${#CLAVE_AP} -ge 8 ] || morir "la clave del punto de acceso debe tener al menos 8 caracteres"
        # Lo mismo que valida wifi_ap.py, pero ANTES de tocar nada: así un
        # dato malo no aborta la instalación a medias.
        printf '%s' "$CLAVE_AP" | LC_ALL=C grep -qxE '[ -~]{8,63}' \
            || morir "la clave del punto de acceso: entre 8 y 63 caracteres ASCII (sin tildes ni ñ)"
        [ "$(printf '%s' "$AP_SSID" | wc -c)" -le 32 ] || morir "el SSID ocupa más de 32 bytes"
        ;;
    ninguno)
        nsay "modo Wi-Fi: ninguno (la tarjeta Wi-Fi no se usa)."
        WIFI_IF=''
        AP_IF=''
        ;;
esac

case "$WIFI_MODO" in
    ap)
        # En modo AP la LAN es el puente br-lan: lo que se pregunta es el
        # puerto de CABLE esclavo del puente (o nada, con --sin-cable-lan).
        # --lan-if, si se pasó, es ese puerto de cable.
        LAN_IF_ARG=$LAN_IF
        LAN_IF='br-lan'
        if [ "$SIN_CABLE_LAN" != 1 ]; then
            PUERTO_CABLE=$(preguntar PUERTO_CABLE "Puerto de CABLE de la LAN (esclavo del puente br-lan)" "${PUERTO_CABLE:-${LAN_IF_ARG:-$CANDIDATO_IF}}")
            PUERTO_CABLE=$(echo "$PUERTO_CABLE" | head -n1)
            [ -n "$PUERTO_CABLE" ] || morir "sin puerto de cable para la LAN (usa --sin-cable-lan si la LAN es sólo Wi-Fi)"
            [ -d "/sys/class/net/$PUERTO_CABLE" ] || morir "el puerto de cable «$PUERTO_CABLE» no existe (usa --sin-cable-lan si la LAN es sólo Wi-Fi)"
        fi
        ;;
    *)
        LAN_IF=$(preguntar LAN_IF "Interfaz de la LAN" "${LAN_IF:-$CANDIDATO_IF}")
        LAN_IF=$(echo "$LAN_IF" | head -n1)
        [ -n "$LAN_IF" ] || morir "sin interfaz para la LAN (--lan-if)"
        [ -d "/sys/class/net/$LAN_IF" ] || morir "la interfaz «$LAN_IF» no existe (--lan-if)"
        PUERTO_CABLE=''
        ;;
esac

# Interfaz FÍSICA de la LAN (para mensajería y limpieza de conexiones): el
# puerto de cable en modo AP, vacío en sólo-AP; en los demás modos es LAN_IF.
IF_LAN_FISICA=${PUERTO_CABLE:-$LAN_IF}
if [ "$WIFI_MODO" = ap ] && [ -z "$PUERTO_CABLE" ]; then
    IF_LAN_FISICA=''
fi

LAN_IP=$(preguntar LAN_IP "IP del router en la LAN" "${LAN_IP:-192.168.50.1}")
ip_valida "$LAN_IP" || morir "$LAN_IP no es una IP IPv4 válida"
LAN_RED=$(red_de_24 "$LAN_IP")        # 192.168.50.0
LAN_RED_CON_PREFIJO="$LAN_RED/24"
DHCP_INICIO=$(preguntar DHCP_INICIO "Inicio del rango DHCP" "${DHCP_INICIO:-$(echo "$LAN_IP" | cut -d. -f1-3).100}")
DHCP_FIN=$(preguntar DHCP_FIN "Fin del rango DHCP" "${DHCP_FIN:-$(echo "$LAN_IP" | cut -d. -f1-3).250}")
ip_valida "$DHCP_INICIO" || morir "inicio DHCP no válido"
ip_valida "$DHCP_FIN" || morir "fin DHCP no válido"
DOMINIO=$(preguntar DOMINIO "Dominio DNS local" "${DOMINIO:-lan.home.arpa}")
WAN_CABLE=$(preguntar WAN_CABLE "Interfaces cableadas que son salida a Internet (módem, fibra; separadas por comas, vacía = ninguna)" "${WAN_CABLE:-}")
if [ "$WIFI_MODO" = ap ]; then
    [ "$AP_IF" != "$LAN_IF" ] || morir "la interfaz del AP no puede ser el puente de la LAN"
    if [ -n "$PUERTO_CABLE" ]; then
        [ "$AP_IF" != "$PUERTO_CABLE" ] || morir "la interfaz del AP no puede ser el puerto de cable de la LAN"
    fi
fi
for i in ${WAN_CABLE//,/ }; do
    [ "$i" != "$LAN_IF" ] || morir "la interfaz de la LAN ($LAN_IF) no puede ser también WAN"
    if [ "$WIFI_MODO" = ap ]; then
        [ "$i" != "$AP_IF" ] || morir "la interfaz del AP ($AP_IF) no puede ser también WAN"
    fi
    [ -d "/sys/class/net/$i" ] || avisar "la interfaz WAN «$i» no existe ahora mismo (se usará cuando aparezca)"
done
ADMIN=$(preguntar ADMIN "Usuario admin del panel" "${ADMIN:-admin}")
case "$ADMIN" in *[!a-zA-Z0-9_.-]*) morir "el usuario admin sólo puede llevar letras, números, _ . -" ;; esac
CLAVE=''
ADMIN_EXISTE=0
if [ -f /var/lib/router-panel/usuarios.json ] && python3 -c 'import json,sys; sys.exit(0 if sys.argv[2] in json.load(open(sys.argv[1])) else 1)' /var/lib/router-panel/usuarios.json "$ADMIN" 2>/dev/null; then
    ADMIN_EXISTE=1
    nsay "el usuario «$ADMIN» del panel ya existe: se conserva con su contraseña."
elif [ -n "$CLAVE_FICH" ]; then
    [ -r "$CLAVE_FICH" ] || morir "no puedo leer --admin-clave-fichero $CLAVE_FICH"
    CLAVE=$(head -n1 "$CLAVE_FICH")
    [ ${#CLAVE} -ge 12 ] || morir "la contraseña del fichero tiene menos de 12 caracteres"
elif [ -t 0 ]; then
    nsay "La contraseña del admin del panel se pide dos veces, sin eco; no queda en el historial ni en ps."
    CLAVE=$(contrasena_interactiva)
else
    morir "sin terminal: usa --admin-clave-fichero para la contraseña del admin (o --si si ya existe el usuario)"
fi
if [ "$ADMIN_EXISTE" = 0 ] && [ ${#CLAVE} -lt 12 ]; then
    morir "falta una contraseña de al menos 12 caracteres"
fi
nsay "Resumen: LAN=$LAN_IF $LAN_RED_CON_PREFIJO router=$LAN_IP  DHCP=$DHCP_INICIO-$DHCP_FIN  dominio=$DOMINIO  wifi=$WIFI_MODO${AP_SSID:+ (SSID «$AP_SSID» en $AP_IF)}${WIFI_IF:+ (WAN Wi-Fi: $WIFI_IF)}  wan-cable=${WAN_CABLE:-(ninguna)}  admin=$ADMIN"

# ───────────────────────── 4. usuario de sistema ─────────────────────────
if ! id -u routerpanel >/dev/null 2>&1; then
    nsay "creando el usuario de sistema routerpanel…"
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin routerpanel
fi

# ───────────────────────── 2. paquetes ─────────────────────────
instalar_paquetes() {
    local pendientes=() p
    for p in "${PAQUETES[@]}"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || pendientes+=("$p")
    done
    if [ ${#pendientes[@]} -gt 0 ]; then
        nsay "instalando paquetes: ${pendientes[*]}"
        # En un sistema recién arrancado apt suele estar ocupado (actualizaciones
        # automáticas, cloud-init): se espera al bloqueo de dpkg hasta 10 min.
        apt-get -o DPkg::Lock::Timeout=600 update
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y "${pendientes[@]}"
    else
        nsay "paquetes ya presentes: nada que instalar."
    fi
}
instalar_paquetes

# Perfiles NetworkManager del modo AP (los crea TAMBIÉN el cambio de modo
# sobre router.json ya existente). Órdenes probadas a mano en Debian 13
# (NetworkManager 1.52); ojo: `autoconnect-ports` admite true/false, NO yes.
crear_perfiles_nm_ap() {
    local ip_lan=$1
    nmcli connection add type bridge ifname br-lan con-name LAN-ROUTER \
        ipv4.method manual ipv4.addresses "$ip_lan/24" ipv4.gateway '' \
        ipv6.method disabled bridge.stp no \
        connection.autoconnect no connection.autoconnect-ports true >/dev/null
    if [ -n "$PUERTO_CABLE" ]; then
        nmcli connection add type ethernet ifname "$PUERTO_CABLE" con-name LAN-ROUTER-cable \
            port-type bridge controller br-lan connection.autoconnect no >/dev/null
    fi
}

# El punto de acceso necesita una tarjeta que admita modo AP; el chequeo usa
# `wifi_ap.py soporta-ap` con `iw` (ya instalado arriba):
if [ "$WIFI_MODO" = ap ]; then
    SOPORTE_AP=$(python3 "$BASE/core/wifi_ap.py" soporta-ap "$AP_IF" 2>/dev/null || true)
    case "$SOPORTE_AP" in
        si) nsay "la tarjeta $AP_IF admite modo punto de acceso (AP)." ;;
        no) morir "la tarjeta $AP_IF no admite modo punto de acceso (AP)" ;;
        desconocido) avisar "no se pudo saber si la tarjeta $AP_IF admite modo AP: continúo, puede fallar al activar." ;;
        *) avisar "respuesta inesperada de «wifi_ap.py soporta-ap»: «${SOPORTE_AP:-(vacía)}»; continúo igualmente." ;;
    esac
fi

# ───────────────────────── 5. código + unidades + ficheros de sistema ─────────────────────────
nsay "instalando el núcleo en /usr/local/lib/router (sin acme_ionos.py)…"
install -d -m 0755 /usr/local/lib/router /usr/local/sbin
install -m 0755 -o root -g root "$BASE"/core/*.py /usr/local/lib/router/
rm -f /usr/local/lib/router/acme_ionos.py   # versión privada: nunca se instala
install -m 0755 -o root -g root "$BASE/core/router_migrar.py" /usr/local/sbin/router-migrar

nsay "instalando unidades y ficheros de sistema…"
systemd_unidades() {
    local unidad
    for unidad in "$BASE"/systemd/*.service "$BASE"/systemd/*.timer; do
        case "$(basename "$unidad")" in router-certbot.service|router-certbot.timer) continue ;; esac
        install -m 0644 -o root -g root "$unidad" /etc/systemd/system/
    done
}
systemd_unidades
install -m 0644 -o root -g root "$BASE/systemd/router-tmpfiles.conf" /etc/tmpfiles.d/router.conf
install -m 0644 -o root -g root "$BASE/systemd/90-router.conf" /etc/sysctl.d/90-router.conf
install -m 0644 -o root -g root "$BASE/systemd/90-router-usb.rules" /etc/udev/rules.d/90-router-usb.rules
install -d -m 0755 /etc/systemd/logind.conf.d
install -m 0644 -o root -g root "$BASE/systemd/logind-router.conf" /etc/systemd/logind.conf.d/90-router.conf
install -m 0644 -o root -g root "$BASE/systemd/logrotate-router" /etc/logrotate.d/router
install -d -m 0755 /etc/systemd/system/router-bloqueo.timer.d   # drop-in de bloqueo.actualizar_h (routerd)

systemctl daemon-reload
sysctl --system >/dev/null
udevadm control --reload
systemd-tmpfiles --create

# directorios de datos del contrato: /var/lib/router y su buzón para el panel
install -d -m 0755 -o root -g root /var/lib/router
install -d -m 0770 -o root -g routerpanel /var/lib/router/solicitudes /var/lib/router/respuestas
install -d -m 0755 -o root -g root /var/log/router

# ───────────────────────── 6. router.json (idempotente) ─────────────────────────
if [ -f /etc/router/router.json ]; then
    nsay "/etc/router/router.json YA existe."
    if [ "$WIFI_MODO_EXPLICITO" = 1 ]; then
        # CAMBIO DE MODO sobre una instalación existente: sólo se reescriben
        # lan.interfaz, ignorar_interfaces, wifi_wan, wifi_ap y activacion
        # (el resto de router.json queda INTACTO), se recrean los perfiles NM
        # de la LAN y, si hay AP, hostapd.conf. Sólo con el router sin activar.
        FASE_ACTUAL=''
        [ -r /etc/router/fase ] && FASE_ACTUAL=$(head -n1 /etc/router/fase 2>/dev/null || true)
        if [ "$FASE_ACTUAL" = produccion ]; then
            morir "deshaz antes la activación: sudo router-migrar --deshacer"
        fi
        nsay "cambiando el modo Wi-Fi a «$WIFI_MODO» (sólo lan.interfaz, ignorar_interfaces, wifi_wan, wifi_ap y activacion)…"
        IP_CFG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("lan",{}).get("ip") or "")' /etc/router/router.json 2>/dev/null || true)
        [ -n "$IP_CFG" ] || IP_CFG="$LAN_IP"
        python3 - "$WIFI_MODO" "$LAN_IF" "$WIFI_IF" "$AP_IF" "$PUERTO_CABLE" "$AP_PAIS" "$AP_CANAL" <<'PYEOF'
import json, sys
(modo, lan_if, wifi_if, ap_if, puerto_cable, ap_pais, ap_canal) = sys.argv[1:8]
ruta = '/etc/router/router.json'
with open(ruta) as f:
    cfg = json.load(f)
# Sólo los apartados que dependen del modo; el resto de router.json intacto.
if modo == 'ap':
    cfg['lan']['interfaz'] = 'br-lan'
    ignorar = ['lo', puerto_cable or 'br-lan', 'docker0']
    if ap_if:
        ignorar.append(ap_if)
    cfg['wifi_ap'] = {'habilitado': True, 'interfaz': ap_if, 'pais': ap_pais, 'canal': int(ap_canal)}
    cfg['wifi_wan'] = {'habilitada': False, 'interfaz': '', 'ssid_bloqueadas': []}
else:
    cfg['lan']['interfaz'] = lan_if
    ignorar = ['lo', lan_if, 'docker0']
    wifi_wan_antes = cfg.get('wifi_wan', {})
    cfg['wifi_wan'] = {
        'habilitada': wifi_wan_antes.get('habilitada') is True if modo == 'wan' else False,
        'interfaz': wifi_if if modo == 'wan' else '',
        'ssid_bloqueadas': wifi_wan_antes.get('ssid_bloqueadas', []),
    }
    cfg['wifi_ap'] = {'habilitado': False, 'interfaz': '', 'pais': 'ES', 'canal': 6}
activacion = {'perfil_lan': 'LAN-ROUTER',
              'perfil_wifi': (cfg.get('activacion') or {}).get('perfil_wifi', '')}
activacion['wifi_interfaz'] = wifi_if if modo == 'wan' else ''
activacion['puerto_cable'] = puerto_cable
cfg['activacion'] = activacion
cfg['ignorar_interfaces'] = ignorar
with open(ruta, 'w') as f:
    json.dump(cfg, f, sort_keys=True)
PYEOF
        # Se recrean los perfiles NM de la LAN según el modo nuevo:
        nmcli connection delete LAN-ROUTER-cable >/dev/null 2>&1 || true
        nmcli connection delete LAN-ROUTER >/dev/null 2>&1 || true
        if [ "$WIFI_MODO" = ap ]; then
            crear_perfiles_nm_ap "$IP_CFG"
            if [ -n "$CLAVE_AP" ]; then
                nsay "reescribiendo /etc/router/hostapd.conf para el modo AP (clave por stdin)…"
                printf '%s' "$CLAVE_AP" | python3 "$BASE/core/wifi_ap.py" escribir \
                    --interfaz "$AP_IF" --ssid "$AP_SSID" --pais "$AP_PAIS" --canal "$AP_CANAL"
                HOSTAPD_HECHO=1
            else
                avisar "no hay clave nueva del AP (--ap-clave-fichero o terminal): /etc/router/hostapd.conf no se reescribe."
            fi
        else
            nmcli connection add type ethernet ifname "$LAN_IF" con-name LAN-ROUTER \
                ipv4.method manual ipv4.addresses "$IP_CFG/24" ipv4.gateway '' \
                connection.autoconnect no >/dev/null
        fi
        nsay "modo Wi-Fi cambiado a «$WIFI_MODO»: revisa el resumen del final y confirma con router-migrar --comprobar."
    else
        nsay "  idempotente: no lo toco (pasa --wifi-modo para cambiar el modo Wi-Fi; sólo con el router sin activar)."
    fi
else
    install -d -m 0755 /etc/router
    # activacion.perfil_wifi es la conexión Wi-Fi con la que la máquina sale
    # HOY a Internet (se apaga al activar y se recupera al deshacer). Se deja
    # vacía: la activación no toca el Wi-Fi salvo que el admin la rellene.
    PERFILO_WIFI=''
    nsay "generando /etc/router/router.json desde core/router.json.inicial…"
    python3 - "$BASE" "$LAN_IF" "$LAN_IP" "$LAN_RED" "$DHCP_INICIO" "$DHCP_FIN" "$DOMINIO" "$WIFI_IF" "$PERFILO_WIFI" "$WAN_CABLE" "$WIFI_MODO" "$AP_IF" "$PUERTO_CABLE" "$AP_PAIS" "$AP_CANAL" <<'PYEOF'
import json, sys
(base, lan_if, lan_ip, lan_red, dhcp_ini, dhcp_fin, dominio, wifi_if, perfil_wifi,
 wan_cable, modo, ap_if, puerto_cable, ap_pais, ap_canal) = sys.argv[1:16]
try:
    with open(base + '/core/router.json.inicial') as f:
        cfg = json.load(f)
except OSError as e:
    sys.exit('no se pudo leer core/router.json.inicial: %s' % e)
cfg['lan'] = {'interfaz': lan_if, 'red': lan_red + '/24', 'ip': lan_ip}
cfg['dhcp'] = {'inicio': dhcp_ini, 'fin': dhcp_fin, 'lease': '12h'}
# En modo AP la LAN es el puente br-lan: en las mediciones se ignora el
# puerto de cable (o el propio puente si es sólo AP) y la interfaz del AP.
if modo == 'ap':
    ignorar = ['lo', puerto_cable or lan_if, 'docker0']
    if ap_if:
        ignorar.append(ap_if)
else:
    ignorar = ['lo', lan_if, 'docker0']
cfg['ignorar_interfaces'] = ignorar
cfg['dominio'] = dominio
cfg['dns'] = ['1.1.1.1', '9.9.9.9']
if modo == 'ap':
    # La tarjeta Wi-Fi es el punto de acceso: nada de WAN Wi-Fi (la gestiona
    # hostapd, no NetworkManager).
    cfg['wifi_wan'] = {'habilitada': False, 'interfaz': '', 'ssid_bloqueadas': []}
else:
    cfg['wifi_wan'] = {'habilitada': False, 'interfaz': wifi_if, 'ssid_bloqueadas': []}
cfg['wifi_ap'] = {
    'habilitado': modo == 'ap',
    'interfaz': ap_if if modo == 'ap' else '',
    'pais': ap_pais if modo == 'ap' else 'ES',
    'canal': int(ap_canal) if modo == 'ap' else 6,
}
cfg['wan_forzadas'] = [i for i in wan_cable.replace(',', ' ').split() if i]
cfg['activacion'] = {
    'perfil_lan': 'LAN-ROUTER',
    'perfil_wifi': perfil_wifi,
    'wifi_interfaz': wifi_if if modo == 'wan' else '',
    'puerto_cable': puerto_cable,
}
with open('/etc/router/router.json', 'w') as f:
    json.dump(cfg, f, sort_keys=True)
PYEOF
    chmod 0644 /etc/router/router.json
    if [ -n "$WIFI_IF" ]; then
        avisar "WAN Wi-Fi: $WIFI_IF queda configurada pero APAGADA (wifi_wan.habilitada=false). Actívala desde el panel cuando el router esté activado."
    fi
fi

# Configuración de hostapd (instalación NUEVA en modo AP; en un cambio de
# modo ya se escribió dentro del bloque de arriba). La clave viaja por stdin,
# nunca por argv:
if [ "$WIFI_MODO" = ap ] && [ "$HOSTAPD_HECHO" != 1 ]; then
    nsay "escribiendo /etc/router/hostapd.conf (clave por stdin, nunca en argv)…"
    printf '%s' "$CLAVE_AP" | python3 "$BASE/core/wifi_ap.py" escribir \
        --interfaz "$AP_IF" --ssid "$AP_SSID" --pais "$AP_PAIS" --canal "$AP_CANAL"
    HOSTAPD_HECHO=1
fi

# ───────────────────────── 7. fase = preparación ─────────────────────────
if [ ! -f /etc/router/fase ]; then
    printf 'preparacion\n' > /etc/router/fase
    chmod 0644 /etc/router/fase
    nsay "/etc/router/fase = preparacion (routerd sólo OBSERVA: no cambia la red)."
fi

# ───────────────────────── 8. perfil NM de la LAN ─────────────────────────
if ! nmcli -g connection.id connection show LAN-ROUTER >/dev/null 2>&1; then
    if [ "$WIFI_MODO" = ap ]; then
        nsay "creando los perfiles NM del modo AP: puente LAN-ROUTER (IP fija $LAN_IP/24 en br-lan) y su puerto de cable…"
        crear_perfiles_nm_ap "$LAN_IP"
    else
        nsay "creando el perfil NetworkManager LAN-ROUTER (IP fija $LAN_IP/24, SIN gateway, autoconnect=no)…"
        nmcli connection add type ethernet ifname "$LAN_IF" con-name LAN-ROUTER \
            ipv4.method manual ipv4.addresses "$LAN_IP/24" ipv4.gateway '' \
            connection.autoconnect no >/dev/null
    fi
else
    nsay "el perfil NM LAN-ROUTER ya existe: no lo toco."
fi
# En modo AP el puerto de cable puede faltar aunque el puente ya existiera
# (lo de hoy era un perfil ethernet suelto): se crea si falta.
if [ "$WIFI_MODO" = ap ] && [ -n "$PUERTO_CABLE" ] && ! nmcli -g connection.id connection show LAN-ROUTER-cable >/dev/null 2>&1; then
    nsay "creando el perfil NM LAN-ROUTER-cable (puerto de cable esclavo de br-lan)…"
    nmcli connection add type ethernet ifname "$PUERTO_CABLE" con-name LAN-ROUTER-cable \
        port-type bridge controller br-lan connection.autoconnect no >/dev/null
fi

# NetworkManager crea por su cuenta una conexión DHCP («Wired connection N»)
# en cada tarjeta cableada sin perfil. En la LAN competiría con LAN-ROUTER:
# se le quita esa costumbre y se borra la que ya hubiera en la LAN, salvo
# que esté en uso (con IP), porque podría ser la conexión de esta sesión SSH.
install -d -m 0755 /etc/NetworkManager/conf.d
printf '[main]\nno-auto-default=*\n' > /etc/NetworkManager/conf.d/90-router.conf
systemctl reload NetworkManager 2>/dev/null || true
# NetworkManager crea por su cuenta conexiones DHCP («Wired connection N»)
# en cada tarjeta cableada sin perfil. En la LAN competirían con LAN-ROUTER:
# la limpieza aplica a la interfaz FÍSICA de la LAN (el puerto de cable en
# modo AP); en sólo-AP no hay nada cableado que limpiar.
if [ -n "$IF_LAN_FISICA" ]; then
    if [ -z "$(ip -4 -o addr show dev "$IF_LAN_FISICA" 2>/dev/null)" ]; then
        nmcli -t -f NAME,DEVICE connection show 2>/dev/null | while IFS=: read -r nombre disp; do
            if [ "$disp" = "$IF_LAN_FISICA" ] && [ "$nombre" != LAN-ROUTER ] && [ "$nombre" != LAN-ROUTER-cable ]; then
                nsay "borrando la conexión automática «$nombre» de la LAN ($IF_LAN_FISICA)…"
                nmcli connection delete "$nombre" >/dev/null || avisar "no se pudo borrar «$nombre»"
            fi
        done
    elif [ "$(nmcli -g GENERAL.CONNECTION device show "$IF_LAN_FISICA" 2>/dev/null)" != LAN-ROUTER ]; then
        avisar "$IF_LAN_FISICA tiene IP ahora mismo (¿es tu conexión actual?): no toco sus conexiones. Al activar, LAN-ROUTER la sustituye."
    fi
fi

# ───────────────────────── 9. panel ─────────────────────────
nsay "instalando el panel en /opt/router-panel…"
install -d -m 0750 -o root -g routerpanel /opt/router-panel
rm -rf /opt/router-panel/routerpanel.nuevo
cp -a "$BASE/panel/routerpanel" /opt/router-panel/routerpanel.nuevo
rm -rf /opt/router-panel/routerpanel.nuevo/__pycache__
install -m 0640 -o root -g routerpanel "$BASE/panel/wsgi.py" "$BASE/panel/requirements.txt" /opt/router-panel/
if [ -d /opt/router-panel/venv ]; then
    /opt/router-panel/venv/bin/pip install --quiet -r "$BASE/panel/requirements.txt"
else
    python3 -m venv /opt/router-panel/venv
    /opt/router-panel/venv/bin/pip install --quiet --upgrade pip
    /opt/router-panel/venv/bin/pip install --quiet -r "$BASE/panel/requirements.txt"
fi
# el código del panel (el paquete routerpanel): routerpanel:routerpanel,
# dirs 750, ficheros 640 (ver panel/README.md y docs/CONTRATO.md)
chown -R routerpanel:routerpanel /opt/router-panel/routerpanel.nuevo
find /opt/router-panel/routerpanel.nuevo -type d -exec chmod 750 {} +
find /opt/router-panel/routerpanel.nuevo -type f -exec chmod 640 {} +
if [ -d /opt/router-panel/routerpanel ]; then
    rm -rf /opt/router-panel/routerpanel.antes
    mv /opt/router-panel/routerpanel /opt/router-panel/routerpanel.antes
fi
mv /opt/router-panel/routerpanel.nuevo /opt/router-panel/routerpanel
rm -rf /opt/router-panel/routerpanel.antes
chown -R routerpanel:routerpanel /opt/router-panel/venv
install -d -m 0750 -o routerpanel -g routerpanel /var/lib/router-panel /var/log/router-panel

if [ "$ADMIN_EXISTE" = 0 ]; then
nsay "creando el admin del panel (flask crear-usuario como routerpanel)…"
# La contraseña viaja por stdin a un setsid (sin tty: getpass cae a stdin,
# la segunda línea es la repetición; NADA en argv/ps ni en el historial).
# runuser y no sudo: no depende de sudoers ni abre un pty propio.
printf '%s\n%s\n' "$CLAVE" "$CLAVE" |
    setsid -w runuser -u routerpanel -- env \
        PANEL_USUARIOS=/var/lib/router-panel/usuarios.json \
        PANEL_SECRET_FILE=/var/lib/router-panel/secret_key \
        PANEL_AUDIT=/var/log/router-panel/audit.log \
        bash -c "cd /opt/router-panel && exec /opt/router-panel/venv/bin/flask --app wsgi crear-usuario '$ADMIN' --rol admin" \
    || { unset CLAVE; morir "no se pudo crear el usuario admin (¿ya existe? borra /var/lib/router-panel/usuarios.json o usa otro nombre)"; }
fi
unset CLAVE

# ───────────────────────── 10. certificado + nginx ─────────────────────────
install -d -m 0750 -o root -g root /etc/router/tls
regenera_cert=0
if [ ! -s /etc/router/tls/panel.crt ] || [ ! -s /etc/router/tls/panel.key ]; then
    regenera_cert=1
elif ! openssl x509 -in /etc/router/tls/panel.crt -noout -ext subjectAltName 2>/dev/null | grep -qE "IP:$LAN_IP(,|$)"; then
    regenera_cert=1   # la IP cambió desde la última instalación
fi
if [ "$regenera_cert" = 1 ]; then
    nsay "generando certificado autofirmado (10 años, CN=$LAN_IP)…"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout /etc/router/tls/panel.key -out /etc/router/tls/panel.crt \
        -subj "/CN=$LAN_IP" -addext "subjectAltName=IP:$LAN_IP" >/dev/null 2>&1
    chmod 0600 /etc/router/tls/panel.key
    chmod 0644 /etc/router/tls/panel.crt
else
    nsay "el certificado autofirmado ya cubre la IP $LAN_IP: no lo toco."
fi

if [ -d /etc/nginx/sites-available ]; then
    nsay "generando /etc/nginx/sites-available/router-panel desde la plantilla…"
    python3 - "$BASE/systemd/nginx-router-panel.conf.plantilla" "$LAN_RED_CON_PREFIJO" <<'PYEOF'
import sys
plantilla, lan_red = sys.argv[1], sys.argv[2]
texto = open(plantilla).read()
texto = texto.replace('@LAN_RED@', lan_red)
texto = texto.replace('@CERT@', '/etc/router/tls/panel.crt')
texto = texto.replace('@CLAVE@', '/etc/router/tls/panel.key')
open('/etc/nginx/sites-available/router-panel', 'w').write(texto)
PYEOF
    ln -sf /etc/nginx/sites-available/router-panel /etc/nginx/sites-enabled/router-panel
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
else
    avisar "nginx sin /etc/nginx/sites-available (¿distribución distinta?): NO configuré el proxy HTTPS."
fi

# ───────────────────────── 11. prerequisitos de la activación + servicios ────
nsay "preparando los prerequisitos de router-migrar --comprobar…"
if ! systemctl is-enabled dnsmasq 2>/dev/null | grep -q '^enabled$'; then
    systemctl enable dnsmasq || avisar "no se pudo marcar dnsmasq como enabled"
fi
if systemctl is-enabled nftables >/dev/null 2>&1; then
    nsay "nftables.service deshabilitado (routerd instala su propia tabla en cada ciclo)."
    systemctl disable nftables
fi
# En preparación dnsmasq no tiene todavía la configuración del router (la
# escribe routerd al activar) y con la de serie choca con otros servicios
# en el puerto 53 (p. ej. systemd-resolved): se queda habilitado pero parado.
systemctl stop dnsmasq 2>/dev/null || true
systemctl reset-failed dnsmasq 2>/dev/null || true
if nft list table ip filter >/dev/null 2>&1; then
    avisar "ya existe una «table ip filter» (¿Docker?): router-migrar --comprobar fallará por eso; no toco nada."
fi
nsay "habilitando y arrancando los servicios del router…"
systemctl enable --now routerd.service router-panel.service router-estadisticas.service \
    router-bloqueo.timer router-logrotate-dns.timer \
    router-firewall-arranque.service router-migracion-arranque.service
# router-adb (tethering USB de teléfonos) sólo si el binario está:
if command -v adb >/dev/null 2>&1; then
    systemctl enable --now router-adb.service
fi
sleep 3
CAIDOS=0
for servicio in routerd router-panel router-estadisticas; do
    if ! systemctl is-active --quiet "$servicio"; then
        avisar "$servicio no está activo: mira journalctl -u $servicio -n 20"
        CAIDOS=1
    fi
done

# ───────────────────────── 12. resumen final ─────────────────────────
IP_ACTUAL=$(ip -4 -o addr show scope global | awk '{sub(/\/.*/, "", $4); print $4; exit}')
nsay "================== INSTALACIÓN TERMINADA =================="
echo "  Panel: https://$LAN_IP/ (sólo desde la LAN $LAN_RED_CON_PREFIJO, en cuanto el router esté activado)"
echo "  Certificado autofirmado: el navegador avisará la primera vez."
if [ "$WIFI_MODO" = ap ]; then
    echo "  Wi-Fi: punto de acceso «$AP_SSID» (interfaz $AP_IF, país $AP_PAIS, canal $AP_CANAL):"
    echo "    se enciende al ACTIVAR el router (router-migrar) y sirve la LAN por Wi-Fi."
fi
echo "  Máquina ahora en: ${IP_ACTUAL:-sin IP} (fase preparación: la red no ha cambiado)"
echo
echo "  PASOS DE ACTIVACIÓN (la máquina pasa a ser el router de la LAN):"
echo "    1) sudo router-migrar --comprobar        # repasa la lista: todo debe salir ✔"
if [ "$WIFI_MODO" = ap ] && [ -z "$PUERTO_CABLE" ]; then
    echo "    2) apaga el otro equipo que tenga la IP $LAN_IP (LAN sólo Wi-Fi: no hace falta cable)"
elif [ "$WIFI_MODO" = ap ]; then
    echo "    2) apaga el otro equipo que tenga la IP $LAN_IP y conecta el cable LAN (interfaz $PUERTO_CABLE)"
else
    echo "    2) apaga el otro equipo que tenga la IP $LAN_IP y conecta el cable LAN (interfaz $LAN_IF)"
fi
echo "    3) sudo systemctl start router-migracion  # espera, activa y vigila 30 min"
echo "    4) entra al panel por https://$LAN_IP/ y confirma a tiempo:"
echo "       sudo router-migrar --confirmar        # si nadie confirma, vuelve sola atrás"
echo "==========================================================="
if [ "$CAIDOS" = 1 ]; then
    echo "  ATENCIÓN: algún servicio no arrancó (ver avisos de arriba). Corrígelo antes de activar."
    exit 1
fi
exit 0
