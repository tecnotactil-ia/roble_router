#!/usr/bin/env bash
# desinstalar.sh — desinstala Roble Router (servicios, ficheros y panel).
#
# Por defecto NO borra datos: se desinstala el software pero /etc/router,
# /var/lib/router y las bases de datos del panel se quedan (si quieres una
# máquina limpia, usa --purgar). Si la fase es "produccion", PRIMERO se
# deshace la activación (router-migrar --deshacer) para devolver la IP a
# otro equipo de la LAN; se pide confirmación salvo con --si.
#
#   Uso:  sudo bash desinstalar.sh            # confirmación interactiva
#         sudo bash desinstalar.sh --si       # sin confirmación
#         sudo bash desinstalar.sh --purgar   # además borra datos y usuario
set -euo pipefail

SI=0
PURGAR=0

nsay() { echo "desinstalar: $*"; }
morir() { echo "desinstalar: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --si) SI=1 ;;
        --purgar) PURGAR=1 ;;
        *) morir "opción desconocida: $1" ;;
    esac
    shift
done

[ "$(id -u)" = 0 ] || morir "hay que ejecutarlo como root (sudo)"
[ -d /etc/systemd/system ] || morir "esto es para un sistema con systemd"

confirmar() {
    [ "$SI" = 1 ] && return 0
    read -r -p "¿Seguro que desinstalo Roble Router [sí/NO]? " resp
    case "$resp" in
        si|Si|SI|sí|Sí|SÍ|s|S) ;;
        *) morir "cancelado por el usuario." ;;
    esac
}

confirmar
# Si la máquina ESTÁ activada como router, primero devolver la red a su dueño,
# con routerd todavía en marcha para que retire él mismo sus reglas:
FASE=''
[ -r /etc/router/fase ] && FASE=$(head -n1 /etc/router/fase 2>/dev/null)
if [ -x /usr/local/sbin/router-migrar ] && [ "$FASE" = "produccion" ]; then
    nsay "la fase es produccion: ejecutando «router-migrar --deshacer» (vuelve atrás la activación)…"
    if router-migrar --deshacer; then
        nsay "deshacer terminado: la IP del router volvió al otro equipo."
    else
        nsay "AVISO: --deshacer devolvió un error; la red quizá siga en modo router. Revisar a mano."
    fi
    sleep 3
fi

nsay "parando y deshabilitando los servicios del router…"
SERVICIOS=(
    router-migracion.service router-migracion-arranque.service
    router-firewall-arranque.service router-certbot.timer router-certbot.service
    router-logrotate-dns.timer router-bloqueo.timer
    router-adb.service router-estadisticas.service router-ap.service router-panel.service routerd.service
)
for s in "${SERVICIOS[@]}"; do
    systemctl stop "$s" 2>/dev/null || true
    systemctl disable "$s" 2>/dev/null || true
done
systemctl daemon-reload

nsay "borrando unidades y ficheros instalados…"
for s in "${SERVICIOS[@]}"; do rm -f "/etc/systemd/system/$s"; done
rm -f /etc/systemd/system/router-certbot.service /etc/systemd/system/router-certbot.timer
rm -rf /etc/systemd/system/router-bloqueo.timer.d /etc/systemd/system/router.service.d
rm -f /etc/tmpfiles.d/router.conf /etc/sysctl.d/90-router.conf /etc/logrotate.d/router
rm -f /etc/udev/rules.d/90-router-usb.rules
rm -f /etc/systemd/logind.conf.d/90-router.conf
rm -f /etc/NetworkManager/conf.d/90-router.conf
rm -f /etc/NetworkManager/conf.d/91-router-ap.conf   # la interfaz del AP vuelve a NetworkManager
nmcli general reload conf >/dev/null 2>&1 || true
rmdir /etc/systemd/logind.conf.d 2>/dev/null || true
rm -f /usr/local/sbin/router-migrar
rm -rf /usr/local/lib/router

nsay "borrando el sitio nginx…"
rm -f /etc/nginx/sites-enabled/router-panel /etc/nginx/sites-available/router-panel
nginx -t 2>/dev/null && (systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null) || \
    nsay "nginx no recargó (¿no está corriendo?): se ignora."
systemctl daemon-reload

if [ "$PURGAR" = 1 ]; then
    nsay "**purgar**: borrando datos, configuración y usuario…"
    rm -rf /etc/router /var/lib/router /var/lib/router-panel /opt/router-panel /var/log/router-panel /var/log/router
    userdel routerpanel 2>/dev/null || true
    if nmcli -g connection.id connection show LAN-ROUTER >/dev/null 2>&1; then
        nmcli connection delete LAN-ROUTER >/dev/null 2>&1 || true
    fi
    if nmcli -g connection.id connection show LAN-ROUTER-cable >/dev/null 2>&1; then
        nmcli connection delete LAN-ROUTER-cable >/dev/null 2>&1 || true
    fi
    if nmcli -g connection.id connection show WAN-WIFI >/dev/null 2>&1; then
        # Creado por el admin (no por nosotros): se avisa y NO se borra.
        nsay "queda el perfil NM «WAN-WIFI» (creado a mano): bórralo tú si ya no lo quieres."
    fi
    nsay "purga terminada."
else
    nsay "se conservan /etc/router, /var/lib/router, /var/lib/router-panel y /opt/router-panel"
    nsay "  (vuelve a instalar sobre esto sin re-responder nada; para borrar TODO usa --purgar)."
fi
nsay "desinstalación terminada."
