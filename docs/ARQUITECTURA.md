# Arquitectura de Roble Router

Todo lo que se describe aquí sale del código (cabeceras de `core/`,
`docs/CONTRATO.md`, `docs/FIREWALL_PLAN.md`, `panel/README.md` y las unidades
de `systemd/`).

## Reparto de privilegios: el principio básico

- **root**: routerd, router-adb, router-bloqueo, router-estadisticas,
  router-migrar y el arranque del cortafuegos. Son los procesos responsables
  de tocar el sistema (nftables, dnsmasq, rutas, NetworkManager, sysctl,
  conntrack, adb) y de escribir la configuración.
- **sin privilegios (`routerpanel`)**: el panel web (gunicorn) y nginx (sólo
  proxy HTTPS). El panel **nunca** ejecuta comandos del sistema ni escribe
  la configuración: sólo lee lo que publica el núcleo y deja **peticiones**
  en un buzón.

Así, si el panel se viera comprometido, lo peor que puede hacer es pedir
cambios que routerd valida uno a uno (nunca shell, nunca rutas de fichero):
ver `docs/CONTRATO.md`.

## Procesos y su comunicación (buzón)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  LAN de la casa                     INTERNET                             │
│  clientes (PC, móviles, TV…)        para cada WAN: cable / tethering     │
│        │                            USB de teléfonos / hotspot Wi-Fi     │
│  │ DHCP/DNS: dnsmasq (gestionado por routerd)                            │
│  ▼                                                                      │
│  NAT y balanceo hacia las WAN (nftables «elegir_wan» + rutas por WAN)     │
└──────────────────────────────────────────────────────────────────────────┘
        │                                   ▲
        ▼                                   │
┌────────────────────────── root ──────────┴────────────────────────────────┐
│  routerd            (bucle de unos segundos)                             │
│   • descubre las WAN (drivers de tethering) y comprueba Internet         │
│     de verdad en cada una (pings con histéresis)                         │
│   • reescribe con mapa de pesos (numgen) la cadena nftables              │
│     «elegir_wan», de forma atómica                                       │
│   • publica /run/router/estado.json y /run/router/firewall.txt           │
│   • valida y atiende el buzón de peticiones del panel                    │
│                                                                          │
│  router_adb        servicio aparte: mantiene activo el tethering USB     │
│                    de los teléfonos Android (svc usb setFunctions        │
│                    rndis/ncm, con cooldown y backoff);                   │
│                    publica /run/router/adb.json                          │
│                                                                          │
│  router-bloqueo    oneshot por timer: descarga las listas HaGeZi y       │
│                    genera el servers-file de dnsmasq;                    │
│                    publica /run/router/bloqueo.json                      │
│                                                                          │
│  router_estadisticas: cada minuto guarda en SQLite el tráfico            │
│                    por WAN y por dispositivo, y las consultas DNS        │
│                                                                          │
│  router-migrar     activa la fase producción, vigila 30 min y deshace    │
│                    si nadie confirma (ver más abajo)                     │
└──────────────────────────────────────────────────────────────────────────┘
        ▲                                                          ▲
        │ sólo lectura de ficheros publicados                      │
┌───────┴────────── routerpanel (sin privilegios) ─────────────────────────┐
│  panel Flask con gunicorn (escucha en 127.0.0.1:5001)                    │
│   • login, CSRF, roles, auditoría propia                                 │
│   • lee estado.json, leases DHCP, oplog y la base SQLite (lectura)       │
│   • deja peticiones en /var/lib/router/solicitudes/<uuid>.json           │
│     {id, usuario, accion, datos} — escritura atómica (temporal+rename),  │
│     grupo routerpanel 0660                                               │
│   • espera la respuesta en /var/lib/router/respuestas/<uuid>.json        │
│                                                                          │
│  nginx (HTTPS en la LAN, sólo la red LAN)  →  proxy 127.0.0.1:5001       │
└──────────────────────────────────────────────────────────────────────────┘
```

## Servicios systemd y para qué sirve cada uno

| Unidad | Qué hace |
|---|---|
| `routerd.service` | El bucle del núcleo. `WatchdogSec=60` y `ProtectSystem=full`. Gestiona rutas, nftables y dnsmasq; atiende el buzón |
| `router-adb.service` | Vigilante ADB: mantiene el tethering USB de los teléfonos Android (órdenes mínimas validadas, cooldown que se dobla hasta 30 min) |
| `router-estadisticas.service` | Recolector de estadísticas (SQLite en modo WAL): tráfico por WAN y por dispositivo, conexiones, consultas DNS |
| `router-bloqueo.service` + `.timer` | Oneshot por timer: descarga las listas HaGeZi y regenera el servers-file de dnsmasq (el intervalo lo ajusta routerd con un drop-in) |
| `router-firewall-arranque.service` | Aplica el cortafuegos ANTES de que arranque la red (sin ventana sin filtrar al arrancar) |
| `router-logrotate-dns.service` + `.timer` | Comprobación horaria del tamaño del log de consultas DNS |
| `router-migracion.service` | La activación: espera a que la IP del router quede libre, activa, vigila y deshace |
| `router-migracion-arranque.service` | Si la máquina reinició con una migración sin confirmar, deshace sola |
| `router-ap.service` | hostapd del punto de acceso Wi-Fi (nombre de arranque `/etc/router/hostapd.conf`). NO va habilitada: la enciende/apaga `router-migrar` con la activación; al confirmar se habilita para sobrevivir a reinicios |
| `router-panel.service` | gunicorn del panel, con el usuario `routerpanel` (sin privilegios) |

## Flujo de una petición del panel (buzón)

1. El admin completa un formulario (p. ej. cambia el rango DHCP).
2. El panel valida otra vez los datos (mismas reglas que el contrato, en
   `routerpanel/validacion.py`) y escribe una petición en
   `/var/lib/router/solicitudes/<uuid>.json` de forma atómica — sólo ficheros,
   ninguna orden ejecutada.
3. La petición lleva una única acción (`accion`) y sus `datos`; si la acción
   no está en la lista admitida por el contrato, se rechaza entera.
4. routerd la valida de nuevo (defensa en profundidad, `core/peticiones.py`)
   y, si la acepta, la ejecuta dentro de su ciclo. Las acciones del
   cortafuegos pasan además por una validación nft intermedia
   (`nft -c -f` sobre un fichero temporal) antes de guardar nada.
5. routerd deja la respuesta en `/var/lib/router/respuestas/<uuid>.json`
   (`{id, ok, mensaje, aplicado}`); el panel espera hasta ~10 s y, si no
   aparece, informa de «pendiente».

Consecuencia: el panel sólo puede pedir acciones tipadas y ya validadas, y
nunca se interpola texto libre en nftables o dnsmasq. Las claves Wi-Fi, por
ejemplo, nunca pasan por `router.json`: van a un keyfile de NetworkManager
con permisos 0600 de root.

## Fases: preparación y producción

- **`preparacion`** (fase tras instalar): routerd sólo OBSERVA — descubre
  WAN, mide, publica estado. No toca nftables, ni dnsmasq, ni las reglas de
  rutas. Así el servicio se puede dejar instalado y en marcha sin cambiar la
  red que ya funciona: no puede cortar el SSH por el que se administra la
  máquina.
- **`produccion`**: routerd instala de verdad — tablas nftables del router,
  rutas por WAN, NAT, balanceo y DHCP/DNS con dnsmasq. Sólo se llega a esta
  fase a través de `router-migrar`; nunca a mano.

La fase vive en `/etc/router/fase`, un fichero aparte de `router.json`:
un cambio de configuración no puede activar ni desactivar el rol de router
por accidente. routerd la lee en cada ciclo; sólo la escribe `router-migrar`.

`router-migrar` garantiza la vuelta atrás:

- se niega a activar mientras otro equipo tenga la IP del router (ARP);
- ANTES de activar nada, programa un deshacer automático INDEPENDIENTE
  (`router-deshacer`, a los 30 min) con `systemd-run`, para que la vuelta
  atrás no dependa de que el proceso siga vivo (corte de luz, `kill -9`…);
- deja un marcador en disco (`/etc/router/migracion-pendiente`) y una
  unidad de arranque (`router-migracion-arranque.service`) que deshace
  si la máquina se reinicia con una activación sin confirmar;
- al deshacer: fase `preparacion` de nuevo, perfil de la LAN abajo y sin
  autoconexión, y si hay WAN Wi-Fi configurada se reconecta el Wi-Fi. Cada
  paso va por separado: que uno falle no impide los demás.

## La LAN como puente: modo punto de acceso

La LAN vive en `router.json` como `lan.interfaz`. En las instalaciones
clásicas es la tarjeta cableada (perfil NM `LAN-ROUTER`). Si el modo Wi-Fi
definido en la instalación es «ap», `lan.interfaz` es el **puente**
NetworkManager `br-lan`:

```
            LAN de la casa
   cable (a un switch)   Wi-Fi (móviles, portátiles…)
           │                    │
           │ Puerto esclavo     │ hostapd (router-ap.service)
           │ LAN-ROUTER-cable   │ con bridge=br-lan, /etc/router/hostapd.conf
           ▼                    ▼
        ════════ puente NetworkManager br-lan (LAN-ROUTER) ════════
        IP fija en el puente (192.168.50.1/24): dnsmasq, nftables,
        estadísticas y balanceo siguen usando lan.interfaz sin cambiar nada
```

- El puente lo creó el instalador (`instalar.sh`) con dos perfiles NM:
  `LAN-ROUTER` (bridge, IP fija sin gateway, `autoconnect-ports true`) y
  `LAN-ROUTER-cable` (el puerto de cable, esclavo del puente; también en
  `activacion.puerto_cable`). En modo «sólo AP» el puente no lleva puerto:
  la LAN es exclusivamente Wi-Fi.
- La tarjeta del AP **NO la gestiona NetworkManager**: `router-migrar` la
  aparta (`nmcli device set <if> managed no`, drop-in
  `/etc/NetworkManager/conf.d/91-router-ap.conf` al confirmar) y **hostapd**
  la levanta dentro del puente. La configuración de hostapd la genera
  `core/wifi_ap.py` en la instalación y la lee `routerd` (SSID, clientes)
  para publicarla en `estado.json` -> `wifi_ap`.
- El punto de acceso sigue el ciclo de activación/deshacer: `router-migrar`
  lo ENCIENDE al activar (tras levantar el perfil de la LAN) y lo APAGA al
  deshacer, antes de bajar el perfil. Sin activación no hay AP: sólo LAN
  cableada o el punto de acceso que hubiera a mano fuera del router.

## Ficheros de estado

| Fichero | Quién lo escribe | Qué contiene |
|---|---|---|
| `/run/router/estado.json` | routerd (cada ciclo) | Estado completo: LAN, WANs (latencia, pérdida, pesos), servicios, vecinos ARP, Wi-Fi, firewall y bloqueo, y copia de la config editable. Es lo que pinta el panel |
| `/run/router/firewall.txt` | routerd | Volcado de `nft list` de las tablas del router |
| `/run/router/adb.json` | router_adb | Estado de los teléfonos Android conectados por USB |
| `/run/router/bloqueo.json` | router-bloqueo | Estado del bloqueo DNS: listas, dominios, siguiente pasada, fail-open |
| `/run/router/migracion.json` | router-migrar | Estado de una activación en curso |
| `/etc/router/router.json` | routerd | Configuración persistente del router |
| `/etc/router/fase` | router-migrar | Fase actual: `preparacion` o `produccion` |
| `/var/lib/router/solicitudes/` y `/respuestas/` | panel / routerd | Buzón de peticiones y respuestas |
| `/var/lib/router/estadisticas/estadisticas.db` | router-estadisticas | SQLite (WAL) con tráfico por WAN y por dispositivo, y consultas DNS |
| `/var/log/router/operaciones.log` | routerd (JSON por línea) | Registro de operaciones |
| `/var/log/router/dns.log` | dnsmasq | Log de consultas DNS (rotación diaria) |
| `/var/lib/router-panel/usuarios.json` | panel | Usuarios y roles del panel |

El formato completo de `estado.json` y la tabla íntegra de acciones del
buzón están en `docs/CONTRATO.md`.
