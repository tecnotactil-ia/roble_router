# Contrato entre el núcleo del router y el panel web

El panel (`routerpanel`, sin privilegios) **nunca** ejecuta comandos del sistema
ni escribe la configuración. Sólo:

1. **Lee** el estado que publica el demonio `routerd` (root).
2. **Deja peticiones** en un buzón; `routerd` las valida con un esquema
   estricto, las aplica y deja la respuesta.

Así, aunque el panel se viera comprometido, lo peor que puede hacer es pedir
cambios que el demonio valida uno a uno (nunca shell, nunca rutas de fichero).

## Ficheros

| Fichero | Quién escribe | Quién lee | Permisos |
|---|---|---|---|
| `/etc/router/router.json` | routerd | routerd | 0644 root |
| `/run/router/estado.json` | routerd (cada ~5 s) | panel | 0644 root |
| `/run/router/firewall.txt` | routerd | panel | 0644 root (`nft list` de las tablas del router) |
| `/var/lib/misc/dnsmasq.leases` | dnsmasq | panel, router_estadisticas | 0644 |
| `/var/lib/router/estadisticas/estadisticas.db` | router_estadisticas | panel (sólo lectura) | 0640 root:routerpanel |
| `/var/lib/router/solicitudes/<uuid>.json` | panel | routerd | grupo `routerpanel`, 0660 |
| `/var/lib/router/respuestas/<uuid>.json` | routerd | panel | 0640 root:routerpanel |
| `/var/log/router/operaciones.log` | routerd | panel (grupo) | JSON por línea |

## `/run/router/estado.json`

```json
{
  "generado": "2026-10-10T20:30:00+00:00",
  "uptime_s": 12345,
  "modo": "balanceo",            // "balanceo" | "respaldo"
  "modo_pesos": "auto",          // "auto" | "manual" (fase 4, A): quién decide el peso de cada WAN
  "lan": {"interfaz": "enp2s0", "ip": "192.168.50.1/24", "activa": true},
  "servicios": {"dnsmasq": "active", "nftables_router": true, "balanceo": true, "routerd": "active"},
  "internet": true,              // al menos una WAN operativa
  "wans": [
    {
      "id": "R58M123ABC",        // número de serie USB del teléfono (o nombre de interfaz si no hay)
      "nombre": "WAN1",          // nombre lógico (editable)
      "interfaz": "enx0a1b2c3d4e5f",
      "telefono": "SAMSUNG SM-A515F",   // fabricante + modelo USB, o null
      "ip": "192.168.42.17/24",
      "gateway": "192.168.42.129",
      "tethering": true,         // hay interfaz con IP y gateway
      "internet": true,          // pasa la comprobación real (ping/DNS por esa interfaz)
      "latencia_ms": 48.2,       // media de las medianas de los últimos ciclos (3 pings -c 3 por ciclo, fase 4 A); null si no hay
      "perdida_pct": 0,          // media de la pérdida real por ciclo (0-100%, ya no sólo 0 o 100)
      "habilitada": true,        // decisión lógica del admin
      "en_balanceo": true,       // habilitada && internet && (según modo)
      "peso": 50,                // 1..100, el que pone el admin (sólo se usa de verdad si modo_pesos="manual")
      "peso_efectivo": 50,       // 1..100, el que de verdad usa elegir_wan (fase 4, A): = "peso" en manual,
                                 // calculado SÓLO por latencia/pérdida en auto (H2: la capacidad NO entra,
                                 // para no crear un bucle de realimentación); null si la WAN no está presente
      "prioridad": 1,            // 1 = principal (modo respaldo)
      "rx_bytes": 123, "tx_bytes": 456,
      "rx_bps": 1000, "tx_bps": 200,
      "ultimo_cambio": "2026-10-10T20:20:00+00:00",
      "presente": true           // false = configurada pero el teléfono no está conectado
    }
  ],
  "config": {                    // copia de lo editable de router.json, para pintar formularios
    "lan": {"interfaz": "enp2s0", "red": "192.168.50.0/24", "ip": "192.168.50.1"},   // red CONFIGURADA (validar contra esta)
    "dhcp": {"inicio": "192.168.50.100", "fin": "192.168.50.250", "lease": "12h"},
    "dns": ["1.1.1.1", "9.9.9.9"],
    "monitor": {"destinos": ["1.1.1.1", "8.8.8.8"], "intervalo_s": 5, "fallos_caida": 3, "exitos_alta": 2},
    "reservas": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.50.10", "nombre": "nas"}],
    "etiquetas": {"aa:bb:cc:dd:ee:ff": "NAS del salón"},
    "bloqueo": {                  // router.json → "bloqueo", TAL CUAL (incluye lista_blanca/lista_negra)
      "habilitado": true, "listas": ["hagezi_pro", "hagezi_tif"],
      "lista_blanca": [], "lista_negra": [],
      "forzar_dns": true, "bloquear_doh": true,
      "actualizar_h": 24, "registro_dns_dias": 30
    },
    "bloqueo_version": "a1b2c3d4e5f60708"   // hex, 16 car.: hash de "bloqueo" SIN lista_blanca/lista_negra
                                             // (router_bloqueo.calcular_version_bloqueo) — mandar en
                                             // bloqueo_config → "version" para evitar pisar un cambio ajeno
    ,
    "firewall": {                 // firewall con reglas propias (FIREWALL_PLAN.md)
      "version": 3,               // entero, +1 en cada cambio (concurrencia optimista)
      "grupos": [
        {"id": "g_ab12cd34", "nombre": "Móviles de los niños",
         "tipo": "mac",            // "mac" | "ip"
         "miembros": ["aa:bb:cc:dd:ee:01"]}
      ],
      "reglas": [
        {"id": "r_ab12cd34", "nombre": "Sin juegos de noche",
         "habilitada": true,
         "accion": "bloquear",     // "permitir" | "bloquear" | "rechazar"
         "origen":  {"tipo": "cualquiera"},   // cualquiera|mac|ip|red|grupo
         "destino": {"tipo": "cualquiera"},   // cualquiera|ip|red|grupo (grupo tipo ip)
         "protocolo": "tcp",       // cualquiera|tcp|udp|tcp_udp|icmp
         "puertos": [{"desde": 443, "hasta": 443}],
         "registrar": false,
         "comentario": ""}
      ],
      "firewall_error": null,      // str|null: mensaje si la instalación nft falló
      "firewall_aciertos": {}      // {id_regla: paquetes} — contadores de nft (columna «Hits»)
    }
  },
  "vecinos": {"aa:bb:cc:dd:ee:ff": "REACHABLE"},  // tabla ARP de la LAN (ip neigh): estado real de conexión
  "dns_emergencia": {            // fail-open del bloqueador (M6/M1, ronda 3; M2, ronda 4) — SIEMPRE presente, nunca se omite
    "activo": false,             // true: dnsmasq lleva varios arranques fallidos seguidos
    "desde": null,               // ISO8601 de cuándo se entró en ESTE episodio de fail-open, o null si activo=false
    "motivo": null,               // texto en español, o null si activo=false
    "nivel_backoff": 0,           // ronda 4: sube un nivel por cada recaída dentro de 24h desde la ÚLTIMA salida
                                   // (nunca se resetea a 0 sólo por salir); baja un nivel tras 24h sanas SEGUIDAS
                                   // fuera de fail-open. Determina cuánto tiempo estable hace falta para la
                                   // próxima salida (30 min * 2^nivel, tope 24h).
    "salida_anterior": null       // ISO8601 de la ÚLTIMA vez que se salió de fail-open, o null si nunca ha pasado
  }
}
```

Mientras `dns_emergencia.activo` es `true`, el bloqueador DNS está
efectivamente apagado por routerd (servers-file vacío, sin log de
consultas, sin `forzar_dns`) hasta que dnsmasq lleve un rato estable sin
caerse (histéresis: al menos 30 min, hasta 24 h si recae varias veces) —
no es un error de configuración que el admin tenga que arreglar desde el
panel, se resuelve solo; el panel debe mostrarlo como un aviso informativo,
no como un fallo que pida acción.

Ronda 4 (M2): `nivel_backoff`/`salida_anterior` (y la hora de la última
salida que los produce) se persisten en `/run/router/dns_emergencia.json`
— sobreviven a un reinicio de routerd. El panel puede mostrar
`nivel_backoff` como una pista de "cuántas veces ha recaído ya" (0 =
nunca ha recaído, o lleva 24h+ sano desde la última vez), pero no hace
falta que ofrezca ninguna acción sobre él — sólo sube/baja solo.

«Conectado» en el panel = MAC presente en `vecinos` con estado REACHABLE/STALE/DELAY/PROBE,
**no** sólo un lease DHCP.

### `wifi` (WAN Wi-Fi: la tarjeta del portátil como cliente de un hotspot)

```json
"wifi": {
  "habilitada": true,          // wifi_wan.habilitada de router.json (interruptor maestro: gestiona la radio)
  "interfaz": "wlp3s0b1",
  "presente": true,            // la interfaz existe en /sys/class/net (hay tarjeta)
  "radio": true,                // última lectura/aplicación de `nmcli radio wifi`; null si aún no se ha tocado
  "conectada_a": "Pixel_8a",   // SSID actual, o null
  "senal": 72,                  // 0-100, o null sin conexión
  "redes": [{"ssid": "Pixel_8a", "prioridad": 50}],   // perfiles propios (WAN-wifi-*) ya guardados — NUNCA la clave
  "escaneo": [{"ssid": "Pixel_8a", "senal": 72, "seguridad": "WPA2", "canal": "6", "bloqueada": false}],
  "escaneo_ts": "2026-10-11T10:00:00+00:00",   // null si nunca se ha pedido wifi_escanear
  "bloqueadas": ["MI-WIFI"]
}
```

Esta misma WAN Wi-Fi aparece TAMBIÉN como una entrada más de `wans` (id
`"wifi-<interfaz>"`, `"telefono"` = el SSID conectado): entra en el
balanceo, el monitor, los pesos automáticos y el firewall exactamente igual
que una WAN de tethering USB. La sección `wifi` de arriba es sólo la
información y los controles específicos de Wi-Fi (radio, redes guardadas,
escaneo) que no tienen sitio en una entrada `wans` genérica.

**Sólo en producción, y nunca con una migración en curso.** Mientras la fase
sea `"preparacion"`, o mientras exista el marcador de migración de
`router_migrar.py` (`/etc/router/migracion-pendiente` — la portátil puede
deshacer la migración en cualquier momento y reconectar el Wi-Fi de casa),
routerd no toca NADA Wi-Fi: no la descubre, no aparece en `wans`, no
gestiona la radio, no hay guarda anti-bucle. `estado.json` → `wifi` sigue
publicándose igualmente con los datos de configuración (`habilitada`,
`interfaz`, `bloqueadas`) pero `presente`/`radio`/`conectada_a`/`senal`/
`redes` no reflejan ninguna lectura nueva de ese ciclo. Las acciones
`wifi_agregar/eliminar/conectar/escanear` del buzón se rechazan
("La WAN Wi-Fi no está disponible ahora…") mientras dure cualquiera de los
dos casos.

**La radio no se consulta en cada ciclo**: `estado.json` → `wifi.radio` es
una caché que routerd resincroniza con el estado REAL (`nmcli radio wifi`)
cada ~60 s (o al entrar en producción / dejar de haber migración en curso),
y sólo emite `nmcli radio wifi on|off` de verdad cuando el estado deseado
(`wifi.habilitada`) difiere del real.

Guardas anti-bucle (cada ciclo, en producción y sin migración en curso,
antes de nada más): la WAN Wi-Fi queda fuera del balanceo (`ip=gw=null` ese
ciclo) si su SSID actual está en `wifi.bloqueadas` (comparación
normalizada: `ssid.strip().casefold()`, así "mi-wifi" o "MI-WIFI "
también cuentan como bloqueadas, no sólo la grafía exacta), si su IPv4 cae
dentro de la red de la LAN, si su puerta de enlace es la IP del propio
router, o si la conexión activa en esa interfaz NO es un perfil propio
(`WAN-wifi-*`) — en producción sólo se admiten los perfiles que ha creado
`wifi_agregar`. Cuando salta, routerd baja la conexión activa
(`nmcli connection down <uuid>`, nunca `device disconnect`, que deja el
dispositivo "unmanaged" un rato) y, si el perfil activo era ajeno, además le
quita el autoconnect (`connection.autoconnect no`) para que NetworkManager
no vuelva a asociarse sola. Se registra un error en el oplog una sola vez
por evento, no en cada ciclo.

## Peticiones (`/var/lib/router/solicitudes/<uuid>.json`)

Siempre: `{"id": "<uuid4>", "usuario": "<login>", "accion": "<accion>", "datos": {...}}`.
El nombre del fichero es `<id>.json`. Se escribe en `<id>.json.tmp` y se renombra
(atómico). Acciones admitidas (cualquier otra → rechazada):

| accion | datos | validación |
|---|---|---|
| `wan_actualizar` | `{"wan": id, "nombre"?: str, "habilitada"?: bool, "peso"?: int, "prioridad"?: int}` | wan existente; nombre 1-32 `[\w .-]`; peso 1-100; prioridad 1-9 |
| `modo` | `{"modo": "balanceo"\|"respaldo"}` | |
| `modo_pesos` | `{"modo_pesos": "auto"\|"manual"}` | fase 4 (A/C): sólo esos dos valores |
| `reserva_agregar` | `{"mac": str, "ip": str, "nombre": str}` | MAC válida; IP dentro de la LAN y fuera del rango dinámico o dentro (se permite) pero no .1 ni red/broadcast; nombre `[a-z0-9-]{1,40}`; sin duplicados de MAC ni IP |
| `reserva_eliminar` | `{"mac": str}` | |
| `dispositivo_etiquetar` | `{"mac": str, "etiqueta": str}` | etiqueta 0-60 caracteres imprimibles (vacía = quitar) |
| `dhcp_rango` | `{"inicio": ip, "fin": ip, "lease": "12h"}` | ambos en la LAN, inicio<fin, no incluyen .1; lease `\d+[mh]` |
| `dns` | `{"servidores": [ip, ...]}` | 1-4 IPv4 válidas |
| `monitor` | `{"destinos": [ip,...], "intervalo_s": int, "fallos_caida": int, "exitos_alta": int}` | 1-4 IPv4; intervalo 3-60; 1-10; 1-10 |
| `wifi_config` | `{"habilitada": bool}` | activa/desactiva la WAN Wi-Fi (gestiona la radio); se guarda en router.json |
| `wifi_agregar` | `{"ssid": str, "clave": str, "prioridad": int}` | ssid 1-32 bytes UTF-8 sin caracteres de control, no bloqueado (normalizado); clave `""` (abierta) o 8-63 ASCII imprimibles; prioridad 0-100; si ya existe un perfil para ese SSID, se reemplaza |
| `wifi_eliminar` | `{"ssid": str}` | borra el perfil `WAN-wifi-*` de ese SSID (nunca otro perfil NM); comprueba el código de `nmcli connection delete` |
| `wifi_conectar` | `{"ssid": str}` | `nmcli -w 10 connection up` del perfil propio de ese SSID; si se agota esa espera no se trata como fallo (puede que el teléfono tarde): responde `ok` "conectando…" y el resultado de verdad se ve en `estado.json` |
| `wifi_escanear` | `{}` | responde EN SEGUIDA "Escaneo lanzado…" (`nmcli device wifi rescan`, no bloqueante) — nunca espera el escaneo entero, que puede tardar más que el sondeo del panel (~6 s); el resultado aparece unos segundos después en `estado.json` → `wifi.escaneo`/`escaneo_ts` |
| `bloqueo_config` | `{habilitado: bool, listas: [id,...], forzar_dns: bool, bloquear_doh: bool, actualizar_h: int, registro_dns_dias: int, version?: str}` | TODOS los campos obligatorios salvo `version` (reemplaza la sección entera salvo `lista_blanca`/`lista_negra`, que se conservan); `listas` sólo ids del catálogo fijo (`router_bloqueo.CATALOGO`: `hagezi_light`, `hagezi_multi`, `hagezi_pro`, `hagezi_pro_plus`, `hagezi_tif`, `hagezi_doh`, `hagezi_nsfw`, `hagezi_gambling` — las URLs NUNCA vienen del panel); `actualizar_h` 6-168; `registro_dns_dias` 1-365; `version` (hex, 16 caracteres — petición del panel, ronda 3) es la `bloqueo_version` que el panel vio en `estado.json` al abrir el formulario — si se manda y no coincide con la actual, se rechaza ENTERA sin aplicar nada con el mensaje «La configuración cambió mientras editabas; recarga la página» (concurrencia optimista: evita que dos pestañas/admins se pisen sin darse cuenta) |
| `bloqueo_lista` | `{tipo: "blanca"\|"negra", accion: "agregar"\|"quitar", dominio: str}` | dominio validado con la misma regex estricta que usa `router_bloqueo.py` para parsear las listas (IDN→punycode incluido); máx. 5000 entradas por lista; "quitar" de un dominio que no está → rechazada |
| `bloqueo_actualizar` | `{forzar?: bool}` | nunca muta `router.json`; routerd lanza `systemctl --no-block start router-bloqueo.service` (no bloqueante: sólo encola el trabajo); `forzar: true` (BAJA4, ronda 3) deja un marcador de un solo uso que hace que esa pasada se SALTE la guarda de variación ±50% (útil si el admin sabe que un cambio grande es legítimo) |
| `bloqueo_probar` | `{dominio: str}` | nunca muta `router.json`, nunca hace red: `mensaje` de la respuesta lleva "BLOQUEADO: …"/"NO bloqueado: …" con la razón (lista negra/blanca manual, canario DoH, o el nombre de la lista HaGeZi que lo bloquea), consultando sólo lo ya generado en `/var/lib/router/bloqueo/` |
| `fw_regla_guardar` | `{version: int, regla: {...}, posicion?: int}` | firewall con reglas propias (FIREWALL_PLAN.md). `version` es la `firewall.version` que el panel vio en `estado.json` → `config.firewall` (concurrencia optimista: si no coincide → «La configuración cambió mientras editabas; recarga la página»). `regla` sin `id` = crear (la id la genera el core: `r_`+8 hex, nunca el panel); con `id` = editar (debe existir). Campos: `nombre` `[A-Za-z0-9_ .áéíóúñÁÉÍÓÚÑ-]{1,40}` (no solo espacios), `habilitada` bool, `accion` `permitir\|bloquear\|rechazar`, `origen`/`destino` `{tipo, valor?}` (`cualquiera\|mac\|ip\|red\|grupo`; mac sólo origen; grupo destino debe ser tipo ip), `protocolo` `cualquiera\|tcp\|udp\|tcp_udp\|icmp`, `puertos` (sólo tcp/udp/tcp_udp, destino, máx. 15, 1-65535, desde≤hasta; lista, no otro tipo), `registrar` bool, `comentario` 0-120 sin caracteres de control ni invisibles Unicode. `posicion` al editar mueve la regla. Rechazada si: versión incorrecta, nombre/comentario inválidos, origen/destino contra `lan.ip` (ip exacta o /32), origen fuera de la LAN, destino `cualquiera` o `0.0.0.0/0` con acción `bloquear`/`rechazar` sin otra condición cuando el origen cubre la LAN entera («cortaría el Internet de todos»), más de 200 reglas. Tras validar, routerd genera el texto nft y lo valida con `nft -c -f` ANTES de guardar: si nft lo rechaza, `ok=false` con el error y la config no se guarda (HIGH-3) |
| `fw_regla_eliminar` | `{version: int, id: str}` | borra la regla con esa id (`r_[0-9a-f]{8}`); versión optimista |
| `fw_regla_mover` | `{version: int, id: str, posicion: int}` | mueve la regla a esa posición (0 = la primera); versión optimista. Con la lista vacía → «No hay reglas que mover» |
| `fw_regla_activar` | `{version: int, id: str, habilitada: bool}` | activa/desactiva la regla; versión optimista |
| `fw_grupo_guardar` | `{version: int, grupo: {id?, nombre, tipo, miembros}}` | `id` opcional: sin id = crear (la genera el core: `g_`+8 hex); con id existente = editar. `tipo` `mac\|ip`; `miembros` MACs o IPv4, máx. 256 (sin duplicados tras normalizar). Los miembros ip deben estar en la LAN y no ser la IP del router. No se puede cambiar el tipo de un grupo que alguna regla use como destino (HIGH-3). Rechazado si más de 50 grupos. Nombre `[A-Za-z0-9_ .áéíóúñÁÉÍÓÚÑ-]{1,40}` |
| `fw_grupo_eliminar` | `{version: int, id: str}` | rechazada si alguna regla usa ese grupo (origen o destino) — dice cuál; versión optimista |

**Como mucho una acción `wifi_agregar/eliminar/conectar/escanear` se
EJECUTA de verdad por ciclo** (watchdog): si llegan varias a la vez, las
siguientes se quedan SIN reclamar en el buzón (el panel las ve
"pendiente") hasta el ciclo siguiente. Las lecturas de nmcli que hace
routerd para publicar `estado.json` (señal, redes guardadas…) tienen un
tiempo límite de 4 s cada una; si una se agota, el resto de lecturas Wi-Fi
de ESE ciclo se saltan (se publican los últimos valores conocidos) en vez
de arriesgar el ciclo entero.

**Importante (seguridad de la clave Wi-Fi):** `wifi_agregar`, `wifi_eliminar` y
`wifi_conectar` son, a diferencia de las demás acciones, VALIDADAS en
`peticiones.py` pero NUNCA mutan `router.json` — la clave en particular
**jamás** se guarda ahí, ni en `estado.json`, ni se registra en el oplog
(`datos.clave` se sustituye por `"***"` antes de escribir cualquier
registro), ni aparece en el mensaje de la respuesta. Routerd las ejecuta de
verdad escribiendo un perfil propio de NetworkManager (ver más abajo) y
llamando a `nmcli`; la clave sólo existe en ese fichero (0600, root) y en
memoria mientras se procesa la petición — nunca pasa por `argv`/`ps`. Si
`nmcli connection load` rechaza el perfil, el keyfile recién escrito se
borra (no debe quedar huérfano en disco con la clave dentro sin que ningún
perfil NM lo respalde). El fichero de la petición en el buzón (que SÍ
contiene la clave en claro, porque la escribió el panel) se borra en cuanto
se procesa, se acepte o se rechace, igual que cualquier otra petición.

**El SSID bloqueado se compara normalizado** (`ssid.strip().casefold()`),
tanto al validar `wifi_agregar` como en la guarda anti-bucle: el panel debe
aplicar la misma normalización al avisar en el formulario de que un SSID
está bloqueado (para no decir "SSID disponible" y que el backend lo
rechace después por una mayúscula o un espacio de más).

### Perfiles Wi-Fi propios de routerd

Las redes Wi-Fi guardadas desde el panel son perfiles de NetworkManager
propios, nunca router.json: `/etc/NetworkManager/system-connections/WAN-wifi-<slug>.nmconnection`
(formato keyfile, 0600 root; `<slug>` = ASCII seguro del SSID + sufijo hash
corto, para que dos SSID distintos nunca colisionen en el mismo fichero).
Contenido: `type=wifi`, `interface-name=<wifi_wan.interfaz>`, un `uuid`
estable derivado del SSID (`uuid5`, no al azar: así reemplazar la misma red
reutiliza el mismo `connection.uuid` en vez de dejar perfiles fantasma), el
SSID como lista de bytes (`ssid=104;111;…;`, nunca como texto escapado a
mano), `wpa-psk` con la clave si no es abierta —escapada al formato
keyfile/GKeyFile: `\` → `\\`, un espacio en los extremos del valor → `\s`—,
`autoconnect=true` con la prioridad pedida, IPv4 automática con
`route-metric=750` e `ignore-auto-dns=true` (no debe competir con la
ruta/DNS de la LAN ni de las demás WAN), IPv6 deshabilitada. Se escribe con
el mismo `escribir_atomico()` que usa el resto de routerd (temporal
exclusivo + `fsync` + `rename` atómico) y se activa con
`nmcli connection load <ruta>`; si nmcli lo rechaza, el fichero se borra.
`wifi_eliminar` sólo borra perfiles cuyo nombre empiece por `WAN-wifi-`
(nunca otro perfil NM, aunque el admin lo haya creado a mano con nmcli), y
comprueba el código de `nmcli connection delete`.

**Systemd (`systemd/routerd.service`)**: `ProtectSystem=full` deja `/etc`
de sólo lectura salvo lo listado en `ReadWritePaths`; sin
`-/etc/NetworkManager/system-connections` ahí, `wifi_agregar`/`wifi_eliminar`
fallarían con `EROFS` al intentar escribir o borrar el keyfile. El `-`
inicial ignora la ruta si no existiera (instalación sin NetworkManager).

## Respuestas (`/var/lib/router/respuestas/<uuid>.json`)

`{"id": ..., "ok": true|false, "mensaje": "texto en español", "aplicado": "ISO8601"}`.
El panel espera hasta ~10 s a que aparezca; si no, informa «pendiente».

## `/run/router/adb.json`

Lo publica `router_adb.py` (vigilante APARTE de routerd — ver cabecera del
módulo — que mantiene siempre activo el tethering USB de los teléfonos
Android por ADB), cada `adb_tether.intervalo_s` (router.json, defecto 10 s).
Atómico, 0644 root, para que el panel lo pueda mostrar más adelante.
Es una **lista** (no un objeto con envoltorio), una entrada por teléfono que
aparezca en `adb devices` ese ciclo:

```json
[
  {
    "serial": "R58M123ABC",
    "modelo": "SM-A515F",
    "android": "16",
    "estado_adb": "device",
    "funciones": ["adb", "rndis"],
    "interfaz": "enx0a1b2c3d4e5f",
    "compartiendo": true,
    "ultima_accion": "compartiendo por USB (rndis)",
    "ultimo_error": null,
    "ts": "2026-10-11T10:00:00+00:00"
  }
]
```

- `estado_adb`: tal como lo reporta `adb devices` — `"device"` (autorizado y
  listo), `"unauthorized"` (falta aceptar la depuración USB en el
  teléfono), `"offline"`, `"no permissions"` o `"desconocido"` (cualquier
  otro valor que no sea uno de los anteriores).
- `funciones`/`interfaz`/`compartiendo`/`ultima_accion`/`ultimo_error` sólo
  se leen de verdad cuando `estado_adb == "device"` (es el único estado en
  el que el teléfono acepta `shell`); en cualquier otro estado quedan
  `funciones: []`, `interfaz: null`, `compartiendo: false` y `ultima_accion`
  describe el propio estado (p. ej. "sin autorizar: acepta la depuración
  USB en el teléfono"). `modelo`/`android` vienen de `getprop` (recortados a
  64 caracteres imprimibles, sin caracteres de control) y se leen UNA sola
  vez por serial (se cachean mientras el teléfono siga conectado).
- `funciones` es lo que reporta `svc usb getFunctions` (filtrado: sólo
  tokens `[a-z_]{1,16}`, cualquier otra cosa se descarta). `interfaz` es el
  nombre de CUALQUIER interfaz de red del PROPIO portátil (sin filtrar por
  driver — da igual cómo se llame) cuyo dispositivo USB padre tiene este
  mismo serial — o `null` si no existe ninguna — comprobado de verdad en
  `/sys/class/net`, no sólo confiando en lo que dice adb.
- `compartiendo` es `true` sólo si `funciones` contiene `rndis` o `ncm` Y
  además existe esa `interfaz` en el kernel del portátil AHORA MISMO. Si
  adb dice que comparte pero NO hay interfaz, `compartiendo` es `false` y
  `ultima_accion`/`ultimo_error` llevan "el teléfono dice que comparte pero
  no aparece interfaz en el router" — este caso NUNCA manda ninguna orden
  (ver más abajo: sería inútil, el teléfono ya cree que está compartiendo),
  sólo se avisa una vez por el oplog cuando empieza a pasar.
- Las ÚNICAS órdenes que este vigilante ejecuta en el teléfono son
  `svc usb getFunctions`, `svc usb setFunctions rndis|ncm`,
  `getprop ro.product.model`/`ro.build.version.release` y
  `getprop sys.boot_completed` — nunca nada más, y siempre con el serial
  validado contra una regex estricta (`router_adb.RE_SERIAL`) antes de
  construir el comando.
- **Diseño conservador** (nunca se manda una orden "a la primera"):
  - Si la lectura de `getFunctions` falla, no se hace NADA ese ciclo (ni
    orden, ni se cuenta como lectura, ni cambia `compartiendo`, ni oplog):
    se mantiene lo último que se supo con certeza.
  - `setFunctions` SÓLO se intenta cuando adb dice que NO hay ni `rndis` ni
    `ncm`, y sólo tras 3 lecturas VÁLIDAS consecutivas diciendo lo mismo.
    Si adb dice que SÍ hay `rndis`/`ncm` pero falta la interfaz del kernel,
    nunca se manda nada (es un caso distinto: el teléfono ya cree que
    comparte, lo que falla es otra cosa — revisar el cable/puerto USB).
  - Antes de mandar `setFunctions` se exige `getprop sys.boot_completed`
    == `"1"`; si el teléfono todavía está arrancando, no se toca nada ese
    ciclo (no consume cooldown ni backoff).
  - Tras cada intento, un cooldown que empieza en 60 s y se DOBLA cada vez
    que el anterior no cuaja, hasta un tope de 30 min — nunca más de una
    orden `setFunctions` por serial mientras el cooldown esté activo. Si
    `rndis` no cuaja, el siguiente intento prueba `ncm` (y alterna); la
    función que SÍ funcionó se recuerda por serial, y al volver a compartir
    de verdad se olvida cuál se estaba probando (el próximo episodio
    empieza limpio).
  - El estado de cooldown/backoff de un serial sobrevive a que desaparezca
    un rato de `adb devices` (USB flojo, reinicio corto…): sólo se olvida
    tras 30 minutos sin verse.
  - La caída momentánea de la conexión adb justo al cambiar de función USB
    es normal y no se trata como error ni se registra en el oplog.
  - Si `adb devices` reporta `"offline"` o un estado que no se reconoce
    (`"desconocido"`), NO se fuerza `compartiendo` a `false`: se conserva
    el último valor sabido con certeza (perder adb un instante no significa
    que el teléfono haya dejado de compartir) y no se escribe nada al
    oplog por ese motivo. Con `"unauthorized"` o `"no permissions"` sí se
    fuerza a `false` (ahí no hay ninguna duda: sin autorización no hay
    `shell`, y sin `shell` este vigilante no puede confirmar nada).

### Eventos `adb_tether` en el oplog

`router_adb.py` añade líneas a `/var/log/router/operaciones.log` (mismo
fichero y formato que usa routerd — `accion: "adb_tether"`) **sólo cuando
algo cambia**, nunca una por ciclo:

| Cuándo | `ok` | `mensaje` |
|---|---|---|
| Un teléfono pasa a compartir (de no compartir a compartir) | `true` | «Activado compartir Internet por USB en \<modelo o serial\> (\<serial\>)» |
| Un teléfono deja de compartir (regresión) | `false` | «Se ha dejado de compartir Internet por USB en \<modelo o serial\> (\<serial\>)» |
| Aparece un teléfono con `estado_adb="unauthorized"` que antes no lo estaba | `false` | «Teléfono no autorizado detectado (\<serial\>): Acepta «Permitir depuración USB» en el teléfono» |
| adb dice que un teléfono comparte pero no aparece su interfaz en el router (nuevo, antes no pasaba) | `false` | «El teléfono \<modelo o serial\> dice que comparte pero no aparece ninguna interfaz en el router: revisa el cable/puerto USB» |

`datos` lleva sólo `{"serial": "..."}`; `usuario` es siempre `"sistema"`
(igual que los eventos propios de routerd como `wan_nueva`).

## `/run/router/bloqueo.json`

Lo publica `router_bloqueo.py` (proceso APARTE, oneshot — ver cabecera del
módulo, mismo patrón que `router_adb.py`), cada vez que termina una pasada
(lanzado por `router-bloqueo.timer` cada `bloqueo.actualizar_h` horas, o por
routerd a demanda con la acción de buzón `bloqueo_actualizar`). Atómico,
0644 root:

```json
{
  "habilitado": true,
  "listas": [
    {"id": "hagezi_pro", "nombre": "HaGeZi Pro", "dominios": 234567,
     "actualizada": "2026-10-11T10:00:00+00:00", "error": null},
    {"id": "hagezi_tif", "nombre": "HaGeZi Threat Intelligence Feeds", "dominios": 1976192,
     "actualizada": "2026-10-11T10:00:05+00:00", "error": null}
  ],
  "total_dominios": 2100000,
  "generado": "2026-10-11T10:00:10+00:00",
  "siguiente": "2026-10-12T10:00:10+00:00",
  "activo": true
}
```

- `listas[].error`: `null` si la descarga/caché salió bien; si no, un texto
  en español (fallo de red, HTTP, límite de tamaño superado, redirección no
  HTTPS, plazo total agotado, o `"caché anterior: <motivo>"` cuando la
  descarga falló pero se pudo usar la caché de la vez anterior). `dominios`
  es el recuento YA filtrado (nunca una línea cruda sin validar llega a
  contar aquí).
- `activo`: `false` si `dnsmasq --test` rechazó la config nueva (se
  mantiene la anterior), si dnsmasq no llegó a estar activo tras el
  `SIGHUP` (se restaura la anterior, o se deja vacía si eso también
  falla), o si saltó la guarda de variación ±50% (ver más abajo) — en
  cualquiera de esos casos hay además un campo `"error"` a nivel raíz.
  `"recortado": true` si el total superó la cota global (1 500 000) y se
  truncó.
- `habilitado=false`: `listas` queda vacía y `total_dominios` en 0 (el
  `servers-file` se deja vacío, nunca se borra — routerd lo referencia
  SIEMPRE, exista lo que exista dentro).
- Catálogo de listas (fijo en código, `router_bloqueo.CATALOGO`; las URLs
  **nunca** vienen del panel, sólo estos ids): `hagezi_light`,
  `hagezi_multi`, `hagezi_pro`, `hagezi_pro_plus`, `hagezi_tif`
  (amenazas/malware/phishing), `hagezi_doh` (servidores DNS cifrados
  conocidos — se añade sola si `bloquear_doh` está activo, aunque no esté
  en `listas`), `hagezi_nsfw`, `hagezi_gambling`.
- **Dominios protegidos** (fijos en código, `router_bloqueo.PROTEGIDOS_FIJOS`
  + los hosts reales de `CATALOGO` + el propio `router.json` → `dominio`
  con sus subdominios): nunca se bloquean, aunque aparezcan en una lista o
  en `lista_negra` — lo que el propio router necesita para funcionar
  (GitHub/raw.githubusercontent.com, IONOS, Let's Encrypt, Debian, NTP,
  `arpa`/`home.arpa`, el dominio de la casa). `lista_negra` tampoco admite
  un sufijo público de dos etiquetas pelado (`co.uk`, `com.es`...) — sí un
  dominio concreto debajo de uno.
- `router.json` → `bloqueo`: `{habilitado, listas: [id,...], lista_blanca:
  [dominio,...], lista_negra: [dominio,...], forzar_dns, bloquear_doh,
  actualizar_h (6-168), registro_dns_dias (1-365)}` — ver `bloqueo_config`/
  `bloqueo_lista` en la tabla de peticiones.
- Caché de cada lista: `/var/lib/router/bloqueo/<id>.txt` (texto crudo
  descargado, con su `.<id>.meta.json` de ETag/Last-Modified) — se usa tal
  cual (sin red) si la próxima descarga falla, y es lo que consulta
  `bloqueo_probar` (routerd → `router_bloqueo.comprobar_dominio()`, que
  decide siguiendo el mismo criterio de especificidad que dnsmasq: un
  dominio protegido gana siempre; entre lista negra/blanca/catálogo gana
  el más específico). `/var/lib/router/bloqueo/.ultimo.json` guarda el
  total y las listas de la última pasada CON ÉXITO, para la guarda de
  variación.
- **Config activa de dnsmasq — `servers-file`, no `conf-file`**:
  `/var/lib/router/bloqueo/dnsmasq-bloqueo.conf`, con SÓLO líneas
  `server=/dominio/` (bloqueado: dnsmasq no tiene a quién preguntar →
  NXDOMAIN, también para los subdominios) y `server=/dominio/#` (excepción
  — lista blanca y dominios protegidos: "usa los servidores normales para
  este dominio", que dnsmasq aplica por ser la coincidencia MÁS
  ESPECÍFICA, sin importar el orden de las líneas — así un hijo en la
  lista blanca "agujerea" un padre bloqueado sin desbloquear a sus
  hermanos; comprobado empíricamente con dnsmasq 2.93). `dnsmasq_conf.py`
  (routerd) referencia este fichero con `servers-file=` SIEMPRE,
  incondicionalmente — routerd garantiza que existe (vacío si hace falta);
  a diferencia de un `conf-file=` genérico, dnsmasq RELEE un
  `servers-file=` con un simple `systemctl kill -s HUP dnsmasq`, sin cortar
  el DHCP. Si el contenido no cambió desde la última vez (comparación por
  hash), `router_bloqueo.py` no toca nada.
- **Fail-open** (si dnsmasq lleva 3 arranques fallidos CONSECUTIVOS, por el
  motivo que sea): routerd vacía el `servers-file` él mismo, quita
  `log-queries`/`log-facility` de la config de la LAN, y desactiva la
  cadena `redirigir_dns` (forzar_dns) hasta que dnsmasq vuelva a estar
  activo — con oplog claro al entrar y al salir (`bloqueo_fail_open`).
- Log de consultas DNS (para estadísticas del panel): `/var/log/router/dns.log`
  (`log-queries=extra` si el dnsmasq instalado lo admite, si no
  `log-queries` simple — routerd lo detecta solo; `log-async=25`), rotado a
  diario (+ `maxsize 200M`, comprobado cada hora por
  `router-logrotate-dns.timer`) por `/etc/logrotate.d/router-dns` (lo
  regenera routerd según `bloqueo.registro_dns_dias`).
- `router-bloqueo.timer`: `OnUnitActiveSec` se ajusta a `bloqueo.actualizar_h`
  mediante un drop-in que regenera routerd
  (`/etc/systemd/system/router-bloqueo.timer.d/override.conf` +
  `systemctl daemon-reload`) — el directorio `.timer.d` debe existir ya en
  la instalación.

## Estadísticas (`/var/lib/router/estadisticas/estadisticas.db`)

Lo publica `router_estadisticas.py` (proceso APARTE, Type=notify +
watchdog propio — mismo patrón que `router_adb.py`; ver cabecera del
módulo), cada `router_estadisticas.intervalo_s` de `router.json` (defecto
y recomendado 60 s). SQLite en modo WAL, directorio `/var/lib/router/
estadisticas` 0750 root:routerpanel y fichero `estadisticas.db` 0640
root:routerpanel — **el panel sólo lo abre en modo lectura** (no escribe
nunca ahí; sigue valiendo el contrato de arriba: ningún componente sin
privilegios escribe estado, sólo lo lee). Transacciones cortas por tabla
(nunca una transacción para todo el ciclo): el panel puede leer en
paralelo sin bloquearse más de lo imprescindible.

### Esquema (exacto — el panel lo usa tal cual)

```sql
-- ts epoch UTC al minuto; rx = bajada, tx = subida (mismo sentido que estado.json -> wans).
CREATE TABLE trafico_wan(
  ts INTEGER, wan TEXT, nombre TEXT, rx_bytes INTEGER, tx_bytes INTEGER,
  latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER, PRIMARY KEY(ts, wan));
-- misma forma, por hora (ts al INICIO de la hora); latencia/perdida = media, en_balanceo = máximo de la hora.
CREATE TABLE trafico_wan_hora(ts INTEGER, wan TEXT, nombre TEXT, rx_bytes INTEGER, tx_bytes INTEGER,
  latencia_ms REAL, perdida_pct REAL, en_balanceo INTEGER, PRIMARY KEY(ts, wan));
-- por minuto, por dispositivo LAN.
CREATE TABLE trafico_disp(ts INTEGER, ip TEXT, mac TEXT, nombre TEXT,
  bajada_bytes INTEGER, subida_bytes INTEGER, conexiones INTEGER, PRIMARY KEY(ts, ip));
-- misma forma, por hora; bajada/subida = suma, conexiones = MÁXIMO de la hora.
CREATE TABLE trafico_disp_hora(ts INTEGER, ip TEXT, mac TEXT, nombre TEXT,
  bajada_bytes INTEGER, subida_bytes INTEGER, conexiones INTEGER, PRIMARY KEY(ts, ip));
CREATE TABLE conexiones(ts INTEGER PRIMARY KEY, total INTEGER);   -- por minuto
CREATE TABLE dns_hora(hora INTEGER, cliente TEXT, dominio TEXT,
  consultas INTEGER, bloqueadas INTEGER, PRIMARY KEY(hora, cliente, dominio));
CREATE TABLE meta(clave TEXT PRIMARY KEY, valor TEXT);   -- 'version_esquema'='1', 'ultimo_ts', 'ultima_hora_rollup'
```

Más índices por `ts`/`(ip, ts)`/`(cliente, hora)` para las consultas
típicas del panel (rango de tiempo, por dispositivo, por cliente DNS), más
un índice CUBRIDOR `idx_dns_hora_cubre (hora, dominio, consultas,
bloqueadas)` para "consultas/bloqueadas por dominio en este rango de
horas" sin tocar la tabla (sustituye a un `idx_dns_hora_hora (hora)` más
antiguo, redundante con el índice automático de la PK — `DROP INDEX IF
EXISTS` lo retira solo en una base ya existente al reabrirla).

### Semántica de cada fuente

- **`trafico_wan`**: delta de `estado.json` → `wans[].rx_bytes`/`tx_bytes`
  desde la lectura anterior — SÓLO si esa WAN está `presente` Y tiene
  `interfaz` (revisión Opus, ALTA3): para una WAN ausente o sin medir
  todavía, `estado.json` publica un rx/tx "sintético" (normalmente 0) que
  NO es una medición real — se ignora entero y se OLVIDA la línea base,
  para que al volver a estar presente el primer ciclo sea "primera
  lectura" (sin delta) en vez de contar de golpe todo su contador de vida
  como tráfico de un solo minuto. Un cambio de `interfaz` bajo el MISMO
  `id` (otro teléfono, u otro nombre de interfaz) también invalida la
  línea base: los contadores del kernel son de otro dispositivo. Un delta
  **negativo** (la interfaz se reinició de verdad) se **descarta** igual.
  `latencia_ms`/`perdida_pct`/`en_balanceo` se copian tal cual de
  `estado.json`, sin acumular (salvo dentro del mismo minuto, ver UPSERT
  más abajo).
- **`trafico_disp`**: delta de los sets nft `disp_sube`/`disp_baja` (ver
  `core/nft_conf.py` — son `set` con un `counter` por elemento añadido
  desde la EXPRESIÓN del `update` ("ip saddr counter"), NO un `map` con
  `type ipv4_addr : counter`: ese diseño pasa `nft -c` sin error pero el
  KERNEL lo rechaza al cargar de verdad ("Operation not supported"),
  comprobado cargando la tabla con root en un netns real — `nft -c` sólo
  analiza sintaxis, no basta para esto; se leen con
  `nft -j list set inet router disp_sube`/`disp_baja`, desde la cadena
  `contabilidad_disp`, de prioridad MAYOR que `reenvio` en el mismo hook
  — ver la nota de `contabilidad_disp` más abajo).
  `subida_bytes` = delta de `disp_sube` (tráfico que ENTRA por la LAN:
  bytes que el dispositivo sube); `bajada_bytes` = delta de `disp_baja`
  (tráfico que SALE hacia la LAN: bytes que el dispositivo baja). Mismo
  criterio de reinicio que arriba — y aquí ocurre más a menudo: cada
  elemento expira solo (pasado `timeout` sin tráfico que lo refresque) y,
  además, la tabla `inet router` entera se reinstala (`destroy` + recrear)
  cada vez que cambia `router.json`, lo que vacía estos sets. Además
  (BAJA9), se compara el `handle` del set entre ciclos: si cambió (la
  tabla se reinstaló de verdad), la primera lectura tras el cambio se
  trata como un `0 → N` limpio (delta = el valor entero), no como "sin
  datos" — así no se pierde ese primer minuto sólo porque el valor nuevo
  "parecía" un reinicio ambiguo. Un fallo de `nft` en UN set (BAJA8)
  nunca borra la línea base del OTRO set ni la suya propia: ese ciclo
  simplemente no aporta datos para esa dimensión (columna `NULL` en vez
  de 0), se reintenta en el siguiente. Si además ha pasado mucho más
  tiempo del normal desde el ciclo anterior (routerd/el propio proceso
  atascados — más de 2× `intervalo_s`, revisión Opus, punto A), el delta
  de ESE ciclo se descarta entero (igual en `trafico_wan`): meter de
  golpe el tráfico de varios minutos en una sola fila de 60 s se vería
  como un pico falso de N veces lo real.

  **Las líneas base (de `trafico_wan` Y de `trafico_disp`, con el `handle`
  de cada set y el reloj real del último ciclo) sobreviven a un reinicio
  del PROCESO** — comprobado de verdad con el e2e con root: cada
  `--una-vez` (y cada reinicio real del servicio: `systemctl restart`,
  un fallo, una actualización…) es un proceso nuevo, así que guardarlas
  sólo en memoria las perdía siempre, y la primera lectura tras CUALQUIER
  reinicio se quedaba sin delta. Se persisten en `meta` (clave
  `estado_runtime`, JSON: `tiempo_ultimo_ciclo`, `wan_prev`, `disp_prev`,
  `disp_handle`), en la MISMA transacción que `meta.ultimo_ts` al final de
  cada ciclo, y se cargan UNA sola vez al arrancar el proceso. No hace
  falta comprobar su antigüedad aparte: la propia regla del "hueco de
  reloj grande" (punto A, de arriba) ya las descarta si `tiempo_
  ultimo_ciclo` persistido queda a más de 2×`intervalo_s` del momento de
  cargarlas.

  `--una-vez` escribe en **stderr** (nunca por el `logging` normal, que va
  a stdout) un resumen de una línea con las filas guardadas por tabla —
  `RESUMEN --una-vez: conexiones=1 dns_hora=0 trafico_disp=1 trafico_wan=1`
  — para que una ejecución desde un script (p. ej. el e2e) nunca se quede
  sin ninguna pista de qué pasó.

  `mac`/`nombre` se resuelven por IP contra `estado.json` →
  `config.reservas`/`config.etiquetas` (equipos con reserva) y, para
  cualquier otro equipo, `/var/lib/misc/dnsmasq.leases` (ya es un fichero
  que el panel puede leer — ver tabla de ficheros más arriba); `estado.json`
  → `vecinos` NO sirve para esto porque va al revés (clave MAC, no IP).
  `conexiones`: cuenta de `/proc/net/nf_conntrack` agrupando por la IP
  origen de la tupla ORIGINAL — `null` (no `0`) si ese ciclo se consideró
  demasiado caro. Esa decisión se toma ANTES de abrir el fichero (si
  `/proc/sys/net/netfilter/nf_conntrack_count`, mucho más barato de leer,
  ya supera el límite, ni se abre `/proc/net/nf_conntrack`) y, si se abre,
  se itera línea a línea cortando en cuanto se pasa el límite — nunca se
  carga el fichero entero en memoria primero (MEDIA7).
- **`conexiones`**: `/proc/sys/net/netfilter/nf_conntrack_count` tal cual,
  cada minuto; si no se puede leer (módulo no cargado…) no se escribe fila
  ese minuto (hueco, nunca un 0 falso).
- **`dns_hora`**: lectura INCREMENTAL de `/var/log/router/dns.log` por
  inodo+offset, persistida en la tabla `meta` (clave `dns_posicion`) EN LA
  MISMA transacción que los agregados de ese ciclo (BAJA12 — nunca puede
  quedar la posición avanzada sin haber contado esas líneas, ni al revés);
  el primer arranque de verdad (sin posición previa) NO procesa el
  histórico, se coloca cerca del final. `copytruncate` (tamaño nuevo <
  offset ya leído) recupera primero lo que quedara sin leer desde `.1` (la
  copia que logrotate toma ANTES de truncar, si todavía llega a ese
  offset) y reinicia desde 0 en el fichero ya truncado; una rotación de
  verdad (inodo distinto) termina de leer el `.1` viejo (si su inodo
  coincide) y sigue con el fichero nuevo desde el principio. Una "línea"
  sin salto que agote todo el presupuesto de un ciclo (log corrupto) se
  descarta y se avanza, nunca se queda esperando para siempre. Cada ciclo
  procesa como máximo ~8 MB de log (nunca arriesga el watchdog por un pico
  de tráfico DNS); si hace falta más de un ciclo para ponerse al día,
  sigue exactamente donde lo dejó. Si el fichero EXISTE pero no se puede
  abrir (permisos: ver `SupplementaryGroups=dnsmasq` en el `.service`,
  ALTA1), se avisa por el log UNA sola vez, no en cada ciclo.

  Con `log-queries=extra` (lo que pide `dnsmasq_conf.py` cuando el
  dnsmasq instalado lo admite), cada línea de consulta/resultado lleva
  `<id> <ip>/<puerto> ...`, lo que permite emparejar la línea
  `query[TIPO] dominio from IP` con su respuesta por el `id`. **El
  timestamp de syslog es hora LOCAL del sistema, no UTC** (como cualquier
  syslog clásico) — se convierte con `zoneinfo` (la zona IANA real del
  sistema, leída de `$TZ` o de `/etc/localtime`) + `fold` explícito (PEP
  495), nunca con un `mktime` a ciegas: la hora que se repite en el cambio
  de horario de otoño (p. ej. 02:30 en Europe/Rome, finales de octubre)
  se resuelve de forma DETERMINISTA (la primera ocurrencia, `fold=0`) en
  vez de depender de cómo decida la libc de turno.
  Un dominio bloqueado por el `servers-file` del bloqueador
  (`server=/dominio/` SIN dirección) se resuelve con la línea
  `<id> <ip>/<puerto> config dominio is NXDOMAIN` (comprobado con un
  dnsmasq 2.93 real) — pero esa MISMA línea también sale de
  `local=/<dominio de casa>/`, `local=/home.arpa/` (incondicional) y de
  `bogus-priv` (PTR de IPs privadas bajo `*.in-addr.arpa`/`*.ip6.arpa`) —
  NINGUNO de esos tres es un bloqueo real, así que se excluyen
  explícitamente (MEDIA6: comprobar contra el servers-file activo del
  bloqueador sería más preciso pero caro para lo que aporta aquí; en la
  práctica ese fichero nunca contiene estos nombres — son los
  `PROTEGIDOS_FIJOS` de `router_bloqueo.py` — así que la exclusión nunca
  tapa un bloqueo de verdad). Un NXDOMAIN que SÍ pasó por `forwarded`/
  `reply` (el dominio está en la excepción `server=/x/#` de lista blanca,
  o el servidor remoto de verdad no tiene ese nombre) tampoco cuenta como
  bloqueo, sólo como consulta normal; ni `cached`/`config ... is
  <ip-fija>` (p. ej. el centinela de `router_bloqueo.py`). El centinela
  `bloqueo-centinela.router-casa.invalid` y sus subdominios se ignoran por
  completo (ni consultas ni bloqueadas). Sin `log-queries=extra` (dnsmasq
  más viejo) no hay `id`/cliente en estas líneas: no se intenta emparejar
  nada con una heurística — se ignoran, antes que arriesgar atribuir una
  consulta al cliente/dominio equivocado.

  **Dos ciclos en el MISMO minuto suman, nunca se pisan** (MEDIA5 — puede
  pasar con `intervalo_s` corto, o un reinicio del servicio a mitad de
  minuto): `rx_bytes`/`tx_bytes`/`bajada_bytes`/`subida_bytes` se SUMAN
  sobre lo que ya hubiera esa fila; `conexiones`/`en_balanceo` toman el
  MÁXIMO; `latencia_ms`/`perdida_pct`/`nombre`/`mac` se quedan con el
  valor más reciente no nulo. `dns_hora` ya sumaba así desde el principio.

### WAL, permisos de `-wal`/`-shm`, y cierre limpio (revisión Opus)

Mientras `router_estadisticas.py` está en marcha, `estadisticas.db` vive
en modo WAL (mejor para lecturas concurrentes del panel mientras este
servicio escribe) — eso significa que, además del `.db`, existen
`estadisticas.db-wal` y `estadisticas.db-shm`. **Ambos deben llevar el
MISMO modo/grupo que el `.db`** (0640 root:routerpanel): SQLite los crea
nuevos con el `UMask` del proceso (root; `router-estadisticas.service`
pone `UMask=0027` como defensa en profundidad, pero el GRUPO sigue siendo
el primario del proceso —`root`—, nunca `routerpanel`, así que hace falta
un `chmod`/`chown` explícito aparte: `router_estadisticas._igualar_
permisos_wal`, llamado cada vez que se abre la base, no sólo la primera
vez) — sin esto el panel no podría ni mapear `-shm` aunque el `.db` en sí
estuviera bien.

**Cierre limpio obligatorio antes de parar** (`router_estadisticas.
cerrar_db`, llamado al recibir SIGTERM y al terminar un `--una-vez`):
`PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;` ANTES de
`close()`. Comprobado de verdad (no sólo supuesto): un `close()` normal
NO basta, aunque la última conexión dispare un checkpoint automático que
puede incluso borrar `-wal`/`-shm` del disco — el modo WAL queda anotado
en la propia CABECERA del fichero `.db` (bytes de versión de formato,
offset 18-19), así que el PRÓXIMO que lo abra (el panel, en modo lectura,
SIN permiso de escritura en el directorio — 0750 root:routerpanel, el
panel sólo está en el grupo) sigue viendo "esto es WAL", necesita crear un
`-shm` para el protocolo de bloqueo de WAL (aunque la conexión en sí sea
de sólo lectura) y falla con `attempt to write a readonly database`. Sólo
`journal_mode=DELETE` reescribe esa cabecera a "fichero normal" y
garantiza que `-wal`/`-shm` quedan borrados de verdad — a partir de ahí
cualquier lector con permiso de LECTURA puede abrirla sin pegas, sea quien
sea, exactamente mientras este servicio está parado (mantenimiento,
actualización, `systemctl restart`…). Al volver a arrancar, `abrir_db`
pone `WAL` otra vez y vuelve a igualar los permisos de los `-wal`/`-shm`
que se creen de nuevo.

### Rollup y retención

Al cruzar una hora (detectado por `ts // 3600` contra lo último agregado,
persistido en `meta.ultima_hora_rollup` — sobrevive a un reinicio), se
agrega el tramo de esa hora de `trafico_wan`/`trafico_disp` a sus tablas
`_hora` y se aplica la retención: `trafico_wan`/`trafico_disp`/
`conexiones` 48 h; `trafico_wan_hora`/`trafico_disp_hora` 400 días;
`dns_hora` según `bloqueo.registro_dns_dias` de `router.json` (defecto 30,
1-365 — el MISMO campo que ya usa `router_bloqueo.py`, no uno nuevo).

Tras una parada LARGA (días/semanas), ponerse al día con los rollups
pendientes se **acota a las últimas 48 h** (BAJA13 — más atrás no habría
datos por minuto de los que agregar nada, ya los habría borrado la propia
retención; sin este tope, miles de horas pendientes podrían agotar el
watchdog) y se avisa al watchdog en CADA vuelta del bucle de puesta al
día, no sólo al final.

Una vez al día (BAJA14), además, se pide `PRAGMA incremental_vacuum` —
las bases NUEVAS se crean con `auto_vacuum=INCREMENTAL` (sólo tiene efecto
puesto ANTES de la primera tabla; una base ya existente de antes de este
cambio se queda en `auto_vacuum=NONE`, nunca peor que antes) para que la
retención de arriba libere espacio de disco de verdad, poco a poco, en vez
de dejarlo reservado dentro del fichero para siempre.

### `disp_sube`/`disp_baja` y `contabilidad_disp` en `core/nft_conf.py`

Dos `set` dinámicos (`type ipv4_addr; flags dynamic, timeout; timeout 1d;
size 4096` — SIN concatenar `counter` en el `type`) dentro de
`table inet router`, alimentados con `update @disp_sube { ip saddr counter }`
/ `update @disp_baja { ip daddr counter }` desde una cadena base APARTE,
`contabilidad_disp` (BAJA10 — revisión Opus): `type filter hook forward
priority filter + 10; policy accept;`, es decir, en el MISMO hook
`forward` que `reenvio` pero 10 unidades DESPUÉS en prioridad. Varias
cadenas base en un mismo hook se recorren TODAS para cada paquete, en
orden de prioridad, pero si una de prioridad MENOR ya dijo `drop` el
recorrido del hook entero se para ahí — así, `contabilidad_disp` sólo
llega a ver tráfico que `reenvio` YA aceptó de verdad (nunca lo que iba a
`wan_gws`, ni `ct state invalid`, ni el DoT bloqueado por
`bloquear_doh`), sin tener que repetir ninguna de esas condiciones. Un
diseño anterior ponía estas dos líneas al PRINCIPIO de la propia
`reenvio` (antes de `ct state established,related accept`, para no
perderse el tráfico de una conexión ya abierta) — funcionaba, pero también
contaba paquetes que esa misma cadena acababa descartando más abajo;
con la cadena de prioridad mayor se cuenta EXACTAMENTE lo aceptado.
`update` sigue sin ser un veredicto: no cambia nada del filtrado ni de las
marcas de balanceo.

**Importante — por qué son `set` con `counter` en la expresión del
`update`, y NO un `map` con `type ipv4_addr : counter`**: un diseño
anterior usó precisamente ese `map`, que pasa `nft -c` sin ningún error
(el analizador sintáctico lo acepta perfectamente) — pero al cargarlo de
verdad el KERNEL lo rechaza: `Error: Could not process rule: Operation
not supported` al instalar la tabla, y el propio `update` falla con "No
such file or directory". **`nft -c` no detecta esto** (sólo analiza
sintaxis + un chequeo de caché, sin instalar nada de verdad); se descubrió
cargando la tabla en un netns con root (Debian 13, nftables 1.1.3) y se
reprodujo de forma independiente en otra máquina (nftables 1.1.7). Lo que
SÍ carga y cuenta de verdad, con contadores reales tras tráfico real:

```
set disp_sube { type ipv4_addr; flags dynamic, timeout; timeout 1d; size 4096; }
update @disp_sube { ip saddr counter }
```

Consecuencia práctica para quien lea/escriba este fichero: estos dos
objetos se leen con `nft -j list set inet router disp_sube`/`disp_baja`
(sí es "list set" — la petición original que dio pie a esto tenía razón en
la forma del objeto; sólo hacía falta encontrar la sintaxis de `update`
que el kernel admite de verdad, no `type ipv4_addr : counter`). La salida
JSON de un elemento tiene esta forma (`nft` 1.1.3, capturada de una tabla
cargada de verdad con tráfico real pasando por ella):

```json
{"elem": {"val": "192.168.50.50", "expires": 86210, "counter": {"packets": 3, "bytes": 252}}}
```

`pruebas/netns_multiwan.sh` (paso 17) es la prueba que de verdad instala
esta tabla con root y comprueba el contador tras tráfico real; los tests
unitarios (`pruebas/test_router_estadisticas.py`) comprueban el parseo de
ese JSON (con un fixture real pegado tal cual) y, best-effort si hay `nft`/
`unshare` disponibles, que el ruleset completo no tenga errores de
sintaxis — nunca sustituyen a la prueba con root.

## Registro de operaciones

`/var/log/router/operaciones.log`, una línea JSON por operación:
`{"fecha", "usuario", "accion", "datos", "ok", "mensaje"}`. El panel lo muestra.
