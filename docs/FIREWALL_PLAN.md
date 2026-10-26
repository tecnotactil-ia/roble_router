# Firewall con reglas propias (estilo Kerio) — plan y contrato

Estado: IMPLEMENTADO (2026-10-12, con correcciones de la revisión de seguridad Opus).
`/firewall` tiene reglas propias en `reenvio` con validación campo a campo y `nft -c`
antes de guardar.

## Alcance de la v1 (decisiones cerradas)

- **Sólo la cadena `reenvio`** (tráfico de la LAN hacia Internet, y LAN→LAN si algún día
  hay bridge). **NO se tocan `entrada` ni `salida`**: así ninguna regla del usuario puede
  dejar al admin sin panel ni SSH (la administración vive en `entrada`, que no cambia).
  Anti-encierro por diseño, sin temporizador de marcha atrás.
- Las reglas del usuario se insertan en `reenvio` **después** de `ct state established,related
  accept`, `ct state invalid drop`, `iifname LAN ip daddr @wan_gws drop` y del bloqueo DoT,
  y **antes** del `accept` genérico LAN→WAN. Orden = orden de la lista (primera que casa gana,
  como Kerio).
- Una regla nueva sólo afecta a conexiones NUEVAS (por el `established accept` de arriba).
  Para que un bloqueo valga YA, routerd vacía de conntrack las conexiones que la regla debe
  coger (`conntrack -D` con `-s`, `-p`, `--dport` y `-d` según la regla) al aplicar una
  regla `bloquear`/`rechazar`. Se re-vacía al editar la regla (clave id+huella). Para
  orígenes mac/grupo se resuelve la IP con `ip neigh` o se recorren los miembros.
- v1 NO incluye: reenvío de puertos (DNAT; las WAN son teléfonos con CGNAT), horarios
  (fase 2: `meta hour`/`meta day` dependen de la zona horaria y del cambio de hora; hay que
  probarlo en el netns), IPv6, reglas por dominio (nft resuelve nombres sólo al cargar).
- Límites: máx. 200 reglas, 50 grupos, 256 miembros por grupo.

## Reglas de generación nft (correcciones de la revisión Opus 2026-10-12)

- **Protocolo icmp**: `meta l4proto icmp` (el nombre `ipv4-icmp` no existe en
  `/etc/protocols` y `nft -c` lo rechazaba — HIGH-1).
- **`rechazar` con `tcp_udp`**: una línea por protocolo concreto (`meta l4proto tcp` +
  `tcp dport`, `meta l4proto udp` + `udp dport`), nunca el conjunto `{ tcp, udp }` junto a
  `reject with tcp reset` (nft: «you cannot use tcp reset with this protocol» — HIGH-2).
- **`permitir`**: añade `ip saddr {red} oifname @wan_ifs`, igual que el accept genérico, para
  no dejar pasar a interfaces que no son WAN vivas ni permitir orígenes falsificados (MEDIUM-1).
- **Validación antes de guardar**: las acciones `fw_*` generan el texto nft y lo validan con
  `nft -c -f` sobre un temporal ANTES de `_guardar_config`. Si falla, `ok=False` con el error
  y la config vuelve a la anterior — el panel nunca recibe un «guardada» que luego no se
  instala (HIGH-3).

## Modelo de datos (en `router.json`, sección `firewall`)

```json
"firewall": {
  "version": 3,
  "grupos": [
    {"id": "g_ninos", "nombre": "Móviles de los niños",
     "tipo": "mac",                       // "mac" | "ip"
     "miembros": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]}
  ],
  "reglas": [
    {"id": "r_ab12cd34", "nombre": "Sin juegos de noche",
     "habilitada": true,
     "accion": "bloquear",                // "permitir" | "bloquear" | "rechazar"
     "origen":  {"tipo": "cualquiera"},   // cualquiera | mac | ip | red | grupo
     "destino": {"tipo": "cualquiera"},   // cualquiera | ip | red | grupo (grupo tipo ip)
     "protocolo": "tcp",                  // cualquiera | tcp | udp | tcp_udp | icmp
     "puertos": [{"desde": 443, "hasta": 443}],   // sólo tcp/udp/tcp_udp; destino; máx. 15
     "registrar": false,
     "comentario": ""}
  ]
}
```

- `origen`/`destino` por tipo: `{"tipo":"mac","valor":"aa:bb:..."}` (sólo origen),
  `{"tipo":"ip","valor":"192.168.50.50"}`, `{"tipo":"red","valor":"10.0.0.0/8"}`,
  `{"tipo":"grupo","valor":"g_ninos"}`. El origen debe estar en la LAN salvo `cualquiera`
  (las reglas son de LAN→fuera); un `mac` sólo tiene sentido como origen.
- `bloquear` = `drop`; `rechazar` = `reject` (TCP reset / ICMP admin-prohibited, respuesta
  inmediata, como ya hace `entrada` con la LAN).
- `registrar: true` añade `limit rate 5/minute log prefix "fw-<id> "` antes del veredicto.
- `id`: `r_` + 8 hex generados por routerd (nunca por el panel). Orden = posición en la lista.
- Reglas que NO se pueden crear: origen ni destino contra la IP del router (`lan.ip`); destino
  `cualquiera` o `0.0.0.0/0` con acción `bloquear`/`rechazar` sin otra condición cuando el
  origen cubre la LAN entera (cortaría el internet de todos: se rechaza con mensaje claro;
  sí se admite con protocolo/puertos/origen concretos — MEDIUM-2). Un grupo ip no admite
  miembros fuera de la LAN ni la IP del router. No se puede cambiar el tipo de un grupo que
  alguna regla use como destino (HIGH-3).

## Peticiones nuevas (`docs/CONTRATO.md` → tabla de acciones)

Todas llevan `version` (int): la `firewall.version` que el panel vio en `estado.json` →
`config.firewall`. Si no coincide → «La configuración cambió mientras editabas; recarga la
página» y no se aplica nada (concurrencia optimista, como `bloqueo_config`).

| accion | datos |
|---|---|
| `fw_regla_guardar` | `{version, regla: {...sin id para crear / con id para editar...}, posicion?: int}` |
| `fw_regla_eliminar` | `{version, id}` |
| `fw_regla_mover` | `{version, id, posicion: int}` (0 = la primera) |
| `fw_regla_activar` | `{version, id, habilitada: bool}` |
| `fw_grupo_guardar` | `{version, grupo: {id?, nombre, tipo, miembros}}` |
| `fw_grupo_eliminar` | `{version, id}` — rechazada si alguna regla lo usa (dice cuál) |

Cada acción muta `cfg['firewall']`, sube `version` en 1 y `routerd` reinstala la tabla en
el ciclo siguiente (`instalar_base` ya compara el texto generado). Si `nft -c -f` rechaza el
resultado, `instalar_base` ya NO instala nada y deja `_firewall_error`; el panel debe mostrarlo.
**Además** `peticiones.py` valida cada regla campo a campo con listas blancas (nada de texto
libre hacia nft): MAC, IPv4/CIDR con `ipaddress`, puertos 1-65535, nombre `[A-Za-z0-9_ .áéíóúñÁÉÍÓÚÑ-]{1,40}`,
comentario 0-120 sin caracteres de control.

## nftables generado (`core/nft_conf.py`)

- Un `set` con nombre por grupo (`grp_<id>`: `type ether_addr` o `ipv4_addr`, `flags` vacíos),
  poblado en la misma transacción que crea la tabla.
- Cada regla = una línea en `reenvio`, en orden, con comentario `comment "fw:<id>"` para poder
  localizarla en `/run/router/firewall.txt`. Regla deshabilitada = no se genera. Para
  `rechazar` con protocolo mixto, dos líneas (una por protocolo).
- Las ids y los valores pasan por `_if`-style validadores en `nft_conf.py` TAMBIÉN (defensa en
  profundidad: nunca se interpola texto sin validar en el .nft).
- `contabilidad_disp` (prioridad filter+10) no cambia: sólo cuenta lo que `reenvio` acepta.

## Estado para el panel (`estado.json` → `config.firewall`)

Copia de `firewall` + `firewall_error` (str|null) + `firewall_aciertos`: `{id_regla: paquetes}`
leído de los contadores (`counter` en cada regla) — así el panel enseña cuántas veces ha
saltado cada regla (como la columna «Hits» de Kerio).

## Panel (`panel/`)

Página `/firewall`: tabla de reglas (nº, interruptor activa, nombre, origen, destino,
servicio, acción con color, registrar, hits, botones ↑ ↓ editar borrar), formulario de
regla en página propia (`/firewall/regla/nueva`, `/firewall/regla/<id>`), gestión de
grupos (`/firewall/grupos`), y debajo el volcado nft de sólo lectura que ya existe.
Selector de dispositivos para origen/miembros a partir de `estado.vecinos` (nombre + MAC + IP).
Sin JS inline, CSP estricta, UI en español, responsive, mismas variables `--tt-*`.
Plantillas de ejemplo: «Bloquear un dispositivo», «Bloquear un puerto para todos».

## Pruebas (TDD: tests primero)

- `pruebas/test_nft_firewall.py`: generación + orden + sets + validación defensa en profundidad
  + `nft -c` si hay binario. Incluye los casos de la revisión Opus (icmp, rechazar tcp_udp,
  permitir con saddr+oifname).
- `pruebas/test_peticiones_firewall.py`: cada acción, límites, versión, rechazos, protección
  bloquear-todo (MEDIUM-2), cambio de tipo de grupo destino (HIGH-3), y validaciones LOW
  (tipos estrictos, posición al editar, miembros dedup, ids únicas, nombre/comentario).
- `pruebas/test_routerd_firewall.py`: validación `nft -c` en `atender_buzon` antes de guardar
  (HIGH-3) y vaciado de conntrack filtrado (MEDIUM-3).
- `panel/tests/test_firewall.py`: página, formularios, CSRF, estado vacío, errores.
- `pruebas/netns_multiwan.sh`: paso 18 (HIGH-4) con root: conexión establecida ANTES de la
  regla y que muere tras aplicarla; segundo cliente LAN intacto; `firewall_error` null; casos
  icmp, rechazar + tcp_udp y registrar; respuesta `ok` de cada petición; versiones leídas del
  estado, no fijas.

## Fuera de esta fase

Horarios, DNAT, IPv6, importar/exportar reglas. Despliegue: SÓLO con visto bueno de Félix.
