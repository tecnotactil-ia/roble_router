# Guía de instalación y uso de Roble Router

Paso a paso para montar el router. Asumimos que sabes usar una terminal pero
no que seas experto en redes: cada comando se explica antes de usarse.

---

## 0. Resumen del recorrido

1. Preparas la máquina con Debian 13.
2. Clonas el proyecto y ejecutas `sudo bash instalar.sh`: instala el código,
   los servicios, el panel y nginx. **No toca la red todavía**: queda en fase
   «preparación», en la que el núcleo sólo observa.
3. Con `router-migrar` le pasas el relevo: la máquina toma la IP del router
   y tienes 30 minutos para confirmar (si no, deshace sola y tu red vuelve a
   como estaba).
4. Desde el panel administras todo: WAN, cortafuegos, bloqueo DNS, DHCP,
   estadísticas.

---

## 1. Preparar la máquina

- Instala una **Debian 13 mínima** con el instalador oficial, sin
  seleccionar ningún entorno de gráfico. Vale un mini-PC o un portátil:
  mejor pequeño, silencioso y de bajo consumo, porque va a estar encendido
  siempre.
- **SSH activado y acceso desde tu red actual** (lo necesitas durante la
  instalación, porque la máquina aún usa la red que ya tenía).
- Identifica la interfaz **cableada** que irá a la LAN: se ve con
  `ip -o link`, y los nombres empiezan por `en` (por ejemplo `enp2s0`).
  A esa interfaz se conectará el cable que va al **switch o punto de
  acceso** de tu casa.
- Prepara las **salidas a Internet** que vayas a usar:
  - Teléfonos Android: activa la depuración USB (Ajustes → Acerca del
    teléfono → pulsa 7 veces «Número de compilación», y en Opciones de
    desarrollador activa «Depuración USB»).
  - Hotspot Wi-Fi: un teléfono compartiendo sus datos por hotspot.
  - Una conexión por cable (fibra/cablemódem con salida RJ45).

## 2. Clonar e instalar

```bash
git clone https://github.com/tecnotactil-ia/roble_router.git
cd roble_router
sudo bash instalar.sh
```

El instalador pregunta (con valores por defecto entre corchetes):

| Pregunta | Qué es | Por defecto |
|---|---|---|
| **¿Qué hace la tarjeta Wi-Fi?** | `ninguno` (no se usa), `ap` (punto de acceso para los clientes de casa) o `wan` (salida a Internet de un hotspot; ver la sección 7) | ninguno |
| **Interfaz de la LAN** (modos ninguno/wan) | la tarjeta cableada que servirá tu red doméstica | la primera cableada con enlace detectada |
| **Puerto de cable de la LAN** (sólo modo ap) | el puerto de cable esclavo del puente `br-lan` (con `--sin-cable-lan` no se pregunta) | la primera cableada con enlace detectada |
| **Interfaz Wi-Fi del AP / SSID / clave WPA2 / país / canal** (sólo modo ap) | datos del punto de acceso: la clave se pide dos veces sin eco (mínimo 8 caracteres), y el instalador comprueba que la tarjeta admita modo AP | primera Wi-Fi detectada; `RobleRouter`; ES; canal 6 |
| **IP del router en la LAN** | la IP fija que tendrá la máquina como router | 192.168.50.1 |
| **Inicio / fin del rango DHCP** | el rango de IPs automáticas para los clientes | .100-.250 dentro de esa red |
| **Dominio DNS local** | el dominio que anuncia dnsmasq para nombres internos | lan.home.arpa |
| **Interfaz Wi-Fi para WAN Wi-Fi** (sólo modo wan) | si la dejas vacía, el Wi-Fi del equipo no se usa para salir a Internet; si la pones, puedes usar hotspots (por ejemplo, de un teléfono) como salida a Internet | vacía |
| **Interfaces WAN por cable** | tarjetas cableadas que salen a Internet (módem, ONT de fibra, otro router), separadas por comas. Los teléfonos por USB se detectan solos y no hace falta ponerlos aquí | vacía |
| **Usuario admin del panel** | el login del administrador | `admin` |
| **Contraseña del admin** | dos veces, sin eco; mínimo 12 caracteres | — |

En modo no interactivo se puede contestar todo por opciones:

```bash
sudo bash instalar.sh --si        # acepta todos los valores por defecto
# ...o todo por argumentos:
sudo bash instalar.sh \
  --lan-if enp2s0 --lan-ip 192.168.50.1 \
  --dhcp-inicio 192.168.50.100 --dhcp-fin 192.168.50.250 \
  --dominio lan.home.arpa \
  --wifi-if '' --wan-cable eth1 \
  --admin admin --admin-clave-fichero /root/clave.txt

# ...y ejemplo en modo punto de acceso (Wi-Fi para los clientes de casa):
sudo bash instalar.sh \
  --wifi-modo ap --ap-ssid MiCasaWiFi --ap-pais ES --ap-canal 6 \
  --ap-clave-fichero /root/clave-wifi.txt \
  --lan-ip 192.168.50.1 --wan-cable eth1 \
  --admin admin --admin-clave-fichero /root/clave.txt
```

Otras opciones: `--sin-cable-lan` (sólo en modo ap: el puente de la LAN no
lleva puerto de cable), `--forzar` instala aun si la versión de Debian no es la
esperada (no está probado); `--actualizar` sólo re-copia el código del núcleo
y del panel y reinicia los servicios, sin tocar `/etc/router/router.json` ni
los certificados (para actualizar una instalación ya activa).

Qué queda instalado: los demonios de `core/` en `/usr/local/lib/router`
(sin `acme_ionos.py`, que no se publica), `router-migrar` en
`/usr/local/sbin`, las unidades systemd, sysctl, udev, tmpfiles, logind y
logrotate de `systemd/`, el panel Flask en `/opt/router-panel` (con su
venv y el usuario del sistema `routerpanel`), el certificado autofirmado
en `/etc/router/tls/`, el sitio nginx en
`/etc/nginx/sites-available/router-panel`, y el perfil NetworkManager
`LAN-ROUTER` — la IP fija de la LAN, sin gateway y sin autoconexión
(la activación es la que lo levanta). En modo ap crea además los perfiles
del puente `br-lan` (puerto de cable esclavo `LAN-ROUTER-cable`) y escribe
`/etc/router/hostapd.conf`; la unidad `router-ap.service` se instala pero se
queda sin habilitar: es la activación la que enciende el AP.

[CAPTURA: el instalador listando sus preguntas con los valores por defecto]

## 3. La fase «preparación» (la red aún no cambia)

Tras instalar, routerd arranca y publica `/run/router/estado.json` con lo
que ve ( interfaces, teléfonos con tethering, hotspots, conectividad ), pero
no cambia nada: no instala tablas nftables, ni gestiona dnsmasq, ni toca las
rutas. Tu red sigue funcionando exactamente como antes, y el SSH por el que
instalaste no se corta.

En esta fase puedes, desde el panel:

- Ajustar el rango DHCP, los servidores DNS, el monitor de conectividad y
  las etiquetas de los dispositivos.
- Comprobar si routerd ya ve tus teléfonos por USB o la WAN Wi-Fi.

[CAPTURA: dashboard del panel en fase preparación, con las WAN detectadas]

## 4. Activación con router-migrar (la máquina pasa a ser el router)

Todo el proceso es reversible: hay una comprobación previa a través de la
cual puedes revisar sin cambiar nada, y un deshacer automático si nadie
confirma la activación.

```bash
sudo router-migrar --comprobar   # imprime la lista ✔/✘ sin tocar nada
```

Revisa la salida: perfil NetworkManager de la LAN, binarios necesarios
(nft, ip, conntrack, dnsmasq, nmcli, arping), dnsmasq habilitado,
nftables.service NO habilitado, sin `table ip filter` de otro sistema
(¿Docker?), routerd activo. Si algo falla, arréglalo y repite — la
activación no arranca con cualquier ✔ faltante.

1. **Apaga el router anterior** (o quítale la IP del router, desde su propio
   panel o interfaz de administración).
2. **Conecta el cable LAN** entre la interfaz LAN de la máquina y el switch
   o punto de acceso de tu casa.
3. Lanza la activación:
   ```bash
   sudo systemctl start router-migracion
   ```
   Esto activa el perfil NetworkManager de la LAN, pone la fase en
   `produccion` (routerd ya instala nftables, NAT, balanceo y DHCP/DNS) y
 programa un temporizador independiente que deshace a los 30 minutos si
   nadie confirma.
4. **Entra por la URL nueva** (`https://192.168.50.1/`, la IP que elegiste)
   y **confirma antes de 30 minutos**:
   ```bash
   sudo router-migrar --confirmar
   ```
   Hecho: la máquina queda definitivamente como tu router.

Qué pasa si no confirmas: a los 30 minutos — o si la máquina detecta que
otro equipo vuelve a reclamar la IP del router — se deshace todo: routerd
retira sus tablas y su dnsmasq, el perfil de la LAN queda abajo y sin
autoconexión, y el Wi-Fi (si estaba configurado como WAN) se reconecta.
Tu red queda como estaba, sin intervención.

Qué pasa si la máquina se reinicia con la activación sin confirmar: el
servicio de arranque ve el marcador `/etc/router/migracion-pendiente` y
deshace de inmediato.

Y en cualquier momento puedes Dar marcha atrás a mano:

```bash
sudo router-migrar --deshacer
```

[CAPTURA: dashboard tras la migración, con las WAN activas y el balanceo]

## 5. Primer acceso al panel

- URL: `https://<IP-del-router>/` (la que elegiste al instalar).
- El certificado es **autofirmado**: el navegador mostrará un aviso la
  primera vez. Es lo esperado (el certificado lo generó el instalador con
  openssl), añade la excepción de seguridad y sigue.
- Login con el usuario y la contraseña elegidos.

[CAPTURA: pantalla de login del panel]

## 6. Añadir WAN

### Teléfono por USB (tethering/ADB)

- Conecta el teléfono por USB y **acepta la depuración USB** en la
  pantalla que aparece en el propio teléfono.
- En el dashboard la WAN aparece en cuanto routerd la descubra
  (interfaces con nombres tipo `enx…`: routerd las identifica como WAN por
  el driver del kernel, no por el nombre).
- Puedes ponerle nombre, activar o desactivar («habilitada»), y ajustar
  peso y prioridad.
- `router-adb` (servicio aparte) mantiene activo el tethering USB de los
  teléfonos Android: si el teléfono lo desconecta, lo reactiva suavemente,
  con períodos de espera que se doblan hasta media hora (no machaca adb).
  Su estado está en `/run/router/adb.json` y, con sucesos, en el registro
  de operaciones.

[CAPTURA: página de WAN con un teléfono conectado por USB]

### Hotspot Wi-Fi (la tarjeta Wi-Fi como cliente)

- Da la interfaz Wi-Fi al instalar (`--wifi-if`) o relléna
  más tarde en `router.json` (`wifi_wan.interfaz`).
- Desde el panel se escanea la red, se guarda el SSID con su clave y
  prioridad, y se conecta. La clave va a un keyfile de NetworkManager con
  permisos 0600 de root — nunca se guarda en `router.json` ni se registra
  en los logs.
- routerd protege contra bucles: no deja que la tarjeta se conecte al
  hotspot de la propia LAN (SSIDS bloqueados, comparados normalizados:
  mayúsculas y espacios también cuentan), ni a redes cuyo gateway sea el
  propio router.

[CAPTURA: página Wi-Fi con la lista de redes y el botón de conexión]

## 7. La tarjeta Wi-Fi: punto de acceso o salida a Internet

Al instalar se pregunta qué hace la tarjeta Wi-Fi del equipo
(`--wifi-modo`):

| Modo | Qué pasa con la tarjeta |
|---|---|
| `ninguno` | No se usa (puedes haber conectado un punto de acceso aparte al switch). |
| `ap` | **Punto de acceso**: los móviles y portátiles de casa se conectan por Wi-Fi a la LAN del router. |
| `wan` | **Cliente** de otra red Wi-Fi y salida a Internet (lo que describe la sección 6: hotspot de un teléfono). |

Qué cambia en modo `ap`:

- La LAN pasa a ser un **puente de NetworkManager** llamado `br-lan`:
  el puerto de cable que elijas queda como esclavo del puente y la tarjeta
  Wi-Fi se levanta DENTRO de ese puente con **hostapd** (unidad
  `router-ap.service`, configuración en `/etc/router/hostapd.conf`, de root
  con permisos 0600). Para dnsmasq, nftables y estadísticas no cambia nada:
  siguen viendo «la LAN».
- Con `--sin-cable-lan` el puente no lleva puerto de cable: la LAN queda
  de sólo Wi-Fi, sin cable al switch.
- El AP sigue el ciclo de activación: **se enciende al activar el router**
  (router-migrar aparta la tarjeta de NetworkManager y arranca el servicio)
  y **se apaga al deshacer**. Si confirmas la activación, la unidad queda
  habilitada para sobrevivir a reinicios.
- Sólo se usa 2,4 GHz: país `--ap-pais` (ES por defecto) y canal
  `--ap-canal` (1..13, 6 por defecto). La clave WPA2 va a
  `/etc/router/hostapd.conf`, nunca a `router.json` ni a los logs.
- El panel muestra la tarjeta en el dashboard (SSID, estado, clientes
  conectados) y en la página Wi-Fi avisa de que la tarjeta está en modo AP.

Antes de instalar, comprueba que la tarjeta admite modo de punto de acceso
(no todas lo hacen; muchas USB tipo RTL8188/RTL8821 sí):

```bash
iw list | sed -n '/Supported interface modes/,+12p'   # debe listar «* AP»
```

Si no lo admite, el instalador se niega (`la tarjeta X no admite modo
punto de acceso (AP)`): usa `--wifi-modo wan` o `ninguno`.

Cambiar de modo después: con el router SIN activar (fase «preparacion»),
repite la instalación pasando el modo nuevo:

```bash
sudo router-migrar --deshacer 2>/dev/null || true   # si estuviera activado
sudo bash instalar.sh --wifi-modo wan --wifi-if wlp3s0    # de AP a WAN Wi-Fi
sudo bash instalar.sh --wifi-modo ap --ap-ssid MiRed      # a punto de acceso
```

Sólo se reescribe lo que depende del modo (`lan.interfaz`,
`ignorar_interfaces`, `wifi_wan`, `wifi_ap` y `activacion`), se recrean los
perfiles NM de la LAN y, si hay AP, hostapd.conf. Con el router ACTIVADO se
niega y te lo dice: deshaz antes.

Solución de problemas del punto de acceso:

| Problema | Dónde mirar |
|---|---|
| El SSID no aparece o los clientes no conectan | `systemctl status router-ap` |
| hostapd no arranca (interfaz, canal…) | `journalctl -u router-ap -n 50` |
| «no admite modo AP» al instalar | la tarjeta no soporta AP (`iw list` sin `* AP`): usa otro modo |
| Nombre/canal/país mal | revisa `ssid2`, `country_code` y `channel` en `/etc/router/hostapd.conf`; para cambiarlo del todo, reinstala con otras `--ap-*` |
| Los clientes conectan pero «sin Internet» | el router no está activado todavía: el AP se enciende SOLO al activar |

[CAPTURA: dashboard con la tarjeta «Wi-Fi (punto de acceso)» y un móvil conectado]

## 8. Reparto de carga y pesos

- **Modo `auto`** (por defecto): routerd reparte entre las WAN activas por
  la latencia y la pérdida que en cada ciclo mide. La «capacidad» (Mbps) no
  entra en el cálculo: no hay forma de medirla de verdad sin saturar la
  línea, así se evita un bucle de realimentación.
- **Modo `manual`**: tú fijas el peso (1-100) de cada WAN desde el panel.
- **Modo `respaldo`**: sólo reenvía la WAN de mejor prioridad que funcione;
  si cae, pasa a la siguiente.
- El reparto se hace con un mapa de pesos nftables (numgen) aplicado sobre
  conexiones NUEVAS; la pertenencia a una WAN se guarda en conntrack,
  así que una conexión ya abierta no salta de WAN a mitad.

[CAPTURA: página de WAN mostrando los pesos efectivos y la conectividad]

## 9. Cortafuegos: reglas y grupos

Estilo Kerio: listas de reglas con orden manual; la primera que casa, gana.

- **Grupos**: conjuntos de dispositivos por MAC o por IP (hasta 50 grupos,
  256 miembros por grupo).
- **Reglas**: origen (`cualquiera`, `mac`, `ip`, `red` o `grupo`), destino
  (`cualquiera`, `ip`, `red` o `grupo` de tipo ip), protocolo
  (`cualquiera`, `tcp`, `udp`, `tcp_udp`, `icmp`), puertos destino (hasta
  15), acción (`permitir`, `bloquear`, `rechazar`), registro (5/máx por
  minuto) y comentario.

Las reglas se aplican en la cadena `reenvio` (LAN→fuera), después de las
conexiones ya establecidas; para que un bloqueo valga ya, routerd vacía de
conntrack las conexiones que la regla debe coger.

Ejemplos:

- «**Móviles de los niños**: bloquear UDP 443 (QUIC)» — origen `grupo`
  con las MAC de esos móviles, destino `cualquiera`, protocolo udp,
  puertos 443-443, acción `bloquear`.
- «**BAJAR la TV del salón**: bloquear todo» — origen `mac` (la TV),
  destino `cualquiera`, acción `bloquear`.
- «**Permitir a la NAS sólo al servidor X**» — origen `ip` (la NAS),
  destino `ip` (el servidor), acción `permitir`.

Anti-encierro por diseño: no se puede crear una regla que deje la LAN
entera sin salida (p. ej. bloquear `cualquiera`→`cualquiera` con origen
que cubre la LAN, sin otra condición). El núcleo valida cada regla con
`nft -c` ANTES de guardarla — y nunca te deja guardar algo que el sistema
no puede aplicar. Tampoco se puede cambiar el tipo de un grupo que alguna
regla ya usa.

La página `/firewall` del panel mestra las reglas con contador de
**Hits** (cuántos paquetes coincide), interruptor para activar/desactivar
y reordenación con botones, más el volcado nft de sólo lectura.

[CAPTURA: página /firewall con la tabla de reglas y los contadores]

## 10. Bloqueo DNS (listas HaGeZi)

- Se activa desde el panel eligiendo listas del catálogo fijo:
  `hagezi_light`, `hagezi_multi`, `hagezi_pro`, `hagezi_pro_plus`,
  `hagezi_tif` (amenazas/malware/phishing), `hagezi_doh` (servidores DNS
  cifrados), `hagezi_nsfw`, `hagezi_gambling`.
- **Lista blanca**: dominios que nunca se bloquean, aunque una lista los
  traiga (una entrada concreta gana a una general: puede «tapar» a su
  padre bloqueado sin desbloquear a los hermanos).
- **Lista negra**: dominios que se bloquean SIEMPRE (un dominio concreto;
  no se admite un sufijo publico pelado como `co.uk`: sí un dominio
  debajo de uno).
- **Forzar DNS**: si está activo, las consultas DNS de los clientes de la
  LAN hacia fuera se redirigen al DNS del router (por si un cliente se
  salta tu DHCP y configura otros servidores).
- **Bloquear DoH**: además de su propia lista, redes DoH (DNS sobre HTTPS)
  conocidas, para que los clientes no esquiven el bloqueo por DNS cifrado.
- **Registro DNS**: cuántos días se guarda el log de consultas (1-365,
  30 por defecto), con rotación diaria.
- **Modo a prueba de fallos**: si dnsmasq lleva varios arranques fallidos
  consecutivos, el bloqueo se apaga solo (el DNS de la casa sigue
  funcionando, sin anuncios bloqueados, hasta que dnsmasq vuelva a estar
  estable un rato: mínimo 30 minutos, más si recae). Se muestra en el
  panel como un aviso informativo, no como un error.

Además, los dominios que el propio router necesita para funcionar
(GitHub, Debian, NTP, `home.arpa`, el dominio local…) nunca se bloquean,
aunque vengan en una lista o en la lista negra.

[CAPTURA: página del bloqueo DNS con las listas y su estado]

## 11. Solución de problemas

| Problema | Dónde mirar |
|---|---|
| El núcleo no arranca | `journalctl -u routerd -n 50` |
| Problemas de una activación en curso | `journalctl -u router-migracion -n 50` |
| Volver atrás manualmente | `sudo router-migrar --deshacer` |
| El panel no responde | `journalctl -u router-panel -n 50` |
| Estado actual del router | `/run/router/estado.json` (JSON legible) |
| Estado de una migración | `/run/router/migracion.json` |
| Volcado del cortafuegos | `/run/router/firewall.txt` |
| Registro de acciones del núcleo | `/var/log/router/operaciones.log` (JSON por línea) |
| Estado de los teléfonos USB | `/run/router/adb.json` |
| Estado del bloqueo DNS | `/run/router/bloqueo.json` |
| Log de consultas DNS | `/var/log/router/dns.log` |

El panel tiene una página de **Registro** con las operaciones del núcleo
y las respuestas de cada petición.

[CAPTURA: página de registro del panel con las acciones recientes]

## 12. Desinstalar

```bash
sudo bash desinstalar.sh            # para servicios, borra unidades y código; conserva datos
sudo bash desinstalar.sh --purgar   # además borra /etc/router, bases de datos, logs y usuario
```

Por defecto no se borra ningún dato: la configuración en `/etc/router`, las
estadísticas en `/var/lib/router` y los usuarios del panel pueden permitir
una reinstalación sobre la misma máquina con lo mismo. Con la máquina aún en
`produccion`, el desinstalador primero ejecuta `router-migrar --deshacer`
para devolver la red a como estaba, antes de borrar unidades o software.

---

## Apéndice: ficheros importantes

| Fichero | Para qué |
|---|---|
| `/etc/router/router.json` | Configuración del router (la edita el núcleo, no a mano) |
| `/etc/router/fase` | Fase actual: `preparacion` o `produccion` |
| `/run/router/estado.json` | Estado vivo publicado por routerd cada ciclo |
| `/var/lib/router/solicitudes/` y `respuestas/` | El buzón entre panel y núcleo |
| `/var/lib/router/estadisticas/estadisticas.db` | La base de datos SQLite de estadísticas |
| `/var/log/router/operaciones.log` | Log de operaciones del núcleo |
