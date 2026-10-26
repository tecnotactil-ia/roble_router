# Roble Router — dale una segunda vida a un PC viejo: router doméstico multi-WAN para Debian 13

¿Tienes un portátil o un PC viejo en un cajón? Con Roble Router se convierte
en el router de tu casa. Puede usar varias salidas a Internet a la vez:
teléfonos Android por USB con tethering, la propia Wi-Fi como cliente de
otra red, o cable. Reparte la carga entre ellas y cambia sola cuando una
cae. Trae cortafuegos con reglas propias y bloqueo DNS de anuncios y
rastreadores. Su tarjeta Wi-Fi puede hacer de punto de acceso para la casa.
Además, DHCP/DNS con dnsmasq, estadísticas de consumo por dispositivo y un
panel web HTTPS con usuarios. Pide poco hardware: un equipo de hace diez
años con Debian 13 sobra.

## Funciones

- **Multi-WAN con reparto de carga**: cada salida a Internet entra en el
  balanceo con un peso (calculado con la latencia y la pérdida medidas, o
  el que tú fijes). Una conexión no cambia de WAN a mitad.
- **Respaldo por prioridad** (modo `respaldo`): sólo la WAN de mejor
  prioridad que funcione reenvía tráfico; si cae, pasa a la siguiente.
- **Comprobación real de Internet** por cada WAN (pings marcados a
  destinos públicos) con histéresis: detectar el cable no es tener Internet.
- **Cortafuegos con reglas propias** (estilo Kerio): reglas y grupos de
  dispositivos, orden de evaluación manual, contadores de uso por regla,
  validación nft antes de guardar y anti-encierro por diseño (no puede
  dejar sin red a todos).
- **Bloqueador DNS** con listas HaGeZi (anuncios, rastreadores, amenazas),
  lista blanca/negra propia, forzado de DNS para los clientes y bloqueo de
  DoH. Si dnsmasq falla varias veces seguidas, el bloqueo se apaga solo
  y la casa sigue con DNS, sin filtrar, hasta que vuelva a estar estable.
- **DHCP/DNS local** con dnsmasq: rango configurable, reservas por
  MAC, etiquetas de dispositivos y dominio local `lan.home.arpa`.
- **Wi-Fi a elegir: punto de acceso o salida a Internet**: la tarjeta Wi-Fi
  se usa como **punto de acceso** para los clientes de la casa (hostapd
  sobre el puente de la LAN, se enciende al activar el router) o como
  **cliente de un hotspot** (por ejemplo un teléfono compartiendo sus datos)
  como salida a Internet, con guardas anti-bucle para no conectarse a la
  red de la propia LAN. También puede no usarse.
- **Estadísticas por dispositivo y por WAN**: tráfico de subida/bajada,
  latencia, pérdida y consumo DNS por dominio, en una base SQLite.
- **Panel web HTTPS** en la LAN, con usuarios y roles, sin privilegios:
  el núcleo actúa como demonio con validación estricta de cada petición;
  el panel nunca ejecuta comandos del sistema.
- **Activación reversible**: la máquina pasa a ser el router con vuelta
  atrás automática. Si nadie confirma en 30 minutos, o aparece otro equipo
  con la IP del router, vuelve sola a la fase de preparación.

## Requisitos de hardware

- Un equipo con **Debian 13**, con al menos una **interfaz de red cableada**
  para la LAN. Vale un mini-PC o un portátil: mejor pequeño, silencioso y
  de bajo consumo, porque va a estar encendido siempre.
- Uno o varios dispositivos como salida a Internet: teléfonos Android con
  **tethering USB/ADB**, un hotspot Wi-Fi, o una conexión por cable.
- Un **switch o punto de acceso** para conectar los clientes de la casa a
  la interfaz LAN del router (o usa la propia tarjeta Wi-Fi del router como
  punto de acceso: abajo).
- **Si quieres la Wi-Fi del router como punto de acceso** (modo `ap` de
  instalar), la tarjeta debe admitir modo AP:
  `iw list | sed -n '/Supported interface modes/,+6p'` debe mostrar
  `* AP`, y sólo se usa 2,4 GHz (canales 1..13). No todas las tarjetas lo
  admiten; si no es tu caso, conecta los clientes por cable a un punto de
  acceso aparte.

## Instalación rápida

```bash
git clone https://github.com/tecnotactil-ia/roble_router.git
cd roble_router
sudo bash instalar.sh
```

El instalador pregunta el papel de la tarjeta Wi-Fi (ninguno / punto de
acceso / salida a Internet), la interfaz de la LAN, la IP, el rango DHCP,
los dominio local, y el usuario y contraseña del panel. También se puede
responder todo por opciones (modo no interactivo); [GUIA.md](GUIA.md)
explica cada pregunta.

## Actualizar (sólo código)

```bash
sudo bash instalar.sh --actualizar
```

Reinstala el código del núcleo y del panel y reinicia los servicios **sin
tocar la configuración** (`/etc/router/router.json` y los certificados se
conservan).

## Desinstalar

```bash
sudo bash desinstalar.sh            # deja datos (router.json, bd, perfiles NM)
sudo bash desinstalar.sh --purgar   # borra también /etc/router, bases de datos, usuario
```

## Correr los tests

```bash
# Núcleo y componentes (unittest; no necesita privilegios ni router real)
python3 -m unittest discover -s pruebas -p 'test_*.py'

# Panel web (requiere un venv local)
cd panel
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest
```

No hace falta ningún router real: las pruebas trabajan con ficheros de
ejemplo y mocks.

## Estructura de carpetas

```
core/       núcleo de Python que corre como root (routerd y componentes de apoyo)
panel/      panel web Flask con gunicorn (usuario sin privilegios)
systemd/    unidades systemd, sysctl, udev, logind, logrotate y plantilla nginx
pruebas/    pruebas unitarias y e2e del núcleo (sin router real ni root)
docs/       documentación (contrato panel↔núcleo, plan del firewall, arquitectura)
```

## Documentación

- **[GUIA.md](GUIA.md)** — guía paso a paso de instalación, activación, uso
  del panel, cortafuegos y solución de problemas.
- [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) — procesos, servicios
  systemd y flujo de una petición.
- [docs/CONTRATO.md](docs/CONTRATO.md) — contrato técnico entre el núcleo
  y el panel (ficheros, formatos, acciones del buzón).

## Licencia y autor

MIT — ver [LICENSE](LICENSE). Canal del proyecto:
[MODO ROOT](https://www.youtube.com/@modo_root_IA).
