# Panel del router casa (routerpanel)

Panel web de administración **sin privilegios** para el router doméstico
Debian 13. Sólo lee ficheros publicados por `routerd` y deja peticiones en un
buzón para que `routerd` las valide y aplique; nunca ejecuta comandos del
sistema. Ver el contrato completo en `../docs/CONTRATO.md`.

## Variables de entorno

| Variable | Por defecto | Uso |
|---|---|---|
| `ROUTER_ESTADO` | `/run/router/estado.json` | Estado publicado por routerd |
| `ROUTER_BUZON` | `/var/lib/router/solicitudes` | Carpeta donde el panel deja peticiones |
| `ROUTER_RESPUESTAS` | `/var/lib/router/respuestas` | Carpeta donde routerd deja respuestas |
| `ROUTER_LEASES` | `/var/lib/misc/dnsmasq.leases` | Leases DHCP |
| `ROUTER_FIREWALL` | `/run/router/firewall.txt` | Volcado de `nft list` |
| `ROUTER_OPLOG` | `/var/log/router/operaciones.log` | Log de operaciones de routerd |
| `PANEL_USUARIOS` | `/var/lib/router-panel/usuarios.json` | Usuarios del panel (JSON) |
| `PANEL_SECRET_FILE` | `/var/lib/router-panel/secret_key` | Clave de sesión (se genera sola si no existe) |
| `PANEL_AUDIT` | `/var/log/router-panel/audit.log` | Auditoría propia del panel |
| `SESSION_COOKIE_SECURE` | `False` | Poner `True` si el panel se sirve por HTTPS |
| `WTF_CSRF_ENABLED` | `True` | Sólo se desactiva en tests puntuales |

Todas tienen el valor del contrato por defecto; para pruebas basta con
apuntarlas a ficheros de ejemplo.

## Instalación y primer arranque

El panel debe ejecutarse siempre como el mismo usuario del sistema, por
ejemplo `routerpanel` (el que sea propietario de `PANEL_USUARIOS` y de
`PANEL_SECRET_FILE`). Si `crear-usuario` se ejecuta una vez como root u otro
usuario y gunicorn arranca después como `routerpanel` (o al revés), los
ficheros `usuarios.json` y/o `secret_key` quedan con un propietario distinto
al del proceso: éste no podrá leerlos y el servicio no arrancará. Usa
siempre `sudo -u routerpanel` (o el usuario dedicado que corresponda) tanto
para `flask crear-usuario` como para lanzar gunicorn:

```bash
cd panel
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# Crear el primer usuario administrador (pide la contraseña, mínimo 12
# caracteres). Ejecutarlo como el mismo usuario que usará el servicio:
sudo -u routerpanel flask --app wsgi crear-usuario admin --rol admin

# Arrancar con gunicorn (sirviendo sólo en localhost; un proxy en el router
# expondría esto a la LAN). `--threads 4` con worker gthread es necesario
# porque cada petición que escribe en el buzón (ver routerpanel/buzon.py)
# bloquea el worker hasta ~6 s esperando la respuesta de routerd; sin hilos
# un único worker sync no podría atender otras peticiones mientras tanto.
sudo -u routerpanel gunicorn -w 2 -k gthread --threads 4 -b 127.0.0.1:5001 wsgi:app
```

Para crear un usuario de sólo lectura:

```bash
sudo -u routerpanel flask --app wsgi crear-usuario invitado --rol lectura
```

Si el panel falla al arrancar por no poder leer `secret_key` (permiso
denegado), el log mostrará un error explícito indicando que el fichero
pertenece a otro usuario y que hay que ejecutar el proceso como su
propietario.

## Seguridad

- Login obligatorio en todo salvo `/login` y los estáticos.
- Contraseñas con `werkzeug.security.generate_password_hash` (scrypt).
- Bloqueo por fuerza bruta: 5 fallos en 15 min por IP+usuario → 15 min
  bloqueado. El contador vive en memoria del proceso de la app (por worker
  de gunicorn): suficiente para un panel doméstico en LAN, documentado como
  limitación conocida.
- Login con tiempo constante frente a enumeración de usuarios: si el login
  no existe, se verifica igualmente contra un hash scrypt ficticio, para que
  el tiempo de respuesta no distinga «usuario inexistente» de «contraseña
  incorrecta».
- Redirección tras login (`?next=`) sólo admite rutas relativas propias del
  panel (empiezan por `/`, nunca por `//` ni `/\`, sin esquema ni netloc);
  cualquier otro valor se ignora en favor del dashboard, para evitar una
  redirección abierta.
- Revocación de sesiones por versión: cada usuario guarda un
  `version_sesion` en `usuarios.json`. La sesión guarda la versión vigente
  al iniciar sesión; si en una petición no coincide con la actual del
  usuario (o el usuario ya no existe o cambió de rol), la sesión se cierra
  en el momento. Cambiar la contraseña incrementa `version_sesion`, lo que
  cierra TODAS las sesiones de ese usuario en cualquier dispositivo, no sólo
  la que hizo el cambio.
- Cookies de sesión `HttpOnly`, `SameSite=Strict`, caducidad 8 h, y `Secure`
  configurable por `SESSION_COOKIE_SECURE` (desactivado por defecto porque
  el panel se sirve por HTTP dentro de la LAN).
- CSRF (Flask-WTF) en todos los POST.
- CSP estricta, `X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options: DENY`.
- Toda petición de cambio se valida dos veces: una vez en el panel
  (`routerpanel/validacion.py`, mismas reglas que el contrato) y otra vez en
  routerd antes de aplicarla.
- Auditoría propia del panel (`PANEL_AUDIT`) además del log de operaciones
  de routerd.

## Tests

```bash
cd panel
. .venv/bin/activate
pytest -q
```

Los tests usan ficheros de ejemplo en `tmp_path` y variables de entorno
apuntando a ellos; no requieren un router real ni privilegios.

## Estructura

```
panel/
├── requirements.txt
├── wsgi.py                  # punto de entrada WSGI (gunicorn)
├── routerpanel/
│   ├── __init__.py          # app factory create_app()
│   ├── auth.py               # blueprint: login/logout
│   ├── dashboard.py          # blueprint: dashboard + JSON de refresco
│   ├── wan.py                 # blueprint: WAN
│   ├── dispositivos.py        # blueprint: dispositivos/reservas/etiquetas
│   ├── firewall.py            # blueprint: firewall (reglas y grupos fw_*)
│   ├── configuracion.py       # blueprint: DHCP/DNS/monitor
│   ├── registro.py            # blueprint: operaciones
│   ├── estado.py              # lectura tolerante de estado/leases/firewall/oplog
│   ├── buzon.py                # peticiones atómicas + espera de respuesta
│   ├── validacion.py           # reglas del contrato (igual que routerd)
│   ├── usuarios.py             # usuarios + control de fuerza bruta
│   ├── auditoria.py            # log de auditoría propio del panel
│   ├── seguridad.py            # decoradores login_requerido/rol_requerido
│   ├── formularios.py          # WTForms
│   ├── templates/
│   └── static/
│       ├── css/panel.css
│       ├── js/panel.js
│       └── vendor/             # Bootstrap 5.3.3 + Bootstrap Icons 1.11.3 (locales, sin CDN)
└── tests/
```
