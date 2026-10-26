"""Panel de administración del router doméstico (sin privilegios).

App factory: `create_app()`. El panel nunca ejecuta comandos del sistema; sólo
lee ficheros de estado publicados por routerd y deja peticiones en un buzón
(ver `docs/CONTRATO.md`). Todas las rutas a esos ficheros son configurables
por variables de entorno.
"""
from __future__ import annotations

import getpass
import logging
import os
import secrets
from datetime import timedelta

from flask import Flask, render_template
from flask_wtf import CSRFProtect

csrf = CSRFProtect()

_log = logging.getLogger(__name__)


def _cargar_o_crear_secret_key(ruta: str) -> bytes:
    try:
        with open(ruta, "rb") as f:
            clave = f.read().strip()
            if clave:
                return clave
    except FileNotFoundError:
        pass
    except PermissionError:
        # Caso típico: el fichero lo creó un proceso con otro usuario (por
        # ejemplo se arrancó antes como root) y el proceso actual no puede
        # leerlo. Sin este aviso explícito, el fallo se ve como un error
        # genérico de arranque difícil de diagnosticar.
        _log.error(
            "No se puede leer la clave de sesión en %s: permiso denegado. "
            "El fichero existe pero pertenece a otro usuario u otro grupo; "
            "ejecuta el panel (y `flask --app wsgi crear-usuario`) como el "
            "propietario de ese fichero, p. ej. «sudo -u routerpanel ...» "
            "(ver README).",
            ruta,
        )
        raise

    clave = secrets.token_bytes(32)
    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as f:
        f.write(clave)
    os.chmod(ruta, 0o600)
    return clave


def create_app(config_extra: dict | None = None) -> Flask:
    app = Flask(__name__)
    # Detrás de nginx (único proxy, en la misma máquina): la IP real del
    # cliente viene en X-Forwarded-For. Sin esto todo llegaría como 127.0.0.1
    # y el bloqueo por fuerza bruta y la auditoría no distinguirían a nadie.
    # Sólo se confía en UN salto: el nginx local, que reescribe la cabecera.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    secret_file = os.environ.get("PANEL_SECRET_FILE", "/var/lib/router-panel/secret_key")
    if config_extra and "SECRET_KEY" in config_extra:
        app.config["SECRET_KEY"] = config_extra["SECRET_KEY"]
    else:
        app.config["SECRET_KEY"] = _cargar_o_crear_secret_key(secret_file)

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "False") == "True",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        WTF_CSRF_ENABLED=os.environ.get("WTF_CSRF_ENABLED", "True") == "True",
    )

    if config_extra:
        app.config.update(config_extra)

    csrf.init_app(app)

    @app.template_filter("miles")
    def _formatear_miles(valor):
        """«259.560» (separador de miles español); «—» si no hay dato o no
        es un número (nunca lanza desde una plantilla)."""
        if valor is None or isinstance(valor, bool):
            return "—"
        try:
            return "{:,}".format(int(valor)).replace(",", ".")
        except (TypeError, ValueError):
            return "—"

    from . import usuarios as usuarios_mod

    # Estado del bloqueo por fuerza bruta: en memoria, por instancia de la
    # app (es decir, por proceso/worker de gunicorn). Documentado como
    # limitación: con varios workers cada uno lleva su propia cuenta, lo que
    # basta para un panel doméstico en LAN.
    app.extensions["control_fuerza_bruta"] = usuarios_mod.ControlFuerzaBruta()

    from . import auth, configuracion, cuenta, dashboard, dispositivos, firewall, proteccion, registro, wan, wifi

    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(wan.bp)
    app.register_blueprint(wifi.bp)
    app.register_blueprint(dispositivos.bp)
    app.register_blueprint(firewall.bp)
    app.register_blueprint(proteccion.bp)
    app.register_blueprint(configuracion.bp)
    app.register_blueprint(registro.bp)
    app.register_blueprint(cuenta.bp)

    @app.context_processor
    def _inyectar_fase():
        from . import estado as estado_mod

        try:
            fase = estado_mod.leer_estado().fase
        except Exception:
            fase = None
        return {"fase_global": fase}

    @app.after_request
    def cabeceras_seguridad(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        # same-origin, NO no-referrer: por HTTPS, Flask-WTF exige un Referer del
        # mismo sitio en cada POST (defensa extra contra CSRF) y con
        # no-referrer el navegador no lo manda → «400 The referrer header is
        # missing» al hacer login. same-origin lo envía sólo dentro del panel,
        # nunca a otros sitios.
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.errorhandler(403)
    def error_403(e):
        return render_template("errores/403.html"), 403

    @app.errorhandler(404)
    def error_404(e):
        return render_template("errores/404.html"), 404

    @app.errorhandler(500)
    def error_500(e):
        return render_template("errores/500.html"), 500

    _registrar_cli(app)

    return app


def _registrar_cli(app: Flask) -> None:
    import click

    from . import usuarios as usuarios_mod

    @app.cli.command("crear-usuario")
    @click.argument("login")
    @click.option("--rol", type=click.Choice(["admin", "lectura"]), default="admin", show_default=True)
    def crear_usuario_cmd(login: str, rol: str):
        """Crea (o reemplaza) un usuario del panel pidiendo la contraseña de forma segura."""
        password = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
        confirmacion = getpass.getpass("Repite la contraseña: ")
        if password != confirmacion:
            click.echo("Las contraseñas no coinciden.")
            raise SystemExit(1)
        try:
            usuarios_mod.crear_usuario(login, password, rol)
        except ValueError as exc:
            click.echo(str(exc))
            raise SystemExit(1)
        click.echo(f"Usuario «{login}» creado con rol «{rol}».")
