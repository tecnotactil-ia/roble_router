"""Formularios WTForms. Validan la forma de los datos; `validacion.py`
aplica además las reglas exactas del contrato antes de escribir en el buzón."""
from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, IntegerField, PasswordField, SelectField, StringField
from wtforms.validators import DataRequired, EqualTo, InputRequired, Length, NumberRange, Optional, Regexp


class WanActualizarForm(FlaskForm):
    wan = StringField(validators=[DataRequired()])
    nombre = StringField(validators=[Optional(), Length(min=1, max=32)])
    habilitada = BooleanField(validators=[Optional()])
    peso = IntegerField(validators=[Optional()])
    prioridad = IntegerField(validators=[Optional()])


class ModoForm(FlaskForm):
    modo = SelectField(choices=[("balanceo", "Balanceo"), ("respaldo", "Respaldo")], validators=[DataRequired()])


class ModoPesosForm(FlaskForm):
    modo_pesos = SelectField(
        choices=[("auto", "Automático"), ("manual", "Manual")], validators=[DataRequired()]
    )


class ReservaAgregarForm(FlaskForm):
    mac = StringField(validators=[DataRequired()])
    ip = StringField(validators=[DataRequired()])
    nombre = StringField(validators=[DataRequired(), Regexp(r"^[a-z0-9-]{1,40}$")])


class ReservaEliminarForm(FlaskForm):
    mac = StringField(validators=[DataRequired()])


class EtiquetarForm(FlaskForm):
    mac = StringField(validators=[DataRequired()])
    etiqueta = StringField(validators=[Optional(), Length(max=60)])


class DhcpRangoForm(FlaskForm):
    inicio = StringField(validators=[DataRequired()])
    fin = StringField(validators=[DataRequired()])
    lease = StringField(validators=[DataRequired(), Regexp(r"^\d+[mh]$")])


class DnsForm(FlaskForm):
    servidores = StringField(validators=[DataRequired()])  # separados por coma


class MonitorForm(FlaskForm):
    destinos = StringField(validators=[DataRequired()])  # separados por coma
    intervalo_s = IntegerField(validators=[DataRequired()])
    fallos_caida = IntegerField(validators=[DataRequired()])
    exitos_alta = IntegerField(validators=[DataRequired()])


class WifiConfigForm(FlaskForm):
    habilitada = SelectField(
        choices=[("1", "Activada"), ("0", "Desactivada")], validators=[DataRequired()]
    )


class WifiAgregarForm(FlaskForm):
    ssid = StringField(validators=[DataRequired(message="Escribe el nombre de la red (SSID)."), Length(min=1, max=32, message="El nombre de la red debe tener entre 1 y 32 caracteres.")])
    # La clave puede ir vacía (red abierta): nunca DataRequired. El rango
    # exacto (8-63 ASCII imprimibles o vacía) lo exige validacion.py. El
    # mensaje de error es un texto fijo que nunca repite lo que se escribió
    # (WTForms no incluye el valor por defecto, pero se fija explícitamente
    # para no depender de eso).
    clave = PasswordField(
        validators=[Optional(), Length(max=63, message="La clave no es válida.")]
    )
    prioridad = IntegerField(validators=[Optional(), NumberRange(min=0, max=100, message="La prioridad debe estar entre 0 y 100.")])


class WifiEliminarForm(FlaskForm):
    ssid = StringField(validators=[DataRequired(message="Falta el nombre de la red.")])


class WifiConectarForm(FlaskForm):
    ssid = StringField(validators=[DataRequired(message="Falta el nombre de la red.")])


class WifiEscanearForm(FlaskForm):
    pass


class BloqueoSeccionEstadoForm(FlaskForm):
    """Sección «Estado» de /proteccion: sólo cambia `habilitado`. La vista
    relee `leer_estado()` justo antes de combinar y envía el resto de campos
    del contrato `bloqueo_config` con el valor ACTUAL (nunca con lo que esta
    página tenía pintado, para no pisar un cambio concurrente -ver
    `proteccion.config()`-). `seccion`/`version` son HiddenField: el primero
    identifica qué sección se envió, el segundo es `config.bloqueo_version`
    tal como estaba cuando se pintó la página (concurrencia optimista; campo
    opcional, en espera de que el núcleo lo admita)."""
    seccion = HiddenField(validators=[DataRequired()])
    version = HiddenField(validators=[Optional()])
    habilitado = SelectField(
        choices=[("1", "Activado"), ("0", "Desactivado")],
        validators=[DataRequired(message="Elige si el bloqueo está activado o desactivado.")],
    )


class BloqueoSeccionListasForm(FlaskForm):
    """Sección «Listas»: `listas` (checkboxes de nombre repetido) se lee en
    la vista con `request.form.getlist`, no aquí."""
    seccion = HiddenField(validators=[DataRequired()])
    version = HiddenField(validators=[Optional()])


class BloqueoSeccionOpcionesForm(FlaskForm):
    seccion = HiddenField(validators=[DataRequired()])
    version = HiddenField(validators=[Optional()])
    forzar_dns = BooleanField(validators=[Optional()], false_values=("0", "false", ""))
    bloquear_doh = BooleanField(validators=[Optional()], false_values=("0", "false", ""))
    actualizar_h = IntegerField(
        validators=[
            InputRequired(message="La frecuencia de actualización es obligatoria."),
            NumberRange(min=6, max=168, message="La frecuencia de actualización debe estar entre 6 y 168 horas."),
        ]
    )
    registro_dns_dias = IntegerField(
        validators=[
            InputRequired(message="Los días de registro DNS son obligatorios."),
            NumberRange(min=1, max=365, message="Los días de registro DNS deben estar entre 1 y 365."),
        ]
    )


class BloqueoActualizarForm(FlaskForm):
    # `forzar` sólo se envía (=1) desde el botón «Forzar actualización»
    # cuando la guarda de variación ±50% frenó la pasada anterior (ver
    # docs/CONTRATO.md; campo opcional, en espera de que el núcleo lo admita).
    forzar = BooleanField(validators=[Optional()])


class BloqueoProbarForm(FlaskForm):
    dominio = StringField(
        validators=[
            DataRequired(message="Escribe un dominio para comprobar."),
            Length(max=253, message="Ese dominio es demasiado largo."),
        ]
    )


class BloqueoListaForm(FlaskForm):
    tipo = StringField(validators=[DataRequired()])
    accion = StringField(validators=[DataRequired()])
    dominio = StringField(
        validators=[
            DataRequired(message="Escribe un dominio."),
            Length(max=253, message="Ese dominio es demasiado largo."),
        ]
    )


class CambiarPasswordForm(FlaskForm):
    password_actual = PasswordField(validators=[DataRequired(message="Falta la contraseña actual.")])
    password_nueva = PasswordField(
        validators=[
            DataRequired(message="Falta la contraseña nueva."),
            Length(min=12, message="La contraseña nueva debe tener al menos 12 caracteres."),
        ]
    )
    password_repetir = PasswordField(
        validators=[
            DataRequired(message="Repite la contraseña nueva."),
            EqualTo("password_nueva", message="Las contraseñas no coinciden."),
        ]
    )


class FwReglaForm(FlaskForm):
    """Formulario de regla de firewall (crear/editar, FIREWALL_PLAN.md).

    `regla_id` está vacío al crear (la id la genera siempre el core); al
    editar lleva la `r_` + 8 hex de la regla existente. `version` es la
    `firewall.version` vista al pintar la página (concurrencia optimista).
    El origen/destino se compone en la vista a partir de `*_tipo` + el campo
    de valor que corresponda (`origen_dispositivo` es el selector de
    dispositivos; manda sobre `origen_valor` si viene relleno)."""
    regla_id = HiddenField(validators=[Optional()])
    version = HiddenField(validators=[Optional()])
    nombre = StringField(
        validators=[
            DataRequired(message="Escribe un nombre para la regla."),
            Length(max=64, message="El nombre es demasiado largo."),
        ]
    )
    habilitada = BooleanField(validators=[Optional()], false_values=("0", "false", ""))
    accion = SelectField(
        choices=[("bloquear", "Bloquear"), ("rechazar", "Rechazar"), ("permitir", "Permitir")],
        validators=[DataRequired(message="Elige la acción de la regla.")],
    )
    origen_tipo = SelectField(
        choices=[
            ("cualquiera", "Cualquiera"),
            ("mac", "Dispositivo (MAC)"),
            ("ip", "IP"),
            ("red", "Red"),
            ("grupo", "Grupo"),
        ],
        validators=[DataRequired(message="Elige el origen.")],
    )
    origen_valor = StringField(validators=[Optional(), Length(max=64)])
    origen_dispositivo = StringField(validators=[Optional()])
    origen_grupo = StringField(validators=[Optional()])
    destino_tipo = SelectField(
        choices=[
            ("cualquiera", "Cualquiera"),
            ("ip", "IP"),
            ("red", "Red"),
            ("grupo", "Grupo"),
        ],
        validators=[DataRequired(message="Elige el destino.")],
    )
    destino_valor = StringField(validators=[Optional(), Length(max=64)])
    destino_grupo = StringField(validators=[Optional()])
    protocolo = SelectField(
        choices=[
            ("cualquiera", "Cualquiera"),
            ("tcp", "TCP"),
            ("udp", "UDP"),
            ("tcp_udp", "TCP/UDP"),
            ("icmp", "ICMP"),
        ],
        validators=[DataRequired(message="Elige el protocolo.")],
    )
    puertos = StringField(validators=[Optional(), Length(max=200)])
    registrar = BooleanField(validators=[Optional()], false_values=("0", "false", ""))
    comentario = StringField(validators=[Optional(), Length(max=240)])


class FwReglaAccionForm(FlaskForm):
    """Acciones de fila sobre una regla (eliminar/mover/activar). Todos los
    campos van ocultos; el botón de la fila es el que envía el formulario.
    `habilitada` viaja como «0»/«1» y la vista lo convierte a bool."""
    version = HiddenField(validators=[Optional()])
    regla_id = HiddenField(validators=[DataRequired(message="Falta identificar la regla.")])
    posicion = HiddenField(validators=[Optional()])
    habilitada = HiddenField(validators=[Optional()])


class FwGrupoForm(FlaskForm):
    """Formulario de grupo mac/ip de firewall (crear/editar). `grupo_id` está
    vacío al crear. Los miembros llegan como casillas (`miembros`) y como
    texto libre (`miembros_texto`, uno por línea); la vista los une."""
    grupo_id = HiddenField(validators=[Optional()])
    version = HiddenField(validators=[Optional()])
    nombre = StringField(
        validators=[
            DataRequired(message="Escribe un nombre para el grupo."),
            Length(max=64, message="El nombre es demasiado largo."),
        ]
    )
    tipo = SelectField(
        choices=[("mac", "Direcciones MAC"), ("ip", "Direcciones IP")],
        validators=[DataRequired(message="Elige el tipo de grupo.")],
    )
    miembros_texto = StringField(validators=[Optional(), Length(max=4000)])


class FwGrupoEliminarForm(FlaskForm):
    version = HiddenField(validators=[Optional()])
    grupo_id = HiddenField(validators=[DataRequired(message="Falta identificar el grupo.")])
