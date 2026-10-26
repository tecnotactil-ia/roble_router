"""Validación de peticiones hacia el núcleo (routerd).

Replica EXACTAMENTE las reglas del contrato (`docs/CONTRATO.md`), para que el
panel rechace de antemano lo que routerd rechazaría también. El panel nunca
confía sólo en el formulario HTML: toda petición pasa por aquí antes de
escribirse en el buzón.

Cada función `validar_<accion>(datos, contexto)` devuelve una tupla
``(ok: bool, error: str | None, datos_normalizados: dict | None)``.
``contexto`` es un dict con información del estado actual (p. ej. wans
existentes, rango de la LAN) necesaria para validar referencias cruzadas.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

NOMBRE_WAN_RE = re.compile(r"^[\w .-]{1,32}$")
ETIQUETA_RE = re.compile(r"^[\x20-\x7eÀ-ÿ]{0,60}$")
NOMBRE_RESERVA_RE = re.compile(r"^[a-z0-9-]{1,40}$")
LEASE_RE = re.compile(r"^\d+[mh]$")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
# Wi-Fi WAN (docs/CONTRATO.md): mismo rigor que core/peticiones.py. El SSID
# admite cualquier byte UTF-8 salvo caracteres de control (0x00-0x1f, 0x7f);
# la clave es la vacía (red abierta) o 8-63 ASCII imprimibles (WPA-PSK).
RE_CONTROL_WIFI = re.compile(r"[\x00-\x1f\x7f]")
CLAVE_WIFI_RE = re.compile(r"^[\x20-\x7e]{8,63}$")

# Bloqueador DNS (docs/CONTRATO.md, core/router_bloqueo.py): mismas reglas de
# sintaxis de dominio que el demonio (`normalizar_dominio`), replicadas aquí
# porque el panel nunca importa `core/` (sin privilegios, sin acceso directo
# al núcleo). Las URLs del catálogo NUNCA viven en el panel: sólo estos ids.
RE_ETIQUETA_DOMINIO = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_CARACTERES_PROHIBIDOS_DOMINIO = re.compile(r'[\s\x00-\x1f\x7f/\\=;,*?#\'"`$|&<>%@:]')
# `bloqueo_config` -> "version" (concurrencia optimista, docs/CONTRATO.md):
# hex de 16 caracteres -mismo `re.fullmatch` que core/peticiones.py-.
RE_BLOQUEO_VERSION = re.compile(r"[0-9a-f]{16}")

# Firewall con reglas propias (FIREWALL_PLAN.md): mismas reglas que
# `core/peticiones.py`, replicadas aquí para que el panel rechace de antemano
# lo que routerd rechazaría también. Las ids las genera SIEMPRE el core
# (`r_`/`g_` + 8 hex); el panel nunca las inventa.
RE_NOMBRE_FW = re.compile(r"[A-Za-z0-9_ .áéíóúñÁÉÍÓÚÑ-]{1,40}")
RE_ID_REGLA_FW = re.compile(r"r_[0-9a-f]{8}")
RE_ID_GRUPO_FW = re.compile(r"g_[0-9a-f]{8}")
RE_CONTROL_FW = re.compile(r"[\x00-\x1f\x7f]")
MAX_REGLAS_FW = 200
MAX_GRUPOS_FW = 50
MAX_MIEMBROS_GRUPO = 256
MAX_PUERTOS_REGLA = 15
COMENTARIO_FW_MAX = 120
ACCIONES_FW = ("permitir", "bloquear", "rechazar")
PROTOCOLOS_FW = ("cualquiera", "tcp", "udp", "tcp_udp", "icmp")
TIPOS_ORIGEN_FW = ("cualquiera", "mac", "ip", "red", "grupo")
TIPOS_DESTINO_FW = ("cualquiera", "ip", "red", "grupo")

CATALOGO_BLOQUEO_IDS = frozenset({
    "hagezi_light", "hagezi_multi", "hagezi_pro", "hagezi_pro_plus",
    "hagezi_tif", "hagezi_doh", "hagezi_nsfw", "hagezi_gambling",
})

# M5 (router_bloqueo.py): sufijos públicos de dos etiquetas más habituales
# -misma lista, para rechazar en el formulario lo mismo que rechazaría el
# demonio al añadir a la lista negra-.
SUFIJOS_PUBLICOS_DOS_ETIQUETAS = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.mx", "com.br", "com.ar", "com.co", "com.pe", "com.ve",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.il", "co.th", "co.id",
    "com.cn", "com.tw", "com.hk", "com.sg", "com.my", "com.ph", "com.pk",
    "com.tr", "com.ua", "com.pl",
})

# M5 (router_bloqueo.PROTEGIDOS_FIJOS): dominios que el núcleo NUNCA bloquea
# -lo que el propio router necesita para funcionar-, copiados aquí como
# defensa adicional en el formulario (el núcleo sigue siendo quien decide de
# verdad; esto sólo evita que el admin crea que "ya está en la negra" cuando
# nunca llegaría a bloquearse). No incluye el dominio de casa
# (`router.json` -> `dominio`), que el panel no tiene forma de leer.
PROTEGIDOS_FIJOS = frozenset({
    "raw.githubusercontent.com", "github.com",
    "api.hosting.ionos.com",
    "acme-v02.api.letsencrypt.org", "letsencrypt.org",
    "deb.debian.org", "security.debian.org", "debian.org",
    "pool.ntp.org", "ntp.org",
    "time.cloudflare.com",
})

ACCIONES_VALIDAS = {
    "wan_actualizar",
    "modo",
    "modo_pesos",
    "reserva_agregar",
    "reserva_eliminar",
    "dispositivo_etiquetar",
    "dhcp_rango",
    "dns",
    "monitor",
    "wifi_config",
    "wifi_agregar",
    "wifi_eliminar",
    "wifi_conectar",
    "wifi_escanear",
    "bloqueo_config",
    "bloqueo_lista",
    "bloqueo_actualizar",
    "bloqueo_probar",
    "fw_regla_guardar",
    "fw_regla_eliminar",
    "fw_regla_mover",
    "fw_regla_activar",
    "fw_grupo_guardar",
    "fw_grupo_eliminar",
}


class ErrorValidacion(Exception):
    """Se lanza con un mensaje en español listo para mostrar al usuario."""


def _normalizar_mac(mac: Any) -> str:
    if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):
        raise ErrorValidacion("La dirección MAC no es válida.")
    return mac.lower()


def _validar_ip(valor: Any, campo: str) -> str:
    if not isinstance(valor, str):
        raise ErrorValidacion(f"{campo} no es una IPv4 válida.")
    try:
        ip = ipaddress.IPv4Address(valor)
    except ipaddress.AddressValueError:
        raise ErrorValidacion(f"{campo} no es una IPv4 válida.")
    return str(ip)


def _red_lan(contexto: dict) -> ipaddress.IPv4Network | None:
    lan = (contexto or {}).get("lan_red")
    if not lan:
        return None
    try:
        return ipaddress.IPv4Network(lan, strict=False)
    except ValueError:
        return None


def _en_lan(ip: str, contexto: dict) -> bool:
    red = _red_lan(contexto)
    if red is None:
        # Sin información de la LAN no podemos verificar: se deja pasar y
        # que routerd aplique su propia validación definitiva.
        return True
    return ipaddress.IPv4Address(ip) in red


def validar_wan_actualizar(datos: dict, contexto: dict | None = None) -> dict:
    contexto = contexto or {}
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    wan = datos.get("wan")
    wans_existentes = contexto.get("wans_ids") or []
    if not isinstance(wan, str) or not wan:
        raise ErrorValidacion("Falta identificar la WAN a modificar.")
    if wans_existentes and wan not in wans_existentes:
        raise ErrorValidacion("Esa WAN no existe.")

    salida: dict[str, Any] = {"wan": wan}

    if "nombre" in datos and datos["nombre"] is not None:
        nombre = datos["nombre"]
        if not isinstance(nombre, str) or not NOMBRE_WAN_RE.fullmatch(nombre):
            raise ErrorValidacion(
                "El nombre debe tener entre 1 y 32 caracteres (letras, números, espacios, puntos o guiones)."
            )
        salida["nombre"] = nombre

    if "habilitada" in datos and datos["habilitada"] is not None:
        habilitada = datos["habilitada"]
        if not isinstance(habilitada, bool):
            raise ErrorValidacion("«Habilitada» debe ser verdadero o falso.")
        salida["habilitada"] = habilitada

    if "peso" in datos and datos["peso"] is not None:
        peso = datos["peso"]
        if isinstance(peso, bool) or not isinstance(peso, int):
            raise ErrorValidacion("El peso debe ser un número entero entre 1 y 100.")
        if peso < 1 or peso > 100:
            raise ErrorValidacion("El peso debe estar entre 1 y 100.")
        salida["peso"] = peso

    if "prioridad" in datos and datos["prioridad"] is not None:
        prioridad = datos["prioridad"]
        if isinstance(prioridad, bool) or not isinstance(prioridad, int):
            raise ErrorValidacion("La prioridad debe ser un número entero entre 1 y 9.")
        if prioridad < 1 or prioridad > 9:
            raise ErrorValidacion("La prioridad debe estar entre 1 y 9.")
        salida["prioridad"] = prioridad

    if len(salida) == 1:
        raise ErrorValidacion("No se indicó ningún cambio para la WAN.")

    return salida


def validar_modo(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict) or datos.get("modo") not in ("balanceo", "respaldo"):
        raise ErrorValidacion("El modo debe ser «balanceo» o «respaldo».")
    return {"modo": datos["modo"]}


def validar_modo_pesos(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict) or datos.get("modo_pesos") not in ("auto", "manual"):
        raise ErrorValidacion("El reparto de pesos debe ser «automático» o «manual».")
    return {"modo_pesos": datos["modo_pesos"]}


def validar_reserva_agregar(datos: dict, contexto: dict | None = None) -> dict:
    contexto = contexto or {}
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    mac = _normalizar_mac(datos.get("mac"))
    ip = _validar_ip(datos.get("ip"), "La IP de la reserva")
    nombre = datos.get("nombre")
    if not isinstance(nombre, str) or not NOMBRE_RESERVA_RE.fullmatch(nombre):
        raise ErrorValidacion(
            "El nombre de la reserva debe tener entre 1 y 40 caracteres: minúsculas, números o guiones."
        )

    red = _red_lan(contexto)
    if red is not None:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj not in red:
            raise ErrorValidacion("La IP de la reserva debe estar dentro de la red LAN.")
        if ip_obj == red.network_address or ip_obj == red.broadcast_address:
            raise ErrorValidacion("La IP de la reserva no puede ser la de red o difusión.")
        if str(ip_obj) == str(contexto.get("lan_ip_router")):
            raise ErrorValidacion("La IP de la reserva no puede ser la del propio router (.1).")

    reservas = contexto.get("reservas") or []
    for r in reservas:
        if r.get("mac") == mac:
            raise ErrorValidacion("Ya existe una reserva con esa MAC.")
        if r.get("ip") == ip:
            raise ErrorValidacion("Ya existe una reserva con esa IP.")

    return {"mac": mac, "ip": ip, "nombre": nombre}


def validar_reserva_eliminar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    mac = _normalizar_mac(datos.get("mac"))
    return {"mac": mac}


def validar_dispositivo_etiquetar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    mac = _normalizar_mac(datos.get("mac"))
    etiqueta = datos.get("etiqueta", "")
    if not isinstance(etiqueta, str) or not ETIQUETA_RE.fullmatch(etiqueta):
        raise ErrorValidacion("La etiqueta debe tener como máximo 60 caracteres imprimibles.")
    return {"mac": mac, "etiqueta": etiqueta}


def validar_dhcp_rango(datos: dict, contexto: dict | None = None) -> dict:
    contexto = contexto or {}
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    inicio = _validar_ip(datos.get("inicio"), "El inicio del rango")
    fin = _validar_ip(datos.get("fin"), "El fin del rango")
    lease = datos.get("lease")
    if not isinstance(lease, str) or not LEASE_RE.fullmatch(lease):
        raise ErrorValidacion("El tiempo de lease debe ser un número seguido de «m» u «h» (ej. 12h).")

    red = _red_lan(contexto)
    if red is not None:
        ini_obj = ipaddress.IPv4Address(inicio)
        fin_obj = ipaddress.IPv4Address(fin)
        if ini_obj not in red or fin_obj not in red:
            raise ErrorValidacion("El rango DHCP debe estar dentro de la red LAN.")
        router_ip = contexto.get("lan_ip_router")
        if router_ip and (str(ini_obj) == str(router_ip) or str(fin_obj) == str(router_ip)):
            raise ErrorValidacion("El rango DHCP no puede incluir la IP del router (.1).")
        if ini_obj >= fin_obj:
            raise ErrorValidacion("El inicio del rango debe ser menor que el fin.")
    else:
        if ipaddress.IPv4Address(inicio) >= ipaddress.IPv4Address(fin):
            raise ErrorValidacion("El inicio del rango debe ser menor que el fin.")

    return {"inicio": inicio, "fin": fin, "lease": lease}


def validar_dns(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    servidores = datos.get("servidores")
    if not isinstance(servidores, list) or not (1 <= len(servidores) <= 4):
        raise ErrorValidacion("Debe indicar entre 1 y 4 servidores DNS.")
    normalizados = [_validar_ip(s, "Cada servidor DNS") for s in servidores]
    return {"servidores": normalizados}


def validar_monitor(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    destinos = datos.get("destinos")
    if not isinstance(destinos, list) or not (1 <= len(destinos) <= 4):
        raise ErrorValidacion("Debe indicar entre 1 y 4 destinos de monitorización.")
    destinos_norm = [_validar_ip(d, "Cada destino") for d in destinos]

    def _entero(nombre_campo: str, minimo: int, maximo: int) -> int:
        valor = datos.get(nombre_campo)
        if isinstance(valor, bool) or not isinstance(valor, int):
            raise ErrorValidacion(f"«{nombre_campo}» debe ser un número entero entre {minimo} y {maximo}.")
        if valor < minimo or valor > maximo:
            raise ErrorValidacion(f"«{nombre_campo}» debe estar entre {minimo} y {maximo}.")
        return valor

    intervalo_s = _entero("intervalo_s", 3, 60)
    fallos_caida = _entero("fallos_caida", 1, 10)
    exitos_alta = _entero("exitos_alta", 1, 10)

    return {
        "destinos": destinos_norm,
        "intervalo_s": intervalo_s,
        "fallos_caida": fallos_caida,
        "exitos_alta": exitos_alta,
    }


def _validar_ssid_wifi(valor: Any, contexto: dict | None = None, comprobar_bloqueada: bool = True) -> str:
    if not isinstance(valor, str):
        raise ErrorValidacion("El SSID debe ser una cadena de texto.")
    if RE_CONTROL_WIFI.search(valor):
        raise ErrorValidacion("El SSID no puede tener caracteres de control.")
    try:
        n = len(valor.encode("utf-8"))
    except UnicodeEncodeError:
        raise ErrorValidacion("El SSID no es un texto válido.")
    if not 1 <= n <= 32:
        raise ErrorValidacion("El SSID debe tener entre 1 y 32 bytes (UTF-8).")
    if comprobar_bloqueada:
        # Comparación sin distinguir mayúsculas/minúsculas ni espacios al
        # principio/final: el panel se adelanta así a bloquear variantes
        # obvias del mismo SSID aunque el demonio todavía compare en crudo
        # (el demonio se alineará con esta misma normalización).
        bloqueadas = {
            str(b).strip().casefold() for b in ((contexto or {}).get("wifi_bloqueadas") or [])
        }
        if valor.strip().casefold() in bloqueadas:
            raise ErrorValidacion(
                "Esa red es la Wi-Fi de casa: conectarse a ella crearía un bucle."
            )
    return valor


def validar_wifi_config(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict) or not isinstance(datos.get("habilitada"), bool):
        raise ErrorValidacion("«habilitada» debe ser verdadero o falso.")
    return {"habilitada": datos["habilitada"]}


def validar_wifi_agregar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    if not {"ssid", "clave", "prioridad"} <= set(datos):
        raise ErrorValidacion("Faltan campos: SSID, clave y prioridad son obligatorios.")

    ssid = _validar_ssid_wifi(datos.get("ssid"), contexto, comprobar_bloqueada=True)

    clave = datos.get("clave")
    if not isinstance(clave, str):
        raise ErrorValidacion("La clave debe ser una cadena de texto.")
    if clave != "" and not CLAVE_WIFI_RE.fullmatch(clave):
        raise ErrorValidacion(
            "La clave debe tener entre 8 y 63 caracteres ASCII imprimibles, "
            "o estar vacía para una red abierta."
        )

    prioridad = datos.get("prioridad")
    if isinstance(prioridad, bool) or not isinstance(prioridad, int) or not 0 <= prioridad <= 100:
        raise ErrorValidacion("La prioridad debe ser un número entero entre 0 y 100.")

    return {"ssid": ssid, "clave": clave, "prioridad": prioridad}


def validar_wifi_eliminar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict) or "ssid" not in datos:
        raise ErrorValidacion("Falta el SSID de la red a eliminar.")
    ssid = _validar_ssid_wifi(datos.get("ssid"), contexto, comprobar_bloqueada=False)
    return {"ssid": ssid}


def validar_wifi_conectar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict) or "ssid" not in datos:
        raise ErrorValidacion("Falta el SSID de la red a conectar.")
    ssid = _validar_ssid_wifi(datos.get("ssid"), contexto, comprobar_bloqueada=False)
    return {"ssid": ssid}


def validar_wifi_escanear(datos: dict, contexto: dict | None = None) -> dict:
    if datos not in (None, {}):
        raise ErrorValidacion("Esta acción no admite datos.")
    return {}


def normalizar_dominio_bloqueo(crudo: Any) -> str | None:
    """Replica `router_bloqueo.normalizar_dominio`: devuelve el dominio en
    minúsculas/punycode, sin punto final, o `None` si `crudo` no es un único
    dominio válido (ASCII/punycode, etiquetas 1-63, longitud total 1-253,
    nunca un «dominio» todo numérico). NUNCA copia la entrada tal cual."""
    if not isinstance(crudo, str):
        return None
    cruda = crudo.strip()
    if not cruda or cruda.startswith("#"):
        return None
    if _CARACTERES_PROHIBIDOS_DOMINIO.search(cruda):
        return None
    dominio = cruda.rstrip(".")
    if not dominio:
        return None
    try:
        dominio = dominio.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if not 1 <= len(dominio) <= 253:
        return None
    etiquetas = dominio.split(".")
    if len(etiquetas) < 2:
        return None
    for et in etiquetas:
        if not RE_ETIQUETA_DOMINIO.fullmatch(et):
            return None
    if etiquetas[-1].isdigit():  # "1.2.3.4": es una IP, no un dominio
        return None
    return dominio


def es_sufijo_publico_bloqueo(dominio: str | None) -> bool:
    return dominio is not None and dominio in SUFIJOS_PUBLICOS_DOS_ETIQUETAS


def validar_bloqueo_config(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    campos = ("habilitado", "listas", "forzar_dns", "bloquear_doh", "actualizar_h", "registro_dns_dias")
    # `version` (concurrencia optimista, config.bloqueo_version): opcional,
    # en espera de que el núcleo lo admita -ver BloqueoSeccion*Form-.
    campos_opcionales = ("version",)
    faltan = [c for c in campos if c not in datos]
    if faltan:
        raise ErrorValidacion("Faltan campos: %s." % ", ".join(faltan))
    sobra = set(datos) - set(campos) - set(campos_opcionales)
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))

    if not isinstance(datos["habilitado"], bool):
        raise ErrorValidacion("«Activado» debe ser verdadero o falso.")

    listas = datos["listas"]
    if not isinstance(listas, list) or not all(isinstance(x, str) for x in listas):
        raise ErrorValidacion("«listas» debe ser una lista de identificadores del catálogo.")
    desconocidas = sorted(set(listas) - CATALOGO_BLOQUEO_IDS)
    if desconocidas:
        raise ErrorValidacion("Lista(s) desconocida(s) del catálogo: %s." % ", ".join(desconocidas))

    if not isinstance(datos["forzar_dns"], bool):
        raise ErrorValidacion("«Forzar DNS» debe ser verdadero o falso.")
    if not isinstance(datos["bloquear_doh"], bool):
        raise ErrorValidacion("«Bloquear DoH» debe ser verdadero o falso.")

    actualizar_h = datos["actualizar_h"]
    if isinstance(actualizar_h, bool) or not isinstance(actualizar_h, int) or not 6 <= actualizar_h <= 168:
        raise ErrorValidacion("La frecuencia de actualización debe ser un entero entre 6 y 168 horas.")

    registro_dns_dias = datos["registro_dns_dias"]
    if isinstance(registro_dns_dias, bool) or not isinstance(registro_dns_dias, int) or not 1 <= registro_dns_dias <= 365:
        raise ErrorValidacion("Los días de registro DNS deben ser un entero entre 1 y 365.")

    salida = {
        "habilitado": datos["habilitado"],
        "listas": sorted(dict.fromkeys(listas)),
        "forzar_dns": datos["forzar_dns"],
        "bloquear_doh": datos["bloquear_doh"],
        "actualizar_h": actualizar_h,
        "registro_dns_dias": registro_dns_dias,
    }
    if "version" in datos:
        version = datos["version"]
        if not isinstance(version, str) or not RE_BLOQUEO_VERSION.fullmatch(version):
            raise ErrorValidacion("«version» debe ser una cadena hexadecimal de 16 caracteres.")
        salida["version"] = version
    return salida


def validar_bloqueo_lista(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"tipo", "accion", "dominio"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    if datos.get("tipo") not in ("blanca", "negra"):
        raise ErrorValidacion("«tipo» debe ser «blanca» o «negra».")
    if datos.get("accion") not in ("agregar", "quitar"):
        raise ErrorValidacion("«accion» debe ser «agregar» o «quitar».")
    dominio = normalizar_dominio_bloqueo(datos.get("dominio"))
    if dominio is None:
        raise ErrorValidacion("Ese dominio no es válido.")
    if datos["tipo"] == "negra" and datos["accion"] == "agregar":
        if es_sufijo_publico_bloqueo(dominio):
            raise ErrorValidacion(
                "«%s» es un sufijo público (como co.uk/com.es): bloquearlo entero afectaría a "
                "demasiados sitios ajenos." % dominio
            )
        # M5 (router_bloqueo.PROTEGIDOS_FIJOS): defensa adicional -el núcleo
        # también lo rechaza, pero avisar aquí evita que el admin crea que
        # "ya está en la negra" cuando nunca llegaría a bloquearse-.
        if dominio in PROTEGIDOS_FIJOS or any(
            dominio == p or dominio.endswith("." + p) for p in PROTEGIDOS_FIJOS
        ):
            raise ErrorValidacion(
                "«%s» es un dominio protegido (necesario para el propio router): nunca se "
                "puede bloquear." % dominio
            )
    return {"tipo": datos["tipo"], "accion": datos["accion"], "dominio": dominio}


def validar_bloqueo_actualizar(datos: dict, contexto: dict | None = None) -> dict:
    if datos is None:
        datos = {}
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"forzar"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    salida: dict[str, Any] = {}
    if "forzar" in datos:
        if not isinstance(datos["forzar"], bool):
            raise ErrorValidacion("«forzar» debe ser verdadero o falso.")
        salida["forzar"] = datos["forzar"]
    return salida


def validar_bloqueo_probar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict) or "dominio" not in datos:
        raise ErrorValidacion("Falta el dominio a comprobar.")
    sobra = set(datos) - {"dominio"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    dominio = normalizar_dominio_bloqueo(datos.get("dominio"))
    if dominio is None:
        raise ErrorValidacion("Ese dominio no es válido.")
    return {"dominio": dominio}


def _version_fw(datos: dict) -> int:
    """`version` (int) de concurrencia optimista de las acciones fw_*:
    la `firewall.version` que el panel vio en `config.firewall`. Es
    OBLIGATORIA en todas las acciones fw_* (a diferencia de `bloqueo_config`,
    que la tenía opcional): sin ella no hay forma de detectar que dos
    administradores se pisan, y el core la exige para mutar."""
    if "version" not in datos:
        raise ErrorValidacion("Falta el campo «version».")
    version = datos["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ErrorValidacion("«version» debe ser un número entero.")
    return version


def _validar_id_regla(valor: Any) -> str:
    if not isinstance(valor, str) or not RE_ID_REGLA_FW.fullmatch(valor):
        raise ErrorValidacion("«id» de regla no válida.")
    return valor


def _validar_id_grupo(valor: Any) -> str:
    if not isinstance(valor, str) or not RE_ID_GRUPO_FW.fullmatch(valor):
        raise ErrorValidacion("«id» de grupo no válido.")
    return valor


def _nombre_fw(valor: Any) -> str:
    if not isinstance(valor, str) or not RE_NOMBRE_FW.fullmatch(valor):
        raise ErrorValidacion(
            "El nombre debe tener entre 1 y 40 caracteres: letras, números, espacios, punto, guion, tildes o ñ."
        )
    return valor


def _comentario_fw(valor: Any) -> str:
    if valor is None:
        return ""
    if not isinstance(valor, str) or len(valor) > COMENTARIO_FW_MAX:
        raise ErrorValidacion("El comentario debe tener como máximo %d caracteres." % COMENTARIO_FW_MAX)
    if RE_CONTROL_FW.search(valor):
        raise ErrorValidacion("El comentario no puede tener caracteres de control.")
    return valor


def _validar_puertos_fw(puertos: Any, protocolo: str) -> list:
    if puertos is None:
        return []
    if not isinstance(puertos, list):
        raise ErrorValidacion("«puertos» debe ser una lista de rangos.")
    if not puertos:
        return []
    if len(puertos) > MAX_PUERTOS_REGLA:
        raise ErrorValidacion("Máximo %d rangos de puertos por regla." % MAX_PUERTOS_REGLA)
    if protocolo not in ("tcp", "udp", "tcp_udp"):
        raise ErrorValidacion("Los puertos sólo aplican al protocolo tcp, udp o tcp_udp.")
    salida = []
    for rango in puertos:
        if not isinstance(rango, dict) or set(rango) != {"desde", "hasta"}:
            raise ErrorValidacion("Cada rango de puertos debe tener «desde» y «hasta».")
        desde = rango["desde"]
        hasta = rango["hasta"]
        if isinstance(desde, bool) or not isinstance(desde, int) or not 1 <= desde <= 65535:
            raise ErrorValidacion("El puerto «desde» debe estar entre 1 y 65535.")
        if isinstance(hasta, bool) or not isinstance(hasta, int) or not 1 <= hasta <= 65535:
            raise ErrorValidacion("El puerto «hasta» debe estar entre 1 y 65535.")
        if desde > hasta:
            raise ErrorValidacion("El puerto «desde» no puede ser mayor que «hasta».")
        salida.append({"desde": desde, "hasta": hasta})
    return salida


def _validar_endpoint_fw(ep: Any, es_origen: bool) -> dict:
    """Valida origen/destino de una regla: `{tipo, valor?}`. El MAC sólo tiene
    sentido como origen; el grupo de destino debe ser tipo ip (eso lo comprueba
    el core contra la config real; aquí sólo la forma)."""
    if not isinstance(ep, dict):
        raise ErrorValidacion("El origen/destino debe ser un objeto con «tipo».")
    tipo = ep.get("tipo")
    tipos = TIPOS_ORIGEN_FW if es_origen else TIPOS_DESTINO_FW
    if tipo not in tipos:
        raise ErrorValidacion(
            "Tipo de %s no válido: %s." % ("origen" if es_origen else "destino", ", ".join(tipos))
        )
    if tipo == "cualquiera":
        return {"tipo": "cualquiera"}
    valor = ep.get("valor")
    if not isinstance(valor, str) or not valor:
        raise ErrorValidacion("Falta el valor del %s." % ("origen" if es_origen else "destino"))
    if tipo == "mac":
        return {"tipo": "mac", "valor": _normalizar_mac(valor)}
    if tipo == "ip":
        return {"tipo": "ip", "valor": _validar_ip(valor, "La IP del %s" % ("origen" if es_origen else "destino"))}
    if tipo == "red":
        try:
            red = ipaddress.IPv4Network(valor, strict=True)
        except (ValueError, TypeError):
            raise ErrorValidacion("La red del %s no es una red CIDR IPv4 válida." % ("origen" if es_origen else "destino"))
        return {"tipo": "red", "valor": str(red)}
    # grupo
    return {"tipo": "grupo", "valor": _validar_id_grupo(valor)}


def validar_fw_regla_guardar(datos: dict, contexto: dict | None = None) -> dict:
    """`fw_regla_guardar` (FIREWALL_PLAN.md): `{version, regla, posicion?}`.
    La `regla` lleva `id` sólo al editar (en creación la genera el core)."""
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"version", "regla", "posicion"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    version = _version_fw(datos)
    regla = datos.get("regla")
    if not isinstance(regla, dict):
        raise ErrorValidacion("«regla» debe ser un objeto.")
    campos_regla = {"id", "nombre", "habilitada", "accion", "origen", "destino",
                    "protocolo", "puertos", "registrar", "comentario"}
    sobra_regla = set(regla) - campos_regla
    if sobra_regla:
        raise ErrorValidacion("Campos no admitidos en la regla: %s." % ", ".join(sorted(sobra_regla)))

    salida_regla: dict[str, Any] = {}
    if "id" in regla and regla["id"] is not None:
        salida_regla["id"] = _validar_id_regla(regla["id"])
    salida_regla["nombre"] = _nombre_fw(regla.get("nombre"))
    habilitada = regla.get("habilitada", True)
    if not isinstance(habilitada, bool):
        raise ErrorValidacion("«habilitada» debe ser verdadero o falso.")
    salida_regla["habilitada"] = habilitada
    accion = regla.get("accion")
    if accion not in ACCIONES_FW:
        raise ErrorValidacion("La acción debe ser «permitir», «bloquear» o «rechazar».")
    salida_regla["accion"] = accion
    salida_regla["origen"] = _validar_endpoint_fw(
        regla.get("origen") or {"tipo": "cualquiera"}, es_origen=True
    )
    salida_regla["destino"] = _validar_endpoint_fw(
        regla.get("destino") or {"tipo": "cualquiera"}, es_origen=False
    )
    protocolo = regla.get("protocolo", "cualquiera")
    if protocolo not in PROTOCOLOS_FW:
        raise ErrorValidacion("El protocolo debe ser cualquiera, tcp, udp, tcp_udp o icmp.")
    salida_regla["protocolo"] = protocolo
    salida_regla["puertos"] = _validar_puertos_fw(regla.get("puertos") or [], protocolo)
    registrar = regla.get("registrar", False)
    if not isinstance(registrar, bool):
        raise ErrorValidacion("«registrar» debe ser verdadero o falso.")
    salida_regla["registrar"] = registrar
    salida_regla["comentario"] = _comentario_fw(regla.get("comentario", ""))

    salida: dict[str, Any] = {"version": version, "regla": salida_regla}
    if "posicion" in datos and datos["posicion"] is not None:
        posicion = datos["posicion"]
        if isinstance(posicion, bool) or not isinstance(posicion, int) or posicion < 0:
            raise ErrorValidacion("La posición debe ser un número entero mayor o igual que 0.")
        salida["posicion"] = posicion
    return salida


def validar_fw_regla_eliminar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"version", "id"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    return {"version": _version_fw(datos), "id": _validar_id_regla(datos.get("id"))}


def validar_fw_regla_mover(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"version", "id", "posicion"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    posicion = datos.get("posicion")
    if isinstance(posicion, bool) or not isinstance(posicion, int) or posicion < 0:
        raise ErrorValidacion("La posición debe ser un número entero mayor o igual que 0.")
    return {"version": _version_fw(datos), "id": _validar_id_regla(datos.get("id")), "posicion": posicion}


def validar_fw_regla_activar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"version", "id", "habilitada"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    habilitada = datos.get("habilitada")
    if not isinstance(habilitada, bool):
        raise ErrorValidacion("«habilitada» debe ser verdadero o falso.")
    return {"version": _version_fw(datos), "id": _validar_id_regla(datos.get("id")), "habilitada": habilitada}


def validar_fw_grupo_guardar(datos: dict, contexto: dict | None = None) -> dict:
    """`fw_grupo_guardar` (FIREWALL_PLAN.md): `{version, grupo}`. El grupo
    lleva `id` sólo al editar (en creación la genera el core)."""
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"version", "grupo"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    version = _version_fw(datos)
    grupo = datos.get("grupo")
    if not isinstance(grupo, dict):
        raise ErrorValidacion("«grupo» debe ser un objeto.")
    campos_grupo = {"id", "nombre", "tipo", "miembros"}
    sobra_grupo = set(grupo) - campos_grupo
    if sobra_grupo:
        raise ErrorValidacion("Campos no admitidos en el grupo: %s." % ", ".join(sorted(sobra_grupo)))

    salida_grupo: dict[str, Any] = {}
    if "id" in grupo and grupo["id"] is not None:
        salida_grupo["id"] = _validar_id_grupo(grupo["id"])
    salida_grupo["nombre"] = _nombre_fw(grupo.get("nombre"))
    tipo = grupo.get("tipo")
    if tipo not in ("mac", "ip"):
        raise ErrorValidacion("El tipo de grupo debe ser «mac» o «ip».")
    salida_grupo["tipo"] = tipo
    miembros = grupo.get("miembros") or []
    if not isinstance(miembros, list):
        raise ErrorValidacion("«miembros» debe ser una lista.")
    if len(miembros) > MAX_MIEMBROS_GRUPO:
        raise ErrorValidacion("Máximo %d miembros por grupo." % MAX_MIEMBROS_GRUPO)
    normalizados = []
    for m in miembros:
        if tipo == "mac":
            normalizados.append(_normalizar_mac(m))
        else:
            normalizados.append(_validar_ip(m, "Cada miembro"))
    salida_grupo["miembros"] = normalizados
    return {"version": version, "grupo": salida_grupo}


def validar_fw_grupo_eliminar(datos: dict, contexto: dict | None = None) -> dict:
    if not isinstance(datos, dict):
        raise ErrorValidacion("Datos de la petición inválidos.")
    sobra = set(datos) - {"version", "id"}
    if sobra:
        raise ErrorValidacion("Campos no admitidos: %s." % ", ".join(sorted(sobra)))
    return {"version": _version_fw(datos), "id": _validar_id_grupo(datos.get("id"))}


VALIDADORES = {
    "wan_actualizar": validar_wan_actualizar,
    "modo": validar_modo,
    "modo_pesos": validar_modo_pesos,
    "reserva_agregar": validar_reserva_agregar,
    "reserva_eliminar": validar_reserva_eliminar,
    "dispositivo_etiquetar": validar_dispositivo_etiquetar,
    "dhcp_rango": validar_dhcp_rango,
    "dns": validar_dns,
    "monitor": validar_monitor,
    "wifi_config": validar_wifi_config,
    "wifi_agregar": validar_wifi_agregar,
    "wifi_eliminar": validar_wifi_eliminar,
    "wifi_conectar": validar_wifi_conectar,
    "wifi_escanear": validar_wifi_escanear,
    "bloqueo_config": validar_bloqueo_config,
    "bloqueo_lista": validar_bloqueo_lista,
    "bloqueo_actualizar": validar_bloqueo_actualizar,
    "bloqueo_probar": validar_bloqueo_probar,
    "fw_regla_guardar": validar_fw_regla_guardar,
    "fw_regla_eliminar": validar_fw_regla_eliminar,
    "fw_regla_mover": validar_fw_regla_mover,
    "fw_regla_activar": validar_fw_regla_activar,
    "fw_grupo_guardar": validar_fw_grupo_guardar,
    "fw_grupo_eliminar": validar_fw_grupo_eliminar,
}


def validar_peticion(accion: str, datos: dict, contexto: dict | None = None) -> dict:
    """Valida una petición completa. Lanza ErrorValidacion si es inválida."""
    if accion not in ACCIONES_VALIDAS:
        raise ErrorValidacion("Acción no reconocida.")
    return VALIDADORES[accion](datos, contexto)
