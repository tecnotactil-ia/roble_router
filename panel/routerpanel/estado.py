"""Lectura tolerante del estado publicado por routerd y ficheros asociados.

El panel nunca escribe estos ficheros, sólo los lee. Si no existen o están
corruptos se devuelve una estructura «sin datos» en vez de lanzar una
excepción, para que el dashboard siga funcionando (con un aviso).
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Formato de id de regla de firewall (`r_` + 8 hex, FIREWALL_PLAN.md). Se
# replica aquí (defensa en profundidad, igual que `core/nft_conf.py`) para que
# `normalizar_firewall` pueda descartar claves de `firewall_aciertos` que no
# sean ids de regla creíbles en vez de pintarlas como «hits» inventados.
RE_ID_REGLA_FW = re.compile(r"r_[0-9a-f]{8}")


def _ruta(var_entorno: str, por_defecto: str) -> str:
    return os.environ.get(var_entorno, por_defecto)


def ruta_estado() -> str:
    return _ruta("ROUTER_ESTADO", "/run/router/estado.json")


def ruta_firewall() -> str:
    return _ruta("ROUTER_FIREWALL", "/run/router/firewall.txt")


def ruta_leases() -> str:
    return _ruta("ROUTER_LEASES", "/var/lib/misc/dnsmasq.leases")


def ruta_oplog() -> str:
    return _ruta("ROUTER_OPLOG", "/var/log/router/operaciones.log")


def ruta_bloqueo() -> str:
    return _ruta("ROUTER_BLOQUEO", "/run/router/bloqueo.json")


@dataclass
class Estado:
    """Representación tolerante de estado.json."""

    disponible: bool = False
    error: str | None = None
    generado: str | None = None
    antiguedad_s: float | None = None
    uptime_s: int | None = None
    modo: str | None = None
    modo_pesos: str = "auto"
    fase: str | None = None
    lan: dict = field(default_factory=dict)
    servicios: dict = field(default_factory=dict)
    internet: bool | None = None
    wans: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    vecinos: dict = field(default_factory=dict)
    wifi: dict = field(default_factory=dict)
    wifi_ap: dict = field(default_factory=dict)
    dns_emergencia: dict = field(default_factory=dict)
    bruto: dict = field(default_factory=dict)

    @property
    def caido(self) -> bool:
        """El demonio se considera caído si no hay datos o son viejos (>30 s)."""
        if not self.disponible:
            return True
        if self.antiguedad_s is None:
            return True
        return self.antiguedad_s > 30


def leer_estado() -> Estado:
    ruta = ruta_estado()
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            bruto = json.load(f)
    except FileNotFoundError:
        return Estado(disponible=False, error="No hay datos: estado.json no existe todavía.")
    except (json.JSONDecodeError, OSError, ValueError):
        return Estado(disponible=False, error="No hay datos: estado.json está corrupto o ilegible.")

    if not isinstance(bruto, dict):
        return Estado(disponible=False, error="No hay datos: estado.json tiene un formato inesperado.")

    generado = bruto.get("generado")
    antiguedad_s = None
    if isinstance(generado, str):
        try:
            dt = datetime.fromisoformat(generado)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            antiguedad_s = (datetime.now(timezone.utc) - dt).total_seconds()
        except ValueError:
            antiguedad_s = None

    wans = bruto.get("wans")
    if not isinstance(wans, list):
        wans = []
    # routerd nunca debería publicar algo que no sea un objeto por WAN, pero
    # se normaliza aquí (una sola vez) en vez de que cada vista tenga que
    # comprobarlo por su cuenta: así el resto del panel puede asumir que
    # `est.wans` es siempre una lista de dict.
    wans = [w for w in wans if isinstance(w, dict)]

    # `modo_pesos` puede faltar o venir null cuando nunca se cambió (routerd
    # todavía no lo publicaba, o simplemente usa el valor por defecto): se
    # trata igual que el demonio, como "auto".
    modo_pesos = bruto.get("modo_pesos")
    if modo_pesos not in ("auto", "manual"):
        modo_pesos = "auto"

    return Estado(
        disponible=True,
        error=None,
        generado=generado,
        antiguedad_s=antiguedad_s,
        uptime_s=bruto.get("uptime_s"),
        modo=bruto.get("modo"),
        modo_pesos=modo_pesos,
        fase=bruto.get("fase") if isinstance(bruto.get("fase"), str) else None,
        lan=bruto.get("lan") if isinstance(bruto.get("lan"), dict) else {},
        servicios=bruto.get("servicios") if isinstance(bruto.get("servicios"), dict) else {},
        internet=bruto.get("internet"),
        wans=wans,
        config=bruto.get("config") if isinstance(bruto.get("config"), dict) else {},
        vecinos=bruto.get("vecinos") if isinstance(bruto.get("vecinos"), dict) else {},
        wifi=_normalizar_wifi(bruto.get("wifi")),
        wifi_ap=_normalizar_wifi_ap(bruto.get("wifi_ap")),
        dns_emergencia=_normalizar_dns_emergencia(bruto.get("dns_emergencia")),
        bruto=bruto,
    )


def _ssid_seguro(valor: Any) -> str | None:
    """Convierte a `str` y descarta SSID que no se puedan codificar en UTF-8
    (p. ej. cadenas con "surrogates" sueltos): nunca debe romper al pintar
    la página ni al construir la petición hacia routerd."""
    if not valor:
        return None
    texto = str(valor)
    try:
        texto.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return texto


def _numero_acotado(valor: Any, lo: int, hi: int) -> int | None:
    """Convierte a entero acotado [lo, hi]; descarta bool, NaN/infinito y
    cualquier cosa que no sea un número (devuelve `None` en esos casos, en
    vez de romper o dejar pasar un valor absurdo). Un número finito fuera de
    rango se recorta al límite más cercano en vez de descartarse del todo."""
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        n: float = valor
    elif isinstance(valor, float):
        if not math.isfinite(valor):
            return None
        n = valor
    else:
        return None
    if n < lo:
        return lo
    if n > hi:
        return hi
    return int(n)


def _texto_o_ninguno(valor: Any) -> str | None:
    """Para campos de presentación como `seguridad`/`canal` del escaneo
    Wi-Fi: sólo `str` o `int` (nunca `bool`) se convierten a texto; cualquier
    otro tipo (dict, list, float...) se descarta como `None` en vez de
    forzarlo a texto con `str()`, que podría pintar basura irreconocible."""
    if isinstance(valor, bool):
        return None
    if isinstance(valor, (str, int)):
        return str(valor)
    return None


def _normalizar_wifi(bruto: Any) -> dict:
    """Normaliza defensivamente `wifi` de estado.json (docs/CONTRATO.md):
    ausente, null, o con tipos inesperados (listas que no son listas,
    números NaN/infinitos o fuera de rango, SSID no codificables...) nunca
    debe romper el panel —ni esta página ni ninguna otra que llame a
    `leer_estado()`—, sólo producir valores seguros equivalentes a "sin
    Wi-Fi todavía". La clave de cada red NUNCA viaja en `estado.json` (la
    publica routerd sólo mientras se aplica una petición, nunca en el estado
    persistido), así que aquí no hay nada que redactar: simplemente no
    existe ese campo."""
    defecto: dict = {
        "habilitada": False,
        "interfaz": None,
        "presente": False,
        "radio": None,
        "conectada_a": None,
        "senal": None,
        "redes": [],
        "escaneo": [],
        "escaneo_ts": None,
        "bloqueadas": [],
    }
    if not isinstance(bruto, dict):
        return defecto

    redes = []
    if isinstance(bruto.get("redes"), list):
        for r in bruto["redes"]:
            if not isinstance(r, dict):
                continue
            ssid = _ssid_seguro(r.get("ssid"))
            if ssid is None:
                continue
            prioridad = _numero_acotado(r.get("prioridad"), 0, 100)
            if prioridad is None:
                prioridad = 50
            redes.append({"ssid": ssid, "prioridad": prioridad})

    escaneo = []
    if isinstance(bruto.get("escaneo"), list):
        for r in bruto["escaneo"]:
            if not isinstance(r, dict):
                continue
            ssid = _ssid_seguro(r.get("ssid"))
            if ssid is None:
                continue
            senal = _numero_acotado(r.get("senal"), 0, 100)
            if senal is None:
                senal = 0
            escaneo.append(
                {
                    "ssid": ssid,
                    "senal": senal,
                    "seguridad": _texto_o_ninguno(r.get("seguridad")),
                    "canal": _texto_o_ninguno(r.get("canal")),
                    "bloqueada": r.get("bloqueada") is True,
                }
            )
    escaneo.sort(key=lambda r: r["senal"], reverse=True)

    bloqueadas = []
    if isinstance(bruto.get("bloqueadas"), list):
        for b in bruto["bloqueadas"]:
            if not isinstance(b, str):
                continue
            b_segura = _ssid_seguro(b)
            if b_segura is not None:
                bloqueadas.append(b_segura)

    interfaz = bruto.get("interfaz")
    conectada_a = _ssid_seguro(bruto.get("conectada_a"))
    escaneo_ts = bruto.get("escaneo_ts")

    return {
        "habilitada": bruto.get("habilitada") is True,
        "interfaz": interfaz if isinstance(interfaz, str) and interfaz else None,
        "presente": bruto.get("presente") is True,
        "radio": bruto.get("radio") if isinstance(bruto.get("radio"), bool) else None,
        "conectada_a": conectada_a,
        "senal": _numero_acotado(bruto.get("senal"), 0, 100),
        "redes": redes,
        "escaneo": escaneo,
        "escaneo_ts": escaneo_ts if isinstance(escaneo_ts, str) and escaneo_ts else None,
        "bloqueadas": bloqueadas,
    }


def _normalizar_wifi_ap(bruto: Any) -> dict:
    """Normaliza `wifi_ap` de estado.json (modo punto de acceso,
    core/wifi_ap.py + core/routerd.py): `{habilitado, interfaz, ssid, activo,
    clientes}`. Con el AP deshabilitado routerd publica sólo
    `{"habilitado": False}` (y por debajo de esa clave una máquina con la
    tarjeta en modo WAN Wi-Fi no es errónea): se devuelve entonces la
    estructura "sin punto de acceso" y nada de la página consulta lo demás.
    Igual que `_normalizar_wifi`: tipos raros o ausentes nunca deben romper
    ninguna página que llame a `leer_estado()`, sólo producir valores
    seguros (SSID con `_ssid_seguro`, clientes acotado 0..1000)."""
    defecto: dict = {
        "habilitado": False,
        "interfaz": None,
        "ssid": None,
        "activo": None,
        "clientes": None,
    }
    if not isinstance(bruto, dict) or bruto.get("habilitado") is not True:
        return defecto
    interfaz = bruto.get("interfaz")
    return {
        "habilitado": True,
        "interfaz": interfaz if isinstance(interfaz, str) and interfaz else None,
        "ssid": _ssid_seguro(bruto.get("ssid")),
        "activo": bruto.get("activo") is True,
        "clientes": _numero_acotado(bruto.get("clientes"), 0, 1000),
    }


def _normalizar_dns_emergencia(bruto: Any) -> dict:
    """Normaliza `estado.json` -> `dns_emergencia` (docs/CONTRATO.md, M6/M1
    ronda 3: fail-open del bloqueador DNS; routerd lo publica SIEMPRE, pero
    un routerd más antiguo o un estado.json corrupto no debe romper la
    página): `{activo, desde, motivo}`, igual que `_normalizar_wifi`."""
    defecto = {"activo": False, "desde": None, "motivo": None}
    if not isinstance(bruto, dict):
        return defecto
    desde = bruto.get("desde")
    motivo = bruto.get("motivo")
    return {
        "activo": bruto.get("activo") is True,
        "desde": desde if isinstance(desde, str) and desde else None,
        "motivo": motivo if isinstance(motivo, str) and motivo else None,
    }


def _endpoint_firewall_normalizado(bruto: Any) -> dict | None:
    """Normaliza un endpoint (origen/destino) de regla de firewall:
    `{tipo, valor?}`. Devuelve `None` si ni siquiera tiene un `tipo`
    reconocible (se descarta la regla entera en vez de romper la página)."""
    if not isinstance(bruto, dict):
        return None
    tipo = bruto.get("tipo")
    if tipo not in ("cualquiera", "mac", "ip", "red", "grupo"):
        return None
    if tipo == "cualquiera":
        return {"tipo": "cualquiera"}
    valor = bruto.get("valor")
    if not isinstance(valor, str) or not valor:
        return None
    return {"tipo": tipo, "valor": valor}


def _puertos_firewall_normalizados(bruto: Any) -> list:
    """Lista segura de rangos `{desde, hasta}` (enteros 1-65535, desde<=hasta).
    Cualquier cosa que no sea una lista de dicts con enteros razonables se
    descarta del todo (preferible a pintar basura en la tabla)."""
    if not isinstance(bruto, list):
        return []
    salida = []
    for rango in bruto:
        if not isinstance(rango, dict):
            return []
        desde = _numero_acotado(rango.get("desde"), 1, 65535)
        hasta = _numero_acotado(rango.get("hasta"), 1, 65535)
        if desde is None or hasta is None or desde > hasta:
            return []
        salida.append({"desde": desde, "hasta": hasta})
    return salida


def _regla_firewall_normalizada(bruto: Any) -> dict | None:
    """Normaliza una regla de `config.firewall.reglas`. Devuelve `None` si la
    entrada no es ni siquiera un dict con id/nombre usables: se descarta en
    vez de romper la página (mismo criterio que `_lista_bloqueo_normalizada`)."""
    if not isinstance(bruto, dict):
        return None
    id_ = bruto.get("id")
    if not isinstance(id_, str) or not id_:
        return None
    nombre = bruto.get("nombre")
    nombre = nombre if isinstance(nombre, str) and nombre else id_
    origen = _endpoint_firewall_normalizado(bruto.get("origen")) or {"tipo": "cualquiera"}
    destino = _endpoint_firewall_normalizado(bruto.get("destino")) or {"tipo": "cualquiera"}
    accion = bruto.get("accion")
    if accion not in ("permitir", "bloquear", "rechazar"):
        accion = "bloquear"
    protocolo = bruto.get("protocolo")
    if protocolo not in ("cualquiera", "tcp", "udp", "tcp_udp", "icmp"):
        protocolo = "cualquiera"
    comentario = bruto.get("comentario")
    comentario = comentario if isinstance(comentario, str) else ""
    return {
        "id": id_,
        "nombre": nombre,
        "habilitada": bruto.get("habilitada") is not False,
        "accion": accion,
        "origen": origen,
        "destino": destino,
        "protocolo": protocolo,
        "puertos": _puertos_firewall_normalizados(bruto.get("puertos")),
        "registrar": bruto.get("registrar") is True,
        "comentario": comentario,
    }


def _grupo_firewall_normalizado(bruto: Any) -> dict | None:
    """Normaliza un grupo de `config.firewall.grupos`. Devuelve `None` si no
    es un dict con id/nombre/tipo usables (se descarta)."""
    if not isinstance(bruto, dict):
        return None
    id_ = bruto.get("id")
    if not isinstance(id_, str) or not id_:
        return None
    nombre = bruto.get("nombre")
    nombre = nombre if isinstance(nombre, str) and nombre else id_
    tipo = bruto.get("tipo")
    if tipo not in ("mac", "ip"):
        return None
    miembros = []
    if isinstance(bruto.get("miembros"), list):
        for m in bruto["miembros"]:
            if isinstance(m, str) and m:
                miembros.append(m)
    return {"id": id_, "nombre": nombre, "tipo": tipo, "miembros": miembros}


def normalizar_firewall(bruto: Any) -> dict:
    """Normalización defensiva de `config.firewall` (FIREWALL_PLAN.md):
    copia de la sección firewall (`version`, `grupos`, `reglas`) más
    `firewall_error` (str|null) y `firewall_aciertos` (`{id_regla: paquetes}`),
    tal como lo publica routerd en estado.json.

    Igual que `_normalizar_wifi`/`_normalizar_config_bloqueo`: tipos raros,
    listas que no son listas o números NaN nunca deben romper la página —ni
    esta ni ninguna otra que llame a `leer_estado()`—, sólo producir valores
    seguros equivalentes a "firewall sin configurar todavía"."""
    defecto = {
        "version": 1,
        "grupos": [],
        "reglas": [],
        "firewall_error": None,
        "firewall_aciertos": {},
    }
    if not isinstance(bruto, dict):
        return defecto

    version = bruto.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        version = 1

    grupos = []
    if isinstance(bruto.get("grupos"), list):
        for g in bruto["grupos"]:
            n = _grupo_firewall_normalizado(g)
            if n is not None:
                grupos.append(n)

    reglas = []
    if isinstance(bruto.get("reglas"), list):
        for r in bruto["reglas"]:
            n = _regla_firewall_normalizada(r)
            if n is not None:
                reglas.append(n)

    error = bruto.get("firewall_error")
    error = error if isinstance(error, str) and error else None

    aciertos = {}
    bruto_aciertos = bruto.get("firewall_aciertos")
    if isinstance(bruto_aciertos, dict):
        for clave, valor in bruto_aciertos.items():
            # Sólo cuentan como «hits» las claves con forma de id de regla
            # (`r_` + 8 hex): una clave inventada no debe pintarse como si
            # fuera el contador de una regla que no existe.
            if not isinstance(clave, str) or not RE_ID_REGLA_FW.fullmatch(clave):
                continue
            paquetes = _numero_acotado(valor, 0, 10_000_000_000)
            if paquetes is not None:
                aciertos[clave] = paquetes

    return {
        "version": version,
        "grupos": grupos,
        "reglas": reglas,
        "firewall_error": error,
        "firewall_aciertos": aciertos,
    }


def formatear_relativo(valor: Any) -> str:
    """Da formato en español a una marca de tiempo ISO8601 relativa a ahora:
    «hace instantes», «hace 5 min», «hace 2 h», «hace 3 d». Devuelve «—» si
    no hay marca de tiempo o no se puede interpretar (nunca se rompe)."""
    if not isinstance(valor, str):
        return "—"
    try:
        dt = datetime.fromisoformat(valor)
    except ValueError:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    segundos = int((datetime.now(timezone.utc) - dt).total_seconds())
    if segundos < 0:
        segundos = 0
    if segundos < 60:
        return "hace instantes"
    minutos = segundos // 60
    if minutos < 60:
        return f"hace {minutos} min"
    horas = minutos // 60
    if horas < 24:
        return f"hace {horas} h"
    dias = horas // 24
    return f"hace {dias} d"


def _lista_bloqueo_normalizada(item: Any) -> dict | None:
    """Normaliza una entrada de `bloqueo.json` -> `listas` (docs/CONTRATO.md):
    `{id, nombre, dominios, actualizada, error}`. Devuelve `None` si `item`
    no es ni siquiera un dict con un `id` usable (se descarta en vez de
    romper la página)."""
    if not isinstance(item, dict):
        return None
    id_ = item.get("id")
    if not isinstance(id_, str) or not id_:
        return None
    nombre = item.get("nombre")
    nombre = nombre if isinstance(nombre, str) and nombre else id_
    dominios = _numero_acotado(item.get("dominios"), 0, 10_000_000)
    actualizada = item.get("actualizada")
    error = item.get("error")
    return {
        "id": id_,
        "nombre": nombre,
        "dominios": dominios if dominios is not None else 0,
        "actualizada": actualizada if isinstance(actualizada, str) and actualizada else None,
        "error": error if isinstance(error, str) and error else None,
    }


def leer_bloqueo() -> dict:
    """Lectura tolerante de `/run/router/bloqueo.json` (docs/CONTRATO.md),
    publicado por `router_bloqueo.py` (proceso aparte de routerd). Igual que
    `leer_estado()`/`_normalizar_wifi`: si el fichero no existe, está
    corrupto o tiene una forma inesperada, se devuelve una estructura "sin
    datos" segura en vez de romper ninguna página que dependa de esto."""
    defecto = {
        "disponible": False,
        "error": None,
        "habilitado": False,
        "listas": [],
        "total_dominios": 0,
        "generado": None,
        "siguiente": None,
        "activo": True,
        "recortado": False,
        "error_actualizacion": None,
    }
    ruta = ruta_bloqueo()
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            bruto = json.load(f)
    except FileNotFoundError:
        return dict(defecto, error="No hay datos de bloqueo todavía: nunca se ha ejecutado una actualización.")
    except (json.JSONDecodeError, OSError, ValueError):
        return dict(defecto, error="No se pudo leer el estado del bloqueo DNS.")

    if not isinstance(bruto, dict):
        return dict(defecto, error="El estado del bloqueo DNS tiene un formato inesperado.")

    listas = []
    if isinstance(bruto.get("listas"), list):
        for item in bruto["listas"]:
            n = _lista_bloqueo_normalizada(item)
            if n is not None:
                listas.append(n)

    total_dominios = _numero_acotado(bruto.get("total_dominios"), 0, 10_000_000)
    generado = bruto.get("generado")
    siguiente = bruto.get("siguiente")
    error_actualizacion = bruto.get("error")

    return {
        "disponible": True,
        "error": None,
        "habilitado": bruto.get("habilitado") is True,
        "listas": listas,
        "total_dominios": total_dominios if total_dominios is not None else 0,
        "generado": generado if isinstance(generado, str) and generado else None,
        "siguiente": siguiente if isinstance(siguiente, str) and siguiente else None,
        "activo": bruto.get("activo") is not False,
        "recortado": bruto.get("recortado") is True,
        "error_actualizacion": error_actualizacion if isinstance(error_actualizacion, str) and error_actualizacion else None,
    }


def formatear_proximo(valor: Any) -> str:
    """Igual que `formatear_relativo` pero para una marca de tiempo FUTURA
    (p. ej. `bloqueo.json` -> `siguiente`): «dentro de 5 h», «dentro de
    2 d». Si ya pasó (el timer de systemd puede tardar un poco en
    disparar), se devuelve «en cualquier momento» en vez de un negativo.
    Devuelve «—» si no hay marca de tiempo o no se puede interpretar."""
    if not isinstance(valor, str):
        return "—"
    try:
        dt = datetime.fromisoformat(valor)
    except ValueError:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    segundos = int((dt - datetime.now(timezone.utc)).total_seconds())
    if segundos <= 0:
        return "en cualquier momento"
    minutos = segundos // 60
    if minutos < 60:
        return f"dentro de {minutos} min"
    horas = minutos // 60
    if horas < 24:
        return f"dentro de {horas} h"
    dias = horas // 24
    return f"dentro de {dias} d"


ESTADOS_CONECTADO = {"REACHABLE", "STALE", "DELAY", "PROBE"}


def leer_firewall() -> tuple[str | None, str | None]:
    """Devuelve (contenido, error). contenido es None si no se pudo leer."""
    ruta = ruta_firewall()
    try:
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), None
    except FileNotFoundError:
        return None, "No hay datos de firewall todavía."
    except OSError:
        return None, "No se pudo leer el fichero de firewall."


@dataclass
class Lease:
    expira_epoch: int
    mac: str
    ip: str
    hostname: str | None
    client_id: str | None

    @property
    def expirado(self) -> bool:
        return self.expira_epoch != 0 and self.expira_epoch < time.time()


def leer_leases() -> tuple[list[Lease], str | None]:
    """Formato dnsmasq.leases: <expira_epoch> <mac> <ip> <hostname|*> <client-id|*>"""
    ruta = ruta_leases()
    leases: list[Lease] = []
    try:
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        return [], "No hay datos de dispositivos todavía (sin fichero de leases)."
    except OSError:
        return [], "No se pudo leer el fichero de leases."

    for linea in lineas:
        partes = linea.split()
        if len(partes) < 4:
            continue
        try:
            expira = int(partes[0])
        except ValueError:
            continue
        mac = partes[1]
        ip = partes[2]
        hostname = partes[3] if partes[3] != "*" else None
        client_id = partes[4] if len(partes) > 4 and partes[4] != "*" else None
        leases.append(Lease(expira_epoch=expira, mac=mac.lower(), ip=ip, hostname=hostname, client_id=client_id))
    return leases, None


OPLOG_LIMITE_BYTES = 256 * 1024


def leer_oplog(limite: int = 200, limite_bytes: int = OPLOG_LIMITE_BYTES) -> tuple[list[dict], str | None]:
    """Lee las últimas `limite` líneas JSON del log de operaciones, más
    recientes primero.

    El fichero puede crecer sin límite (lo escribe routerd de forma
    continua), así que nunca se lee entero: se posiciona con `seek` a
    `limite_bytes` del final (por defecto ~256 KiB) y se parsean sólo las
    líneas completas leídas a partir de ahí, descartando el posible
    fragmento inicial truncado (la parte de una línea que ya estaba
    empezada antes del punto en el que se hizo `seek`).
    """
    ruta = ruta_oplog()
    try:
        with open(ruta, "rb") as f:
            f.seek(0, os.SEEK_END)
            tamano = f.tell()
            inicio = max(0, tamano - max(0, limite_bytes))
            f.seek(inicio)
            bruto = f.read()
    except FileNotFoundError:
        return [], "No hay operaciones registradas todavía."
    except OSError:
        return [], "No se pudo leer el registro de operaciones."

    texto = bruto.decode("utf-8", errors="replace")
    lineas = texto.split("\n")
    if inicio > 0:
        # La primera "línea" es el resto de una línea que empezaba antes de
        # `inicio`: puede estar truncada por la mitad, así que se descarta.
        lineas = lineas[1:]

    operaciones: list[dict] = []
    for linea in lineas[-limite:]:
        linea = linea.strip()
        if not linea:
            continue
        try:
            op = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if isinstance(op, dict):
            operaciones.append(op)
    operaciones.reverse()
    return operaciones[:limite], None


def dispositivo_conectado(mac: str, vecinos: dict) -> bool:
    estado_vecino = vecinos.get(mac.lower()) or vecinos.get(mac.upper())
    return isinstance(estado_vecino, str) and estado_vecino.upper() in ESTADOS_CONECTADO


def construir_dispositivos(estado: Estado, leases: list[Lease]) -> list[dict]:
    """Cruza leases + vecinos + reservas + etiquetas en una lista de dispositivos."""
    reservas = {}
    for r in (estado.config.get("reservas") or []):
        if isinstance(r, dict) and r.get("mac"):
            reservas[r["mac"].lower()] = r

    etiquetas = estado.config.get("etiquetas") or {}
    vecinos = estado.vecinos or {}

    por_mac: dict[str, dict] = {}

    for lease in leases:
        mac = lease.mac
        conectado = dispositivo_conectado(mac, vecinos)
        if conectado:
            estado_txt = "Conectado"
        elif lease.expirado:
            estado_txt = "Lease caducado"
        else:
            estado_txt = "Inactivo"
        por_mac[mac] = {
            "mac": mac,
            "ip": lease.ip,
            "nombre": lease.hostname or "(desconocido)",
            "etiqueta": etiquetas.get(mac, ""),
            "estado": estado_txt,
            "reserva": mac in reservas,
            "tiene_lease": True,
            "expira_epoch": lease.expira_epoch,
        }

    # Dispositivos reservados sin lease activo todavía.
    for mac, r in reservas.items():
        if mac not in por_mac:
            conectado = dispositivo_conectado(mac, vecinos)
            por_mac[mac] = {
                "mac": mac,
                "ip": r.get("ip", ""),
                "nombre": r.get("nombre") or "(reservado)",
                "etiqueta": etiquetas.get(mac, ""),
                "estado": "Conectado" if conectado else "Inactivo",
                "reserva": True,
                "tiene_lease": False,
                "expira_epoch": None,
            }

    return sorted(por_mac.values(), key=lambda d: (d["ip"] or ""))


def contar_dispositivos_lan(estado: Estado) -> int:
    """Nº de dispositivos conectados (vecinos REACHABLE/STALE/DELAY/PROBE)."""
    vecinos = estado.vecinos or {}
    return sum(1 for v in vecinos.values() if isinstance(v, str) and v.upper() in ESTADOS_CONECTADO)


def contexto_validacion(est: "Estado") -> dict:
    """Construye el contexto que necesita `validacion.py` para comprobar
    referencias cruzadas (WANs existentes, red LAN, reservas actuales).

    Usa `config.lan` (la red CONFIGURADA: "red" + "ip" del router) siempre
    que esté disponible. `lan.ip` es la IP actual de la interfaz y vale
    `None` mientras el cable no está conectado, así que sólo se usa como
    respaldo cuando routerd todavía no publica `config.lan`.
    """
    config_lan = (est.config or {}).get("lan")
    if isinstance(config_lan, dict) and config_lan.get("red"):
        lan_red = config_lan.get("red")
        lan_ip_router = config_lan.get("ip")
    else:
        lan = est.lan or {}
        lan_ip_cidr = lan.get("ip")  # respaldo antiguo: "192.168.50.1/24"
        lan_red = lan_ip_cidr
        lan_ip_router = None
        if isinstance(lan_ip_cidr, str) and "/" in lan_ip_cidr:
            lan_ip_router = lan_ip_cidr.split("/", 1)[0]
    return {
        "wans_ids": [w.get("id") for w in (est.wans or []) if isinstance(w, dict)],
        "lan_red": lan_red,
        "lan_ip_router": lan_ip_router,
        "reservas": est.config.get("reservas") or [],
    }


def formatear_bitrate(valor: Any) -> str:
    """Da formato en español a una velocidad en bits/segundo:
    «364 bit/s», «1,5 kbit/s», «2,3 Mbit/s» (nunca «364.0 bps»)."""
    try:
        bps = float(valor)
    except (TypeError, ValueError):
        return "—"
    if bps < 0:
        return "—"
    unidades = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"]
    i = 0
    while bps >= 1000 and i < len(unidades) - 1:
        bps /= 1000
        i += 1
    texto = f"{bps:.0f}" if i == 0 else f"{bps:.1f}".replace(".", ",")
    return f"{texto} {unidades[i]}"


def formatear_bytes(valor: Any) -> str:
    """Da formato en español a bytes acumulados: «512 B», «3,2 KB», «1,8 GB»."""
    try:
        b = float(valor)
    except (TypeError, ValueError):
        return "—"
    if b < 0:
        return "—"
    unidades = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while b >= 1024 and i < len(unidades) - 1:
        b /= 1024
        i += 1
    texto = f"{b:.0f}" if i == 0 else f"{b:.1f}".replace(".", ",")
    return f"{texto} {unidades[i]}"


def formatear_uptime(segundos: Any) -> str:
    """Da formato en español a un uptime en segundos: «1 d 1 h 29 min»
    (nunca el número de segundos en crudo)."""
    try:
        total_min = round(float(segundos) / 60)
    except (TypeError, ValueError):
        return "—"
    if total_min < 0:
        return "—"
    dias, resto = divmod(total_min, 1440)
    horas, minutos = divmod(resto, 60)
    partes = []
    if dias:
        partes.append(f"{dias} d")
    if horas or dias:
        partes.append(f"{horas} h")
    partes.append(f"{minutos} min")
    return " ".join(partes)


SERVICIOS_ETIQUETAS = {
    "dnsmasq": "DHCP/DNS (dnsmasq)",
    "nftables_router": "Cortafuegos",
    "balanceo": "Balanceo",
    "routerd": "Núcleo (routerd)",
}


def _servicio_activo(valor: Any) -> bool:
    return valor is True or valor == "active"


def formatear_servicios(servicios: dict, fase: str | None) -> list[dict]:
    """Traduce el dict crudo de `servicios` a etiquetas humanas con el color
    que corresponde según la fase del router: activo siempre en verde;
    inactivo en gris durante la preparación (todavía no deben estar
    arrancados) y en rojo sólo si ya estamos en producción."""
    resultado = []
    for clave, valor in (servicios or {}).items():
        activo = _servicio_activo(valor)
        if activo:
            color = "ok"
        elif fase == "produccion":
            color = "error"
        else:
            color = "gris"
        resultado.append(
            {
                "clave": clave,
                "etiqueta": SERVICIOS_ETIQUETAS.get(clave, clave),
                "activo": activo,
                "texto": "activo" if activo else "inactivo",
                "color": color,
            }
        )
    return resultado
