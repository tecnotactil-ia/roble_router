#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""router-firewall-arranque — aplica el cortafuegos del router ANTES de que
arranque la red (M2).

Sin esto hay una ventana, entre que arranca el sistema y que NetworkManager
levanta las WAN (y routerd hace su primer ciclo), en la que no hay ningún
`nft` del router cargado: un paquete podría colarse mientras tanto. Este
script se lanza como ExecStart de systemd/router-firewall-arranque.service,
un oneshot con Before=network-pre.target.

routerd ya deja `nft_base` validado en disco (instalar_base() lo valida con
`nft -c -f` sobre un temporal antes de renombrarlo — H5): aquí basta
aplicarlo tal cual, sin volver a generarlo ni validarlo.

N1: la fase ya no vive dentro de router.json, sino en su propio fichero
(`/etc/router/fase`, el mismo que lee routerd en cada ciclo). Este script
lee primero ese fichero y, si no existe o no es válido, cae a la "fase"
de router.json sólo por compatibilidad con instalaciones viejas.

Nunca debe hacer fallar el arranque del sistema: si no hay fase
"produccion" (ni en el fichero ni, por compatibilidad, en router.json) o no
hay `router.nft` todavía (primer arranque de la máquina, antes de que
routerd haya corrido nunca), simplemente no hace nada y sale con éxito —
routerd lo instala en su primer ciclo de todos modos. Si `nft -f` falla
(fichero corrupto, versión de nft distinta…) tampoco se propaga el fallo al
arranque.
"""
import json
import subprocess
import sys

CONFIG = '/etc/router/router.json'
FASE_RUTA = '/etc/router/fase'
NFT_BASE = '/etc/router/nftables/router.nft'


def _fase():
    """N1: fichero de fase primero; si no existe o no tiene un valor
    reconocido, la "fase" de router.json por compatibilidad; si tampoco,
    None (que nunca es "produccion", así que no se hace nada)."""
    try:
        with open(FASE_RUTA) as f:
            contenido = f.read().strip()
        if contenido in ('preparacion', 'produccion'):
            return contenido
    except OSError:
        pass
    try:
        with open(CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    return cfg.get('fase') if isinstance(cfg, dict) else None


def main():
    if _fase() != 'produccion':
        return 0
    try:
        with open(NFT_BASE):
            pass
    except OSError:
        return 0
    try:
        subprocess.run(['nft', '-f', NFT_BASE], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        pass   # el arranque sigue; routerd lo reinstalará en su primer ciclo
    return 0


if __name__ == '__main__':
    sys.exit(main())
