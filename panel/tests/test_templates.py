from __future__ import annotations

import pathlib
import re

RAIZ_TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / "routerpanel" / "templates"

RE_SCRIPT = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)


def _plantillas():
    return list(RAIZ_TEMPLATES.rglob("*.html"))


def test_hay_plantillas_para_revisar():
    assert len(_plantillas()) > 0


def test_sin_estilos_inline():
    infractores = []
    for ruta in _plantillas():
        contenido = ruta.read_text(encoding="utf-8")
        if re.search(r"\sstyle\s*=", contenido):
            infractores.append(str(ruta))
    assert not infractores, f"Plantillas con style= inline: {infractores}"


def test_sin_onclick_inline():
    infractores = []
    for ruta in _plantillas():
        contenido = ruta.read_text(encoding="utf-8")
        if re.search(r"\bon[a-z]+\s*=", contenido, re.IGNORECASE):
            infractores.append(str(ruta))
    assert not infractores, f"Plantillas con manejadores on*= inline: {infractores}"


def test_sin_script_sin_src():
    infractores = []
    for ruta in _plantillas():
        contenido = ruta.read_text(encoding="utf-8")
        for coincidencia in RE_SCRIPT.finditer(contenido):
            atributos = coincidencia.group(1)
            if "src=" not in atributos:
                infractores.append(str(ruta))
    assert not infractores, f"Plantillas con <script> sin src: {infractores}"
