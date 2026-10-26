"""Cálculo del reparto previsto de tráfico entre WAN (fase 4, A/C).

Un único lugar para esta cuenta: tanto el dashboard como la página WAN
deben mostrar la misma cifra para la misma línea, así que ambos llaman a
`anotar_pct_reparto` en vez de calcularlo cada uno por su lado (si uno de
los dos cambiara el criterio sin tocar el otro, mostrarían números
distintos para lo mismo).
"""
from __future__ import annotations

import math
from typing import Any


def valor_peso_reparto(w: dict, modo_pesos: str) -> int | float | None:
    """Valor que de verdad usa el balanceo para esta WAN según `modo_pesos`:
    `peso_efectivo` (lo calcula routerd por latencia/pérdida) en auto,
    `peso` (el que pone el admin) en manual.

    Devuelve `None` si el campo falta, no es un número, no es finito (NaN o
    infinito) o no es positivo: un peso <= 0 no participa en el reparto
    (evita divisiones por cero o segmentos con cuota 0/negativa sin
    sentido)."""
    valor = w.get("peso") if modo_pesos == "manual" else w.get("peso_efectivo")
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        return None
    if not math.isfinite(valor) or valor <= 0:
        return None
    return valor


def anotar_pct_reparto(wans: list[dict], modo_pesos: str, fase: str | None = None) -> list[dict]:
    """Devuelve una copia de `wans` con la clave `pct_reparto` añadida a
    cada WAN: la cuota (0-100) de conexiones nuevas que le tocaría según el
    peso que corresponde al modo activo, calculada sobre la suma de todas
    las WAN en balanceo con un peso calculable.

    `pct_reparto` es `None` cuando no se puede calcular: fase de
    preparación (el balanceo todavía no está activo), la WAN no está en
    balanceo, o su peso falta/no es numérico/no es positivo. Los elementos
    de `wans` que no sean `dict` se descartan (routerd nunca debería
    publicar eso, pero el panel no debe romperse si pasa)."""
    wans_validas = [w for w in (wans or []) if isinstance(w, dict)]
    en_preparacion = fase == "preparacion"

    valores: list[Any] = []
    for w in wans_validas:
        if not en_preparacion and w.get("en_balanceo"):
            valores.append(valor_peso_reparto(w, modo_pesos))
        else:
            valores.append(None)

    suma = sum(v for v in valores if v is not None)

    resultado = []
    for w, valor in zip(wans_validas, valores):
        w2 = dict(w)
        w2["pct_reparto"] = (valor / suma * 100) if (valor is not None and suma > 0) else None
        resultado.append(w2)
    return resultado
