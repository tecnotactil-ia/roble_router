from __future__ import annotations

import math

from routerpanel import reparto


def test_valor_peso_reparto_auto_usa_peso_efectivo():
    assert reparto.valor_peso_reparto({"peso": 50, "peso_efectivo": 84}, "auto") == 84


def test_valor_peso_reparto_manual_usa_peso():
    assert reparto.valor_peso_reparto({"peso": 50, "peso_efectivo": 84}, "manual") == 50


def test_valor_peso_reparto_ausente_es_none():
    assert reparto.valor_peso_reparto({}, "auto") is None
    assert reparto.valor_peso_reparto({}, "manual") is None


def test_valor_peso_reparto_no_numerico_es_none():
    assert reparto.valor_peso_reparto({"peso_efectivo": "84"}, "auto") is None
    assert reparto.valor_peso_reparto({"peso_efectivo": None}, "auto") is None
    assert reparto.valor_peso_reparto({"peso_efectivo": True}, "auto") is None


def test_valor_peso_reparto_cero_o_negativo_es_none():
    assert reparto.valor_peso_reparto({"peso_efectivo": 0}, "auto") is None
    assert reparto.valor_peso_reparto({"peso_efectivo": -5}, "auto") is None


def test_valor_peso_reparto_no_finito_es_none():
    assert reparto.valor_peso_reparto({"peso_efectivo": math.inf}, "auto") is None
    assert reparto.valor_peso_reparto({"peso_efectivo": math.nan}, "auto") is None


def test_anotar_pct_reparto_reparte_proporcionalmente():
    wans = [
        {"id": "a", "en_balanceo": True, "peso_efectivo": 75},
        {"id": "b", "en_balanceo": True, "peso_efectivo": 25},
        {"id": "c", "en_balanceo": False, "peso_efectivo": 100},
    ]
    resultado = reparto.anotar_pct_reparto(wans, "auto", "produccion")
    por_id = {w["id"]: w["pct_reparto"] for w in resultado}
    assert por_id["a"] == 75.0
    assert por_id["b"] == 25.0
    assert por_id["c"] is None  # no está en balanceo, no reparte


def test_anotar_pct_reparto_usa_peso_segun_modo():
    wans = [
        {"id": "a", "en_balanceo": True, "peso": 70, "peso_efectivo": 10},
        {"id": "b", "en_balanceo": True, "peso": 30, "peso_efectivo": 90},
    ]
    auto = {w["id"]: w["pct_reparto"] for w in reparto.anotar_pct_reparto(wans, "auto", "produccion")}
    manual = {w["id"]: w["pct_reparto"] for w in reparto.anotar_pct_reparto(wans, "manual", "produccion")}
    assert auto["a"] == 10.0
    assert auto["b"] == 90.0
    assert manual["a"] == 70.0
    assert manual["b"] == 30.0


def test_anotar_pct_reparto_en_preparacion_es_none_para_todas():
    wans = [{"id": "a", "en_balanceo": True, "peso_efectivo": 50}]
    resultado = reparto.anotar_pct_reparto(wans, "auto", "preparacion")
    assert resultado[0]["pct_reparto"] is None


def test_anotar_pct_reparto_sin_peso_calculable_es_none():
    wans = [
        {"id": "a", "en_balanceo": True, "peso_efectivo": "no-numerico"},
        {"id": "b", "en_balanceo": True, "peso_efectivo": 0},
    ]
    resultado = reparto.anotar_pct_reparto(wans, "auto", "produccion")
    assert all(w["pct_reparto"] is None for w in resultado)


def test_anotar_pct_reparto_descarta_elementos_que_no_son_dict():
    wans = [{"id": "a", "en_balanceo": True, "peso_efectivo": 50}, "esto-no-es-una-wan", None, 42]
    resultado = reparto.anotar_pct_reparto(wans, "auto", "produccion")
    assert len(resultado) == 1
    assert resultado[0]["id"] == "a"
    assert resultado[0]["pct_reparto"] == 100.0


def test_anotar_pct_reparto_no_modifica_los_dict_originales():
    original = {"id": "a", "en_balanceo": True, "peso_efectivo": 50}
    reparto.anotar_pct_reparto([original], "auto", "produccion")
    assert "pct_reparto" not in original
