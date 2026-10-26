from __future__ import annotations

from conftest import extraer_csrf, login

from routerpanel import usuarios as usuarios_mod


def test_login_correcto(cliente):
    resp = login(cliente, "admin", "contrasena-admin-1")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


def test_login_incorrecto(cliente):
    resp = login(cliente, "admin", "contrasena-equivocada")
    assert resp.status_code == 200
    assert "incorrectos".encode() in resp.data or b"incorrectos" in resp.data


def test_bloqueo_tras_5_fallos(cliente):
    for _ in range(5):
        resp = login(cliente, "admin", "mal")
        assert resp.status_code == 200

    resp = login(cliente, "admin", "contrasena-admin-1")
    assert resp.status_code == 200
    assert b"bloqueado" in resp.data.lower() or "bloqueado".encode() in resp.data or b"intentos" in resp.data


def test_rutas_protegidas_redirigen_a_login(cliente):
    for ruta in ("/", "/wan", "/dispositivos", "/firewall", "/configuracion", "/registro"):
        resp = cliente.get(ruta)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_csrf_rechaza_post_sin_token(app, cliente):
    app.config["WTF_CSRF_ENABLED"] = True
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.post("/wan/modo", data={"modo": "respaldo"})
    assert resp.status_code == 400


def test_rol_lectura_no_puede_post(cliente):
    login(cliente, "lector", "contrasena-lector-1")
    resp = cliente.get("/wan")
    token = extraer_csrf(resp.data)
    resp = cliente.post("/wan/modo", data={"modo": "respaldo", "csrf_token": token})
    assert resp.status_code == 403


def _post_login_con_next(cliente, next_valor):
    resp = cliente.get(f"/login?next={next_valor}")
    token = extraer_csrf(resp.data)
    return cliente.post(
        f"/login?next={next_valor}",
        data={"usuario": "admin", "password": "contrasena-admin-1", "csrf_token": token},
    )


def test_login_next_rechaza_url_absoluta(cliente):
    resp = _post_login_con_next(cliente, "https://evil.com")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"


def test_login_next_rechaza_doble_barra(cliente):
    resp = _post_login_con_next(cliente, "//evil.com")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"


def test_login_next_rechaza_barra_invertida(cliente):
    resp = _post_login_con_next(cliente, "/%5Cevil.com")  # "/\evil.com"
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"


def test_login_next_acepta_ruta_relativa_valida(cliente):
    resp = _post_login_con_next(cliente, "/wan")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/wan"


def test_login_usuario_inexistente_comprueba_hash_ficticio(cliente, monkeypatch):
    """La enumeración de usuarios por temporización se evita comprobando el
    hash ficticio incluso cuando el usuario no existe."""
    llamadas = []
    original = usuarios_mod.verificar_ficticio

    def _espia(password):
        llamadas.append(password)
        return original(password)

    monkeypatch.setattr(usuarios_mod, "verificar_ficticio", _espia)

    resp = cliente.get("/login")
    token = extraer_csrf(resp.data)
    resp = cliente.post(
        "/login",
        data={"usuario": "no-existe", "password": "lo-que-sea", "csrf_token": token},
    )
    assert resp.status_code == 200
    assert llamadas == ["lo-que-sea"]


def test_login_usuario_existente_no_comprueba_hash_ficticio(cliente, monkeypatch):
    """Si el usuario existe (aunque la contraseña sea incorrecta) no debe
    tocarse el hash ficticio: ya se compara contra el hash real."""
    llamadas = []
    monkeypatch.setattr(usuarios_mod, "verificar_ficticio", lambda password: llamadas.append(password))

    resp = cliente.get("/login")
    token = extraer_csrf(resp.data)
    resp = cliente.post(
        "/login",
        data={"usuario": "admin", "password": "mal", "csrf_token": token},
    )
    assert resp.status_code == 200
    assert llamadas == []


def test_referrer_policy_permite_el_csrf_estricto_por_https(cliente):
    """Por HTTPS Flask-WTF exige Referer del mismo origen en los POST: la
    política debe dejar que el navegador lo envíe dentro del panel."""
    r = cliente.get("/login")
    assert r.headers["Referrer-Policy"] == "same-origin"
