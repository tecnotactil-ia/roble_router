from __future__ import annotations

from conftest import extraer_csrf, login


def test_cambiar_password_correcto(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/cuenta")
    assert resp.status_code == 200
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/cuenta",
        data={
            "csrf_token": token,
            "password_actual": "contrasena-admin-1",
            "password_nueva": "nueva-contrasena-larga-1",
            "password_repetir": "nueva-contrasena-larga-1",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")

    # La sesión actual debe haberse invalidado: una ruta protegida redirige
    # de nuevo a /login en vez de servir contenido.
    resp_protegida = cliente.get("/")
    assert resp_protegida.status_code == 302
    assert "/login" in resp_protegida.headers["Location"]

    # La contraseña nueva debe funcionar ya para iniciar sesión.
    resp_login = login(cliente, "admin", "nueva-contrasena-larga-1")
    assert resp_login.status_code == 302
    assert resp_login.headers["Location"].endswith("/")


def test_cambiar_password_invalida_sesiones_de_otros_dispositivos(app, cliente):
    """Cambiar la contraseña debe cerrar TODAS las sesiones del usuario, no
    sólo la que hizo el cambio: simula una segunda sesión (otro navegador)
    que debe quedar revocada en su siguiente petición."""
    otro_cliente = app.test_client()
    login(otro_cliente, "admin", "contrasena-admin-1")
    # La otra sesión funciona antes del cambio.
    resp_otro_antes = otro_cliente.get("/")
    assert resp_otro_antes.status_code == 200

    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/cuenta")
    token = extraer_csrf(resp.data)
    resp = cliente.post(
        "/cuenta",
        data={
            "csrf_token": token,
            "password_actual": "contrasena-admin-1",
            "password_nueva": "nueva-contrasena-larga-1",
            "password_repetir": "nueva-contrasena-larga-1",
        },
    )
    assert resp.status_code == 302

    # La otra sesión (que no hizo el cambio) queda revocada igualmente.
    resp_otro_despues = otro_cliente.get("/")
    assert resp_otro_despues.status_code == 302
    assert "/login" in resp_otro_despues.headers["Location"]


def test_cambiar_password_actual_incorrecta(app, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/cuenta")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/cuenta",
        data={
            "csrf_token": token,
            "password_actual": "esto-no-es-la-actual",
            "password_nueva": "nueva-contrasena-larga-1",
            "password_repetir": "nueva-contrasena-larga-1",
        },
    )
    assert resp.status_code == 200
    assert "no es correcta".encode() in resp.data

    # La contraseña original sigue funcionando: no se cambió nada (con un
    # cliente nuevo, sin la sesión ya iniciada).
    cliente_nuevo = app.test_client()
    resp_login = login(cliente_nuevo, "admin", "contrasena-admin-1")
    assert resp_login.status_code == 302


def test_cambiar_password_nueva_corta_rechazada(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/cuenta")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/cuenta",
        data={
            "csrf_token": token,
            "password_actual": "contrasena-admin-1",
            "password_nueva": "corta123",
            "password_repetir": "corta123",
        },
    )
    assert resp.status_code == 200
    assert "12 caracteres".encode() in resp.data


def test_cambiar_password_no_coinciden_rechazada(cliente):
    login(cliente, "admin", "contrasena-admin-1")
    resp = cliente.get("/cuenta")
    token = extraer_csrf(resp.data)

    resp = cliente.post(
        "/cuenta",
        data={
            "csrf_token": token,
            "password_actual": "contrasena-admin-1",
            "password_nueva": "nueva-contrasena-larga-1",
            "password_repetir": "otra-contrasena-distinta-1",
        },
    )
    assert resp.status_code == 200
    assert "no coinciden".encode() in resp.data


def test_cambiar_password_sin_csrf_rechazado(app, cliente):
    app.config["WTF_CSRF_ENABLED"] = True
    login(cliente, "admin", "contrasena-admin-1")

    resp = cliente.post(
        "/cuenta",
        data={
            "password_actual": "contrasena-admin-1",
            "password_nueva": "nueva-contrasena-larga-1",
            "password_repetir": "nueva-contrasena-larga-1",
        },
    )
    assert resp.status_code == 400
