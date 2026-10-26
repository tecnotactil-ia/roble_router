from __future__ import annotations

from conftest import extraer_csrf, login


def _flashear(cliente, mensajes):
    """Inyecta mensajes flash directamente en la sesión, como si se hubiera
    llamado a `flash(mensaje, categoria)` en una vista, sin depender de
    ninguna ruta concreta que los genere."""
    with cliente.session_transaction() as sess:
        sess["_flashes"] = list(mensajes)


def test_flash_se_renderiza_en_wrapper_y_origen(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    _flashear(cliente, [("ok", "Todo correcto")])

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    # Wrapper fijo con las dos regiones vivas, ambas vacías en el HTML
    # servido por Flask (el reparto por categoría lo hace el JS).
    assert 'id="tt-toast-wrapper"' in html
    assert 'id="tt-toast-urgente"' in html
    assert 'id="tt-toast-contenedor"' in html
    assert '<div id="tt-toast-urgente" data-tt-toasts-urgente aria-live="assertive"></div>' in html
    assert '<div id="tt-toast-contenedor" data-tt-toasts aria-live="polite"></div>' in html

    # El toast real, ya renderizado y visible, vive en #tt-toast-origen.
    assert 'id="tt-toast-origen"' in html
    inicio_origen = html.index('id="tt-toast-origen"')
    fin_origen = html.index("</div>", html.index("tt-toast tt-alerta-ok", inicio_origen))
    assert "Todo correcto" in html[inicio_origen:fin_origen]


def test_toasts_no_llevan_role_ni_aria_live_propios(entorno, cliente):
    """El role/aria-live vive en la región de destino (#tt-toast-urgente o
    #tt-toast-contenedor), no en cada aviso: ponerlo también en el aviso
    duplicaría el anuncio una vez que avisos.js lo mueva dentro."""
    login(cliente, "admin", "contrasena-admin-1")
    _flashear(
        cliente,
        [
            ("ok", "Mensaje ok"),
            ("warning", "Mensaje warning"),
            ("error", "Mensaje error"),
        ],
    )

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    inicio_origen = html.index('id="tt-toast-origen"')
    bloque_origen = html[inicio_origen:html.index("<main")]

    assert 'role="status"' not in bloque_origen
    assert 'role="alert"' not in bloque_origen
    assert "aria-live" not in bloque_origen
    # Pero sí llevan su categoría, para que el JS sepa a qué región moverlos.
    assert 'data-tt-categoria="ok"' in bloque_origen
    assert 'data-tt-categoria="warning"' in bloque_origen
    assert 'data-tt-categoria="error"' in bloque_origen


def test_categoria_desconocida_usa_icono_por_defecto(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    _flashear(cliente, [("rara", "Categoría que no existe en el mapeo")])

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    assert 'data-tt-categoria="rara"' in html
    # Icono por defecto (el mismo que "info").
    assert "bi-info-circle tt-toast-icono" in html
    assert "Categoría que no existe en el mapeo" in html
    # No lleva role/aria-live propios, igual que el resto.
    inicio_origen = html.index('id="tt-toast-origen"')
    assert 'role=' not in html[inicio_origen:html.index("Categoría que no existe")]


def test_cada_toast_tiene_boton_cerrar_accesible(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    _flashear(cliente, [("info", "Aviso")])

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    assert 'aria-label="Cerrar"' in html
    assert "data-tt-toast-cerrar" in html


def test_flash_con_html_queda_escapado(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")
    _flashear(cliente, [("error", "<script>alert(1)</script>")])

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_sin_flash_no_hay_wrapper_de_toasts(entorno, cliente):
    login(cliente, "admin", "contrasena-admin-1")

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    assert 'id="tt-toast-wrapper"' not in html
    assert 'id="tt-toast-contenedor"' not in html
    assert 'id="tt-toast-urgente"' not in html
    assert 'id="tt-toast-origen"' not in html


def test_mensajes_van_antes_de_main_en_el_marcado(entorno, cliente):
    """#tt-toast-origen no es "fixed": va en el flujo normal, antes de
    <main>, así que en el HTML servido debe aparecer antes que la etiqueta
    <main ...> que lo sigue."""
    login(cliente, "admin", "contrasena-admin-1")
    _flashear(cliente, [("ok", "Todo correcto")])

    resp = cliente.get("/")
    html = resp.data.decode("utf-8")

    assert html.index('id="tt-toast-wrapper"') < html.index("<main")
    assert html.index('id="tt-toast-origen"') < html.index("<main")


def test_flash_en_pagina_sin_sesion_tambien_usa_toasts(entorno, cliente):
    """La página de login (sin sesión, usa tt-main-sin-sesion) también debe
    mostrar sus flash como toasts: credenciales incorrectas flashea en
    categoría "error"."""
    resp = cliente.get("/login")
    token = extraer_csrf(resp.data)
    resp = cliente.post(
        "/login",
        data={"usuario": "admin", "password": "mala", "csrf_token": token},
    )
    html = resp.data.decode("utf-8")

    assert resp.status_code == 200
    assert 'id="tt-toast-wrapper"' in html
    assert 'id="tt-toast-urgente"' in html
    assert 'data-tt-categoria="error"' in html
    assert "Usuario o contraseña incorrectos." in html
    assert html.index('id="tt-toast-origen"') < html.index("<main")
