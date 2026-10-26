"""Punto de entrada WSGI del panel, para gunicorn:

    gunicorn -w 2 -b 127.0.0.1:5001 wsgi:app
"""
from routerpanel import create_app

app = create_app()
