// /proteccion: mueve el foco al recuadro de resultado de "¿Está bloqueado?"
// cuando aparece tras comprobar un dominio (tabindex="-1" en el propio
// elemento, puesto por la plantilla), para que quien use lector de
// pantalla o navegación por teclado sepa de inmediato que hay un resultado
// nuevo sin tener que buscarlo en la página. Nada de estilos ni manejadores
// inline: acorde a la CSP "script-src 'self'".
(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
        var resultado = document.getElementById("tt-proteccion-resultado");
        if (resultado) {
            resultado.focus();
        }
    });
})();
