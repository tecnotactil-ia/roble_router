// JS propio de la página de Wi-Fi (sin dependencias externas). Único
// trabajo: cuando hay un escaneo (`wifi_escanear`) en curso, recargar la
// página sola al cabo de unos segundos para que la tabla de "Redes
// cercanas" se rellene sin que haya que pulsar nada. El servidor es quien
// decide si sigue "pendiente" (ver wifi.py: `_info_escaneo_pendiente()`,
// con un tope de 30 s) marcando el contenedor con
// data-wifi-escaneo-pendiente="1"; este script sólo lee ese atributo, no
// decide por su cuenta cuánto tiempo lleva esperando.
//
// La recarga NUNCA debe interrumpir a quien esté rellenando "Añadir red":
// si algún campo de ese formulario tiene el foco, o si SSID/clave ya
// tienen algo escrito, se posterga la comprobación otros 5 s en vez de
// recargar (que borraría lo que estuviera escribiendo).

(function () {
    "use strict";

    var INTERVALO_MS = 5000;

    function formularioAnadirTieneActividad() {
        var form = document.getElementById("tt-wifi-form-agregar");
        if (!form) {
            return false;
        }
        if (form.contains(document.activeElement)) {
            return true;
        }
        var ssid = form.querySelector("#tt-wifi-ssid");
        var clave = form.querySelector("#tt-wifi-clave");
        if (ssid && ssid.value.trim() !== "") {
            return true;
        }
        if (clave && clave.value.trim() !== "") {
            return true;
        }
        return false;
    }

    function intentarRecargar() {
        if (formularioAnadirTieneActividad()) {
            setTimeout(intentarRecargar, INTERVALO_MS);
            return;
        }
        window.location.reload();
    }

    document.addEventListener("DOMContentLoaded", function () {
        var contenedor = document.querySelector('[data-wifi-escaneo-pendiente="1"]');
        if (!contenedor) {
            return;
        }
        setTimeout(intentarRecargar, INTERVALO_MS);
    });
})();
