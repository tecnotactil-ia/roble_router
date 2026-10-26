// JS propio del panel (sin dependencias externas más allá de Bootstrap).
// Refresca los datos del dashboard cada 5 s mediante fetch a un endpoint JSON.
// No usa estilos inline en el HTML: los anchos de las barras se fijan aquí,
// vía la API de JavaScript (element.style), que la CSP "style-src 'self'"
// no restringe (sólo restringe el atributo style="" escrito en el marcado).

(function () {
    "use strict";

    var INTERVALO_MS = 5000;

    function formatearBps(valor) {
        if (valor === null || valor === undefined || isNaN(valor)) {
            return "—";
        }
        var unidades = ["bps", "kbps", "Mbps", "Gbps"];
        var i = 0;
        var n = Number(valor);
        while (n >= 1000 && i < unidades.length - 1) {
            n /= 1000;
            i += 1;
        }
        return n.toFixed(1) + " " + unidades[i];
    }

    function textoONulo(valor, sufijo) {
        if (valor === null || valor === undefined) {
            return "—";
        }
        return String(valor) + (sufijo || "");
    }

    var NIVELES = ["ok", "advertencia", "error", "neutro"];

    function nivelPct(valor) {
        if (valor === null || valor === undefined || isNaN(valor)) {
            return "neutro";
        }
        var n = Number(valor);
        if (n >= 90) {
            return "error";
        }
        if (n >= 70) {
            return "advertencia";
        }
        return "ok";
    }

    function fijarAncho(el, pct) {
        var n = (pct === null || pct === undefined || isNaN(pct)) ? 0 : Number(pct);
        n = Math.max(0, Math.min(100, n));
        el.style.width = n + "%";
    }

    // Fija el ancho de toda barra con data-pct a partir del marcado ya
    // renderizado por el servidor (se ejecuta antes del primer fetch, para
    // que no aparezcan a 0 mientras llega la respuesta).
    function inicializarBarras() {
        var barras = document.querySelectorAll("[data-pct]");
        barras.forEach(function (el) {
            fijarAncho(el, parseFloat(el.getAttribute("data-pct")));
        });
    }

    // Actualiza una barra de progreso (ancho + color según nivel) con un
    // valor nuevo venido del refresco periódico.
    function actualizarBarraConNivel(id, valor) {
        var el = document.getElementById(id);
        if (!el) {
            return;
        }
        fijarAncho(el, valor);
        var nivel = nivelPct(valor);
        NIVELES.forEach(function (n) {
            el.classList.remove("tt-barra-" + n);
        });
        el.classList.add("tt-barra-" + nivel);
    }

    function actualizarIconoInternet(valorInternet) {
        var icono = document.getElementById("tt-icono-internet");
        if (!icono) {
            return;
        }
        icono.classList.remove("tt-kpi-icono-ok", "tt-kpi-icono-error", "tt-kpi-icono-neutro");
        if (valorInternet === true) {
            icono.classList.add("tt-kpi-icono-ok");
        } else if (valorInternet === false) {
            icono.classList.add("tt-kpi-icono-error");
        } else {
            icono.classList.add("tt-kpi-icono-neutro");
        }
    }

    function actualizarResumen(datos) {
        var avisoCaido = document.getElementById("tt-aviso-caido");
        if (avisoCaido) {
            if (datos.caido) {
                avisoCaido.classList.remove("d-none");
            } else {
                avisoCaido.classList.add("d-none");
            }
        }

        var antiguedad = document.getElementById("tt-antiguedad");
        if (antiguedad) {
            antiguedad.textContent = datos.antiguedad_s === null ? "—" : datos.antiguedad_s;
        }

        var estadoInternet = document.getElementById("tt-estado-internet");
        if (estadoInternet) {
            if (datos.internet === true) {
                estadoInternet.textContent = "Internet: Sí";
            } else if (datos.internet === false) {
                estadoInternet.textContent = "Internet: No";
            } else {
                estadoInternet.textContent = "Internet: ?";
            }
        }
        actualizarIconoInternet(datos.internet);

        var uptime = document.getElementById("tt-uptime");
        if (uptime) {
            // El servidor ya da formato humano («1 d 1 h 29 min»); se usa
            // tal cual para que coincida con el renderizado inicial.
            uptime.textContent = datos.uptime_fmt || "—";
        }

        var sistema = datos.sistema || {};
        var cpu = document.getElementById("tt-cpu");
        if (cpu) {
            cpu.textContent = textoONulo(sistema.cpu_pct, " %");
        }
        actualizarBarraConNivel("tt-cpu-barra", sistema.cpu_pct);

        var mem = document.getElementById("tt-mem");
        if (mem) {
            mem.textContent = textoONulo(sistema.memoria_pct, " %");
        }
        actualizarBarraConNivel("tt-mem-barra", sistema.memoria_pct);

        var disco = document.getElementById("tt-disco");
        if (disco) {
            disco.textContent = textoONulo(sistema.disco_pct, " %");
        }
        actualizarBarraConNivel("tt-disco-barra", sistema.disco_pct);

        var nDispositivos = document.getElementById("tt-n-dispositivos");
        if (nDispositivos) {
            nDispositivos.textContent = textoONulo(datos.n_dispositivos, "");
        }
    }

    function refrescarDashboard() {
        var contenedor = document.getElementById("tt-wans");
        if (!contenedor) {
            return; // no estamos en el dashboard
        }
        fetch("/dashboard/datos.json", { credentials: "same-origin" })
            .then(function (resp) {
                if (!resp.ok) {
                    throw new Error("respuesta no válida");
                }
                return resp.json();
            })
            .then(actualizarResumen)
            .catch(function () {
                // Si falla el refresco, se mantiene el último estado conocido.
            });
    }

    document.addEventListener("DOMContentLoaded", function () {
        inicializarBarras();
        refrescarDashboard();
        setInterval(refrescarDashboard, INTERVALO_MS);
    });
})();
