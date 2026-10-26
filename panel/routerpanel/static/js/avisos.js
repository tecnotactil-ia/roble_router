// Avisos flotantes (toasts) a partir de los mensajes flash renderizados por
// el servidor en _mensajes.html. Sin este script los avisos ya son visibles
// (se renderizan en el HTML, dentro de #tt-toast-origen, en el flujo
// normal de la página, antes de <main>); este fichero:
//  - reparte cada aviso, según su categoría, a una de las dos regiones
//    vivas vacías del wrapper fijo (#tt-toast-urgente para warning/error,
//    #tt-toast-contenedor para el resto), MOVIENDO los nodos ya
//    renderizados (sin clonar, sin innerHTML) con un pequeño retraso tras
//    DOMContentLoaded para que el lector de pantalla llegue a registrar
//    esas regiones como vivas antes de la inserción;
//  - añade la animación de entrada/salida;
//  - añade el cierre automático/manual y muestra el botón de cerrar
//    (oculto sin JS, ver panel.css);
//  - gestiona el foco al cerrar un aviso.
//
// Sin JS, los avisos se quedan donde están (#tt-toast-origen, visible, en
// el flujo de la página) y no se cierran nunca solos: no hay temporizador
// posible sin JS.
//
// Nada de estilos ni manejadores inline: todo se añade aquí vía JS, acorde
// a la CSP "script-src 'self'".

(function () {
    "use strict";

    // warning y error no se cierran solos (0 = sin temporizador).
    var DURACIONES_MS = {
        ok: 5000,
        info: 5000,
        warning: 0,
        error: 0
    };

    var CATEGORIAS_URGENTES = ["warning", "error"];

    // Retraso antes de mover los avisos a las regiones vivas. No es un
    // capricho: si se insertan en el mismo tick en que el lector de
    // pantalla todavía está procesando el DOM inicial (regiones vacías
    // incluidas), algunos lectores no llegan a registrarlas como "vivas"
    // a tiempo y se saltan el anuncio. Un pequeño margen después de
    // DOMContentLoaded da tiempo a que el árbol de accesibilidad esté
    // asentado antes de la inserción.
    var RETRASO_REPARTO_MS = 150;

    function reducirMovimiento() {
        return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    }

    function destinoParaCategoria(categoria) {
        var selector = CATEGORIAS_URGENTES.indexOf(categoria) !== -1
            ? "[data-tt-toasts-urgente]"
            : "[data-tt-toasts]";
        return document.querySelector(selector);
    }

    // Reparte (mueve, no clona, no usa innerHTML) cada aviso ya renderizado
    // en #tt-toast-origen a la región viva que le corresponda por
    // categoría. Devuelve el wrapper fijo si existe.
    function repartirEnRegionesVivas() {
        var origen = document.querySelector("[data-tt-toasts-origen]");
        var wrapper = document.querySelector("[data-tt-toast-wrapper]");
        if (!origen || !wrapper) {
            return wrapper;
        }
        var nodos = Array.prototype.slice.call(origen.children);
        nodos.forEach(function (nodo) {
            var categoria = nodo.getAttribute("data-tt-categoria") || "info";
            var destino = destinoParaCategoria(categoria);
            if (destino) {
                destino.appendChild(nodo);
            }
        });
        wrapper.classList.add("tt-toast-js");
        return wrapper;
    }

    // Si el foco estaba dentro del aviso que se cierra, lo mueve al
    // siguiente aviso restante (su botón cerrar) -entre las dos regiones,
    // en orden del documento, saltando cualquiera que ya se esté
    // cerrando-, o si no queda ninguno, a <main> (tabindex="-1").
    function moverFocoTrasCierre(toast) {
        if (!toast.contains(document.activeElement)) {
            return;
        }
        var wrapper = document.querySelector("[data-tt-toast-wrapper]");
        var todos = wrapper ? Array.prototype.slice.call(wrapper.querySelectorAll("[data-tt-toast]")) : [];
        var indice = todos.indexOf(toast);

        function siguienteUtilizable(lista) {
            for (var i = 0; i < lista.length; i++) {
                if (lista[i].dataset.ttCerrando !== "1") {
                    return lista[i];
                }
            }
            return null;
        }

        var candidato = siguienteUtilizable(todos.slice(indice + 1));
        if (!candidato) {
            candidato = siguienteUtilizable(todos.slice(0, indice).reverse());
        }
        if (candidato) {
            var boton = candidato.querySelector("[data-tt-toast-cerrar]");
            (boton || candidato).focus();
            return;
        }
        var main = document.getElementById("tt-main");
        if (main) {
            main.focus();
        }
    }

    function cerrarToast(toast) {
        if (!toast || toast.dataset.ttCerrando === "1") {
            return;
        }
        toast.dataset.ttCerrando = "1";
        if (toast._ttTemporizador) {
            clearTimeout(toast._ttTemporizador);
            toast._ttTemporizador = null;
        }

        moverFocoTrasCierre(toast);

        if (reducirMovimiento()) {
            toast.remove();
            return;
        }
        toast.classList.remove("tt-toast-entrando");
        toast.classList.add("tt-toast-saliendo");
        toast.addEventListener("transitionend", function () {
            toast.remove();
        }, { once: true });
        // Por si la transición no llega a disparar (p. ej. display:none en un
        // ancestro), aseguramos la eliminación igualmente.
        window.setTimeout(function () {
            if (toast.isConnected) {
                toast.remove();
            }
        }, 400);
    }

    function iniciarTemporizador(toast, duracionMs) {
        if (!duracionMs) {
            return;
        }
        toast._ttRestante = duracionMs;
        toast._ttInicio = Date.now();
        toast._ttTemporizador = window.setTimeout(function () {
            cerrarToast(toast);
        }, toast._ttRestante);
    }

    function pausarTemporizador(toast) {
        if (!toast._ttTemporizador) {
            return;
        }
        window.clearTimeout(toast._ttTemporizador);
        toast._ttTemporizador = null;
        var transcurrido = Date.now() - toast._ttInicio;
        toast._ttRestante = Math.max(0, toast._ttRestante - transcurrido);
    }

    function reanudarTemporizador(toast) {
        if (toast._ttTemporizador || !toast._ttRestante || toast.dataset.ttCerrando === "1") {
            return;
        }
        toast._ttInicio = Date.now();
        toast._ttTemporizador = window.setTimeout(function () {
            cerrarToast(toast);
        }, toast._ttRestante);
    }

    function prepararToast(toast) {
        var categoria = toast.getAttribute("data-tt-categoria") || "info";
        var duracionMs = DURACIONES_MS.hasOwnProperty(categoria) ? DURACIONES_MS[categoria] : 5000;

        // Animación de entrada: se añade por JS (sin JS el aviso ya es
        // visible por defecto, ver CSS).
        if (!reducirMovimiento()) {
            toast.classList.add("tt-toast-entrando");
            window.requestAnimationFrame(function () {
                window.requestAnimationFrame(function () {
                    toast.classList.remove("tt-toast-entrando");
                });
            });
        }

        iniciarTemporizador(toast, duracionMs);

        // Hover y foco se controlan por separado: solo se reanuda el
        // temporizador cuando NINGUNO de los dos está activo.
        toast._ttHover = false;
        toast._ttFoco = false;

        function evaluarPausa() {
            if (toast._ttHover || toast._ttFoco) {
                pausarTemporizador(toast);
            } else {
                reanudarTemporizador(toast);
            }
        }

        toast.addEventListener("mouseenter", function () {
            toast._ttHover = true;
            evaluarPausa();
        });
        toast.addEventListener("mouseleave", function () {
            toast._ttHover = false;
            evaluarPausa();
        });
        toast.addEventListener("focusin", function () {
            toast._ttFoco = true;
            evaluarPausa();
        });
        toast.addEventListener("focusout", function () {
            toast._ttFoco = false;
            evaluarPausa();
        });

        var boton = toast.querySelector("[data-tt-toast-cerrar]");
        if (boton) {
            boton.addEventListener("click", function () {
                cerrarToast(toast);
            });
        }
    }

    function inicializarToasts() {
        window.setTimeout(function () {
            var wrapper = repartirEnRegionesVivas();
            if (!wrapper) {
                return;
            }
            var toasts = wrapper.querySelectorAll("[data-tt-toast]");
            toasts.forEach(prepararToast);
        }, RETRASO_REPARTO_MS);
    }

    document.addEventListener("DOMContentLoaded", inicializarToasts);
})();
