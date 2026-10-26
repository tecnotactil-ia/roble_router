// JS propio de la página de Dispositivos (sin dependencias externas más
// allá de Bootstrap, que ya gestiona el dropdown y el modal mediante sus
// atributos data-bs-*). Dos cosas:
//   1. Filtra la lista en vivo por texto y por los chips rápidos.
//   2. Rellena los modales de etiquetar/reservar/quitar-reserva a partir
//      de los data-attributes del botón que los abrió.

(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
        inicializarFiltros();
        inicializarModales();
    });

    function inicializarFiltros() {
        var lista = document.getElementById("tt-dispositivos-lista");
        if (!lista) {
            return;
        }

        var filas = Array.prototype.slice.call(lista.querySelectorAll(".tt-dispositivo-fila"));
        var busqueda = document.getElementById("tt-dispositivos-busqueda");
        var chips = Array.prototype.slice.call(document.querySelectorAll(".tt-filtros .tt-filtro-chip"));
        var sinResultados = document.getElementById("tt-dispositivos-sin-resultados");
        var filtroActual = "todos";

        function coincideFiltro(fila) {
            if (filtroActual === "todos") {
                return true;
            }
            if (filtroActual === "reservado") {
                return fila.getAttribute("data-reserva") === "1";
            }
            return fila.getAttribute("data-estado-filtro") === filtroActual;
        }

        function coincideBusqueda(fila) {
            var texto = ((busqueda && busqueda.value) || "").trim().toLowerCase();
            if (!texto) {
                return true;
            }
            return (fila.getAttribute("data-busqueda") || "").indexOf(texto) !== -1;
        }

        function aplicarFiltros() {
            var visibles = 0;
            filas.forEach(function (fila) {
                var mostrar = coincideFiltro(fila) && coincideBusqueda(fila);
                fila.classList.toggle("d-none", !mostrar);
                if (mostrar) {
                    visibles += 1;
                }
            });
            if (sinResultados) {
                sinResultados.classList.toggle("d-none", visibles !== 0 || filas.length === 0);
            }
        }

        if (busqueda) {
            busqueda.addEventListener("input", aplicarFiltros);
        }

        chips.forEach(function (chip) {
            chip.addEventListener("click", function () {
                chips.forEach(function (c) {
                    c.classList.remove("activo");
                    c.setAttribute("aria-pressed", "false");
                });
                chip.classList.add("activo");
                chip.setAttribute("aria-pressed", "true");
                filtroActual = chip.getAttribute("data-filtro") || "todos";
                aplicarFiltros();
            });
        });

        aplicarFiltros();
    }

    // Copia los data-attributes del botón que abrió el modal (el "disparador",
    // relatedTarget del evento show.bs.modal de Bootstrap) a los campos del
    // formulario del modal, identificados por id.
    function rellenarModal(modalId, mapaAtributoAId) {
        var modal = document.getElementById(modalId);
        if (!modal) {
            return;
        }
        modal.addEventListener("show.bs.modal", function (evento) {
            var disparador = evento.relatedTarget;
            if (!disparador) {
                return;
            }
            Object.keys(mapaAtributoAId).forEach(function (atributo) {
                var destino = document.getElementById(mapaAtributoAId[atributo]);
                if (!destino) {
                    return;
                }
                var valor = disparador.getAttribute("data-" + atributo) || "";
                if ("value" in destino) {
                    destino.value = valor;
                } else {
                    destino.textContent = valor;
                }
            });
        });
    }

    function inicializarModales() {
        rellenarModal("tt-modal-etiquetar", {
            mac: "tt-modal-etiquetar-mac",
            nombre: "tt-modal-etiquetar-nombre",
            etiqueta: "tt-modal-etiquetar-etiqueta"
        });
        rellenarModal("tt-modal-reservar", {
            mac: "tt-modal-reservar-mac",
            ip: "tt-modal-reservar-ip",
            nombre: "tt-modal-reservar-nombre",
            sugerencia: "tt-modal-reservar-nombrecampo"
        });
        rellenarModal("tt-modal-quitar-reserva", {
            mac: "tt-modal-quitar-reserva-mac",
            nombre: "tt-modal-quitar-reserva-nombre"
        });
    }
})();
