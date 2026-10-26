// JS propio de la página de Registro: filtra la línea de tiempo en vivo
// por texto y por el chip rápido (Todos / Errores). Oculta también los
// grupos de día que se quedan sin ninguna operación visible.

(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
        var contenedor = document.getElementById("tt-registro-linea");
        if (!contenedor) {
            return;
        }

        var grupos = Array.prototype.slice.call(contenedor.querySelectorAll(".tt-registro-grupo"));
        var busqueda = document.getElementById("tt-registro-busqueda");
        var chips = Array.prototype.slice.call(document.querySelectorAll(".tt-registro-filtros .tt-filtro-chip"));
        var sinResultados = document.getElementById("tt-registro-sin-resultados");
        var filtroActual = "todos";

        function coincideFiltro(item) {
            if (filtroActual === "todos") {
                return true;
            }
            return item.getAttribute("data-resultado") === filtroActual;
        }

        function coincideBusqueda(item) {
            var texto = ((busqueda && busqueda.value) || "").trim().toLowerCase();
            if (!texto) {
                return true;
            }
            return (item.getAttribute("data-busqueda") || "").indexOf(texto) !== -1;
        }

        function aplicarFiltros() {
            var totalVisible = 0;
            grupos.forEach(function (grupo) {
                var items = Array.prototype.slice.call(grupo.querySelectorAll(".tt-registro-item"));
                var visiblesGrupo = 0;
                items.forEach(function (item) {
                    var mostrar = coincideFiltro(item) && coincideBusqueda(item);
                    item.classList.toggle("d-none", !mostrar);
                    if (mostrar) {
                        visiblesGrupo += 1;
                    }
                });
                grupo.classList.toggle("d-none", visiblesGrupo === 0);
                totalVisible += visiblesGrupo;
            });
            if (sinResultados) {
                sinResultados.classList.toggle("d-none", totalVisible !== 0 || grupos.length === 0);
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
    });
})();
