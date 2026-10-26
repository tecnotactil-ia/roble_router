// /dashboard: sección "Estadísticas". Pide el JSON del rango elegido y
// dibuja los gráficos con Chart.js (vendorizado en static/vendor/chartjs,
// nada de CDN). Nada de estilos ni manejadores inline: acorde a la CSP
// "script-src 'self'". Los nombres de dispositivo/dominio que vienen del
// servidor sólo se usan como datos de Chart.js (los dibuja en <canvas>, no
// los interpreta como HTML) o se escriben con textContent cuando hace falta
// construir algún nodo a mano (incluida la tabla accesible de cada gráfico).
(function () {
    "use strict";

    if (typeof Chart === "undefined") {
        return; // vendor no disponible: la sección se queda con los <p> "sin datos" del servidor.
    }

    var INTERVALO_MS = 60000;
    var TIMEOUT_MS = 15000;
    var RANGOS = ["1h", "24h", "7d", "30d"];

    var seccion = document.getElementById("tt-estadisticas");
    if (!seccion) {
        return; // no estamos en el dashboard
    }

    var urlBase = seccion.getAttribute("data-estadisticas-url");
    if (!urlBase) {
        return;
    }

    var reducirMovimiento = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    Chart.defaults.animation = reducirMovimiento ? false : { duration: 350 };
    Chart.defaults.font.family = "system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif";
    Chart.defaults.maintainAspectRatio = false;
    Chart.defaults.responsive = true;

    function temaOscuro() {
        return !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    }

    // ---------- colores (leídos de las variables CSS del panel: respetan
    // claro/oscuro automáticamente, sin duplicar la paleta aquí) ----------

    function variableCss(nombre, porDefecto) {
        var valor = getComputedStyle(document.documentElement).getPropertyValue(nombre);
        valor = (valor || "").trim();
        return valor || porDefecto;
    }

    function colores() {
        return {
            lineas: [
                variableCss("--tt-linea-1", "#13a8d8"),
                variableCss("--tt-linea-2", "#5fd0f0"),
                variableCss("--tt-linea-3", "#134074"),
                variableCss("--tt-linea-4", "#0b2545"),
                variableCss("--tt-linea-5", "#0e7fa6"),
                variableCss("--tt-linea-6", "#5c7fa3"),
            ],
            texto: variableCss("--tt-texto-sec", "#5b6b82"),
            borde: variableCss("--tt-borde", "rgba(11,37,69,0.10)"),
            cian: variableCss("--tt-cian", "#13a8d8"),
            azul: variableCss("--tt-azul", "#134074"),
            // Paleta de datos: permitidas en azules/cian del panel, bloqueadas
            // en oro/ámbar (--tt-oro) -- nunca verde/rojo para series de datos.
            permitidas: variableCss("--tt-azul", "#134074"),
            bloqueadas: variableCss("--tt-oro", "#c9a227"),
            neutro: variableCss("--tt-neutro", "#6b7a90"),
        };
    }

    function colorLinea(indice) {
        var paleta = colores().lineas;
        return paleta[indice % paleta.length];
    }

    function conAlfa(colorHex, alfa) {
        // Los colores del panel son siempre "#rrggbb"; si llegara algo
        // distinto (p. ej. un "rgba(...)" ya con alfa) se usa tal cual.
        if (typeof colorHex !== "string" || colorHex.charAt(0) !== "#" || colorHex.length !== 7) {
            return colorHex;
        }
        var r = parseInt(colorHex.slice(1, 3), 16);
        var g = parseInt(colorHex.slice(3, 5), 16);
        var b = parseInt(colorHex.slice(5, 7), 16);
        return "rgba(" + r + "," + g + "," + b + "," + alfa + ")";
    }

    function opcionesLeyenda() {
        var c = colores();
        return { labels: { color: c.texto, boxWidth: 12, usePointStyle: true } };
    }

    function tituloEje(texto) {
        var c = colores();
        return { display: true, text: texto, color: c.texto, font: { size: 11 } };
    }

    // ---------- formato de números (siempre con separador de miles) ----------

    function formatearNumero(valor) {
        if (valor === null || valor === undefined || isNaN(valor)) {
            return "—";
        }
        var n = Number(valor);
        try {
            var texto = n.toLocaleString("es-ES", { useGrouping: "always" });
            if (texto) {
                return texto;
            }
        } catch (e) {
            // sigue al respaldo manual
        }
        var entero = String(Math.round(n));
        var negativo = entero.charAt(0) === "-";
        if (negativo) {
            entero = entero.slice(1);
        }
        entero = entero.replace(/\B(?=(\d{3})+(?!\d))/g, ".");
        return negativo ? "-" + entero : entero;
    }

    function formatearBytesEje(valor) {
        if (valor === null || valor === undefined || isNaN(valor) || valor < 0) {
            return "0 B";
        }
        var unidades = ["B", "KB", "MB", "GB", "TB"];
        var n = Number(valor);
        var i = 0;
        while (n >= 1000 && i < unidades.length - 1) {
            n /= 1000;
            i += 1;
        }
        var texto = i === 0 ? String(Math.round(n)) : n.toFixed(1).replace(".", ",");
        return texto + " " + unidades[i];
    }

    // Recorta las etiquetas largas del eje Y de los gráficos de barras
    // horizontales ("nombre (ip)", dominios largos...) para que no se
    // corten de forma impredecible en pantallas estrechas; el texto
    // completo sigue disponible en el tooltip y en la tabla de datos.
    function etiquetaCorta(texto, maxLen) {
        if (typeof texto !== "string" || texto.length <= maxLen) {
            return texto;
        }
        return texto.slice(0, maxLen - 1) + "…";
    }

    // Recorta más corto si el propio <canvas> es estrecho (p. ej.
    // en 390px de ancho): "this" en un callback de ticks es la escala, que
    // conoce el ancho real ya calculado del gráfico (this.chart.width), así
    // que la etiqueta no se corta de forma impredecible por falta de sitio.
    function ticksEtiquetaResponsiva(maxLenAncho, maxLenEstrecho, anchoCorte) {
        return function (valor) {
            var ancho = (this.chart && this.chart.width) || (window.innerWidth || anchoCorte);
            var maxLen = ancho < anchoCorte ? maxLenEstrecho : maxLenAncho;
            return etiquetaCorta(this.getLabelForValue(valor), maxLen);
        };
    }

    // Altura del contenedor del gráfico proporcional al número de filas
    // (barras horizontales de dominios/dispositivos): en vez de una altura
    // fija, cada fila tiene sitio real tanto en escritorio como en móvil.
    function ajustarAltoPorFilas(idWrap, nFilas, alturaFila, minimoPx) {
        var wrap = document.getElementById(idWrap);
        if (!wrap) {
            return;
        }
        var alto = Math.max(minimoPx, nFilas * alturaFila + 36);
        wrap.style.height = alto + "px";
    }

    // ---------- estado vacío por tarjeta ----------

    function mostrarVacio(idCanvas, idVacio, vacio) {
        var canvas = document.getElementById(idCanvas);
        var aviso = document.getElementById(idVacio);
        if (canvas) {
            canvas.classList.toggle("d-none", vacio);
        }
        if (aviso) {
            aviso.classList.toggle("d-none", !vacio);
        }
    }

    // ---------- tabla de datos accesible (alternativa textual a cada gráfico) ----------

    function limpiarNodo(el) {
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    }

    function llenarCuerpoTabla(tbody, filas) {
        limpiarNodo(tbody);
        filas.forEach(function (fila) {
            var tr = document.createElement("tr");
            fila.forEach(function (valor) {
                var td = document.createElement("td");
                td.textContent = valor === null || valor === undefined ? "—" : String(valor);
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
    }

    // Si el <details> ya existe de un refresco anterior, se reutiliza (sólo
    // se reemplaza el <tbody>): así no se pierde si el usuario lo tenía
    // abierto leyendo los datos cuando llega el siguiente refresco de 60s.
    function construirTablaDatos(idContenedor, cabeceras, filas) {
        var contenedor = document.getElementById(idContenedor);
        if (!contenedor) {
            return;
        }
        if (!filas || filas.length === 0) {
            limpiarNodo(contenedor);
            return;
        }

        var details = contenedor.querySelector(".tt-estad-detalle");
        if (details) {
            var tbody = details.querySelector("tbody");
            if (tbody) {
                llenarCuerpoTabla(tbody, filas);
                return;
            }
            limpiarNodo(contenedor); // estructura inesperada: se reconstruye desde cero
        }

        details = document.createElement("details");
        details.className = "tt-estad-detalle";
        var summary = document.createElement("summary");
        summary.textContent = "Ver datos";
        details.appendChild(summary);

        var wrap = document.createElement("div");
        wrap.className = "tt-estad-tabla-wrap";
        var tabla = document.createElement("table");
        tabla.className = "tt-estad-tabla";

        var thead = document.createElement("thead");
        var trCab = document.createElement("tr");
        cabeceras.forEach(function (texto) {
            var th = document.createElement("th");
            th.scope = "col";
            th.textContent = texto;
            trCab.appendChild(th);
        });
        thead.appendChild(trCab);
        tabla.appendChild(thead);

        var nuevoTbody = document.createElement("tbody");
        llenarCuerpoTabla(nuevoTbody, filas);
        tabla.appendChild(nuevoTbody);

        wrap.appendChild(tabla);
        details.appendChild(wrap);
        contenedor.appendChild(details);
    }

    // ---------- gráficos: se actualizan en sitio (chart.update('none')); sólo
    // se destruyen y recrean si cambia el tema claro/oscuro (los colores se
    // fijan al crear el gráfico). Actualizar en sitio conserva qué series
    // tiene ocultas el usuario (clic en la leyenda). ----------

    var graficos = {};
    var modoTrafico = "bajada"; // "bajada" | "subida" -- ver segmentado de la tarjeta

    function sincronizarGrafico(clave, idCanvas, config) {
        var canvas = document.getElementById(idCanvas);
        if (!canvas) {
            return null;
        }
        var tema = temaOscuro();
        var existente = graficos[clave];

        if (existente && existente.__ttTema === tema) {
            existente.data.labels = config.data.labels;
            var actuales = existente.data.datasets;
            var nuevos = config.data.datasets;
            // Empareja por "label", no por posición: el nº/orden de series
            // puede cambiar entre rangos (p. ej. "Conexiones activas" sólo
            // existe en 1h/24h), y así el estado "oculto" (clic en la
            // leyenda) de una serie no se cuela sobre una serie distinta.
            var restantes = nuevos.map(function (nuevo) {
                var actual = actuales.filter(function (a) { return a.label === nuevo.label; })[0];
                if (!actual) {
                    return nuevo;
                }
                var oculto = actual.hidden;
                Object.keys(nuevo).forEach(function (clave) {
                    actual[clave] = nuevo[clave];
                });
                if (oculto !== undefined) {
                    actual.hidden = oculto;
                }
                return actual;
            });
            existente.data.datasets = restantes;
            existente.options = config.options;
            existente.update("none");
            return existente;
        }

        if (existente) {
            existente.destroy();
        }
        var ctx = canvas.getContext("2d");
        var nuevo = new Chart(ctx, config);
        nuevo.__ttTema = tema;
        graficos[clave] = nuevo;
        return nuevo;
    }

    function actualizarTrafico(datos) {
        var trafico = (datos && datos.trafico) || { etiquetas: [], series: [] };
        var vacio = !trafico.series || trafico.series.length === 0 || trafico.etiquetas.length === 0;
        mostrarVacio("tt-grafico-trafico", "tt-vacio-trafico", vacio);
        if (vacio) {
            construirTablaDatos("tt-datos-trafico", [], []);
            return;
        }
        var campo = modoTrafico === "subida" ? "subida_mbps" : "bajada_mbps";
        var etiquetaCampo = modoTrafico === "subida" ? "Subida" : "Bajada";
        var datasets = trafico.series.map(function (serie, i) {
            var color = colorLinea(i);
            return {
                label: serie.nombre,
                data: serie[campo],
                borderColor: color,
                backgroundColor: conAlfa(color, 0.18),
                // Líneas de comparación por línea WAN, no un total apilado:
                // sumar capacidades de líneas distintas no es una magnitud
                // útil aquí, así que cada una se dibuja con su propio
                // relleno (no "stacked") para que no parezca un apilado que
                // no lo es.
                fill: true,
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2,
                spanGaps: true,
            };
        });
        sincronizarGrafico("trafico", "tt-grafico-trafico", {
            type: "line",
            data: { labels: trafico.etiquetas, datasets: datasets },
            options: {
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: opcionesLeyenda(),
                    tooltip: {
                        callbacks: {
                            label: function (item) {
                                var v = item.parsed.y;
                                return item.dataset.label + ": " + (v === null ? "—" : v.toFixed(2) + " Mbit/s");
                            },
                        },
                    },
                },
                scales: {
                    x: { ticks: { color: colores().texto, maxRotation: 0, autoSkipPadding: 12 }, grid: { color: colores().borde } },
                    y: { ticks: { color: colores().texto }, grid: { color: colores().borde }, beginAtZero: true, title: tituloEje("Mbit/s") },
                },
            },
        });

        construirTablaDatos(
            "tt-datos-trafico",
            ["Hora", etiquetaCampo + " (línea)", "Mbit/s"],
            trafico.etiquetas.reduce(function (filas, etiqueta, i) {
                trafico.series.forEach(function (serie) {
                    var v = serie[campo][i];
                    filas.push([etiqueta, serie.nombre, v === null ? "—" : v.toFixed(2)]);
                });
                return filas;
            }, [])
        );
    }

    function actualizarLatencia(datos) {
        var lat = (datos && datos.latencia) || { etiquetas: [], series: [] };
        var vacio = !lat.series || lat.series.length === 0 || lat.etiquetas.length === 0;
        mostrarVacio("tt-grafico-latencia", "tt-vacio-latencia", vacio);
        if (vacio) {
            construirTablaDatos("tt-datos-latencia", [], []);
            return;
        }
        var datasets = lat.series.map(function (serie, i) {
            var color = colorLinea(i);
            return {
                label: serie.nombre,
                data: serie.latencia_ms,
                borderColor: color,
                backgroundColor: color,
                fill: false,
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2,
                spanGaps: true,
            };
        });
        sincronizarGrafico("latencia", "tt-grafico-latencia", {
            type: "line",
            data: { labels: lat.etiquetas, datasets: datasets },
            options: {
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: opcionesLeyenda(),
                    tooltip: {
                        callbacks: {
                            label: function (item) {
                                var v = item.parsed.y;
                                return item.dataset.label + ": " + (v === null ? "—" : v.toFixed(0) + " ms");
                            },
                        },
                    },
                },
                scales: {
                    x: { ticks: { color: colores().texto, maxRotation: 0, autoSkipPadding: 12 }, grid: { color: colores().borde } },
                    y: { ticks: { color: colores().texto }, grid: { color: colores().borde }, beginAtZero: true, title: tituloEje("ms") },
                },
            },
        });

        construirTablaDatos(
            "tt-datos-latencia",
            ["Hora", "Línea", "Latencia (ms)"],
            lat.etiquetas.reduce(function (filas, etiqueta, i) {
                lat.series.forEach(function (serie) {
                    var v = serie.latencia_ms[i];
                    filas.push([etiqueta, serie.nombre, v === null ? "—" : v.toFixed(0)]);
                });
                return filas;
            }, [])
        );
    }

    function actualizarTopDispositivos(datos) {
        var lista = (datos && datos.top_dispositivos) || [];
        var vacio = lista.length === 0;
        mostrarVacio("tt-grafico-top-dispositivos", "tt-vacio-top-dispositivos", vacio);
        if (vacio) {
            construirTablaDatos("tt-datos-top-dispositivos", [], []);
            return;
        }
        ajustarAltoPorFilas("tt-wrap-top-dispositivos", lista.length, 34, 220);
        var c = colores();
        var etiquetas = lista.map(function (d) {
            return d.nombre + " (" + d.ip + ")";
        });
        sincronizarGrafico("topDispositivos", "tt-grafico-top-dispositivos", {
            type: "bar",
            data: {
                labels: etiquetas,
                datasets: [
                    {
                        label: "Bajada",
                        data: lista.map(function (d) { return d.bajada_bytes; }),
                        backgroundColor: c.cian,
                        stack: "trafico",
                    },
                    {
                        label: "Subida",
                        data: lista.map(function (d) { return d.subida_bytes; }),
                        backgroundColor: c.azul,
                        stack: "trafico",
                    },
                ],
            },
            options: {
                indexAxis: "y",
                plugins: {
                    legend: opcionesLeyenda(),
                    tooltip: {
                        callbacks: {
                            label: function (item) {
                                return item.dataset.label + ": " + formatearBytesEje(item.parsed.x);
                            },
                        },
                    },
                },
                scales: {
                    x: {
                        stacked: true,
                        beginAtZero: true,
                        ticks: { color: c.texto, maxRotation: 0, maxTicksLimit: 6, callback: function (v) { return formatearBytesEje(v); } },
                        grid: { color: c.borde },
                        title: tituloEje("Bytes"),
                    },
                    y: {
                        stacked: true,
                        ticks: { color: c.texto, autoSkip: false, callback: ticksEtiquetaResponsiva(26, 18, 420) },
                        grid: { display: false },
                    },
                },
            },
        });

        construirTablaDatos(
            "tt-datos-top-dispositivos",
            ["Dispositivo", "IP", "Bajada", "Subida"],
            lista.map(function (d) {
                return [d.nombre, d.ip, d.bajada_fmt, d.subida_fmt];
            })
        );
    }

    function actualizarDnsBloqueo(datos) {
        var serie = (datos && datos.dns_consultas_vs_bloqueadas) || { etiquetas: [], consultas: [], bloqueadas: [] };
        var vacio = !serie.etiquetas || serie.etiquetas.length === 0;
        mostrarVacio("tt-grafico-dns-bloqueo", "tt-vacio-dns-bloqueo", vacio);
        if (vacio) {
            construirTablaDatos("tt-datos-dns-bloqueo", [], []);
            return;
        }
        var c = colores();
        var permitidas = serie.consultas.map(function (total, i) {
            var bloqueadas = serie.bloqueadas[i] || 0;
            return Math.max(0, (total || 0) - bloqueadas);
        });
        sincronizarGrafico("dnsBloqueo", "tt-grafico-dns-bloqueo", {
            type: "bar",
            data: {
                labels: serie.etiquetas,
                datasets: [
                    { label: "Permitidas", data: permitidas, backgroundColor: c.permitidas, stack: "dns" },
                    { label: "Bloqueadas", data: serie.bloqueadas, backgroundColor: c.bloqueadas, stack: "dns" },
                ],
            },
            options: {
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: opcionesLeyenda(),
                    tooltip: {
                        callbacks: {
                            label: function (item) {
                                return item.dataset.label + ": " + formatearNumero(item.parsed.y);
                            },
                        },
                    },
                },
                scales: {
                    x: { stacked: true, ticks: { color: c.texto, maxRotation: 0, autoSkipPadding: 12 }, grid: { color: c.borde } },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        ticks: { color: c.texto, callback: function (v) { return formatearNumero(v); } },
                        grid: { color: c.borde },
                        title: tituloEje("Consultas"),
                    },
                },
            },
        });

        construirTablaDatos(
            "tt-datos-dns-bloqueo",
            ["Hora", "Permitidas", "Bloqueadas"],
            serie.etiquetas.map(function (etiqueta, i) {
                return [etiqueta, formatearNumero(permitidas[i]), formatearNumero(serie.bloqueadas[i])];
            })
        );
    }

    function actualizarDnsTop(datos) {
        var lista = (datos && datos.dns_top) || [];
        var vacio = lista.length === 0;
        mostrarVacio("tt-grafico-dns-top", "tt-vacio-dns-top", vacio);
        if (vacio) {
            construirTablaDatos("tt-datos-dns-top", [], []);
            return;
        }
        ajustarAltoPorFilas("tt-wrap-dns-top", lista.length, 30, 260);
        var c = colores();
        sincronizarGrafico("dnsTop", "tt-grafico-dns-top", {
            type: "bar",
            data: {
                labels: lista.map(function (d) { return d.dominio; }),
                datasets: [{ label: "Consultas", data: lista.map(function (d) { return d.consultas; }), backgroundColor: c.permitidas }],
            },
            options: {
                indexAxis: "y",
                plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { label: function (item) { return formatearNumero(item.parsed.x) + " consultas"; } } },
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { color: c.texto, maxRotation: 0, maxTicksLimit: 6, callback: function (v) { return formatearNumero(v); } },
                        grid: { color: c.borde },
                        title: tituloEje("Consultas"),
                    },
                    y: { ticks: { color: c.texto, autoSkip: false, callback: ticksEtiquetaResponsiva(30, 18, 420) }, grid: { display: false } },
                },
            },
        });

        construirTablaDatos(
            "tt-datos-dns-top",
            ["Dominio", "Consultas"],
            lista.map(function (d) { return [d.dominio, formatearNumero(d.consultas)]; })
        );
    }

    function actualizarDnsBloqueados(datos) {
        var lista = (datos && datos.dns_bloqueados_top) || [];
        var vacio = lista.length === 0;
        mostrarVacio("tt-grafico-dns-bloqueados", "tt-vacio-dns-bloqueados", vacio);
        if (vacio) {
            construirTablaDatos("tt-datos-dns-bloqueados", [], []);
            return;
        }
        ajustarAltoPorFilas("tt-wrap-dns-bloqueados", lista.length, 30, 260);
        var c = colores();
        sincronizarGrafico("dnsBloqueados", "tt-grafico-dns-bloqueados", {
            type: "bar",
            data: {
                labels: lista.map(function (d) { return d.dominio; }),
                datasets: [{ label: "Bloqueadas", data: lista.map(function (d) { return d.bloqueadas; }), backgroundColor: c.bloqueadas }],
            },
            options: {
                indexAxis: "y",
                plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { label: function (item) { return formatearNumero(item.parsed.x) + " bloqueadas"; } } },
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { color: c.texto, maxRotation: 0, maxTicksLimit: 6, callback: function (v) { return formatearNumero(v); } },
                        grid: { color: c.borde },
                        title: tituloEje("Consultas bloqueadas"),
                    },
                    y: { ticks: { color: c.texto, autoSkip: false, callback: ticksEtiquetaResponsiva(30, 18, 420) }, grid: { display: false } },
                },
            },
        });

        construirTablaDatos(
            "tt-datos-dns-bloqueados",
            ["Dominio", "Bloqueadas"],
            lista.map(function (d) { return [d.dominio, formatearNumero(d.bloqueadas)]; })
        );
    }

    function actualizarActividad(datos) {
        var act = (datos && datos.actividad) || { etiquetas: [], conexiones: [], dispositivos_activos: [], conexiones_disponible: true };
        var vacio = !act.etiquetas || act.etiquetas.length === 0;
        mostrarVacio("tt-grafico-actividad", "tt-vacio-actividad", vacio);

        var notaConexiones = document.getElementById("tt-nota-conexiones");
        if (notaConexiones) {
            notaConexiones.classList.toggle("d-none", act.conexiones_disponible !== false);
        }

        if (vacio) {
            construirTablaDatos("tt-datos-actividad", [], []);
            return;
        }
        var c = colores();
        var hayConexiones = act.conexiones_disponible !== false;

        var datasets = [];
        var scales = {
            x: { ticks: { color: c.texto, maxRotation: 0, autoSkipPadding: 12 }, grid: { color: c.borde } },
        };

        if (hayConexiones) {
            datasets.push({
                label: "Conexiones activas",
                data: act.conexiones,
                borderColor: c.cian,
                backgroundColor: conAlfa(c.cian, 0.18),
                fill: true,
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2,
                spanGaps: true,
                yAxisID: "y",
            });
            scales.y = {
                position: "left",
                beginAtZero: true,
                ticks: { color: c.texto, callback: function (v) { return formatearNumero(v); } },
                grid: { color: c.borde },
                title: tituloEje("Conexiones"),
            };
            scales.y1 = {
                position: "right",
                beginAtZero: true,
                // "Dispositivos" es un conteo entero (nunca 2,5 dispositivos)
                // y con poco margen (grace) la línea queda pegada al borde
                // superior del gráfico cuando el valor apenas varía.
                grace: "15%",
                ticks: { color: c.texto, precision: 0, callback: function (v) { return formatearNumero(v); } },
                grid: { drawOnChartArea: false },
                title: tituloEje("Dispositivos"),
            };
        } else {
            // Sin conexiones disponibles (rango > 48h): un solo eje, para no
            // dibujar una escala 0-1 vacía por la izquierda sin ninguna línea.
            scales.y = {
                beginAtZero: true,
                grace: "15%",
                ticks: { color: c.texto, precision: 0, callback: function (v) { return formatearNumero(v); } },
                grid: { color: c.borde },
                title: tituloEje("Dispositivos"),
            };
        }

        datasets.push({
            label: "Dispositivos activos",
            data: act.dispositivos_activos,
            borderColor: c.azul,
            backgroundColor: c.azul,
            fill: false,
            tension: 0.25,
            pointRadius: 0,
            borderWidth: 2,
            spanGaps: true,
            yAxisID: hayConexiones ? "y1" : "y",
        });

        sincronizarGrafico("actividad", "tt-grafico-actividad", {
            type: "line",
            data: { labels: act.etiquetas, datasets: datasets },
            options: {
                interaction: { mode: "index", intersect: false },
                plugins: { legend: opcionesLeyenda() },
                scales: scales,
            },
        });

        construirTablaDatos(
            "tt-datos-actividad",
            ["Hora", "Conexiones activas", "Dispositivos activos"],
            act.etiquetas.map(function (etiqueta, i) {
                var conexion = act.conexiones[i];
                var disp = act.dispositivos_activos[i];
                return [etiqueta, conexion === null ? "—" : formatearNumero(conexion), disp === null ? "—" : formatearNumero(disp)];
            })
        );
    }

    function actualizarKpis(datos) {
        var totales = (datos && datos.totales) || {};
        var elBajada = document.getElementById("tt-estad-kpi-bajada");
        var elSubida = document.getElementById("tt-estad-kpi-subida");
        var elConsultas = document.getElementById("tt-estad-kpi-consultas");
        var elBloqueado = document.getElementById("tt-estad-kpi-bloqueado");
        if (elBajada) {
            elBajada.textContent = totales.bajada_fmt || "—";
        }
        if (elSubida) {
            elSubida.textContent = totales.subida_fmt || "—";
        }
        if (elConsultas) {
            elConsultas.textContent = formatearNumero(totales.consultas);
        }
        if (elBloqueado) {
            elBloqueado.textContent =
                totales.pct_bloqueado === null || totales.pct_bloqueado === undefined
                    ? "—"
                    : formatearNumero(totales.bloqueadas) + " (" + String(totales.pct_bloqueado).replace(".", ",") + " %)";
        }
    }

    function aplicarDatos(datos) {
        var avisoVacio = document.getElementById("tt-estad-aviso-vacio");
        var avisoVacioTexto = document.getElementById("tt-estad-aviso-vacio-texto");
        var cuerpo = document.getElementById("tt-estad-cuerpo");
        var sinDatos = !datos || datos.disponible === false;

        if (avisoVacio) {
            avisoVacio.classList.toggle("d-none", !sinDatos);
            if (sinDatos) {
                var icono = avisoVacio.querySelector("i");
                if (icono) {
                    icono.className = datos && datos.estado_vacio === "error" ? "bi bi-exclamation-triangle" : "bi bi-bar-chart-line";
                    icono.setAttribute("aria-hidden", "true");
                }
            }
        }
        if (sinDatos && avisoVacioTexto) {
            // Un único texto, el que da el servidor: distingue "todavía no hay
            // datos" de "hubo un error leyendo" sin duplicar la frase aquí.
            avisoVacioTexto.textContent = (datos && datos.error) || "Aún no hay datos de estadísticas.";
        }
        if (cuerpo) {
            cuerpo.classList.toggle("d-none", sinDatos);
        }

        var notaDns = document.getElementById("tt-estad-dns-nota");
        var notaDnsTexto = document.getElementById("tt-estad-dns-nota-texto");
        if (notaDns && notaDnsTexto) {
            var tieneNota = !sinDatos && !!(datos && datos.dns_nota);
            notaDns.classList.toggle("d-none", !tieneNota);
            notaDnsTexto.textContent = tieneNota ? datos.dns_nota : "";
        }

        if (sinDatos) {
            return;
        }
        actualizarKpis(datos);
        actualizarTrafico(datos);
        actualizarLatencia(datos);
        actualizarTopDispositivos(datos);
        actualizarDnsBloqueo(datos);
        actualizarDnsTop(datos);
        actualizarDnsBloqueados(datos);
        actualizarActividad(datos);
    }

    // ---------- "Actualizado a las HH:MM" / aviso de sin conexión ----------

    function marcarActualizado() {
        var el = document.getElementById("tt-estad-actualizado");
        var texto = document.getElementById("tt-estad-actualizado-texto");
        if (el && texto) {
            var ahora = new Date();
            var hh = String(ahora.getHours()).padStart(2, "0");
            var mm = String(ahora.getMinutes()).padStart(2, "0");
            texto.textContent = "Actualizado a las " + hh + ":" + mm;
            el.classList.remove("d-none");
        }
    }

    function marcarSinConexion(mostrar) {
        var el = document.getElementById("tt-estad-sin-conexion");
        if (el) {
            el.classList.toggle("d-none", !mostrar);
        }
    }

    // ---------- carga de datos: cancela la petición anterior si llega otra
    // más nueva (cambio rápido de rango), con timeout propio ----------

    var rangoActual = "24h";
    var ultimosDatos = null;
    var controladorActual = null;

    function rangoSeleccionado() {
        var marcado = document.querySelector('input[name="tt-estad-rango"]:checked');
        return (marcado && RANGOS.indexOf(marcado.value) !== -1) ? marcado.value : "24h";
    }

    function cargar() {
        rangoActual = rangoSeleccionado();
        if (controladorActual) {
            controladorActual.abort();
        }
        var miControlador = (typeof AbortController !== "undefined") ? new AbortController() : null;
        controladorActual = miControlador;
        var temporizador = miControlador
            ? setTimeout(function () { miControlador.abort(); }, TIMEOUT_MS)
            : null;

        var opciones = { credentials: "same-origin" };
        if (miControlador) {
            opciones.signal = miControlador.signal;
        }

        fetch(urlBase + "?rango=" + encodeURIComponent(rangoActual), opciones)
            .then(function (resp) {
                if (!resp.ok) {
                    throw new Error("respuesta no válida");
                }
                return resp.json();
            })
            .then(function (datos) {
                if (miControlador && miControlador !== controladorActual) {
                    return; // superada por una petición más nueva: se ignora
                }
                if (temporizador) {
                    clearTimeout(temporizador);
                }
                ultimosDatos = datos;
                aplicarDatos(datos);
                marcarActualizado();
                marcarSinConexion(false);
            })
            .catch(function () {
                if (miControlador && miControlador !== controladorActual) {
                    return; // cancelada a propósito por una petición más nueva
                }
                if (temporizador) {
                    clearTimeout(temporizador);
                }
                marcarSinConexion(true);
            });
    }

    document.addEventListener("DOMContentLoaded", function () {
        var selectorRango = document.getElementById("tt-estad-rango");
        if (selectorRango) {
            selectorRango.addEventListener("change", cargar);
        }

        var selectorModo = document.getElementById("tt-estad-trafico-modo");
        if (selectorModo) {
            selectorModo.addEventListener("change", function (ev) {
                if (ev.target && ev.target.name === "tt-estad-trafico-modo") {
                    modoTrafico = ev.target.value === "subida" ? "subida" : "bajada";
                    if (ultimosDatos) {
                        actualizarTrafico(ultimosDatos);
                    }
                }
            });
        }

        cargar();

        setInterval(function () {
            if (document.visibilityState === "visible") {
                cargar();
            }
        }, INTERVALO_MS);

        document.addEventListener("visibilitychange", function () {
            if (document.visibilityState === "visible") {
                cargar();
            }
        });

        if (window.matchMedia) {
            window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
                if (ultimosDatos) {
                    aplicarDatos(ultimosDatos);
                }
            });
        }
    });
})();
