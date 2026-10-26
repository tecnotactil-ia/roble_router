#!/bin/bash
# Prueba de extremo a extremo del router multi-WAN en espacios de red aislados.
#
# NO toca la red real del equipo: todo vive en netns propios (rt, cli, tel1,
# tel2, inet) con su propio nftables, rutas y sysctl. Al terminar los borra.
#
#   cli (192.168.50.100) ── lan0 ─[ rt: routerd + nftables ]─ wan1 ── tel1 ──┐
#                                                           └─ wan2 ── tel2 ──┴─ inet (1.1.1.1:8000)
#
# tel1/tel2 hacen NAT como un teléfono; el servidor de inet ve 10.1.0.2 si la
# conexión salió por tel1 y 10.2.0.2 si salió por tel2.
#
# Uso (root): pruebas/netns_multiwan.sh /ruta/a/core
set -u
CORE=${1:?ruta a core/}
T=$(mktemp -d /tmp/rt-prueba.XXXX)
FALLOS=0
ok()   { echo "  ✔ $*"; }
mal()  { echo "  ✘ $*"; FALLOS=$((FALLOS+1)); }
nsx()  { ip netns exec "$@"; }

limpiar() {
  [ -n "${PID_RD:-}" ] && kill "$PID_RD" 2>/dev/null
  [ -n "${PID_WEB:-}" ] && kill "$PID_WEB" 2>/dev/null
  [ -n "${PID_UDP:-}" ] && kill "$PID_UDP" 2>/dev/null
  [ -n "${PID_DNSMASQ:-}" ] && kill "$PID_DNSMASQ" 2>/dev/null
  [ -n "${PID_DNS_ECO:-}" ] && kill "$PID_DNS_ECO" 2>/dev/null
  # tel3: netns del paso 15 (WAN Wi-Fi simulada); se intenta borrar siempre,
  # aunque ese paso no llegue a crearla (2>/dev/null ya lo cubre).
  # Cualquier proceso que siga vivo dentro de los netns (p. ej. el dnsmasq de
  # prueba) se mata antes de borrarlos: un netns borrado no mata a sus
  # procesos y se quedarían huérfanos en la máquina.
  for n in rt cli cli2 tel1 tel2 tel3 inet; do
    ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null
  done
  sleep 0.5
  for n in rt cli cli2 tel1 tel2 tel3 inet; do ip netns del $n 2>/dev/null; done
}
trap limpiar EXIT
limpiar

for n in rt cli tel1 tel2 inet; do ip netns add $n; nsx $n ip link set lo up; done

# enlaces
ip link add lan0 netns rt type veth peer name eth0 netns cli
ip link add wan1 netns rt type veth peer name usb0 netns tel1
ip link add wan2 netns rt type veth peer name usb0 netns tel2
ip link add up1 netns tel1 type veth peer name p1 netns inet
ip link add up2 netns tel2 type veth peer name p2 netns inet

# cliente LAN
nsx cli ip addr add 192.168.50.100/24 dev eth0; nsx cli ip link set eth0 up
nsx cli ip route add default via 192.168.50.1
# Segundo cliente LAN (otra IP, netns propio) — HIGH-4: sirve para comprobar
# que una regla contra un cliente no corta a los demás. Se engancha al mismo
# segmento L2 con macvlan sobre eth0 de cli: el router lo ve por lan0 como
# cualquier otro cliente (pasa por reenvio, no por output).
ip netns add cli2; nsx cli2 ip link set lo up
nsx cli ip link add link eth0 name mac0 type macvlan mode bridge
nsx cli ip link set mac0 netns cli2
nsx cli2 ip link set mac0 name eth0
nsx cli2 ip addr add 192.168.50.101/24 dev eth0; nsx cli2 ip link set eth0 up
nsx cli2 ip route add default via 192.168.50.1

# router
nsx rt ip addr add 192.168.50.1/24 dev lan0
nsx rt ip addr add 192.168.42.17/24 dev wan1
nsx rt ip addr add 192.168.43.20/24 dev wan2
for i in lan0 wan1 wan2; do nsx rt ip link set $i up; done
# lo que haría NetworkManager con el DHCP de cada teléfono
nsx rt ip route add default via 192.168.42.129 dev wan1 metric 700
nsx rt ip route add default via 192.168.43.1 dev wan2 metric 701
nsx rt sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2

# teléfonos: NAT hacia «internet»
for k in 1 2; do
  gw=$([ $k = 1 ] && echo 192.168.42.129/24 || echo 192.168.43.1/24)
  nsx tel$k ip addr add $gw dev usb0; nsx tel$k ip link set usb0 up
  nsx tel$k ip addr add 10.$k.0.2/30 dev up$k; nsx tel$k ip link set up$k up
  nsx tel$k ip route add default via 10.$k.0.1
  nsx tel$k sysctl -qw net.ipv4.ip_forward=1
  nsx tel$k nft -f - <<EOF
table ip nat {
  chain post {
    type nat hook postrouting priority srcnat;
    oifname "up$k" masquerade
  }
}
EOF
done
# internet
nsx inet ip addr add 10.1.0.1/30 dev p1; nsx inet ip addr add 10.2.0.1/30 dev p2
nsx inet ip link set p1 up; nsx inet ip link set p2 up
nsx inet ip addr add 1.1.1.1/32 dev lo; nsx inet ip addr add 8.8.8.8/32 dev lo

# servidor que dice por qué teléfono llegó la conexión (y mantiene keep-alive)
cat > $T/web.py <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        b = self.client_address[0].encode()
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('1.1.1.1', 8000), H).serve_forever()
EOF
nsx inet python3 $T/web.py & PID_WEB=$!

# config del router de prueba
mkdir -p $T/etc
cat > $T/etc/router.json <<EOF
{"modo": "balanceo",
 "lan": {"interfaz": "lan0", "red": "192.168.50.0/24", "ip": "192.168.50.1"},
 "monitor": {"destinos": ["1.1.1.1"], "intervalo_s": 2, "fallos_caida": 2, "exitos_alta": 1},
 "ignorar_interfaces": ["lo", "lan0"], "wan_forzadas": ["wan1", "wan2"], "gestionar_dnsmasq": false,
 "wans": {}, "reservas": [], "etiquetas": {}}
EOF
# N1: la fase ya NO vive en router.json, sino en su propio fichero; se pasa
# a routerd con --fase (ruta explícita, igual que --config: no se mueve con
# --raiz-datos porque no es un dato de ejecución sino de "quién manda").
echo produccion > $T/etc/fase
nsx rt env ROUTER_LOG_CICLO=1 python3 $CORE/routerd.py --config $T/etc/router.json --fase $T/etc/fase --raiz-datos $T > $T/routerd.log 2>&1 & PID_RD=$!

# N conexiones NUEVAS desde el netns indicado → reparto por teléfono.
# Con netns=rt esto es tráfico PROPIO del router (sale de rt, no se reenvía
# desde cli): sirve para probar C1 (marcar_salida + nat_salida).
reparto() {  # reparto <netns> <n>
  # Ronda 4 (e2e, fallo intermitente del paso 2): además del reparto, se
  # cuenta el TIPO de excepción de cada conexión fallida (reset vs
  # timeout vs otra) — se imprime a stderr (nunca a stdout: no debe
  # colarse en la línea que `read a b err <<<` consume, que sólo mira la
  # primera línea). Antes sólo se contaba "error" sin más, y distinguir
  # un reset (servidor/NAT todavía reconfigurándose) de un timeout (de
  # verdad caído) era imposible a simple vista en el log.
  nsx "$1" python3 - "$2" <<'EOF'
import sys, urllib.request, urllib.error, collections, socket
c = collections.Counter()
tipos = collections.Counter()
for _ in range(int(sys.argv[1])):
    try:
        c[urllib.request.urlopen('http://1.1.1.1:8000/', timeout=3).read().decode()] += 1
    except Exception as e:
        c['error'] += 1
        causa = getattr(e, 'reason', e)
        if isinstance(causa, ConnectionResetError) or 'reset' in str(causa).lower():
            tipos['reset'] += 1
        elif isinstance(causa, (socket.timeout, TimeoutError)) or 'timed out' in str(causa).lower():
            tipos['timeout'] += 1
        else:
            tipos[type(causa).__name__] += 1
print(c.get('10.1.0.2', 0), c.get('10.2.0.2', 0), c.get('error', 0))
if tipos:
    print('    tipos de error:', dict(tipos), file=sys.stderr)
EOF
}
esperar_estado() {  # esperar_estado <python-expr sobre e (estado.json)> <segundos>
  for _ in $(seq 1 "$2"); do
    python3 - "$T/run/router/estado.json" "$1" <<'EOF' && return 0
import json, sys
try: e = json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
sys.exit(0 if eval(sys.argv[2]) else 1)
EOF
    sleep 1
  done
  return 1
}
esperar_estado_estable() {  # esperar_estado_estable <expr> <ciclos_seguidos> <timeout_s>
  # Ronda 4 (e2e, fallo intermitente del paso 2): no basta con ver la
  # condición UNA vez — nada impide que, justo en ese instante, una WAN
  # entre en balanceo y salga otra vez al ciclo siguiente (calentando
  # todavía las muestras de ping). Exige verla cierta "$2" ciclos
  # SEGUIDOS antes de darla por buena; cualquier ciclo que falle reinicia
  # la cuenta desde cero.
  local expr="$1" ciclos="$2" timeout="$3" seguidos=0
  for _ in $(seq 1 "$timeout"); do
    if python3 - "$T/run/router/estado.json" "$expr" <<'EOF'
import json, sys
try: e = json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
sys.exit(0 if eval(sys.argv[2]) else 1)
EOF
    then
      seguidos=$((seguidos+1))
      [ "$seguidos" -ge "$ciclos" ] && return 0
    else
      seguidos=0
    fi
    sleep 1
  done
  return 1
}
peticion() {  # peticion <accion> <json-datos>
  id=$(python3 -c 'import uuid; print(uuid.uuid4())')
  mkdir -p $T/var/lib/router/solicitudes
  f=$T/var/lib/router/solicitudes/$id.json
  echo "{\"id\":\"$id\",\"usuario\":\"prueba\",\"accion\":\"$1\",\"datos\":$2}" > $f.tmp
  # Como el panel real: el buzón sólo acepta ficheros del usuario routerpanel
  # (si existe); con $3=root se prueba precisamente que se rechaza.
  if [ "${3:-}" != root ] && id routerpanel >/dev/null 2>&1; then chown routerpanel $f.tmp; fi
  mv $f.tmp $f
  for _ in $(seq 1 15); do [ -f $T/var/lib/router/respuestas/$id.json ] && { cat $T/var/lib/router/respuestas/$id.json; echo; return; }; sleep 1; done
  echo "sin respuesta"
}

echo "== 0. modo_pesos=manual (fase 4, C) para que los pasos clásicos de abajo usen los pesos fijos del admin, no los automáticos"
peticion modo_pesos '{"modo_pesos":"manual"}' >/dev/null
sleep 2

echo "== 1. arranque: las dos WAN con Internet y en balanceo (estable 3 ciclos seguidos)"
# Ronda 4 (e2e, fallo intermitente del paso 2): antes bastaba verlo UNA
# vez — si el paso 2 arrancaba justo cuando una WAN seguía "calentando"
# (pocas muestras de ping válidas todavía), unas pocas conexiones de las
# 200 caían antes de que esa WAN se asentara de verdad.
if esperar_estado_estable "sum(w['en_balanceo'] for w in e['wans']) == 2" 3 30; then
  ok "2 WAN en balanceo (estable 3 ciclos)"
else
  mal "no llegan a 2 WAN en balanceo de forma estable"
fi
nsx rt nft list chain inet router elegir_wan | grep -q "numgen random mod 100" && ok "mapa de pesos 50/50 instalado" || mal "sin mapa de pesos"

echo "== 2. reparto 50/50 de conexiones nuevas (200)"
read a b err <<< "$(reparto cli 200)"; echo "    tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" -ge 60 ] && [ "$b" -ge 60 ] && ok "reparto equilibrado" || mal "reparto 50/50 fuera de lo esperado"

echo "== 3. pesos 80/20 desde el buzón del panel"
WAN1=$(python3 -c "import json;print([w['id'] for w in json.load(open('$T/run/router/estado.json'))['wans'] if w['interfaz']=='wan1'][0])")
echo "    $(peticion wan_actualizar "{\"wan\":\"$WAN1\",\"peso\":80}")"
WAN2=$(python3 -c "import json;print([w['id'] for w in json.load(open('$T/run/router/estado.json'))['wans'] if w['interfaz']=='wan2'][0])")
echo "    $(peticion wan_actualizar "{\"wan\":\"$WAN2\",\"peso\":20}")"
sleep 3
read a b err <<< "$(reparto cli 200)"; echo "    tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" -ge 135 ] && [ "$b" -ge 15 ] && ok "reparto ponderado ~80/20" || mal "pesos no respetados"

echo "== 4. petición inválida rechazada (peso 0, acción desconocida)"
peticion wan_actualizar "{\"wan\":\"$WAN1\",\"peso\":0}" | grep -q '"ok": false' && ok "peso 0 rechazado" || mal "peso 0 aceptado"
peticion rm_rf "{}" | grep -q '"ok": false' && ok "acción desconocida rechazada" || mal "acción desconocida aceptada"

echo "== 4b. una petición que no es del usuario del panel se rechaza"
if id routerpanel >/dev/null 2>&1; then
  peticion modo '{"modo":"respaldo"}' root | grep -q 'propietario esperado' && ok "petición de otro usuario rechazada" || mal "se aceptó una petición ajena"
fi

echo "== 5. afinidad: una conexión keep-alive no cambia de WAN"
nsx cli python3 - <<'EOF' && ok "100 peticiones por la misma conexión, mismo teléfono" || mal "la conexión cambió de WAN"
import http.client, sys
c = http.client.HTTPConnection('1.1.1.1', 8000, timeout=3)
vistos = set()
for _ in range(100):
    c.request('GET', '/'); vistos.add(c.getresponse().read())
sys.exit(0 if len(vistos) == 1 else 1)
EOF

echo "== 6. caída de tel1 (sin salida a internet, el USB sigue «conectado»)"
nsx tel1 sysctl -qw net.ipv4.ip_forward=0   # el móvil se queda sin datos; el USB sigue conectado
if esperar_estado "[w for w in e['wans'] if w['interfaz']=='wan1'][0]['internet'] is False" 20; then ok "detectada la caída real"; else mal "no detecta la caída"; fi
sleep 2
read a b err <<< "$(reparto cli 60)"; echo "    tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" = 0 ] && [ "$b" = 60 ] && ok "todo sale por tel2, sin errores" || mal "la caída afecta a la navegación"

echo "== 7. recuperación de tel1"
nsx tel1 sysctl -qw net.ipv4.ip_forward=1   # vuelven los datos
if esperar_estado "[w for w in e['wans'] if w['interfaz']=='wan1'][0]['en_balanceo'] is True" 20; then ok "tel1 vuelve al balanceo"; else mal "tel1 no vuelve"; fi
sleep 2
read a b err <<< "$(reparto cli 100)"; echo "    tel1=$a tel2=$b errores=$err"
[ "$a" -ge 50 ] && ok "tel1 vuelve a recibir conexiones" || mal "tel1 no recibe conexiones"

echo "== 8. modo respaldo: sólo la de prioridad 1"
peticion modo '{"modo":"respaldo"}' >/dev/null; sleep 3
read a b err <<< "$(reparto cli 40)"; echo "    tel1=$a tel2=$b errores=$err"
{ [ "$a" = 40 ] || [ "$b" = 40 ]; } && ok "una sola línea principal" || mal "respaldo reparte entre líneas"
peticion modo '{"modo":"balanceo"}' >/dev/null

echo "== 9. firewall"
nsx tel1 python3 - <<'EOF' && mal "desde la WAN se llega al puerto 22 del router" || ok "WAN → router:22 bloqueado (sin respuesta)"
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(('192.168.42.17', 22)); sys.exit(0)
except ConnectionRefusedError: sys.exit(0)   # respondió: el firewall lo dejó pasar
except OSError: sys.exit(1)                  # timeout: descartado
EOF
nsx cli python3 - <<'EOF' && ok "LAN → router:22 permitido (llega y responde)" || mal "la LAN no llega a la administración"
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(('192.168.50.1', 22)); sys.exit(0)
except ConnectionRefusedError: sys.exit(0)
except OSError: sys.exit(1)
EOF
nsx cli ping -c1 -W2 192.168.42.129 >/dev/null 2>&1 && mal "la LAN llega al teléfono" || ok "LAN → teléfono bloqueado"

echo "== 10. tráfico PROPIO del router (C1): sale de rt, no de cli, con las dos WAN en balanceo"
# C1: antes, el tráfico del propio router salía con la IP origen que eligió
# la tabla main (la de la primera WAN), aunque marcar_salida lo mandara por
# la otra — y el NAT (sólo `ip saddr {red}`) no lo enmascaraba. Si el fallo
# estuviera presente, estas peticiones (hechas DESDE el netns rt, no desde
# cli) fallarían o no se repartirían entre los dos teléfonos.
read a b err <<< "$(reparto rt 50)"; echo "    (desde rt) tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" -ge 1 ] && [ "$b" -ge 1 ] && ok "tráfico propio del router: sin errores y repartido entre WAN" \
  || mal "tráfico propio del router: NAT o balanceo no funcionan (C1)"

echo "== 11. tráfico PROPIO del router con tel1 sin datos"
nsx tel1 sysctl -qw net.ipv4.ip_forward=0
if esperar_estado "[w for w in e['wans'] if w['interfaz']=='wan1'][0]['internet'] is False" 20; then ok "tel1 detectado caído (paso 11)"; else mal "no detecta la caída (paso 11)"; fi
sleep 2
read a b err <<< "$(reparto rt 20)"; echo "    (desde rt) tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" = 0 ] && [ "$b" = 20 ] && ok "tráfico propio del router sigue sin errores, todo por tel2" \
  || mal "tráfico propio del router falla con tel1 caído"
nsx tel1 sysctl -qw net.ipv4.ip_forward=1   # deja el entorno como estaba, por si se añaden más pasos

echo "== 12. fase 4 (A): latencia artificial en tel1 (300 ms) y modo_pesos=auto"
# netem delay en el egress de usb0 dentro del netns tel1: retrasa las
# respuestas que vuelven hacia rt (lo que ve routerd al medir con ping),
# simulando el caso real descrito en la tarea (TCL a ratos con 500 ms).
nsx tel1 tc qdisc add dev usb0 root netem delay 300ms
peticion modo_pesos '{"modo_pesos":"auto"}' >/dev/null
sleep 10   # varios ciclos (intervalo_s=2): que la mediana recoja el retraso y el suavizado baje el peso de tel1
read a b err <<< "$(reparto cli 200)"; echo "    tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" -lt 70 ] && ok "modo auto: tel1 (300 ms) recibe <35% del reparto" || mal "modo auto: tel1 no baja de peso pese a la latencia"
python3 - "$T/run/router/estado.json" <<'EOF'
import json, sys
e = json.load(open(sys.argv[1]))
print('    modo_pesos:', e.get('modo_pesos'))
for w in e['wans']:
    print('    %s: peso=%s peso_efectivo=%s latencia_ms=%s' %
          (w['nombre'], w.get('peso'), w.get('peso_efectivo'), w.get('latencia_ms')))
EOF

echo "== 13. fase 4 (B): 30 flujos UDP independientes salen TODOS por la WAN de menor latencia (tel2)"
# Un flujo UDP real no es un paquete suelto: aquí se abren 30 sockets
# NUEVOS (uno por flujo → cada uno con su propio puerto de origen), no 30
# paquetes del mismo socket/flujo — con uno solo el resultado podía salir
# por suerte (una sola tirada del mapa de pesos). Server de eco: igual que
# el servidor HTTP de más arriba, contesta con la IP de origen que ve (la
# del teléfono que hizo el NAT), así se sabe por qué WAN salió cada flujo.
cat > $T/udp_eco.py <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('1.1.1.1', 5000))
while True:
    datos, origen = s.recvfrom(64)
    s.sendto(origen[0].encode(), origen)
EOF
nsx inet python3 $T/udp_eco.py & PID_UDP=$!
sleep 1
udp_30_flujos() {  # udp_30_flujos <netns> → "tel1 tel2 errores" (30 sockets nuevos)
  nsx "$1" python3 - <<'EOF'
import socket, collections
c = collections.Counter()
for _ in range(30):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(b'x', ('1.1.1.1', 5000))
        c[s.recv(64).decode()] += 1
    except Exception:
        c['error'] += 1
    finally:
        s.close()
print(c.get('10.1.0.2', 0), c.get('10.2.0.2', 0), c.get('error', 0))
EOF
}
read t1 t2 err <<< "$(udp_30_flujos cli)"
echo "    30 flujos UDP nuevos: tel1=$t1 tel2=$t2 errores=$err"
[ "$err" = 0 ] && [ "$t2" = 30 ] && ok "los 30 flujos UDP nuevos salen por tel2, la de menor latencia" \
  || mal "no todos los flujos UDP nuevos salen por la WAN rápida (tel1=$t1 tel2=$t2 errores=$err)"

echo "== 13b. fase 4 (B/D): en manual 80/20 a favor de tel1 (la lenta), el UDP de tiempo real IGNORA el reparto"
# D: con modo_pesos=manual y pesos 80/20 a favor de tel1 (la que tiene los
# 300 ms de netem desde el paso 12), elegir_wan (TCP/resto) reparte según
# ESE 80/20 — pero elegir_wan_rt (UDP nuevo, tiempo real) sigue mirando
# sólo la latencia medida y manda TODO a tel2, la rápida: son cadenas
# independientes (B), y el peso manual de elegir_wan no influye en absoluto
# en elegir_wan_rt. netem en tel1 sigue activo (no se quita hasta el final
# del paso 14): si no lo estuviera, tel1 podría parecer tan buena como
# tel2 y el resultado de este paso no demostraría nada.
peticion wan_actualizar "{\"wan\":\"$WAN1\",\"peso\":80}" >/dev/null
peticion wan_actualizar "{\"wan\":\"$WAN2\",\"peso\":20}" >/dev/null
peticion modo_pesos '{"modo_pesos":"manual"}' >/dev/null
sleep 3
read t1 t2 err <<< "$(udp_30_flujos cli)"
echo "    30 flujos UDP nuevos (manual 80/20 a favor de tel1): tel1=$t1 tel2=$t2 errores=$err"
[ "$err" = 0 ] && [ "$t2" = 30 ] && ok "los 30 flujos UDP nuevos siguen saliendo TODOS por tel2 (ignoran el 80/20)" \
  || mal "el UDP de tiempo real se dejó arrastrar por el reparto manual (tel1=$t1 tel2=$t2 errores=$err)"
read a b err <<< "$(reparto cli 100)"
echo "    100 conexiones TCP (manual 80/20 a favor de tel1): tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" -ge 55 ] && [ "$b" -ge 5 ] && ok "las 100 TCP sí se reparten ~80/20 a favor de tel1 (el manual manda ahí)" \
  || mal "las conexiones TCP no respetan el 80/20 manual (tel1=$a tel2=$b errores=$err)"
kill $PID_UDP 2>/dev/null; unset PID_UDP

echo "== 14. fase 4 (A/D): modo manual con pesos 50/50 ignora la latencia real (vuelve ~50/50)"
peticion wan_actualizar "{\"wan\":\"$WAN1\",\"peso\":50}" >/dev/null
peticion wan_actualizar "{\"wan\":\"$WAN2\",\"peso\":50}" >/dev/null
peticion modo_pesos '{"modo_pesos":"manual"}' >/dev/null
sleep 3
read a b err <<< "$(reparto cli 200)"; echo "    tel1=$a tel2=$b errores=$err"
[ "$err" = 0 ] && [ "$a" -ge 60 ] && [ "$b" -ge 60 ] && ok "modo manual 50/50: reparto equilibrado pese al retraso de tel1" \
  || mal "modo manual no respeta el 50/50 del admin"
nsx tel1 tc qdisc del dev usb0 root   # quita la latencia artificial, como pide la tarea

echo "== 15. WAN Wi-Fi simulada (brcmsmac real no disponible aquí): una veth como wifi_wan.interfaz"
# No hay tarjeta Wi-Fi de verdad en este netns: se simula con un veth que
# routerd debe aceptar igual por CONFIG (wifi_wan.interfaz), aunque no sea
# wifi real — si el código depende de nmcli para el SSID, debe fallar en
# blando (telefono=null), nunca tirar el descubrimiento. AVISO: nmcli habla
# con NetworkManager por D-Bus, que NO está aislado por el netns — por eso
# se pone "gestionar_radio_wifi": false antes de activar wifi_wan, para que
# routerd NUNCA llame a `nmcli radio wifi` de verdad durante esta prueba
# (sí puede llamar a `nmcli device show` de lectura, o a `nmcli connection
# down/modify` si la guarda anti-bucle salta — ver 15b: como esta interfaz
# de pruebas no está gestionada por NM, esas llamadas simplemente fallan en
# blando, sin uuid de conexión activa que bajar). Ejecutar este paso sólo en
# la máquina de pruebas dedicada.
ip netns add tel3; nsx tel3 ip link set lo up
ip link add wifisim0 netns rt type veth peer name usb0 netns tel3
ip link add up3 netns tel3 type veth peer name p3 netns inet
nsx rt ip addr add 192.168.44.17/24 dev wifisim0; nsx rt ip link set wifisim0 up
nsx rt ip route add default via 192.168.44.129 dev wifisim0 metric 702
nsx tel3 ip addr add 192.168.44.129/24 dev usb0; nsx tel3 ip link set usb0 up
nsx tel3 ip addr add 10.3.0.2/30 dev up3; nsx tel3 ip link set up3 up
nsx tel3 ip route add default via 10.3.0.1
nsx tel3 sysctl -qw net.ipv4.ip_forward=1
nsx tel3 nft -f - <<EOF
table ip nat {
  chain post {
    type nat hook postrouting priority srcnat;
    oifname "up3" masquerade
  }
}
EOF
nsx inet ip addr add 10.3.0.1/30 dev p3; nsx inet ip link set p3 up

python3 - "$T/etc/router.json" <<'EOF'
import json, os, sys
ruta = sys.argv[1]
cfg = json.load(open(ruta))
# "interfaz" apunta a la veth de pruebas, no a wlp3s0b1 (deployment real):
# descubrir_wans() debe aceptarla igual, por config, sin mirar el driver.
cfg['wifi_wan'] = {'habilitada': True, 'interfaz': 'wifisim0', 'ssid_bloqueadas': ['MI-WIFI']}
cfg['gestionar_radio_wifi'] = False
tmp = ruta + '.tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f)
os.replace(tmp, ruta)
EOF

if esperar_estado "any(w['interfaz'] == 'wifisim0' and w['id'].startswith('wifi-') for w in e['wans'])" 20; \
  then ok "la WAN Wi-Fi simulada aparece (id wifi-*, interfaz wifisim0)"; else mal "la WAN Wi-Fi simulada no aparece"; fi
if esperar_estado "[w for w in e['wans'] if w['interfaz'] == 'wifisim0'][0]['en_balanceo'] is True" 20; \
  then ok "la WAN Wi-Fi simulada entra en el balanceo"; else mal "la WAN Wi-Fi simulada no entra en el balanceo"; fi
nsx rt nft list set inet router wan_ifs 2>/dev/null | grep -q wifisim0 && \
  ok "wifisim0 está en el set wan_ifs del firewall (NAT/forward)" || mal "wifisim0 no está en wan_ifs"
python3 - "$T/run/router/estado.json" <<'EOF'
import json, sys
e = json.load(open(sys.argv[1]))
w = [x for x in e['wans'] if x['interfaz'] == 'wifisim0'][0]
print('    wifi WAN: id=%s nombre=%s telefono=%s internet=%s en_balanceo=%s' %
      (w['id'], w['nombre'], w['telefono'], w['internet'], w['en_balanceo']))
print('    wifi:', json.dumps(e.get('wifi')))
EOF

echo "== 15b. anti-bucle: si la WAN Wi-Fi simulada recibe una IP de la LAN, queda fuera"
nsx rt ip route del default via 192.168.44.129 dev wifisim0 metric 702 2>/dev/null
nsx rt ip addr del 192.168.44.17/24 dev wifisim0
nsx rt ip addr add 192.168.50.77/24 dev wifisim0
if esperar_estado "[w for w in e['wans'] if w['interfaz'] == 'wifisim0'][0]['en_balanceo'] is False" 20; \
  then ok "con IP de la LAN, la WAN Wi-Fi simulada queda fuera del balanceo"; \
  else mal "la WAN Wi-Fi simulada con IP de la LAN sigue en el balanceo (riesgo de bucle)"; fi
grep -q '"accion": "wifi_bucle"' $T/var/log/router/operaciones.log 2>/dev/null && \
  ok "el oplog registra la guarda anti-bucle" || mal "no se registró wifi_bucle en el oplog"
nsx rt ip addr del 192.168.50.77/24 dev wifisim0 2>/dev/null   # deja el entorno limpio

echo "== 16. bloqueador DNS (HaGeZi): lista_blanca resuelve, el resto da NXDOMAIN, forzar_dns redirige hasta 8.8.8.8:53"
# bloqueo.forzar_dns/bloquear_doh van a True POR DEFECTO (CONFIG_DEFECTO) sin
# que este router.json toque "bloqueo" en absoluto: routerd ya lleva desde
# el paso 1 la cadena "redirigir_dns" y el corte de 853 instalados en «inet
# router» (nft_conf.py). Lo único que falta aquí es la propia lista de
# dominios y un dnsmasq real escuchando en lan0 que la aplique.
#
# Sin Internet real: en vez de servir la lista por HTTP, se prepara
# DIRECTAMENTE la caché que router_bloqueo.py deja en disco tras una
# descarga (mismo formato: un dominio por línea) — es la vía que pide la
# tarea ("o carga un fichero de caché preparado"). router_bloqueo.py
# intentará descargar de verdad (fallará: este netns no tiene salida a
# Internet) y caerá a esa caché, exactamente el camino de
# test_bloqueo.py::TestDescargarLista, aquí de punta a punta.
mkdir -p $T/var/lib/router/bloqueo
cat > $T/var/lib/router/bloqueo/hagezi_pro.txt <<'EOF'
bloqueado-de-prueba.test
EOF
python3 - "$T/etc/router.json" <<'EOF'
import json, os, sys
ruta = sys.argv[1]
cfg = json.load(open(ruta))
cfg['bloqueo'] = {
    'habilitado': True, 'listas': ['hagezi_pro'],
    'lista_blanca': ['permitido-de-prueba.test'], 'lista_negra': [],
    'forzar_dns': True, 'bloquear_doh': False,
    'actualizar_h': 24, 'registro_dns_dias': 30,
}
tmp = ruta + '.tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f)
os.replace(tmp, ruta)
EOF
nsx rt python3 $CORE/router_bloqueo.py --config $T/etc/router.json --raiz-datos $T > $T/bloqueo.log 2>&1
# Formato servers-file: `server=/dom/` bloquea; `server=/dom/#` es una
# excepción (lista blanca) que usa los servidores normales.
grep -qx 'server=/bloqueado-de-prueba.test/' $T/var/lib/router/bloqueo/dnsmasq-bloqueo.conf 2>/dev/null \
  && ok "dnsmasq-bloqueo.conf generado con el dominio de la lista" || mal "dnsmasq-bloqueo.conf no tiene el dominio esperado"
grep -qx 'server=/permitido-de-prueba.test/' $T/var/lib/router/bloqueo/dnsmasq-bloqueo.conf 2>/dev/null \
  && mal "el dominio de lista_blanca aparece bloqueado en la config (no se respetó)" \
  || ok "el dominio de lista_blanca NO aparece bloqueado en la config"

# dnsmasq REAL en el netns rt, escuchando sólo en lan0, con esa config —
# a mano (gestionar_dnsmasq sigue en false en este router.json: el resto
# del script nunca toca el dnsmasq real de la máquina que lo ejecuta).
# M4 (ronda 3): servers-file= (NO conf-file=, aunque el contenido sea el
# mismo: es la directiva de verdad que usa producción, la única que
# dnsmasq relee con SIGHUP) y --user=nobody (como en producción,
# --user=dnsmasq que cae de privilegios tras ligar el puerto — comprueba
# que router_bloqueo._asegurar_legible_por_dnsmasq deja los directorios
# padre con "x" para "otros" y el fichero con "r", o 'nobody' no podría
# ni abrirlo).
cat > $T/etc/dnsmasq-bloqueo-prueba.conf <<EOF
interface=lan0
bind-interfaces
no-resolv
no-hosts
servers-file=$T/var/lib/router/bloqueo/dnsmasq-bloqueo.conf
EOF
nsx rt dnsmasq -k --user=nobody --conf-file=$T/etc/dnsmasq-bloqueo-prueba.conf \
  --pid-file=$T/dnsmasq-prueba.pid --log-facility=$T/dnsmasq-prueba.log & PID_DNSMASQ=$!
sleep 1

consulta_dns() {  # consulta_dns <servidor> <dominio> → "respondido <rcode>" | "sin_respuesta ..."
  nsx cli python3 - "$1" "$2" <<'EOF'
import socket, struct, sys, random
servidor, dominio = sys.argv[1], sys.argv[2]
qid = random.randint(0, 65535)
cabecera = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
pregunta = b''.join(struct.pack('B', len(e)) + e.encode() for e in dominio.split('.')) + b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(cabecera + pregunta, (servidor, 53))
    datos, origen = s.recvfrom(512)
    print('respondido', datos[3] & 0x0f, origen[0])
except Exception as e:
    print('sin_respuesta', e)
EOF
}

salida=$(consulta_dns 192.168.50.1 bloqueado-de-prueba.test); echo "    $salida"
echo "$salida" | grep -q '^respondido 3 ' && ok "dominio de la lista resuelve NXDOMAIN (rc=3) directo al router" \
  || mal "dominio de la lista no da NXDOMAIN consultando al router ($salida)"
salida=$(consulta_dns 192.168.50.1 permitido-de-prueba.test); echo "    $salida"
echo "$salida" | grep -q '^respondido 3 ' && mal "dominio de lista_blanca también da NXDOMAIN ($salida)" \
  || ok "dominio de lista_blanca NO da NXDOMAIN ($salida)"

echo "== 16a. servers-file + SIGHUP: cambiar lista_blanca SIN reiniciar dnsmasq, comprobado por DNS"
# M4: la señal de verdad que usa router_bloqueo._validar_y_activar es
# `systemctl kill -s HUP dnsmasq` — pero esto corre con gestionar_dnsmasq
# en false (netns), así que ese paso se omite a propósito (routerd NUNCA
# debe tocar el dnsmasq de sistema real durante esta prueba). Lo que SÍ se
# comprueba aquí, con un SIGHUP de verdad al dnsmasq de prueba que
# arrancamos arriba, es el mecanismo que importa: que dnsmasq con
# --user=nobody relee servers-file con SIGHUP y aplica el cambio SIN
# reiniciar (mismo PID antes y después).
pid_antes=$(cat $T/dnsmasq-prueba.pid 2>/dev/null)
python3 - "$T/etc/router.json" <<'EOF'
import json, os, sys
ruta = sys.argv[1]
cfg = json.load(open(ruta))
# "bloqueado-de-prueba.test" (antes bloqueado) pasa a lista_blanca: debe
# empezar a resolver SIN reiniciar dnsmasq.
cfg['bloqueo']['lista_blanca'] = ['permitido-de-prueba.test', 'bloqueado-de-prueba.test']
tmp = ruta + '.tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f)
os.replace(tmp, ruta)
EOF
nsx rt python3 $CORE/router_bloqueo.py --config $T/etc/router.json --raiz-datos $T >> $T/bloqueo.log 2>&1
grep -qx 'server=/bloqueado-de-prueba.test/#' $T/var/lib/router/bloqueo/dnsmasq-bloqueo.conf 2>/dev/null \
  && ok "servers-file regenerado con la excepción nueva (server=/.../#)" \
  || mal "el servers-file no tiene la excepción nueva esperada"
# El SIGHUP de verdad (gestionar_dnsmasq=false se lo salta dentro de
# router_bloqueo; aquí se manda a mano al proceso de prueba).
# $PID_DNSMASQ es el del lanzador (ip netns exec); dnsmasq se demoniza y
# deja su pid real en el pid-file: la señal va a ese.
kill -HUP "$pid_antes" 2>/dev/null
sleep 1
pid_despues=$(cat $T/dnsmasq-prueba.pid 2>/dev/null)
[ "$pid_antes" = "$pid_despues" ] && [ -n "$pid_antes" ] && \
  ok "dnsmasq sigue siendo el mismo proceso tras el SIGHUP (pid=$pid_antes, nunca se reinició)" \
  || mal "el pid de dnsmasq cambió tras el SIGHUP (pid_antes=$pid_antes pid_despues=$pid_despues)"
salida=$(consulta_dns 192.168.50.1 bloqueado-de-prueba.test); echo "    $salida"
# Sin upstream real configurado en este dnsmasq de prueba (no-resolv, sin
# server=), "usa los servidores normales" no puede devolver una respuesta
# de verdad — pero YA NO debe dar NXDOMAIN (rc=3): ese es el cambio que
# demuestra que el SIGHUP recogió la excepción nueva sin reiniciar.
echo "$salida" | grep -q '^respondido 3 ' && mal "el dominio recién puesto en lista_blanca sigue dando NXDOMAIN ($salida)" \
  || ok "el dominio recién puesto en lista_blanca ya NO da NXDOMAIN tras el SIGHUP, sin reiniciar dnsmasq ($salida)"

echo "== 16b. forzar_dns: una consulta de cli a 8.8.8.8:53 (NO al router) la responde igualmente el router"
# 8.8.8.8 existe en el netns "inet" (paso 0, `ip addr add 8.8.8.8/32 dev lo`)
# pero ahí no escucha nada en :53 — sin la cadena "redirigir_dns" (ya
# instalada por defecto desde el paso 1) esta consulta llegaría a "inet" y
# se quedaría sin respuesta. Si SÍ hay respuesta, forzar_dns funciona.
salida=$(consulta_dns 8.8.8.8 bloqueado-de-prueba.test); echo "    $salida"
echo "$salida" | grep -q '^respondido' && ok "consulta a 8.8.8.8:53 respondida (forzar_dns la redirigió al router)" \
  || mal "consulta a 8.8.8.8:53 sin respuesta (forzar_dns no está redirigiendo)"

echo "== 16c. bloquear_doh: DoT (853) desde la LAN hacia las WAN se rechaza con reset inmediato, no con un cuelgue"
# 1.1.1.1 (no es un wan_gw, a diferencia de 192.168.42.129/192.168.43.1: si
# se usara una de esas direcciones, la regla "LAN -> wan_gws drop" —ya
# existente, ajena a bloquear_doh— actuaría primero y el resultado no
# demostraría nada de la regla nueva en concreto) no tiene nada escuchando
# en :853 en el netns "inet" — sin la regla de bloquear_doh esto sería un
# cuelgue (timeout) hasta agotar el plazo; CON ella, un reset inmediato.
nsx cli python3 - <<'EOF' && ok "LAN -> 1.1.1.1:853 rechazado al instante (reset), no colgado" \
  || mal "LAN -> 1.1.1.1:853 no se rechazó como se esperaba (bloquear_doh)"
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('1.1.1.1', 853))
    sys.exit(1)   # conectó: no debería, no hay nada escuchando ni debería dejarse pasar
except ConnectionRefusedError:
    sys.exit(0)   # reset inmediato: exactamente lo esperado
except OSError:
    sys.exit(1)   # timeout: NO es lo esperado (debe rechazarse al instante)
EOF

echo "== 16d. forzar_dns: una consulta DNS del PROPIO router (no de la LAN) a 1.1.1.1:53 NO se redirige a sí mismo"
# redirigir_dns sólo mira "iifname LAN" (tráfico que ENTRA por la LAN): el
# tráfico que SALE del propio router (marcar_salida/nat_salida, igual que
# el paso 10/C1) nunca pasa por esa cadena de prerouting. Se demuestra con
# un eco en 1.1.1.1:53 dentro de "inet": si la consulta del propio router
# (netns rt, no cli) LLEGA de verdad hasta ahí (y vuelve con la IP NATeada
# de la WAN que tocara, como en el paso 10), forzar_dns no se la ha
# comido por error.
cat > $T/dns_eco.py <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('1.1.1.1', 53))
while True:
    datos, origen = s.recvfrom(64)
    s.sendto(origen[0].encode(), origen)
EOF
nsx inet python3 $T/dns_eco.py & PID_DNS_ECO=$!
sleep 1
salida=$(nsx rt python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b'x', ('1.1.1.1', 53))
    datos, origen = s.recvfrom(64)
    print(datos.decode())
except Exception as e:
    print('sin_respuesta', e)
EOF
)
echo "    $salida"
echo "$salida" | grep -qE '^10\.[12]\.0\.2$' \
  && ok "la consulta DNS del propio router llegó de verdad a 1.1.1.1 (forzar_dns no la redirigió a sí mismo)" \
  || mal "la consulta DNS del propio router no llegó a 1.1.1.1 como se esperaba ($salida)"
kill $PID_DNS_ECO 2>/dev/null; unset PID_DNS_ECO

echo "== 17. contabilidad de tráfico por dispositivo (disp_sube/disp_baja, core/nft_conf.py)"
# Un poco de tráfico fresco de cli (ya hay de sobra de los pasos 2/3/5/etc.,
# pero esto deja claro que SIGUE acumulando, no sólo que haya algo de la
# primera vez). Esta es LA prueba que de verdad importa para disp_sube/
# disp_baja: una tabla real cargada con root. Un diseño anterior (`map
# disp_sube { type ipv4_addr : counter; ... }`) pasaba `nft -c` sin ningún
# error pero el KERNEL lo rechazaba al cargar ("Operation not supported") —
# `nft -c` no lo detecta, sólo analiza sintaxis; esto de aquí sí lo habría
# pillado. disp_sube/disp_baja son `set` (el contador se añade en la
# EXPRESIÓN del "update", "ip saddr counter" — ver la nota larga en
# nft_conf.py): se leen con "list set".
read _a _b _err <<< "$(reparto cli 5)"
salida_sube=$(nsx rt nft list set inet router disp_sube)
salida_baja=$(nsx rt nft list set inet router disp_baja)
echo "    disp_sube: $(echo "$salida_sube" | grep -o '192\.168\.50\.100 counter[^,}]*' || echo '(sin entrada)')"
echo "    disp_baja: $(echo "$salida_baja" | grep -o '192\.168\.50\.100 counter[^,}]*' || echo '(sin entrada)')"
echo "$salida_sube" | grep -q '192\.168\.50\.100 counter packets [1-9]' \
  && ok "disp_sube tiene contador > 0 para cli (192.168.50.100, subida)" \
  || mal "disp_sube sin contador para cli"
echo "$salida_baja" | grep -q '192\.168\.50\.100 counter packets [1-9]' \
  && ok "disp_baja tiene contador > 0 para cli (192.168.50.100, bajada)" \
  || mal "disp_baja sin contador para cli"

echo "== 17b. router_estadisticas.py --una-vez DOS VECES contra la tabla real (BAJA16, revisión Opus)"
# --raiz-datos (igual que routerd.py): prefija estado/leases/dns-log/db a
# $T, pero --config queda explícito (mismo patrón que routerd más arriba).
# nft-bin/tabla-nft/conntrack-count/conntrack-tabla usan sus rutas REALES
# (el propio "nft" del PATH, y /proc dentro de ESTE netns "rt" — no son
# datos de fichero de este programa, nunca se prefijan).
nsx rt python3 $CORE/router_estadisticas.py --config $T/etc/router.json --raiz-datos $T --una-vez \
  >> $T/estadisticas.log 2>&1
echo "    primera pasada: línea base (sin fila todavía, o con el acumulado ya existente de pasos anteriores)"
read _a _b _err <<< "$(reparto cli 5)"   # tráfico FRESCO entre las dos pasadas
nsx rt python3 $CORE/router_estadisticas.py --config $T/etc/router.json --raiz-datos $T --una-vez \
  >> $T/estadisticas.log 2>&1
echo "    segunda pasada: debe ver un delta > 0 en trafico_disp para cli"
fila=$(python3 -c "
import sqlite3
conn = sqlite3.connect('$T/var/lib/router/estadisticas/estadisticas.db')
print(conn.execute(\"SELECT bajada_bytes, subida_bytes FROM trafico_disp \"
                    \"WHERE ip='192.168.50.100' ORDER BY ts DESC LIMIT 1\").fetchall())
" 2>&1)
echo "    trafico_disp (bajada_bytes, subida_bytes) para cli: $fila"
echo "$fila" | grep -qE '\([1-9][0-9]*, [1-9][0-9]*\)' \
  && ok "router_estadisticas.py --una-vez (dos pasadas, tabla real con root) registró bajada/subida > 0 para cli" \
  || mal "router_estadisticas.py no registró tráfico real para cli en trafico_disp ($fila)"
echo "    registro de router_estadisticas.py (últimas líneas)"; tail -5 $T/estadisticas.log | sed 's/^/        /'

echo "== 18. firewall con reglas propias (FIREWALL_PLAN.md): bloquear, rechazar, registrar e icmp"
# Escenario del plan y HIGH-4 (revisión Opus 2026-10-12): la conexión se abre
# ANTES de la petición y debe morir después de que routerd aplique la regla;
# un segundo cliente LAN queda intacto; firewall_error null; los casos icmp,
# rechazar + tcp_udp y registrar habrían cazado HIGH-1 y HIGH-2. Cada
# petición se comprueba por su respuesta «ok». Las versiones se leen del
# estado, nunca se fijan a mano.

# Lee la versión actual del firewall desde estado.json (HIGH-4: sin versiones fijas).
fw_version() {
  python3 -c "
import json
e = json.load(open('$T/run/router/estado.json'))
print(e.get('config', {}).get('firewall', {}).get('version', 1))
" 2>/dev/null || echo 1
}

# Comprueba que la respuesta de peticion tiene ok=true; si no, registra fallo.
peticion_ok() {  # peticion_ok <accion> <json-datos> <descripcion>
  local resp
  resp=$(peticion "$1" "$2")
  echo "    $resp"
  echo "$resp" | grep -q '"ok": true' && ok "$3" || mal "$3 (respuesta: $resp)"
}

# Espera a que routerd INSTALE de verdad N reglas de usuario en la tabla
# (la petición se guarda en un ciclo y nft se reinstala en el siguiente:
# firewall_error ya era null antes, así que no sirve como señal).
esperar_reglas() {  # esperar_reglas <n> <descripcion>
  local n=0
  for _ in $(seq 1 30); do
    n=$(nsx rt nft list chain inet router reenvio 2>/dev/null | grep -o 'fw:r_[0-9a-f]*' | sort -u | wc -l)
    [ "$n" -ge "$1" ] && { ok "$2 ($n reglas instaladas)"; return 0; }
    sleep 0.5
  done
  mal "$2: sólo $n de $1 reglas instaladas tras 15 s"; return 1
}

# — 18a. conexión establecida ANTES de la regla; debe morir al aplicarse —
echo "-- 18a. conexión establecida previa muere al aplicar la regla bloquear"
# Keep-alive desde cli (192.168.50.100) hacia 1.1.1.1:8000. Se abre ANTES
# de la petición (HIGH-4: el paso 18c viejo la abría cuando la regla ya
# estaba, y el connect nunca se establecía). Escribe $T/keepalive.estado:
#   listo = conexión establecida; muerto = la conexión se cayó.
rm -f $T/keepalive.estado
nsx cli python3 - "$T/keepalive.estado" <<'EOF' &
import socket, time, sys
ruta = sys.argv[1]
s = socket.socket(); s.settimeout(20)
try:
    s.connect(('1.1.1.1', 8000))
except Exception:
    open(ruta, 'w').write('error')
    sys.exit(1)
open(ruta, 'w').write('listo')
try:
    while True:
        s.send(b'x')
        time.sleep(0.5)
except Exception:
    open(ruta, 'w').write('muerto')
    sys.exit(1)
EOF
PID_KEEP=$!
# Espera a que la conexión esté de verdad establecida
for _ in $(seq 1 15); do
  [ "$(cat $T/keepalive.estado 2>/dev/null)" = listo ] && break
  sleep 0.5
done
if [ "$(cat $T/keepalive.estado 2>/dev/null)" = listo ]; then
  ok "conexión previa establecida (cli → 1.1.1.1:8000)"
else
  mal "no se pudo abrir la conexión previa ($(cat $T/keepalive.estado 2>/dev/null))"
fi

V=$(fw_version)
peticion_ok fw_regla_guardar "{\"version\":$V,\"regla\":{\"nombre\":\"Bloquear 8000 cli\",\"habilitada\":true,\"accion\":\"bloquear\",\"origen\":{\"tipo\":\"ip\",\"valor\":\"192.168.50.100\"},\"destino\":{\"tipo\":\"ip\",\"valor\":\"1.1.1.1\"},\"protocolo\":\"tcp\",\"puertos\":[{\"desde\":8000,\"hasta\":8000}],\"registrar\":true,\"comentario\":\"paso 18a\"}}" \
  "petición fw_regla_guardar bloquear aceptada"

# Espera a que routerd la aplique (firewall_error null y la regla en la config)
esperar_estado "e.get('config',{}).get('firewall',{}).get('firewall_error') is None" 15 \
  && ok "firewall_error null tras aplicar" \
  || mal "firewall_error no es null: $(python3 -c "import json;e=json.load(open('$T/run/router/estado.json'));print(e.get('config',{}).get('firewall',{}).get('firewall_error'))")"
esperar_reglas 1 "regla bloquear instalada en nft"
sleep 2
# Con «drop» el cliente no se entera en segundos (TCP reintenta en silencio
# minutos), así que la prueba de verdad es conntrack: routerd borró la
# entrada ESTABLISHED tras instalar la regla y, como el keep-alive sigue
# mandando, cualquier paquete nuevo cae en la regla y ya no vuelve a
# crearse una conexión establecida.
vivas=$(nsx rt conntrack -L -p tcp -s 192.168.50.100 -d 1.1.1.1 --dport 8000 2>/dev/null | grep -c ESTABLISHED)
[ "${vivas:-0}" = 0 ] \
  && ok "conexión establecida previa cortada (sin entrada ESTABLISHED en conntrack, el keep-alive sigue intentando)" \
  || mal "la conexión establecida previa sigue viva tras aplicar la regla ($vivas entradas ESTABLISHED)"
kill $PID_KEEP 2>/dev/null; wait $PID_KEEP 2>/dev/null

# Conexión NUEVA de cli a 1.1.1.1:8000 debe cortarse.
nsx cli python3 - <<'EOF' && mal "cli → 1.1.1.1:8000 sigue conectando (la regla bloquear no actúa)" || ok "cli → 1.1.1.1:8000 cortado por la regla bloquear"
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('1.1.1.1', 8000)); sys.exit(0)
except ConnectionRefusedError: sys.exit(0)
except OSError: sys.exit(1)
EOF

# — 18b. segundo cliente LAN intacto (HIGH-4: antes medía tráfico del router) —
echo "-- 18b. segundo cliente LAN (192.168.50.101) intacto"
nsx cli2 python3 - <<'EOF' && ok "segundo cliente (192.168.50.101) intacto: la regla no le afecta" || mal "el segundo cliente también se cortó"
import socket, sys
s = socket.socket(); s.settimeout(5)
try:
    s.connect(('1.1.1.1', 8000))
    s.send(b'GET / HTTP/1.0\r\n\r\n')
    s.recv(1)
    sys.exit(0)
except OSError:
    sys.exit(1)
EOF

# — 18c. contador de la regla > 0 (la columna «Hits» de Kerio) —
echo "-- 18c. contador de la regla > 0"
aciertos=$(python3 -c "
import json, sys
e = json.load(open('$T/run/router/estado.json'))
print(json.dumps(e.get('config', {}).get('firewall', {}).get('firewall_aciertos', {})))
" 2>/dev/null || echo '{}')
echo "    firewall_aciertos: $aciertos"
echo "$aciertos" | grep -qE '"r_[0-9a-f]{8}":\s*[1-9]' \
  && ok "contador de la regla > 0 en firewall_aciertos" \
  || mal "contador de la regla en 0 o ausente ($aciertos)"

# — 18d. caso icmp (HIGH-1: habría cazado «ipv4-icmp») —
echo "-- 18d. regla icmp se instala sin romper el firewall"
V=$(fw_version)
peticion_ok fw_regla_guardar "{\"version\":$V,\"regla\":{\"nombre\":\"Bloquear icmp cli\",\"habilitada\":true,\"accion\":\"bloquear\",\"origen\":{\"tipo\":\"ip\",\"valor\":\"192.168.50.100\"},\"destino\":{\"tipo\":\"cualquiera\"},\"protocolo\":\"icmp\",\"puertos\":[],\"registrar\":false,\"comentario\":\"paso 18d\"}}" \
  "petición fw_regla_guardar icmp aceptada"
esperar_estado "e.get('config',{}).get('firewall',{}).get('firewall_error') is None" 15 \
  && ok "firewall_error null tras regla icmp (HIGH-1)" \
  || mal "firewall_error no es null tras regla icmp"
esperar_reglas 2 "regla icmp instalada en nft"
nsx cli ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 \
  && mal "cli → ping sigue funcionando (la regla icmp no actúa)" \
  || ok "cli → ping cortado por la regla icmp"
nsx cli2 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 \
  && ok "segundo cliente → ping intacto" \
  || mal "el segundo cliente también perdió el ping"

# — 18e. caso rechazar + tcp_udp (HIGH-2: habría cazado el conjunto {tcp,udp}) —
echo "-- 18e. regla rechazar + tcp_udp se instala sin romper el firewall"
V=$(fw_version)
peticion_ok fw_regla_guardar "{\"version\":$V,\"regla\":{\"nombre\":\"Rechazar 8000 cli2\",\"habilitada\":true,\"accion\":\"rechazar\",\"origen\":{\"tipo\":\"ip\",\"valor\":\"192.168.50.101\"},\"destino\":{\"tipo\":\"ip\",\"valor\":\"1.1.1.1\"},\"protocolo\":\"tcp_udp\",\"puertos\":[{\"desde\":8000,\"hasta\":8000}],\"registrar\":false,\"comentario\":\"paso 18e\"}}" \
  "petición fw_regla_guardar rechazar tcp_udp aceptada"
esperar_estado "e.get('config',{}).get('firewall',{}).get('firewall_error') is None" 15 \
  && ok "firewall_error null tras rechazar tcp_udp (HIGH-2)" \
  || mal "firewall_error no es null tras rechazar tcp_udp"
esperar_reglas 3 "regla rechazar tcp_udp instalada en nft"
# cli2 → 1.1.1.1:8000 debe rechazarse (reset o icmpx, no timeout)
nsx cli2 python3 - <<'EOF' && ok "cli2 → 1.1.1.1:8000 rechazado (respuesta de rechazo)" || mal "cli2 → 1.1.1.1:8000 no se rechazó"
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('1.1.1.1', 8000)); sys.exit(1)
except ConnectionRefusedError: sys.exit(0)   # rechazo activo
except OSError: sys.exit(0)                    # reset / icmpx
EOF

# — 18f. caso registrar (log en línea propia, sin romper la regla) —
echo "-- 18f. regla con registrar (log) se instala sin romper el firewall"
V=$(fw_version)
peticion_ok fw_regla_guardar "{\"version\":$V,\"regla\":{\"nombre\":\"Bloquear 8000 registrar\",\"habilitada\":true,\"accion\":\"bloquear\",\"origen\":{\"tipo\":\"ip\",\"valor\":\"192.168.50.100\"},\"destino\":{\"tipo\":\"ip\",\"valor\":\"1.1.1.1\"},\"protocolo\":\"tcp\",\"puertos\":[{\"desde\":8000,\"hasta\":8000}],\"registrar\":true,\"comentario\":\"paso 18f\"},\"posicion\":0}" \
  "petición fw_regla_guardar con registrar aceptada"
esperar_estado "e.get('config',{}).get('firewall',{}).get('firewall_error') is None" 15 \
  && ok "firewall_error null tras regla con registrar" \
  || mal "firewall_error no es null tras regla con registrar"
esperar_reglas 4 "regla con registrar instalada en nft"

# — 18g. permitir por encima de un bloquear: la primera que casa gana —
echo "-- 18g. permitir por encima de un bloquear"
V=$(fw_version)
peticion_ok fw_regla_guardar "{\"version\":$V,\"regla\":{\"nombre\":\"Permitir 8000 cli\",\"habilitada\":true,\"accion\":\"permitir\",\"origen\":{\"tipo\":\"ip\",\"valor\":\"192.168.50.100\"},\"destino\":{\"tipo\":\"ip\",\"valor\":\"1.1.1.1\"},\"protocolo\":\"tcp\",\"puertos\":[{\"desde\":8000,\"hasta\":8000}],\"registrar\":false,\"comentario\":\"paso 18g\"},\"posicion\":0}" \
  "petición fw_regla_guardar permitir aceptada"
esperar_reglas 5 "regla permitir instalada en nft"
nsx cli python3 - <<'EOF' && ok "permitir por encima de un bloquear: la primera que casa gana" \
  || mal "la regla permitir no respetó el orden (sigue bloqueado)"
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('1.1.1.1', 8000)); sys.exit(0)
except ConnectionRefusedError: sys.exit(0)
except OSError: sys.exit(1)
EOF

# — 18h. grupo destino público + varios puertos: routerd no debe tardar —
echo "-- 18h. grupo destino público y varios puertos: el ciclo de routerd sigue siendo corto"
V=$(fw_version)
# Grupo ip con miembros PÚBLICOS usado como destino (MEDIUM-A): debe admitirse.
peticion_ok fw_grupo_guardar "{\"version\":$V,\"grupo\":{\"nombre\":\"DNS públicos\",\"tipo\":\"ip\",\"miembros\":[\"8.8.8.8\",\"1.1.1.1\"]}}" \
  "petición fw_grupo_guardar con miembros públicos aceptada"
GID=$(python3 -c "
import json
e = json.load(open('$T/run/router/estado.json'))
gs = e.get('config', {}).get('firewall', {}).get('grupos', [])
print(gs[-1]['id'] if gs else '')
" 2>/dev/null || echo '')
if [ -n "$GID" ]; then
  V=$(fw_version)
  # Regla bloquear hacia ese grupo destino público con varios rangos de puerto.
  peticion_ok fw_regla_guardar "{\"version\":$V,\"regla\":{\"nombre\":\"Bloquear DNS públicos\",\"habilitada\":true,\"accion\":\"bloquear\",\"origen\":{\"tipo\":\"ip\",\"valor\":\"192.168.50.100\"},\"destino\":{\"tipo\":\"grupo\",\"valor\":\"$GID\"},\"protocolo\":\"tcp_udp\",\"puertos\":[{\"desde\":53,\"hasta\":53},{\"desde\":443,\"hasta\":443},{\"desde\":8000,\"hasta\":8010}],\"registrar\":false,\"comentario\":\"paso 18h\"}}" \
    "petición fw_regla_guardar con grupo destino público y varios puertos aceptada"
  esperar_estado "e.get('config',{}).get('firewall',{}).get('firewall_error') is None" 15 \
    && ok "firewall_error null tras grupo destino público + varios puertos" \
    || mal "firewall_error no es null tras grupo destino público + varios puertos"
  esperar_reglas 6 "regla con grupo destino público instalada en nft"
else
  mal "no se pudo leer la id del grupo destino público"
fi
# El tiempo de ciclo de routerd debe seguir siendo corto (HIGH-A: el vaciado
# de conntrack agrupado no debe acercarse al watchdog de 60 s).
sleep 3
ciclo_s=$(grep -oE 'ciclo completado en [0-9.]+s' $T/routerd.log | tail -1 | grep -oE '[0-9.]+' || echo '')
if [ -n "$ciclo_s" ]; then
  echo "    último ciclo de routerd: ${ciclo_s}s"
  python3 -c "import sys; sys.exit(0 if float('$ciclo_s') < 10.0 else 1)" \
    && ok "ciclo de routerd corto (${ciclo_s}s < 10 s)" \
    || mal "ciclo de routerd demasiado largo (${ciclo_s}s)"
else
  mal "no se encontró el tiempo de ciclo en el log de routerd"
fi

echo "== registro de routerd (últimas líneas)"; tail -5 $T/routerd.log | sed 's/^/    /'
echo; [ $FALLOS = 0 ] && echo "RESULTADO: TODO OK" || echo "RESULTADO: $FALLOS FALLOS"
exit $FALLOS
