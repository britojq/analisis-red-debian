#!/bin/bash

#################################################
#   MIT License
#
#   Copyright (c) 2025 Jose A. Brito H. britojab.com
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
#################################################
# Script avanzado de análisis de red para Debian
# Fecha: 2025-10-31
#################################################

if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
    SUDO_USER="$USER"
fi

REPORT_DIR="$USER_HOME/reporte_red"
mkdir -p "$REPORT_DIR"

TMP_DIR="/tmp/red_analisis_$$"
HTML_REPORT="$REPORT_DIR/reporte_$(date +%Y%m%d_%H%M).html"
TXT_REPORT="$REPORT_DIR/reporte_$(date +%Y%m%d_%H%M).txt"
PCAP_FILE="$REPORT_DIR/captura_$(date +%Y%m%d_%H%M).pcap"
LOG_FILE="$REPORT_DIR/historial.log"
OUI_FILE="$REPORT_DIR/oui.txt"

mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    chown "$SUDO_USER:" "$LOG_FILE" 2>/dev/null
}

if [[ $EUID -ne 0 ]]; then
    error "Ejecuta con sudo."
    exit 1
fi

# --- Detección de interfaz ---
INTERFACE=""
info "Buscando interfaz de red activa con IP IPv4..."

while IFS= read -r iface; do
    if [[ -n "$iface" ]] && [[ "$iface" != "lo" ]]; then
        if ip -4 addr show dev "$iface" 2>/dev/null | grep -q "inet "; then
            INTERFACE="$iface"
            break
        fi
    fi
done < <(ip -br link show up 2>/dev/null | awk '{print $1}')

if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
fi

if [ -z "$INTERFACE" ]; then
    error "❌ No se encontró interfaz de red activa con IP."
    echo "Interfaces disponibles (UP):"
    ip -br link show up 2>/dev/null | grep -v lo || echo "Ninguna"
    echo ""
    echo "Interfaces con IP IPv4:"
    ip -4 addr show 2>/dev/null | awk '/^[0-9]+:/ { iface=$2; gsub(/:/, "", iface) } /inet / { print iface }' | grep -v lo || echo "Ninguna"
    exit 1
fi

info "✅ Interfaz seleccionada: $INTERFACE"

IPV4_NET=$(ip -4 route show dev "$INTERFACE" scope global 2>/dev/null | awk '{print $1}' | head -n1)
IPV6_NET=$(ip -6 route show dev "$INTERFACE" 2>/dev/null | grep -v default | awk '{print $1}' | head -n1)

WHITELIST="$REPORT_DIR/mac_whitelist.txt"
if [[ ! -f "$WHITELIST" ]]; then
    cat > "$WHITELIST" <<EOF
# Lista blanca de direcciones MAC (una por línea)
# Ejemplo:
# 00:11:22:33:44:55
EOF
    chown "$SUDO_USER:" "$WHITELIST"
fi

mapfile -t KNOWN_MACS < <(grep -E '^[0-9a-fA-F:]{17}$' "$WHITELIST")

# --- Descargar OUI ---
if [[ ! -f "$OUI_FILE" ]]; then
    info "Descargando base de OUI (fabricantes de MAC)..."
    if command -v curl &> /dev/null; then
        curl -s "https://www.wireshark.org/download/automated/data/manuf" | \
        awk -F'\t' 'NF>=2 && /^[0-9A-F]{6}/ {print tolower($1) "\t" $2}' > "$OUI_FILE"
    else
        echo "# Base OUI no disponible (instala curl)" > "$OUI_FILE"
    fi
    chown "$SUDO_USER:" "$OUI_FILE"
fi

get_hostname() {
    local ip="$1"
    local hn=""
    if command -v dig &> /dev/null; then
        hn=$(dig +short -x "$ip" 2>/dev/null | head -n1 | sed 's/\.$//')
    elif command -v nslookup &> /dev/null; then
        hn=$(nslookup "$ip" 2>/dev/null | awk '/name =/ {print $4}' | head -n1 | sed 's/\.$//')
    fi
    if [[ -z "$hn" ]]; then
        mac="${DEVICE_MAC[$ip]}"
        if [[ -n "$mac" ]]; then
            oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:upper:]' '[:lower:]' | tr -d ':')
            if [[ ${#oui} -eq 6 ]]; then
                vendor=$(grep "^$oui" "$OUI_FILE" | cut -f2 | head -n1)
                if [[ -n "$vendor" ]]; then
                    echo "$vendor"
                    return
                fi
            fi
        fi
        echo "desconocido"
    else
        echo "$hn"
    fi
}

declare -A DEVICE_MAC
declare -A DEVICE_RX
declare -A DEVICE_TX
declare -A DEVICE_ISSUES
declare -A SUSPICIOUS_DEVICES

# --- Captura ---
info "Iniciando captura en '$INTERFACE' (120s). Capturando tráfico en la red."
tcpdump -i "$INTERFACE" -s 0 -w "$PCAP_FILE" -nn -p > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 120
kill "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null
sync
chown "$SUDO_USER:" "$PCAP_FILE" 2>/dev/null

if [[ ! -s "$PCAP_FILE" ]]; then
    error "Captura vacía."
    exit 1
fi

PKT_COUNT=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l)
log "Paquetes: $PKT_COUNT"
info "✅ Captura finalizada. Paquetes: $PKT_COUNT"

if ! command -v tshark &> /dev/null; then
    error "Instala tshark: sudo apt install tshark"
    exit 1
fi

# --- Análisis de trafico IPv4 ---
if [ -n "$IPV4_NET" ]; then
    arp-scan --interface="$INTERFACE" --localnet --ignoredups > "$TMP_DIR/arp4.txt" 2>/dev/null
    nmap -sn "$IPV4_NET" -oN "$TMP_DIR/nmap4.txt" >/dev/null 2>&1

    while IFS= read -r line; do
        if [[ $line =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            ip=$(echo "$line" | awk '{print $1}')
            mac=$(echo "$line" | awk '{print $2}')
            DEVICE_MAC["$ip"]="$mac"
        fi
    done < "$TMP_DIR/arp4.txt"

    while IFS= read -r ip; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            avg_line=$(ping -c 3 -W 1 "$ip" 2>/dev/null | tail -1)
            if [[ "$avg_line" == *"="* ]] && [[ "$avg_line" == *"/"* ]]; then
                avg_raw=$(echo "$avg_line" | awk -F'[=/]' '{
                    for(i=1;i<=NF;i++) {
                        if($i ~ /^[0-9]+\.?[0-9]*$/) {
                            print $i;
                            exit;
                        }
                    }
                }')
                if [[ -n "$avg_raw" ]]; then
                    avg_int=${avg_raw%.*}
                    avg_int=${avg_int:-0}
                    echo "$ip (IPv4): $avg_raw ms" >> "$TMP_DIR/latencia.txt"
                    if (( avg_int > 150 )); then
                        DEVICE_ISSUES["$ip"]="Alta latencia ($avg_raw ms)"
                    fi
                fi
            fi
        fi
    done < <(grep "Nmap scan report" "$TMP_DIR/nmap4.txt" | awk '{print $NF}' | tr -d '()')

    for ip in "${!DEVICE_MAC[@]}"; do
        mac="${DEVICE_MAC[$ip]}"
        is_known=false
        for known in "${KNOWN_MACS[@]}"; do
            if [[ "${known,,}" == "${mac,,}" ]]; then
                is_known=true
                break
            fi
        done
        if [[ "$is_known" == false ]]; then
            if [[ -n "${DEVICE_ISSUES[$ip]}" ]]; then
                DEVICE_ISSUES["$ip"]+="; Dispositivo no autorizado"
            else
                DEVICE_ISSUES["$ip"]="Dispositivo no autorizado"
            fi
        fi
    done
fi

# --- Análisis de trafico IPv6 ---
if [ -n "$IPV6_NET" ]; then
    ip -6 neigh show dev "$INTERFACE" > "$TMP_DIR/ndp6.txt" 2>/dev/null

    while IFS= read -r line; do
        set -- $line
        ip=$1
        mac=$5
        if [[ -n "$ip" && -n "$mac" && "$mac" != "REACHABLE" ]]; then
            DEVICE_MAC["$ip"]="$mac"
        fi
    done < "$TMP_DIR/ndp6.txt"

    while IFS= read -r ip; do
        if [[ "$ip" == *":"* ]] && [[ -n "$ip" ]]; then
            avg_line=$(ping -6 -c 3 -W 1 "$ip" 2>/dev/null | tail -1)
            if [[ "$avg_line" == *"="* ]] && [[ "$avg_line" == *"/"* ]]; then
                avg_raw=$(echo "$avg_line" | awk -F'[=/]' '{
                    for(i=1;i<=NF;i++) {
                        if($i ~ /^[0-9]+\.?[0-9]*$/) {
                            print $i;
                            exit;
                        }
                    }
                }')
                if [[ -n "$avg_raw" ]]; then
                    avg_int=${avg_raw%.*}
                    avg_int=${avg_int:-0}
                    echo "$ip (IPv6): $avg_raw ms" >> "$TMP_DIR/latencia.txt"
                    if (( avg_int > 150 )); then
                        DEVICE_ISSUES["$ip"]="Alta latencia ($avg_raw ms)"
                    fi
                fi
            fi
        fi
    done < <(awk '{print $1}' "$TMP_DIR/ndp6.txt" | grep -v '^$')

    for ip in "${!DEVICE_MAC[@]}"; do
        [[ -n "${DEVICE_MAC[$ip]}" ]] || continue
        mac="${DEVICE_MAC[$ip]}"
        is_known=false
        for known in "${KNOWN_MACS[@]}"; do
            if [[ "${known,,}" == "${mac,,}" ]]; then
                is_known=true
                break
            fi
        done
        if [[ "$is_known" == false ]]; then
            if [[ -n "${DEVICE_ISSUES[$ip]}" ]]; then
                DEVICE_ISSUES["$ip"]+="; Dispositivo no autorizado"
            else
                DEVICE_ISSUES["$ip"]="Dispositivo no autorizado"
            fi
        fi
    done
fi

# --- Procesamiento de datos recopilados ---
TOTAL_SUSPICIOUS=0
BROADCAST=0
MULTICAST_IPv4=0
MULTICAST_IPv6=0

if [[ $PKT_COUNT -gt 0 ]]; then
    BROADCAST=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | grep -c "255\.255\.255\.255\|ff:ff:ff:ff:ff:ff")
    MULTICAST_IPv4=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | grep -c " 224\.")
    MULTICAST_IPv6=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | grep -c " ff0[0-2]")

    while read -r count ip; do
        [[ -n "$ip" ]] && DEVICE_TX["$ip"]=$(( ${DEVICE_TX[$ip]:-0} + count ))
    done < <(
        tshark -r "$PCAP_FILE" -T fields -e ip.src -e ipv6.src -E occurrence=f 2>/dev/null | \
        awk '$0 !~ /^(0\.0\.0\.0|::)$/ && NF { for(i=1;i<=NF;i++) if($i!="") print $i }' | \
        sort | uniq -c
    )

    while read -r count ip; do
        [[ -n "$ip" ]] && DEVICE_RX["$ip"]=$(( ${DEVICE_RX[$ip]:-0} + count ))
    done < <(
        tshark -r "$PCAP_FILE" -T fields -e ip.dst -e ipv6.dst -E occurrence=f 2>/dev/null | \
        awk '$0 !~ /^(0\.0\.0\.0|::)$/ && NF { for(i=1;i<=NF;i++) if($i!="") print $i }' | \
        sort | uniq -c
    )

    while read -r count ip; do
        if [[ -n "$ip" ]]; then
            SUSPICIOUS_DEVICES["$ip"]=$(( ${SUSPICIOUS_DEVICES[$ip]:-0} + count ))
            (( TOTAL_SUSPICIOUS += count ))
        fi
    done < <(
        tshark -r "$PCAP_FILE" -Y "not (tcp.port in {80,443,22,53,123,5353} or udp.port in {53,123,5353})" \
               -T fields -e ip.src -e ipv6.src -E occurrence=f 2>/dev/null | \
        awk '$0 !~ /^(0\.0\.0\.0|::)$/ && NF { for(i=1;i<=NF;i++) if($i!="") print $i }' | \
        sort | uniq -c
    )
fi

DASH_URL="No activo"
if systemctl is-active --quiet darkstat; then
    IP_LOCAL=$(ip -4 addr show dev "$INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -n1)
    DASH_URL="http://${IP_LOCAL:-localhost}:667"
fi

FECHA_REPORTE=$(date '+%Y-%m-%d %H:%M:%S')

# --- Incluir todas las IPs con tráfico al reporte ---
declare -A ALL_IPS_SEEN
for ip in "${!DEVICE_RX[@]}"; do ALL_IPS_SEEN["$ip"]=1; done
for ip in "${!DEVICE_TX[@]}"; do ALL_IPS_SEEN["$ip"]=1; done

# --- Generar reporte de texto ---
{
    echo "=== REPORTE DE ANÁLISIS DE RED ==="
    echo "Fecha: $FECHA_REPORTE"
    echo "Interfaz: $INTERFACE"
    echo "Red IPv4: ${IPV4_NET:-N/A}"
    echo "Red IPv6: ${IPV6_NET:-N/A}"
    echo "Paquetes capturados: $PKT_COUNT"
    echo ""

    if (( TOTAL_SUSPICIOUS > 50 )); then
        echo "🚨 TRÁFICO SOSPECHOSO DETECTADO"
        echo "--------------------------------"
        printf "%-40s %-20s %s\n" "IP" "MAC" "Paquetes Sospechosos"
        echo "--------------------------------"
        for ip in "${!SUSPICIOUS_DEVICES[@]}"; do
            if (( SUSPICIOUS_DEVICES["$ip"] > 0 )); then
                mac="${DEVICE_MAC[$ip]:-desconocida}"
                printf "%-40s %-20s %s\n" "$ip" "$mac" "${SUSPICIOUS_DEVICES[$ip]}"
            fi
        done
        echo ""
    fi

    echo "📊 TABLA DE DISPOSITIVOS EN LA RED"
    echo "--------------------------------------------------------------------------------------------------------------------------------------------------"
    printf "%-40s %-25s %-20s %-18s %-18s %-12s %s\n" "IP" "Hostname" "MAC" "RX (recibidos)" "TX (enviados)" "Total Tráfico" "Fecha"
    echo "--------------------------------------------------------------------------------------------------------------------------------------------------"

    if [[ ${#ALL_IPS_SEEN[@]} -eq 0 ]]; then
        echo "No se detectaron direcciones IP con tráfico durante la captura."
    else
        for ip in "${!ALL_IPS_SEEN[@]}"; do
            hostname=$(get_hostname "$ip")
            mac="${DEVICE_MAC[$ip]:-desconocida}"
            rx=${DEVICE_RX[$ip]:-0}
            tx=${DEVICE_TX[$ip]:-0}
            total=$(( rx + tx ))
            printf "%-40s %-25s %-20s %-18s %-18s %-12s %s\n" "$ip" "$hostname" "$mac" "$rx" "$tx" "$total" "$FECHA_REPORTE"
        done
    fi
    echo ""

    if (( BROADCAST > 200 || MULTICAST_IPv4 > 300 || MULTICAST_IPv6 > 300 )); then
        echo "⚠️  ALERTA GLOBAL: Posible storm de broadcast/multicast"
        echo ""
    fi

    echo "=== LATENCIAS ==="
    if [[ -f "$TMP_DIR/latencia.txt" ]]; then
        sort -k3 -n -t: "$TMP_DIR/latencia.txt"
    else
        echo "Sin datos de latencia."
    fi
    echo ""
    echo "ℹ️ Nota: Este reporte analiza solo el tráfico capturado durante su ejecución (120 segundos)."
    echo "   Darkstat muestra tráfico acumulado desde que se inició el servicio."
    echo ""
    echo "Archivos: $REPORT_DIR"
} > "$TXT_REPORT"

chown "$SUDO_USER:" "$TXT_REPORT"

# --- Generar reporte en formato HTML ---
cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reporte de Red - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #fafafa; }
        .header { background: #4a6fa5; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 15px; margin: 15px 0; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .suspicious { background-color: #ffcdd2; border-left: 4px solid #d32f2f; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f5f5f5; }
        .alert { background-color: #ffebee; }
        .note { background-color: #e8f5e8; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Reporte de Análisis de Red</h1>
        <p><strong>Fecha:</strong> $FECHA_REPORTE</p>
        <p><strong>Interfaz:</strong> $INTERFACE</p>
        <p><strong>IPv4:</strong> ${IPV4_NET:-N/A} | <strong>IPv6:</strong> ${IPV6_NET:-N/A}</p>
        <p><strong>Paquetes capturados:</strong> $PKT_COUNT</p>
    </div>

EOF

if (( TOTAL_SUSPICIOUS > 50 )); then
    cat >> "$HTML_REPORT" <<EOF
    <div class="section suspicious">
        <h2>🚨 Tráfico Sospechoso Detectado</h2>
        <p>Se detectaron <strong>$TOTAL_SUSPICIOUS</strong> paquetes fuera de puertos comunes.</p>
        <table>
            <tr><th>IP</th><th>MAC</th><th>Paquetes Sospechosos</th></tr>
EOF
    for ip in "${!SUSPICIOUS_DEVICES[@]}"; do
        if (( SUSPICIOUS_DEVICES["$ip"] > 0 )); then
            mac="${DEVICE_MAC[$ip]:-desconocida}"
            echo "            <tr><td>$ip</td><td>$mac</td><td>${SUSPICIOUS_DEVICES[$ip]}</td></tr>" >> "$HTML_REPORT"
        fi
    done
    cat >> "$HTML_REPORT" <<EOF
        </table>
    </div>
EOF
fi

cat >> "$HTML_REPORT" <<EOF
    <div class="section">
        <h2>📊 Tabla de Dispositivos en la Red</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>RX (recibidos)</th>
                <th>TX (enviados)</th>
                <th>Total Tráfico</th>
                <th>Fecha</th>
            </tr>
EOF

if [[ ${#ALL_IPS_SEEN[@]} -eq 0 ]]; then
    echo "            <tr><td colspan='7'>No se detectaron direcciones IP con tráfico.</td></tr>" >> "$HTML_REPORT"
else
    for ip in "${!ALL_IPS_SEEN[@]}"; do
        hostname=$(get_hostname "$ip")
        mac="${DEVICE_MAC[$ip]:-desconocida}"
        rx=${DEVICE_RX[$ip]:-0}
        tx=${DEVICE_TX[$ip]:-0}
        total=$(( rx + tx ))
        echo "            <tr><td>$ip</td><td>$hostname</td><td>$mac</td><td>$rx</td><td>$tx</td><td>$total</td><td>$FECHA_REPORTE</td></tr>" >> "$HTML_REPORT"
    done
fi

cat >> "$HTML_REPORT" <<EOF
        </table>
    </div>

    <div class="note">
        <p><strong>ℹ️ Nota:</strong> Este reporte analiza solo el tráfico capturado durante su ejecución (120 segundos). 
        Darkstat muestra tráfico acumulado desde que se inició el servicio.</p>
    </div>
EOF

if (( BROADCAST > 200 || MULTICAST_IPv4 > 300 || MULTICAST_IPv6 > 300 )); then
    cat >> "$HTML_REPORT" <<EOF
    <div class="section alert">
        <p>⚠️ <strong>ALERTA GLOBAL:</strong> Posible storm de broadcast/multicast</p>
    </div>
EOF
fi

cat >> "$HTML_REPORT" <<EOF
    <div class="section">
        <h2>📊 Latencias</h2>
        <table>
            <tr><th>Dispositivo</th><th>Latencia</th></tr>
EOF

if [[ -f "$TMP_DIR/latencia.txt" ]]; then
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            dev=$(echo "$line" | cut -d: -f1)
            lat=$(echo "$line" | cut -d: -f2-)
            echo "            <tr><td>$dev</td><td>$lat</td></tr>" >> "$HTML_REPORT"
        fi
    done < "$TMP_DIR/latencia.txt"
else
    echo "            <tr><td colspan='2'>Sin datos de latencia.</td></tr>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" <<EOF
        </table>
    </div>

    <div class="section">
        <h2>📁 Archivos Generados</h2>
        <ul>
            <li><a href="./$(basename "$PCAP_FILE")">Captura de tráfico (.pcap)</a></li>
            <li><a href="./$(basename "$WHITELIST")">Lista blanca de MACs</a></li>
            <li><a href="./$(basename "$OUI_FILE")">Base de fabricantes (OUI)</a></li>
        </ul>
        <p><strong>Darkstat:</strong> <a href="$DASH_URL" target="_blank">$DASH_URL</a></p>
    </div>
</body>
</html>
EOF

chown "$SUDO_USER:" "$HTML_REPORT"

# --- Mostrar informacion de culminacion de procesos en Shell ---
log "Análisis completado. IPs con tráfico: ${#ALL_IPS_SEEN[@]}"
info "✅ Análisis completado."
info "📁 Reportes en: $REPORT_DIR"
info "📄 Abrir: file://$HTML_REPORT"
