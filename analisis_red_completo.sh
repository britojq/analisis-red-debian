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

# --- Obtener IP y máscara de la interfaz ---
MY_IP=$(ip -4 addr show dev "$INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | head -n1 | cut -d'/' -f1)
MY_MASK=$(ip -4 addr show dev "$INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | head -n1 | cut -d'/' -f2)

if [[ -z "$MY_IP" ]] || [[ -z "$MY_MASK" ]]; then
    warn "No se pudo determinar la IP/máscara de la interfaz."
    MY_IP=""
    MY_MASK=""
else
    info "IP de la interfaz: $MY_IP/$MY_MASK"
fi

# --- Función para verificar si una IP es local ---
es_ip_local() {
    local ip="$1"

    # Validar formato de IP
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi

    if [[ -z "$MY_IP" ]] || [[ -z "$MY_MASK" ]]; then
        return 1
    fi

    if ! [[ "$MY_MASK" =~ ^[0-9]+$ ]] || [[ "$MY_MASK" -lt 0 ]] || [[ "$MY_MASK" -gt 32 ]]; then
        return 1
    fi

    # Validar octetos de la IP
    IFS='.' read -r a b c d <<< "$ip"
    for i in "$a" "$b" "$c" "$d"; do
        if ! [[ "$i" =~ ^[0-9]+$ ]] || [[ "$i" -lt 0 ]] || [[ "$i" -gt 255 ]]; then
            return 1
        fi
    done
    local ip_int=$((a<<24 | b<<16 | c<<8 | d))

    IFS='.' read -r a b c d <<< "$MY_IP"
    local my_ip_int=$((a<<24 | b<<16 | c<<8 | d))

    local netmask=$((0xffffffff << (32 - MY_MASK)))
    [[ $((ip_int & netmask)) -eq $((my_ip_int & netmask)) ]]
}

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

# --- Descargar OUI (URL corregida) ---
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
        if [[ -n "$mac" ]] && [[ "$mac" != "N/A (externo)" ]] && [[ "$mac" != "desconocida" ]]; then
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
info "Iniciando captura en '$INTERFACE' (120s). Genera tráfico AHORA."
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

# --- EXTRAER MACS DEL TRÁFICO (solo para IPs locales) ---
info "Extrayendo direcciones MAC del tráfico capturado..."
tshark -r "$PCAP_FILE" -T fields -e eth.src -e ip.src 2>/dev/null | \
while read -r mac ip; do
    if [[ "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] && [[ -n "$ip" ]] && [[ "$ip" != "0.0.0.0" ]]; then
        if es_ip_local "$ip"; then
            if [[ -z "${DEVICE_MAC[$ip]}" ]]; then
                DEVICE_MAC["$ip"]="$mac"
            fi
        else
            if [[ -z "${DEVICE_MAC[$ip]}" ]]; then
                DEVICE_MAC["$ip"]="N/A (externo)"
            fi
        fi
    fi
done

# --- Análisis IPv4 (ARP) - solo para hosts locales ---
if [ -n "$MY_IP" ]; then
    arp-scan --interface="$INTERFACE" --localnet --ignoredups > "$TMP_DIR/arp4.txt" 2>/dev/null

    while IFS= read -r line; do
        if [[ $line =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            ip=$(echo "$line" | awk '{print $1}')
            mac=$(echo "$line" | awk '{print $2}')
            if [[ -n "$mac" ]] && es_ip_local "$ip"; then
                if [[ -z "${DEVICE_MAC[$ip]}" ]] || [[ "${DEVICE_MAC[$ip]}" == "N/A (externo)" ]]; then
                    DEVICE_MAC["$ip"]="$mac"
                fi
            fi
        fi
    done < "$TMP_DIR/arp4.txt"

    # Solo escanear la red local si tenemos MY_IP
    nmap -sn "$MY_IP/$MY_MASK" -oN "$TMP_DIR/nmap4.txt" >/dev/null 2>&1

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
                    # Guardar latencia para procesamiento posterior
                    echo -e "$ip\t$avg_raw" >> "$TMP_DIR/latencia_raw.txt"
                    if (( avg_int > 150 )); then
                        DEVICE_ISSUES["$ip"]="Alta latencia ($avg_raw ms)"
                    fi
                fi
            fi
        fi
    done < <(grep "Nmap scan report" "$TMP_DIR/nmap4.txt" | awk '{print $NF}' | tr -d '()')

    for ip in "${!DEVICE_MAC[@]}"; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && es_ip_local "$ip"; then
            mac="${DEVICE_MAC[$ip]}"
            is_known=false
            for known in "${KNOWN_MACS[@]}"; do
                if [[ "${known,,}" == "${mac,,}" ]] && [[ "$mac" != "N/A (externo)" ]] && [[ "$mac" != "desconocida" ]]; then
                    is_known=true
                    break
                fi
            done
            if [[ "$is_known" == false ]] && [[ "$mac" != "N/A (externo)" ]]; then
                if [[ -n "${DEVICE_ISSUES[$ip]}" ]]; then
                    DEVICE_ISSUES["$ip"]+="; Dispositivo no autorizado"
                else
                    DEVICE_ISSUES["$ip"]="Dispositivo no autorizado"
                fi
            fi
        fi
    done
fi

# --- Análisis IPv6 ---
if [ -n "$MY_IP" ]; then
    ip -6 neigh show dev "$INTERFACE" > "$TMP_DIR/ndp6.txt" 2>/dev/null

    while IFS= read -r line; do
        set -- $line
        ip=$1
        mac=$5
        if [[ -n "$ip" && -n "$mac" && "$mac" != "REACHABLE" && "$mac" != "00:00:00:00:00:00" ]]; then
            if [[ -z "${DEVICE_MAC[$ip]}" ]]; then
                DEVICE_MAC["$ip"]="$mac"
            fi
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
                    echo -e "$ip\t$avg_raw" >> "$TMP_DIR/latencia_raw.txt"
                    if (( avg_int > 150 )); then
                        DEVICE_ISSUES["$ip"]="Alta latencia ($avg_raw ms)"
                    fi
                fi
            fi
        fi
    done < <(awk '{print $1}' "$TMP_DIR/ndp6.txt" | grep -v '^$')

    for ip in "${!DEVICE_MAC[@]}"; do
        if [[ "$ip" == *":"* ]]; then
            mac="${DEVICE_MAC[$ip]}"
            is_known=false
            for known in "${KNOWN_MACS[@]}"; do
                if [[ "${known,,}" == "${mac,,}" ]] && [[ "$mac" != "N/A (externo)" ]] && [[ "$mac" != "desconocida" ]]; then
                    is_known=true
                    break
                fi
            done
            if [[ "$is_known" == false ]] && [[ "$mac" != "N/A (externo)" ]]; then
                if [[ -n "${DEVICE_ISSUES[$ip]}" ]]; then
                    DEVICE_ISSUES["$ip"]+="; Dispositivo no autorizado"
                else
                    DEVICE_ISSUES["$ip"]="Dispositivo no autorizado"
                fi
            fi
        fi
    done
fi

# --- Procesamiento de tráfico (RX/TX) ---
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

# --- Clasificar IPs por segmento ---
declare -a LOCAL_CON_MAC
declare -a LOCAL_SIN_MAC
declare -a EXTERNOS

# Recopilar todas las IPs con tráfico
declare -A ALL_IPS_SEEN
for ip in "${!DEVICE_RX[@]}" "${!DEVICE_TX[@]}"; do
    [[ -n "$ip" ]] && ALL_IPS_SEEN["$ip"]=1
done

for ip in "${!ALL_IPS_SEEN[@]}"; do
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if es_ip_local "$ip"; then
            if [[ -n "${DEVICE_MAC[$ip]}" ]] && [[ "${DEVICE_MAC[$ip]}" != "desconocida" ]] && [[ "${DEVICE_MAC[$ip]}" != "N/A (externo)" ]]; then
                LOCAL_CON_MAC+=("$ip")
            else
                LOCAL_SIN_MAC+=("$ip")
            fi
        else
            EXTERNOS+=("$ip")
        fi
    else
        EXTERNOS+=("$ip")
    fi
done

# Eliminar duplicados
mapfile -t LOCAL_CON_MAC < <(printf '%s\n' "${LOCAL_CON_MAC[@]}" | sort -u)
mapfile -t LOCAL_SIN_MAC < <(printf '%s\n' "${LOCAL_SIN_MAC[@]}" | sort -u)
mapfile -t EXTERNOS < <(printf '%s\n' "${EXTERNOS[@]}" | sort -u)

# --- Construir tabla de latencias completa ---
declare -a LATENCIA_TABLA
declare -A LATENCIA_VALORES

# Cargar valores de latencia
if [[ -f "$TMP_DIR/latencia_raw.txt" ]]; then
    while IFS=$'\t' read -r ip latencia; do
        LATENCIA_VALORES["$ip"]="$latencia"
    done < "$TMP_DIR/latencia_raw.txt"
fi

# Para cada IP con latencia, construir entrada completa
for ip in "${!LATENCIA_VALORES[@]}"; do
    latencia="${LATENCIA_VALORES[$ip]}"
    mac="${DEVICE_MAC[$ip]:-desconocida}"
    tx=${DEVICE_TX[$ip]:-0}
    rx=${DEVICE_RX[$ip]:-0}
    total=$(( tx + rx ))
    LATENCIA_TABLA+=("$ip|$latencia|$mac|$tx|$rx|$total")
done

# Ordenar por latencia descendente
if [[ ${#LATENCIA_TABLA[@]} -gt 0 ]]; then
    # Usar proceso temporal para ordenar
    {
        for entry in "${LATENCIA_TABLA[@]}"; do
            IFS='|' read -r ip latencia mac tx rx total <<< "$entry"
            echo -e "$latencia\t$entry"
        done
    } | sort -k1 -n -r | cut -f2- > "$TMP_DIR/latencia_ordenada.txt"

    # Recargar la tabla ordenada
    mapfile -t LATENCIA_TABLA < "$TMP_DIR/latencia_ordenada.txt"
fi

DASH_URL="No activo"
if systemctl is-active --quiet darkstat; then
    IP_LOCAL=$(ip -4 addr show dev "$INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -n1)
    DASH_URL="http://${IP_LOCAL:-localhost}:667"
fi

FECHA_REPORTE=$(date '+%Y-%m-%d %H:%M:%S')

# --- Generar reporte de texto ---
{
    echo "=== REPORTE DE ANÁLISIS DE RED ==="
    echo "Fecha: $FECHA_REPORTE"
    echo "Interfaz: $INTERFACE"
    if [[ -n "$MY_IP" ]]; then
        echo "Red local: $MY_IP/$MY_MASK"
    fi
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

    # Sección 1: Hosts locales con MAC
    if [[ ${#LOCAL_CON_MAC[@]} -gt 0 ]]; then
        echo "🔹 HOSTS LOCALES (en la misma red):"
        for ip in "${LOCAL_CON_MAC[@]}"; do
            hostname=$(get_hostname "$ip")
            mac="${DEVICE_MAC[$ip]:-desconocida}"
            rx=${DEVICE_RX[$ip]:-0}
            tx=${DEVICE_TX[$ip]:-0}
            total=$(( rx + tx ))
            printf "%-40s %-25s %-20s %-18s %-18s %-12s %s\n" "$ip" "$hostname" "$mac" "$rx" "$tx" "$total" "$FECHA_REPORTE"
        done
        echo ""
    fi

    # Sección 2: Hosts locales sin MAC
    if [[ ${#LOCAL_SIN_MAC[@]} -gt 0 ]]; then
        echo "🔸 HOSTS LOCALES (sin MAC detectada):"
        for ip in "${LOCAL_SIN_MAC[@]}"; do
            hostname=$(get_hostname "$ip")
            mac="desconocida"
            rx=${DEVICE_RX[$ip]:-0}
            tx=${DEVICE_TX[$ip]:-0}
            total=$(( rx + tx ))
            printf "%-40s %-25s %-20s %-18s %-18s %-12s %s\n" "$ip" "$hostname" "$mac" "$rx" "$tx" "$total" "$FECHA_REPORTE"
        done
        echo ""
    fi

    # Sección 3: Hosts externos
    if [[ ${#EXTERNOS[@]} -gt 0 ]]; then
        echo "🌐 HOSTS EXTERNOS (Internet/otras redes):"
        for ip in "${EXTERNOS[@]}"; do
            hostname=$(get_hostname "$ip")
            mac="${DEVICE_MAC[$ip]:-N/A (externo)}"
            rx=${DEVICE_RX[$ip]:-0}
            tx=${DEVICE_TX[$ip]:-0}
            total=$(( rx + tx ))
            printf "%-40s %-25s %-20s %-18s %-18s %-12s %s\n" "$ip" "$hostname" "$mac" "$rx" "$tx" "$total" "$FECHA_REPORTE"
        done
        echo ""
    fi

    if (( BROADCAST > 200 || MULTICAST_IPv4 > 300 || MULTICAST_IPv6 > 300 )); then
        echo "⚠️  ALERTA GLOBAL: Posible storm de broadcast/multicast"
        echo ""
    fi

    echo "=== LATENCIAS (ordenadas de mayor a menor) ==="
    if [[ ${#LATENCIA_TABLA[@]} -gt 0 ]]; then
        printf "%-40s %-15s %-20s %-12s %-12s %-12s\n" "Dispositivo" "Latencia (ms)" "MAC" "TX" "RX" "Total"
        echo "------------------------------------------------------------------------------------------------------------------------"
        for entry in "${LATENCIA_TABLA[@]}"; do
            IFS='|' read -r ip latencia mac tx rx total <<< "$entry"
            printf "%-40s %-15s %-20s %-12s %-12s %-12s\n" "$ip" "$latencia" "$mac" "$tx" "$rx" "$total"
        done
    else
        echo "Sin datos de latencia."
    fi
    echo ""
    echo "ℹ️ Nota: Este reporte analiza solo el tráfico capturado durante su ejecución (120 segundos)."
    if [[ -n "$MY_IP" ]]; then
        echo "   - Hosts locales: en tu red $MY_IP/$MY_MASK"
    fi
    echo "   - Hosts externos: direcciones fuera de tu red local (MAC no visible)."
    echo ""
    echo "Archivos: $REPORT_DIR"
} > "$TXT_REPORT"

chown "$SUDO_USER:" "$TXT_REPORT"

# --- Generar reporte HTML ---
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
        .local { border-left: 4px solid #4caf50; }
        .local-unknown { border-left: 4px solid #ff9800; }
        .external { border-left: 4px solid #2196f3; }
        .suspicious { background-color: #ffcdd2; border-left: 4px solid #d32f2f; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f5f5f5; }
        .alert { background-color: #ffebee; }
        .note { background-color: #e8f5e8; padding: 10px; border-radius: 4px; }
        .high-latency { color: #d32f2f; font-weight: bold; }
        h3 { margin-top: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Reporte de Análisis de Red</h1>
        <p><strong>Fecha:</strong> $FECHA_REPORTE</p>
        <p><strong>Interfaz:</strong> $INTERFACE</p>
        <p><strong>Red local:</strong> ${MY_IP:-N/A}${MY_MASK:+/$MY_MASK}</p>
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

EOF

# Sección 1: Locales con MAC
if [[ ${#LOCAL_CON_MAC[@]} -gt 0 ]]; then
    cat >> "$HTML_REPORT" <<EOF
        <div class="local">
            <h3>🔹 Hosts Locales (en la misma red)</h3>
            <table>
                <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>RX</th><th>TX</th><th>Total</th><th>Fecha</th></tr>
EOF
    for ip in "${LOCAL_CON_MAC[@]}"; do
        hostname=$(get_hostname "$ip")
        mac="${DEVICE_MAC[$ip]:-desconocida}"
        rx=${DEVICE_RX[$ip]:-0}
        tx=${DEVICE_TX[$ip]:-0}
        total=$(( rx + tx ))
        echo "                <tr><td>$ip</td><td>$hostname</td><td>$mac</td><td>$rx</td><td>$tx</td><td>$total</td><td>$FECHA_REPORTE</td></tr>" >> "$HTML_REPORT"
    done
    cat >> "$HTML_REPORT" <<EOF
            </table>
        </div>
EOF
fi

# Sección 2: Locales sin MAC
if [[ ${#LOCAL_SIN_MAC[@]} -gt 0 ]]; then
    cat >> "$HTML_REPORT" <<EOF
        <div class="local-unknown">
            <h3>🔸 Hosts Locales (sin MAC detectada)</h3>
            <table>
                <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>RX</th><th>TX</th><th>Total</th><th>Fecha</th></tr>
EOF
    for ip in "${LOCAL_SIN_MAC[@]}"; do
        hostname=$(get_hostname "$ip")
        mac="desconocida"
        rx=${DEVICE_RX[$ip]:-0}
        tx=${DEVICE_TX[$ip]:-0}
        total=$(( rx + tx ))
        echo "                <tr><td>$ip</td><td>$hostname</td><td>$mac</td><td>$rx</td><td>$tx</td><td>$total</td><td>$FECHA_REPORTE</td></tr>" >> "$HTML_REPORT"
    done
    cat >> "$HTML_REPORT" <<EOF
            </table>
        </div>
EOF
fi

# Sección 3: Externos
if [[ ${#EXTERNOS[@]} -gt 0 ]]; then
    cat >> "$HTML_REPORT" <<EOF
        <div class="external">
            <h3>🌐 Hosts Externos (Internet/otras redes)</h3>
            <table>
                <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>RX</th><th>TX</th><th>Total</th><th>Fecha</th></tr>
EOF
    for ip in "${EXTERNOS[@]}"; do
        hostname=$(get_hostname "$ip")
        mac="${DEVICE_MAC[$ip]:-N/A (externo)}"
        rx=${DEVICE_RX[$ip]:-0}
        tx=${DEVICE_TX[$ip]:-0}
        total=$(( rx + tx ))
        echo "                <tr><td>$ip</td><td>$hostname</td><td>$mac</td><td>$rx</td><td>$tx</td><td>$total</td><td>$FECHA_REPORTE</td></tr>" >> "$HTML_REPORT"
    done
    cat >> "$HTML_REPORT" <<EOF
            </table>
        </div>
EOF
fi

cat >> "$HTML_REPORT" <<EOF
    </div>

    <div class="section">
        <h2>⏱️ Latencias (ordenadas de mayor a menor)</h2>
        <table>
            <tr>
                <th>Dispositivo</th>
                <th>Latencia (ms)</th>
                <th>MAC</th>
                <th>TX</th>
                <th>RX</th>
                <th>Total</th>
            </tr>
EOF

if [[ ${#LATENCIA_TABLA[@]} -gt 0 ]]; then
    for entry in "${LATENCIA_TABLA[@]}"; do
        IFS='|' read -r ip latencia mac tx rx total <<< "$entry"
        if (( ${latencia%.*} > 150 )); then
            echo "            <tr>" >> "$HTML_REPORT"
            echo "                <td>$ip</td>" >> "$HTML_REPORT"
            echo "                <td class=\"high-latency\">$latencia</td>" >> "$HTML_REPORT"
            echo "                <td>$mac</td>" >> "$HTML_REPORT"
            echo "                <td>$tx</td>" >> "$HTML_REPORT"
            echo "                <td>$rx</td>" >> "$HTML_REPORT"
            echo "                <td>$total</td>" >> "$HTML_REPORT"
            echo "            </tr>" >> "$HTML_REPORT"
        else
            echo "            <tr><td>$ip</td><td>$latencia</td><td>$mac</td><td>$tx</td><td>$rx</td><td>$total</td></tr>" >> "$HTML_REPORT"
        fi
    done
else
    echo "            <tr><td colspan='6'>Sin datos de latencia.</td></tr>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" <<EOF
        </table>
    </div>

    <div class="note">
        <p><strong>ℹ️ Nota:</strong>
        Este reporte analiza solo el tráfico capturado durante su ejecución (120 segundos).<br>
EOF

if [[ -n "$MY_IP" ]]; then
    cat >> "$HTML_REPORT" <<EOF
        - <strong>Hosts locales</strong>: en tu red $MY_IP/$MY_MASK<br>
EOF
fi

cat >> "$HTML_REPORT" <<EOF
        - <strong>Hosts externos</strong>: direcciones fuera de tu red local (MAC no visible).<br>
        - <strong class="high-latency">Latencias altas (>150 ms)</strong> se muestran en rojo.
        </p>
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

log "Análisis completado. Locales con MAC: ${#LOCAL_CON_MAC[@]}, sin MAC: ${#LOCAL_SIN_MAC[@]}, externos: ${#EXTERNOS[@]}"
info "✅ Análisis completado."
info "📁 Reportes en: $REPORT_DIR"
info "📄 Abrir: file://$HTML_REPORT"
