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
# Script: ejecuta análisis de red y envía reporte a Telegram
# Requiere: analisis_red_completo.sh + curl
# Fecha: 2025-10-31

# --- CONFIGURACIÓN DE TELEGRAM (¡MODIFICA ESTOS VALORES!) ---
TELEGRAM_BOT_TOKEN="TU_TOKEN_AQUI"          # Reemplaza con tu token de bot
TELEGRAM_CHAT_ID="TU_CHAT_ID_AQUI"          # Reemplaza con tu ID de usuario



# --- Rutas ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALISIS_SCRIPT="$SCRIPT_DIR/analisis_red_completo.sh"
REPORT_DIR="$HOME/reporte_red"

# --- Colores ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Verificar configuracion
if [[ "$TELEGRAM_BOT_TOKEN" == "TU_TOKEN_AQUI" ]] || [[ "$TELEGRAM_CHAT_ID" == "TU_CHAT_ID_AQUI" ]]; then
    error "Configura TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID en este script!"
    exit 1
fi

# Verificar dependencias
if ! command -v curl &> /dev/null; then
    error "curl no esta instalado. Ejecuta: sudo apt install curl"
    exit 1
fi

if [[ ! -f "$ANALISIS_SCRIPT" ]]; then
    error "No se encontro el script de analisis: $ANALISIS_SCRIPT"
    error "Asegurate de que este script y 'analisis_red_completo.sh' esten en la misma carpeta."
    exit 1
fi

# Funcion para enviar mensaje a Telegram
enviar_mensaje_telegram() {
    local mensaje="$1"
    local parse_mode="${2:-Markdown}"
    local url="https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
    local response

    response=$(curl -s -X POST "$url" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$mensaje" \
        -d "parse_mode=$parse_mode" \
        -d "disable_web_page_preview=true")

    if echo "$response" | grep -q '"ok":true'; then
        return 0
    else
        echo "Error en API de Telegram" >&2
        return 1
    fi
}

# Iniciar proceso
info "Iniciando analisis de la red..."

# Enviar mensaje de inicio
MENSAJE_INICIO="*Se Inicio el analisis de red*%0A"
MENSAJE_INICIO+="*Fecha:* $(date '+%d-%m-%Y %H:%M:%S')%0A"
MENSAJE_INICIO+="*Ejecutando script de diagnostico...*%0A"
MENSAJE_INICIO+="Por Favor Espere%0A"
MENSAJE_INICIO+="*(tardara 4minutos en procesar)*"
enviar_mensaje_telegram "$MENSAJE_INICIO" || warn "No se pudo enviar mensaje de inicio."

# Ejecutar el analisis (con sudo)
info "Ejecutando analisis de red (esto tomara ~120 segundos)..."
if sudo "$ANALISIS_SCRIPT"; then
    info "Analisis completado con exito."
else
    error "El analisis fallo."
    MENSAJE_ERROR="*Analisis de red fallido*%0A"
    MENSAJE_ERROR+="*Fecha:* $(date '+%d-%m-%Y %H:%M:%S')%0A"
    MENSAJE_ERROR+="El script de diagnostico termino con error."
    enviar_mensaje_telegram "$MENSAJE_ERROR"
    exit 1
fi

# Encontrar el ultimo reporte HTML
HTML_REPORT=$(ls -t "$REPORT_DIR"/reporte_*.html 2>/dev/null | head -n1)

if [[ -z "$HTML_REPORT" ]] || [[ ! -f "$HTML_REPORT" ]]; then
    error "No se encontro el reporte HTML en $REPORT_DIR"
    MENSAJE_SIN_REPORTE="*Analisis completado, pero sin reporte*%0A"
    MENSAJE_SIN_REPORTE+="*Fecha:* $(date '+%d-%m-%Y %H:%M:%S')%0A"
    MENSAJE_SIN_REPORTE+="No se genero archivo HTML de reporte."
    enviar_mensaje_telegram "$MENSAJE_SIN_REPORTE"
    exit 1
fi

# Contar dispositivos
DISPOSITIVOS=0
if command -v grep &> /dev/null; then
    DISPOSITIVOS=$(grep -c "<tr><td>[0-9]" "$HTML_REPORT" 2>/dev/null || echo "0")
fi

# Enviar mensaje de exito
MENSAJE_EXITO="*Analisis de red completado*%0A"
MENSAJE_EXITO+="*Fecha:* $(date '+%d-%m-%Y %H:%M:%S')%0A"
MENSAJE_EXITO+="*Total de Dispositivos detectados:* $DISPOSITIVOS%0A"
MENSAJE_EXITO+="*Reporte:* $(basename "$HTML_REPORT")"
enviar_mensaje_telegram "$MENSAJE_EXITO" || warn "No se pudo enviar mensaje de exito."

# Enviar el archivo HTML
info "Enviando reporte HTML a Telegram..."
curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument" \
  -F "chat_id=$TELEGRAM_CHAT_ID" \
  -F "document=@$HTML_REPORT" \
  -F "caption=Reporte de analisis de red - $(date '+%d-%m-%Y %H:%M')" > /dev/null

info "Reporte enviado a Telegram."
