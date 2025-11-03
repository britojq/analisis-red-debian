# 🕵️‍♂️ Análisis de Red para Debian

Script avanzado en Bash para diagnosticar redes locales en sistemas Debian/Ubuntu. Detecta:
- Alta latencia
- Direcciones MAC/IP duplicadas
- Tráfico sospechoso
- Storms de broadcast/multicast
- Dispositivos no autorizados

## 📊 Características

- Tabla detallada: **IP | Hostname | MAC | RX | TX | Total | Fecha**
- Reporte en **HTML y texto**
- Captura de tráfico en `.pcap`
- Integración con **darkstat**
- Lista blanca de MACs
- Soporte IPv4 e IPv6

## 🚀 Instalación

# Guía de instalación detallada

## 1. Dependencias

Ejecuta:

```bash
sudo apt update
sudo apt install -y nmap arp-scan iproute2 tcpdump tshark darkstat curl dnsutils
```

## 2. Permisos

El script debe ejecutarse con \`sudo\`:

```bash
sudo ./analisis_red_completo.sh
```

## 3. Configuración de darkstat (opcional)

Edita \`/etc/darkstat/init.cfg\` para ajustar la interfaz:

```ini
INTERFACE="-i eno1"
PORT="-p 667"
BINDIP="-b 0.0.0.0"
```

Luego reinicia:

```bash
sudo systemctl restart darkstat
```

## 4. Lista blanca de MACs
La primera vez que ejecutes el script, se creará en tu home la siguiente carpeta:

```bash
\`~/reporte_red/mac_whitelist.txt\`
```

Añade tus dispositivos confiables allí (una MAC por línea).

```bash
# Lista blanca de direcciones MAC (una por línea)
# Ejemplo:
# 00:11:22:33:44:55
```

En los archivos del repositorio se encuentra el archivo oui.txt, este archivo contiene el listado de dispositivos por Marca de MAC, en caso de no poder descargarlo de internet puede ubicarlo dentro de la carpeta:

```bash
\`~/reporte_red/oui.txt\`
```

## 5. Vista del reporte generado

![Ejemplo del reporte de Red Generado ](ejemplo_reporte.png "Reporte del analisis del trafico de la red")


## 6. Modulo Adicional (envio de reporte a bot de telegram)

- Ejecuta automáticamente el análisis de red
- Espera a que termine
- Envía el último reporte HTML al bot de Telegram

Se debe configurar las siguientes variables del script:

```bash
TELEGRAM_BOT_TOKEN="TU_TOKEN_AQUI"          # Reemplaza con tu token de bot
TELEGRAM_CHAT_ID="TU_CHAT_ID_AQUI"          # Reemplaza con tu ID de usuario
```

Luego debes ejecutarlo: 

```bash
sudo ./envio_telegram.sh
```


## ¡Eso es todo, chicos!

Si cree que falta algo o si encontró un error, ¡no dude en enviar una solicitud de pull request! o enviame un correo a: britojq@gmail.com

## Autor
Jose A. Brito H. 
: @britojq : @britojab :
www.britojab.com
