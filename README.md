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

```bash
sudo apt install -y nmap arp-scan iproute2 tcpdump tshark darkstat curl dnsutils
