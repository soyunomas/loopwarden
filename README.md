# 🛡️ LoopWarden

![Go Version](https://img.shields.io/badge/go-1.20%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

**LoopWarden** es un sistema de detección de bucles de Capa 2 (L2 Loop Detector) de alto rendimiento para Linux, escrito en Go.

Diseñado para ingenieros de red y administradores de sistemas, LoopWarden utiliza **Raw Sockets (`AF_PACKET`)** y filtros **BPF (Berkeley Packet Filter)** en el Kernel para monitorear, detectar y notificar tormentas de broadcast y bucles de conmutación en tiempo real, con una huella de memoria mínima.

## 🚀 Características Principales

### 📡 Detección y Análisis
*   **EtherFuse (Detección Pasiva):** Analiza duplicados exactos de *payload* (hashing FNV-1a) para detectar rebotes de tramas.
*   **ActiveProbe (Inyección Activa):** Envía sondas Ethernet periódicas. Si regresan, confirma un bucle físico.
*   **MacStorm (Análisis de Velocidad):** Detecta hosts o puertos que inundan la red (PPS excesivos) y los identifica.

### 🔌 Soporte VLAN (802.1Q)
LoopWarden es capaz de parsear cabeceras 802.1Q en tiempo real.
*   Identifica si el bucle ocurre en la **VLAN Nativa** (Access Ports) o en una **VLAN Tagged** específica (Trunk Ports).
*   Los logs indican explícitamente la ubicación: `🚨 LOOP DETECTED on VLAN 10`.

### 🔔 Sistema de Notificaciones (Notifier)
No dependas solo de la consola. LoopWarden integra un sistema de alertas asíncrono y no bloqueante:
*   **Webhooks:** Slack, Microsoft Teams, Discord (JSON payloads).
*   **Syslog:** Integración con SIEMs (Splunk, Graylog, ELK) vía UDP/TCP.
*   **Email (SMTP):** Alertas críticas directas a tu buzón.
*   **Smart Silence:** Implementa "Hysteresis" para evitar el spam de alertas durante una tormenta masiva.

## ⚡ Rendimiento y Arquitectura

LoopWarden está construido siguiendo principios estrictos de optimización ("Zero-Allocation" en rutas críticas):

*   **Kernel-Space Filtering:** Utiliza instrucciones BPF ensambladas a mano para descartar tráfico Unicast en el Kernel. Solo el tráfico Broadcast/Multicast llega a la aplicación.
*   **Zero-Copy Capture:** Reutilización de buffers de lectura estáticos para evitar presión sobre el Garbage Collector (GC) de Go.
*   **Stack Allocation:** Uso de arrays fijos (`[6]byte`) para direcciones MAC y paso de variables por valor para VLAN IDs.

## 🛠️ Instalación y Compilación

Necesitas **Go 1.20+** y `make` instalado.

```bash
# Clonar el repositorio
git clone https://github.com/soyunomas/LoopWarden.git
cd LoopWarden

# Descargar dependencias
make deps

# Compilar binario optimizado (strip symbols & dwarf)
make build
```

El binario resultante se encontrará en `bin/loopwarden`.

## ⚙️ Configuración

La configuración se gestiona mediante `configs/config.toml`. Ejemplo completo:

```toml
[network]
interface = "eth0"    # Interfaz a monitorear (Promiscuous Mode)
snaplen = 2048        

[alerts]
# Integraciones externas (Opcionales)
webhook_url = "https://hooks.slack.com/services/T000/B000/XXXX"
syslog_server = "192.168.1.50:514"
smtp_enabled = false

[algorithms.etherfuse]
enabled = true
storm_pps_limit = 5000 # Umbral de pps global para alerta de tormenta

[algorithms.active_probe]
enabled = true
interval_ms = 1000     # Frecuencia de inyección
magic_payload = "LOOPWARDEN_PROBE"

[algorithms.mac_storm]
enabled = true
max_pps_per_mac = 2000 # Máximo pps permitido por host
```

## 🏃 Uso

Para ejecutar LoopWarden (requiere privilegios de root para abrir Raw Sockets):

```bash
# Usando make (compila y ejecuta con sudo)
make run

# Ejecución manual
sudo ./bin/loopwarden -config configs/config.toml
```

### Despliegue como Servicio (Systemd)

Para ejecutar LoopWarden como un demonio en background:

1.  Copia el binario a `/usr/local/bin`.
2.  Copia la config a `/etc/loopwarden/config.toml`.
3.  Usa el archivo de servicio incluido:

```bash
sudo cp deploy/systemd/loopwarden.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now loopwarden
```

## 🏗️ Estructura del Proyecto

```text
├── cmd/            # Punto de entrada (Main)
├── configs/        # Archivos de configuración
├── deploy/         # Archivos de despliegue (Systemd)
├── internal/
│   ├── sniffer/    # Gestión de sockets AF_PACKET, BPF y VLAN Parsing
│   ├── detector/   # Motor de algoritmos (EtherFuse, ActiveProbe, MacStorm)
│   ├── notifier/   # Worker pool de notificaciones (Slack/Syslog/SMTP)
│   └── config/     # Parsers de configuración
└── Makefile        # Automatización de tareas
```

## 📜 Licencia

Este proyecto está bajo la Licencia MIT.
