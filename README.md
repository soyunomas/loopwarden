# 🛡️ LoopWarden

![Go Version](https://img.shields.io/badge/go-1.21%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Performance](https://img.shields.io/badge/performance-10Gbps%20Ready-brightgreen)

**LoopWarden** es un Detector de Bucles Ethernet (L2 Loop Detector) de alto rendimiento. Monitoriza la red en tiempo real para alertar sobre bucles físicos y tormentas de broadcast en milisegundos, reduciendo drásticamente el tiempo de diagnóstico (MTTR).

## 🚀 Características Principales

LoopWarden ejecuta 5 motores de detección concurrentes. Cada uno busca una "firma" específica de fallo en la red:

### 1. ActiveProbe (Inyección Activa Determinista) ⚡
*El "Sonar" de la red. La única forma de tener 100% de certeza.*

*   **🔬 Mecánica:** LoopWarden genera e inyecta una trama Ethernet unicast especialmente diseñada (con un EtherType `0xFFFF` configurable y un payload "mágico") cada segundo.
*   **🛡️ Lógica de Detección:** Si esta trama, que salió por la interfaz `TX`, regresa a la interfaz `RX`, existe un camino físico cerrado sin lugar a dudas.
*   **💡 Valor Diferencial:** A diferencia de los métodos pasivos que "deducen" un bucle por volumen de tráfico, ActiveProbe lo **confirma físicamente**. Es inmune a falsos positivos causados por tráfico legítimo de alta carga (backups, streaming).
*   **Caso de Uso:** Detectar un cable de parcheo conectado por error entre dos bocas del mismo switch o entre dos switches troncales donde STP ha fallado o está desactivado.

### 2. EtherFuse (Análisis Pasivo de Payload) 🧬
*Detección de "rebotes" mediante huella digital criptográfica.*

*   **🔬 Mecánica:** Inspecciona pasivamente el tráfico Broadcast/Multicast entrante. Calcula un hash ultrarrápido (FNV-1a) del contenido (payload) de la trama, ignorando cabeceras cambiantes. Almacena estos hashes en un buffer circular en memoria.
*   **🛡️ Lógica de Detección:** Si el sistema observa el mismo hash `N` veces en una ventana de tiempo de milisegundos, significa que la trama está "orbitando" la red infinitamente.
*   **💡 Valor Diferencial:** Capaz de detectar bucles **remotos**. Aunque el bucle no esté en tu switch local, recibirás la onda expansiva de los paquetes duplicados.
*   **Caso de Uso:** Identificar bucles ocurriendo aguas abajo (ej: en un switch no gestionado bajo la mesa de un usuario) que están rebotando tráfico hacia el Core.

### 3. MacStorm (Velocidad y Volumetría por Host) 🌪️
*Aislamiento de la fuente del problema.*

*   **🔬 Mecánica:** Mantiene una tabla de estado en tiempo real que rastrea los Paquetes Por Segundo (PPS) generados por cada dirección MAC origen única (Source MAC).
*   **🛡️ Lógica de Detección:** Aplica un límite de velocidad (Rate Limiting) lógico. Si una MAC individual supera el umbral definido (ej: 2000 pps), se marca como host hostil.
*   **💡 Valor Diferencial:** No solo te dice "hay un problema", te dice **quién** es el problema. Convierte una alerta genérica en una acción precisa ("Apagar el puerto donde está la MAC `AA:BB:CC...`").
*   **Caso de Uso:** Tarjetas de red (NICs) averiadas que entran en "jabbering", virus que intentan escanear la red local, o bucles detrás de teléfonos VoIP.

### 4. FlapGuard (Consistencia de Topología L2) 🦇
*Detección de fugas de VLAN e inestabilidad de puertos.*

*   **🔬 Mecánica:** Crea un mapa dinámico de la relación `MAC Address <-> VLAN ID`.
*   **🛡️ Lógica de Detección:** Monitoriza si una misma dirección MAC aparece en distintas VLANs en intervalos de tiempo muy cortos (Flapping).
*   **💡 Valor Diferencial:** Un síntoma clásico de configuraciones erróneas que STP no siempre bloquea. Indica que hay un "puente" no autorizado entre dominios de difusión distintos.
*   **Caso de Uso:**
    *   **Cableado Cruzado:** Un técnico conecta por error un cable entre un puerto de acceso de la VLAN 10 y otro de la VLAN 20.
    *   **VLAN Leaking:** Un switch mal configurado que está dejando escapar tráfico etiquetado hacia puertos nativos.

### 5. ArpWatchdog (Protección del Plano de Control) 🐶
*El sistema de alerta temprana.*

*   **🔬 Mecánica:** Realiza una inspección profunda de paquetes (DPI ligera) buscando cabeceras ARP y contando específicamente las operaciones `WHO-HAS` (Request).
*   **🛡️ Lógica de Detección:** Los bucles de capa 2 amplifican el tráfico Broadcast. Como ARP es el protocolo de broadcast más común y vital, es el primero en saturarse. ArpWatchdog alerta cuando la tasa global de peticiones ARP se vuelve anormal.
*   **💡 Valor Diferencial:** Protege la CPU de los switches y routers. Una tormenta ARP es lo que suele "matar" la conectividad incluso antes de que el enlace se sature por ancho de banda, ya que la CPU del router no puede procesar tantas peticiones.
*   **Caso de Uso:** Detectar el inicio de una tormenta (Broadcast Radiation) segundos antes de que la red se vuelva inutilizable, dando tiempo a reaccionar.

### 🔔 Notificaciones Inteligentes (Smart Silence)

En una tormenta de broadcast, una red puede generar millones de eventos por segundo. Un sistema de alertas ingenuo tumbaría tu servidor de correo o bloquearía tu API de Slack. LoopWarden implementa **Higiene Operacional**:

*   **Global Dampening:** Si el sistema detecta una inundación de alertas (>20 alertas/minuto), activa automáticamente un "Modo Pánico". Silencia las notificaciones durante 60 segundos y envía un único resumen consolidado.
*   **Adaptive Hysteresis:** Cada algoritmo tiene memoria. Si *FlapGuard* detecta un host inestable, te avisa una vez y luego guarda silencio por 30 segundos sobre ese host específico, manteniendo tus canales de comunicación limpios.
*   **Integraciones:** Webhooks JSON (Slack, Discord, Mattermost, Google Chat, Rocket.Chat), **Telegram Bots**, Syslog (RFC 3164) y SMTP (Email).

## ⚙️ Referencia de Configuración (`config.toml`)

A continuación se detallan todos los parámetros disponibles en el archivo de configuración.

### 🔌 Red y Alertas

| Sección | Parámetro | Default | Descripción |
| :--- | :--- | :--- | :--- |
| **[network]** | `interface` | `"eno1"` | **Crítico.** Nombre exacto de la interfaz de red a escuchar (ver `ip link`). |
| | `snaplen` | `2048` | Bytes a capturar por trama. |
| **[alerts]** | `syslog_server` | `""` | Dirección `IP:Puerto` del servidor Syslog (UDP). |
| **[alerts.webhook]** | `enabled` | `false` | Activa/Desactiva notificaciones vía Webhook. |
| | `url` | `""` | URL del Webhook (Slack, Discord, Teams). |
| **[alerts.smtp]** | `enabled` | `false` | Activa el envío por correo electrónico. |
| | `host` | `"smtp.gmail.com"` | Servidor SMTP. |
| | `port` | `587` | Puerto SMTP (587 para TLS/STARTTLS). |
| | `user` | `""` | Usuario SMTP (email completo). |
| | `pass` | `""` | Contraseña o App Password. |
| | `to` | `""` | Destinatario de la alerta. |
| | `from` | `""` | Remitente (debe coincidir con el usuario en Gmail). |
| **[alerts.telegram]** | `enabled` | `false` | Activa notificaciones a Telegram. |
| | `token` | `""` | Token del bot proporcionado por @BotFather. |
| | `chat_id` | `""` | ID numérico del usuario o grupo (ej: `-100...` para grupos). |


### 🧠 Algoritmos de Detección

| Sección | Parámetro | Default | Descripción |
| :--- | :--- | :--- | :--- |
| **[algorithms.etherfuse]** | `enabled` | `true` | Activa/Desactiva el análisis de rebote de payloads. |
| | `history_size` | `4096` | Tamaño del buffer de memoria para hashes. Más tamaño = mayor ventana de tiempo. |
| | `alert_threshold` | `50` | Cantidad de veces que un paquete debe repetirse para considerar bucle. |
| | `storm_pps_limit` | `5000` | Umbral de PPS global para considerar que la red está bajo tormenta masiva. |
| **[algorithms.active_probe]**| `enabled` | `true` | Activa/Desactiva la inyección activa de sondas. |
| | `interval_ms` | `1000` | Frecuencia de envío de la sonda (milisegundos). |
| | `ethertype` | `65535` | Tipo de protocolo Ethernet (0xFFFF) usado para la sonda. |
| **[algorithms.mac_storm]** | `enabled` | `true` | Activa/Desactiva el limitador de velocidad por host. |
| | `max_pps_per_mac`| `2000` | Máximo de paquetes/segundo permitidos por una única MAC antes de alertar. |
| **[algorithms.flap_guard]**| `enabled` | `true` | Activa/Desactiva la detección de inestabilidad de VLANs. |
| | `threshold` | `5` | Número de cambios de VLAN permitidos por segundo para una misma MAC. |
| **[algorithms.arp_watch]** | `enabled` | `true` | Activa/Desactiva la monitorización específica de ARP. |
| | `max_pps` | `500` | Límite global de peticiones ARP (`WHO-HAS`) por segundo en toda la interfaz. |

## 🚨 Playbook de Respuesta a Incidentes

Guía de actuación rápida para operadores de red (NOC) ante alertas críticas de LoopWarden:

| Alerta Recibida | Causa Probable | Acción Recomendada |
| :--- | :--- | :--- |
| **ActiveProbe:**<br>`LOOP CONFIRMED` | **Bucle Físico Cerrado (Hard Loop).**<br>Un cable conecta dos puertos del mismo dominio de broadcast (mismo switch o switches interconectados) y STP no lo ha bloqueado (ej: Switches "tontos" no gestionados). | **ACCION INMEDIATA (CRÍTICO)**<br>1. El bucle es físico y total. La red caerá en segundos.<br>2. Revisa los últimos cables conectados o cambios en el patch-panel.<br>3. Desconecta enlaces redundantes hasta que cese la alerta. |
| **MacStorm:**<br>`MAC VELOCITY ALERT` | **Host Inundador.**<br>Una tarjeta de red averiada ("Jabbering NIC"), un virus haciendo escaneo masivo, o un bucle local detrás de un dispositivo de borde (ej: Teléfono VoIP con el puerto PC conectado al muro). | **AISLAR Y APAGAR**<br>1. Copia la MAC de la alerta.<br>2. Búscala en el switch: `show mac address-table address <MAC>`.<br>3. Identifica el puerto físico y apágalo administrativamente (`shutdown`). |
| **FlapGuard:**<br>`MAC FLAPPING` | **Inestabilidad de Topología.**<br>Un cable está puenteando físicamente dos VLANs distintas (ej: puerto VLAN 10 conectado a puerto VLAN 20), o un Trunk tiene una configuración de VLAN nativa errónea. | **INVESTIGAR CABLEADO**<br>1. Rastrea la MAC para ver entre qué puertos o switches está "saltando".<br>2. Verifica el cableado físico en el armario de comunicaciones.<br>3. Comprueba configuraciones de "Native VLAN" en los Trunks. |
| **ArpWatchdog:**<br>`ARP STORM` | **Tormenta de Plano de Control.**<br>Suele ser el primer síntoma de un bucle (amplificación de broadcast) o un ataque de escaneo de red. Pone en riesgo la CPU de los Routers/Core. | **CORRELACIONAR**<br>1. Si aparece junto a alertas de *EtherFuse* o *ActiveProbe*, es un bucle: prioriza buscar el cable físico.<br>2. Si aparece sola, es un host infectado o mal configurado: localízalo por MAC y aíslalo. |

## 🛠️ Instalación y Uso

LoopWarden está diseñado para ser compilado y ejecutado directamente desde su código fuente en entornos Linux. Se requiere Go 1.21+ y `make` para el proceso de compilación.

### Compilación y Ejecución Segura

```bash
# Paso 1: Clonar el repositorio de LoopWarden
# Obtiene la última versión del código fuente.
git clone https://github.com/soyunomas/LoopWarden.git
cd LoopWarden

# Paso 2: Descargar dependencias y compilar el binario optimizado
# 'make deps' sincroniza los módulos de Go.
# 'make build' compila el ejecutable, optimizándolo para producción (strip symbols, no debug info).
make deps
make build

# El binario resultante se encontrará en el directorio ./bin/loopwarden

# Paso 3: Asignar Capacidades de Red (Recomendado para Seguridad)
# En lugar de ejecutar como 'root' total, se otorgan únicamente los permisos necesarios
# para abrir sockets raw ('CAP_NET_RAW'). Esto mejora la postura de seguridad.
sudo setcap cap_net_raw=+ep ./bin/loopwarden

# Paso 4: Ejecutar LoopWarden
# El binario ahora puede ser ejecutado por un usuario no-root, leyendo la configuración.
# Asegúrate de ajustar 'configs/config.toml' según tu entorno.
./bin/loopwarden -config configs/config.toml
```

### Despliegue como Servicio de Sistema (systemd)

Para una operación continua y robusta en producción, se recomienda desplegar LoopWarden como un servicio `systemd`.

```bash
# Paso 1: Copiar el binario a una ubicación estándar del sistema
sudo cp bin/loopwarden /usr/local/bin/

# Paso 2: Crear el directorio de configuración del servicio
sudo mkdir -p /etc/loopwarden

# Paso 3: Copiar el archivo de configuración al directorio del servicio
sudo cp configs/config.toml /etc/loopwarden/

# Paso 4: Instalar el archivo de unidad de systemd
# Esto permite que systemd gestione el inicio, reinicio y monitoreo de LoopWarden.
sudo cp deploy/systemd/loopwarden.service /etc/systemd/system/

# Paso 5: Recargar systemd, habilitar y arrancar el servicio
# 'daemon-reload' actualiza systemd con la nueva unidad.
# 'enable --now' habilita el servicio para que inicie en el arranque y lo arranca de inmediato.
sudo systemctl daemon-reload
sudo systemctl enable --now loopwarden
```

### Tuning para Alto Rendimiento (>10Gbps)

Para interfaces de red de alta velocidad (10Gbps o superior) en entornos de alta carga (ej. Core Routers, DMZ) o bajo ataques masivos, optimizar el subsistema de red del Kernel es fundamental para evitar la pérdida de paquetes.

1.  **Ajuste del Ring Buffer de la NIC:**
    *   **Comando:** `ethtool -G <nombre_interfaz> rx <tamaño_buffer>`
    *   **Ejemplo:** `sudo ethtool -G eno1 rx 4096`
    *   **Descripción:** Aumenta el tamaño del "anillo" de memoria (Ring Buffer) que la tarjeta de red utiliza para almacenar paquetes antes de que el Kernel los procese. Un buffer más grande reduce las caídas de paquetes (`rx_dropped`) bajo picos de tráfico. El valor óptimo es específico de cada NIC y su driver.

2.  **Ajuste de Buffers del Kernel para Sockets:**
    *   **Comandos:**
        *   `sudo sysctl -w net.core.rmem_max=26214400`
        *   `sudo sysctl -w net.core.rmem_default=26214400`
    *   **Descripción:** `rmem_max` y `rmem_default` controlan el tamaño máximo y por defecto del buffer de recepción para todos los sockets del Kernel. Valores más altos (aquí 25MB) permiten que los sockets raw de LoopWarden acumulen más datos en el Kernel antes de que la aplicación Go necesite leerlos, reduciendo el riesgo de sobrecarga del procesador y garantizando la captura completa incluso bajo tormentas severas. Para que sean permanentes, añadir al `/etc/sysctl.conf`.

> **¿Por qué LoopWarden si ya tengo STP?**
> Spanning Tree (STP/RSTP) es lento en converger y a menudo falla en "Edge Ports" donde los usuarios conectan switches no gestionados o cometen errores de cableado. LoopWarden detecta bucles, tormentas y anomalías de topología en **milisegundos**, proporcionando la telemetría que a los switches les falta.

## 🏗️ Arquitectura "Fast-Path"

LoopWarden está diseñado para procesar tráfico a velocidad de línea sin ahogar la CPU:

```text
[ NETWORK WIRE ] <=== (10Gbps+)
      ||
[ NIC HARDWARE ]
      ||
[ KERNEL RING ] <--- (AF_PACKET RX_RING)
      ||
[ BPF FILTER ]  <--- "Drop Unicast. Keep Broadcast/Multicast/ARP/Tagged"
      ||
[ GO RUNTIME ]  <--- (Zero-Copy Read)
      ||
      +--> [ Engine ] (Parallel Processing)
             ||
             +-- 1. ActiveProbe (Injection)
             +-- 2. EtherFuse (Payload Hash)
             +-- 3. MacStorm (Velocity Check)
             +-- 4. FlapGuard (Topology Check)
             +-- 5. ArpWatchdog (Protocol Check)
             ||
[ NOTIFIER ] <-- (Global Deduplication & Throttling)
      ||
[ ALERTS ] ----> Slack / Syslog / Email
```



## 📜 Licencia

MIT License. Copyright (c) 2025 soyunomas.
