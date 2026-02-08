# AGENTS.md - LoopWarden

## 📋 Descripción General del Proyecto

**LoopWarden** es un Detector de Bucles Ethernet (L2 Loop Detector) de alto rendimiento escrito en Go. Monitoriza la red en tiempo real para detectar bucles físicos, tormentas de broadcast, servidores DHCP fraudulentos, y otras anomalías de Capa 2 en milisegundos.

- **Lenguaje:** Go 1.25+
- **Plataforma:** Linux (requiere sockets RAW y capacidades `CAP_NET_RAW`)
- **Licencia:** MIT
- **Arquitectura:** Fast-Path con múltiples motores de detección concurrentes

---

## 🏗️ Estructura del Proyecto

```
loopwarden-main/
├── bin/                          # Binarios compilados
│   └── loopwarden                # Ejecutable principal
├── cmd/
│   └── loopwarden/
│       └── main.go               # Punto de entrada de la aplicación
├── configs/
│   └── config.toml               # Configuración principal (TOML)
├── deploy/
│   └── systemd/
│       └── loopwarden.service    # Unidad systemd para despliegue
├── internal/
│   ├── config/
│   │   └── config.go             # Parsing y estructuras de configuración
│   ├── detector/
│   │   ├── engine.go             # Orquestador de algoritmos de detección
│   │   ├── topology_store.go     # Almacén de topología (vecinos LLDP/CDP)
│   │   ├── algo_active_probe.go  # Motor 1: Inyección activa de sondas
│   │   ├── algo_etherfuse.go     # Motor 2: Detección de payloads repetidos
│   │   ├── algo_mac_storm.go     # Motor 3: Límite de tráfico por MAC
│   │   ├── algo_flapguard.go     # Motor 4: Detección de MAC flapping
│   │   ├── algo_arpwatch.go      # Motor 5: Monitorización ARP
│   │   ├── algo_dhcp_hunter.go   # Motor 6: Detección DHCP Rogue
│   │   ├── algo_flow_panic.go    # Motor 7: Detección PAUSE Frames
│   │   ├── algo_ra_guard.go      # Motor 8: IPv6 RA Guard
│   │   ├── algo_mcast_policer.go # Motor 9: Policer de Multicast
│   │   ├── algo_neighbor.go      # Motor 0: Descubrimiento LLDP/CDP
│   │   ├── algo_neighbor_test.go # Tests del motor neighbor
│   │   └── detector_test.go      # Tests del detector
│   ├── notifier/
│   │   └── notifier.go           # Sistema de alertas multi-canal
│   ├── sniffer/
│   │   └── sniffer.go            # Captura de paquetes con BPF
│   ├── telemetry/
│   │   └── metrics.go            # Métricas Prometheus
│   └── utils/
│       └── protocol_mapper.go    # Clasificación de MACs y protocolos
├── sniffer_debug_neighbors.go    # Herramienta debug LLDP/CDP
├── traffic_gen.go                # Generador de tráfico de prueba
├── go.mod                        # Dependencias Go
├── go.sum                        # Checksums de dependencias
├── Makefile                      # Comandos de compilación
├── README.md                     # Documentación principal
└── LICENSE                       # Licencia MIT
```

---

## 🔧 Comandos Frecuentes

```bash
# Gestión de dependencias
make deps                    # Sincroniza go.mod y verifica dependencias

# Compilación
make build                   # Compila binario optimizado en ./bin/loopwarden
make all                     # deps + build

# Ejecución
make run                     # Compila y ejecuta con sudo

# Verificación de código
make lint                    # Ejecuta go vet
make test                    # Ejecuta tests y benchmarks

# Limpieza
make clean                   # Elimina binarios y artefactos

# Ayuda
make help                    # Muestra todos los targets disponibles
```

### Ejecución Manual

```bash
# Con capacidades (recomendado)
sudo setcap cap_net_raw=+ep ./bin/loopwarden
./bin/loopwarden -config configs/config.toml

# Como root
sudo ./bin/loopwarden -config configs/config.toml
```

---

## 📁 Descripción Detallada de Archivos

### `/cmd/loopwarden/main.go`

**Propósito:** Punto de entrada principal de la aplicación.

**Funcionalidad:**
1. Parsea argumentos de línea de comandos (`-config`)
2. Carga la configuración desde archivo TOML
3. Inicializa el sistema de logging
4. Crea el notificador de alertas
5. Inicializa el TopologyStore (compartido entre motores)
6. Lanza goroutines paralelas para cada interfaz de red
7. Inicia servidor HTTP para métricas Prometheus y API de topología
8. Gestiona señales de sistema (SIGINT, SIGTERM) para shutdown graceful

**Entradas:**
- `-config string`: Ruta al archivo de configuración (default: `configs/config.toml`)

**Salidas:**
- Logs a consola o archivo según configuración
- Servidor HTTP en puerto configurado (default `:9090`) con:
  - `/metrics`: Métricas Prometheus
  - `/topology`: JSON con información de vecinos LLDP/CDP

**Dependencias Internas:**
- `internal/config`
- `internal/detector`
- `internal/notifier`
- `internal/sniffer`

---

### `/internal/config/config.go`

**Propósito:** Define todas las estructuras de configuración y carga el archivo TOML.

**Estructuras Principales:**

| Estructura | Descripción |
|------------|-------------|
| `Config` | Raíz de configuración con System, Network, Algorithms, Alerts, Telemetry |
| `SystemConfig` | `sensor_name`, `log_file` |
| `NetworkConfig` | `interfaces []string`, `snaplen int` |
| `AlgorithmConfig` | Contiene configuración de los 10 motores de detección |
| `AlertsConfig` | Configuración de notificaciones (Syslog, Webhook, SMTP, Telegram) |
| `TelemetryConfig` | Configuración del servidor Prometheus |

**Patrón Override:**
Cada algoritmo tiene su configuración base y un mapa `Overrides map[string]XxxOverride` que permite sobrescribir valores por interfaz.

**Función Principal:**
```go
func LoadConfig(path string) (*Config, error)
```
- **Entrada:** Ruta al archivo TOML
- **Salida:** Puntero a Config o error

---

### `/internal/sniffer/sniffer.go`

**Propósito:** Captura de paquetes de red usando sockets RAW con filtros BPF.

**Función Principal:**
```go
func Run(ctx context.Context, ifaceName string, cfg *config.Config, engine *detector.Engine) error
```

**Flujo de Ejecución:**
1. Abre socket RAW en la interfaz especificada
2. Activa modo promiscuo
3. Aplica filtro BPF (solo tráfico Multicast/Broadcast)
4. Inicia monitor de drops del kernel
5. Loop de lectura con timeout de 1 segundo
6. Extrae VLAN ID si hay tag 802.1Q
7. Despacha paquetes al Engine

**Filtro BPF:**
```
Permite: Multicast (bit 0 de MAC destino = 1)
Incluye: Broadcast, IPv4 Multicast, IPv6 Multicast, STP, LLDP, CDP
Descarta: Unicast (optimización de rendimiento)
```

**Entradas:**
- `ctx`: Context para cancelación
- `ifaceName`: Nombre de interfaz (ej: "eno1")
- `cfg`: Configuración global
- `engine`: Motor de detección

**Salidas:**
- Error si falla la inicialización
- Métricas de telemetría actualizadas

---

### `/internal/detector/engine.go`

**Propósito:** Orquestador central de todos los algoritmos de detección.

**Interfaz Algorithm:**
```go
type Algorithm interface {
    Name() string
    Start(conn *packet.Conn, iface *net.Interface) error
    OnPacket(data []byte, length int, vlanID uint16)
}
```

**Estructura Engine:**
```go
type Engine struct {
    algorithms []Algorithm      // Lista de algoritmos activos
    cfg        *config.AlgorithmConfig
    mu         sync.RWMutex
    ifaceName  string
    store      *TopologyStore  // Store compartido entre motores
}
```

**Constructor:**
```go
func NewEngine(cfg *config.AlgorithmConfig, notify *notifier.Notifier, ifaceName string, store *TopologyStore) *Engine
```
- Inicializa todos los algoritmos habilitados según configuración
- Inyecta dependencias (notifier, store) a cada algoritmo

**Métodos:**
- `StartAll(conn, iface)`: Inicia todos los algoritmos
- `DispatchPacket(data, length, vlanID)`: Envía paquete a todos los algoritmos

---

### `/internal/detector/topology_store.go`

**Propósito:** Almacén thread-safe de información de vecinos (switches conectados).

**Estructura NeighborInfo:**
```go
type NeighborInfo struct {
    SystemName    string        // Nombre del switch
    SystemDesc    string        // Descripción del sistema
    PortID        string        // Puerto remoto (ej: "Gi1/0/48")
    ChassisID     string        // ID del chasis
    VLAN          uint16        // VLAN detectada
    ManagementIP  string        // IP de gestión del switch
    Protocol      string        // "LLDP" o "CDP"
    AdvertisedTTL time.Duration // TTL reportado
    LastSeen      time.Time     // Última actualización
}
```

**Métodos:**
| Método | Descripción |
|--------|-------------|
| `Update(ifaceName, info)` | Actualiza información de vecino para una interfaz |
| `Get(ifaceName)` | Obtiene copia del vecino (thread-safe) |
| `GetAll()` | Snapshot completo para API HTTP |
| `Prune()` | Elimina vecinos expirados según TTL |
| `StartCleanup()` | Inicia goroutine de limpieza periódica |

---

### `/internal/detector/algo_active_probe.go`

**Propósito:** Inyección activa de sondas para detección determinista de bucles.

**Mecánica:**
1. Genera trama Ethernet broadcast con EtherType `0xFFFF`
2. Payload: `MAGIC|interfaz|dominio`
3. Envía periódicamente según `interval_ms`
4. Si recibe su propia sonda:
   - Misma MAC origen → **Hard Loop** (bucle físico)
   - Mismo dominio, diferente MAC → Vecino legítimo (ignorar)
   - Diferente dominio → **Cross-Domain Loop** (cruce de VLANs)

**Configuración:**
```toml
[algorithms.active_probe]
enabled = true
interval_ms = 1000        # Frecuencia de inyección
ethertype = 65535         # 0xFFFF
magic_payload = "LOOPWARDEN_PROBE"
domain = "default"        # Identificador de red

[algorithms.active_probe.overrides.eno1]
domain = "VLAN_10"        # Override por interfaz
```

**Alertas Generadas:**
- `LOOP CONFIRMED! (Self-Loop)`
- `CRITICAL TOPOLOGY ERROR (Cross-Domain)`

---

### `/internal/detector/algo_etherfuse.go`

**Propósito:** Detección pasiva de bucles mediante análisis de payloads repetidos.

**Mecánica:**
1. Calcula hash FNV-1a de cada paquete
2. Mantiene ring buffer de hashes recientes
3. Si un hash aparece `alert_threshold` veces → bucle detectado
4. Monitor de PPS global para tormentas masivas

**Estructuras Internas:**
- `ringBuffer []uint64`: Buffer circular de hashes
- `lookupTable map[uint64]uint8`: Contador de repeticiones
- `packetsSec uint64`: Contador de PPS para detección de tormentas

**Configuración:**
```toml
[algorithms.etherfuse]
enabled = true
history_size = 4096       # Tamaño del ring buffer
alert_threshold = 200     # Repeticiones para alarma
storm_pps_limit = 15000   # PPS para tormenta global
alert_cooldown = "5s"
```

**Alertas Generadas:**
- `LOOP DETECTED (Repeated Payload)`
- `GLOBAL STORM DETECTED`

---

### `/internal/detector/algo_mac_storm.go`

**Propósito:** Rate limiting por dirección MAC origen.

**Mecánica:**
1. Mantiene contador de PPS por cada MAC origen
2. Reset cada segundo
3. Alerta si una MAC supera `max_pps_per_mac`

**Configuración:**
```toml
[algorithms.mac_storm]
enabled = true
max_pps_per_mac = 2000    # Límite por host
max_tracked_macs = 10000  # Protección OOM
alert_cooldown = "30s"
```

**Alertas Generadas:**
- `HOST FLOODING DETECTED`

---

### `/internal/detector/algo_flapguard.go`

**Propósito:** Detección de MAC flapping (cambios rápidos de VLAN).

**Mecánica:**
1. Rastrea la última VLAN vista por cada MAC
2. Si una MAC cambia de VLAN `threshold` veces en `window` → alerta

**Configuración:**
```toml
[algorithms.flap_guard]
enabled = true
threshold = 5             # Cambios permitidos
window = "1s"             # Ventana de tiempo
alert_cooldown = "30s"
```

**Alertas Generadas:**
- `TOPOLOGY CHANGE DETECTED (MAC FLAPPING)`

---

### `/internal/detector/algo_arpwatch.go`

**Propósito:** Monitorización de tráfico ARP para detectar escaneos y bucles.

**Mecánica:**
1. Cuenta ARP Requests por MAC origen
2. Rastrea IPs destino únicas
3. Modo normal: límite `max_pps`
4. Modo escaneo: si `>scan_ip_threshold` IPs → límite `scan_mode_pps`

**Patrones Detectados:**
- `SUBNET SCANNING`: Muchas IPs destino diferentes
- `SINGLE TARGET ATTACK / LOOP`: Una sola IP bombardeada
- `HIGH VOLUME ARP ANOMALY`: Volumen alto genérico

**Configuración:**
```toml
[algorithms.arp_watch]
enabled = true
max_pps = 500
scan_ip_threshold = 10
scan_mode_pps = 100
alert_cooldown = "30s"
```

---

### `/internal/detector/algo_dhcp_hunter.go`

**Propósito:** Detección de servidores DHCP no autorizados (Rogue DHCP).

**Mecánica:**
1. Analiza paquetes UDP 67→68 (DHCP Offer/ACK)
2. Verifica MAC origen contra whitelist
3. Verifica IP origen contra CIDRs autorizados

**Configuración:**
```toml
[algorithms.dhcp_hunter]
enabled = true
trusted_macs = ["00:15:5d:01:02:03"]
trusted_cidrs = ["192.168.1.0/24"]
```

**Alertas Generadas:**
- `ROGUE DHCP SERVER DETECTED`

---

### `/internal/detector/algo_flow_panic.go`

**Propósito:** Detección de inundación de PAUSE Frames (802.3x Flow Control).

**Mecánica:**
1. Detecta tramas EtherType `0x8808` con OpCode PAUSE
2. Cuenta PPS de frames de pausa
3. Alerta si supera `max_pause_pps`

**Configuración:**
```toml
[algorithms.flow_panic]
enabled = true
max_pause_pps = 50
```

**Alertas Generadas:**
- `PAUSE FRAME FLOOD (DoS)`

---

### `/internal/detector/algo_ra_guard.go`

**Propósito:** Protección contra Router Advertisements IPv6 fraudulentos.

**Mecánica:**
1. Detecta paquetes ICMPv6 tipo 134 (Router Advertisement)
2. Verifica MAC origen contra whitelist de routers autorizados

**Configuración:**
```toml
[algorithms.ra_guard]
enabled = true
trusted_macs = ["aa:bb:cc:dd:ee:ff"]
```

**Alertas Generadas:**
- `ROGUE IPv6 ROUTER ADVERTISEMENT`

---

### `/internal/detector/algo_mcast_policer.go`

**Propósito:** Rate limiting de tráfico Multicast.

**Mecánica:**
1. Detecta prefijos multicast: `01:00:5E` (IPv4) y `33:33` (IPv6)
2. Cuenta PPS de multicast
3. Alerta si supera `max_pps`

**Configuración:**
```toml
[algorithms.mcast_policer]
enabled = true
max_pps = 8000
```

**Alertas Generadas:**
- `MULTICAST STORM DETECTED`

---

### `/internal/detector/algo_neighbor.go`

**Propósito:** Descubrimiento pasivo de topología mediante LLDP y CDP.

**Mecánica:**
1. Detecta EtherType `0x88CC` (LLDP) o LLC SNAP CDP
2. Parsea TLVs para extraer:
   - System Name
   - Port ID
   - Chassis ID
   - Management IP
   - TTL
3. Actualiza TopologyStore

**Protocolos Soportados:**
- **LLDP** (Link Layer Discovery Protocol) - Estándar IEEE
- **CDP** (Cisco Discovery Protocol) - Propietario Cisco

**No genera alertas directamente**, alimenta información para otros motores.

---

### `/internal/notifier/notifier.go`

**Propósito:** Sistema de alertas multi-canal con protección anti-spam.

**Canales de Notificación:**
| Canal | Descripción |
|-------|-------------|
| Console/Log | Siempre activo |
| Syslog | UDP RFC 3164 |
| Webhook | Slack, Discord, Teams (JSON) |
| SMTP | Email con autenticación |
| Telegram | Bot API |

**Dampening (Anti-Spam):**
- `max_alerts_per_minute`: Límite de alertas antes de silenciar
- `mute_duration`: Tiempo de silencio tras activar protección
- Envía resumen al finalizar el período de silencio

**Configuración:**
```toml
[alerts.dampening]
max_alerts_per_minute = 60
mute_duration = "60s"

[alerts.webhook]
enabled = true
url = "https://hooks.slack.com/..."

[alerts.telegram]
enabled = true
token = "BOT_TOKEN"
chat_id = "-1001234567890"
```

---

### `/internal/telemetry/metrics.go`

**Propósito:** Métricas Prometheus para observabilidad.

**Métricas Expuestas:**

| Métrica | Tipo | Etiquetas | Descripción |
|---------|------|-----------|-------------|
| `loopwarden_rx_packets_total` | Counter | interface, ethertype, cast | Paquetes procesados |
| `loopwarden_rx_bytes_total` | Counter | interface, ethertype | Bytes procesados |
| `loopwarden_engine_hits_total` | Counter | interface, engine, threat_type | Alertas por motor |
| `loopwarden_processing_ns` | Histogram | interface | Latencia de procesamiento |
| `loopwarden_socket_drops_total` | Counter | interface | Drops del kernel |
| `loopwarden_packet_size_bytes` | Histogram | interface | Distribución de tamaños |
| `loopwarden_arp_ops_total` | Counter | interface, operation | Operaciones ARP |
| `loopwarden_neighbor_packets_total` | Counter | interface, protocol | Paquetes LLDP/CDP |

**Función de Tracking:**
```go
func TrackPacket(ifaceName string, data []byte, length int)
```
- Zero-allocation (rendimiento optimizado)
- Clasifica EtherType y tipo de cast

---

### `/internal/utils/protocol_mapper.go`

**Propósito:** Clasificación e identificación de direcciones MAC.

**Función Principal:**
```go
func ClassifyMAC(mac net.HardwareAddr) ProtocolInfo
```

**Retorna:**
```go
type ProtocolInfo struct {
    Name        string  // Nombre del protocolo
    Description string  // Descripción legible
    IsCritical  bool    // Afecta infraestructura
}
```

**MACs Conocidas:**
- Broadcast (`ff:ff:ff:ff:ff:ff`)
- STP, LACP, LLDP (`01:80:c2:...`)
- Cisco CDP/VTP (`01:00:0c:...`)
- IPv4/IPv6 Multicast (`01:00:5e:...`, `33:33:...`)
- HSRP, VRRP

---

### `/configs/config.toml`

**Propósito:** Archivo de configuración principal en formato TOML.

**Secciones:**
1. `[system]` - Nombre del sensor, archivo de logs
2. `[network]` - Interfaces a monitorizar, snaplen
3. `[alerts]` - Configuración de notificaciones
4. `[algorithms]` - Configuración de cada motor
5. `[telemetry]` - Servidor Prometheus

**Sistema de Overrides:**
```toml
# Configuración global
[algorithms.active_probe]
domain = "default"

# Override para interfaz específica
[algorithms.active_probe.overrides.eno1]
domain = "VLAN_10"
```

---

### `/deploy/systemd/loopwarden.service`

**Propósito:** Unidad systemd para ejecución como servicio.

**Características:**
- Ejecuta como root
- Reinicio automático (`Restart=always`)
- Límite de file descriptors elevado (`LimitNOFILE=65536`)

**Instalación:**
```bash
sudo cp loopwarden.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now loopwarden
```

---

### `/sniffer_debug_neighbors.go`

**Propósito:** Herramienta de debug para visualizar tráfico LLDP/CDP.

**Uso:**
```bash
go run sniffer_debug_neighbors.go -i eno1
```

**Salida:**
```
[15:04:05] 🟢 LLDP DETECTADO de aa:bb:cc:dd:ee:ff
   ├─ System Name: Switch-Core-01
   ├─ Port ID:    GigabitEthernet1/0/48
   ├─ Mgmt IP:    10.20.1.5
```

---

### `/traffic_gen.go`

**Propósito:** Generador de tráfico LLDP/CDP para pruebas.

**Uso:**
```bash
go run traffic_gen.go -i eno1 -d 500ms
```

**Funcionalidad:**
- Genera paquetes LLDP y CDP aleatorios
- MACs, IPs y nombres de puertos aleatorios
- Útil para probar el parser de NeighborDiscovery

---

### `/Makefile`

**Propósito:** Automatización de tareas de desarrollo.

**Targets Principales:**
| Target | Descripción |
|--------|-------------|
| `all` | deps + build |
| `build` | Compila binario optimizado (CGO_ENABLED=0) |
| `run` | Compila y ejecuta con sudo |
| `deps` | go mod tidy + verify |
| `clean` | Elimina ./bin |
| `lint` | go vet ./... |
| `test` | go test -v -bench=. ./... |

---

## 🔌 Dependencias Externas

| Paquete | Versión | Propósito |
|---------|---------|-----------|
| `github.com/BurntSushi/toml` | v1.6.0 | Parsing de configuración TOML |
| `github.com/mdlayher/packet` | v1.1.2 | Sockets RAW de bajo nivel |
| `github.com/prometheus/client_golang` | v1.23.2 | Métricas Prometheus |
| `golang.org/x/net` | v0.48.0 | Filtros BPF |

---

## 🔐 Consideraciones de Seguridad

1. **Capacidades de red:** Requiere `CAP_NET_RAW` o ejecución como root
2. **Credenciales:** Tokens de Telegram y passwords SMTP en config.toml (proteger archivo)
3. **Sin secretos en código:** Toda configuración sensible en archivo externo
4. **Whitelist explícita:** DHCP Hunter y RA Guard requieren configuración manual de MACs/CIDRs autorizados

---

## 📊 Arquitectura de Alto Rendimiento

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL SPACE                             │
│  ┌─────────────┐                                                │
│  │  NIC DRIVER │ → Ring Buffer → BPF Filter (Drop Unicast)     │
│  └─────────────┘                     │                         │
└──────────────────────────────────────┼─────────────────────────┘
                                       │ AF_PACKET
                                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                        USER SPACE (Go Runtime)                  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     SNIFFER (Hot Path)                      ││
│  │  ReadFrom() → VLAN Extract → Telemetry → Engine.Dispatch()  ││
│  └─────────────────────────────────────────────────────────────┘│
│                               │                                 │
│           ┌───────────────────┼───────────────────┐             │
│           ▼                   ▼                   ▼             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │ Stack eno1  │     │ Stack eno2  │     │ Stack vlan10│       │
│  ├─────────────┤     ├─────────────┤     ├─────────────┤       │
│  │ Neighbor    │     │ Neighbor    │     │ Neighbor    │       │
│  │ EtherFuse   │     │ EtherFuse   │     │ EtherFuse   │       │
│  │ ActiveProbe │     │ ActiveProbe │     │ ActiveProbe │       │
│  │ MacStorm    │     │ MacStorm    │     │ MacStorm    │       │
│  │ FlapGuard   │     │ FlapGuard   │     │ FlapGuard   │       │
│  │ ArpWatch    │     │ ArpWatch    │     │ ArpWatch    │       │
│  │ DhcpHunter  │     │ DhcpHunter  │     │ DhcpHunter  │       │
│  │ FlowPanic   │     │ FlowPanic   │     │ FlowPanic   │       │
│  │ RaGuard     │     │ RaGuard     │     │ RaGuard     │       │
│  │ McastPolicer│     │ McastPolicer│     │ McastPolicer│       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│           │                   │                   │             │
│           └───────────────────┼───────────────────┘             │
│                               ▼                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   NOTIFIER (Async Worker)                   ││
│  │  Channel Buffer → Dampening → Webhook/Syslog/SMTP/Telegram  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   HTTP SERVER (:9090)                       ││
│  │  /metrics (Prometheus)  │  /topology (JSON)                 ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Convenciones de Código

1. **Arquitectura Shared-Nothing:** Cada interfaz tiene su propio stack de detección
2. **Zero-Allocation Hot Path:** Evitar allocaciones en el loop de paquetes
3. **Goroutines para alertas:** Las notificaciones son asíncronas
4. **Mutex por estructura:** Cada algoritmo gestiona su propio estado
5. **Overrides:** Sistema jerárquico Global → Por-Interfaz
6. **Cooldowns:** Todos los algoritmos implementan anti-spam

---

## 🧪 Testing

```bash
# Ejecutar todos los tests
make test

# Tests específicos
go test -v ./internal/detector/...

# Benchmarks
go test -bench=. ./internal/detector/
```

---

## 📡 Endpoints API

### GET /metrics
Métricas Prometheus en formato text/plain.

### GET /topology
```json
{
  "timestamp": "2025-02-07T10:00:00Z",
  "sensor": "LoopWarden-Core-Stack",
  "neighbor_count": 2,
  "neighbors": {
    "eno1": {
      "SystemName": "Switch-Core-01",
      "PortID": "GigabitEthernet1/0/48",
      "ManagementIP": "10.20.1.5",
      "Protocol": "LLDP"
    }
  }
}
```

---

## 📝 Notas para Desarrolladores

- El filtro BPF es crítico para rendimiento en redes de alta velocidad
- TopologyStore es thread-safe y compartido entre todos los motores
- Los algoritmos reciben paquetes en paralelo (RWMutex en Engine)
- Siempre capturar variables para goroutines antes de liberarlas
- El sistema soporta shutdown graceful mediante Context
