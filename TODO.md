# 📋 TODO - LoopWarden Roadmap

Este documento contiene las mejoras propuestas para LoopWarden, priorizadas por ROI (Valor vs Esfuerzo).

---

## 📊 Análisis de ROI (Valor vs Esfuerzo)

| # | Feature | Valor | Esfuerzo | Rating | Veredicto |
|---|---------|-------|----------|--------|-----------|
| **9** | Correlación Multi-Motor | 🔥🔥🔥🔥🔥 | Bajo | **A+** | **IMPLEMENTAR YA** |
| **1A** | Root Bridge Inconsistente | 🔥🔥🔥🔥 | Medio | **A** | Vale la pena |
| **5** | VLAN Leakage Detection | 🔥🔥🔥🔥 | Bajo | **A** | Ya tienes el 80% hecho |
| **1B** | STP TC Storm | 🔥🔥🔥 | Bajo | **B+** | Fácil win |
| **7** | DHCP Starvation | 🔥🔥🔥 | Bajo | **B+** | Extensión natural |
| **3** | Time-of-Flight RTT | 🔥🔥🔥 | Muy Bajo | **B+** | 10 líneas de código |
| **6** | LACP Inconsistente | 🔥🔥🔥 | Medio | **B** | Nicho pero útil |
| **N1** | Native VLAN Mismatch | 🔥🔥🔥🔥 | Bajo | **A-** | Extensión de Neighbor |
| **N2** | Duplex/Speed Mismatch | 🔥🔥🔥 | Muy Bajo | **B+** | Ya tienes los datos |
| **N3** | Dark Port Detection | 🔥🔥🔥 | Bajo | **B** | Útil para seguridad |
| **N4** | Gratuitous ARP Flood | 🔥🔥🔥🔥 | Bajo | **A-** | 90% código existe |
| **N5** | MTU/Jumbo Anomaly | 🔥🔥 | Muy Bajo | **B** | Quick win |
| **N6** | Broadcast Ratio Alert | 🔥🔥🔥 | Muy Bajo | **B+** | Alerta temprana |
| **N7** | Loop Fingerprint Export | 🔥🔥🔥 | Bajo | **B+** | Valor forense |
| **4** | Microloops | 🔥🔥 | Alto | **C+** | Purista, difícil de probar |
| **2** | Unicast Sampling | 🔥🔥 | Alto | **C** | Rompe arquitectura BPF |
| **8** | IGMP/MLD Chaos | 🔥🔥 | Medio | **C** | Muy nicho (IPTV) |
| **10** | Auto-mitigación | 🔥 | Medio | **D** | Peligroso, liability |
| **Bonus** | Loop Replay | 🔥🔥 | Medio | **C+** | Nice-to-have |

---

## ✅ TIER 1: Implementar Primero (Alto ROI, Bajo Esfuerzo)

### 9. Meta-Engine de Correlación Multi-Motor
**Prioridad:** 🔴 CRÍTICA  
**Esfuerzo:** 2-3 horas  
**Valor:** Reduce falsos positivos dramáticamente

#### Descripción
Crear un motor que correlacione alertas de múltiples engines. Si 2+ motores disparan en ventana de <2 segundos, elevar severidad a "CONFIRMED".

#### Dónde implementar
- **Nuevo archivo:** `internal/detector/meta_engine.go`

#### Estructura sugerida
```go
package detector

type MetaEngine struct {
    mu          sync.Mutex
    recentHits  map[string][]time.Time  // engine_name -> timestamps
    window      time.Duration           // default 2s
    threshold   int                     // default 2 engines
    notify      *notifier.Notifier
    ifaceName   string
}

func NewMetaEngine(notify *notifier.Notifier, ifaceName string) *MetaEngine

// Llamado por otros engines cuando disparan
func (me *MetaEngine) RecordHit(engineName string, threatType string)

// Evalúa si hay correlación
func (me *MetaEngine) evaluateCorrelation() bool
```

#### Cambios necesarios
1. **`internal/detector/engine.go`:**
   - Añadir `metaEngine *MetaEngine` al struct `Engine`
   - Instanciar en `NewEngine()`
   - Exponer método para que algoritmos reporten hits

2. **Todos los `algo_*.go`:**
   - Después de cada `telemetry.EngineHits.WithLabelValues()`, llamar:
   ```go
   engine.metaEngine.RecordHit("EtherFuse", "LoopDetected")
   ```

3. **Configuración** (`internal/config/config.go`):
   ```go
   type MetaEngineConfig struct {
       Enabled   bool   `toml:"enabled"`
       Window    string `toml:"window"`     // default "2s"
       Threshold int    `toml:"threshold"`  // default 2
   }
   ```

#### Alerta generada
```
[MetaEngine] 🚨 CONFIRMED LOOP - MULTI-SIGNAL DETECTION!
    INTERFACE:   eno1
    SIGNALS:     EtherFuse (LoopDetected), ActiveProbe (HardLoop), FlapGuard (MacFlapping)
    WINDOW:      1.2s
    CONFIDENCE:  HIGH
    CONNECTED:   Switch-Core-01, Port Gi1/0/48
```

---

### 3. Time-of-Flight RTT Classification
**Prioridad:** 🟠 ALTA  
**Esfuerzo:** 30 minutos  
**Valor:** Localización física del bucle

#### Descripción
Añadir timestamp al payload de ActiveProbe. Al recibir la propia sonda, calcular RTT y clasificar distancia.

#### Dónde implementar
- **Archivo:** `internal/detector/algo_active_probe.go`

#### Cambios en `Start()` (línea ~87)
```go
// ANTES:
fullPayload := fmt.Sprintf("%s|%s|%s", ap.cfg.MagicPayload, ap.ifaceName, ap.domain)

// DESPUÉS:
timestamp := time.Now().UnixNano()
fullPayload := fmt.Sprintf("%s|%s|%s|%d", ap.cfg.MagicPayload, ap.ifaceName, ap.domain, timestamp)
```

#### Cambios en `OnPacket()` (línea ~149)
```go
// Después de parsear parts[]
var rttClassification string
if len(parts) >= 4 {
    if sentNano, err := strconv.ParseInt(string(parts[3]), 10, 64); err == nil {
        rttNano := time.Now().UnixNano() - sentNano
        rttDuration := time.Duration(rttNano)
        
        switch {
        case rttDuration < 50*time.Microsecond:
            rttClassification = "SAME RACK (patch cord)"
        case rttDuration < 500*time.Microsecond:
            rttClassification = "ACCESS LAYER"
        case rttDuration < 2*time.Millisecond:
            rttClassification = "DISTRIBUTION LAYER"
        default:
            rttClassification = "CORE / CAMPUS"
        }
    }
}

// Añadir a alertMsg:
alertMsg += fmt.Sprintf("\n    RTT:         %v (%s)", rttDuration, rttClassification)
```

---

### 5. VLAN Leakage Detection (cruce de datos existentes)
**Prioridad:** 🟠 ALTA  
**Esfuerzo:** 1-2 horas  
**Valor:** Detección de misconfiguraciones críticas

#### Descripción
Cruzar datos de `TopologyStore`, `FlapGuard` y `ActiveProbe` para detectar tráfico cruzando VLANs que no deberían coexistir.

#### Dónde implementar
- **Nuevo archivo:** `internal/detector/algo_vlan_leak.go`

#### Lógica
```go
type VlanLeakDetector struct {
    store        *TopologyStore
    macVlanMap   map[[6]byte]map[uint16]time.Time  // MAC -> VLAN -> lastSeen
    ifaceName    string
    notify       *notifier.Notifier
    
    // Config
    alertIfVlanPairs map[uint16][]uint16  // VLANs que NO deben cruzarse
}

func (vl *VlanLeakDetector) OnPacket(data []byte, length int, vlanID uint16) {
    var srcMac [6]byte
    copy(srcMac[:], data[6:12])
    
    // Si esta MAC ya fue vista en otra VLAN "prohibida"
    if seenVlans, exists := vl.macVlanMap[srcMac]; exists {
        for previousVlan := range seenVlans {
            if vl.isProhibitedPair(previousVlan, vlanID) {
                // ALERTA: VLAN Leakage detectado
            }
        }
    }
}
```

#### Configuración
```toml
[algorithms.vlan_leak]
enabled = true
# Pares de VLANs que NUNCA deberían compartir tráfico
prohibited_pairs = [
    [10, 20],   # Servidores vs Usuarios
    [100, 200], # Producción vs Desarrollo
]
alert_cooldown = "60s"
```

---

### N4. Gratuitous ARP Flood Detection
**Prioridad:** 🟠 ALTA  
**Esfuerzo:** 30 minutos  
**Valor:** Detecta IP conflicts, VRRP flapping, ARP poisoning

#### Descripción
Detectar flood de Gratuitous ARP (sender IP == target IP).

#### Dónde implementar
- **Archivo:** `internal/detector/algo_arpwatch.go`

#### Cambios en `OnPacket()` (después de línea ~139)
```go
// Ya tienes: opCode := binary.BigEndian.Uint16(data[arpBase+6 : arpBase+8])

// Añadir detección de GARP:
senderIP := data[arpBase+14 : arpBase+18]
targetIP := data[arpBase+24 : arpBase+28]

isGratuitous := bytes.Equal(senderIP, targetIP)

if isGratuitous {
    // Contar en estructura separada
    aw.garpCounter[srcMacKey]++
    
    if aw.garpCounter[srcMacKey] > aw.garpThreshold {
        // Alerta: GARP Flood
        // Causas: VRRP/HSRP flapping, VM migration, IP conflict, ARP poisoning
    }
}
```

#### Configuración adicional en `config.go`
```go
type ArpWatchConfig struct {
    // ... existentes ...
    GarpThreshold   uint64 `toml:"garp_threshold"`    // default 50/s
    GarpAlertTypes  bool   `toml:"garp_alert_types"`  // distinguir causa
}
```

---

### N1. Native VLAN Mismatch Detection
**Prioridad:** 🟠 ALTA  
**Esfuerzo:** 1 hora  
**Valor:** Causa común de bucles silenciosos

#### Descripción
Comparar VLAN nativa anunciada por LLDP/CDP vs VLAN observada en paquetes.

#### Dónde implementar
- **Archivo:** `internal/detector/algo_neighbor.go`

#### Cambios en `parseLLDP()` y `parseCDP()`
```go
// LLDP TLV Type 127 (Org-Specific) con OUI 00-80-C2 contiene Port VLAN ID
// CDP TLV 0x000A contiene Native VLAN

// Añadir campo a NeighborInfo:
type NeighborInfo struct {
    // ... existentes ...
    NativeVLAN    uint16  // VLAN nativa anunciada por vecino
}
```

#### Nuevo método de validación
```go
func (nd *NeighborDiscovery) validateVlanConsistency(advertisedVlan, observedVlan uint16) {
    if advertisedVlan != 0 && observedVlan != 0 && advertisedVlan != observedVlan {
        // ALERTA: Native VLAN Mismatch
        msg := fmt.Sprintf("[NeighborDiscovery] ⚠️ NATIVE VLAN MISMATCH!\n"+
            "    INTERFACE:     %s\n"+
            "    ADVERTISED:    VLAN %d (from LLDP/CDP)\n"+
            "    OBSERVED:      VLAN %d (from traffic)\n"+
            "    RISK:          Traffic leaking between VLANs",
            nd.ifaceName, advertisedVlan, observedVlan)
        nd.notify.Alert(msg)
    }
}
```

---

### N6. Broadcast Ratio Alert (Alerta Temprana)
**Prioridad:** 🟡 MEDIA-ALTA  
**Esfuerzo:** 20 minutos  
**Valor:** Detectar problemas antes del colapso

#### Descripción
Alertar si el ratio de broadcast supera umbral (ej: 30%), aunque no sea "storm" todavía.

#### Dónde implementar
- **Archivo:** `internal/detector/algo_etherfuse.go` (o nuevo `algo_ratio_monitor.go`)

#### Implementación
```go
type RatioMonitor struct {
    bcastCount   uint64
    totalCount   uint64
    threshold    float64  // default 0.30 (30%)
    lastCheck    time.Time
    // ...
}

func (rm *RatioMonitor) OnPacket(data []byte, length int, vlanID uint16) {
    rm.totalCount++
    
    if data[0] == 0xFF { // Broadcast
        rm.bcastCount++
    }
    
    // Cada segundo, evaluar ratio
    if time.Since(rm.lastCheck) > time.Second {
        ratio := float64(rm.bcastCount) / float64(rm.totalCount)
        
        if ratio > rm.threshold {
            // ALERTA: Alto ratio de broadcast (pre-storm warning)
        }
        
        rm.bcastCount = 0
        rm.totalCount = 0
        rm.lastCheck = time.Now()
    }
}
```

---

## ⚠️ TIER 2: Considerar (Buen Valor, Esfuerzo Moderado)

### 1A. Root Bridge Inconsistency Detection
**Prioridad:** 🟡 MEDIA  
**Esfuerzo:** 3-4 horas  
**Valor:** Detección avanzada de STP mal configurado

#### Descripción
Parsear BPDUs (802.1D/802.1w) para detectar:
- Dos Root Bridge distintos en la misma VLAN
- Cambio de Root demasiado frecuente

#### Dónde implementar
- **Nuevo archivo:** `internal/detector/algo_stp_monitor.go`

#### Estructura
```go
package detector

const (
    EtherTypeSTP = 0x0000  // LLC con DSAP/SSAP 0x42
    BPDUTypeTCN  = 0x80
    BPDUTypeRSTP = 0x02
)

type STPMonitor struct {
    rootBridges    map[uint16]*RootInfo  // VLAN -> RootInfo
    tcCounter      map[uint16]uint64     // VLAN -> TC count per second
    rootChanges    map[uint16][]time.Time
    notify         *notifier.Notifier
    ifaceName      string
    
    // Config
    maxRootChanges int           // default 3
    rootWindow     time.Duration // default 60s
    maxTCPerSec    uint64        // default 10
}

type RootInfo struct {
    RootID       [8]byte   // Priority (2) + MAC (6)
    RootPriority uint16
    RootMAC      net.HardwareAddr
    LastSeen     time.Time
}

func (sm *STPMonitor) OnPacket(data []byte, length int, vlanID uint16) {
    // 1. Detectar si es BPDU (LLC DSAP=0x42, SSAP=0x42)
    // 2. Parsear Root Bridge ID
    // 3. Detectar TC bit
    // 4. Comparar con estado anterior
}
```

#### Alertas
```
[STPMonitor] 🌳 ROOT BRIDGE CONFLICT DETECTED!
    INTERFACE:   eno1
    VLAN:        10
    ROOT 1:      32768:aa:bb:cc:dd:ee:ff (seen 2s ago)
    ROOT 2:      32768:11:22:33:44:55:66 (just seen)
    IMPACT:      STP convergence failure, possible loop

[STPMonitor] 🌳 TOPOLOGY CHANGE STORM!
    INTERFACE:   eno1
    VLAN:        10
    TC RATE:     47/sec (threshold: 10)
    IMPACT:      CAM table thrashing, CPU spike on switches
```

---

### 1B. STP Topology Change Storm
**Prioridad:** 🟡 MEDIA  
**Esfuerzo:** Incluido en 1A  
**Valor:** Alerta temprana de inestabilidad

#### Descripción
Contar TC bits en BPDUs. Alta frecuencia indica problemas.

#### Implementación
Ver 1A - es parte del mismo motor.

---

### 7. DHCP Starvation Detection
**Prioridad:** 🟡 MEDIA  
**Esfuerzo:** 1 hora  
**Valor:** Detecta ataques y síntomas de bucles

#### Dónde implementar
- **Archivo:** `internal/detector/algo_dhcp_hunter.go`

#### Cambios
```go
type DhcpHunter struct {
    // ... existentes ...
    discoverCounter map[[6]byte]uint64  // MAC -> DISCOVER count
    uniqueMacsPerSec int                 // Counter de MACs únicas
    
    // Config
    starvationThreshold int  // default 50 DISCOVER/sec de MACs únicas
}

func (d *DhcpHunter) OnPacket(data []byte, length int, vlanID uint16) {
    // Detectar DHCP DISCOVER (opción 53 = 1)
    // Si muchos DISCOVER de MACs aleatorias → starvation attack
    
    // También detectar:
    // - Gateway anómalo en DHCP ACK
    // - Lease time sospechoso (muy corto = ataque, muy largo = miscfg)
}
```

---

### N2. Duplex/Speed Mismatch Detection
**Prioridad:** 🟡 MEDIA  
**Esfuerzo:** 30 minutos  
**Valor:** Detecta causa de packet loss intermitente

#### Dónde implementar
- **Archivo:** `internal/detector/algo_neighbor.go`

#### Cambios en `NeighborInfo`
```go
type NeighborInfo struct {
    // ... existentes ...
    AutoNeg       bool
    Speed         uint32  // Mbps
    Duplex        string  // "full" / "half"
}
```

#### En `parseLLDP()`
```go
// LLDP TLV Type 127 con OUI 00-12-0F (IEEE 802.3) contiene MAC/PHY config
case 127:  // Organizationally Specific
    if len(value) >= 5 {
        oui := value[0:3]
        if bytes.Equal(oui, []byte{0x00, 0x12, 0x0F}) {
            subtype := value[3]
            if subtype == 1 { // MAC/PHY Config
                // Parsear autoneg, speed, duplex
            }
        }
    }
```

#### Alerta
```
[NeighborDiscovery] ⚠️ DUPLEX MISMATCH RISK!
    INTERFACE:   eno1
    LOCAL:       1000Mbps Full-Duplex (assumed)
    REMOTE:      100Mbps Half-Duplex (from LLDP)
    SWITCH:      Switch-Old-01, Port Fa0/24
    IMPACT:      Late collisions, packet loss, "phantom loop" symptoms
```

---

### N3. Dark Port Detection
**Prioridad:** 🟡 MEDIA  
**Esfuerzo:** 45 minutos  
**Valor:** Seguridad y visibilidad

#### Descripción
Alertar si una interfaz configurada nunca recibe LLDP/CDP.

#### Dónde implementar
- **Archivo:** `internal/detector/topology_store.go`

#### Cambios
```go
type TopologyStore struct {
    // ... existentes ...
    configuredIfaces []string           // Interfaces que DEBERÍAN tener vecino
    darkPortTimeout  time.Duration      // default 5 min
    notify           *notifier.Notifier
}

func (ts *TopologyStore) CheckDarkPorts() {
    ts.mu.RLock()
    defer ts.mu.RUnlock()
    
    for _, iface := range ts.configuredIfaces {
        if _, exists := ts.neighbors[iface]; !exists {
            // ALERTA: Dark port - sin LLDP/CDP recibido
        }
    }
}

// Llamar desde StartCleanup() cada minuto
```

---

### N7. Loop Fingerprint Export
**Prioridad:** 🟡 MEDIA  
**Esfuerzo:** 1 hora  
**Valor:** Forense y evidencia

#### Descripción
Cuando se detecta un bucle, generar JSON exportable con toda la evidencia.

#### Dónde implementar
- **Nuevo archivo:** `internal/detector/fingerprint.go`

#### Estructura
```go
type LoopFingerprint struct {
    Timestamp     time.Time         `json:"timestamp"`
    Interface     string            `json:"interface"`
    VLAN          uint16            `json:"vlan"`
    DetectedBy    []string          `json:"detected_by"`  // engines que dispararon
    SourceMAC     string            `json:"source_mac"`
    DestMAC       string            `json:"dest_mac"`
    PayloadHash   string            `json:"payload_hash"`
    RTT           *time.Duration    `json:"rtt,omitempty"`
    Neighbor      *NeighborInfo     `json:"neighbor,omitempty"`
    Confidence    string            `json:"confidence"`  // LOW/MEDIUM/HIGH
    RawPacket     string            `json:"raw_packet_b64,omitempty"`  // base64
}

func (lf *LoopFingerprint) ToJSON() ([]byte, error)
func (lf *LoopFingerprint) SaveToFile(path string) error
```

#### Uso
```go
// En cada motor, cuando detecta bucle:
fingerprint := &LoopFingerprint{
    Timestamp:  time.Now(),
    Interface:  ifaceName,
    DetectedBy: []string{"EtherFuse"},
    // ...
}
go fingerprint.SaveToFile("/var/log/loopwarden/fingerprints/")
```

#### Endpoint API
```go
// En main.go, añadir:
http.HandleFunc("/fingerprints", func(w http.ResponseWriter, r *http.Request) {
    // Listar últimos N fingerprints
})
```

---

### N5. MTU/Jumbo Frame Anomaly
**Prioridad:** 🟢 BAJA-MEDIA  
**Esfuerzo:** 15 minutos  
**Valor:** Quick win

#### Dónde implementar
- **Archivo:** `internal/telemetry/metrics.go` o nuevo motor

#### Implementación
```go
// En TrackPacket(), añadir:
const StandardMTU = 1518

if length > StandardMTU {
    // Log warning o incrementar contador
    JumboFrames.WithLabelValues(ifaceName).Inc()
    
    // Si interfaz no está en whitelist de jumbo:
    if !isJumboAllowed(ifaceName) {
        // Alerta: Jumbo frame en interfaz estándar
    }
}
```

---

### 6. LACP Inconsistency Detection
**Prioridad:** 🟢 BAJA  
**Esfuerzo:** 2-3 horas  
**Valor:** Nicho pero útil para troubleshooting

#### Dónde implementar
- **Nuevo archivo:** `internal/detector/algo_lacp_monitor.go`

#### Descripción
Parsear LACP frames (01:80:c2:00:00:02) y detectar:
- Mismo System ID pero diferente Key
- Estado Actor/Partner inconsistente
- LACP timeout sin respuesta

---

## ❌ TIER 3: Evitar o Posponer

### 4. Microloops Detection
**Razón:** Muy difícil de reproducir y testear. Alto riesgo de falsos positivos.

### 2. Unicast Sampling
**Razón:** Rompe la premisa de rendimiento del filtro BPF. Cambio arquitectónico mayor.

### 8. IGMP/MLD Chaos Detector
**Razón:** Muy nicho (solo IPTV/enterprise WiFi). Bajo ROI para mayoría de usuarios.

### 10. Auto-mitigación
**Razón:** 🚨 PELIGROSO
- Liability legal si causa outage en producción
- Los switches ya tienen storm-control
- Un bug = outage autoinfligido
- Si se implementa, DEBE ser opt-in con muchas advertencias

### Bonus. Loop Replay
**Razón:** Nice-to-have pero no crítico. Considerar después de Tier 1 y 2.

---

## 📅 Plan de Implementación Sugerido

### Fase 1 (1-2 días) ✅ COMPLETADA
- [x] #9 - Meta-Engine Correlación
- [x] #3 - Time-of-Flight RTT
- [x] N6 - Broadcast Ratio Alert

### Fase 2 (2-3 días) ✅ COMPLETADA
- [x] #5 - VLAN Leakage Detection
- [x] N4 - Gratuitous ARP Flood
- [x] N1 - Native VLAN Mismatch

### Fase 3 (3-4 días)
- [ ] #1A + #1B - STP Monitor (Root Bridge + TC Storm)
- [ ] #7 - DHCP Starvation
- [ ] N7 - Loop Fingerprint Export

### Fase 4 (Opcional)
- [ ] N2 - Duplex/Speed Mismatch
- [ ] N3 - Dark Port Detection
- [ ] N5 - MTU Anomaly
- [ ] #6 - LACP Monitor

---

## 📝 Notas para el Desarrollador

### Patrones a seguir
1. **Cada algoritmo implementa la interfaz `Algorithm`:**
   ```go
   type Algorithm interface {
       Name() string
       Start(conn *packet.Conn, iface *net.Interface) error
       OnPacket(data []byte, length int, vlanID uint16)
   }
   ```

2. **Configuración con Overrides:**
   - Definir struct en `internal/config/config.go`
   - Añadir a `AlgorithmConfig`
   - Soportar `Overrides map[string]XxxOverride`

3. **Alertas asíncronas:**
   ```go
   go func() {
       notify.Alert(msg)
   }()
   ```

4. **Telemetría:**
   ```go
   telemetry.EngineHits.WithLabelValues(ifaceName, "EngineName", "ThreatType").Inc()
   ```

5. **Thread-safety:**
   - Usar `sync.Mutex` o `sync.RWMutex`
   - Capturar variables antes de goroutines

### Archivos clave a conocer
| Archivo | Propósito |
|---------|-----------|
| `internal/detector/engine.go` | Orquestador de algoritmos |
| `internal/detector/topology_store.go` | Estado compartido de vecinos |
| `internal/config/config.go` | Todas las estructuras de config |
| `internal/notifier/notifier.go` | Sistema de alertas |
| `internal/telemetry/metrics.go` | Métricas Prometheus |

### Comandos útiles
```bash
# Compilar y testear
make build && make test

# Ejecutar con debug
sudo ./bin/loopwarden -config configs/config.toml

# Ver métricas
curl localhost:9090/metrics | grep loopwarden

# Ver topología
curl localhost:9090/topology | jq
```
