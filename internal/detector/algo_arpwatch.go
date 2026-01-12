package detector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

const (
	EtherTypeARP     = 0x0806
	// Fix: Reintroducimos EtherTypeIPv6 (0x86DD) porque algo_ra_guard.go lo necesita
	// y Go comparte constantes dentro del mismo paquete.
	EtherTypeIPv6    = 0x86DD 
	OpCodeRequest    = 1
	ArpAlertCooldown = 30 * time.Second

	// Precepto #10: Limits. Evitar OOM si nos atacan con Mac Spoofing masivo
	MaxTrackedArpSources = 5000 
	
	// Umbrales de Comportamiento
	ScanThresholdIPs = 10 // Si toca más de 10 IPs distintas en 1s, es Scan
	MinScanPPS       = 20 // Sensibilidad alta para escaneos (20 pps detecta nmap rápido)
)

// Estadísticas por Host (Source MAC)
// Precepto #5: Estructura alineada para memoria (8 bytes first)
type arpStats struct {
	pps     uint64
	minIP   uint32
	maxIP   uint32
	// Precepto #33: Map pre-sizing en el init. 
	// Usamos uint32 para evitar allocs de net.IP en el mapa.
	targets map[uint32]struct{} 
}

type ArpWatchdog struct {
	cfg           *config.ArpWatchConfig
	notify        *notifier.Notifier
	mu            sync.Mutex
	
	// Estado actual del segundo en curso (Hot Map)
	sources       map[string]*arpStats 
	
	// Registro de alertas para cooldowns (Cold Map)
	alertRegistry map[string]time.Time 
}

func NewArpWatchdog(cfg *config.ArpWatchConfig, n *notifier.Notifier) *ArpWatchdog {
	return &ArpWatchdog{
		cfg:           cfg,
		notify:        n,
		sources:       make(map[string]*arpStats, 100),
		alertRegistry: make(map[string]time.Time),
	}
}

func (aw *ArpWatchdog) Name() string { return "ArpWatchdog" }

func (aw *ArpWatchdog) Start(conn *packet.Conn, iface *net.Interface) error {
	// Goroutine de análisis (Heartbeat de 1 segundo)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			aw.analyzeAndReset()
		}
	}()
	return nil
}

// ipToUint32 convierte IP (slice) a uint32 para comparaciones rápidas en stack.
// Precepto #36: Pure Go, inlineable.
func ipToUint32(ip []byte) uint32 {
	if len(ip) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// OnPacket procesa el tráfico ARP entrante (Hot Path).
func (aw *ArpWatchdog) OnPacket(data []byte, length int, vlanID uint16) {
	// Offset logic
	ethOffset := 14
	ethTypeOffset := 12
	if vlanID != 0 {
		ethOffset = 18
		ethTypeOffset = 16
	}

	// Bounds Check básico
	if length < ethOffset+8 { 
		return
	}

	// 1. Check EtherType (ARP)
	if binary.BigEndian.Uint16(data[ethTypeOffset:ethTypeOffset+2]) != EtherTypeARP {
		return
	}

	// 2. Parse ARP Packet (IPv4 over Ethernet)
	// ARP Header Structure:
	// HW Type (2) | Proto (2) | HW Size (1) | Proto Size (1) | OpCode (2)
	// Sender MAC (6) | Sender IP (4) | Target MAC (6) | Target IP (4)
	
	arpBase := ethOffset
	if length < arpBase+28 { // 28 bytes length of ARP Request/Reply
		return
	}

	// Check OpCode (Request = 1)
	opCode := binary.BigEndian.Uint16(data[arpBase+6 : arpBase+8])
	if opCode != OpCodeRequest {
		return
	}

	// Extract Fields (Zero-Copy slicing)
	srcMac := data[arpBase+8 : arpBase+14]
	targetIPBytes := data[arpBase+24 : arpBase+28]
	targetIP := ipToUint32(targetIPBytes)
	
	// Convert to String for Map Key.
	srcMacKey := string(srcMac)

	aw.mu.Lock()
	stats, exists := aw.sources[srcMacKey]
	
	// Precepto #10: Evitar OOM por Mac Spoofing Flood
	if !exists {
		if len(aw.sources) > MaxTrackedArpSources {
			aw.mu.Unlock()
			return 
		}
		stats = &arpStats{
			targets: make(map[uint32]struct{}, 8), // Start small
			minIP:   targetIP,
			maxIP:   targetIP,
		}
		aw.sources[srcMacKey] = stats
	}

	// Actualizar estadísticas
	stats.pps++
	
	// Rango de IPs tocadas
	if targetIP < stats.minIP {
		stats.minIP = targetIP
	}
	if targetIP > stats.maxIP {
		stats.maxIP = targetIP
	}

	// Registrar IP única (Set) para calcular entropía
	// Limitamos a 255 para evitar que una sola MAC consuma toda la RAM
	if len(stats.targets) < 255 {
		stats.targets[targetIP] = struct{}{}
	}

	aw.mu.Unlock()
}

// analyzeAndReset se ejecuta cada segundo para aplicar heurística y limpiar memoria.
func (aw *ArpWatchdog) analyzeAndReset() {
	aw.mu.Lock()
	defer aw.mu.Unlock()

	// Recorremos las fuentes activas en este segundo
	for macStr, stats := range aw.sources {
		
		// --- LÓGICA DE SENSIBILIDAD ADAPTATIVA ---
		uniqueTargets := len(stats.targets)
		isScanning := uniqueTargets > ScanThresholdIPs 
		
		// Umbral Dinámico:
		// 1. Si está escaneando (>10 IPs), bajamos el umbral a MinScanPPS (20).
		// 2. Si golpea una sola IP, mantenemos el umbral alto de Config (500).
		threshold := aw.cfg.MaxPPS
		if isScanning {
			threshold = MinScanPPS
		}

		// ¿Supera el umbral aplicable?
		if stats.pps > threshold {
			
			// Verificar Cooldown (Precepto #77)
			lastAlert, alerted := aw.alertRegistry[macStr]
			if !alerted || time.Since(lastAlert) > ArpAlertCooldown {
				
				var pattern string
				var details string
				var metricType string

				// --- CLASIFICACIÓN FORENSE ---
				if isScanning {
					// CASO 1: ESCANEO DE RED
					pattern = "SUBNET SCANNING (SWEEP)"
					metricType = "NetworkScan"
					
					ipStart := uint32ToIP(stats.minIP)
					ipEnd := uint32ToIP(stats.maxIP)
					
					details = fmt.Sprintf("Scanning Range: %s -> %s (Covering %d IPs)", 
						ipStart.String(), ipEnd.String(), uniqueTargets)
						
				} else if uniqueTargets == 1 {
					// CASO 2: BUCLE O ATAQUE DIRIGIDO
					pattern = "SINGLE TARGET ATTACK / LOOP"
					metricType = "SingleTargetLoop"
					
					ipTarget := uint32ToIP(stats.minIP)
					details = fmt.Sprintf("Hammering Target: %s", ipTarget.String())
					
				} else {
					// CASO 3: ANOMALÍA GENERICA
					pattern = "HIGH VOLUME ARP ANOMALY"
					metricType = "ArpNoise"
					details = fmt.Sprintf("Multiple Targets (%d distinct IPs)", uniqueTargets)
				}

				// TELEMETRÍA
				telemetry.EngineHits.WithLabelValues("ArpWatchdog", metricType).Inc()

				// NOTIFICACIÓN (Async: No bloquear con I/O dentro del Lock)
				capturedPPS := stats.pps
				capturedMAC := net.HardwareAddr(macStr).String()
				
				go func(m, p, d string, rate uint64, lim uint64) {
					msg := fmt.Sprintf("[ArpWatchdog] 🐶 DISCOVERY STORM DETECTED!\n"+
						"    PROTOCOL:   ARP (IPv4)\n"+
						"    RATE:       %d req/s (Threshold: %d)\n"+
						"    SOURCE MAC: %s\n"+
						"    PATTERN:    %s\n"+
						"    DETAILS:    %s",
						rate, lim, m, p, d)
					aw.notify.Alert(msg)
				}(capturedMAC, pattern, details, capturedPPS, threshold)

				aw.alertRegistry[macStr] = time.Now()
			}
		}
		
		// Limpieza de registro de alertas viejas para no fugar memoria a largo plazo
		if len(aw.alertRegistry) > MaxTrackedArpSources {
			for k, t := range aw.alertRegistry {
				if time.Since(t) > ArpAlertCooldown*2 {
					delete(aw.alertRegistry, k)
				}
			}
		}
	}

	// RESETEO DE ESTADO (Precepto #12)
	// Recreamos el mapa para liberar toda la memoria de los structs arpStats usados.
	aw.sources = make(map[string]*arpStats, 100)
}
