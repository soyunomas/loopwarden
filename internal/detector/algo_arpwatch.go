package detector

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

const (
	EtherTypeARP         = 0x0806
	EtherTypeIPv6        = 0x86DD
	OpCodeRequest        = 1
	MaxTrackedArpSources = 5000
)

type arpStats struct {
	pps     uint64
	minIP   uint32
	maxIP   uint32
	targets map[uint32]struct{}
}

type ArpWatchdog struct {
	cfg       *config.ArpWatchConfig
	notify    *notifier.Notifier
	ifaceName string // Identidad de la interfaz
	mu        sync.Mutex

	// --- Configuración Efectiva (Cargada en Start) ---
	limitPPS      uint64
	scanThreshold int
	scanLimitPPS  uint64
	cooldown      time.Duration

	sources       map[[6]byte]*arpStats
	alertRegistry map[[6]byte]time.Time
}

func NewArpWatchdog(cfg *config.ArpWatchConfig, n *notifier.Notifier, ifaceName string) *ArpWatchdog {
	return &ArpWatchdog{
		cfg:           cfg,
		notify:        n,
		ifaceName:     ifaceName,
		sources:       make(map[[6]byte]*arpStats, 100),
		alertRegistry: make(map[[6]byte]time.Time),
	}
}

func (aw *ArpWatchdog) Name() string { return "ArpWatchdog" }

func (aw *ArpWatchdog) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Cargar Defaults Globales
	aw.limitPPS = aw.cfg.MaxPPS
	aw.scanThreshold = aw.cfg.ScanIPThreshold
	aw.scanLimitPPS = aw.cfg.ScanModePPS

	// Parseo de Cooldown Global
	dur, err := time.ParseDuration(aw.cfg.AlertCooldown)
	if err != nil {
		log.Printf("⚠️ [ArpWatch:%s] Invalid AlertCooldown '%s', defaulting to 30s", iface.Name, aw.cfg.AlertCooldown)
		aw.cooldown = 30 * time.Second
	} else {
		aw.cooldown = dur
	}

	// 2. Aplicar Overrides
	if override, ok := aw.cfg.Overrides[iface.Name]; ok {
		if override.MaxPPS > 0 {
			aw.limitPPS = override.MaxPPS
			log.Printf("🔧 [ArpWatch:%s] Override MaxPPS = %d", iface.Name, aw.limitPPS)
		}
		if override.ScanIPThreshold > 0 {
			aw.scanThreshold = override.ScanIPThreshold
			log.Printf("🔧 [ArpWatch:%s] Override ScanIPThreshold = %d", iface.Name, aw.scanThreshold)
		}
		if override.ScanModePPS > 0 {
			aw.scanLimitPPS = override.ScanModePPS
			log.Printf("🔧 [ArpWatch:%s] Override ScanModePPS = %d", iface.Name, aw.scanLimitPPS)
		}
		// Nota: ArpWatchOverride no tiene AlertCooldown en config.go fase 1, se mantiene el global.
	}

	// 3. Fallbacks de Seguridad (Precepto #15: Zero-Value usability)
	if aw.limitPPS == 0 { aw.limitPPS = 500 }
	if aw.scanThreshold == 0 { aw.scanThreshold = 10 }
	if aw.scanLimitPPS == 0 { aw.scanLimitPPS = 20 }
	if aw.cooldown == 0 { aw.cooldown = 30 * time.Second }

	log.Printf("✅ [ArpWatch:%s] Active. Limit: %d pps (Scan Mode: >%d targets -> %d pps)", 
		iface.Name, aw.limitPPS, aw.scanThreshold, aw.scanLimitPPS)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			aw.analyzeAndReset()
		}
	}()
	return nil
}

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

func (aw *ArpWatchdog) OnPacket(data []byte, length int, vlanID uint16) {
	ethOffset := 14
	ethTypeOffset := 12
	if vlanID != 0 {
		ethOffset = 18
		ethTypeOffset = 16
	}

	if length < ethOffset+8 { return }

	if binary.BigEndian.Uint16(data[ethTypeOffset:ethTypeOffset+2]) != EtherTypeARP { return }

	arpBase := ethOffset
	if length < arpBase+28 { return }

	opCode := binary.BigEndian.Uint16(data[arpBase+6 : arpBase+8])
	if opCode != OpCodeRequest { return }

	// ZERO-ALLOC KEY EXTRACTION
	var srcMacKey [6]byte
	copy(srcMacKey[:], data[arpBase+8:arpBase+14])
	
	targetIPBytes := data[arpBase+24 : arpBase+28]
	targetIP := ipToUint32(targetIPBytes)

	aw.mu.Lock()
	stats, exists := aw.sources[srcMacKey]

	if !exists {
		// Protección de memoria
		if len(aw.sources) > MaxTrackedArpSources {
			aw.mu.Unlock()
			return
		}
		stats = &arpStats{
			targets: make(map[uint32]struct{}, 8),
			minIP:   targetIP,
			maxIP:   targetIP,
		}
		aw.sources[srcMacKey] = stats
	}

	stats.pps++
	if targetIP < stats.minIP {
		stats.minIP = targetIP
	}
	if targetIP > stats.maxIP {
		stats.maxIP = targetIP
	}
	// Límite hardcodeado de 255 targets para no explotar memoria en un scan masivo /16
	if len(stats.targets) < 255 {
		stats.targets[targetIP] = struct{}{}
	}

	aw.mu.Unlock()
}

func (aw *ArpWatchdog) analyzeAndReset() {
	aw.mu.Lock()
	defer aw.mu.Unlock()

	currentIface := aw.ifaceName

	for macArray, stats := range aw.sources {
		uniqueTargets := len(stats.targets)
		
		// USAR VARIABLE DE INSTANCIA
		isScanning := uniqueTargets > aw.scanThreshold

		threshold := aw.limitPPS
		
		if isScanning {
			// USAR VARIABLE DE INSTANCIA
			threshold = aw.scanLimitPPS
		}

		if stats.pps > threshold {
			lastAlert, alerted := aw.alertRegistry[macArray]
			
			// USAR VARIABLE DE INSTANCIA (Cooldown)
			if !alerted || time.Since(lastAlert) > aw.cooldown {
				var pattern, details, metricType string

				if isScanning {
					pattern = "SUBNET SCANNING (SWEEP)"
					metricType = "NetworkScan"
					ipStart := uint32ToIP(stats.minIP)
					ipEnd := uint32ToIP(stats.maxIP)
					details = fmt.Sprintf("Scanning Range: %s -> %s (%d IPs)", ipStart, ipEnd, uniqueTargets)
				} else if uniqueTargets == 1 {
					pattern = "SINGLE TARGET ATTACK / LOOP"
					metricType = "SingleTargetLoop"
					ipTarget := uint32ToIP(stats.minIP)
					details = fmt.Sprintf("Hammering Target: %s", ipTarget)
				} else {
					pattern = "HIGH VOLUME ARP ANOMALY"
					metricType = "ArpNoise"
					details = fmt.Sprintf("Multiple Targets (%d IPs)", uniqueTargets)
				}

				telemetry.EngineHits.WithLabelValues(aw.ifaceName, "ArpWatchdog", metricType).Inc()

				capturedPPS := stats.pps
				capturedMAC := net.HardwareAddr(macArray[:]).String()

				go func(iface, m, p, d string, rate uint64, lim uint64) {
					msg := fmt.Sprintf("[ArpWatchdog] 🐶 DISCOVERY STORM DETECTED!\n"+
						"    INTERFACE:  %s\n"+
						"    RATE:       %d req/s (Threshold: %d)\n"+
						"    SOURCE:     %s\n"+
						"    PATTERN:    %s\n"+
						"    DETAILS:    %s",
						iface, rate, lim, m, p, d)
					aw.notify.Alert(msg)
				}(currentIface, capturedMAC, pattern, details, capturedPPS, threshold)

				aw.alertRegistry[macArray] = time.Now()
			}
		}

		if len(aw.alertRegistry) > MaxTrackedArpSources {
			// Limpieza de memoria simple
			for k, t := range aw.alertRegistry {
				if time.Since(t) > aw.cooldown*2 {
					delete(aw.alertRegistry, k)
				}
			}
		}
	}
	// Precepto #12: Mapas como caches -> Re-make para evitar fuga de memoria en long-running
	aw.sources = make(map[[6]byte]*arpStats, 100)
}
