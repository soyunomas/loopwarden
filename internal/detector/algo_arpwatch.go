package detector

import (
	"bytes" // Usado para GARP check
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
	pps      uint64
	senderIP uint32
	minIP    uint32
	maxIP    uint32
	targets  map[uint32]struct{}
}

type ArpWatchdog struct {
	cfg       *config.ArpWatchConfig
	notify    *notifier.Notifier
	ifaceName string 
	mu        sync.Mutex

	// Configuración Efectiva
	limitPPS      uint64
	scanThreshold int
	scanLimitPPS  uint64
	cooldown      time.Duration

	sources       map[[6]byte]*arpStats
	alertRegistry map[[6]byte]time.Time

	// --- FASE 2: GARP Detection ---
	garpStats     map[[6]byte]uint64
	garpThreshold uint64
	garpAlerts    map[[6]byte]time.Time
}

func NewArpWatchdog(cfg *config.ArpWatchConfig, n *notifier.Notifier, ifaceName string) *ArpWatchdog {
	return &ArpWatchdog{
		cfg:           cfg,
		notify:        n,
		ifaceName:     ifaceName,
		sources:       make(map[[6]byte]*arpStats, 100),
		alertRegistry: make(map[[6]byte]time.Time),
		garpStats:     make(map[[6]byte]uint64),
		garpAlerts:    make(map[[6]byte]time.Time),
	}
}

func (aw *ArpWatchdog) Name() string { return "ArpWatchdog" }

func (aw *ArpWatchdog) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Cargar Defaults
	aw.limitPPS = aw.cfg.MaxPPS
	aw.scanThreshold = aw.cfg.ScanIPThreshold
	aw.scanLimitPPS = aw.cfg.ScanModePPS
	aw.garpThreshold = aw.cfg.GarpThreshold // Nuevo campo Fase 2

	dur, err := time.ParseDuration(aw.cfg.AlertCooldown)
	if err != nil {
		aw.cooldown = 30 * time.Second
	} else {
		aw.cooldown = dur
	}

	// 2. Overrides
	if override, ok := aw.cfg.Overrides[iface.Name]; ok {
		if override.MaxPPS > 0 { aw.limitPPS = override.MaxPPS }
		if override.ScanIPThreshold > 0 { aw.scanThreshold = override.ScanIPThreshold }
		if override.ScanModePPS > 0 { aw.scanLimitPPS = override.ScanModePPS }
	}

	// 3. Fallbacks
	if aw.limitPPS == 0 { aw.limitPPS = 500 }
	if aw.scanThreshold == 0 { aw.scanThreshold = 10 }
	if aw.scanLimitPPS == 0 { aw.scanLimitPPS = 20 }
	if aw.garpThreshold == 0 { aw.garpThreshold = 50 } // Default GARP threshold
	if aw.cooldown == 0 { aw.cooldown = 30 * time.Second }

	log.Printf("✅ [ArpWatch:%s] Active. Limit: %d pps, GARP Limit: %d pps", 
		iface.Name, aw.limitPPS, aw.garpThreshold)

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
	if len(ip) != 4 { return 0 }
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

	if length < ethOffset+28 { return }
	if binary.BigEndian.Uint16(data[ethTypeOffset:ethTypeOffset+2]) != EtherTypeARP { return }

	arpBase := ethOffset
	opCode := binary.BigEndian.Uint16(data[arpBase+6 : arpBase+8])
	
	// Solo analizamos Requests (1) y Replies (2, para GARP)
	if opCode != 1 && opCode != 2 { return }

	var srcMacKey [6]byte
	copy(srcMacKey[:], data[arpBase+8:arpBase+14])
	
	senderIP := data[arpBase+14 : arpBase+18]
	targetIP := data[arpBase+24 : arpBase+28]

	// --- LOGICA GARP (Fase 2) ---
	// Gratuitous ARP: Sender IP == Target IP
	isGratuitous := bytes.Equal(senderIP, targetIP)

	aw.mu.Lock()
	defer aw.mu.Unlock()

	if isGratuitous {
		aw.garpStats[srcMacKey]++
		return // GARP se cuenta por separado
	}

	// --- LOGICA ARP STORM NORMAL (Requests) ---
	if opCode == OpCodeRequest {
		stats, exists := aw.sources[srcMacKey]
		if !exists {
			if len(aw.sources) > MaxTrackedArpSources { return }
			stats = &arpStats{
				senderIP: ipToUint32(senderIP),
				targets:  make(map[uint32]struct{}, 8),
				minIP:    ipToUint32(targetIP),
				maxIP:    ipToUint32(targetIP),
			}
			aw.sources[srcMacKey] = stats
		}
		stats.senderIP = ipToUint32(senderIP)

		stats.pps++
		tIP := ipToUint32(targetIP)
		if tIP < stats.minIP { stats.minIP = tIP }
		if tIP > stats.maxIP { stats.maxIP = tIP }
		if len(stats.targets) < 255 {
			stats.targets[tIP] = struct{}{}
		}
	}
}

func (aw *ArpWatchdog) analyzeAndReset() {
	aw.mu.Lock()
	defer aw.mu.Unlock()

	// 1. Analizar GARP Storms
	for mac, count := range aw.garpStats {
		if count > aw.garpThreshold {
			lastAlert, alerted := aw.garpAlerts[mac]
			if !alerted || time.Since(lastAlert) > aw.cooldown {
				
				telemetry.EngineHits.WithLabelValues(aw.ifaceName, "ArpWatchdog", "GarpFlood").Inc()
				
				capturedMac := net.HardwareAddr(mac[:]).String()
				capturedCount := count
				ifaceName := aw.ifaceName // capture for goroutine

				go func(iface, m string, rate, limit uint64) {
					msg := fmt.Sprintf("[ArpWatchdog] 📢 GRATUITOUS ARP FLOOD!\n"+
						"    INTERFACE:  %s\n"+
						"    RATE:       %d pkts/s (Limit: %d)\n"+
						"    SOURCE:     %s\n"+
						"    CAUSE:      IP Conflict, VRRP Flapping, or ARP Poisoning attack.",
						iface, rate, limit, m)
					aw.notify.Alert(msg)
				}(ifaceName, capturedMac, capturedCount, aw.garpThreshold)

				aw.garpAlerts[mac] = time.Now()
			}
		}
	}
	// Reset GARP
	aw.garpStats = make(map[[6]byte]uint64)


	// 2. Analizar ARP Scan / Storm Normal
	for macArray, stats := range aw.sources {
		uniqueTargets := len(stats.targets)
		isScanning := uniqueTargets > aw.scanThreshold
		threshold := aw.limitPPS
		if isScanning { threshold = aw.scanLimitPPS }

		if stats.pps > threshold {
			lastAlert, alerted := aw.alertRegistry[macArray]
			if !alerted || time.Since(lastAlert) > aw.cooldown {
				var pattern, details, metricType string

				if isScanning {
					pattern = "SUBNET SCANNING (SWEEP)"
					metricType = "NetworkScan"
					details = fmt.Sprintf("Scanning %d targets (%s → %s)",
						uniqueTargets, uint32ToIP(stats.minIP), uint32ToIP(stats.maxIP))
				} else if uniqueTargets <= 1 {
					pattern = "SINGLE TARGET ATTACK / LOOP"
					metricType = "SingleTarget"
					details = fmt.Sprintf("Flooding target %s (%d req/s)",
						uint32ToIP(stats.minIP), stats.pps)
				} else {
					pattern = "ARP FLOOD"
					metricType = "ArpNoise"
					details = fmt.Sprintf("High Volume Requests to %d IPs (%s → %s)",
						uniqueTargets, uint32ToIP(stats.minIP), uint32ToIP(stats.maxIP))
				}

				telemetry.EngineHits.WithLabelValues(aw.ifaceName, "ArpWatchdog", metricType).Inc()
				capturedMac := net.HardwareAddr(macArray[:]).String()
				capturedSrcIP := uint32ToIP(stats.senderIP).String()
				capturedPPS := stats.pps
				ifaceName := aw.ifaceName

				go func(iface, m, srcIP, p, d string, rate uint64) {
					msg := fmt.Sprintf("[ArpWatchdog] 🐶 ARP ANOMALY!\n"+
						"    INTERFACE:  %s\n"+
						"    RATE:       %d req/s\n"+
						"    SOURCE:     %s (%s)\n"+
						"    PATTERN:    %s\n"+
						"    DETAILS:    %s",
						iface, rate, m, srcIP, p, d)
					aw.notify.Alert(msg)
				}(ifaceName, capturedMac, capturedSrcIP, pattern, details, capturedPPS)

				aw.alertRegistry[macArray] = time.Now()
			}
		}
	}
	// Reset ARP Normal
	aw.sources = make(map[[6]byte]*arpStats, 100)
}
