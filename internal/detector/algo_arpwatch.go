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
	EtherTypeARP     = 0x0806
	EtherTypeIPv6    = 0x86DD
	OpCodeRequest    = 1
	ArpAlertCooldown = 30 * time.Second
	MaxTrackedArpSources = 5000
	ScanThresholdIPs = 10
	MinScanPPS       = 20
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

	// Configuración Efectiva
	limitPPS uint64

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
	// 1. Cargar Base
	aw.limitPPS = aw.cfg.MaxPPS

	// 2. Override
	if override, ok := aw.cfg.Overrides[iface.Name]; ok {
		if override.MaxPPS > 0 {
			aw.limitPPS = override.MaxPPS
			log.Printf("🔧 [ArpWatch] Override applied for %s: MaxPPS = %d", iface.Name, aw.limitPPS)
		}
	}

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

	if length < ethOffset+8 {
		return
	}

	if binary.BigEndian.Uint16(data[ethTypeOffset:ethTypeOffset+2]) != EtherTypeARP {
		return
	}

	arpBase := ethOffset
	if length < arpBase+28 {
		return
	}

	opCode := binary.BigEndian.Uint16(data[arpBase+6 : arpBase+8])
	if opCode != OpCodeRequest {
		return
	}

	// ZERO-ALLOC KEY EXTRACTION
	var srcMacKey [6]byte
	copy(srcMacKey[:], data[arpBase+8:arpBase+14])
	
	targetIPBytes := data[arpBase+24 : arpBase+28]
	targetIP := ipToUint32(targetIPBytes)

	aw.mu.Lock()
	stats, exists := aw.sources[srcMacKey]

	if !exists {
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
	if len(stats.targets) < 255 {
		stats.targets[targetIP] = struct{}{}
	}

	aw.mu.Unlock()
}

func (aw *ArpWatchdog) analyzeAndReset() {
	aw.mu.Lock()
	defer aw.mu.Unlock()

	for macArray, stats := range aw.sources {
		uniqueTargets := len(stats.targets)
		isScanning := uniqueTargets > ScanThresholdIPs

		threshold := aw.limitPPS
		
		if isScanning {
			threshold = MinScanPPS
		}

		if stats.pps > threshold {
			lastAlert, alerted := aw.alertRegistry[macArray]
			if !alerted || time.Since(lastAlert) > ArpAlertCooldown {
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

				// UPDATED: Added aw.ifaceName label
				telemetry.EngineHits.WithLabelValues(aw.ifaceName, "ArpWatchdog", metricType).Inc()

				capturedPPS := stats.pps
				capturedMAC := net.HardwareAddr(macArray[:]).String()

				go func(m, p, d string, rate uint64, lim uint64) {
					msg := fmt.Sprintf("[ArpWatchdog] 🐶 DISCOVERY STORM DETECTED!\n"+
						"    RATE:       %d req/s (Threshold: %d)\n"+
						"    SOURCE:     %s\n"+
						"    PATTERN:    %s\n"+
						"    DETAILS:    %s",
						rate, lim, m, p, d)
					aw.notify.Alert(msg)
				}(capturedMAC, pattern, details, capturedPPS, threshold)

				aw.alertRegistry[macArray] = time.Now()
			}
		}

		if len(aw.alertRegistry) > MaxTrackedArpSources {
			for k, t := range aw.alertRegistry {
				if time.Since(t) > ArpAlertCooldown*2 {
					delete(aw.alertRegistry, k)
				}
			}
		}
	}
	aw.sources = make(map[[6]byte]*arpStats, 100)
}
