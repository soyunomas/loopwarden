package detector

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
	"github.com/soyunomas/loopwarden/internal/utils"
)

const (
	MaxFlapEntries = 50000
)

type flapEntry struct {
	lastSeen  int64
	lastAlert int64
	lastVLAN  uint16
	flapCount uint16
}

type FlapGuard struct {
	cfg       *config.FlapGuardConfig
	notify    *notifier.Notifier
	ifaceName string 
	
	// --- Configuración Efectiva (Hot Path Optimized: int64 Nano) ---
	threshold    uint16
	windowNano   int64
	cooldownNano int64

	mu       sync.Mutex
	registry map[[6]byte]flapEntry
}

func NewFlapGuard(cfg *config.FlapGuardConfig, n *notifier.Notifier, ifaceName string) *FlapGuard {
	return &FlapGuard{
		cfg:       cfg,
		notify:    n,
		ifaceName: ifaceName,
		registry:  make(map[[6]byte]flapEntry, 1000),
	}
}

func (fg *FlapGuard) Name() string { return "FlapGuard" }

func (fg *FlapGuard) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Defaults Globales
	fg.threshold = uint16(fg.cfg.Threshold)
	
	// Parseo de Window Global
	winDur, err := time.ParseDuration(fg.cfg.Window)
	if err != nil {
		log.Printf("⚠️ [FlapGuard:%s] Invalid Window '%s', defaulting to 1s", iface.Name, fg.cfg.Window)
		winDur = 1 * time.Second
	}
	
	// Parseo de Cooldown Global
	coolDur, err := time.ParseDuration(fg.cfg.AlertCooldown)
	if err != nil {
		log.Printf("⚠️ [FlapGuard:%s] Invalid AlertCooldown '%s', defaulting to 30s", iface.Name, fg.cfg.AlertCooldown)
		coolDur = 30 * time.Second
	}

	// 2. Overrides
	if override, ok := fg.cfg.Overrides[iface.Name]; ok {
		if override.Threshold > 0 {
			fg.threshold = uint16(override.Threshold)
			log.Printf("🔧 [FlapGuard:%s] Override Threshold = %d", iface.Name, fg.threshold)
		}
		// Override de Window si existe
		if override.Window != "" {
			ovWin, err := time.ParseDuration(override.Window)
			if err == nil {
				winDur = ovWin
				log.Printf("🔧 [FlapGuard:%s] Override Window = %v", iface.Name, ovWin)
			} else {
				log.Printf("⚠️ [FlapGuard:%s] Invalid Override Window '%s', ignoring", iface.Name, override.Window)
			}
		}
	}

	// 3. Fallbacks y Conversión a Nanosegundos (Metal Optimization)
	if fg.threshold == 0 { fg.threshold = 5 }
	if winDur == 0 { winDur = 1 * time.Second }
	if coolDur == 0 { coolDur = 30 * time.Second }

	fg.windowNano = winDur.Nanoseconds()
	fg.cooldownNano = coolDur.Nanoseconds()

	log.Printf("✅ [FlapGuard:%s] Active. Threshold: %d moves / %v", iface.Name, fg.threshold, winDur)

	// Goroutine de limpieza de memoria
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			fg.mu.Lock()
			now := time.Now().UnixNano()
			expiry := int64(60 * time.Second) // Limpieza agresiva si está lleno

			if len(fg.registry) > MaxFlapEntries {
				expiry = int64(10 * time.Second)
			}
			
			// Convertir a nanosegundos para la comparación
			expiryNano := expiry

			for mac, entry := range fg.registry {
				if now-entry.lastSeen > expiryNano {
					delete(fg.registry, mac)
				}
			}
			fg.mu.Unlock()
		}
	}()
	return nil
}

func (fg *FlapGuard) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 12 { return }

	var srcMac [6]byte
	copy(srcMac[:], data[6:12])

	// Hot Path: UnixNano es mucho más rápido que instanciar objetos time.Time
	now := time.Now().UnixNano()

	fg.mu.Lock()
	entry, exists := fg.registry[srcMac]

	if !exists {
		// Protección OOM
		if len(fg.registry) >= MaxFlapEntries {
			fg.mu.Unlock()
			return
		}

		fg.registry[srcMac] = flapEntry{
			lastVLAN: vlanID,
			lastSeen: now,
		}
		fg.mu.Unlock()
		return
	}

	if entry.lastVLAN != vlanID {
		// USAR VARIABLE DE INSTANCIA (Calculada en Start)
		if (now - entry.lastSeen) < fg.windowNano {
			entry.flapCount++
		} else {
			entry.flapCount = 1
		}

		entry.lastVLAN = vlanID
		entry.lastSeen = now

		if entry.flapCount >= fg.threshold {
			// USAR VARIABLE DE INSTANCIA
			if (now - entry.lastAlert) > fg.cooldownNano {
				entry.lastAlert = now

				telemetry.EngineHits.WithLabelValues(fg.ifaceName, "FlapGuard", "MacFlapping").Inc()

				fg.registry[srcMac] = entry
				fg.mu.Unlock()

				currentIface := fg.ifaceName
				go fg.sendAlert(currentIface, srcMac, entry.flapCount, vlanID)
				return
			}
		}

		fg.registry[srcMac] = entry
	} else {
		// Update de mantenimiento (keep-alive)
		if (now - entry.lastSeen) > 1_000_000_000 { // > 1s
			entry.lastSeen = now
			fg.registry[srcMac] = entry
		}
	}

	fg.mu.Unlock()
}

func (fg *FlapGuard) sendAlert(iface string, mac [6]byte, count uint16, vlanID uint16) {
	macSlice := mac[:]
	info := utils.ClassifyMAC(macSlice)

	macStr := net.HardwareAddr(macSlice).String()
	identity := "Host"
	if info.Name != "Unicast" {
		identity = fmt.Sprintf("%s (%s)", info.Name, info.Description)
	}

	severity := "⚠️ WARNING"
	if info.IsCritical {
		severity = "🔥 CRITICAL"
	}

	msg := fmt.Sprintf("[FlapGuard] %s: TOPOLOGY CHANGE DETECTED!\n"+
		"    INTERFACE: %s\n"+
		"    IDENTITY:  %s\n"+
		"    MAC:       %s\n"+
		"    MOVES:     %d times in %s (Current VLAN: %d)\n"+
		"    ANALYSIS:  Device is jumping between VLANs. Possible cabling loop or leaking configuration.",
		severity, iface, identity, macStr, count, time.Duration(fg.windowNano), vlanID)

	fg.notify.Alert(msg)
}
