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

type MacStorm struct {
	cfg       *config.MacStormConfig
	notify    *notifier.Notifier
	ifaceName string

	// --- Configuración Efectiva ---
	limitPPS   uint64
	maxTracked int
	cooldown   time.Duration

	mu         sync.Mutex
	counters   map[[6]byte]uint64
	alertState map[[6]byte]time.Time
}

func NewMacStorm(cfg *config.MacStormConfig, n *notifier.Notifier, ifaceName string) *MacStorm {
	return &MacStorm{
		cfg:        cfg,
		notify:     n,
		ifaceName:  ifaceName,
		counters:   make(map[[6]byte]uint64, 1000),
		alertState: make(map[[6]byte]time.Time),
	}
}

func (ms *MacStorm) Name() string { return "MacStorm" }

func (ms *MacStorm) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Defaults Globales
	ms.limitPPS = ms.cfg.MaxPPSPerMac
	ms.maxTracked = ms.cfg.MaxTrackedMacs
	
	dur, err := time.ParseDuration(ms.cfg.AlertCooldown)
	if err != nil {
		log.Printf("⚠️ [MacStorm:%s] Invalid AlertCooldown '%s', defaulting to 30s", iface.Name, ms.cfg.AlertCooldown)
		ms.cooldown = 30 * time.Second
	} else {
		ms.cooldown = dur
	}

	// 2. Overrides
	if override, ok := ms.cfg.Overrides[iface.Name]; ok {
		if override.MaxPPSPerMac > 0 {
			ms.limitPPS = override.MaxPPSPerMac
			log.Printf("🔧 [MacStorm:%s] Override MaxPPS = %d", iface.Name, ms.limitPPS)
		}
	}

	// 3. Fallbacks de Seguridad
	if ms.limitPPS == 0 { ms.limitPPS = 2000 }
	if ms.maxTracked == 0 { ms.maxTracked = 10000 }
	if ms.cooldown == 0 { ms.cooldown = 30 * time.Second }

	log.Printf("✅ [MacStorm:%s] Active. Limit: %d pps, MemLimit: %d hosts, Cooldown: %v", 
		iface.Name, ms.limitPPS, ms.maxTracked, ms.cooldown)

	go func() {
		rateTicker := time.NewTicker(1 * time.Second)
		cleanupTicker := time.NewTicker(60 * time.Second)
		defer rateTicker.Stop()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-rateTicker.C:
				ms.mu.Lock()
				// Precepto #12: Map reset
				ms.counters = make(map[[6]byte]uint64, 1000)
				ms.mu.Unlock()

			case <-cleanupTicker.C:
				ms.mu.Lock()
				now := time.Now()
				expiry := ms.cooldown * 2
				for mac, lastAlert := range ms.alertState {
					if now.Sub(lastAlert) > expiry {
						delete(ms.alertState, mac)
					}
				}
				ms.mu.Unlock()
			}
		}
	}()
	return nil
}

func (ms *MacStorm) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 14 { return }

	var srcMac [6]byte
	copy(srcMac[:], data[6:12])

	ms.mu.Lock()

	count, exists := ms.counters[srcMac]
	if !exists {
		// Precepto #10: Protección OOM usando variable configurada
		if len(ms.counters) >= ms.maxTracked {
			ms.mu.Unlock()
			return
		}
	}

	newCount := count + 1
	ms.counters[srcMac] = newCount

	if newCount > ms.limitPPS {
		lastAlert, hasAlerted := ms.alertState[srcMac]
		
		// Usamos ms.cooldown configurado
		if !hasAlerted || time.Since(lastAlert) > ms.cooldown {

			telemetry.EngineHits.WithLabelValues(ms.ifaceName, "MacStorm", "HostFlood").Inc()

			ms.alertState[srcMac] = time.Now()
			ms.mu.Unlock()

			var dstMacSample [6]byte
			copy(dstMacSample[:], data[0:6])

			currentIface := ms.ifaceName
			go ms.sendAlert(currentIface, srcMac, dstMacSample, newCount, vlanID)
			return
		}
	}

	ms.mu.Unlock()
}

func (ms *MacStorm) sendAlert(iface string, srcMac [6]byte, dstSample [6]byte, count uint64, vlanID uint16) {
	location := "Native VLAN"
	if vlanID != 0 {
		location = fmt.Sprintf("VLAN %d", vlanID)
	}

	targetInfo := utils.ClassifyMAC(dstSample[:])
	floodType := "Unicast Flood"
	if targetInfo.Name != "Unicast" {
		floodType = fmt.Sprintf("%s (%s)", targetInfo.Name, targetInfo.Description)
	}

	srcStr := net.HardwareAddr(srcMac[:]).String()

	msg := fmt.Sprintf("[MacStorm] 🌪️ HOST FLOODING DETECTED!\n"+
		"    INTERFACE: %s\n"+
		"    VLAN:      %s\n"+
		"    HOST:      %s\n"+
		"    RATE:      > %d pps (Current: %d)\n"+
		"    PATTERN:   Flooding %s",
		iface, location, srcStr, ms.limitPPS, count, floodType)

	ms.notify.Alert(msg)
}
