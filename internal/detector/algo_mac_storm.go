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
	MaxTrackedMacs   = 10000
	MacAlertCooldown = 30 * time.Second
)

type MacStorm struct {
	cfg    *config.MacStormConfig
	notify *notifier.Notifier

	// Configuración Efectiva (Local Copy para Hot Path)
	limitPPS uint64

	mu         sync.Mutex
	counters   map[[6]byte]uint64
	alertState map[[6]byte]time.Time
}

func NewMacStorm(cfg *config.MacStormConfig, n *notifier.Notifier) *MacStorm {
	return &MacStorm{
		cfg:        cfg,
		notify:     n,
		counters:   make(map[[6]byte]uint64, 1000),
		alertState: make(map[[6]byte]time.Time),
	}
}

func (ms *MacStorm) Name() string { return "MacStorm" }

func (ms *MacStorm) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Cargar valor base Global
	ms.limitPPS = ms.cfg.MaxPPSPerMac

	// 2. Aplicar Override si existe y es > 0
	if override, ok := ms.cfg.Overrides[iface.Name]; ok {
		if override.MaxPPSPerMac > 0 {
			ms.limitPPS = override.MaxPPSPerMac
			log.Printf("🔧 [MacStorm] Override applied for %s: MaxPPS = %d", iface.Name, ms.limitPPS)
		}
	}

	go func() {
		rateTicker := time.NewTicker(1 * time.Second)
		cleanupTicker := time.NewTicker(60 * time.Second)
		defer rateTicker.Stop()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-rateTicker.C:
				ms.mu.Lock()
				// Precepto #12: Re-make map para evitar memory leak en long-running
				ms.counters = make(map[[6]byte]uint64, 1000)
				ms.mu.Unlock()

			case <-cleanupTicker.C:
				ms.mu.Lock()
				now := time.Now()
				for mac, lastAlert := range ms.alertState {
					if now.Sub(lastAlert) > MacAlertCooldown*2 {
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
	if length < 14 {
		return
	}

	var srcMac [6]byte
	copy(srcMac[:], data[6:12])

	ms.mu.Lock()

	count, exists := ms.counters[srcMac]
	if !exists {
		// Precepto #10: Protección OOM
		if len(ms.counters) >= MaxTrackedMacs {
			ms.mu.Unlock()
			return
		}
	}

	newCount := count + 1
	ms.counters[srcMac] = newCount

	// USAMOS EL LÍMITE EFECTIVO CALCULADO EN START
	if newCount > ms.limitPPS {
		lastAlert, hasAlerted := ms.alertState[srcMac]
		if !hasAlerted || time.Since(lastAlert) > MacAlertCooldown {

			// TELEMETRY HIT
			telemetry.EngineHits.WithLabelValues("MacStorm", "HostFlood").Inc()

			ms.alertState[srcMac] = time.Now()
			ms.mu.Unlock()

			// --- CAPTURA DE DESTINO PARA FORENSE ---
			var dstMacSample [6]byte
			copy(dstMacSample[:], data[0:6])

			go ms.sendAlert(srcMac, dstMacSample, newCount, vlanID)
			return
		}
	}

	ms.mu.Unlock()
}

func (ms *MacStorm) sendAlert(srcMac [6]byte, dstSample [6]byte, count uint64, vlanID uint16) {
	location := "Native VLAN"
	if vlanID != 0 {
		location = fmt.Sprintf("VLAN %d", vlanID)
	}

	// Clasificar el destino para saber QUÉ están inundando
	targetInfo := utils.ClassifyMAC(dstSample[:])

	floodType := "Unicast Flood"
	if targetInfo.Name != "Unicast" {
		floodType = fmt.Sprintf("%s (%s)", targetInfo.Name, targetInfo.Description)
	}

	srcStr := net.HardwareAddr(srcMac[:]).String()

	msg := fmt.Sprintf("[MacStorm] 🌪️ HOST FLOODING DETECTED!\n"+
		"    VLAN:    %s\n"+
		"    HOST:    %s\n"+
		"    RATE:    > %d pps (Current: %d)\n"+
		"    PATTERN: Flooding %s",
		location, srcStr, ms.limitPPS, count, floodType)

	ms.notify.Alert(msg)
}
