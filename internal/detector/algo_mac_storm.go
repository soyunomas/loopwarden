package detector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/utils"
)

const (
	MaxTrackedMacs = 10000 
	MacAlertCooldown = 30 * time.Second
)

type MacStorm struct {
	cfg    *config.MacStormConfig
	notify *notifier.Notifier
	
	mu sync.Mutex
	counters map[[6]byte]uint64
	alertState map[[6]byte]time.Time
}

func NewMacStorm(cfg *config.MacStormConfig, n *notifier.Notifier) *MacStorm {
	return &MacStorm{
		cfg:    cfg,
		notify: n,
		counters:   make(map[[6]byte]uint64, 1000),
		alertState: make(map[[6]byte]time.Time),
	}
}

func (ms *MacStorm) Name() string { return "MacStorm" }

func (ms *MacStorm) Start(conn *packet.Conn, iface *net.Interface) error {
	go func() {
		rateTicker := time.NewTicker(1 * time.Second)
		cleanupTicker := time.NewTicker(60 * time.Second)
		defer rateTicker.Stop()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-rateTicker.C:
				ms.mu.Lock()
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
		if len(ms.counters) >= MaxTrackedMacs {
			ms.mu.Unlock()
			return
		}
	}
	
	newCount := count + 1
	ms.counters[srcMac] = newCount
	
	if newCount > ms.cfg.MaxPPSPerMac {
		lastAlert, hasAlerted := ms.alertState[srcMac]
		if !hasAlerted || time.Since(lastAlert) > MacAlertCooldown {
			ms.alertState[srcMac] = time.Now()
			ms.mu.Unlock()
			
			// --- CAPTURA DE DESTINO PARA FORENSE ---
			// Capturamos la MAC de destino del paquete actual que rompió el límite.
			// Es una muestra estadística, pero muy precisa en inundaciones.
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
	// Convertimos array a slice para la función utils
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
		location, srcStr, ms.cfg.MaxPPSPerMac, count, floodType)

	ms.notify.Alert(msg)
}
