package detector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
)

const MacStormCooldown = 30 * time.Second
const MaxTrackedMacs = 5000

type MacStorm struct {
	cfg         *config.MacStormConfig
	notify      *notifier.Notifier
	mu          sync.Mutex
	macCounters map[[6]byte]uint64
	lastAlerts  map[[6]byte]time.Time
}

func NewMacStorm(cfg *config.MacStormConfig, n *notifier.Notifier) *MacStorm {
	return &MacStorm{
		cfg:         cfg,
		notify:      n,
		macCounters: make(map[[6]byte]uint64),
		lastAlerts:  make(map[[6]byte]time.Time),
	}
}

func (ms *MacStorm) Name() string {
	return "MacStorm"
}

func (ms *MacStorm) Start(conn *packet.Conn, iface *net.Interface) error {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			ms.mu.Lock()
			ms.macCounters = make(map[[6]byte]uint64)
			if len(ms.lastAlerts) > MaxTrackedMacs {
				ms.lastAlerts = make(map[[6]byte]time.Time)
			}
			ms.mu.Unlock()
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
	ms.macCounters[srcMac]++
	count := ms.macCounters[srcMac]
	
	if count > ms.cfg.MaxPPSPerMac {
		lastAlert, exists := ms.lastAlerts[srcMac]
		now := time.Now()

		if !exists || now.Sub(lastAlert) > MacStormCooldown {
			
			location := "Native VLAN"
			if vlanID != 0 {
				location = fmt.Sprintf("VLAN %d", vlanID)
			}

			msg := fmt.Sprintf("[MacStorm] 🌪️  MAC VELOCITY ALERT on %s! MAC %x sent > %d pps (%d pps detected) - Silencing for 30s", 
				location, srcMac, ms.cfg.MaxPPSPerMac, count)
			
			ms.notify.Alert(msg)
			
			ms.lastAlerts[srcMac] = now
		}
	}
	ms.mu.Unlock()
}
