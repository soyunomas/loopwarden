package detector

import (
	"fmt"
	"hash/fnv"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
)

// Cooldown para evitar spam de alertas
const FuseAlertCooldown = 5 * time.Second

type EtherFuse struct {
	cfg            *config.EtherFuseConfig
	notify         *notifier.Notifier // Referencia al notificador
	mu             sync.Mutex
	hashHistory    []uint64
	historyIndex   int
	dupCounter     int
	lastReset      time.Time
	packetsSec     uint64
	lastDupAlert   time.Time
	lastStormAlert time.Time
}

func NewEtherFuse(cfg *config.EtherFuseConfig, n *notifier.Notifier) *EtherFuse {
	return &EtherFuse{
		cfg:          cfg,
		notify:       n,
		hashHistory:  make([]uint64, cfg.HistorySize),
		historyIndex: 0,
		lastReset:    time.Now(),
	}
}

func (ef *EtherFuse) Name() string {
	return "EtherFuse"
}

func (ef *EtherFuse) Start(conn *packet.Conn, iface *net.Interface) error {
	return nil
}

func (ef *EtherFuse) OnPacket(data []byte, length int, vlanID uint16) {
	h := fnv.New64a()
	h.Write(data[:length])
	sum := h.Sum64()

	ef.mu.Lock()
	defer ef.mu.Unlock()

	// 1. Detección de Volumetría (Storm)
	ef.packetsSec++
	now := time.Now()
	
	if now.Sub(ef.lastReset) >= time.Second {
		if ef.packetsSec > ef.cfg.StormPPSLimit {
			if now.Sub(ef.lastStormAlert) > FuseAlertCooldown {
				msg := fmt.Sprintf("[EtherFuse] ⛈️  Broadcast Storm detected: %d pps (throttling logs for 5s)", ef.packetsSec)
				ef.notify.Alert(msg)
				ef.lastStormAlert = now
			}
		}
		ef.packetsSec = 0
		ef.lastReset = now
		ef.dupCounter = 0
	}

	// 2. Detección de Duplicados
	isDup := false
	for _, v := range ef.hashHistory {
		if v == sum {
			isDup = true
			break
		}
	}

	if isDup {
		ef.dupCounter++
		if ef.dupCounter > ef.cfg.AlertThreshold {
			if now.Sub(ef.lastDupAlert) > FuseAlertCooldown {
				location := "Native VLAN"
				if vlanID != 0 {
					location = fmt.Sprintf("VLAN %d", vlanID)
				}
				
				msg := fmt.Sprintf("[EtherFuse] 🚨 LOOP DETECTED on %s! Frame Hash %x repeated %d times", location, sum, ef.dupCounter)
				ef.notify.Alert(msg)
				
				ef.lastDupAlert = now
			}
			ef.dupCounter = 0 
		}
	} else {
		ef.hashHistory[ef.historyIndex] = sum
		ef.historyIndex++
		if ef.historyIndex >= ef.cfg.HistorySize {
			ef.historyIndex = 0
		}
	}
}
