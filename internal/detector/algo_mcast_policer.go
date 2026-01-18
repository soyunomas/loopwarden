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
)

type McastPolicer struct {
	cfg       *config.McastPolicerConfig
	notify    *notifier.Notifier
	ifaceName string // Identidad de la interfaz
	mu        sync.Mutex
	
	// Configuración Efectiva
	maxPPS uint64
	
	packetCount uint64
	lastReset   time.Time
	lastAlert   time.Time
}

func NewMcastPolicer(cfg *config.McastPolicerConfig, n *notifier.Notifier, ifaceName string) *McastPolicer {
	return &McastPolicer{
		cfg:       cfg,
		notify:    n,
		ifaceName: ifaceName,
		lastReset: time.Now(),
	}
}

func (mp *McastPolicer) Name() string { return "McastPolicer" }

func (mp *McastPolicer) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Base Global
	mp.maxPPS = mp.cfg.MaxPPS

	// 2. Override
	if override, ok := mp.cfg.Overrides[iface.Name]; ok {
		if override.MaxPPS > 0 {
			mp.maxPPS = override.MaxPPS
			log.Printf("🔧 [McastPolicer] Override applied for %s: MaxPPS = %d", iface.Name, mp.maxPPS)
		}
	}
	return nil
}

func (mp *McastPolicer) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 6 { return }

	isMulticast := false
	
	// Check IPv4 Multicast Prefix: 01:00:5E
	if data[0] == 0x01 && data[1] == 0x00 && data[2] == 0x5E {
		isMulticast = true
	} else if data[0] == 0x33 && data[1] == 0x33 {
		// Check IPv6 Multicast Prefix: 33:33
		isMulticast = true
	}

	if isMulticast {
		mp.mu.Lock()
		mp.packetCount++

		now := time.Now()
		if now.Sub(mp.lastReset) >= time.Second {
			// USO DE VARIABLE LOCAL
			if mp.packetCount > mp.maxPPS {
				if now.Sub(mp.lastAlert) > 10*time.Second {
					
					// UPDATED: Added mp.ifaceName label
					telemetry.EngineHits.WithLabelValues(mp.ifaceName, "McastPolicer", "MulticastStorm").Inc()
					
					pps := mp.packetCount
					
					// CAPTURE VARIABLE FOR SAFETY
					currentIface := mp.ifaceName

					go func(iface string, count uint64, vlan uint16, limit uint64) {
						vlanStr := "Native"
						if vlan != 0 {
							vlanStr = fmt.Sprintf("%d", vlan)
						}
						msg := fmt.Sprintf("[McastPolicer] 👻 MULTICAST STORM DETECTED!\n"+
							"    INTERFACE: %s\n"+
							"    VLAN:      %s\n"+
							"    RATE:      %d pps (Limit: %d)\n"+
							"    CAUSE:     Likely Ghost/FOG cloning or Video Streaming gone wrong.",
							iface, vlanStr, count, limit)
						mp.notify.Alert(msg)
					}(currentIface, pps, vlanID, mp.maxPPS)

					mp.lastAlert = now
				}
			}
			mp.packetCount = 0
			mp.lastReset = now
		}
		mp.mu.Unlock()
	}
}
