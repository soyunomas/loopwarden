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

type McastPolicer struct {
	cfg       *config.McastPolicerConfig
	notify    *notifier.Notifier
	mu        sync.Mutex
	
	packetCount uint64
	lastReset   time.Time
	lastAlert   time.Time
}

func NewMcastPolicer(cfg *config.McastPolicerConfig, n *notifier.Notifier) *McastPolicer {
	return &McastPolicer{
		cfg:       cfg,
		notify:    n,
		lastReset: time.Now(),
	}
}

func (mp *McastPolicer) Name() string { return "McastPolicer" }

// Start requiere "net" para *net.Interface
func (mp *McastPolicer) Start(conn *packet.Conn, iface *net.Interface) error { return nil }

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
			if mp.packetCount > mp.cfg.MaxPPS {
				if now.Sub(mp.lastAlert) > 10*time.Second {
					
					pps := mp.packetCount
					go func(count uint64, vlan uint16) {
						vlanStr := "Native"
						if vlan != 0 {
							vlanStr = fmt.Sprintf("%d", vlan)
						}
						msg := fmt.Sprintf("[McastPolicer] 👻 MULTICAST STORM DETECTED!\n"+
							"    VLAN:  %s\n"+
							"    RATE:  %d pps (Limit: %d)\n"+
							"    CAUSE: Likely Ghost/FOG cloning or Video Streaming gone wrong.",
							vlanStr, count, mp.cfg.MaxPPS)
						mp.notify.Alert(msg)
					}(pps, vlanID)

					mp.lastAlert = now
				}
			}
			mp.packetCount = 0
			mp.lastReset = now
		}
		mp.mu.Unlock()
	}
}
