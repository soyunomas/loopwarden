package detector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry" // IMPORTAR
	"github.com/soyunomas/loopwarden/internal/utils"
)

const (
	EtherTypeARP    = 0x0806
	EtherTypeIPv6   = 0x86DD
	OpCodeRequest   = 1
	ArpAlertCooldown = 20 * time.Second 
)

type ArpWatchdog struct {
	cfg       *config.ArpWatchConfig
	notify    *notifier.Notifier
	mu        sync.Mutex
	
	packetCount uint64
	lastReset   time.Time
	lastAlert   time.Time 
}

func NewArpWatchdog(cfg *config.ArpWatchConfig, n *notifier.Notifier) *ArpWatchdog {
	return &ArpWatchdog{
		cfg:       cfg,
		notify:    n,
		lastReset: time.Now(),
	}
}

func (aw *ArpWatchdog) Name() string {
	return "ArpWatchdog"
}

func (aw *ArpWatchdog) Start(conn *packet.Conn, iface *net.Interface) error {
	return nil
}

func (aw *ArpWatchdog) OnPacket(data []byte, length int, vlanID uint16) {
	// Offset logic
	ethTypeOffset := 12
	if vlanID != 0 {
		ethTypeOffset = 16
	}

	if length < ethTypeOffset+2 {
		return
	}

	ethType := binary.BigEndian.Uint16(data[ethTypeOffset : ethTypeOffset+2])
	
	isTargetProtocol := false
	protocolName := ""
	metricLabel := "Unknown"

	// 1. Check ARP (IPv4)
	if ethType == EtherTypeARP {
		arpOffset := ethTypeOffset + 2
		if length >= arpOffset+8 {
			opCode := binary.BigEndian.Uint16(data[arpOffset+6 : arpOffset+8])
			if opCode == OpCodeRequest {
				isTargetProtocol = true
				protocolName = "ARP (IPv4)"
				metricLabel = "ArpStorm"
			}
		}
	} else if ethType == EtherTypeIPv6 {
		// 2. Check IPv6 Neighbor Discovery (via Multicast MAC prefix 33:33:ff)
		if length >= 6 {
			dstMac := data[0:6]
			if utils.IsIPv6NeighborDiscovery(dstMac) {
				isTargetProtocol = true
				protocolName = "NDP (IPv6 Neighbor Discovery)"
				metricLabel = "NdpStorm"
			}
		}
	}

	if isTargetProtocol {
		aw.mu.Lock()
		aw.packetCount++
		
		now := time.Now()
		
		if now.Sub(aw.lastReset) >= time.Second {
			if aw.packetCount > aw.cfg.MaxPPS {
				if now.Sub(aw.lastAlert) > ArpAlertCooldown {
					
					// TELEMETRY HIT
					telemetry.EngineHits.WithLabelValues("ArpWatchdog", metricLabel).Inc()
					
					vlanMsg := "Native VLAN"
					if vlanID != 0 {
						vlanMsg = fmt.Sprintf("VLAN %d", vlanID)
					}
					
					// Copiamos el nombre para la goroutine
					pName := protocolName
					count := aw.packetCount

					go func(v string, p string, c uint64) {
						msg := fmt.Sprintf("[ArpWatchdog] 🐶 DISCOVERY STORM DETECTED!\n"+
							"    PROTOCOL: %s\n"+
							"    VLAN:     %s\n"+
							"    RATE:     %d req/s (Limit: %d)\n"+
							"    ACTION:   Check for scanning malware or loops.", 
							p, v, c, aw.cfg.MaxPPS)
						aw.notify.Alert(msg)
					}(vlanMsg, pName, count)
					
					aw.lastAlert = now
				}
			}
			aw.packetCount = 0
			aw.lastReset = now
		}
		aw.mu.Unlock()
	}
}
