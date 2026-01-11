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
)

const (
	EtherTypeMacControl = 0x8808
	OpCodePause         = 0x0001
	PauseAlertCooldown  = 5 * time.Second
)

type FlowPanic struct {
	cfg       *config.FlowPanicConfig
	notify    *notifier.Notifier
	mu        sync.Mutex
	
	packetCount uint64
	lastReset   time.Time
	lastAlert   time.Time
}

func NewFlowPanic(cfg *config.FlowPanicConfig, n *notifier.Notifier) *FlowPanic {
	return &FlowPanic{
		cfg:       cfg,
		notify:    n,
		lastReset: time.Now(),
	}
}

func (fp *FlowPanic) Name() string { return "FlowPanic" }

func (fp *FlowPanic) Start(conn *packet.Conn, iface *net.Interface) error {
	return nil
}

func (fp *FlowPanic) OnPacket(data []byte, length int, vlanID uint16) {
	// Offset logic
	ethTypeOffset := 12
	payloadOffset := 14
	if vlanID != 0 {
		ethTypeOffset = 16
		payloadOffset = 18
	}

	if length < payloadOffset+2 {
		return
	}

	ethType := binary.BigEndian.Uint16(data[ethTypeOffset : ethTypeOffset+2])
	
	if ethType == EtherTypeMacControl {
		opCode := binary.BigEndian.Uint16(data[payloadOffset : payloadOffset+2])
		
		if opCode == OpCodePause {
			fp.mu.Lock()
			fp.packetCount++
			
			now := time.Now()
			if now.Sub(fp.lastReset) >= time.Second {
				if fp.packetCount > fp.cfg.MaxPausePPS {
					if now.Sub(fp.lastAlert) > PauseAlertCooldown {
						
						count := fp.packetCount
						srcMac := net.HardwareAddr(data[6:12]).String()
						
						go func(c uint64, mac string) {
							msg := fmt.Sprintf("[FlowPanic] ⏸️ PAUSE FRAME FLOOD (DoS)!\n"+
								"    SOURCE: %s\n"+
								"    RATE:   %d frames/sec (Limit: %d)\n"+
								"    IMPACT: Network stuck. NIC hardware failure or loop.",
								mac, c, fp.cfg.MaxPausePPS)
							fp.notify.Alert(msg)
						}(count, srcMac)
						
						fp.lastAlert = now
					}
				}
				fp.packetCount = 0
				fp.lastReset = now
			}
			fp.mu.Unlock()
		}
	}
}
