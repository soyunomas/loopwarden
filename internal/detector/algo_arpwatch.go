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
	EtherTypeARP    = 0x0806
	OpCodeRequest   = 1
	ArpAlertCooldown = 20 * time.Second // 🔇 Solo 1 alerta cada 20s
)

type ArpWatchdog struct {
	cfg       *config.ArpWatchConfig
	notify    *notifier.Notifier
	mu        sync.Mutex
	
	packetCount uint64
	lastReset   time.Time
	
	// OPT(14): Variable de estado para controlar el silencio
	lastAlert   time.Time 
}

func NewArpWatchdog(cfg *config.ArpWatchConfig, n *notifier.Notifier) *ArpWatchdog {
	return &ArpWatchdog{
		cfg:       cfg,
		notify:    n,
		lastReset: time.Now(),
		// Inicializamos en zero-value, funcionará bien
	}
}

func (aw *ArpWatchdog) Name() string {
	return "ArpWatchdog"
}

func (aw *ArpWatchdog) Start(conn *packet.Conn, iface *net.Interface) error {
	return nil
}

func (aw *ArpWatchdog) OnPacket(data []byte, length int, vlanID uint16) {
	// Cálculo de offsets (VLAN vs Native)
	ethTypeOffset := 12
	if vlanID != 0 {
		ethTypeOffset = 16
	}

	if length < ethTypeOffset+2 {
		return
	}

	// OPT(11): Lectura directa sin allocs
	ethType := binary.BigEndian.Uint16(data[ethTypeOffset : ethTypeOffset+2])
	
	if ethType != EtherTypeARP {
		return
	}

	arpOffset := ethTypeOffset + 2
	if length < arpOffset+8 {
		return
	}

	// OpCode check (Request = 1)
	opCode := binary.BigEndian.Uint16(data[arpOffset+6 : arpOffset+8])

	if opCode == OpCodeRequest {
		aw.mu.Lock()
		aw.packetCount++
		
		now := time.Now()
		
		// Ventana de tiempo: 1 segundo
		if now.Sub(aw.lastReset) >= time.Second {
			
			// Si superamos el umbral de PPS...
			if aw.packetCount > aw.cfg.MaxPPS {
				
				// ... Y ha pasado el tiempo de enfriamiento (Cooldown)
				if now.Sub(aw.lastAlert) > ArpAlertCooldown {
					
					vlanMsg := "Native VLAN"
					if vlanID != 0 {
						vlanMsg = fmt.Sprintf("VLAN %d", vlanID)
					}
					
					msg := fmt.Sprintf("[ArpWatchdog] 🐶 ARP STORM DETECTED on %s! Rate: %d req/s (Limit: %d) - Throttling logs for 20s", 
						vlanMsg, aw.packetCount, aw.cfg.MaxPPS)
					
					aw.notify.Alert(msg)
					
					// Marcamos el momento de la alerta
					aw.lastAlert = now
				}
			}
			
			// Siempre reseteamos el contador cada segundo, hayamos alertado o no
			aw.packetCount = 0
			aw.lastReset = now
		}
		aw.mu.Unlock()
	}
}
