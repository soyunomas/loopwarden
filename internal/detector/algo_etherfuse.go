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

const (
	offset64 = 14695981039346656037
	prime64  = 1099511628211
)

type EtherFuse struct {
	cfg            *config.EtherFuseConfig
	notify         *notifier.Notifier
	mu             sync.Mutex 

	ringBuffer  []uint64
	lookupTable map[uint64]uint8 
	writeCursor int              

	packetsSec    uint64
	lastReset     time.Time
	lastAlertTime time.Time
}

func NewEtherFuse(cfg *config.EtherFuseConfig, n *notifier.Notifier) *EtherFuse {
	return &EtherFuse{
		cfg:         cfg,
		notify:      n,
		ringBuffer:  make([]uint64, cfg.HistorySize),
		lookupTable: make(map[uint64]uint8, cfg.HistorySize),
		writeCursor: 0,
		lastReset:   time.Now(),
	}
}

func (ef *EtherFuse) Name() string { return "EtherFuse" }

func (ef *EtherFuse) Start(conn *packet.Conn, iface *net.Interface) error { return nil }

func hashBody(data []byte) uint64 {
	var hash uint64 = offset64
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}

func (ef *EtherFuse) OnPacket(data []byte, length int, vlanID uint16) {
	// 1. Calcular Hash del contenido
	sum := hashBody(data[:length])

	ef.mu.Lock()

	// Check de tormenta global (PPS)
	ef.packetsSec++
	if ef.packetsSec&0x3FF == 0 { 
		now := time.Now()
		if now.Sub(ef.lastReset) >= time.Second {
			if ef.packetsSec > ef.cfg.StormPPSLimit {
				if now.Sub(ef.lastAlertTime) > 5*time.Second {
					// Extraer ubicación para la alerta de tormenta
					loc := "Native"
					if vlanID != 0 { loc = fmt.Sprintf("%d", vlanID) }
					go ef.notify.Alert(fmt.Sprintf("[EtherFuse] ⛈️ STORM DETECTED! VLAN: %s | Rate: %d pps", loc, ef.packetsSec))
					ef.lastAlertTime = now
				}
			}
			ef.packetsSec = 0
			ef.lastReset = now
		}
	}

	// 2. Lógica de detección de bucle por repetición de hash
	count := ef.lookupTable[sum]

	if count > 0 {
		newCount := count + 1
		ef.lookupTable[sum] = newCount

		if int(newCount) > ef.cfg.AlertThreshold {
			if time.Since(ef.lastAlertTime) > 5*time.Second {
				
				// --- NUEVA LÓGICA DE EXTRACCIÓN DE MACs ---
				// Extraemos los datos ANTES de disparar la goroutine para evitar race conditions
				// con el buffer del sniffer.
				dstMac := "Unknown"
				srcMac := "Unknown"
				if length >= 12 {
					dstMac = net.HardwareAddr(data[0:6]).String()
					srcMac = net.HardwareAddr(data[6:12]).String()
				}

				vlanStr := "Native"
				if vlanID != 0 {
					vlanStr = fmt.Sprintf("%d", vlanID)
				}

				// Formatear mensaje detallado
				msg := fmt.Sprintf("[EtherFuse] 🚨 LOOP DETECTED!\n"+
					"    VLAN: %s\n"+
					"    SOURCE MAC: %s\n"+
					"    DEST MAC:   %s\n"+
					"    PACKET HASH: %x\n"+
					"    REPETITIONS: %d", 
					vlanStr, srcMac, dstMac, sum, newCount)

				go ef.notify.Alert(msg)
				ef.lastAlertTime = time.Now()
			}
			// Reset para evitar spam del mismo paquete
			ef.lookupTable[sum] = 0
		}
	} else {
		// Nuevo hash, actualizar ring buffer
		oldHash := ef.ringBuffer[ef.writeCursor]
		if oldHash != 0 {
			delete(ef.lookupTable, oldHash)
		}
		ef.ringBuffer[ef.writeCursor] = sum
		ef.lookupTable[sum] = 1
		ef.writeCursor = (ef.writeCursor + 1) % len(ef.ringBuffer)
	}

	ef.mu.Unlock()
}
