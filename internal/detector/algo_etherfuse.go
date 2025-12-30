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
	// FNV-1a constantes para implementación inline (evita import hash/fnv y allocs)
	offset64 = 14695981039346656037
	prime64  = 1099511628211
)

type EtherFuse struct {
	cfg            *config.EtherFuseConfig
	notify         *notifier.Notifier
	mu             sync.Mutex // Protege todo el estado interno

	// OPTIMIZACIÓN 1: Estructura Dual (Ring + Map) para O(1)
	ringBuffer  []uint64
	lookupTable map[uint64]uint8 // Count de apariciones
	writeCursor int              // Puntero del Ring Buffer

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

// Inline FNV-1a implementation (Zero Allocation)
func hashBody(data []byte) uint64 {
	var hash uint64 = offset64
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}

func (ef *EtherFuse) OnPacket(data []byte, length int, vlanID uint16) {
	// 1. Hashing sin allocs
	sum := hashBody(data[:length])

	ef.mu.Lock()

	// Check rápido de tormenta global
	ef.packetsSec++
	if ef.packetsSec&0x3FF == 0 { // Check cada 1024 paquetes
		now := time.Now()
		if now.Sub(ef.lastReset) >= time.Second {
			if ef.packetsSec > ef.cfg.StormPPSLimit {
				if now.Sub(ef.lastAlertTime) > 5*time.Second {
					go ef.notify.Alert(fmt.Sprintf("[EtherFuse] ⛈️ Storm: %d pps", ef.packetsSec))
					ef.lastAlertTime = now
				}
			}
			ef.packetsSec = 0
			ef.lastReset = now
		}
	}

	// 2. Lógica O(1) de detección de bucle
	count := ef.lookupTable[sum]

	if count > 0 {
		// Es un duplicado
		newCount := count + 1
		ef.lookupTable[sum] = newCount

		if int(newCount) > ef.cfg.AlertThreshold {
			if time.Since(ef.lastAlertTime) > 5*time.Second {
				go ef.notify.Alert(fmt.Sprintf("[EtherFuse] 🚨 LOOP: Hash %x seen %d times", sum, newCount))
				ef.lastAlertTime = time.Now()
			}
			// Reset count to avoid spamming
			ef.lookupTable[sum] = 0
		}
	} else {
		// Nuevo hash.
		oldHash := ef.ringBuffer[ef.writeCursor]

		if oldHash != 0 {
			delete(ef.lookupTable, oldHash)
		}

		ef.ringBuffer[ef.writeCursor] = sum
		ef.lookupTable[sum] = 1

		ef.writeCursor++
		if ef.writeCursor >= len(ef.ringBuffer) {
			ef.writeCursor = 0
		}
	}

	ef.mu.Unlock()
}
