package detector

import (
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
					// METRICA AÑADIDA: Tormenta detectada
					telemetry.EngineHits.WithLabelValues("EtherFuse", "GlobalStorm").Inc()
					
					loc := "Native"
					if vlanID != 0 { loc = fmt.Sprintf("%d", vlanID) }
					pps := ef.packetsSec
					go func(l string, p uint64) {
						ef.notify.Alert(fmt.Sprintf("[EtherFuse] ⛈️ GLOBAL STORM DETECTED! VLAN: %s | Rate: %d pps", l, p))
					}(loc, pps)
					ef.lastAlertTime = now
				}
			}
			ef.packetsSec = 0
			ef.lastReset = now
		}
	}

	// 2. Lógica de detección de bucle
	count := ef.lookupTable[sum]

	if count > 0 {
		newCount := count + 1
		ef.lookupTable[sum] = newCount

		if int(newCount) > ef.cfg.AlertThreshold {
			if time.Since(ef.lastAlertTime) > 5*time.Second {
				
				// METRICA AÑADIDA: Bucle detectado
				telemetry.EngineHits.WithLabelValues("EtherFuse", "LoopDetected").Inc()

				var dstMacBytes, srcMacBytes []byte
				if length >= 12 {
					dstMacBytes = make([]byte, 6)
					srcMacBytes = make([]byte, 6)
					copy(dstMacBytes, data[0:6])
					copy(srcMacBytes, data[6:12])
				}

				vlanStr := "Native"
				if vlanID != 0 {
					vlanStr = fmt.Sprintf("%d", vlanID)
				}

				go func(v string, sMac, dMac []byte, h uint64, reps uint8) {
					targetInfo := utils.ClassifyMAC(dMac)
					impact := "User Traffic"
					if targetInfo.IsCritical {
						impact = "🔥 CRITICAL INFRASTRUCTURE FAILURE"
					}

					srcStr := net.HardwareAddr(sMac).String()
					dstStr := net.HardwareAddr(dMac).String()

					msg := fmt.Sprintf("[EtherFuse] 🚨 LOOP DETECTED!\n"+
						"    VLAN:        %s\n"+
						"    SOURCE MAC:  %s\n"+
						"    TARGET MAC:  %s (%s)\n"+
						"    PROTOCOL:    %s\n"+
						"    IMPACT:      %s\n"+
						"    REPETITIONS: %d (Hash: %x)", 
						v, srcStr, dstStr, targetInfo.Name, targetInfo.Description, impact, reps, h)

					ef.notify.Alert(msg)
				}(vlanStr, srcMacBytes, dstMacBytes, sum, newCount)

				ef.lastAlertTime = time.Now()
			}
			ef.lookupTable[sum] = 0
		}
	} else {
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
