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
	"github.com/soyunomas/loopwarden/internal/utils"
)

const (
	offset64 = 14695981039346656037
	prime64  = 1099511628211
)

type EtherFuse struct {
	cfg       *config.EtherFuseConfig
	notify    *notifier.Notifier
	ifaceName string
	mu        sync.Mutex

	// --- Configuración Efectiva ---
	alertThreshold int
	stormPPSLimit  uint64
	cooldown       time.Duration

	ringBuffer  []uint64
	lookupTable map[uint64]uint8
	writeCursor int

	packetsSec    uint64
	lastReset     time.Time
	lastAlertTime time.Time
}

func NewEtherFuse(cfg *config.EtherFuseConfig, n *notifier.Notifier, ifaceName string) *EtherFuse {
	return &EtherFuse{
		cfg:         cfg,
		notify:      n,
		ifaceName:   ifaceName,
		ringBuffer:  make([]uint64, cfg.HistorySize),
		lookupTable: make(map[uint64]uint8, cfg.HistorySize),
		writeCursor: 0,
		lastReset:   time.Now(),
	}
}

func (ef *EtherFuse) Name() string { return "EtherFuse" }

func (ef *EtherFuse) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Base Global
	ef.alertThreshold = ef.cfg.AlertThreshold
	ef.stormPPSLimit = ef.cfg.StormPPSLimit
	
	dur, err := time.ParseDuration(ef.cfg.AlertCooldown)
	if err != nil {
		log.Printf("⚠️ [EtherFuse:%s] Invalid AlertCooldown '%s', defaulting to 5s", iface.Name, ef.cfg.AlertCooldown)
		ef.cooldown = 5 * time.Second
	} else {
		ef.cooldown = dur
	}

	// 2. Override
	if override, ok := ef.cfg.Overrides[iface.Name]; ok {
		if override.AlertThreshold > 0 {
			ef.alertThreshold = override.AlertThreshold
		}
		if override.StormPPSLimit > 0 {
			ef.stormPPSLimit = override.StormPPSLimit
		}
		log.Printf("🔧 [EtherFuse:%s] Override Threshold=%d, StormLimit=%d",
			iface.Name, ef.alertThreshold, ef.stormPPSLimit)
	}
	
	// 3. Fallback
	if ef.cooldown == 0 { ef.cooldown = 5 * time.Second }
	
	return nil
}

func hashBody(data []byte) uint64 {
	var hash uint64 = offset64
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}

func (ef *EtherFuse) OnPacket(data []byte, length int, vlanID uint16) {
	// 1. Calcular Hash
	sum := hashBody(data[:length])

	ef.mu.Lock()

	// Check de tormenta global (PPS)
	ef.packetsSec++
	if ef.packetsSec&0x3FF == 0 {
		now := time.Now()
		if now.Sub(ef.lastReset) >= time.Second {
			if ef.packetsSec > ef.stormPPSLimit {
				// Usamos variable configurada
				if now.Sub(ef.lastAlertTime) > ef.cooldown {
					telemetry.EngineHits.WithLabelValues(ef.ifaceName, "EtherFuse", "GlobalStorm").Inc()

					loc := "Native"
					if vlanID != 0 {
						loc = fmt.Sprintf("%d", vlanID)
					}
					pps := ef.packetsSec
					currentIface := ef.ifaceName

					go func(iface string, l string, p uint64) {
						ef.notify.Alert(fmt.Sprintf("[EtherFuse] ⛈️ GLOBAL STORM DETECTED!\n"+
							"    INTERFACE: %s\n"+
							"    VLAN:      %s\n"+
							"    RATE:      %d pps", iface, l, p))
					}(currentIface, loc, pps)
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

		if int(newCount) > ef.alertThreshold {
			// Usamos variable configurada
			if time.Since(ef.lastAlertTime) > ef.cooldown {

				telemetry.EngineHits.WithLabelValues(ef.ifaceName, "EtherFuse", "LoopDetected").Inc()

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
				
				currentIface := ef.ifaceName

				go func(iface string, v string, sMac, dMac []byte, h uint64, reps uint8) {
					targetInfo := utils.ClassifyMAC(dMac)
					impact := "User Traffic"
					if targetInfo.IsCritical {
						impact = "🔥 CRITICAL INFRASTRUCTURE FAILURE"
					}

					srcStr := net.HardwareAddr(sMac).String()
					dstStr := net.HardwareAddr(dMac).String()

					msg := fmt.Sprintf("[EtherFuse] 🚨 LOOP DETECTED!\n"+
						"    INTERFACE:   %s\n"+
						"    VLAN:        %s\n"+
						"    SOURCE MAC:  %s\n"+
						"    TARGET MAC:  %s (%s)\n"+
						"    PROTOCOL:    %s\n"+
						"    IMPACT:      %s\n"+
						"    REPETITIONS: %d (Hash: %x)",
						iface, v, srcStr, dstStr, targetInfo.Name, targetInfo.Description, impact, reps, h)

					ef.notify.Alert(msg)
				}(currentIface, vlanStr, srcMacBytes, dstMacBytes, sum, newCount)

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
