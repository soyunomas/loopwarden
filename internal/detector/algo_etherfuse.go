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
	store     *TopologyStore
	mu        sync.Mutex

	// --- Configuración Efectiva ---
	alertThreshold int
	stormPPSLimit  uint64
	cooldown       time.Duration

	// --- Estado Detección de Bucle (Payload Hash) ---
	ringBuffer  []uint64
	lookupTable map[uint64]uint8
	writeCursor int

	// --- Estado Detección de Tormenta Global (PPS) ---
	packetsSec    uint64
	lastReset     time.Time
	lastAlertTime time.Time
	
	// Forense Ligero para Tormentas
	lastStormSrc   [6]byte // Última MAC vista (Muestra estadística del culpable)
	bcastCount     uint64  // Contador aproximado de Broadcast
	mcastCount     uint64  // Contador aproximado de Multicast
}

func NewEtherFuse(cfg *config.EtherFuseConfig, n *notifier.Notifier, ifaceName string, store *TopologyStore) *EtherFuse {
	return &EtherFuse{
		cfg:         cfg,
		notify:      n,
		ifaceName:   ifaceName,
		store:       store,
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
	// 1. Calcular Hash FNV-1a (Solo payload útil)
	// Asumimos que data incluye headers ethernet, hashBody procesa todo.
	// Para mayor precisión, podríamos hashear solo desde byte 14, pero el header cambia poco en bucles.
	sum := hashBody(data[:length])

	// Forense Rápido (Zero-Alloc extraction)
	var srcMac [6]byte
	if length >= 12 {
		copy(srcMac[:], data[6:12])
	}
	isBcast := (data[0] & 1) == 1 // Bit multicast activo
	// Refinamiento: Broadcast puro es FF:FF...
	isPureBcast := (data[0] == 0xFF && data[1] == 0xFF)

	ef.mu.Lock()

	// ------------------------------------------------------------
	// A. LOGICA DE TORMENTA GLOBAL (PPS LIMIT)
	// ------------------------------------------------------------
	ef.packetsSec++
	
	// Actualizamos estadísticas de la tormenta actual
	ef.lastStormSrc = srcMac
	if isPureBcast {
		ef.bcastCount++
	} else if isBcast {
		ef.mcastCount++
	}

	// Chequeo optimizado (Bitmask Check cada 1024 paquetes)
	if ef.packetsSec&0x3FF == 0 { 
		now := time.Now()
		if now.Sub(ef.lastReset) >= time.Second {
			// Se ha cumplido 1 segundo, evaluamos si hay tormenta
			if ef.packetsSec > ef.stormPPSLimit {
				if now.Sub(ef.lastAlertTime) > ef.cooldown {
					telemetry.EngineHits.WithLabelValues(ef.ifaceName, "EtherFuse", "GlobalStorm").Inc()

					// Contexto de la alerta
					loc := "Native"
					if vlanID != 0 {
						loc = fmt.Sprintf("%d", vlanID)
					}
					
					// Análisis del tráfico dominante
					stormType := "Unicast Flood"
					if ef.bcastCount > ef.mcastCount && ef.bcastCount > (ef.packetsSec/2) {
						stormType = "Broadcast Storm (Layer 2 Loop)"
					} else if ef.mcastCount > ef.bcastCount {
						stormType = "Multicast Storm (Video/Cloning)"
					}

					// Información del Culpable (Probabilística: Último paquete visto)
					sampleSrc := ef.lastStormSrc[:]
					srcInfo := utils.ClassifyMAC(sampleSrc)
					srcStr := net.HardwareAddr(sampleSrc).String()

					// Información de Topología
					topoInfo := "Unknown (No Neighbor Info)"
					if neighbor, found := ef.store.Get(ef.ifaceName); found {
						topoInfo = neighbor.String()
					}

					// Variables capturadas para goroutine
					pps := ef.packetsSec
					currentIface := ef.ifaceName

					go func(iface, vlan, sType, sMac, sVendor, sDesc, topo string, rate uint64) {
						msg := fmt.Sprintf("[EtherFuse] ⛈️ GLOBAL STORM DETECTED!\n"+
							"    INTERFACE:   %s\n"+
							"    VLAN:        %s\n"+
							"    RATE:        %d pps\n"+
							"    STORM TYPE:  %s\n"+
							"    SAMPLE SRC:  %s (%s - %s)\n"+
							"    CONNECTED:   %s", 
							iface, vlan, rate, sType, sMac, sVendor, sDesc, topo)
						ef.notify.Alert(msg)
					}(currentIface, loc, stormType, srcStr, srcInfo.Name, srcInfo.Description, topoInfo, pps)
					
					ef.lastAlertTime = now
				}
			}
			// Reset de contadores de segundo
			ef.packetsSec = 0
			ef.bcastCount = 0
			ef.mcastCount = 0
			ef.lastReset = now
		}
	}

	// ------------------------------------------------------------
	// B. LOGICA DE DETECCIÓN DE BUCLE (HASH DEDUPLICATION)
	// ------------------------------------------------------------
	count := ef.lookupTable[sum]

	if count > 0 {
		newCount := count + 1
		ef.lookupTable[sum] = newCount

		if int(newCount) > ef.alertThreshold {
			if time.Since(ef.lastAlertTime) > ef.cooldown {

				telemetry.EngineHits.WithLabelValues(ef.ifaceName, "EtherFuse", "LoopDetected").Inc()

				// Extracción de MACs para reporte
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

				// Topología
				neighborInfoStr := ""
				if neighbor, found := ef.store.Get(currentIface); found {
					neighborInfoStr = fmt.Sprintf("\n    UPSTREAM:    %s", neighbor.String())
				} else {
					neighborInfoStr = "\n    UPSTREAM:    Unknown (No Discovery Data)"
				}

				go func(iface string, v string, sMac, dMac []byte, h uint64, reps uint8, topoInfo string) {
					targetInfo := utils.ClassifyMAC(dMac)
					impact := "User Traffic"
					if targetInfo.IsCritical {
						impact = "🔥 CRITICAL INFRASTRUCTURE FAILURE"
					}

					srcStr := net.HardwareAddr(sMac).String()
					dstStr := net.HardwareAddr(dMac).String()

					msg := fmt.Sprintf("[EtherFuse] 🚨 LOOP DETECTED (Repeated Payload)!\n"+
						"    INTERFACE:   %s\n"+
						"    VLAN:        %s\n"+
						"    SOURCE MAC:  %s\n"+
						"    TARGET MAC:  %s (%s)\n"+
						"    PROTOCOL:    %s\n"+
						"    IMPACT:      %s\n"+
						"    REPETITIONS: %d (Hash: %x)%s", 
						iface, v, srcStr, dstStr, targetInfo.Name, targetInfo.Description, impact, reps, h, topoInfo)

					ef.notify.Alert(msg)
				}(currentIface, vlanStr, srcMacBytes, dstMacBytes, sum, newCount, neighborInfoStr)

				ef.lastAlertTime = time.Now()
			}
			ef.lookupTable[sum] = 0
		}
	} else {
		// Mantenimiento del Ring Buffer
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
