package detector

import (
	"bytes"
	"encoding/binary"
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

const ProbeAlertCooldown = 10 * time.Second

type ActiveProbe struct {
	cfg        *config.ActiveProbeConfig
	notify     *notifier.Notifier
	myMAC      net.HardwareAddr
	ifaceName  string
	
	// Configuración Efectiva
	intervalMs int
	ethertype  uint16
	
	probeFrame []byte
	destAddr   *packet.Addr

	mu        sync.Mutex
	lastAlert time.Time
}

func NewActiveProbe(cfg *config.ActiveProbeConfig, n *notifier.Notifier, ifaceName string) *ActiveProbe {
	return &ActiveProbe{
		cfg:       cfg,
		notify:    n,
		ifaceName: ifaceName,
	}
}

func (ap *ActiveProbe) Name() string {
	return "ActiveProbe"
}

func (ap *ActiveProbe) Start(conn *packet.Conn, iface *net.Interface) error {
	ap.myMAC = iface.HardwareAddr
	
	// 1. Calcular Configuración Efectiva
	ap.intervalMs = ap.cfg.IntervalMs
	ap.ethertype = ap.cfg.Ethertype

	if override, ok := ap.cfg.Overrides[iface.Name]; ok {
		if override.IntervalMs > 0 {
			ap.intervalMs = override.IntervalMs
			log.Printf("🔧 [ActiveProbe] Override applied for %s: Interval = %dms", iface.Name, ap.intervalMs)
		}
		// Ethertype es raro sobrescribirlo, pero el struct lo permite, así que lo respetamos
		// Nota: ActiveProbeOverride no tenía Ethertype en config.go, pero si lo tuviera, aquí iría.
		// Asumiendo que config.go en ActiveProbeOverride solo tiene IntervalMs según tu ejemplo anterior.
	}

	broadcastHW := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	ap.destAddr = &packet.Addr{
		HardwareAddr: broadcastHW,
	}

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, ap.ethertype)

	// --- GENERACIÓN DE PAYLOAD CON IDENTIDAD ---
	fullPayload := fmt.Sprintf("%s|%s", ap.cfg.MagicPayload, ap.ifaceName)
	payloadBytes := []byte(fullPayload)

	frame := make([]byte, 0, 14+len(payloadBytes))
	frame = append(frame, broadcastHW...)
	frame = append(frame, ap.myMAC...)
	frame = append(frame, typeBytes...)
	frame = append(frame, payloadBytes...)

	ap.probeFrame = frame

	log.Printf("[%s] ActiveProbe Initialized. Frequency: %dms", ap.ifaceName, ap.intervalMs)

	// 2. Usar Intervalo Efectivo en el Ticker
	go func() {
		ticker := time.NewTicker(time.Duration(ap.intervalMs) * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			_, _ = conn.WriteTo(ap.probeFrame, ap.destAddr)
		}
	}()

	return nil
}

func (ap *ActiveProbe) OnPacket(data []byte, length int, vlanID uint16) {
	headerSize := 14
	etherTypeOffset := 12
	if vlanID != 0 {
		headerSize = 18
		etherTypeOffset = 16
	}

	if length < headerSize {
		return
	}

	srcMac := data[6:12]

	if bytes.Equal(srcMac, ap.myMAC) {
		etherType := binary.BigEndian.Uint16(data[etherTypeOffset : etherTypeOffset+2])

		// Usamos variable local ap.ethertype
		if etherType == ap.ethertype {
			payload := data[headerSize:length]
			
			magic := []byte(ap.cfg.MagicPayload + "|")
			
			if bytes.Contains(payload, magic) {
				ap.mu.Lock()
				defer ap.mu.Unlock()
				
				now := time.Now()
				if now.Sub(ap.lastAlert) > ProbeAlertCooldown {
					
					idx := bytes.Index(payload, magic)
					if idx == -1 { return }

					startSuffix := idx + len(magic)
					suffixBytes := payload[startSuffix:]
					nullIdx := bytes.IndexByte(suffixBytes, 0)
					if nullIdx != -1 {
						suffixBytes = suffixBytes[:nullIdx]
					}
					remoteIface := string(suffixBytes)

					var alertMsg string
					var alertType string

					if remoteIface == ap.ifaceName {
						alertType = "HardLoop"
						alertMsg = fmt.Sprintf("[%s] 🚨 LOOP CONFIRMED! (Self-Loop)\n"+
							"    STATUS: Cable connects interface %s back to itself via switch.\n"+
							"    ACTION: IMMEDIATE DISCONNECT.", ap.ifaceName, ap.ifaceName)
					} else {
						alertType = "CrossDomainLoop"
						alertMsg = fmt.Sprintf("[%s] ☣️ CRITICAL TOPOLOGY ERROR (Cross-Domain)!\n"+
							"    DETECTED: Physical bridge between two different networks.\n"+
							"    PATH:     [Remote: %s]  ===>  [Local: %s]\n"+
							"    ACTION:   Check cabling between these two segments immediately.", 
							ap.ifaceName, remoteIface, ap.ifaceName)
					}

					telemetry.EngineHits.WithLabelValues("ActiveProbe", alertType).Inc()
					
					dstMac := data[0:6]
					retInfo := utils.ClassifyMAC(dstMac)
					
					fullMsg := fmt.Sprintf("%s\n    RETURN PATH: %s", alertMsg, retInfo.Description)
					
					go ap.notify.Alert(fullMsg)

					ap.lastAlert = now
				}
			}
		}
	}
}
