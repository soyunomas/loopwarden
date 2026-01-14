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
	ifaceName  string // <--- CONCIENCIA DE IDENTIDAD
	probeFrame []byte
	destAddr   *packet.Addr

	mu        sync.Mutex
	lastAlert time.Time
}

// NewActiveProbe ahora recibe el nombre de la interfaz
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
	broadcastHW := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	ap.destAddr = &packet.Addr{
		HardwareAddr: broadcastHW,
	}

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, ap.cfg.Ethertype)

	// --- GENERACIÓN DE PAYLOAD CON IDENTIDAD ---
	// Formato: "MAGIC_PAYLOAD|INTERFACE_NAME"
	fullPayload := fmt.Sprintf("%s|%s", ap.cfg.MagicPayload, ap.ifaceName)
	payloadBytes := []byte(fullPayload)

	frame := make([]byte, 0, 14+len(payloadBytes))
	frame = append(frame, broadcastHW...)
	frame = append(frame, ap.myMAC...)
	frame = append(frame, typeBytes...)
	frame = append(frame, payloadBytes...)

	ap.probeFrame = frame

	log.Printf("[%s] ActiveProbe Initialized. Sending identity probes '%s'", ap.ifaceName, fullPayload)

	go func() {
		ticker := time.NewTicker(time.Duration(ap.cfg.IntervalMs) * time.Millisecond)
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

	// Solo analizamos si viene de NOSOTROS (es decir, el paquete dio la vuelta)
	if bytes.Equal(srcMac, ap.myMAC) {
		etherType := binary.BigEndian.Uint16(data[etherTypeOffset : etherTypeOffset+2])

		if etherType == ap.cfg.Ethertype {
			payload := data[headerSize:length]
			
			// Buscamos el separador mágico para extraer la identidad
			// Usamos el prefijo mágico configurado
			magic := []byte(ap.cfg.MagicPayload + "|")
			
			if bytes.Contains(payload, magic) {
				ap.mu.Lock()
				defer ap.mu.Unlock() // Defer es aceptable aquí (Cold path relative)
				
				now := time.Now()
				if now.Sub(ap.lastAlert) > ProbeAlertCooldown {
					
					// Extracción de origen (Parsing zero-alloc style si fuera crítico, aquí string es OK)
					// Buscamos dónde empieza el magic
					idx := bytes.Index(payload, magic)
					if idx == -1 { return } // Should not happen due to Contains check

					// El sufijo comienza después del magic
					startSuffix := idx + len(magic)
					// Limpiamos padding (0x00) si existe
					suffixBytes := payload[startSuffix:]
					nullIdx := bytes.IndexByte(suffixBytes, 0)
					if nullIdx != -1 {
						suffixBytes = suffixBytes[:nullIdx]
					}
					remoteIface := string(suffixBytes)

					// --- LÓGICA DE DETECCIÓN CRUZADA ---
					var alertMsg string
					var alertType string

					if remoteIface == ap.ifaceName {
						// CASO A: SELF LOOP
						alertType = "HardLoop"
						alertMsg = fmt.Sprintf("[%s] 🚨 LOOP CONFIRMED! (Self-Loop)\n"+
							"    STATUS: Cable connects interface %s back to itself via switch.\n"+
							"    ACTION: IMMEDIATE DISCONNECT.", ap.ifaceName, ap.ifaceName)
					} else {
						// CASO B: CROSS LOOP
						alertType = "CrossDomainLoop"
						alertMsg = fmt.Sprintf("[%s] ☣️ CRITICAL TOPOLOGY ERROR (Cross-Domain)!\n"+
							"    DETECTED: Physical bridge between two different networks.\n"+
							"    PATH:     [Remote: %s]  ===>  [Local: %s]\n"+
							"    ACTION:   Check cabling between these two segments immediately.", 
							ap.ifaceName, remoteIface, ap.ifaceName)
					}

					// TELEMETRY
					telemetry.EngineHits.WithLabelValues("ActiveProbe", alertType).Inc()
					
					// Capturamos MAC destino para info extra
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
