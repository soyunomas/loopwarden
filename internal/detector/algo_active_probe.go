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
	}

	broadcastHW := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	ap.destAddr = &packet.Addr{
		HardwareAddr: broadcastHW,
	}

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, ap.ethertype)

	// --- GENERACIÓN DE PAYLOAD CON IDENTIDAD ---
	// Formato: "MAGIC_STRING|nombre_interfaz"
	fullPayload := fmt.Sprintf("%s|%s", ap.cfg.MagicPayload, ap.ifaceName)
	payloadBytes := []byte(fullPayload)

	frame := make([]byte, 0, 14+len(payloadBytes))
	frame = append(frame, broadcastHW...)
	frame = append(frame, ap.myMAC...)
	frame = append(frame, typeBytes...)
	frame = append(frame, payloadBytes...)

	ap.probeFrame = frame

	log.Printf("✅ [ActiveProbe:%s] Active. Freq: %dms, EtherType: 0x%X", ap.ifaceName, ap.intervalMs, ap.ethertype)

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

	// -------------------------------------------------------------------------
	// OPTIMIZACIÓN CRÍTICA (Precepto #3): Chequeo rápido de EtherType primero.
	// -------------------------------------------------------------------------
	etherType := binary.BigEndian.Uint16(data[etherTypeOffset : etherTypeOffset+2])
	
	// Si no es el protocolo de sonda (ej: 0xFFFF), salimos inmediatamente.
	// Esto descarta el 99.9% del tráfico antes de hacer allocs o comparaciones caras.
	if etherType != ap.ethertype {
		return
	}

	// -------------------------------------------------------------------------
	// CORRECCIÓN DE BUG: Eliminado "if bytes.Equal(srcMac, ap.myMAC)"
	// Ahora procesamos cualquier paquete con nuestro EtherType, venga de quien venga.
	// -------------------------------------------------------------------------

	payload := data[headerSize:length]
	
	// Construimos el prefijo mágico esperado (ej: "LOOPWARDEN_PROBE|")
	// Nota: Esto crea un slice pequeño, aceptable en este punto porque ya pasamos el filtro de EtherType.
	magic := []byte(ap.cfg.MagicPayload + "|")
	
	if bytes.Contains(payload, magic) {
		ap.mu.Lock()
		defer ap.mu.Unlock()
		
		now := time.Now()
		if now.Sub(ap.lastAlert) > ProbeAlertCooldown {
			
			// Extracción robusta del nombre de la interfaz remota
			idx := bytes.Index(payload, magic)
			if idx == -1 { return } // Should not happen due to Contains check

			startSuffix := idx + len(magic)
			suffixBytes := payload[startSuffix:]
			
			// Limpieza de padding nulo (zero-byte termination) si el driver añade padding ethernet
			nullIdx := bytes.IndexByte(suffixBytes, 0)
			if nullIdx != -1 {
				suffixBytes = suffixBytes[:nullIdx]
			}
			remoteIface := string(suffixBytes)

			var alertMsg string
			var alertType string

			// --- LÓGICA DE DETECCIÓN DE TOPOLOGÍA ---
			if remoteIface == ap.ifaceName {
				// CASO A: SELF-LOOP (Hard Loop)
				// La sonda salió de mí y volvió a mí.
				alertType = "HardLoop"
				alertMsg = fmt.Sprintf("[%s] 🚨 LOOP CONFIRMED! (Self-Loop)\n"+
					"    INTERFACE: %s\n"+
					"    STATUS:    Cable connects interface back to itself.\n"+
					"    ACTION:    IMMEDIATE DISCONNECT.", ap.ifaceName, ap.ifaceName)
			} else {
				// CASO B: CROSS-DOMAIN LOOP
				// La sonda salió de OTRA interfaz (ej: ens18) y llegó a mí (ens19).
				alertType = "CrossDomainLoop"
				alertMsg = fmt.Sprintf("[%s] ☣️ CRITICAL TOPOLOGY ERROR (Cross-Domain)!\n"+
					"    INTERFACE: %s\n"+
					"    DETECTED:  Physical bridge between two different networks.\n"+
					"    PATH:      [Remote: %s]  ===>  [Local: %s]\n"+
					"    ACTION:    Check cabling between these two segments immediately.", 
					ap.ifaceName, ap.ifaceName, remoteIface, ap.ifaceName)
			}

			telemetry.EngineHits.WithLabelValues(ap.ifaceName, "ActiveProbe", alertType).Inc()
			
			dstMac := data[0:6] // Destination MAC (Broadcast FF:FF...)
			srcMac := data[6:12] // Source MAC (Quien generó la sonda)
			
			retInfo := utils.ClassifyMAC(dstMac)
			
			fullMsg := fmt.Sprintf("%s\n    SOURCE MAC: %s\n    DEST TYPE:  %s", 
				alertMsg, net.HardwareAddr(srcMac).String(), retInfo.Description)
			
			go ap.notify.Alert(fullMsg)

			ap.lastAlert = now
		}
	}
}
