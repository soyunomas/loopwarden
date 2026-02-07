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
	store      *TopologyStore // Referencia al TopologyStore
	
	// Configuración Efectiva
	intervalMs int
	ethertype  uint16
	domain     string 
	
	probeFrame []byte
	destAddr   *packet.Addr

	mu        sync.Mutex
	lastAlert time.Time
}

// Constructor actualizado para aceptar TopologyStore
func NewActiveProbe(cfg *config.ActiveProbeConfig, n *notifier.Notifier, ifaceName string, store *TopologyStore) *ActiveProbe {
	return &ActiveProbe{
		cfg:       cfg,
		notify:    n,
		ifaceName: ifaceName,
		store:     store,
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
	ap.domain = ap.cfg.Domain

	// Default fallback si no se configura dominio
	if ap.domain == "" {
		ap.domain = "default"
	}

	if override, ok := ap.cfg.Overrides[iface.Name]; ok {
		if override.IntervalMs > 0 {
			ap.intervalMs = override.IntervalMs
		}
		if override.Domain != "" {
			ap.domain = override.Domain
		}
	}
	
	log.Printf("🔧 [ActiveProbe] Config for %s: Interval=%dms, Domain='%s'", iface.Name, ap.intervalMs, ap.domain)

	broadcastHW := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	ap.destAddr = &packet.Addr{
		HardwareAddr: broadcastHW,
	}

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, ap.ethertype)

	// --- GENERACIÓN DE PAYLOAD CON IDENTIDAD Y DOMINIO ---
	// Formato V2: "MAGIC_STRING|nombre_interfaz|dominio"
	fullPayload := fmt.Sprintf("%s|%s|%s", ap.cfg.MagicPayload, ap.ifaceName, ap.domain)
	payloadBytes := []byte(fullPayload)

	frame := make([]byte, 0, 14+len(payloadBytes))
	frame = append(frame, broadcastHW...)
	frame = append(frame, ap.myMAC...)
	frame = append(frame, typeBytes...)
	frame = append(frame, payloadBytes...)

	ap.probeFrame = frame

	log.Printf("✅ [ActiveProbe:%s] Active. EtherType: 0x%X", ap.ifaceName, ap.ethertype)

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

	// OPTIMIZACIÓN: Chequeo rápido de EtherType.
	etherType := binary.BigEndian.Uint16(data[etherTypeOffset : etherTypeOffset+2])
	
	if etherType != ap.ethertype {
		return
	}

	payload := data[headerSize:length]
	
	// Magic check rápido
	magicPrefix := []byte(ap.cfg.MagicPayload + "|")
	if !bytes.Contains(payload, magicPrefix) {
		return
	}
	
	ap.mu.Lock()
	defer ap.mu.Unlock()
	
	now := time.Now()
	// Throttling
	if now.Sub(ap.lastAlert) <= ProbeAlertCooldown {
		return
	}

	// Parse payload: MAGIC|IFACE|DOMAIN
	cleanedPayload := bytes.TrimRight(payload, "\x00")
	parts := bytes.Split(cleanedPayload, []byte("|"))

	if len(parts) < 2 {
		return 
	}

	remoteIface := string(parts[1])
	remoteDomain := "default"
	if len(parts) >= 3 {
		remoteDomain = string(parts[2])
	}

	srcMac := data[6:12]
	
	isSelfMac := bytes.Equal(srcMac, ap.myMAC)
	isSameDomain := (remoteDomain == ap.domain)
	
	var alertType string
	var alertMsg string
	shouldAlert := false

	// --- ENRIQUECIMIENTO CON TOPOLOGÍA ---
	// Consultamos el store. Si sabemos a qué switch estamos conectados, lo decimos.
	topologyInfo := ""
	if neighbor, found := ap.store.Get(ap.ifaceName); found {
		topologyInfo = fmt.Sprintf("\n    CONNECTED TO: %s", neighbor.String())
	} else {
		topologyInfo = "\n    CONNECTED TO: Unknown (No LLDP/CDP detected)"
	}

	if isSelfMac {
		// CASO 1: AUTO-BUCLE (Hard Loop)
		shouldAlert = true
		alertType = "HardLoop"
		alertMsg = fmt.Sprintf("[%s] 🚨 LOOP CONFIRMED! (Self-Loop)\n"+
			"    INTERFACE: %s\n"+
			"    STATUS:    Cable connects interface back to itself.\n"+
			"    ACTION:    IMMEDIATE DISCONNECT.%s", 
			ap.ifaceName, ap.ifaceName, topologyInfo)

	} else {
		// Viene de OTRA MAC
		if isSameDomain {
			// CASO 2: VECINO LEGÍTIMO
			shouldAlert = false 
		} else {
			// CASO 3: CRUCE DE DOMINIOS (Cross-Domain Loop)
			shouldAlert = true
			alertType = "CrossDomainLoop"
			
			alertMsg = fmt.Sprintf("[%s] ☣️ CRITICAL TOPOLOGY ERROR (Cross-Domain)!\n"+
				"    INTERFACE: %s (Domain: %s)\n"+
				"    REMOTE:    %s (Domain: %s)\n"+
				"    DETECTED:  Physical bridge between two different networks.\n"+
				"    ACTION:    Check cabling between these two segments immediately.%s", 
				ap.ifaceName, ap.ifaceName, ap.domain, remoteIface, remoteDomain, topologyInfo)
		}
	}

	if shouldAlert {
		telemetry.EngineHits.WithLabelValues(ap.ifaceName, "ActiveProbe", alertType).Inc()
		
		dstMac := data[0:6] 
		retInfo := utils.ClassifyMAC(dstMac)
		
		fullMsg := fmt.Sprintf("%s\n    SOURCE MAC: %s\n    DEST TYPE:  %s", 
			alertMsg, net.HardwareAddr(srcMac).String(), retInfo.Description)
		
		go ap.notify.Alert(fullMsg)

		ap.lastAlert = now
	}
}
