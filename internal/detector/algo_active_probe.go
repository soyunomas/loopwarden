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
)

const ProbeAlertCooldown = 10 * time.Second

type ActiveProbe struct {
	cfg        *config.ActiveProbeConfig
	notify     *notifier.Notifier
	myMAC      net.HardwareAddr
	probeFrame []byte
	destAddr   *packet.Addr

	mu        sync.Mutex
	lastAlert time.Time
}

func NewActiveProbe(cfg *config.ActiveProbeConfig, n *notifier.Notifier) *ActiveProbe {
	return &ActiveProbe{
		cfg:    cfg,
		notify: n,
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
	payload := []byte(ap.cfg.MagicPayload)

	frame := make([]byte, 0, 14+len(payload))
	frame = append(frame, broadcastHW...)
	frame = append(frame, ap.myMAC...)
	frame = append(frame, typeBytes...)
	frame = append(frame, payload...)

	ap.probeFrame = frame

	log.Printf("[ActiveProbe] Initialized. Sending probes every %dms (Type: 0x%X)", ap.cfg.IntervalMs, ap.cfg.Ethertype)

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
	if bytes.Equal(srcMac, ap.myMAC) {
		etherType := binary.BigEndian.Uint16(data[etherTypeOffset : etherTypeOffset+2])

		if etherType == ap.cfg.Ethertype {
			payload := data[headerSize:length]
			if bytes.Contains(payload, []byte(ap.cfg.MagicPayload)) {
				
				ap.mu.Lock()
				now := time.Now()
				if now.Sub(ap.lastAlert) > ProbeAlertCooldown {
					vlanMsg := "Native VLAN"
					if vlanID != 0 {
						vlanMsg = fmt.Sprintf("VLAN %d", vlanID)
					}
					
					msg := fmt.Sprintf("[ActiveProbe] 🚨 LOOP CONFIRMED! My probe returned on %s! (Type: 0x%X)", vlanMsg, etherType)
					ap.notify.Alert(msg)
					ap.lastAlert = now
				}
				ap.mu.Unlock()
			}
		}
	}
}
