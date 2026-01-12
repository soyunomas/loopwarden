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
	FlapWindowNano = int64(1 * time.Second) 
	FlapCooldownNano = int64(30 * time.Second)
	MaxFlapEntries = 50000
)

type flapEntry struct {
	lastSeen   int64  
	lastAlert  int64  
	lastVLAN   uint16 
	flapCount  uint16 
}

type FlapGuard struct {
	cfg    *config.FlapGuardConfig
	notify *notifier.Notifier
	mu     sync.Mutex
	registry map[[6]byte]flapEntry
}

func NewFlapGuard(cfg *config.FlapGuardConfig, n *notifier.Notifier) *FlapGuard {
	return &FlapGuard{
		cfg:      cfg,
		notify:   n,
		registry: make(map[[6]byte]flapEntry, 1000),
	}
}

func (fg *FlapGuard) Name() string { return "FlapGuard" }

func (fg *FlapGuard) Start(conn *packet.Conn, iface *net.Interface) error {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			fg.mu.Lock()
			now := time.Now().UnixNano()
			expiry := int64(60 * time.Second) 
			
			if len(fg.registry) > MaxFlapEntries {
				expiry = int64(10 * time.Second)
			}

			for mac, entry := range fg.registry {
				if now - entry.lastSeen > expiry {
					delete(fg.registry, mac)
				}
			}
			fg.mu.Unlock()
		}
	}()
	return nil
}

func (fg *FlapGuard) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 12 {
		return
	}

	var srcMac [6]byte
	copy(srcMac[:], data[6:12])
	
	now := time.Now().UnixNano()

	fg.mu.Lock()
	entry, exists := fg.registry[srcMac]

	if !exists {
		if len(fg.registry) >= MaxFlapEntries {
			fg.mu.Unlock()
			return
		}
		
		fg.registry[srcMac] = flapEntry{
			lastVLAN: vlanID,
			lastSeen: now,
		}
		fg.mu.Unlock()
		return
	}

	if entry.lastVLAN != vlanID {
		if (now - entry.lastSeen) < FlapWindowNano {
			entry.flapCount++
		} else {
			entry.flapCount = 1
		}

		entry.lastVLAN = vlanID
		entry.lastSeen = now

		if entry.flapCount >= uint16(fg.cfg.Threshold) {
			if (now - entry.lastAlert) > FlapCooldownNano {
				entry.lastAlert = now
				
				// TELEMETRY HIT
				telemetry.EngineHits.WithLabelValues("FlapGuard", "MacFlapping").Inc()

				fg.registry[srcMac] = entry
				fg.mu.Unlock()
				
				go fg.sendAlert(srcMac, entry.flapCount, vlanID)
				return
			}
		}
		
		fg.registry[srcMac] = entry
	} else {
		if (now - entry.lastSeen) > int64(time.Second) {
			entry.lastSeen = now
			fg.registry[srcMac] = entry
		}
	}
	
	fg.mu.Unlock()
}

func (fg *FlapGuard) sendAlert(mac [6]byte, count uint16, vlanID uint16) {
	// Clasificación Forense (Cold Path)
	macSlice := mac[:]
	info := utils.ClassifyMAC(macSlice)
	
	macStr := net.HardwareAddr(macSlice).String()
	identity := "Host"
	if info.Name != "Unicast" {
		identity = fmt.Sprintf("%s (%s)", info.Name, info.Description)
	}

	severity := "⚠️ WARNING"
	if info.IsCritical {
		severity = "🔥 CRITICAL"
	}

	msg := fmt.Sprintf("[FlapGuard] %s: TOPOLOGY CHANGE DETECTED!\n"+
		"    IDENTITY: %s\n"+
		"    MAC:      %s\n"+
		"    MOVES:    %d times/sec (Current VLAN: %d)\n"+
		"    ANALYSIS: Device is jumping between VLANs. Possible cabling loop or leaking configuration.",
		severity, identity, macStr, count, vlanID)
	
	fg.notify.Alert(msg)
}
