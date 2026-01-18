package detector

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

const (
	// EtherTypeIPv6 ya está definido en algo_arpwatch.go (package level shared constant)
	ProtoICMPv6      = 58
	ICMPv6TypeRA     = 134 // Router Advertisement
	RaAlertCooldown  = 30 * time.Second
)

type RaGuard struct {
	cfg         *config.RaGuardConfig
	notify      *notifier.Notifier
	trustedMacs map[string]bool
	mu          sync.Mutex
	lastAlert   time.Time
}

func NewRaGuard(cfg *config.RaGuardConfig, n *notifier.Notifier) *RaGuard {
	return &RaGuard{
		cfg:         cfg,
		notify:      n,
		trustedMacs: make(map[string]bool),
	}
}

func (r *RaGuard) Name() string { return "RaGuard" }

func (r *RaGuard) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Recopilación de MACs (Global + Override)
	var rawMacs []string
	
	// A. Global
	rawMacs = append(rawMacs, r.cfg.TrustedMacs...)
	
	// B. Override
	if override, ok := r.cfg.Overrides[iface.Name]; ok {
		log.Printf("🔧 [RaGuard] Applying overrides for interface %s (Extra MACs: %d)", 
			iface.Name, len(override.TrustedMacs))
		rawMacs = append(rawMacs, override.TrustedMacs...)
	}

	// 2. Normalización y llenado del Map
	for _, m := range rawMacs {
		cleanM := strings.ToLower(strings.TrimSpace(m))
		mac, err := net.ParseMAC(cleanM)
		if err == nil {
			r.trustedMacs[mac.String()] = true
		} else {
			log.Printf("⚠️ [RaGuard] Invalid trusted MAC ignored: '%s'", m)
		}
	}
	
	log.Printf("✅ [RaGuard:%s] Active. Trusted Routers: %d", iface.Name, len(r.trustedMacs))
	return nil
}

func (r *RaGuard) OnPacket(data []byte, length int, vlanID uint16) {
	ethOffset := 14
	ethTypeOffset := 12
	if vlanID != 0 {
		ethOffset = 18
		ethTypeOffset = 16
	}

	if length < ethOffset { return }

	ethType := binary.BigEndian.Uint16(data[ethTypeOffset : ethTypeOffset+2])
	
	// Usamos la constante compartida del paquete detector
	if ethType != EtherTypeIPv6 { return }

	// IPv6 Header is fixed 40 bytes
	if length < ethOffset+40 { return }

	// Next Header field is at offset 6 in IPv6 header
	nextHeader := data[ethOffset+6]
	
	// Simplification: We check if NextHeader is ICMPv6 directly.
	// NOTE: In real world IPv6, there could be extension headers chain (Hop-by-Hop, etc).
	// But RA Guard usually assumes standard RAs for performance.
	if nextHeader == ProtoICMPv6 {
		icmpOffset := ethOffset + 40
		if length < icmpOffset+1 { return }

		icmpType := data[icmpOffset]
		
		if icmpType == ICMPv6TypeRA {
			srcMacSlice := data[6:12]
			srcMacStr := net.HardwareAddr(srcMacSlice).String() // Returns lower-case

			if !r.trustedMacs[srcMacStr] {
				r.mu.Lock()
				now := time.Now()
				if now.Sub(r.lastAlert) > RaAlertCooldown {
					
					// TELEMETRY HIT
					telemetry.EngineHits.WithLabelValues("RaGuard", "RogueRA").Inc()

					// Get Src IPv6 (Offset 8 in IPv6 header)
					srcIP := net.IP(data[ethOffset+8 : ethOffset+24])
					ipStr := srcIP.String()

					go func(mac, ip string, vlan uint16) {
						vlanStr := "Native"
						if vlan != 0 {
							vlanStr = fmt.Sprintf("%d", vlan)
						}
						msg := fmt.Sprintf("[RaGuard] 📡 ROGUE IPv6 ROUTER ADVERTISEMENT!\n"+
							"    VLAN:      %s\n"+
							"    ROGUE MAC: %s\n"+
							"    ROGUE IP:  %s\n"+
							"    IMPACT:    Clients will lose connectivity (Man-in-the-Middle).",
							vlanStr, mac, ip)
						r.notify.Alert(msg)
					}(srcMacStr, ipStr, vlanID)

					r.lastAlert = now
				}
				r.mu.Unlock()
			}
		}
	}
}
