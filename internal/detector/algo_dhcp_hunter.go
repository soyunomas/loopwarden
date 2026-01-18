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
	EtherTypeIPv4  = 0x0800
	IPProtoUDP     = 17
	DhcpServerPort = 67
	DhcpClientPort = 68
	DhcpCooldown   = 10 * time.Second
)

type DhcpHunter struct {
	cfg         *config.DhcpHunterConfig
	notify      *notifier.Notifier
	
	trustedMacs map[string]bool
	trustedNets []*net.IPNet
	
	mu        sync.Mutex
	lastAlert time.Time
}

func NewDhcpHunter(cfg *config.DhcpHunterConfig, n *notifier.Notifier) *DhcpHunter {
	return &DhcpHunter{
		cfg:         cfg,
		notify:      n,
		trustedMacs: make(map[string]bool),
		trustedNets: make([]*net.IPNet, 0),
	}
}

func (d *DhcpHunter) Name() string { return "DhcpHunter" }

func (d *DhcpHunter) Start(conn *packet.Conn, iface *net.Interface) error {
	// 1. Construir lista maestra de MACs (Global + Override)
	// Usamos slice intermedio para mantener el orden y claridad
	var rawMacs []string
	
	// A. Añadir Globales
	rawMacs = append(rawMacs, d.cfg.TrustedMacs...)
	
	// B. Añadir Overrides (Si existen para esta interfaz)
	if override, ok := d.cfg.Overrides[iface.Name]; ok {
		log.Printf("🔧 [DhcpHunter] Applying overrides for interface %s (Extra MACs: %d, Extra CIDRs: %d)", 
			iface.Name, len(override.TrustedMacs), len(override.TrustedCidrs))
		rawMacs = append(rawMacs, override.TrustedMacs...)
	}

	// 2. Procesar y Normalizar MACs
	for _, m := range rawMacs {
		// Limpieza de inputs: Trim espacios y LowerCase
		cleanM := strings.ToLower(strings.TrimSpace(m))
		
		mac, err := net.ParseMAC(cleanM)
		if err == nil {
			d.trustedMacs[mac.String()] = true
		} else {
			log.Printf("⚠️ [DhcpHunter] Invalid trusted MAC ignored: '%s'", m)
		}
	}

	// 3. Construir lista maestra de CIDRs (Global + Override)
	var rawCidrs []string
	rawCidrs = append(rawCidrs, d.cfg.TrustedCidrs...)
	
	if override, ok := d.cfg.Overrides[iface.Name]; ok {
		rawCidrs = append(rawCidrs, override.TrustedCidrs...)
	}

	// 4. Procesar CIDRs
	for _, cidr := range rawCidrs {
		cleanCidr := strings.TrimSpace(cidr)
		_, network, err := net.ParseCIDR(cleanCidr)
		if err == nil {
			d.trustedNets = append(d.trustedNets, network)
		} else {
			log.Printf("⚠️ [DhcpHunter] Invalid trusted CIDR ignored: '%s'", cidr)
		}
	}
	
	log.Printf("✅ [DhcpHunter:%s] Active. AllowList: %d MACs, %d Subnets", 
		iface.Name, len(d.trustedMacs), len(d.trustedNets))
	
	return nil
}

func (d *DhcpHunter) OnPacket(data []byte, length int, vlanID uint16) {
	// Offset calculation based on VLAN tag presence
	ethOffset := 14
	ethTypeOffset := 12
	if vlanID != 0 {
		ethOffset = 18
		ethTypeOffset = 16
	}

	// Bounds Check #1: Ethernet Header
	if length < ethOffset {
		return
	}

	// 1. Check EtherType (Must be IPv4)
	ethType := binary.BigEndian.Uint16(data[ethTypeOffset : ethTypeOffset+2])
	if ethType != EtherTypeIPv4 {
		return
	}

	// Bounds Check #2: IPv4 Min Header (20 bytes)
	if length < ethOffset+20 {
		return
	}

	// 2. Parse IPv4 Header
	// IHL is lower 4 bits of first byte. Unit is 32-bit words (4 bytes).
	ihl := int(data[ethOffset]&0x0F) * 4
	if ihl < 20 {
		return // Invalid IP header
	}

	// Protocol is at offset 9 in IPv4 header
	protocol := data[ethOffset+9]
	if protocol != IPProtoUDP {
		return
	}

	// Extract Src IP (Offset 12 in IPv4)
	srcIP := net.IP(data[ethOffset+12 : ethOffset+16])

	// 3. Parse UDP Header
	udpStart := ethOffset + ihl
	if length < udpStart+8 {
		return
	}

	// Ports
	srcPort := binary.BigEndian.Uint16(data[udpStart : udpStart+2])
	dstPort := binary.BigEndian.Uint16(data[udpStart+2 : udpStart+4])

	// DHCP Server (67) sending to Client (68)
	if srcPort == DhcpServerPort && dstPort == DhcpClientPort {
		
		// 4. Security Check
		srcMacSlice := data[6:12]
		// Normalización en Hot Path: net.HardwareAddr.String() devuelve lower-case por defecto.
		srcMacStr := net.HardwareAddr(srcMacSlice).String()
		
		isTrusted := false

		// Check 1: Trusted MAC (Map Lookup O(1))
		if d.trustedMacs[srcMacStr] {
			isTrusted = true
		}

		// Check 2: Trusted CIDR (Linear Scan)
		// Solo si no pasó por MAC, para ahorrar CPU.
		if !isTrusted {
			for _, net := range d.trustedNets {
				if net.Contains(srcIP) {
					isTrusted = true
					break
				}
			}
		}

		if !isTrusted {
			d.mu.Lock()
			now := time.Now()
			if now.Sub(d.lastAlert) > DhcpCooldown {
				
				// TELEMETRY HIT
				telemetry.EngineHits.WithLabelValues("DhcpHunter", "RogueServer").Inc()
				
				// Copy data for goroutine
				capturedSrcIP := srcIP.String()
				capturedSrcMAC := srcMacStr
				
				go func(ip, mac string, vlan uint16) {
					vlanStr := "Native"
					if vlan != 0 {
						vlanStr = fmt.Sprintf("%d", vlan)
					}
					
					msg := fmt.Sprintf("[DhcpHunter] 🚨 ROGUE DHCP SERVER DETECTED!\n"+
						"    VLAN:      %s\n"+
						"    ROGUE MAC: %s\n"+
						"    ROGUE IP:  %s\n"+
						"    ACTION:    Investigate immediately. Possible Man-in-the-Middle.",
						vlanStr, mac, ip)
					d.notify.Alert(msg)
				}(capturedSrcIP, capturedSrcMAC, vlanID)
				
				d.lastAlert = now
			}
			d.mu.Unlock()
		}
	}
}
