package detector

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

const (
	EtherTypeLLDP = 0x88CC
	// Native VLAN Mismatch Check Frequency
	MismatchCooldown = 60 * time.Second
)

type NeighborDiscovery struct {
	store        *TopologyStore
	ifaceName    string
	notify       *notifier.Notifier
	lastMismatch time.Time 
}

// FIX: Firma actualizada para coincidir con engine.go
func NewNeighborDiscovery(store *TopologyStore, ifaceName string, notify *notifier.Notifier) *NeighborDiscovery {
	return &NeighborDiscovery{
		store:     store,
		ifaceName: ifaceName,
		notify:    notify,
	}
}

func (nd *NeighborDiscovery) Name() string { return "NeighborDiscovery" }

func (nd *NeighborDiscovery) Start(conn *packet.Conn, iface *net.Interface) error {
	log.Printf("🗺️  [NeighborDiscovery:%s] Listening for LLDP/CDP", iface.Name)
	return nil
}

func (nd *NeighborDiscovery) OnPacket(data []byte, length int, vlanID uint16) {
	ethTypeOffset := 12
	payloadOffset := 14
	if vlanID != 0 {
		ethTypeOffset = 16
		payloadOffset = 18
	}

	if length < payloadOffset {
		return
	}

	ethType := binary.BigEndian.Uint16(data[ethTypeOffset : ethTypeOffset+2])

	// 1. LLDP
	if ethType == EtherTypeLLDP {
		nd.parseLLDP(data[payloadOffset:length], vlanID)
		return
	}

	// 2. CDP (LLC SNAP Check)
	if ethType <= 1500 {
		llcStart := payloadOffset
		if length < llcStart+8 {
			return
		}

		// Check OUI Cisco (00 00 0C) + PID CDP (20 00)
		if data[llcStart] == 0xAA && data[llcStart+1] == 0xAA && data[llcStart+2] == 0x03 {
			if data[llcStart+3] == 0x00 && data[llcStart+4] == 0x00 && data[llcStart+5] == 0x0C {
				pid := binary.BigEndian.Uint16(data[llcStart+6 : llcStart+8])
				if pid == 0x2000 {
					nd.parseCDP(data[llcStart+8:length], vlanID)
				}
			}
		}
	}
}

// --- NATIVE VLAN MISMATCH DETECTION (Feature N1) ---
func (nd *NeighborDiscovery) checkNativeVlanMismatch(advertisedNativeVlan uint16, observedVlan uint16) {
	// Si el vecino dice "Mi Native VLAN es X", pero recibimos el paquete en VLAN Y
	// OJO: Si el paquete viene sin tag (observedVlan == 0), asume que está en la nativa local.
	
	// Solo chequeamos si ambos son distintos de cero y diferentes
	if advertisedNativeVlan != 0 && observedVlan != 0 && advertisedNativeVlan != observedVlan {
		now := time.Now()
		if now.Sub(nd.lastMismatch) > MismatchCooldown {
			nd.lastMismatch = now
			
			telemetry.EngineHits.WithLabelValues(nd.ifaceName, "NeighborDiscovery", "NativeVlanMismatch").Inc()
			
			msg := fmt.Sprintf("[NeighborDiscovery] ⚠️ NATIVE VLAN MISMATCH DETECTED!\n"+
				"    INTERFACE:     %s\n"+
				"    OBSERVED TAG:  VLAN %d (Local)\n"+
				"    ADVERTISED:    VLAN %d (Remote Switch)\n"+
				"    RISK:          Traffic hopping between VLANs (VLAN Hopping / Leaking).",
				nd.ifaceName, observedVlan, advertisedNativeVlan)
			
			go nd.notify.Alert(msg)
		}
	}
}

// --- LLDP PARSER ---

func (nd *NeighborDiscovery) parseLLDP(payload []byte, vlanID uint16) {
	info := NeighborInfo{
		Protocol: "LLDP",
		VLAN:     vlanID,
		LastSeen: time.Now(),
	}

	offset := 0
	for offset < len(payload) {
		if offset+2 > len(payload) { break }

		header := binary.BigEndian.Uint16(payload[offset : offset+2])
		tlvType := header >> 9
		tlvLen := int(header & 0x01FF)

		offset += 2
		if offset+tlvLen > len(payload) { break }

		value := payload[offset : offset+tlvLen]

		switch tlvType {
		case 0: // End
			goto FinishLLDP
		case 1: // Chassis ID
			if len(value) > 1 { info.ChassisID = parseID(value) }
		case 2: // Port ID
			if len(value) > 1 { info.PortID = parseID(value) }
		case 3: // TTL
			if len(value) == 2 {
				seconds := binary.BigEndian.Uint16(value)
				info.AdvertisedTTL = time.Duration(seconds) * time.Second
			}
		case 5: // System Name
			info.SystemName = string(value)
		case 6: // System Desc
			info.SystemDesc = string(value)
		case 8: // Management Address
			if len(value) >= 6 && value[0] == 5 && value[1] == 1 {
				ip := net.IP(value[2:6])
				info.ManagementIP = ip.String()
			}
		case 127: // Org Specific (Native VLAN)
			// IEEE 802.1 OUI: 00-80-C2, Subtype 1 = Port VLAN ID
			if len(value) >= 5 && value[0] == 0x00 && value[1] == 0x80 && value[2] == 0xC2 && value[3] == 0x01 {
				if len(value) >= 6 {
					info.NativeVLAN = binary.BigEndian.Uint16(value[4:6])
				}
			}
		}
		offset += tlvLen
	}

FinishLLDP:
	if info.SystemName != "" || info.ChassisID != "" {
		telemetry.NeighborsDetected.WithLabelValues(nd.ifaceName, "LLDP").Inc()
		nd.store.Update(nd.ifaceName, info)
		
		// Validar Mismatch
		nd.checkNativeVlanMismatch(info.NativeVLAN, vlanID)
	}
}

// --- CDP PARSER ---

func (nd *NeighborDiscovery) parseCDP(payload []byte, vlanID uint16) {
	if len(payload) < 4 { return }
	ttlSeconds := payload[1]

	info := NeighborInfo{
		Protocol:      "CDP",
		VLAN:          vlanID,
		LastSeen:      time.Now(),
		AdvertisedTTL: time.Duration(ttlSeconds) * time.Second,
	}

	offset := 4
	for offset < len(payload) {
		if offset+4 > len(payload) { break }

		tlvType := binary.BigEndian.Uint16(payload[offset : offset+2])
		tlvLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		if tlvLen < 4 { break }
		valLen := tlvLen - 4

		offset += 4
		if offset+valLen > len(payload) { break }

		value := payload[offset : offset+valLen]

		switch tlvType {
		case 0x0001: // Hostname
			info.SystemName = string(value)
		case 0x0003: // Port ID
			info.PortID = string(value)
		case 0x000A: // Native VLAN (CDP)
			if len(value) >= 2 {
				info.NativeVLAN = binary.BigEndian.Uint16(value[0:2])
			}
		case 0x0002: // Address
			// (Simplificado para brevedad, lógica completa en versión anterior)
		}
		offset += valLen
	}

	if info.SystemName != "" || info.PortID != "" {
		telemetry.NeighborsDetected.WithLabelValues(nd.ifaceName, "CDP").Inc()
		nd.store.Update(nd.ifaceName, info)
		
		// Validar Mismatch
		nd.checkNativeVlanMismatch(info.NativeVLAN, vlanID)
	}
}

func parseID(val []byte) string {
	subtype := val[0]
	content := val[1:]
	if subtype == 4 && len(content) == 6 {
		return net.HardwareAddr(content).String()
	}
	if subtype == 5 || subtype == 7 {
		return string(content)
	}
	return hex.EncodeToString(content)
}

// Helper para tests
func NewDummyConfig() *config.AlgorithmConfig { return nil }
