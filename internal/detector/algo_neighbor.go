package detector

import (
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

const (
	EtherTypeLLDP = 0x88CC
)

type NeighborDiscovery struct {
	store     *TopologyStore
	ifaceName string
}

func NewNeighborDiscovery(store *TopologyStore, ifaceName string) *NeighborDiscovery {
	return &NeighborDiscovery{
		store:     store,
		ifaceName: ifaceName,
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

// --- LLDP PARSER ---

func (nd *NeighborDiscovery) parseLLDP(payload []byte, vlanID uint16) {
	info := NeighborInfo{
		Protocol: "LLDP",
		VLAN:     vlanID,
		LastSeen: time.Now(),
	}

	offset := 0
	for offset < len(payload) {
		if offset+2 > len(payload) {
			break
		}

		header := binary.BigEndian.Uint16(payload[offset : offset+2])
		tlvType := header >> 9
		tlvLen := int(header & 0x01FF)

		offset += 2
		if offset+tlvLen > len(payload) {
			break
		}

		value := payload[offset : offset+tlvLen]

		switch tlvType {
		case 0: // End
			goto FinishLLDP
		case 1: // Chassis ID
			if len(value) > 1 {
				info.ChassisID = parseID(value)
			}
		case 2: // Port ID
			if len(value) > 1 {
				info.PortID = parseID(value)
			}
		case 3: // TTL (Time To Live)
			if len(value) == 2 {
				seconds := binary.BigEndian.Uint16(value)
				info.AdvertisedTTL = time.Duration(seconds) * time.Second
			}
		case 5: // System Name
			info.SystemName = string(value)
		case 6: // System Desc
			info.SystemDesc = string(value)
		case 8: // Management Address
			// Estructura: [Len(1) | Subtype(1) | Address(N) | ... ]
			// IPv4: Len=5 (1 subtype + 4 addr), Subtype=1 (IANA IP)
			if len(value) >= 6 && value[0] == 5 && value[1] == 1 {
				ip := net.IP(value[2:6])
				info.ManagementIP = ip.String()
			}
		}

		offset += tlvLen
	}

FinishLLDP:
	if info.SystemName != "" || info.ChassisID != "" {
		// --- TELEMETRÍA ---
		telemetry.NeighborsDetected.WithLabelValues(nd.ifaceName, "LLDP").Inc()
		// ------------------
		nd.store.Update(nd.ifaceName, info)
	}
}

// --- CDP PARSER ---

func (nd *NeighborDiscovery) parseCDP(payload []byte, vlanID uint16) {
	// Header: Version(1), TTL(1), Checksum(2)
	if len(payload) < 4 {
		return
	}

	ttlSeconds := payload[1]

	info := NeighborInfo{
		Protocol:      "CDP",
		VLAN:          vlanID,
		LastSeen:      time.Now(),
		AdvertisedTTL: time.Duration(ttlSeconds) * time.Second,
	}

	offset := 4

	for offset < len(payload) {
		if offset+4 > len(payload) {
			break
		}

		tlvType := binary.BigEndian.Uint16(payload[offset : offset+2])
		tlvLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		if tlvLen < 4 {
			break
		}
		valLen := tlvLen - 4

		offset += 4
		if offset+valLen > len(payload) {
			break
		}

		value := payload[offset : offset+valLen]

		switch tlvType {
		case 0x0001: // Hostname
			info.SystemName = string(value)
		case 0x0003: // Port ID
			info.PortID = string(value)
		case 0x0002: // Address TLV (Cisco Addresses)
			// Estructura CDP Address:
			// [4 bytes: Count]
			// Loop Count:
			//    [1 byte: ProtoType (1=NLPID)]
			//    [1 byte: ProtoLen (1)]
			//    [1 byte: Proto (0xCC = IP, 0x81 = ISO)]
			//    [2 bytes: AddressLen]
			//    [N bytes: Address]

			if len(value) < 4 {
				break
			}
			// Saltamos count (4 bytes)
			cursor := 4
			if cursor+5 > len(value) {
				break
			}

			// protoType := value[cursor]
			protoLen := int(value[cursor+1])
			cursor += 2

			// Verificar límites antes de leer protocolo
			if cursor+protoLen > len(value) {
				break
			}
			protocol := value[cursor : cursor+protoLen]
			cursor += protoLen

			// Check si es IP (NLPID 0xCC es común para IPv4 en CDP)
			isIP := false
			if len(protocol) == 1 && protocol[0] == 0xCC {
				isIP = true
			}

			if cursor+2 > len(value) {
				break
			}
			addrLen := int(binary.BigEndian.Uint16(value[cursor : cursor+2]))
			cursor += 2

			if cursor+addrLen > len(value) {
				break
			}

			if isIP && addrLen == 4 {
				// Hemos encontrado la IPv4
				ip := net.IP(value[cursor : cursor+4])
				info.ManagementIP = ip.String()
			}

		}

		offset += valLen
	}

	if info.SystemName != "" || info.PortID != "" {
		// --- TELEMETRÍA ---
		telemetry.NeighborsDetected.WithLabelValues(nd.ifaceName, "CDP").Inc()
		// ------------------
		nd.store.Update(nd.ifaceName, info)
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

func NewDummyConfig() *config.AlgorithmConfig { return nil }
