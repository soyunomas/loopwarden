package utils

import (
	"fmt"
	"net"
	"strings"
)

// ProtocolInfo define la metadata de un protocolo L2/L3 conocido.
type ProtocolInfo struct {
	Name        string
	Description string
	IsCritical  bool // Si es true, afecta infraestructura (STP, LACP, Gateways)
}

// Mapas de búsqueda rápida (O(1)) para direcciones exactas.
// Usamos string como key porque net.HardwareAddr no es comparable directamente como map key.
var exactMatches = map[string]ProtocolInfo{
	// --- BROADCAST ---
	"ff:ff:ff:ff:ff:ff": {"Broadcast", "General Broadcast (ARP, DHCP, flooding)", false},

	// --- IEEE 802.1 Control ---
	"01:80:c2:00:00:00": {"STP", "Spanning Tree Protocol (BPDU)", true},
	"01:80:c2:00:00:01": {"Pause", "Ethernet Flow Control (Pause Frames)", true},
	"01:80:c2:00:00:02": {"LACP/OAM", "Link Aggregation / Slow Protocols", true},
	"01:80:c2:00:00:03": {"LACP/802.1x", "Port Authentication / LACP", true},
	"01:80:c2:00:00:0e": {"LLDP", "Link Layer Discovery Protocol", true},
	"01:80:c2:00:00:20": {"GMRP", "GARP Multicast Registration Protocol", true},
	"01:80:c2:00:00:21": {"GVRP", "GARP VLAN Registration Protocol", true},

	// --- CISCO Proprietary ---
	"01:00:0c:cc:cc:cc": {"Cisco Discovery", "CDP / VTP / DTP / PAgP / UDLD", true},
	"01:00:0c:cc:cc:cd": {"Cisco SSTP", "Shared Spanning Tree Protocol", true},
	"01:00:0c:dd:dd:dd": {"Cisco CGMP", "Cisco Group Management Protocol", false},

	// --- MULTICAST IP SPECIFIC ---
	"01:00:5e:00:00:01": {"IPv4 All-Hosts", "All Systems on this Subnet", false},
	"01:00:5e:00:00:02": {"IPv4 All-Routers", "All Routers on this Subnet", true},
	"01:00:5e:00:00:05": {"OSPF", "Open Shortest Path First (All OSPF Routers)", true},
	"01:00:5e:00:00:06": {"OSPF DR", "OSPF Designated Routers", true},
	"01:00:5e:00:00:12": {"VRRP", "Virtual Router Redundancy Protocol (IPv4)", true},
	"01:00:5e:00:00:fb": {"mDNS", "Multicast DNS (Bonjour/Apple)", false},
	"01:00:5e:00:00:fc": {"LLMNR", "Link-Local Multicast Name Resolution", false},
	"01:00:5e:7f:ff:fa": {"SSDP", "UPnP / Simple Service Discovery", false},
}

// Prefijos OUI o rangos multicast (Optimización: chequeo manual).
func checkPrefixes(mac net.HardwareAddr) (ProtocolInfo, bool) {
	// IPv4 Multicast Range: 01:00:5e:xx:xx:xx
	if mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e {
		// Detección específica de VRRP IPv4 (00:00:5e:00:01:XX)
		if mac[0] == 0x00 && mac[1] == 0x00 && mac[2] == 0x5e && mac[3] == 0x00 && mac[4] == 0x01 {
			return ProtocolInfo{"VRRP-IPv4", fmt.Sprintf("Virtual Gateway (VRID %d)", mac[5]), true}, true
		}
		return ProtocolInfo{"IPv4 Multicast", "IP Multicast Group Traffic", false}, true
	}

	// IPv6 Multicast Range: 33:33:xx:xx:xx:xx
	if mac[0] == 0x33 && mac[1] == 0x33 {
		// IPv6 VRRP (00:00:5E:00:02:XX) - mapping standard, but usually handled by mcast range
		if mac[2] == 0x00 && mac[3] == 0x00 && mac[4] == 0x00 { // Common simplistic check
			// Detailed checks for All-Nodes / All-Routers
			if mac[5] == 0x01 {
				return ProtocolInfo{"IPv6 All-Nodes", "Neighbor Discovery / All Nodes", false}, true
			}
			if mac[5] == 0x02 {
				return ProtocolInfo{"IPv6 All-Routers", "IPv6 Router Advertisement", true}, true
			}
		}
		// VRRP IPv6 range usually uses 00:00:5e:00:02:xx mapped to 33:33...
		return ProtocolInfo{"IPv6 Multicast", "IPv6 Neighbor Discovery / Services", false}, true
	}

	// HSRP (Cisco) v1: 00:00:0c:07:ac:xx
	if mac[0] == 0x00 && mac[1] == 0x00 && mac[2] == 0x0c && mac[3] == 0x07 && mac[4] == 0xac {
		return ProtocolInfo{"HSRP-v1", fmt.Sprintf("Cisco Standby Router (Group %d)", mac[5]), true}, true
	}

	// HSRP (Cisco) v2: 00:00:0c:9f:f0:xx ... (simplificado a OUI range)
	if mac[0] == 0x00 && mac[1] == 0x00 && mac[2] == 0x0c && mac[3] == 0x9f && mac[4] == 0xf0 {
		return ProtocolInfo{"HSRP-v2", fmt.Sprintf("Cisco Standby Router v2 (Group %d)", mac[5]), true}, true
	}

	// VRRP Generic (Direct MAC check incase not mapped to multicast)
	if mac[0] == 0x00 && mac[1] == 0x00 && mac[2] == 0x5e && mac[3] == 0x00 && (mac[4] == 0x01 || mac[4] == 0x02) {
		return ProtocolInfo{"VRRP", "Virtual Router Redundancy Protocol", true}, true
	}

	return ProtocolInfo{}, false
}

// GetProtocolByMAC identifica el propósito de una dirección MAC.
// Esta función debe llamarse en el Cold Path (Alertas), NO en el Hot Path.
func ClassifyMAC(mac net.HardwareAddr) ProtocolInfo {
	macStr := strings.ToLower(mac.String())

	// 1. Exact Match (O(1))
	if info, ok := exactMatches[macStr]; ok {
		return info
	}

	// 2. Prefix / Logic Checks
	if info, found := checkPrefixes(mac); found {
		return info
	}

	// 3. Fallback
	if isUnicast(mac) {
		return ProtocolInfo{"Unicast", "Standard Station Traffic", false}
	}

	return ProtocolInfo{"Unknown Multicast", "Proprietary or unregistered multicast", false}
}

func isUnicast(mac net.HardwareAddr) bool {
	// Bit 0 del primer byte indica Multicast (1) o Unicast (0)
	return (mac[0] & 0x01) == 0
}

// IsIPv6NeighborDiscovery detecta si es un paquete de descubrimiento de vecinos (NDP/Solicitation)
// Basado en el prefijo MAC 33:33:ff
func IsIPv6NeighborDiscovery(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0] == 0x33 && mac[1] == 0x33 && mac[2] == 0xff
}
