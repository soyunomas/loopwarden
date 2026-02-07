package detector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestNeighborDiscovery_LLDP_Parsing(t *testing.T) {
	// 1. Setup
	store := NewTopologyStore()
	nd := NewNeighborDiscovery(store, "eth0")

	// 2. Construcción manual de un paquete LLDP (TLV)
	// Chassis ID (Type 1)
	chassisVal := []byte{4} // Subtype MAC Address
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	chassisVal = append(chassisVal, mac...)
	
	// Port ID (Type 2)
	portVal := []byte{5} // Subtype Interface Name
	portVal = append(portVal, []byte("Gi1/0/1")...)

	// TTL (Type 3) - 120 seconds
	ttlVal := make([]byte, 2)
	binary.BigEndian.PutUint16(ttlVal, 120)

	// System Name (Type 5)
	sysNameVal := []byte("Switch-Core-01")

	// Management Address (Type 8) - EL FIX DE TU AMIGO
	// Len(1) + Subtype(1) + IP(4) = 6 bytes minimum validation
	// Subtype 1 = IANA IPv4
	mgmtVal := []byte{5, 1, 192, 168, 1, 10} 

	// Helper para construir TLV header (Type 7 bits + Len 9 bits)
	makeTLV := func(typ int, val []byte) []byte {
		length := len(val)
		header := uint16((typ << 9) | length)
		buf := make([]byte, 2+length)
		binary.BigEndian.PutUint16(buf[0:2], header)
		copy(buf[2:], val)
		return buf
	}

	payload := []byte{}
	payload = append(payload, makeTLV(1, chassisVal)...)
	payload = append(payload, makeTLV(2, portVal)...)
	payload = append(payload, makeTLV(3, ttlVal)...)
	payload = append(payload, makeTLV(5, sysNameVal)...)
	payload = append(payload, makeTLV(8, mgmtVal)...)
	payload = append(payload, makeTLV(0, []byte{})...) // End of LLDPDU

	// 3. Ejecutar Parser (Simulamos etherType 0x88CC y offset de VLAN 0)
	// Header falso para engañar al offset check (14 bytes ethernet header)
	fullFrame := make([]byte, 14) 
	binary.BigEndian.PutUint16(fullFrame[12:14], EtherTypeLLDP)
	fullFrame = append(fullFrame, payload...)

	nd.OnPacket(fullFrame, len(fullFrame), 0)

	// 4. Aserciones
	info, found := store.Get("eth0")
	if !found {
		t.Fatal("No se guardó la info del vecino en el Store")
	}

	if info.SystemName != "Switch-Core-01" {
		t.Errorf("SystemName incorrecto: %s", info.SystemName)
	}
	if info.ManagementIP != "192.168.1.10" {
		t.Errorf("ManagementIP incorrecto (Falló el fix?): %s", info.ManagementIP)
	}
	if info.AdvertisedTTL != 120 * time.Second {
		t.Errorf("TTL incorrecto: %v", info.AdvertisedTTL)
	}
}

func TestNeighborDiscovery_Malformed_Safety(t *testing.T) {
	// Este test asegura que no hay Panic con basura
	store := NewTopologyStore()
	nd := NewNeighborDiscovery(store, "eth0")

	// Paquete truncado a mitad de un TLV
	garbage := []byte{0x02, 0x0A, 0xFF, 0xFF} // Type 1, Len 10... pero solo hay 2 bytes más
	
	fullFrame := make([]byte, 14)
	binary.BigEndian.PutUint16(fullFrame[12:14], EtherTypeLLDP)
	fullFrame = append(fullFrame, garbage...)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("El código entró en Pánico con paquete malformado: %v", r)
		}
	}()

	nd.OnPacket(fullFrame, len(fullFrame), 0)
}
