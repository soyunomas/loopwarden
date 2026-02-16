package detector

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
)

// Helper para crear un Dummy Notifier
// CORRECCIÓN: Se define MuteDuration explícitamente para evitar warnings en logs de test.
func mockNotifier() *notifier.Notifier {
	cfg := &config.AlertsConfig{
		Dampening: config.DampeningConfig{
			MaxAlertsPerMinute: 100,
			MuteDuration:       "1m", // Evita warning "Invalid MuteDuration"
		},
	}
	return notifier.NewNotifier(cfg, "TEST_SENSOR")
}

// =============================================================================
//  TEST 0: Neighbor Discovery (LLDP)
// =============================================================================

func TestNeighborDiscovery_LLDP_Parsing(t *testing.T) {
	store := NewTopologyStore()
	// FIX: Usar mockNotifier para evitar warnings de configuración vacía
	nd := NewNeighborDiscovery(store, "eth0", mockNotifier())

	// Construcción manual de un paquete LLDP (TLV)
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

	// Management Address (Type 8)
	mgmtVal := []byte{5, 1, 192, 168, 1, 10} 

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
	payload = append(payload, makeTLV(0, []byte{})...)

	fullFrame := make([]byte, 14) 
	binary.BigEndian.PutUint16(fullFrame[12:14], EtherTypeLLDP)
	fullFrame = append(fullFrame, payload...)

	nd.OnPacket(fullFrame, len(fullFrame), 0)

	info, found := store.Get("eth0")
	if !found {
		t.Fatal("No se guardó la info del vecino en el Store")
	}
	if info.SystemName != "Switch-Core-01" {
		t.Errorf("SystemName incorrecto: %s", info.SystemName)
	}
}

func TestNeighborDiscovery_Malformed_Safety(t *testing.T) {
	store := NewTopologyStore()
	// FIX: Usar mockNotifier
	nd := NewNeighborDiscovery(store, "eth0", mockNotifier())

	garbage := []byte{0x02, 0x0A, 0xFF, 0xFF} 
	
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

// =============================================================================
//  TEST 1: EtherFuse (Detección de Duplicados - O(1) Check)
// =============================================================================

func TestEtherFuse_Detection(t *testing.T) {
	threshold := 5
	cfg := &config.EtherFuseConfig{
		Enabled:        true,
		HistorySize:    10,
		AlertThreshold: threshold,
		StormPPSLimit:  1000,
		AlertCooldown:  "5s",
		Overrides:      make(map[string]config.EtherFuseOverride),
	}

	store := NewTopologyStore()
	ef := NewEtherFuse(cfg, mockNotifier(), "test0", store)
	
	dummyIface := &net.Interface{Name: "eth0"}
	ef.Start(nil, dummyIface)

	packet := []byte("PAYLOAD_TEST")
	expectedHash := hashBody(packet)

	ef.OnPacket(packet, len(packet), 0)
	
	ef.mu.Lock()
	count := ef.lookupTable[expectedHash]
	ef.mu.Unlock()

	if count != 1 {
		t.Errorf("Esperaba count=1 para el primer paquete, obtuve %d", count)
	}

	for i := 0; i < 4; i++ {
		ef.OnPacket(packet, len(packet), 0)
	}
	
	ef.mu.Lock()
	count = ef.lookupTable[expectedHash]
	ef.mu.Unlock()
	
	if int(count) != threshold {
		t.Errorf("Esperaba count=%d tras 5 inyecciones, obtuve %d", threshold, count)
	}

	ef.OnPacket(packet, len(packet), 0)

	ef.mu.Lock()
	count = ef.lookupTable[expectedHash]
	ef.mu.Unlock()

	if count != 0 {
		t.Errorf("El contador debería haberse reseteado a 0 tras la alerta, pero es %d", count)
	}
}

// =============================================================================
//  TEST 2: MacStorm (Detección de Velocidad - Map Swap Check)
// =============================================================================

func TestMacStorm_Counter(t *testing.T) {
	cfg := &config.MacStormConfig{
		Enabled:       true,
		MaxPPSPerMac:  100,
		AlertCooldown: "30s",
		Overrides:     make(map[string]config.MacStormOverride),
	}

	ms := NewMacStorm(cfg, mockNotifier(), "test0")
	
	dummyIface := &net.Interface{Name: "eth0"}
	ms.Start(nil, dummyIface)

	srcMac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	packet := make([]byte, 14)
	copy(packet[6:12], srcMac)

	for i := 0; i < 150; i++ {
		ms.OnPacket(packet, 14, 0)
	}

	var key [6]byte
	copy(key[:], srcMac)

	ms.mu.Lock()
	count := ms.counters[key]
	_, alerted := ms.alertState[key]
	ms.mu.Unlock()

	if count != 150 {
		t.Errorf("Esperaba contar 150 paquetes, se contaron %d", count)
	}

	if !alerted {
		t.Error("MacStorm debería haber registrado una alerta en alertState")
	}
}

// =============================================================================
//  TEST 3: ActiveProbe (Inyección Activa)
// =============================================================================

func TestActiveProbe_VlanOffset(t *testing.T) {
	cfg := &config.ActiveProbeConfig{
		Enabled:      true,
		Ethertype:    0xFFFF,
		MagicPayload: "MAGIC",
		Overrides:    make(map[string]config.ActiveProbeOverride),
	}

	store := NewTopologyStore()
	ap := NewActiveProbe(cfg, mockNotifier(), "test_iface", store)
	
	myMac, _ := net.ParseMAC("00:11:22:33:44:55")
	ap.myMAC = myMac
	ap.ethertype = 0xFFFF 
	ap.intervalMs = 1000
	ap.domain = "default" 

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, 0xFFFF)

	packetNative := make([]byte, 0)
	packetNative = append(packetNative, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) 
	packetNative = append(packetNative, myMac...)                                       
	packetNative = append(packetNative, typeBytes...)                                   
	packetNative = append(packetNative, []byte("MAGIC|test_iface|default")...)                         

	ap.lastAlert = time.Time{}
	ap.OnPacket(packetNative, len(packetNative), 0)

	ap.mu.Lock()
	if ap.lastAlert.IsZero() {
		t.Error("Falló detección en Native VLAN (Self-Loop)")
	}
	ap.mu.Unlock()
}

// =============================================================================
//  TEST 4: FlapGuard (Topology Instability)
// =============================================================================

func TestFlapGuard_Flapping(t *testing.T) {
	threshold := 3
	cfg := &config.FlapGuardConfig{
		Enabled:       true,
		Threshold:     threshold,
		Window:        "1s",
		AlertCooldown: "30s",
		Overrides:     make(map[string]config.FlapGuardOverride),
	}

	fg := NewFlapGuard(cfg, mockNotifier(), "test0")
	
	dummyIface := &net.Interface{Name: "eth0"}
	fg.Start(nil, dummyIface)

	srcMac := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01}
	
	packet := make([]byte, 14)
	copy(packet[6:12], srcMac)

	fg.OnPacket(packet, 14, 10)
	fg.OnPacket(packet, 14, 20)
	fg.OnPacket(packet, 14, 10)
	fg.OnPacket(packet, 14, 20) // Trigger

	var key [6]byte
	copy(key[:], srcMac)

	fg.mu.Lock()
	entry := fg.registry[key]
	fg.mu.Unlock()

	if entry.flapCount < uint16(threshold) {
		t.Errorf("El contador de Flap debería ser al menos %d, es %d", threshold, entry.flapCount)
	}

	if entry.lastAlert == 0 {
		t.Error("FlapGuard debería haber marcado lastAlert (UnixNano > 0)")
	}
}

// =============================================================================
//  TEST 5: ArpWatchdog (Protocol Storm & Parser)
// =============================================================================

func TestArpWatchdog_ParserAndLimit(t *testing.T) {
	maxPPS := uint64(10)
	cfg := &config.ArpWatchConfig{
		Enabled:       true,
		MaxPPS:        maxPPS,
		AlertCooldown: "30s",
		Overrides:     make(map[string]config.ArpWatchOverride),
	}

	aw := NewArpWatchdog(cfg, mockNotifier(), "test0")
	
	dummyIface := &net.Interface{Name: "eth0"}
	aw.Start(nil, dummyIface)

	ethPacket := make([]byte, 14+28)
	binary.BigEndian.PutUint16(ethPacket[12:14], 0x0806) // EtherType ARP
	binary.BigEndian.PutUint16(ethPacket[20:22], 1) // OpCode Request

	// FIX: Establecer IPs distintas para evitar detección GARP (Sender==Target)
	ethPacket[28+3] = 1 // Sender IP: ...1
	ethPacket[38+3] = 2 // Target IP: ...2

	for i := 0; i < int(maxPPS)+5; i++ {
		aw.OnPacket(ethPacket, len(ethPacket), 0)
	}

	aw.mu.Lock()
	var count uint64
	for _, stats := range aw.sources {
		count += stats.pps
	}
	aw.mu.Unlock()

	if count != maxPPS+5 {
		t.Errorf("Esperaba contar %d paquetes ARP, conté %d. (Revisa si GARP detection se comió los paquetes)", maxPPS+5, count)
	}

	binary.BigEndian.PutUint16(ethPacket[20:22], 2) // Reply
	aw.OnPacket(ethPacket, len(ethPacket), 0)

	aw.mu.Lock()
	var countAfterReply uint64
	for _, stats := range aw.sources {
		countAfterReply += stats.pps
	}
	aw.mu.Unlock()

	if countAfterReply != count {
		t.Error("ArpWatchdog contó erróneamente un ARP Reply como Request")
	}
}

// =============================================================================
//  TEST 6: DhcpHunter (Rogue DHCP Server Detection)
// =============================================================================

func TestDhcpHunter_RogueDetection(t *testing.T) {
	cfg := &config.DhcpHunterConfig{
		Enabled:      true,
		TrustedMacs:  []string{"00:11:22:33:44:55"},
		TrustedCidrs: []string{"10.0.0.0/8"},
		Overrides:    make(map[string]config.DhcpHunterOverride),
	}

	dh := NewDhcpHunter(cfg, mockNotifier(), "test0")
	dh.Start(nil, &net.Interface{Name: "test0"})

	// Construir paquete DHCP Offer: Ethernet + IPv4 + UDP (67->68)
	// Rogue MAC (no está en whitelist)
	rogueMac := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	rogueIP := net.IP{192, 168, 1, 100} // No está en 10.0.0.0/8

	pkt := buildDHCPPacket(rogueMac, rogueIP, DhcpServerPort, DhcpClientPort, 0)
	dh.OnPacket(pkt, len(pkt), 0)

	// Debería haber disparado alerta (lastAlert no es zero)
	dh.mu.Lock()
	alerted := !dh.lastAlert.IsZero()
	dh.mu.Unlock()

	if !alerted {
		t.Error("DhcpHunter debería haber detectado el servidor DHCP rogue")
	}
}

func TestDhcpHunter_TrustedMacAllowed(t *testing.T) {
	trustedMAC := "aa:bb:cc:dd:ee:ff"
	cfg := &config.DhcpHunterConfig{
		Enabled:      true,
		TrustedMacs:  []string{trustedMAC},
		TrustedCidrs: []string{},
		Overrides:    make(map[string]config.DhcpHunterOverride),
	}

	dh := NewDhcpHunter(cfg, mockNotifier(), "test0")
	dh.Start(nil, &net.Interface{Name: "test0"})

	mac, _ := net.ParseMAC(trustedMAC)
	pkt := buildDHCPPacket(mac, net.IP{192, 168, 1, 1}, DhcpServerPort, DhcpClientPort, 0)
	dh.OnPacket(pkt, len(pkt), 0)

	dh.mu.Lock()
	alerted := !dh.lastAlert.IsZero()
	dh.mu.Unlock()

	if alerted {
		t.Error("DhcpHunter no debería alertar para una MAC en la whitelist")
	}
}

func TestDhcpHunter_TrustedCidrAllowed(t *testing.T) {
	cfg := &config.DhcpHunterConfig{
		Enabled:      true,
		TrustedMacs:  []string{},
		TrustedCidrs: []string{"10.0.0.0/8"},
		Overrides:    make(map[string]config.DhcpHunterOverride),
	}

	dh := NewDhcpHunter(cfg, mockNotifier(), "test0")
	dh.Start(nil, &net.Interface{Name: "test0"})

	unknownMac := []byte{0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01}
	trustedIP := net.IP{10, 20, 30, 40} // Dentro de 10.0.0.0/8
	pkt := buildDHCPPacket(unknownMac, trustedIP, DhcpServerPort, DhcpClientPort, 0)
	dh.OnPacket(pkt, len(pkt), 0)

	dh.mu.Lock()
	alerted := !dh.lastAlert.IsZero()
	dh.mu.Unlock()

	if alerted {
		t.Error("DhcpHunter no debería alertar para IP dentro de CIDR trusted")
	}
}

// Helper: construir paquete Ethernet+IPv4+UDP simulando DHCP
func buildDHCPPacket(srcMAC net.HardwareAddr, srcIP net.IP, srcPort, dstPort uint16, vlanID uint16) []byte {
	ethLen := 14
	if vlanID != 0 {
		ethLen = 18
	}
	ipLen := 20
	udpLen := 8

	pkt := make([]byte, ethLen+ipLen+udpLen)

	// Ethernet: Dst=broadcast, Src=srcMAC
	copy(pkt[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	copy(pkt[6:12], srcMAC)

	ethTypeOffset := 12
	ipStart := 14
	if vlanID != 0 {
		// 802.1Q tag
		binary.BigEndian.PutUint16(pkt[12:14], 0x8100)
		binary.BigEndian.PutUint16(pkt[14:16], vlanID)
		ethTypeOffset = 16
		ipStart = 18
	}
	binary.BigEndian.PutUint16(pkt[ethTypeOffset:ethTypeOffset+2], EtherTypeIPv4)

	// IPv4 header
	pkt[ipStart] = 0x45 // Version=4, IHL=5
	pkt[ipStart+9] = IPProtoUDP
	copy(pkt[ipStart+12:ipStart+16], srcIP.To4())

	// UDP header
	udpStart := ipStart + ipLen
	binary.BigEndian.PutUint16(pkt[udpStart:udpStart+2], srcPort)
	binary.BigEndian.PutUint16(pkt[udpStart+2:udpStart+4], dstPort)

	return pkt
}

// =============================================================================
//  TEST 7: FlowPanic (PAUSE Frame Flood)
// =============================================================================

func TestFlowPanic_Detection(t *testing.T) {
	cfg := &config.FlowPanicConfig{
		Enabled:     true,
		MaxPausePPS: 5,
		Overrides:   make(map[string]config.FlowPanicOverride),
	}

	fp := NewFlowPanic(cfg, mockNotifier(), "test0")
	fp.Start(nil, &net.Interface{Name: "test0"})

	pkt := buildPauseFrame()

	// Acumular paquetes (lastReset es reciente, no se evalúa aún)
	for i := 0; i < 10; i++ {
		fp.OnPacket(pkt, len(pkt), 0)
	}

	// Forzar que la próxima llamada dispare evaluación (ventana expirada)
	fp.mu.Lock()
	fp.lastReset = time.Now().Add(-2 * time.Second)
	fp.mu.Unlock()

	// Un paquete más para disparar la evaluación
	fp.OnPacket(pkt, len(pkt), 0)

	fp.mu.Lock()
	alerted := !fp.lastAlert.IsZero()
	fp.mu.Unlock()

	if !alerted {
		t.Error("FlowPanic debería haber detectado inundación de PAUSE frames")
	}
}

func TestFlowPanic_IgnoresNonPause(t *testing.T) {
	cfg := &config.FlowPanicConfig{
		Enabled:     true,
		MaxPausePPS: 5,
		Overrides:   make(map[string]config.FlowPanicOverride),
	}

	fp := NewFlowPanic(cfg, mockNotifier(), "test0")
	fp.Start(nil, &net.Interface{Name: "test0"})

	// Paquete con EtherType correcto pero OpCode != PAUSE
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[12:14], EtherTypeMacControl)
	binary.BigEndian.PutUint16(pkt[14:16], 0x0002) // OpCode != PAUSE

	for i := 0; i < 100; i++ {
		fp.OnPacket(pkt, len(pkt), 0)
	}

	fp.mu.Lock()
	count := fp.packetCount
	fp.mu.Unlock()

	if count != 0 {
		t.Errorf("FlowPanic no debería contar frames con OpCode != PAUSE, contó %d", count)
	}
}

// Helper: construir PAUSE frame (EtherType 0x8808, OpCode 0x0001)
func buildPauseFrame() []byte {
	pkt := make([]byte, 20)
	// Dst MAC: 01:80:C2:00:00:01 (reservada para PAUSE)
	copy(pkt[0:6], []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x01})
	copy(pkt[6:12], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	binary.BigEndian.PutUint16(pkt[12:14], EtherTypeMacControl)
	binary.BigEndian.PutUint16(pkt[14:16], OpCodePause)
	return pkt
}

// =============================================================================
//  TEST 8: RaGuard (Rogue IPv6 Router Advertisement)
// =============================================================================

func TestRaGuard_RogueDetection(t *testing.T) {
	cfg := &config.RaGuardConfig{
		Enabled:     true,
		TrustedMacs: []string{"00:11:22:33:44:55"},
		Overrides:   make(map[string]config.RaGuardOverride),
	}

	rg := NewRaGuard(cfg, mockNotifier(), "test0")
	rg.Start(nil, &net.Interface{Name: "test0"})

	pkt := buildRAPacket([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}, 0)
	rg.OnPacket(pkt, len(pkt), 0)

	rg.mu.Lock()
	alerted := !rg.lastAlert.IsZero()
	rg.mu.Unlock()

	if !alerted {
		t.Error("RaGuard debería haber detectado el RA rogue")
	}
}

func TestRaGuard_TrustedAllowed(t *testing.T) {
	trustedMAC := "aa:bb:cc:dd:ee:ff"
	cfg := &config.RaGuardConfig{
		Enabled:     true,
		TrustedMacs: []string{trustedMAC},
		Overrides:   make(map[string]config.RaGuardOverride),
	}

	rg := NewRaGuard(cfg, mockNotifier(), "test0")
	rg.Start(nil, &net.Interface{Name: "test0"})

	mac, _ := net.ParseMAC(trustedMAC)
	pkt := buildRAPacket(mac, 0)
	rg.OnPacket(pkt, len(pkt), 0)

	rg.mu.Lock()
	alerted := !rg.lastAlert.IsZero()
	rg.mu.Unlock()

	if alerted {
		t.Error("RaGuard no debería alertar para MAC trusted")
	}
}

// Helper: construir paquete IPv6 con ICMPv6 Router Advertisement
func buildRAPacket(srcMAC net.HardwareAddr, vlanID uint16) []byte {
	ethLen := 14
	if vlanID != 0 {
		ethLen = 18
	}
	ipv6Len := 40
	icmpLen := 4 // Mínimo para tipo+código+checksum

	pkt := make([]byte, ethLen+ipv6Len+icmpLen)

	// Ethernet
	copy(pkt[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}) // IPv6 All-Nodes
	copy(pkt[6:12], srcMAC)

	ethTypeOffset := 12
	ipStart := 14
	if vlanID != 0 {
		binary.BigEndian.PutUint16(pkt[12:14], 0x8100)
		binary.BigEndian.PutUint16(pkt[14:16], vlanID)
		ethTypeOffset = 16
		ipStart = 18
	}
	binary.BigEndian.PutUint16(pkt[ethTypeOffset:ethTypeOffset+2], EtherTypeIPv6)

	// IPv6 header
	pkt[ipStart] = 0x60                  // Version 6
	pkt[ipStart+6] = ProtoICMPv6         // Next Header = ICMPv6
	pkt[ipStart+7] = 255                 // Hop Limit
	// Src IPv6: fe80::1 (link-local)
	pkt[ipStart+8] = 0xFE
	pkt[ipStart+9] = 0x80
	pkt[ipStart+23] = 0x01

	// ICMPv6: Type = Router Advertisement (134)
	icmpStart := ipStart + ipv6Len
	pkt[icmpStart] = ICMPv6TypeRA

	return pkt
}

// =============================================================================
//  TEST 9: McastPolicer (Multicast Storm)
// =============================================================================

func TestMcastPolicer_IPv4MulticastDetection(t *testing.T) {
	cfg := &config.McastPolicerConfig{
		Enabled:   true,
		MaxPPS:    5,
		Overrides: make(map[string]config.McastPolicerOverride),
	}

	mp := NewMcastPolicer(cfg, mockNotifier(), "test0")
	mp.Start(nil, &net.Interface{Name: "test0"})

	// Paquete con MAC destino IPv4 Multicast: 01:00:5E:xx:xx:xx
	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x01, 0x00, 0x5E, 0x01, 0x01, 0x01})
	copy(pkt[6:12], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})

	// Acumular paquetes (lastReset es reciente, no se evalúa)
	for i := 0; i < 10; i++ {
		mp.OnPacket(pkt, len(pkt), 0)
	}

	// Forzar expiración de ventana y disparar evaluación
	mp.mu.Lock()
	mp.lastReset = time.Now().Add(-2 * time.Second)
	mp.mu.Unlock()

	mp.OnPacket(pkt, len(pkt), 0)

	mp.mu.Lock()
	alerted := !mp.lastAlert.IsZero()
	mp.mu.Unlock()

	if !alerted {
		t.Error("McastPolicer debería haber detectado tormenta multicast IPv4")
	}
}

func TestMcastPolicer_IPv6MulticastDetection(t *testing.T) {
	cfg := &config.McastPolicerConfig{
		Enabled:   true,
		MaxPPS:    5,
		Overrides: make(map[string]config.McastPolicerOverride),
	}

	mp := NewMcastPolicer(cfg, mockNotifier(), "test0")
	mp.Start(nil, &net.Interface{Name: "test0"})

	// Paquete con MAC destino IPv6 Multicast (no-NDP): 33:33:00:xx:xx:xx
	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[6:12], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})

	// Acumular paquetes
	for i := 0; i < 10; i++ {
		mp.OnPacket(pkt, len(pkt), 0)
	}

	// Forzar expiración y disparar evaluación
	mp.mu.Lock()
	mp.lastReset = time.Now().Add(-2 * time.Second)
	mp.mu.Unlock()

	mp.OnPacket(pkt, len(pkt), 0)

	mp.mu.Lock()
	alerted := !mp.lastAlert.IsZero()
	mp.mu.Unlock()

	if !alerted {
		t.Error("McastPolicer debería haber detectado tormenta multicast IPv6")
	}
}

func TestMcastPolicer_IgnoresNDP(t *testing.T) {
	cfg := &config.McastPolicerConfig{
		Enabled:   true,
		MaxPPS:    5,
		Overrides: make(map[string]config.McastPolicerOverride),
	}

	mp := NewMcastPolicer(cfg, mockNotifier(), "test0")
	mp.Start(nil, &net.Interface{Name: "test0"})

	// Solicited-Node Multicast (NDP): 33:33:ff:xx:xx:xx — debe ser ignorado
	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x33, 0x33, 0xFF, 0xDD, 0xEE, 0x01})
	copy(pkt[6:12], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})

	for i := 0; i < 100; i++ {
		mp.OnPacket(pkt, len(pkt), 0)
	}

	mp.mu.Lock()
	mp.lastReset = time.Now().Add(-2 * time.Second)
	mp.mu.Unlock()

	mp.OnPacket(pkt, len(pkt), 0)

	mp.mu.Lock()
	alerted := !mp.lastAlert.IsZero()
	mp.mu.Unlock()

	if alerted {
		t.Error("McastPolicer no debería contar tráfico NDP Solicited-Node (33:33:ff:*)")
	}
}

func TestMcastPolicer_IgnoresUnicast(t *testing.T) {
	cfg := &config.McastPolicerConfig{
		Enabled:   true,
		MaxPPS:    5,
		Overrides: make(map[string]config.McastPolicerOverride),
	}

	mp := NewMcastPolicer(cfg, mockNotifier(), "test0")
	mp.Start(nil, &net.Interface{Name: "test0"})

	// Paquete unicast (no multicast)
	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	for i := 0; i < 100; i++ {
		mp.OnPacket(pkt, len(pkt), 0)
	}

	mp.mu.Lock()
	count := mp.packetCount
	mp.mu.Unlock()

	if count != 0 {
		t.Errorf("McastPolicer no debería contar paquetes unicast, contó %d", count)
	}
}

// =============================================================================
//  TEST 10: BcastRatio (Broadcast Ratio)
// =============================================================================

func TestBcastRatio_CounterAccuracy(t *testing.T) {
	cfg := &config.BcastRatioConfig{
		Enabled:       true,
		MaxRatio:      0.5,
		MinSampleSize: 10,
		AlertCooldown: "1s",
		Overrides:     make(map[string]config.BcastRatioOverride),
	}

	store := NewTopologyStore()
	br := NewBcastRatio(cfg, mockNotifier(), "test0", store)

	// 8 broadcast + 2 unicast = 80% ratio (> 50% threshold)
	bcastPkt := make([]byte, 14)
	copy(bcastPkt[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	unicastPkt := make([]byte, 14)
	copy(unicastPkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	for i := 0; i < 8; i++ {
		br.OnPacket(bcastPkt, 14, 0)
	}
	for i := 0; i < 2; i++ {
		br.OnPacket(unicastPkt, 14, 0)
	}

	bcast := atomic.LoadUint64(&br.bcastCount)
	total := atomic.LoadUint64(&br.totalCount)

	if bcast != 8 {
		t.Errorf("Esperaba 8 broadcast, obtuve %d", bcast)
	}
	if total != 10 {
		t.Errorf("Esperaba 10 total, obtuve %d", total)
	}
}

func TestBcastRatio_EvaluateTriggersAlert(t *testing.T) {
	cfg := &config.BcastRatioConfig{
		Enabled:       true,
		MaxRatio:      0.5,
		MinSampleSize: 10,
		AlertCooldown: "1s",
		Overrides:     make(map[string]config.BcastRatioOverride),
	}

	store := NewTopologyStore()
	br := NewBcastRatio(cfg, mockNotifier(), "test0", store)

	// Inyectar 9 broadcast + 1 unicast = 90%
	bcastPkt := make([]byte, 14)
	copy(bcastPkt[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	unicastPkt := make([]byte, 14)
	copy(unicastPkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	for i := 0; i < 9; i++ {
		br.OnPacket(bcastPkt, 14, 0)
	}
	br.OnPacket(unicastPkt, 14, 0)

	// Llamar evaluate() directamente (simula tick de 1s)
	br.evaluate()

	br.mu.Lock()
	alerted := !br.lastAlert.IsZero()
	br.mu.Unlock()

	if !alerted {
		t.Error("BcastRatio debería haber disparado alerta con 90% broadcast (threshold 50%)")
	}
}

func TestBcastRatio_BelowThresholdNoAlert(t *testing.T) {
	cfg := &config.BcastRatioConfig{
		Enabled:       true,
		MaxRatio:      0.8,
		MinSampleSize: 10,
		AlertCooldown: "1s",
		Overrides:     make(map[string]config.BcastRatioOverride),
	}

	store := NewTopologyStore()
	br := NewBcastRatio(cfg, mockNotifier(), "test0", store)

	// 5 broadcast + 5 unicast = 50% (< 80% threshold)
	bcastPkt := make([]byte, 14)
	copy(bcastPkt[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	unicastPkt := make([]byte, 14)
	copy(unicastPkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	for i := 0; i < 5; i++ {
		br.OnPacket(bcastPkt, 14, 0)
		br.OnPacket(unicastPkt, 14, 0)
	}

	br.evaluate()

	br.mu.Lock()
	alerted := !br.lastAlert.IsZero()
	br.mu.Unlock()

	if alerted {
		t.Error("BcastRatio no debería alertar con 50% broadcast (threshold 80%)")
	}
}

// =============================================================================
//  TEST 11: VlanLeak (VLAN Leakage Detection)
// =============================================================================

func TestVlanLeak_ProhibitedPairDetection(t *testing.T) {
	cfg := &config.VlanLeakConfig{
		Enabled:         true,
		ProhibitedPairs: [][]int{{10, 20}},
		AlertCooldown:   "1s",
	}

	store := NewTopologyStore()
	vl := NewVlanLeak(cfg, mockNotifier(), "test0", store)
	vl.Start(nil, &net.Interface{Name: "test0"})

	srcMac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	pkt := make([]byte, 14)
	copy(pkt[6:12], srcMac)

	// Mismo MAC en VLAN 10, luego VLAN 20 (par prohibido)
	vl.OnPacket(pkt, 14, 10)
	vl.OnPacket(pkt, 14, 20)

	var key [6]byte
	copy(key[:], srcMac)

	vl.mu.Lock()
	_, alerted := vl.lastAlert[key]
	vl.mu.Unlock()

	if !alerted {
		t.Error("VlanLeak debería haber detectado tráfico en par de VLANs prohibido [10, 20]")
	}
}

func TestVlanLeak_AllowedPairNoAlert(t *testing.T) {
	cfg := &config.VlanLeakConfig{
		Enabled:         true,
		ProhibitedPairs: [][]int{{10, 20}},
		AlertCooldown:   "1s",
	}

	store := NewTopologyStore()
	vl := NewVlanLeak(cfg, mockNotifier(), "test0", store)
	vl.Start(nil, &net.Interface{Name: "test0"})

	srcMac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}
	pkt := make([]byte, 14)
	copy(pkt[6:12], srcMac)

	// VLAN 10 y 30 (no es par prohibido)
	vl.OnPacket(pkt, 14, 10)
	vl.OnPacket(pkt, 14, 30)

	var key [6]byte
	copy(key[:], srcMac)

	vl.mu.Lock()
	_, alerted := vl.lastAlert[key]
	vl.mu.Unlock()

	if alerted {
		t.Error("VlanLeak no debería alertar para VLANs no prohibidas [10, 30]")
	}
}

func TestVlanLeak_IgnoresNativeVlan(t *testing.T) {
	cfg := &config.VlanLeakConfig{
		Enabled:         true,
		ProhibitedPairs: [][]int{{0, 10}},
		AlertCooldown:   "1s",
	}

	store := NewTopologyStore()
	vl := NewVlanLeak(cfg, mockNotifier(), "test0", store)

	pkt := make([]byte, 14)
	copy(pkt[6:12], []byte{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01})

	// vlanID=0 es descartado por OnPacket (solo procesa tráfico con VLAN tag)
	vl.OnPacket(pkt, 14, 0)

	vl.mu.Lock()
	entries := len(vl.macVlanMap)
	vl.mu.Unlock()

	if entries != 0 {
		t.Error("VlanLeak no debería procesar paquetes sin VLAN tag (vlanID=0)")
	}
}

func TestVlanLeak_IgnoresMulticast(t *testing.T) {
	cfg := &config.VlanLeakConfig{
		Enabled:         true,
		ProhibitedPairs: [][]int{{10, 20}},
		AlertCooldown:   "1s",
	}

	store := NewTopologyStore()
	vl := NewVlanLeak(cfg, mockNotifier(), "test0", store)

	// MAC origen multicast (bit 0 del primer byte = 1)
	pkt := make([]byte, 14)
	copy(pkt[6:12], []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01})

	vl.OnPacket(pkt, 14, 10)
	vl.OnPacket(pkt, 14, 20)

	vl.mu.Lock()
	entries := len(vl.macVlanMap)
	vl.mu.Unlock()

	if entries != 0 {
		t.Error("VlanLeak no debería procesar paquetes con MAC origen multicast")
	}
}

// =============================================================================
//  TEST 12: MetaEngine (Correlation + Interface Filtering)
// =============================================================================

func TestMetaEngine_CorrelatedLoop(t *testing.T) {
	store := NewTopologyStore()
	me := NewMetaEngine(mockNotifier(), "eth0", store, 2*time.Second, 2, 1*time.Second)

	// Simular alerta de ActiveProbe en eth0
	me.IngestAlert("[ActiveProbe] 🚨 LOOP CONFIRMED!\n    INTERFACE: eth0\n    DETAIL: Self-Loop")

	// Simular alerta de EtherFuse en eth0
	me.IngestAlert("[EtherFuse] ⚡ LOOP DETECTED!\n    INTERFACE: eth0\n    DETAIL: Repeated Payload")

	me.mu.Lock()
	alerted := !me.lastCorAlert.IsZero()
	me.mu.Unlock()

	if !alerted {
		t.Error("MetaEngine debería haber emitido CorrelatedLoop con ActiveProbe+EtherFuse")
	}
}

func TestMetaEngine_CorrelatedAnomaly(t *testing.T) {
	store := NewTopologyStore()
	me := NewMetaEngine(mockNotifier(), "eth0", store, 2*time.Second, 2, 1*time.Second)

	// DhcpHunter + ArpWatchdog no forman una loop signature
	me.IngestAlert("[DhcpHunter] 🚨 ROGUE DHCP SERVER DETECTED!\n    INTERFACE: eth0\n    DETAIL: rogue")
	me.IngestAlert("[ArpWatchdog] ⚠️ ARP STORM!\n    INTERFACE: eth0\n    DETAIL: high volume")

	me.mu.Lock()
	alerted := !me.lastCorAlert.IsZero()
	engines := len(me.recentHits)
	me.mu.Unlock()

	if !alerted {
		t.Error("MetaEngine debería haber emitido CorrelatedAnomaly con 2 engines no-loop")
	}
	if engines < 2 {
		t.Errorf("Esperaba 2 engines registrados, obtuve %d", engines)
	}
}

func TestMetaEngine_InterfaceFiltering(t *testing.T) {
	store := NewTopologyStore()
	me := NewMetaEngine(mockNotifier(), "eth0", store, 2*time.Second, 2, 1*time.Second)

	// Alerta de eth0 (nuestra interfaz)
	me.IngestAlert("[ActiveProbe] 🚨 LOOP!\n    INTERFACE: eth0\n    DETAIL: test")

	// Alerta de eth1 (otra interfaz, debe ser descartada)
	me.IngestAlert("[EtherFuse] ⚡ LOOP!\n    INTERFACE: eth1\n    DETAIL: test")

	me.mu.Lock()
	engines := len(me.recentHits)
	alerted := !me.lastCorAlert.IsZero()
	me.mu.Unlock()

	if engines != 1 {
		t.Errorf("MetaEngine de eth0 debería tener solo 1 engine (ActiveProbe), tiene %d", engines)
	}
	if alerted {
		t.Error("MetaEngine no debería haber correlado alertas de interfaces distintas")
	}
}

func TestMetaEngine_IgnoresOwnAlerts(t *testing.T) {
	store := NewTopologyStore()
	me := NewMetaEngine(mockNotifier(), "eth0", store, 2*time.Second, 2, 1*time.Second)

	me.IngestAlert("[MetaEngine] 🚨 CONFIRMED LOOP!\n    INTERFACE: eth0")
	me.IngestAlert("[System] ⚠️ Resuming alerts\n    INTERFACE: eth0")

	me.mu.Lock()
	engines := len(me.recentHits)
	me.mu.Unlock()

	if engines != 0 {
		t.Errorf("MetaEngine no debería procesar sus propias alertas ni las de System, tiene %d engines", engines)
	}
}

func TestMetaEngine_CooldownRespected(t *testing.T) {
	store := NewTopologyStore()
	cooldown := 5 * time.Second
	me := NewMetaEngine(mockNotifier(), "eth0", store, 2*time.Second, 2, cooldown)

	// Primera correlación
	me.IngestAlert("[ActiveProbe] LOOP!\n    INTERFACE: eth0")
	me.IngestAlert("[EtherFuse] LOOP!\n    INTERFACE: eth0")

	me.mu.Lock()
	firstAlert := me.lastCorAlert
	me.mu.Unlock()

	// Segunda correlación inmediata (debería ser ignorada por cooldown)
	me.IngestAlert("[MacStorm] STORM!\n    INTERFACE: eth0")

	me.mu.Lock()
	secondAlert := me.lastCorAlert
	me.mu.Unlock()

	if !firstAlert.Equal(secondAlert) {
		t.Error("MetaEngine no debería emitir segunda alerta dentro del cooldown")
	}
}

func TestMetaEngine_WindowExpiration(t *testing.T) {
	store := NewTopologyStore()
	me := NewMetaEngine(mockNotifier(), "eth0", store, 50*time.Millisecond, 2, 1*time.Millisecond)

	me.IngestAlert("[ActiveProbe] LOOP!\n    INTERFACE: eth0")

	// Esperar a que expire la ventana
	time.Sleep(100 * time.Millisecond)

	me.IngestAlert("[EtherFuse] LOOP!\n    INTERFACE: eth0")

	me.mu.Lock()
	alerted := !me.lastCorAlert.IsZero()
	me.mu.Unlock()

	if alerted {
		t.Error("MetaEngine no debería correlacionar hits que caen fuera de la ventana temporal")
	}
}

func TestMetaEngine_BelongsToInterface(t *testing.T) {
	store := NewTopologyStore()
	me := NewMetaEngine(mockNotifier(), "br-lan", store, 2*time.Second, 2, 1*time.Second)

	tests := []struct {
		msg  string
		want bool
	}{
		{"[ActiveProbe] LOOP!\n    INTERFACE: br-lan\n    DETAIL: test", true},
		{"[ActiveProbe] LOOP!\n    INTERFACE: eth0\n    DETAIL: test", false},
		{"[ActiveProbe] LOOP!\n    INTERFACE: br-lan2\n    DETAIL: test", false},
		{"[ActiveProbe] LOOP!\n    INTERFACE:   br-lan\n    DETAIL: test", true},
		{"[ActiveProbe] LOOP!\n    INTERFACE: br-lan (Domain: VLAN_10)\n    DETAIL: test", true},
		{"No tiene INTERFACE field", false},
	}

	for _, tt := range tests {
		got := me.belongsToInterface(tt.msg)
		if got != tt.want {
			t.Errorf("belongsToInterface(%q) = %v, want %v", tt.msg[:40], got, tt.want)
		}
	}
}

func TestMatchesLoopSignature(t *testing.T) {
	tests := []struct {
		engines []string
		want    bool
	}{
		{[]string{"ActiveProbe", "EtherFuse"}, true},
		{[]string{"ActiveProbe", "MacStorm"}, true},
		{[]string{"EtherFuse", "BcastRatio"}, true},
		{[]string{"ActiveProbe", "EtherFuse", "MacStorm"}, true},
		{[]string{"DhcpHunter", "ArpWatchdog"}, false},
		{[]string{"RaGuard", "FlowPanic"}, false},
		{[]string{"ActiveProbe"}, false},
	}

	for _, tt := range tests {
		got := matchesLoopSignature(tt.engines)
		if got != tt.want {
			t.Errorf("matchesLoopSignature(%v) = %v, want %v", tt.engines, got, tt.want)
		}
	}
}

// =============================================================================
//  BENCHMARKS
// =============================================================================

func BenchmarkEtherFuse_OnPacket(b *testing.B) {
	cfg := &config.EtherFuseConfig{
		Enabled:        true,
		HistorySize:    4096,
		AlertThreshold: 5000000, 
		StormPPSLimit:  10000000,
		AlertCooldown:  "5s",
		Overrides:      make(map[string]config.EtherFuseOverride),
	}
	store := NewTopologyStore()
	ef := NewEtherFuse(cfg, mockNotifier(), "bench", store)
	ef.Start(nil, &net.Interface{Name: "bench"})

	packet := bytes.Repeat([]byte("A"), 64)
	
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ef.OnPacket(packet, 64, 0)
	}
}

func BenchmarkMacStorm_OnPacket(b *testing.B) {
	cfg := &config.MacStormConfig{
		Enabled:       true,
		MaxPPSPerMac:  50000000, 
		AlertCooldown: "30s",
		Overrides:     make(map[string]config.MacStormOverride),
	}
	
	ms := NewMacStorm(cfg, mockNotifier(), "bench")
	ms.Start(nil, &net.Interface{Name: "bench"})
	
	packet := make([]byte, 64)
	copy(packet[6:12], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ms.OnPacket(packet, 64, 10)
	}
}

func BenchmarkFlapGuard_OnPacket(b *testing.B) {
	cfg := &config.FlapGuardConfig{
		Enabled:       true, 
		Threshold:     10000, 
		Window:        "1s",
		AlertCooldown: "30s",
		Overrides:     make(map[string]config.FlapGuardOverride),
	}
	
	fg := NewFlapGuard(cfg, mockNotifier(), "bench")
	fg.Start(nil, &net.Interface{Name: "bench"})
	
	packet := make([]byte, 64)
	copy(packet[6:12], []byte{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		vlan := uint16(i % 2)
		fg.OnPacket(packet, 64, vlan)
	}
}

func BenchmarkActiveProbe_OnPacket(b *testing.B) {
	cfg := &config.ActiveProbeConfig{
		Enabled:      true,
		Ethertype:    0xFFFF,
		MagicPayload: "BENCHMARK_PAYLOAD",
		Overrides:    make(map[string]config.ActiveProbeOverride),
	}
	store := NewTopologyStore()
	ap := NewActiveProbe(cfg, mockNotifier(), "bench", store)
	
	ap.myMAC, _ = net.ParseMAC("00:11:22:33:44:55")
	ap.ethertype = 0xFFFF
	
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, 0xFFFF)
	
	packet := make([]byte, 0, 64)
	packet = append(packet, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) 
	packet = append(packet, ap.myMAC...)                                    
	packet = append(packet, typeBytes...)                                   
	packet = append(packet, []byte("BENCHMARK_PAYLOAD")...)                 
	
	padding := make([]byte, 64-len(packet))
	packet = append(packet, padding...)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ap.OnPacket(packet, len(packet), 0)
	}
}

func BenchmarkArpWatchdog_OnPacket(b *testing.B) {
	cfg := &config.ArpWatchConfig{
		Enabled:       true,
		MaxPPS:        100000000, 
		AlertCooldown: "30s",
		Overrides:     make(map[string]config.ArpWatchOverride),
	}
	
	aw := NewArpWatchdog(cfg, mockNotifier(), "bench")
	aw.Start(nil, &net.Interface{Name: "bench"})

	packet := make([]byte, 64)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)
	binary.BigEndian.PutUint16(packet[20:22], 1)

	// FIX: Diferentes IPs para evitar detección GARP en benchmark
	packet[28+3] = 1
	packet[38+3] = 2

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		aw.OnPacket(packet, 64, 0)
	}
}
