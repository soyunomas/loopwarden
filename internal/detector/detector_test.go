package detector

import (
	"bytes"
	"encoding/binary"
	"net"
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
