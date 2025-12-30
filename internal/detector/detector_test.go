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
func mockNotifier() *notifier.Notifier {
	cfg := &config.AlertsConfig{}
	return notifier.NewNotifier(cfg)
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
	}

	ef := NewEtherFuse(cfg, mockNotifier())
	packet := []byte("PAYLOAD_TEST")
	
	expectedHash := hashBody(packet)

	// 1. Primer paquete: Se registra en la tabla con count=1
	ef.OnPacket(packet, len(packet), 0)
	
	ef.mu.Lock()
	count := ef.lookupTable[expectedHash]
	ef.mu.Unlock()

	if count != 1 {
		t.Errorf("Esperaba count=1 para el primer paquete, obtuve %d", count)
	}

	// 2. Inyectamos hasta llegar al umbral
	for i := 0; i < 4; i++ {
		ef.OnPacket(packet, len(packet), 0)
	}
	
	ef.mu.Lock()
	count = ef.lookupTable[expectedHash]
	ef.mu.Unlock()
	
	if int(count) != threshold {
		t.Errorf("Esperaba count=%d tras 5 inyecciones, obtuve %d", threshold, count)
	}

	// 3. Trigger de Alerta (packet #6) -> Reset
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
		Enabled:      true,
		MaxPPSPerMac: 100, 
	}

	ms := NewMacStorm(cfg, mockNotifier())

	srcMac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	packet := make([]byte, 14)
	copy(packet[6:12], srcMac)

	// Inyectamos 150 paquetes (superando el max de 100)
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
	}

	ap := NewActiveProbe(cfg, mockNotifier())
	myMac, _ := net.ParseMAC("00:11:22:33:44:55")
	ap.myMAC = myMac

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, 0xFFFF)

	// Paquete NATIVO (Sin Tag)
	packetNative := make([]byte, 0)
	packetNative = append(packetNative, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) 
	packetNative = append(packetNative, myMac...)                                       
	packetNative = append(packetNative, typeBytes...)                                   
	packetNative = append(packetNative, []byte("MAGIC")...)                             

	ap.lastAlert = time.Time{} // Reset time
	ap.OnPacket(packetNative, len(packetNative), 0)

	ap.mu.Lock()
	if ap.lastAlert.IsZero() {
		t.Error("Falló detección en Native VLAN")
	}
	ap.mu.Unlock()
}

// =============================================================================
//  TEST 4: FlapGuard (Topology Instability)
// =============================================================================

func TestFlapGuard_Flapping(t *testing.T) {
	threshold := 3
	cfg := &config.FlapGuardConfig{
		Enabled:   true,
		Threshold: threshold,
	}

	fg := NewFlapGuard(cfg, mockNotifier())

	// Host problemático
	srcMac := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01}
	
	// Construir paquete base
	packet := make([]byte, 14)
	copy(packet[6:12], srcMac)

	// Simular Flapping rápido: VLAN 10 -> VLAN 20 -> VLAN 10 -> VLAN 20
	// Salto 1: Aparece en VLAN 10
	fg.OnPacket(packet, 14, 10)
	
	// Salto 2: Aparece en VLAN 20 (Count = 1)
	fg.OnPacket(packet, 14, 20)

	// Salto 3: Aparece en VLAN 10 (Count = 2)
	fg.OnPacket(packet, 14, 10)

	// Salto 4: Aparece en VLAN 20 (Count = 3 -> TRIGGER)
	fg.OnPacket(packet, 14, 20)

	var key [6]byte
	copy(key[:], srcMac)

	fg.mu.Lock()
	entry := fg.registry[key]
	fg.mu.Unlock()

	// Verificaciones
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
	// IMPORTANTE: ArpWatchdog resetea cada segundo. 
	// Para testear el límite, debemos inyectar rápido y luego forzar el chequeo.
	
	maxPPS := uint64(10)
	cfg := &config.ArpWatchConfig{
		Enabled: true,
		MaxPPS:  maxPPS,
	}

	aw := NewArpWatchdog(cfg, mockNotifier())

	// Construir Paquete ARP Request (Who-Has)
	// Eth Header (14) + ARP (28)
	// ARP Request: OpCode está en byte 20-21 del ARP header, o 6-7 desde inicio ARP
	// Offset global: 14 (eth) + 6 = 20.
	
	// EtherType 0x0806
	ethPacket := make([]byte, 14+28)
	binary.BigEndian.PutUint16(ethPacket[12:14], 0x0806) // EtherType ARP
	
	// ARP OpCode: 1 (Request) en posición 20,21
	binary.BigEndian.PutUint16(ethPacket[20:22], 1) 

	// 1. Inyectar 'maxPPS + 5' paquetes rápidamente
	for i := 0; i < int(maxPPS)+5; i++ {
		aw.OnPacket(ethPacket, len(ethPacket), 0)
	}

	aw.mu.Lock()
	count := aw.packetCount
	aw.mu.Unlock()

	if count != maxPPS+5 {
		t.Errorf("Esperaba contar %d paquetes ARP, conté %d", maxPPS+5, count)
	}

	// 2. Verificar filtrado de OpCode (No contar ARP Reply = 2)
	binary.BigEndian.PutUint16(ethPacket[20:22], 2) // Reply
	aw.OnPacket(ethPacket, len(ethPacket), 0)

	aw.mu.Lock()
	countAfterReply := aw.packetCount
	aw.mu.Unlock()

	if countAfterReply != count {
		t.Error("ArpWatchdog contó erróneamente un ARP Reply como Request")
	}

	// NOTA: No testeamos el disparo de la alerta aquí porque requiere esperar
	// time.Sleep(1 * time.Second) para que la lógica de ventana temporal se active,
	// lo cual ralentizaría los tests unitarios. Con verificar el conteo es suficiente
	// para validar la lógica del parser.
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
	}
	ef := NewEtherFuse(cfg, mockNotifier())
	packet := bytes.Repeat([]byte("A"), 64)
	
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ef.OnPacket(packet, 64, 0)
	}
}

func BenchmarkMacStorm_OnPacket(b *testing.B) {
	cfg := &config.MacStormConfig{
		Enabled:      true,
		MaxPPSPerMac: 50000000, 
	}
	ms := NewMacStorm(cfg, mockNotifier())
	packet := make([]byte, 64)
	copy(packet[6:12], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ms.OnPacket(packet, 64, 10)
	}
}

func BenchmarkFlapGuard_OnPacket(b *testing.B) {
	cfg := &config.FlapGuardConfig{Enabled: true, Threshold: 10000}
	fg := NewFlapGuard(cfg, mockNotifier())
	packet := make([]byte, 64)
	// MAC Fija
	copy(packet[6:12], []byte{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Alternar VLANs para forzar lógica de actualización
		vlan := uint16(i % 2)
		fg.OnPacket(packet, 64, vlan)
	}
}

func BenchmarkActiveProbe_OnPacket(b *testing.B) {
	cfg := &config.ActiveProbeConfig{
		Enabled:      true,
		Ethertype:    0xFFFF,
		MagicPayload: "BENCHMARK_PAYLOAD",
	}
	// Mock notifier
	ap := NewActiveProbe(cfg, mockNotifier())
	
	// Configuramos nuestra MAC para que el detector crea que el paquete es nuestro
	myMac, _ := net.ParseMAC("00:11:22:33:44:55")
	ap.myMAC = myMac

	// Pre-calculamos el paquete para no medir la creación, solo la detección
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, 0xFFFF)
	
	packet := make([]byte, 0, 64)
	packet = append(packet, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) // Dst Broadcast
	packet = append(packet, myMac...)                                       // Src (Nosotros)
	packet = append(packet, typeBytes...)                                   // EtherType
	packet = append(packet, []byte("BENCHMARK_PAYLOAD")...)                 // Payload
	
	// Rellenar hasta 64 bytes para realismo
	padding := make([]byte, 64-len(packet))
	packet = append(packet, padding...)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Pasamos VlanID 0 (Native)
		ap.OnPacket(packet, len(packet), 0)
	}
}

func BenchmarkArpWatchdog_OnPacket(b *testing.B) {
	cfg := &config.ArpWatchConfig{
		Enabled: true,
		MaxPPS:  100000000, // Límite absurdo para no triggerear lógica de tiempo en bench
	}
	aw := NewArpWatchdog(cfg, mockNotifier())

	// Construimos un paquete ARP Request válido
	packet := make([]byte, 64)
	// EtherType ARP (0x0806) en bytes 12-13
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)
	// OpCode Request (1) en bytes 20-21 (14 header + 6 offset ARP)
	binary.BigEndian.PutUint16(packet[20:22], 1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		aw.OnPacket(packet, 64, 0)
	}
}
