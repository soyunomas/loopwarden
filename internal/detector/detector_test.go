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
//  TEST 1: EtherFuse (Detección de Duplicados)
// =============================================================================

func TestEtherFuse_Detection(t *testing.T) {
	// Configuración: Alerta si hay MÁS de 5 duplicados
	threshold := 5
	cfg := &config.EtherFuseConfig{
		Enabled:        true,
		HistorySize:    10,
		AlertThreshold: threshold,
		StormPPSLimit:  1000,
	}

	ef := NewEtherFuse(cfg, mockNotifier())

	packet := []byte("PAYLOAD_TEST")

	// 1. Primer paquete: Se registra en el historial (No es duplicado)
	ef.OnPacket(packet, len(packet), 0)
	if ef.dupCounter != 0 {
		t.Errorf("El primer paquete no debería contar como duplicado. Counter=%d", ef.dupCounter)
	}

	// 2. Inyectamos 'threshold' veces (5 veces) -> Son duplicados
	for i := 0; i < threshold; i++ {
		ef.OnPacket(packet, len(packet), 0)
	}

	// Ahora dupCounter debería ser exactamente 5
	if ef.dupCounter != threshold {
		t.Errorf("Esperaba dupCounter=%d, obtuve %d", threshold, ef.dupCounter)
	}

	// 3. El trigger es estricto (> threshold). 
	// Necesitamos 1 paquete más para superar el 5 y disparar la alerta.
	// Al disparar la alerta, el contador se resetea a 0.
	
	// Forzamos que haya pasado el tiempo de cooldown para asegurar que entre en el log
	// (Aunque el reset del contador ocurre igual independientemente del cooldown del log,
	// pero es buena práctica mental).
	ef.lastDupAlert = time.Time{} 

	ef.OnPacket(packet, len(packet), 0) // Este es el duplicado número 6

	if ef.dupCounter != 0 {
		t.Errorf("El contador debería haberse reseteado tras superar el umbral (%d), pero es %d", threshold, ef.dupCounter)
	}
}

// =============================================================================
//  TEST 2: MacStorm (Detección de Velocidad por MAC)
// =============================================================================

func TestMacStorm_Counter(t *testing.T) {
	cfg := &config.MacStormConfig{
		Enabled:      true,
		MaxPPSPerMac: 100, 
	}

	ms := NewMacStorm(cfg, mockNotifier())

	// Construimos un paquete Ethernet dummy
	// Src MAC será: AA:BB:CC:DD:EE:FF
	srcMac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	packet := make([]byte, 14)
	copy(packet[6:12], srcMac)

	// Inyectamos 150 paquetes (superando el max de 100)
	for i := 0; i < 150; i++ {
		ms.OnPacket(packet, 14, 0)
	}

	// Verificamos el estado interno
	var key [6]byte
	copy(key[:], srcMac)

	ms.mu.Lock()
	count := ms.macCounters[key]
	_, alerted := ms.lastAlerts[key]
	ms.mu.Unlock()

	if count != 150 {
		t.Errorf("Esperaba contar 150 paquetes, se contaron %d", count)
	}

	if !alerted {
		t.Error("MacStorm debería haber registrado una alerta en lastAlerts")
	}
}

// =============================================================================
//  TEST 3: ActiveProbe con VLAN (Test de Offsets)
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

	// Setup para Types
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, 0xFFFF)

	// CASO A: Paquete sin VLAN (Native)
	packetNative := make([]byte, 0)
	packetNative = append(packetNative, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) // Dst
	packetNative = append(packetNative, myMac...)                                       // Src
	packetNative = append(packetNative, typeBytes...)                                   // Type
	packetNative = append(packetNative, []byte("MAGIC")...)                             // Payload

	initialTime := time.Time{}
	ap.lastAlert = initialTime
	
	ap.OnPacket(packetNative, len(packetNative), 0) // VLAN 0

	ap.mu.Lock()
	if ap.lastAlert == initialTime {
		t.Error("Falló detección en Native VLAN (offset 14)")
	}
	ap.mu.Unlock()

	// CASO B: Paquete CON VLAN (Tagged)
	packetVlan := make([]byte, 0)
	packetVlan = append(packetVlan, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) // Dst
	packetVlan = append(packetVlan, myMac...)                                     // Src
	packetVlan = append(packetVlan, []byte{0x81, 0x00}...)                        // TPID (802.1Q)
	packetVlan = append(packetVlan, []byte{0x00, 0x0A}...)                        // TCI (Vlan 10)
	packetVlan = append(packetVlan, typeBytes...)                                 // Type desplazado
	packetVlan = append(packetVlan, []byte("MAGIC")...)                           // Payload

	ap.lastAlert = initialTime
	
	// VLAN ID = 10
	ap.OnPacket(packetVlan, len(packetVlan), 10) 

	ap.mu.Lock()
	if ap.lastAlert == initialTime {
		t.Error("Falló detección en VLAN Tagged (offset 18).")
	}
	ap.mu.Unlock()
}

// =============================================================================
//  BENCHMARKS
// =============================================================================

func BenchmarkEtherFuse_OnPacket(b *testing.B) {
	cfg := &config.EtherFuseConfig{
		Enabled:        true,
		HistorySize:    4096,
		AlertThreshold: 5000000, // Alto para no resetear ni loguear durante el bench
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
		MaxPPSPerMac: 50000000, // Alto para evitar logs
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
