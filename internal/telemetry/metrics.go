package telemetry

import (
	"encoding/binary"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Buckets para histogramas de latencia (en nanosegundos).
// Rango: 1µs a 1ms. Optimizados para fast-path networking.
var processingBuckets = []float64{1000, 5000, 10000, 50000, 100000, 500000, 1000000}

// Buckets para distribución de tamaño de paquetes (Standard Ethernet).
var sizeBuckets = []float64{60, 64, 128, 256, 512, 1024, 1518, 9000}

var (
	// 1. VOLUMEN DE TRÁFICO
	// Cardinalidad controlada: ethertype y cast son finitos.
	RxPackets = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loopwarden_rx_packets_total",
		Help: "Total packets processed by protocol and cast type",
	}, []string{"ethertype", "cast"})

	RxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loopwarden_rx_bytes_total",
		Help: "Total bytes processed by protocol",
	}, []string{"ethertype"})

	// 2. DETECCIONES DEL MOTOR
	EngineHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loopwarden_engine_hits_total",
		Help: "Alerts triggered by detection engines",
	}, []string{"engine", "threat_type"})

	// 3. LATENCIA DE PROCESAMIENTO
	ProcessingTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "loopwarden_processing_ns",
		Help:    "Time taken to process a packet in nanoseconds",
		Buckets: processingBuckets,
	})

	// 4. SALUD DEL SOCKET (KERNEL DROPS)
	// Crítico para saber si estamos ciegos ante una tormenta.
	SocketDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "loopwarden_socket_drops_total",
		Help: "Number of packets dropped by the kernel interface driver due to buffer overflow",
	})

	// 5. PERFIL DE TAMAÑO
	PacketSizes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "loopwarden_packet_size_bytes",
		Help:    "Distribution of packet sizes in bytes",
		Buckets: sizeBuckets,
	})

	// 6. FORENSE ARP
	ArpOps = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loopwarden_arp_ops_total",
		Help: "ARP operations breakdown (request/reply)",
	}, []string{"operation"})
)

// TrackPacket analiza el paquete RAW y actualiza métricas.
// OPTIMIZACIÓN: Zero-alloc. Lee bytes directamente sin crear objetos intermedios.
func TrackPacket(data []byte, length int) {
	if length < 14 {
		return
	}

	// --- A. TAMAÑO ---
	PacketSizes.Observe(float64(length))

	// --- B. TIPO DE CAST (Broadcast vs Multicast) ---
	// BPF ya filtra Unicast, así que asumimos Multicast salvo que sea FF:FF...
	cast := "multicast"
	// Check optimizado: FF:FF:FF:FF:FF:FF
	if data[0]&data[1]&data[2]&data[3]&data[4]&data[5] == 0xFF {
		cast = "broadcast"
	}

	// --- C. ETHERTYPE ---
	// Offset 12 y 13.
	eTypeVal := binary.BigEndian.Uint16(data[12:14])
	sType := "unknown"

	switch eTypeVal {
	case 0x0800:
		sType = "IPv4"
	case 0x0806:
		sType = "ARP"
	case 0x86DD:
		sType = "IPv6"
	case 0x8100, 0x88A8:
		sType = "VLAN_Tagged"
	case 0x8808:
		sType = "FlowControl" // PAUSE Frames
	case 0x88CC:
		sType = "LLDP"
	default:
		// Agrupación para evitar High Cardinality en ataque de fuzzing
		if eTypeVal < 1500 {
			sType = "Non-IP" // LLC frames
		} else {
			sType = "Other_Eth2"
		}
	}

	RxPackets.WithLabelValues(sType, cast).Inc()
	RxBytes.WithLabelValues(sType).Add(float64(length))

	// --- D. DETALLE ARP ---
	// Si es ARP, miramos si es Request (1) o Reply (2).
	// Header Eth (14) + Offset ARP OpCode (6) = Byte 20.
	if eTypeVal == 0x0806 && length >= 22 {
		opCode := binary.BigEndian.Uint16(data[20:22])
		switch opCode {
		case 1:
			ArpOps.WithLabelValues("request").Inc()
		case 2:
			ArpOps.WithLabelValues("reply").Inc()
		default:
			ArpOps.WithLabelValues("other").Inc()
		}
	}
}
