package sniffer

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"

	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/detector"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

// Run inicia la captura de paquetes.
// OPTIMIZACIÓN: Implementa "Socket Breaker" para shutdown inmediato.
func Run(ctx context.Context, ifaceName string, cfg *config.Config, engine *detector.Engine) error {
	
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	conn, err := packet.Listen(ifi, packet.Raw, 3, nil)
	if err != nil {
		return fmt.Errorf("[%s] failed to open raw socket: %w", ifaceName, err)
	}
	defer conn.Close()

	engine.StartAll(conn, ifi)

	if err := conn.SetPromiscuous(true); err != nil {
		log.Printf("[%s] Warning: Failed to set promiscuous mode: %v", ifaceName, err)
	}

	// --- BPF FILTER CONFIGURATION ---
	// ARQUITECTURA: Permitimos tráfico con bit multicast (incluye broadcast)
	// Esto incluye:
	// - Broadcast (FF:FF:...) -> ActiveProbe, ARP, DHCP
	// - Multicast Standard (01:00:5E...) -> EtherFuse, McastPolicer
	// - Multicast Control (01:80:C2...) -> STP, LLDP (0x88CC), LACP
	// - Multicast Cisco (01:00:0C...) -> CDP, VTP, DTP
	// 
	// NOTA: No filtramos por EtherType específico en el BPF para no cegar a los
	// motores de seguridad (ArpWatch, FlowPanic) que necesitan ver protocolos variados.
	filter, err := bpf.Assemble([]bpf.Instruction{
		// 1. Cargar Byte 0 de la MAC Destino
		bpf.LoadAbsolute{Off: 0, Size: 1},
		// 2. Comprobar Bit Multicast (Bit 0 del Byte 0 == 1)
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 1},
		// 3. Si es 0 (Unicast), saltar a DROP (Ret 0). Si es 1, continuar.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
		// 4. Aceptar (Ret SnapLen)
		bpf.RetConstant{Val: uint32(cfg.Network.SnapLen)}, 
		// 5. Rechazar (Ret 0)
		bpf.RetConstant{Val: 0},                           
	})
	if err != nil {
		return fmt.Errorf("[%s] BPF assembly failed: %w", ifaceName, err)
	}

	if err := conn.SetBPF(filter); err != nil {
		return fmt.Errorf("[%s] failed to apply BPF filter: %w", ifaceName, err)
	}

	log.Printf("🛡️  Sniffer active on %s [BPF: Multicast+Broadcast]", ifaceName)

	// Pre-inicializar app_drops_total a 0 para que siempre aparezca en Prometheus
	telemetry.AppDrops.WithLabelValues(ifaceName, "read_error")

	// --- 1. MONITOR DE DROPS + PPS ---
	var ppsCounter uint64
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastDrops uint32 = 0

		ppsTicker := time.NewTicker(1 * time.Second)
		defer ppsTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ppsTicker.C:
				count := atomic.SwapUint64(&ppsCounter, 0)
				telemetry.RxPPS.WithLabelValues(ifaceName).Set(float64(count))
			case <-ticker.C:
				stats, err := conn.Stats()
				if err == nil {
					if stats.Drops > lastDrops {
						delta := stats.Drops - lastDrops
						telemetry.SocketDrops.WithLabelValues(ifaceName).Add(float64(delta))
						if delta > 100 {
							log.Printf("⚠️ [%s] KERNEL DROPS: %d packets lost", ifaceName, delta)
						}
						lastDrops = stats.Drops
					}
				}
			}
		}
	}()

	// --- 2. SHUTDOWN BREAKER (LA SOLUCIÓN AL HANG) ---
	go func() {
		<-ctx.Done()
		conn.Close() // <--- CRÍTICO: Fuerza el error en ReadFrom
	}()

	// --- 3. LOOP DE LECTURA (HOT PATH) ---
	buf := make([]byte, cfg.Network.SnapLen)

	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return nil 
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			telemetry.AppDrops.WithLabelValues(ifaceName, "read_error").Inc()
			log.Printf("⚠️ [%s] Read error: %v", ifaceName, err)
			continue
		}

		atomic.AddUint64(&ppsCounter, 1)

		// --- PROCESAMIENTO ---
		start := time.Now()

		telemetry.TrackPacket(ifaceName, buf[:n], n)

		var vlanID uint16 = 0
		if n >= 18 {
			etherType := binary.BigEndian.Uint16(buf[12:14])
			if etherType == 0x8100 {
				vlanID = binary.BigEndian.Uint16(buf[14:16]) & 0x0FFF
			}
		}

		engine.DispatchPacket(buf[:n], n, vlanID)

		duration := time.Since(start).Nanoseconds()
		telemetry.ProcessingTime.WithLabelValues(ifaceName).Observe(float64(duration))
		telemetry.ProcessingLatency.WithLabelValues(ifaceName).Observe(float64(duration))
	}
}
