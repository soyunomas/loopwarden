package sniffer

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
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
	// Nota: No usamos defer conn.Close() aquí de forma simple, 
	// porque lo cerraremos explícitamente en el Breaker para desbloquear el Read.
	// Sin embargo, Go permite Close() múltiples veces sin pánico, así que lo mantenemos por seguridad.
	defer conn.Close()

	engine.StartAll(conn, ifi)

	if err := conn.SetPromiscuous(true); err != nil {
		log.Printf("[%s] Warning: Failed to set promiscuous mode: %v", ifaceName, err)
	}

	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
		bpf.RetConstant{Val: uint32(cfg.Network.SnapLen)}, 
		bpf.RetConstant{Val: 0},                           
	})
	if err != nil {
		return fmt.Errorf("[%s] BPF assembly failed: %w", ifaceName, err)
	}

	if err := conn.SetBPF(filter); err != nil {
		return fmt.Errorf("[%s] failed to apply BPF filter: %w", ifaceName, err)
	}

	log.Printf("🛡️  Sniffer active on %s [BPF Active]", ifaceName)

	// --- 1. MONITOR DE DROPS ---
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastDrops uint32 = 0

		for {
			select {
			case <-ctx.Done():
				return
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
	// Esta goroutine espera la señal de cancelación y mata el socket.
	// Esto hace que ReadFrom desbloquee inmediatamente con error.
	go func() {
		<-ctx.Done()
		conn.Close() // <--- CRÍTICO: Fuerza el error en ReadFrom
	}()

	// --- 3. LOOP DE LECTURA (HOT PATH) ---
	buf := make([]byte, cfg.Network.SnapLen)

	for {
		// Ya no necesitamos select case <-ctx.Done() aquí al principio
		// porque el error de ReadFrom manejará la salida.

		// Mantenemos el Deadline para evitar zombies si el breaker fallara (defensa en profundidad)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			// Comprobamos si el error es porque cerramos el socket (shutdown limpio)
			// Go suele devolver "use of closed network connection" o "file already closed"
			if strings.Contains(err.Error(), "closed") {
				return nil // Salida limpia inmediata
			}

			// Si es timeout, solo volvemos a intentar (el contexto se chequeará implicitamente al intentar leer de nuevo si está cerrado)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Verificamos contexto por si acaso fue un timeout natural justo durante el shutdown
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}

			log.Printf("⚠️ [%s] Read error: %v", ifaceName, err)
			continue
		}

		// --- PROCESAMIENTO (Sin cambios) ---
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
	}
}
