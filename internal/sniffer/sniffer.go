package sniffer

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"

	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/detector"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

// Run inicia la captura en UNA interfaz específica
// Ahora recibe 'ifaceName' como argumento principal
func Run(ifaceName string, cfg *config.Config, engine *detector.Engine, stopChan chan os.Signal) error {
	
	// 1. Obtener interfaz física por nombre pasado
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// 2. Abrir Socket Raw (AF_PACKET)
	conn, err := packet.Listen(ifi, packet.Raw, 3, nil)
	if err != nil {
		return fmt.Errorf("[%s] failed to open raw socket: %w", ifaceName, err)
	}
	// No cerramos con defer aquí porque Run es bloqueante y manejado por goroutine superior,
	// pero para limpieza correcta al salir el main:
	defer conn.Close()

	// 3. Iniciar Algoritmos
	engine.StartAll(conn, ifi)

	// 4. Promiscuous Mode
	if err := conn.SetPromiscuous(true); err != nil {
		log.Printf("[%s] Warning: Failed to set promiscuous mode: %v", ifaceName, err)
	}

	// 5. BPF Filter
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

	// --- Monitor de Drops (Por interfaz) ---
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastDrops uint32 = 0

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				stats, err := conn.Stats()
				if err == nil {
					if stats.Drops > lastDrops {
						delta := stats.Drops - lastDrops
						telemetry.SocketDrops.Add(float64(delta))
						if delta > 100 {
							log.Printf("⚠️ [%s] KERNEL DROPS: %d packets lost", ifaceName, delta)
						}
						lastDrops = stats.Drops
					}
				}
			}
		}
	}()

	// 6. Loop de Lectura (Hot Path)
	// Zero-Alloc buffer per goroutine
	buf := make([]byte, cfg.Network.SnapLen)

	for {
		// Leemos del canal de cierre para salir limpiamente
		select {
		case <-stopChan:
			return nil
		default:
			// Non-blocking select allow us to proceed to read
		}
		
		// Set deadline para permitir chequear stopChan periódicamente si no hay tráfico
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return nil
			}
			// Timeout es normal
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("⚠️ [%s] Read error: %v", ifaceName, err)
			continue
		}

		start := time.Now()

		telemetry.TrackPacket(buf[:n], n)

		var vlanID uint16 = 0
		if n >= 18 {
			etherType := binary.BigEndian.Uint16(buf[12:14])
			if etherType == 0x8100 {
				vlanID = binary.BigEndian.Uint16(buf[14:16]) & 0x0FFF
			}
		}

		engine.DispatchPacket(buf[:n], n, vlanID)

		duration := time.Since(start).Nanoseconds()
		telemetry.ProcessingTime.Observe(float64(duration))
	}
}
