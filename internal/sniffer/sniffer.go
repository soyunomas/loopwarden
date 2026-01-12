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

// Run inicia la captura de paquetes a nivel de socket RAW.
func Run(cfg *config.Config, engine *detector.Engine, stopChan chan os.Signal) error {
	// 1. Obtener interfaz física
	ifi, err := net.InterfaceByName(cfg.Network.Interface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", cfg.Network.Interface, err)
	}

	// 2. Abrir Socket Raw (AF_PACKET)
	conn, err := packet.Listen(ifi, packet.Raw, 3, nil)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}
	defer conn.Close()

	// 3. Iniciar Algoritmos
	engine.StartAll(conn, ifi)

	// 4. Promiscuous Mode
	if err := conn.SetPromiscuous(true); err != nil {
		log.Printf("Warning: Failed to set promiscuous mode on %s: %v", cfg.Network.Interface, err)
	}

	// 5. BPF Filter (Optimización Kernel Side)
	// Solo deja pasar Broadcast y Multicast al user-space.
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
		bpf.RetConstant{Val: uint32(cfg.Network.SnapLen)}, // Keep
		bpf.RetConstant{Val: 0},                           // Drop
	})
	if err != nil {
		return fmt.Errorf("BPF assembly failed: %w", err)
	}

	if err := conn.SetBPF(filter); err != nil {
		return fmt.Errorf("failed to apply BPF filter: %w", err)
	}

	log.Printf("🛡️  Sniffer active on %s [BPF: Multicast/Broadcast Only]", cfg.Network.Interface)

	// --- 5.5 MONITOR DE SALUD DEL KERNEL (Background) ---
	// Verifica si el buffer del kernel se desborda (Drops).
	// Se hace en goroutine para no invocar Syscalls en el hot-loop.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		// CORRECCIÓN: Usamos uint32 porque packet.Stats.Drops es uint32
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
						// Opcional: Loguear si hay drops masivos
						if delta > 100 {
							log.Printf("⚠️ KERNEL DROPS DETECTED: %d packets lost (Buffer Full)", delta)
						}
						lastDrops = stats.Drops
					}
				}
			}
		}
	}()

	// 6. Loop de Lectura (Hot Path)
	go func() {
		// Zero-Alloc: Buffer reutilizable
		buf := make([]byte, cfg.Network.SnapLen)

		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					return
				}
				log.Printf("⚠️ Error reading packet: %v", err)
				continue
			}

			// --- INICIO CRONÓMETRO DE LATENCIA ---
			start := time.Now()

			// --- A. TELEMETRÍA (Observabilidad) ---
			// Analizamos el paquete antes de cualquier otra cosa.
			telemetry.TrackPacket(buf[:n], n)

			// --- B. PARSING VLAN (Optimizado) ---
			var vlanID uint16 = 0
			if n >= 18 {
				// Inline binary check
				etherType := binary.BigEndian.Uint16(buf[12:14])
				if etherType == 0x8100 {
					vlanID = binary.BigEndian.Uint16(buf[14:16]) & 0x0FFF
				}
			}

			// --- C. DISPATCH (Motor) ---
			engine.DispatchPacket(buf[:n], n, vlanID)

			// --- FIN CRONÓMETRO ---
			duration := time.Since(start).Nanoseconds()
			telemetry.ProcessingTime.Observe(float64(duration))
		}
	}()

	<-stopChan
	return nil
}
