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

// Run ahora recibe 'ctx context.Context' en lugar de channel
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

	// --- Monitor de Drops ---
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
						
						// UPDATED: Added ifaceName label
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

	// 6. Loop de Lectura
	buf := make([]byte, cfg.Network.SnapLen)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "closed") {
				return nil
			}
			log.Printf("⚠️ [%s] Read error: %v", ifaceName, err)
			continue
		}

		start := time.Now()

		// UPDATED: Pass ifaceName to TrackPacket
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
		// UPDATED: Added ifaceName label to Histogram
		telemetry.ProcessingTime.WithLabelValues(ifaceName).Observe(float64(duration))
	}
}
