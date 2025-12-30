package sniffer

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/detector"
)

func Run(cfg *config.Config, engine *detector.Engine, stopChan chan os.Signal) error {
	ifi, err := net.InterfaceByName(cfg.Network.Interface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", cfg.Network.Interface, err)
	}

	conn, err := packet.Listen(ifi, packet.Raw, 3, nil)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}
	defer conn.Close()

	engine.StartAll(conn, ifi)

	if err := conn.SetPromiscuous(true); err != nil {
		log.Printf("Warning: Failed to set promiscuous mode: %v", err)
	}

	// BPF: Aceptamos Multicast/Broadcast
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},           
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 1}, 
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1}, 
		bpf.RetConstant{Val: uint32(cfg.Network.SnapLen)}, 
		bpf.RetConstant{Val: 0},                     
	})
	if err != nil {
		return fmt.Errorf("BPF assembly failed: %w", err)
	}

	if err := conn.SetBPF(filter); err != nil {
		return fmt.Errorf("failed to apply BPF filter: %w", err)
	}

	log.Printf("Listening on %s [BPF: Multicast/Broadcast + 802.1Q Support]...", cfg.Network.Interface)

	buf := make([]byte, cfg.Network.SnapLen)

	go func() {
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			
			// --- VLAN PARSING (802.1Q) ---
			// Estructura normal: [Dst(6)][Src(6)][Type(2)]...
			// Estructura VLAN:   [Dst(6)][Src(6)][TPID(2)=0x8100][TCI(2)][Type(2)]...
			
			var vlanID uint16 = 0
			
			// Verificamos longitud mínima (14 header + 4 vlan = 18 bytes)
			if n >= 18 {
				// Byte 12 y 13 contienen el EtherType o TPID
				etherType := binary.BigEndian.Uint16(buf[12:14])
				
				if etherType == 0x8100 { // 0x8100 es el TPID para 802.1Q
					// Bytes 14 y 15 son el TCI (Tag Control Information)
					// Los primeros 3 bits son prioridad, el 4º es CFI, los últimos 12 son VLAN ID.
					// Máscara 0x0FFF (0000 1111 1111 1111) para sacar los 12 bits.
					vlanID = binary.BigEndian.Uint16(buf[14:16]) & 0x0FFF
				}
			}

			// Pasar al motor (incluyendo el vlanID detectado)
			engine.DispatchPacket(buf[:n], n, vlanID)
		}
	}()

	<-stopChan
	return nil
}
