package sniffer

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/detector"
)

// Run inicia la captura de paquetes a nivel de socket RAW.
// Esta función bloquea hasta que recibe la señal de parada, pero el procesamiento
// ocurre en una goroutine separada.
func Run(cfg *config.Config, engine *detector.Engine, stopChan chan os.Signal) error {
	// 1. Obtener interfaz física
	ifi, err := net.InterfaceByName(cfg.Network.Interface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", cfg.Network.Interface, err)
	}

	// 2. Abrir Socket Raw (AF_PACKET)
	// ETH_P_ALL (htons(3)) para capturar todo, pero filtraremos con BPF.
	conn, err := packet.Listen(ifi, packet.Raw, 3, nil)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}
	defer conn.Close()

	// 3. Iniciar Algoritmos
	engine.StartAll(conn, ifi)

	// 4. Promiscuous Mode
	// Necesario para ver tráfico que no es para nuestra MAC (ej: bucles de otros)
	if err := conn.SetPromiscuous(true); err != nil {
		log.Printf("Warning: Failed to set promiscuous mode on %s: %v", cfg.Network.Interface, err)
	}

	// 5. BPF Filter (Berkeley Packet Filter) - OPTIMIZACIÓN KERNEL SIDE
	// Este filtro se ejecuta en el Kernel. Solo deja pasar al user-space (nuestra app)
	// los paquetes que sean Broadcast o Multicast.
	// Esto reduce drásticamente el Context Switching y la carga de CPU.
	// Logic: "Load byte 0 (Dst Addr[0]) AND 1". If result != 0, it's Multicast/Broadcast.
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},           
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 1}, 
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1}, 
		bpf.RetConstant{Val: uint32(cfg.Network.SnapLen)}, // Keep packet
		bpf.RetConstant{Val: 0},                     // Drop packet
	})
	if err != nil {
		return fmt.Errorf("BPF assembly failed: %w", err)
	}

	if err := conn.SetBPF(filter); err != nil {
		return fmt.Errorf("failed to apply BPF filter: %w", err)
	}

	log.Printf("🛡️  Sniffer active on %s [BPF: Multicast/Broadcast Only]", cfg.Network.Interface)

	// 6. Loop de Lectura (Hot Path)
	go func() {
		// Alloc fuera del loop: Zero-Allocation durante la ejecución.
		buf := make([]byte, cfg.Network.SnapLen)
		
		for {
			// ReadFrom bloquea hasta que hay un paquete.
			// 'n' es el número de bytes leídos.
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				// Si el error es por cierre de conexión (al apagar), salimos limpio.
				if strings.Contains(err.Error(), "closed") {
					return
				}
				log.Printf("⚠️ Error reading packet: %v", err)
				continue
			}
			
			// --- VLAN PARSING (802.1Q) ---
			// OPTIMIZACIÓN: Parseo inline manual para evitar overhead de funciones.
			var vlanID uint16 = 0
			
			// Header Ethernet mínimo son 14 bytes.
			// Si tiene VLAN tag, son 18 bytes.
			if n >= 18 {
				// Bytes 12 y 13 en Ethernet frame estándar es el EtherType.
				// Si es 0x8100, es un Tag 802.1Q.
				etherType := binary.BigEndian.Uint16(buf[12:14])
				
				if etherType == 0x8100 { 
					// Bytes 14 y 15 son el TCI (Tag Control Information).
					// Mask 0x0FFF extrae los 12 bits del ID.
					vlanID = binary.BigEndian.Uint16(buf[14:16]) & 0x0FFF
				}
			}

			// Pasar copia segura al motor (Dispatch)
			// Engine se encarga de distribuir a los workers.
			engine.DispatchPacket(buf[:n], n, vlanID)
		}
	}()

	// Esperar señal de terminación (Ctrl+C)
	<-stopChan
	return nil
}
