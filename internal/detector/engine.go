package detector

import (
	"log"
	"net"
	"sync"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
)

// Algorithm define la interfaz que deben cumplir todos los detectores
type Algorithm interface {
	Name() string
	Start(conn *packet.Conn, iface *net.Interface) error
	OnPacket(data []byte, length int, vlanID uint16)
}

// Engine es el orquestador
type Engine struct {
	algorithms []Algorithm
	cfg        *config.AlgorithmConfig
	mu         sync.RWMutex
}

// NewEngine recibe el Notifier para pasárselo a los algoritmos
func NewEngine(cfg *config.AlgorithmConfig, notify *notifier.Notifier) *Engine {
	e := &Engine{
		cfg:        cfg,
		algorithms: make([]Algorithm, 0),
	}

	// 1. EtherFuse (Passive Payload Analysis)
	if cfg.EtherFuse.Enabled {
		log.Println("✅ [Engine] Loaded: EtherFuse")
		e.algorithms = append(e.algorithms, NewEtherFuse(&cfg.EtherFuse, notify))
	}

	// 2. ActiveProbe (Injection)
	if cfg.ActiveProbe.Enabled {
		log.Println("✅ [Engine] Loaded: ActiveProbe")
		e.algorithms = append(e.algorithms, NewActiveProbe(&cfg.ActiveProbe, notify))
	}

	// 3. MacStorm (Velocity)
	if cfg.MacStorm.Enabled {
		log.Println("✅ [Engine] Loaded: MacStorm")
		e.algorithms = append(e.algorithms, NewMacStorm(&cfg.MacStorm, notify))
	}

	// 4. FlapGuard (Topology)
	if cfg.FlapGuard.Enabled {
		log.Println("✅ [Engine] Loaded: FlapGuard")
		e.algorithms = append(e.algorithms, NewFlapGuard(&cfg.FlapGuard, notify))
	}

	// 5. ArpWatchdog (ARP Storm)
	if cfg.ArpWatch.Enabled {
		log.Println("✅ [Engine] Loaded: ArpWatchdog")
		e.algorithms = append(e.algorithms, NewArpWatchdog(&cfg.ArpWatch, notify))
	}

	// --- NUEVOS MOTORES DE SEGURIDAD ---

	// 6. DhcpHunter (Rogue DHCP)
	if cfg.DhcpHunter.Enabled {
		log.Println("✅ [Engine] Loaded: DhcpHunter (Rogue DHCP Detection)")
		e.algorithms = append(e.algorithms, NewDhcpHunter(&cfg.DhcpHunter, notify))
	}

	// 7. FlowPanic (Pause Frame Flood)
	if cfg.FlowPanic.Enabled {
		log.Println("✅ [Engine] Loaded: FlowPanic (802.3x Pause Flood)")
		e.algorithms = append(e.algorithms, NewFlowPanic(&cfg.FlowPanic, notify))
	}

	// 8. RaGuard (IPv6 RA Security)
	if cfg.RaGuard.Enabled {
		log.Println("✅ [Engine] Loaded: RaGuard (IPv6 Rogue RA)")
		e.algorithms = append(e.algorithms, NewRaGuard(&cfg.RaGuard, notify))
	}

	// 9. McastPolicer (Multicast Storm)
	if cfg.McastPolicer.Enabled {
		log.Println("✅ [Engine] Loaded: McastPolicer (Multicast Rate Limiter)")
		e.algorithms = append(e.algorithms, NewMcastPolicer(&cfg.McastPolicer, notify))
	}

	return e
}

func (e *Engine) StartAll(conn *packet.Conn, iface *net.Interface) {
	for _, algo := range e.algorithms {
		if err := algo.Start(conn, iface); err != nil {
			log.Printf("❌ Error starting algorithm %s: %v", algo.Name(), err)
		}
	}
}

func (e *Engine) DispatchPacket(data []byte, length int, vlanID uint16) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Data-oriented: Iterate over contiguous memory (slice of interfaces)
	for _, algo := range e.algorithms {
		algo.OnPacket(data, length, vlanID)
	}
}
