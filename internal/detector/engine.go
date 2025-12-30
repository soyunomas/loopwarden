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

	// 1. EtherFuse (Payload Analysis)
	if cfg.EtherFuse.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: EtherFuse (Passive Payload Analysis)")
		e.algorithms = append(e.algorithms, NewEtherFuse(&cfg.EtherFuse, notify))
	}

	// 2. ActiveProbe (Injection)
	if cfg.ActiveProbe.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: ActiveProbe (Active Injection)")
		e.algorithms = append(e.algorithms, NewActiveProbe(&cfg.ActiveProbe, notify))
	}

	// 3. MacStorm (Velocity)
	if cfg.MacStorm.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: MacStorm (Passive MAC Velocity)")
		e.algorithms = append(e.algorithms, NewMacStorm(&cfg.MacStorm, notify))
	}

	// 4. FlapGuard (Topology Stability) - NUEVO
	if cfg.FlapGuard.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: FlapGuard (VLAN Hopping Detector)")
		e.algorithms = append(e.algorithms, NewFlapGuard(&cfg.FlapGuard, notify))
	}

	// 5. ArpWatchdog (Protocol Storm) - NUEVO
	if cfg.ArpWatch.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: ArpWatchdog (ARP Storm Detector)")
		e.algorithms = append(e.algorithms, NewArpWatchdog(&cfg.ArpWatch, notify))
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
	// OPT(7): RLock permite lecturas concurrentes si fuera necesario, 
	// aunque aquí protegemos la lista de algoritmos.
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	for _, algo := range e.algorithms {
		// Pasamos el paquete a cada algoritmo activo
		algo.OnPacket(data, length, vlanID)
	}
}
