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

	if cfg.EtherFuse.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: EtherFuse (Passive Payload Analysis)")
		e.algorithms = append(e.algorithms, NewEtherFuse(&cfg.EtherFuse, notify))
	}

	if cfg.ActiveProbe.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: ActiveProbe (Active Injection)")
		e.algorithms = append(e.algorithms, NewActiveProbe(&cfg.ActiveProbe, notify))
	}

	if cfg.MacStorm.Enabled {
		log.Println("✅ [Engine] Loaded Algorithm: MacStorm (Passive MAC Velocity)")
		e.algorithms = append(e.algorithms, NewMacStorm(&cfg.MacStorm, notify))
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
	
	for _, algo := range e.algorithms {
		algo.OnPacket(data, length, vlanID)
	}
}
