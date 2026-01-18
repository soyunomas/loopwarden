package detector

import (
	"log"
	"net"
	"sync"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
)

type Algorithm interface {
	Name() string
	Start(conn *packet.Conn, iface *net.Interface) error
	OnPacket(data []byte, length int, vlanID uint16)
}

type Engine struct {
	algorithms []Algorithm
	cfg        *config.AlgorithmConfig
	mu         sync.RWMutex
	ifaceName  string // Identidad del Engine
}

// NewEngine propaga ifaceName a todos los constructores
func NewEngine(cfg *config.AlgorithmConfig, notify *notifier.Notifier, ifaceName string) *Engine {
	e := &Engine{
		cfg:        cfg,
		ifaceName:  ifaceName,
		algorithms: make([]Algorithm, 0),
	}

	// 1. EtherFuse
	if cfg.EtherFuse.Enabled {
		e.algorithms = append(e.algorithms, NewEtherFuse(&cfg.EtherFuse, notify, ifaceName))
	}

	// 2. ActiveProbe
	if cfg.ActiveProbe.Enabled {
		e.algorithms = append(e.algorithms, NewActiveProbe(&cfg.ActiveProbe, notify, ifaceName))
	}

	// 3. MacStorm
	if cfg.MacStorm.Enabled {
		e.algorithms = append(e.algorithms, NewMacStorm(&cfg.MacStorm, notify, ifaceName))
	}

	// 4. FlapGuard
	if cfg.FlapGuard.Enabled {
		e.algorithms = append(e.algorithms, NewFlapGuard(&cfg.FlapGuard, notify, ifaceName))
	}

	// 5. ArpWatchdog
	if cfg.ArpWatch.Enabled {
		e.algorithms = append(e.algorithms, NewArpWatchdog(&cfg.ArpWatch, notify, ifaceName))
	}

	// 6. DhcpHunter
	if cfg.DhcpHunter.Enabled {
		e.algorithms = append(e.algorithms, NewDhcpHunter(&cfg.DhcpHunter, notify, ifaceName))
	}

	// 7. FlowPanic
	if cfg.FlowPanic.Enabled {
		e.algorithms = append(e.algorithms, NewFlowPanic(&cfg.FlowPanic, notify, ifaceName))
	}

	// 8. RaGuard
	if cfg.RaGuard.Enabled {
		e.algorithms = append(e.algorithms, NewRaGuard(&cfg.RaGuard, notify, ifaceName))
	}

	// 9. McastPolicer
	if cfg.McastPolicer.Enabled {
		e.algorithms = append(e.algorithms, NewMcastPolicer(&cfg.McastPolicer, notify, ifaceName))
	}

	log.Printf("✅ [Engine:%s] Initialized with %d algorithms", ifaceName, len(e.algorithms))
	return e
}

func (e *Engine) StartAll(conn *packet.Conn, iface *net.Interface) {
	for _, algo := range e.algorithms {
		if err := algo.Start(conn, iface); err != nil {
			log.Printf("❌ [%s] Error starting algorithm %s: %v", e.ifaceName, algo.Name(), err)
		}
	}
}

func (e *Engine) DispatchPacket(data []byte, length int, vlanID uint16) {
	e.mu.RLock()
	// Precepto #41: Mid-stack inlining optimization
	for _, algo := range e.algorithms {
		algo.OnPacket(data, length, vlanID)
	}
	e.mu.RUnlock()
}
