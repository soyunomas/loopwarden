package detector

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
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
	ifaceName  string
	store      *TopologyStore
	metaEngine *MetaEngine
}

func NewEngine(cfg *config.AlgorithmConfig, notify *notifier.Notifier, ifaceName string, store *TopologyStore) *Engine {
	e := &Engine{
		cfg:        cfg,
		ifaceName:  ifaceName,
		store:      store,
		algorithms: make([]Algorithm, 0),
	}

	// Meta-Engine (Correlación)
	// LO INICIALIZAMOS PRIMERO PARA PODER REGISTRARLO
	if cfg.MetaEngine.Enabled {
		window, _ := time.ParseDuration(cfg.MetaEngine.Window)
		cooldown, _ := time.ParseDuration(cfg.MetaEngine.Cooldown)
		e.metaEngine = NewMetaEngine(notify, ifaceName, store, window, cfg.MetaEngine.Threshold, cooldown)
		
		// --- FIX CRÍTICO: CONEXIÓN DE CABLES ---
		// Registramos el MetaEngine como suscriptor del Notifier.
		// Ahora, cada vez que ActiveProbe o MacStorm manden una alerta, 
		// el Notifier la pasará también a e.metaEngine.IngestAlert
		notify.Subscribe(e.metaEngine.IngestAlert)
		log.Printf("🧠 [Engine:%s] MetaEngine wired to Notifier stream", ifaceName)
	}

	// 0. Neighbor Discovery (Passive, Always On preferrably)
	if cfg.NeighborDiscovery.Enabled {
		e.algorithms = append(e.algorithms, NewNeighborDiscovery(store, ifaceName, notify))
	} else {
		log.Printf("ℹ️  [Engine:%s] Neighbor Discovery DISABLED", ifaceName)
	}

	// 1. EtherFuse
	if cfg.EtherFuse.Enabled {
		e.algorithms = append(e.algorithms, NewEtherFuse(&cfg.EtherFuse, notify, ifaceName, store))
	}

	// 2. ActiveProbe
	if cfg.ActiveProbe.Enabled {
		e.algorithms = append(e.algorithms, NewActiveProbe(&cfg.ActiveProbe, notify, ifaceName, store))
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

	// 10. BcastRatio
	if cfg.BcastRatio.Enabled {
		e.algorithms = append(e.algorithms, NewBcastRatio(&cfg.BcastRatio, notify, ifaceName, store))
	}

	// 11. VlanLeak (NUEVO FASE 2)
	if cfg.VlanLeak.Enabled {
		e.algorithms = append(e.algorithms, NewVlanLeak(&cfg.VlanLeak, notify, ifaceName, store))
		log.Printf("✅ [Engine:%s] VlanLeak detector loaded", ifaceName)
	}

	log.Printf("✅ [Engine:%s] Initialized with %d algorithms", ifaceName, len(e.algorithms))

	// Pre-inicializar engine_errors_total a 0 para que siempre aparezca en Prometheus
	for _, algo := range e.algorithms {
		telemetry.EngineErrors.WithLabelValues(ifaceName, algo.Name())
	}

	return e
}

// StartAll inicia todos los algoritmos registrados.
func (e *Engine) StartAll(conn *packet.Conn, iface *net.Interface) {
	for _, algo := range e.algorithms {
		if err := algo.Start(conn, iface); err != nil {
			log.Printf("❌ [%s] Error starting algorithm %s: %v", e.ifaceName, algo.Name(), err)
		}
	}
}

// RecordHit registra un evento directamente (usado por Legacy/Internal calls)
func (e *Engine) RecordHit(engineName string, threatType string) {
	if e.metaEngine != nil {
		e.metaEngine.RecordHit(engineName, threatType)
	}
}

// DispatchPacket reparte el paquete a todos los algoritmos activos.
func (e *Engine) DispatchPacket(data []byte, length int, vlanID uint16) {
	e.mu.RLock()
	for _, algo := range e.algorithms {
		e.safeOnPacket(algo, data, length, vlanID)
	}
	e.mu.RUnlock()
}

// safeOnPacket ejecuta OnPacket con recover para capturar panics por engine.
func (e *Engine) safeOnPacket(algo Algorithm, data []byte, length int, vlanID uint16) {
	defer func() {
		if r := recover(); r != nil {
			telemetry.EngineErrors.WithLabelValues(e.ifaceName, algo.Name()).Inc()
			log.Printf("❌ [%s] PANIC in engine %s: %v", e.ifaceName, algo.Name(), r)
		}
	}()
	algo.OnPacket(data, length, vlanID)
}
