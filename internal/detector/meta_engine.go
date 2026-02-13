package detector

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

type MetaEngine struct {
	mu           sync.Mutex
	recentHits   map[string][]time.Time // engine_name -> timestamps
	window       time.Duration
	threshold    int
	notify       *notifier.Notifier
	ifaceName    string
	store        *TopologyStore
	lastCorAlert time.Time
	cooldown     time.Duration
}

func NewMetaEngine(notify *notifier.Notifier, ifaceName string, store *TopologyStore, window time.Duration, threshold int, cooldown time.Duration) *MetaEngine {
	if window == 0 {
		window = 2 * time.Second
	}
	if threshold == 0 {
		threshold = 2
	}
	if cooldown == 0 {
		cooldown = 30 * time.Second
	}
	return &MetaEngine{
		recentHits: make(map[string][]time.Time),
		window:     window,
		threshold:  threshold,
		notify:     notify,
		ifaceName:  ifaceName,
		store:      store,
		cooldown:   cooldown,
	}
}

// IngestAlert es el puente entre el Notifier y el MetaEngine.
// Analiza el string de alerta para identificar al emisor.
func (me *MetaEngine) IngestAlert(msg string) {
	// Formato esperado de los algoritmos: "[EngineName] Mensaje..."
	// Parseo rápido y sucio (pero efectivo en el Cold Path)
	
	msg = strings.TrimSpace(msg)
	if !strings.HasPrefix(msg, "[") {
		return // Mensaje de sistema o mal formado
	}

	endIndex := strings.Index(msg, "]")
	if endIndex == -1 || endIndex < 2 {
		return
	}

	engineName := msg[1:endIndex]
	
	// Ignoramos alertas del propio MetaEngine para evitar bucles infinitos de feedback
	if engineName == "MetaEngine" || engineName == "System" {
		return
	}

	// Determinamos el tipo de amenaza (simplificado)
	threatType := "Anomaly"
	if strings.Contains(msg, "LOOP") {
		threatType = "Loop"
	} else if strings.Contains(msg, "STORM") || strings.Contains(msg, "FLOOD") {
		threatType = "Storm"
	} else if strings.Contains(msg, "ROGUE") {
		threatType = "Rogue"
	}

	me.RecordHit(engineName, threatType)
}

// RecordHit registra que un motor disparó una alerta
func (me *MetaEngine) RecordHit(engineName string, threatType string) {
	me.mu.Lock()
	defer me.mu.Unlock()

	now := time.Now()
	// Usamos solo el engineName como clave para la correlación cross-threat
	// (Ej: DhcpHunter + MacStorm = Caos generalizado)
	key := engineName 
	
	me.recentHits[key] = append(me.recentHits[key], now)

	// Limpiar hits antiguos
	me.pruneOldHits(now)

	// Evaluar correlación
	me.evaluateCorrelation(now)
}

func (me *MetaEngine) pruneOldHits(now time.Time) {
	cutoff := now.Add(-me.window)
	for key, times := range me.recentHits {
		var fresh []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) > 0 {
			me.recentHits[key] = fresh
		} else {
			delete(me.recentHits, key)
		}
	}
}

func (me *MetaEngine) evaluateCorrelation(now time.Time) {
	if now.Sub(me.lastCorAlert) < me.cooldown {
		return
	}

	// Contar engines únicos que dispararon en la ventana
	var firingEngines []string
	
	for engineName := range me.recentHits {
		firingEngines = append(firingEngines, engineName)
	}

	if len(firingEngines) >= me.threshold {
		me.lastCorAlert = now

		// Construir mensaje de alerta
		topologyInfo := "Unknown (No LLDP/CDP detected)"
		if neighbor, found := me.store.Get(me.ifaceName); found {
			topologyInfo = neighbor.String()
		}

		alertMsg := fmt.Sprintf("[MetaEngine] 🚨 CONFIRMED LOOP - MULTI-SIGNAL DETECTION!\n"+
			"    INTERFACE:   %s\n"+
			"    ENGINES:     %s\n"+
			"    WINDOW:      %v\n"+
			"    CONFIDENCE:  HIGH\n"+
			"    CONNECTED:   %s",
			me.ifaceName,
			strings.Join(firingEngines, " + "),
			me.window,
			topologyInfo)

		telemetry.EngineHits.WithLabelValues(me.ifaceName, "MetaEngine", "CorrelatedLoop").Inc()

		log.Printf("%s", alertMsg)
		// IMPORTANTE: Llamamos a notify directamente. El IngestAlert tiene un filtro
		// para ignorar "MetaEngine" y evitar bucles.
		go me.notify.Alert(alertMsg)
	}
}
