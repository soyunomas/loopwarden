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

// RecordHit registra que un motor disparó una alerta
func (me *MetaEngine) RecordHit(engineName string, threatType string) {
	me.mu.Lock()
	defer me.mu.Unlock()

	now := time.Now()
	key := fmt.Sprintf("%s:%s", engineName, threatType)
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
	uniqueEngines := make(map[string]bool)
	var signals []string

	for key := range me.recentHits {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 2 {
			engineName := parts[0]
			if !uniqueEngines[engineName] {
				uniqueEngines[engineName] = true
				signals = append(signals, key)
			}
		}
	}

	if len(uniqueEngines) >= me.threshold {
		me.lastCorAlert = now

		// Construir mensaje de alerta
		topologyInfo := "Unknown (No LLDP/CDP detected)"
		if neighbor, found := me.store.Get(me.ifaceName); found {
			topologyInfo = neighbor.String()
		}

		alertMsg := fmt.Sprintf("[MetaEngine] 🚨 CONFIRMED LOOP - MULTI-SIGNAL DETECTION!\n"+
			"    INTERFACE:   %s\n"+
			"    SIGNALS:     %s\n"+
			"    WINDOW:      %v\n"+
			"    CONFIDENCE:  HIGH\n"+
			"    CONNECTED:   %s",
			me.ifaceName,
			strings.Join(signals, ", "),
			me.window,
			topologyInfo)

		telemetry.EngineHits.WithLabelValues(me.ifaceName, "MetaEngine", "CorrelatedLoop").Inc()

		log.Printf("%s", alertMsg)
		go me.notify.Alert(alertMsg)
	}
}
