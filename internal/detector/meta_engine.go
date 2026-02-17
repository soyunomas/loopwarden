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

// Combinaciones de engines que confirman un bucle real.
// Si TODOS los engines de algún grupo están presentes → CONFIRMED LOOP.
// Si no → se reporta como CORRELATED ANOMALY (sin gritar "LOOP").
var loopSignatures = [][]string{
	{"ActiveProbe", "EtherFuse"},
	{"ActiveProbe", "MacStorm"},
	{"ActiveProbe", "FlapGuard"},
	{"ActiveProbe", "BcastRatio"},
	{"ActiveProbe", "McastPolicer"},
	{"EtherFuse", "MacStorm"},
	{"EtherFuse", "FlapGuard"},
	{"EtherFuse", "BcastRatio"},
	{"EtherFuse", "McastPolicer"},
	{"ActiveProbe", "EtherFuse", "MacStorm"},
}

// correlatableEngines es el set de engines que participan en loopSignatures.
// Se construye una vez en init para no recalcular en hot path.
var correlatableEngines map[string]struct{}

func init() {
	correlatableEngines = make(map[string]struct{})
	for _, sig := range loopSignatures {
		for _, e := range sig {
			correlatableEngines[e] = struct{}{}
		}
	}
}

// heldAlert es una alerta retenida temporalmente mientras se espera correlación.
type heldAlert struct {
	msg       string
	engine    string
	timestamp time.Time
}

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

	// --- Absorb mode ---
	absorb    bool
	absorbLog bool
	held      []heldAlert    // Alertas retenidas pendientes de decisión
	heldTimer *time.Timer    // Timer para liberar retenidas si no hay correlación
	absorbed  bool           // true si ya se emitió CONFIRMED en esta ventana
}

func NewMetaEngine(notify *notifier.Notifier, ifaceName string, store *TopologyStore, window time.Duration, threshold int, cooldown time.Duration, absorb bool, absorbLog bool) *MetaEngine {
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
		absorb:     absorb,
		absorbLog:  absorbLog,
	}
}

// ShouldAbsorb implementa notifier.AlertGate.
// Retiene alertas de engines correlacionables mientras espera la ventana de correlación.
// Engines no correlacionables (DhcpHunter, RaGuard, etc.) pasan siempre directo.
func (me *MetaEngine) ShouldAbsorb(msg string) bool {
	if !me.absorb {
		return false
	}

	engineName := me.extractEngine(msg)
	if engineName == "" || engineName == "MetaEngine" || engineName == "System" {
		return false
	}

	if !me.belongsToInterface(msg) {
		return false
	}

	if _, ok := correlatableEngines[engineName]; !ok {
		return false
	}

	me.mu.Lock()
	defer me.mu.Unlock()

	if me.absorbLog {
		log.Printf("[ABSORBED:%s] %s", me.ifaceName, msg)
	}

	me.held = append(me.held, heldAlert{
		msg:       msg,
		engine:    engineName,
		timestamp: time.Now(),
	})

	// Si es la primera alerta retenida, iniciar timer de liberación
	if len(me.held) == 1 {
		me.absorbed = false
		me.heldTimer = time.AfterFunc(me.window+200*time.Millisecond, me.releaseHeld)
	}

	return true
}

// releaseHeld se ejecuta cuando expira el timer sin que se haya producido correlación.
// Libera las alertas retenidas al Notifier para que se envíen normalmente.
func (me *MetaEngine) releaseHeld() {
	me.mu.Lock()
	if me.absorbed {
		// Ya se emitió CONFIRMED → descartar las retenidas (son redundantes)
		me.held = me.held[:0]
		me.mu.Unlock()
		return
	}
	// No hubo correlación → liberar todas las retenidas
	toRelease := make([]string, len(me.held))
	for i, h := range me.held {
		toRelease[i] = h.msg
	}
	me.held = me.held[:0]
	me.mu.Unlock()

	for _, msg := range toRelease {
		me.notify.AlertBypass(msg)
	}
}

// extractEngine parsea el nombre del engine desde "[EngineName] ..."
func (me *MetaEngine) extractEngine(msg string) string {
	msg = strings.TrimSpace(msg)
	if !strings.HasPrefix(msg, "[") {
		return ""
	}
	endIndex := strings.Index(msg, "]")
	if endIndex < 2 {
		return ""
	}
	return msg[1:endIndex]
}

// IngestAlert es el puente entre el Notifier y el MetaEngine.
// Analiza el string de alerta para identificar al emisor.
func (me *MetaEngine) IngestAlert(msg string) {
	msg = strings.TrimSpace(msg)
	if !strings.HasPrefix(msg, "[") {
		return
	}

	endIndex := strings.Index(msg, "]")
	if endIndex == -1 || endIndex < 2 {
		return
	}

	engineName := msg[1:endIndex]

	if engineName == "MetaEngine" || engineName == "System" {
		return
	}

	if !me.belongsToInterface(msg) {
		return
	}

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

// belongsToInterface verifica que la alerta pertenece a nuestra interfaz.
func (me *MetaEngine) belongsToInterface(msg string) bool {
	const marker = "INTERFACE:"
	idx := strings.Index(msg, marker)
	if idx == -1 {
		return false
	}

	after := msg[idx+len(marker):]
	after = strings.TrimLeft(after, " ")
	end := strings.IndexAny(after, " \n\r\t(")
	if end > 0 {
		after = after[:end]
	}
	return after == me.ifaceName
}

// RecordHit registra que un motor disparó una alerta
func (me *MetaEngine) RecordHit(engineName string, threatType string) {
	me.mu.Lock()
	defer me.mu.Unlock()

	now := time.Now()
	key := engineName

	me.recentHits[key] = append(me.recentHits[key], now)

	me.pruneOldHits(now)

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

// matchesLoopSignature comprueba si los engines activos coinciden con alguna firma de bucle conocida.
func matchesLoopSignature(firingEngines []string) bool {
	active := make(map[string]struct{}, len(firingEngines))
	for _, e := range firingEngines {
		active[e] = struct{}{}
	}
	for _, sig := range loopSignatures {
		matched := true
		for _, required := range sig {
			if _, ok := active[required]; !ok {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func (me *MetaEngine) evaluateCorrelation(now time.Time) {
	if now.Sub(me.lastCorAlert) < me.cooldown {
		return
	}

	var firingEngines []string

	for engineName := range me.recentHits {
		firingEngines = append(firingEngines, engineName)
	}

	if len(firingEngines) < me.threshold {
		return
	}

	me.lastCorAlert = now

	topologyInfo := "Unknown (No LLDP/CDP detected)"
	if neighbor, found := me.store.Get(me.ifaceName); found {
		topologyInfo = neighbor.String()
	}

	isLoop := matchesLoopSignature(firingEngines)

	var alertMsg string
	var metricType string

	if isLoop {
		metricType = "CorrelatedLoop"
		alertMsg = fmt.Sprintf("[MetaEngine] 🚨 CONFIRMED LOOP - MULTI-SIGNAL DETECTION!\n"+
			"    INTERFACE:   %s\n"+
			"    ENGINES:     %s\n"+
			"    WINDOW:      %v\n"+
			"    CONFIDENCE:  HIGH\n"+
			"    CONNECTED:   %s",
			me.ifaceName,
			strings.Join(firingEngines, " + "),
			me.window,
			topologyInfo)
	} else {
		metricType = "CorrelatedAnomaly"
		alertMsg = fmt.Sprintf("[MetaEngine] ⚠️ CORRELATED ANOMALY (not a loop)\n"+
			"    INTERFACE:   %s\n"+
			"    ENGINES:     %s\n"+
			"    WINDOW:      %v\n"+
			"    CONFIDENCE:  LOW\n"+
			"    CONNECTED:   %s\n"+
			"    NOTE:        Likely legitimate traffic (scan, migration, etc.)",
			me.ifaceName,
			strings.Join(firingEngines, " + "),
			me.window,
			topologyInfo)
	}

	// Marcar como absorbido para que releaseHeld descarte las retenidas
	if me.absorb {
		me.absorbed = true
		if me.heldTimer != nil {
			me.heldTimer.Stop()
		}
		me.held = me.held[:0]
	}

	telemetry.EngineHits.WithLabelValues(me.ifaceName, "MetaEngine", metricType).Inc()

	log.Printf("%s", alertMsg)
	go me.notify.AlertBypass(alertMsg)
}
