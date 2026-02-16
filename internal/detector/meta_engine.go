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

	// Filtrar por interfaz: solo procesar alertas de nuestra propia interfaz.
	// Todos los engines emiten "INTERFACE:" seguido del nombre.
	// Sin este filtro, un Notifier global con N interfaces causa cross-contamination.
	if !me.belongsToInterface(msg) {
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

// belongsToInterface verifica que la alerta pertenece a nuestra interfaz.
// Parsea "INTERFACE:   <name>" del cuerpo del mensaje.
func (me *MetaEngine) belongsToInterface(msg string) bool {
	const marker = "INTERFACE:"
	idx := strings.Index(msg, marker)
	if idx == -1 {
		return false // Sin info de interfaz, descartamos
	}

	after := msg[idx+len(marker):]
	// Trim espacios hasta el nombre de interfaz
	after = strings.TrimLeft(after, " ")
	// Extraer primera palabra (nombre de interfaz) antes de newline o espacio
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

	// Contar engines únicos que dispararon en la ventana
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

	telemetry.EngineHits.WithLabelValues(me.ifaceName, "MetaEngine", metricType).Inc()

	log.Printf("%s", alertMsg)
	go me.notify.Alert(alertMsg)
}
