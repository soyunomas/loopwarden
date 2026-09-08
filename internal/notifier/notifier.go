package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

const alertBufferSize = 100

// ObserverFunc define la firma para los "espías" de alertas (e.g. MetaEngine)
type ObserverFunc func(msg string)

type Notifier struct {
	cfg        *config.AlertsConfig
	sensorName string
	alertChan  chan string
	client     *http.Client
	segments   []config.NetworkSegment

	// --- Configuración Efectiva (Dampening) ---
	maxAlertsPerMin int
	muteDuration    time.Duration

	mu            sync.Mutex
	alertCount    int
	windowStart   time.Time
	isMuted       bool
	mutedUntil    time.Time
	droppedAlerts int

	// --- NUEVO: Observers (Event Bus) ---
	observers   []ObserverFunc
	observersMu sync.RWMutex
}

func NewNotifier(cfg *config.AlertsConfig, sensorName string) *Notifier {
	return NewNotifierWithNetwork(cfg, sensorName, nil)
}

// NewNotifierWithNetwork habilita enriquecimiento de alertas con nombre de red y CIDR.
// Mantiene NewNotifier para compatibilidad con tests y consumidores existentes.
func NewNotifierWithNetwork(cfg *config.AlertsConfig, sensorName string, network *config.NetworkConfig) *Notifier {
	n := &Notifier{
		cfg:        cfg,
		sensorName: sensorName,
		alertChan:  make(chan string, alertBufferSize),
		client: &http.Client{
			Timeout: 10 * time.Second, // AUMENTADO: De 5s a 10s para evitar timeouts en Telegram
		},
		windowStart: time.Now(),
		observers:   make([]ObserverFunc, 0),
	}

	if network != nil {
		n.segments = append([]config.NetworkSegment(nil), network.Segments...)
	}

	// 1. Cargar Configuración de Dampening
	n.maxAlertsPerMin = cfg.Dampening.MaxAlertsPerMinute

	dur, err := time.ParseDuration(cfg.Dampening.MuteDuration)
	if err != nil {
		log.Printf("⚠️ [Notifier] Invalid MuteDuration '%s', defaulting to 60s", cfg.Dampening.MuteDuration)
		n.muteDuration = 60 * time.Second
	} else {
		n.muteDuration = dur
	}

	// 2. Fallbacks de Seguridad
	if n.maxAlertsPerMin <= 0 {
		n.maxAlertsPerMin = 20
	}
	if n.muteDuration <= 0 {
		n.muteDuration = 60 * time.Second
	}

	log.Printf("🔔 [Notifier] Initialized. Dampening: Max %d alerts/min, Silence for %v", n.maxAlertsPerMin, n.muteDuration)

	go n.worker()
	return n
}

// Subscribe permite a componentes externos (MetaEngine) escuchar alertas
func (n *Notifier) Subscribe(fn ObserverFunc) {
	n.observersMu.Lock()
	defer n.observersMu.Unlock()
	n.observers = append(n.observers, fn)
}

func (n *Notifier) Alert(msg string) {
	msg = n.enrichNetworkContext(msg)

	// --- NUEVO: Notificar a los observers ANTES del rate-limit ---
	// Queremos que el MetaEngine se entere incluso si silenciamos el output externo.
	n.observersMu.RLock()
	for _, fn := range n.observers {
		// Lanzamos en goroutine para no bloquear el flujo de detección
		go fn(msg)
	}
	n.observersMu.RUnlock()

	// Precepto #8: String Concatenation.
	taggedMsg := fmt.Sprintf("[%s] %s", n.sensorName, msg)

	n.mu.Lock()
	now := time.Now()

	if n.isMuted {
		if now.Before(n.mutedUntil) {
			n.droppedAlerts++
			n.mu.Unlock()
			return
		}
		// Fin del silencio
		n.isMuted = false
		summary := fmt.Sprintf("⚠️ [System] Resuming alerts. Dropped %d messages.", n.droppedAlerts)
		n.droppedAlerts = 0
		n.windowStart = now
		n.alertCount = 0
		n.mu.Unlock()

		n.dispatch(fmt.Sprintf("[%s] %s", n.sensorName, summary))
		n.dispatch(taggedMsg)
		return
	}

	// Reset de ventana deslizante simple
	if now.Sub(n.windowStart) > time.Minute {
		n.windowStart = now
		n.alertCount = 0
	}

	n.alertCount++

	if n.alertCount > n.maxAlertsPerMin {
		n.isMuted = true
		n.mutedUntil = now.Add(n.muteDuration)
		
		warning := fmt.Sprintf("[%s] ⛔ [System] FLOOD PROTECTION. Silencing for %v...", n.sensorName, n.muteDuration)
		n.mu.Unlock()
		n.dispatch(warning)
		return
	}
	n.mu.Unlock()

	n.dispatch(taggedMsg)
}

func (n *Notifier) dispatch(msg string) {
	log.Println(msg)
	select {
	case n.alertChan <- msg:
	default:
		telemetry.NotifierDropped.Inc()
	}
	telemetry.NotifierBacklog.Set(float64(len(n.alertChan)))
}

func (n *Notifier) worker() {
	for msg := range n.alertChan {
		// Paralelizamos envíos para evitar que un Telegram lento bloquee al resto
		var wg sync.WaitGroup

		if n.cfg.Webhook.Enabled {
			wg.Add(1)
			go func(m string) { defer wg.Done(); n.sendWebhook(m) }(msg)
		}
		if n.cfg.SyslogServer != "" {
			wg.Add(1)
			go func(m string) { defer wg.Done(); n.sendSyslog(m) }(msg)
		}
		if n.cfg.Smtp.Enabled {
			wg.Add(1)
			go func(m string) { defer wg.Done(); n.sendEmail(m) }(msg)
		}
		if n.cfg.Telegram.Enabled {
			wg.Add(1)
			go func(m string) { defer wg.Done(); n.sendTelegram(m) }(msg)
		}
		wg.Wait()
	}
}

func (n *Notifier) sendWebhook(msg string) {
	payload := map[string]string{"text": msg}
	jsonBody, _ := json.Marshal(payload)
	resp, err := n.client.Post(n.cfg.Webhook.URL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("⚠️ [Notifier] Webhook failed: %v", err)
		return
	}
	resp.Body.Close()
}

func (n *Notifier) sendTelegram(msg string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.Telegram.Token)
	payload := map[string]string{
		"chat_id": n.cfg.Telegram.ChatID,
		"text":    msg,
	}
	jsonBody, _ := json.Marshal(payload)
	resp, err := n.client.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("⚠️ [Notifier] Telegram failed: %v", err)
		return
	}
	resp.Body.Close()
}

func (n *Notifier) sendSyslog(msg string) {
	conn, err := net.DialTimeout("udp", n.cfg.SyslogServer, 2*time.Second)
	if err != nil {
		log.Printf("⚠️ [Notifier] Syslog failed: %v", err)
		return
	}
	defer conn.Close()
	timestamp := time.Now().Format(time.RFC3339)
	fmt.Fprintf(conn, "<132>%s LoopWarden: %s", timestamp, msg)
}

func (n *Notifier) sendEmail(msg string) {
	auth := smtp.PlainAuth("", n.cfg.Smtp.User, n.cfg.Smtp.Pass, n.cfg.Smtp.Host)
	addr := fmt.Sprintf("%s:%d", n.cfg.Smtp.Host, n.cfg.Smtp.Port)
	subject := "Subject: [LoopWarden] Network Alert\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"
	body := []byte(subject + mime + msg)

	err := smtp.SendMail(addr, auth, n.cfg.Smtp.From, []string{n.cfg.Smtp.To}, body)
	if err != nil {
		log.Printf("⚠️ [Notifier] SMTP failed: %v", err)
	}
}


// enrichNetworkContext añade NETWORK/SUBNET cuando una alerta puede atribuirse
// de forma inequívoca a un segmento configurado.
func (n *Notifier) enrichNetworkContext(msg string) string {
	if len(n.segments) == 0 || strings.Contains(msg, "
    NETWORK:") {
		return msg
	}

	iface, ok := alertField(msg, "INTERFACE:")
	if !ok {
		return msg
	}
	iface = firstToken(iface)
	if iface == "" {
		return msg
	}

	vlan, hasVLAN := alertVLAN(msg)
	segment, found := n.resolveSegment(iface, vlan, hasVLAN)
	if !found {
		return msg
	}

	context := fmt.Sprintf("
    NETWORK:    %s
    SUBNET:     %s", segment.Name, segment.CIDR)
	if segment.VLAN != 0 {
		context += fmt.Sprintf("
    SEGMENT VLAN: %d", segment.VLAN)
	}

	// Insertar justo después de INTERFACE para mantener la localización visible arriba.
	lines := strings.Split(msg, "
")
	for i, line := range lines {
		if strings.Contains(line, "INTERFACE:") {
			insert := []string{
				fmt.Sprintf("    NETWORK:    %s", segment.Name),
				fmt.Sprintf("    SUBNET:     %s", segment.CIDR),
			}
			if segment.VLAN != 0 && !hasVLAN {
				insert = append(insert, fmt.Sprintf("    SEGMENT VLAN: %d", segment.VLAN))
			}
			lines = append(lines[:i+1], append(insert, lines[i+1:]...)...)
			return strings.Join(lines, "
")
		}
	}
	return msg + context
}

func (n *Notifier) resolveSegment(iface string, vlan uint16, hasVLAN bool) (config.NetworkSegment, bool) {
	var matches []config.NetworkSegment
	for _, segment := range n.segments {
		if segment.Interface != iface {
			continue
		}
		if hasVLAN && segment.VLAN != vlan {
			continue
		}
		matches = append(matches, segment)
	}

	if len(matches) == 1 {
		return matches[0], true
	}
	return config.NetworkSegment{}, false
}

func alertField(msg, marker string) (string, bool) {
	idx := strings.Index(msg, marker)
	if idx == -1 {
		return "", false
	}
	value := msg[idx+len(marker):]
	if end := strings.IndexAny(value, "
"); end >= 0 {
		value = value[:end]
	}
	return strings.TrimSpace(value), true
}

func firstToken(value string) string {
	if idx := strings.IndexAny(value, " 	("); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func alertVLAN(msg string) (uint16, bool) {
	value, ok := alertField(msg, "VLAN:")
	if !ok {
		return 0, false
	}
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "native") || strings.HasPrefix(strings.ToLower(value), "native ") {
		return 0, true
	}
	token := firstToken(value)
	parsed, err := strconv.ParseUint(token, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(parsed), true
}
