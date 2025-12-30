package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"sync"
	"time"

	"github.com/soyunomas/loopwarden/internal/config"
)

// Capacidad del buffer para evitar bloqueos si la red cae
const alertBufferSize = 100

// Configuración de seguridad anti-flood
const (
	GlobalAlertLimit = 20              // Máximo 20 alertas por minuto
	MuteDuration     = 60 * time.Second // Tiempo de silencio tras superar el límite
)

type Notifier struct {
	cfg       *config.AlertsConfig
	alertChan chan string
	client    *http.Client

	// Variables para Rate Limiting Global
	mu            sync.Mutex
	alertCount    int
	windowStart   time.Time
	isMuted       bool
	mutedUntil    time.Time
	droppedAlerts int
}

// NewNotifier arranca el sistema de alertas
func NewNotifier(cfg *config.AlertsConfig) *Notifier {
	n := &Notifier{
		cfg:       cfg,
		alertChan: make(chan string, alertBufferSize),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		windowStart: time.Now(),
	}

	// Arrancar el worker en background
	go n.worker()

	return n
}

// Alert gestiona el envío de alertas con protección Anti-Flood.
// Es Thread-Safe y Non-Blocking.
func (n *Notifier) Alert(msg string) {
	n.mu.Lock()
	now := time.Now()

	// 1. LÓGICA DE MUTE: ¿Estamos silenciados?
	if n.isMuted {
		if now.Before(n.mutedUntil) {
			n.droppedAlerts++
			n.mu.Unlock()
			return // ⛔ SILENCIO TOTAL
		}
		
		// El tiempo de silencio ha terminado. Resumimos.
		n.isMuted = false
		summary := fmt.Sprintf("⚠️  [System] Resuming alerts. Dropped %d messages during silence period.", n.droppedAlerts)
		
		// Reset de contadores
		n.droppedAlerts = 0
		n.windowStart = now
		n.alertCount = 0
		n.mu.Unlock()

		// Enviamos primero el resumen, luego el mensaje actual
		n.dispatch(summary)
		n.dispatch(msg)
		return
	}

	// 2. VENTANA DE TIEMPO: Resetear contador cada minuto
	if now.Sub(n.windowStart) > time.Minute {
		n.windowStart = now
		n.alertCount = 0
	}

	n.alertCount++

	// 3. LÓGICA DE TRIGGER: ¿Superamos el límite?
	if n.alertCount > GlobalAlertLimit {
		n.isMuted = true
		n.mutedUntil = now.Add(MuteDuration)
		
		warning := fmt.Sprintf("⛔ [System] GLOBAL FLOOD PROTECTION ACTIVATED. >%d alerts/min. Silencing notifications for 60s...", GlobalAlertLimit)
		n.mu.Unlock()
		
		n.dispatch(warning)
		return
	}

	n.mu.Unlock()

	// Si todo está bien, despachamos el mensaje
	n.dispatch(msg)
}

// dispatch encola el mensaje en el canal interno
func (n *Notifier) dispatch(msg string) {
	// Siempre logueamos a stdout/journald para registro forense local
	log.Println(msg)

	// Intentar encolar para notificaciones externas
	select {
	case n.alertChan <- msg:
		// Encolado con éxito
	default:
		// Buffer lleno. Descartamos silenciosamente para no bloquear
		// la detección de paquetes (Mandato 8).
	}
}

// worker consume las alertas una a una
func (n *Notifier) worker() {
	for msg := range n.alertChan {
		
		// 1. Webhook (Slack/Teams)
		if n.cfg.WebhookURL != "" {
			n.sendWebhook(msg)
		}

		// 2. Syslog
		if n.cfg.SyslogServer != "" {
			n.sendSyslog(msg)
		}

		// 3. Email
		if n.cfg.SmtpEnabled {
			n.sendEmail(msg)
		}
	}
}

func (n *Notifier) sendWebhook(msg string) {
	// OPT(5): Payload simple
	payload := map[string]string{"text": msg}
	jsonBody, _ := json.Marshal(payload)

	resp, err := n.client.Post(n.cfg.WebhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("⚠️  [Notifier] Webhook failed: %v", err)
		return
	}
	// OPT(11): Cerrar siempre el body
	resp.Body.Close()
}

func (n *Notifier) sendSyslog(msg string) {
	conn, err := net.DialTimeout("udp", n.cfg.SyslogServer, 2*time.Second)
	if err != nil {
		log.Printf("⚠️  [Notifier] Syslog connect failed: %v", err)
		return
	}
	defer conn.Close()

	timestamp := time.Now().Format(time.RFC3339)
	fmt.Fprintf(conn, "<132>%s LoopWarden: %s", timestamp, msg)
}

func (n *Notifier) sendEmail(msg string) {
	auth := smtp.PlainAuth("", n.cfg.SmtpUser, n.cfg.SmtpPass, n.cfg.SmtpHost)
	addr := fmt.Sprintf("%s:%d", n.cfg.SmtpHost, n.cfg.SmtpPort)

	subject := "Subject: [LoopWarden] Network Alert\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"
	body := []byte(subject + mime + msg)

	err := smtp.SendMail(addr, auth, n.cfg.SmtpFrom, []string{n.cfg.SmtpTo}, body)
	if err != nil {
		log.Printf("⚠️  [Notifier] SMTP failed: %v", err)
	}
}
