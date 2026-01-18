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

const alertBufferSize = 100
const (
	GlobalAlertLimit = 20
	MuteDuration     = 60 * time.Second
)

type Notifier struct {
	cfg        *config.AlertsConfig
	sensorName string // <--- NUEVO
	alertChan  chan string
	client     *http.Client

	mu            sync.Mutex
	alertCount    int
	windowStart   time.Time
	isMuted       bool
	mutedUntil    time.Time
	droppedAlerts int
}

// NewNotifier acepta ahora 'sensorName' como argumento
func NewNotifier(cfg *config.AlertsConfig, sensorName string) *Notifier {
	n := &Notifier{
		cfg:        cfg,
		sensorName: sensorName,
		alertChan:  make(chan string, alertBufferSize),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		windowStart: time.Now(),
	}
	go n.worker()
	return n
}

func (n *Notifier) Alert(msg string) {
	// Precepto #8: String Concatenation.
	// Formateamos el mensaje con la etiqueta del sensor al principio.
	// Ej: "[Switch-Planta-1] 🚨 LOOP DETECTED"
	taggedMsg := fmt.Sprintf("[%s] %s", n.sensorName, msg)

	n.mu.Lock()
	now := time.Now()

	if n.isMuted {
		if now.Before(n.mutedUntil) {
			n.droppedAlerts++
			n.mu.Unlock()
			return
		}
		n.isMuted = false
		summary := fmt.Sprintf("⚠️ [System] Resuming alerts. Dropped %d messages.", n.droppedAlerts)
		n.droppedAlerts = 0
		n.windowStart = now
		n.alertCount = 0
		n.mu.Unlock()

		// Enviamos el resumen también etiquetado (recursión segura porque despachamos directo a internal)
		n.dispatch(fmt.Sprintf("[%s] %s", n.sensorName, summary))
		n.dispatch(taggedMsg)
		return
	}

	if now.Sub(n.windowStart) > time.Minute {
		n.windowStart = now
		n.alertCount = 0
	}

	n.alertCount++

	if n.alertCount > GlobalAlertLimit {
		n.isMuted = true
		n.mutedUntil = now.Add(MuteDuration)
		warning := fmt.Sprintf("[%s] ⛔ [System] FLOOD PROTECTION. Silencing for 60s...", n.sensorName)
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
	}
}

func (n *Notifier) worker() {
	for msg := range n.alertChan {
		
		// 1. Webhook (Ahora estructurado)
		if n.cfg.Webhook.Enabled {
			n.sendWebhook(msg)
		}

		// 2. Syslog
		if n.cfg.SyslogServer != "" {
			n.sendSyslog(msg)
		}

		// 3. Email
		if n.cfg.Smtp.Enabled {
			n.sendEmail(msg)
		}

		// 4. Telegram
		if n.cfg.Telegram.Enabled {
			n.sendTelegram(msg)
		}
	}
}

func (n *Notifier) sendWebhook(msg string) {
	payload := map[string]string{"text": msg}
	jsonBody, _ := json.Marshal(payload)
	
	// Usamos n.cfg.Webhook.URL
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
