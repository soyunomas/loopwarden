package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"time"

	"github.com/soyunomas/loopwarden/internal/config"
)

// Capacidad del buffer. Si se acumulan más de 100 alertas sin enviar,
// se descartan las nuevas para no consumir memoria infinita.
const alertBufferSize = 100

type Notifier struct {
	cfg       *config.AlertsConfig
	alertChan chan string
	client    *http.Client
}

// NewNotifier arranca el sistema de alertas
func NewNotifier(cfg *config.AlertsConfig) *Notifier {
	n := &Notifier{
		cfg:       cfg,
		alertChan: make(chan string, alertBufferSize),
		client: &http.Client{
			// Timeout corto. Si Slack no responde en 5s, asumimos fallo (red saturada).
			Timeout: 5 * time.Second,
		},
	}

	// Arrancar el worker en background
	go n.worker()

	return n
}

// Alert encola un mensaje. Es NO BLOQUEANTE.
func (n *Notifier) Alert(msg string) {
	// Siempre a consola
	log.Println(msg)

	// Intentar encolar para notificaciones externas
	select {
	case n.alertChan <- msg:
		// Encolado con éxito
	default:
		// Buffer lleno (posiblemente red caída o demasiadas alertas).
		// Descartamos silenciosamente para proteger la app.
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
	// JSON genérico para Slack/Discord
	payload := map[string]string{"text": msg}
	jsonBody, _ := json.Marshal(payload)

	// Usamos un buffer de bytes para no crear strings gigantes
	resp, err := n.client.Post(n.cfg.WebhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("⚠️  [Notifier] Webhook failed: %v", err)
		return
	}
	// Es importante cerrar el Body siempre para evitar leaks de descriptores
	resp.Body.Close()
}

func (n *Notifier) sendSyslog(msg string) {
	// Dial al servidor Syslog
	conn, err := net.DialTimeout("udp", n.cfg.SyslogServer, 2*time.Second)
	if err != nil {
		// Probamos TCP si falla UDP (opcional, aquí simple)
		log.Printf("⚠️  [Notifier] Syslog connect failed: %v", err)
		return
	}
	defer conn.Close()

	// Formato RFC3164 simplificado: <PRI>TIMESTAMP HOST TAG: MSG
	// PRI 132 = Local0 (16*8) + Warning (4)
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
