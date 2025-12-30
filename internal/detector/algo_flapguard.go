package detector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
)

// OPT(2): Definimos el cooldown como constante para evitar reasignaciones.
const (
	FlapGuardCycle    = 1 * time.Second
	FlapAlertCooldown = 30 * time.Second // 🔇 Silenciar alertas repetidas por 30s
)

type FlapGuard struct {
	cfg         *config.FlapGuardConfig
	notify      *notifier.Notifier
	mu          sync.Mutex
	macRegistry map[[6]byte]macEntry
}

type macEntry struct {
	lastVLAN  uint16
	lastSeen  time.Time
	flapCount int
	// OPT(14): Usamos time.Time para controlar el silencio por MAC
	lastAlert time.Time 
}

func NewFlapGuard(cfg *config.FlapGuardConfig, n *notifier.Notifier) *FlapGuard {
	return &FlapGuard{
		cfg:    cfg,
		notify: n,
		// OPT(4): Pre-asignar capacidad inicial
		macRegistry: make(map[[6]byte]macEntry, 1000),
	}
}

func (fg *FlapGuard) Name() string {
	return "FlapGuard"
}

func (fg *FlapGuard) Start(conn *packet.Conn, iface *net.Interface) error {
	// Limpieza periódica para evitar fugas de memoria en redes grandes
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fg.mu.Lock()
			// Si el mapa crece demasiado (ataque o red gigante), purgamos
			if len(fg.macRegistry) > 50000 {
				fg.macRegistry = make(map[[6]byte]macEntry, 1000)
			}
			fg.mu.Unlock()
		}
	}()
	return nil
}

func (fg *FlapGuard) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 12 {
		return
	}

	var srcMac [6]byte
	copy(srcMac[:], data[6:12])

	fg.mu.Lock()
	entry, exists := fg.macRegistry[srcMac]

	now := time.Now()

	if !exists {
		fg.macRegistry[srcMac] = macEntry{
			lastVLAN: vlanID,
			lastSeen: now,
		}
	} else {
		// Detectar cambio de VLAN
		if entry.lastVLAN != vlanID {
			// Solo contamos saltos rápidos (< 1 segundo)
			if now.Sub(entry.lastSeen) < FlapGuardCycle {
				entry.flapCount++
			} else {
				entry.flapCount = 1 // Reset si el salto fue hace mucho
			}

			entry.lastVLAN = vlanID
			entry.lastSeen = now

			// LÓGICA DE ALERTA + SILENCIO
			if entry.flapCount >= fg.cfg.Threshold {
				// Verificamos si ya alertamos recientemente sobre esta MAC
				if now.Sub(entry.lastAlert) > FlapAlertCooldown {
					
					msg := fmt.Sprintf("[FlapGuard] 🦇 MAC FLAPPING DETECTED! MAC %x jumped VLANs %d times (Last: VLAN %d) - Silencing for 30s", 
						srcMac, entry.flapCount, vlanID)
					
					fg.notify.Alert(msg)
					
					// Actualizamos la marca de tiempo de la última alerta
					entry.lastAlert = now
				}
			}
		}
		// Guardamos el struct actualizado (Go maps are value types)
		fg.macRegistry[srcMac] = entry
	}
	fg.mu.Unlock()
}
