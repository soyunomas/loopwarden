// internal/detector/algo_flapguard.go

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

const (
	// Ventana de tiempo para considerar un cambio como "Flap"
	FlapWindowNano = int64(1 * time.Second) 
	
	// Cooldown de alertas
	FlapCooldownNano = int64(30 * time.Second)

	// Límite de seguridad de memoria
	MaxFlapEntries = 50000
)

// OPT: Struct optimizado para alineación de memoria (Word Alignment)
// Total size: 24 bytes. Fits nicely in cache lines.
type flapEntry struct {
	lastSeen   int64  // 8 bytes (UnixNano)
	lastAlert  int64  // 8 bytes (UnixNano)
	lastVLAN   uint16 // 2 bytes
	flapCount  uint16 // 2 bytes
	// Go añade 4 bytes de padding implícito aquí para llegar a 24.
}

type FlapGuard struct {
	cfg    *config.FlapGuardConfig
	notify *notifier.Notifier
	mu     sync.Mutex
	
	// Mapa principal
	registry map[[6]byte]flapEntry
}

func NewFlapGuard(cfg *config.FlapGuardConfig, n *notifier.Notifier) *FlapGuard {
	return &FlapGuard{
		cfg:      cfg,
		notify:   n,
		registry: make(map[[6]byte]flapEntry, 1000),
	}
}

func (fg *FlapGuard) Name() string { return "FlapGuard" }

func (fg *FlapGuard) Start(conn *packet.Conn, iface *net.Interface) error {
	// Worker de limpieza de memoria (Garbage Collection manual del mapa)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			fg.mu.Lock()
			now := time.Now().UnixNano()
			expiry := int64(60 * time.Second) // Olvidamos hosts inactivos por 1 min
			
			// Si el mapa está muy lleno, somos más agresivos
			if len(fg.registry) > MaxFlapEntries {
				expiry = int64(10 * time.Second)
			}

			for mac, entry := range fg.registry {
				if now - entry.lastSeen > expiry {
					delete(fg.registry, mac)
				}
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
	
	// Usamos tiempo monotónico/UnixNano para evitar allocs de time.Time
	now := time.Now().UnixNano()

	fg.mu.Lock()
	entry, exists := fg.registry[srcMac]

	if !exists {
		// Protección Anti-DoS: Si el mapa está lleno, solo permitimos actualizaciones de existentes
		if len(fg.registry) >= MaxFlapEntries {
			fg.mu.Unlock()
			return
		}
		
		fg.registry[srcMac] = flapEntry{
			lastVLAN: vlanID,
			lastSeen: now,
		}
		fg.mu.Unlock()
		return
	}

	// Lógica de Flapping
	if entry.lastVLAN != vlanID {
		// ¿El cambio ocurrió dentro de la ventana de peligro (1s)?
		if (now - entry.lastSeen) < FlapWindowNano {
			entry.flapCount++
		} else {
			// Si pasó mucho tiempo, reseteamos el contador, es un movimiento legítimo
			entry.flapCount = 1
		}

		entry.lastVLAN = vlanID
		entry.lastSeen = now

		// Chequeo de Alerta
		if entry.flapCount >= uint16(fg.cfg.Threshold) {
			if (now - entry.lastAlert) > FlapCooldownNano {
				entry.lastAlert = now
				
				// Actualizamos el mapa antes de soltar el lock
				fg.registry[srcMac] = entry
				fg.mu.Unlock()
				
				// Alertar fuera de sección crítica
				go fg.sendAlert(srcMac, entry.flapCount, vlanID)
				return
			}
		}
		
		// Guardar cambios
		fg.registry[srcMac] = entry
	} else {
		// Mismo VLAN, solo actualizamos lastSeen para que el GC no lo borre
		// Optimización: Solo actualizar si han pasado > 1s para evitar escrituras constantes
		// en hosts estables con mucho tráfico.
		if (now - entry.lastSeen) > int64(time.Second) {
			entry.lastSeen = now
			fg.registry[srcMac] = entry
		}
	}
	
	fg.mu.Unlock()
}

func (fg *FlapGuard) sendAlert(mac [6]byte, count uint16, vlanID uint16) {
	msg := fmt.Sprintf("[FlapGuard] 🦇 MAC FLAPPING DETECTED! MAC %x jumped VLANs %d times (Last: VLAN %d) - Silencing for 30s",
		mac, count, vlanID)
	
	fg.notify.Alert(msg)
}
