// internal/detector/algo_mac_storm.go

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
	// Límite duro de MACs únicas a rastrear por segundo.
	// Evita OOM (Out Of Memory) si un atacante spoofea millones de MACs aleatorias.
	MaxTrackedMacs = 10000 
	
	// Silencio por MAC tras una alerta
	MacAlertCooldown = 30 * time.Second
)

type MacStorm struct {
	cfg    *config.MacStormConfig
	notify *notifier.Notifier
	
	mu sync.Mutex
	// Mapa actual de conteo (se reinicia cada tick)
	counters map[[6]byte]uint64
	// Mapa de estado de alertas (persiste entre ticks, con limpieza TTL)
	alertState map[[6]byte]time.Time
}

func NewMacStorm(cfg *config.MacStormConfig, n *notifier.Notifier) *MacStorm {
	return &MacStorm{
		cfg:    cfg,
		notify: n,
		// Pre-alloc para evitar resizes costosos al inicio del segundo
		counters:   make(map[[6]byte]uint64, 1000),
		alertState: make(map[[6]byte]time.Time),
	}
}

func (ms *MacStorm) Name() string { return "MacStorm" }

func (ms *MacStorm) Start(conn *packet.Conn, iface *net.Interface) error {
	go func() {
		// Ticker de 1 segundo para resetear contadores de velocidad
		rateTicker := time.NewTicker(1 * time.Second)
		// Ticker lento (1 min) para limpiar memoria de alertas viejas
		cleanupTicker := time.NewTicker(60 * time.Second)
		defer rateTicker.Stop()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-rateTicker.C:
				ms.mu.Lock()
				// FAST RESET: Simplemente reemplazamos el mapa.
				// El GC de Go recogerá el viejo 'counters' concurrentemente.
				// Pre-asignamos 1000 slots para evitar allocs en tráfico normal.
				ms.counters = make(map[[6]byte]uint64, 1000)
				ms.mu.Unlock()

			case <-cleanupTicker.C:
				ms.mu.Lock()
				now := time.Now()
				// Limpieza de estados de alerta viejos para evitar fugas de memoria a largo plazo
				for mac, lastAlert := range ms.alertState {
					if now.Sub(lastAlert) > MacAlertCooldown*2 {
						delete(ms.alertState, mac)
					}
				}
				ms.mu.Unlock()
			}
		}
	}()
	return nil
}

func (ms *MacStorm) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 14 {
		return
	}

	// OPT: Usar array [6]byte en vez de slice []byte.
	// Los arrays son valores en Go, se copian en stack, no generan basura en Heap.
	var srcMac [6]byte
	copy(srcMac[:], data[6:12])

	ms.mu.Lock()
	
	// 1. Incremento con protección de memoria
	count, exists := ms.counters[srcMac]
	if !exists {
		// SAFETY: Si ya estamos rastreando demasiadas MACs este segundo, 
		// ignoramos las nuevas para proteger la RAM (Fail-Open).
		if len(ms.counters) >= MaxTrackedMacs {
			ms.mu.Unlock()
			return
		}
	}
	
	newCount := count + 1
	ms.counters[srcMac] = newCount
	
	// 2. Verificación de Umbral
	if newCount > ms.cfg.MaxPPSPerMac {
		// Chequeo rápido de cooldown
		lastAlert, hasAlerted := ms.alertState[srcMac]
		// Usamos time.Since que es ligeramente más limpio
		if !hasAlerted || time.Since(lastAlert) > MacAlertCooldown {
			ms.alertState[srcMac] = time.Now()
			
			// DESACOPLAMIENTO: Soltamos el Lock ANTES de formatear strings o enviar alertas
			// Esto es crítico para no bloquear el procesamiento de paquetes.
			ms.mu.Unlock()
			
			go ms.sendAlert(srcMac, newCount, vlanID)
			return
		}
	}
	
	ms.mu.Unlock()
}

// sendAlert corre en su propia goroutine para manejar I/O y Strings
func (ms *MacStorm) sendAlert(mac [6]byte, count uint64, vlanID uint16) {
	location := "Native VLAN"
	if vlanID != 0 {
		location = fmt.Sprintf("VLAN %d", vlanID)
	}

	msg := fmt.Sprintf("[MacStorm] 🌪️ MAC VELOCITY ALERT on %s! MAC %x sent > %d pps (%d detected) - Silencing for 30s",
		location, mac, ms.cfg.MaxPPSPerMac, count)

	ms.notify.Alert(msg)
}
