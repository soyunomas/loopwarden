package detector

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

type BcastRatio struct {
	// Contadores atómicos PRIMERO para alineación en 32-bit (MIPS/ARM)
	bcastCount uint64
	totalCount uint64

	cfg       *config.BcastRatioConfig
	notify    *notifier.Notifier
	ifaceName string
	store     *TopologyStore

	// Configuración efectiva
	maxRatio      float64
	minSampleSize uint64
	cooldown      time.Duration

	mu        sync.Mutex
	lastAlert time.Time
}

func NewBcastRatio(cfg *config.BcastRatioConfig, notify *notifier.Notifier, ifaceName string, store *TopologyStore) *BcastRatio {
	maxRatio := cfg.MaxRatio
	if maxRatio == 0 {
		maxRatio = 0.7 // 70% por defecto
	}
	minSample := cfg.MinSampleSize
	if minSample == 0 {
		minSample = 100
	}
	cooldown, _ := time.ParseDuration(cfg.AlertCooldown)
	if cooldown == 0 {
		cooldown = 30 * time.Second
	}

	// Aplicar overrides
	if override, ok := cfg.Overrides[ifaceName]; ok {
		if override.MaxRatio > 0 {
			maxRatio = override.MaxRatio
		}
		if override.MinSampleSize > 0 {
			minSample = override.MinSampleSize
		}
	}

	return &BcastRatio{
		cfg:           cfg,
		notify:        notify,
		ifaceName:     ifaceName,
		store:         store,
		maxRatio:      maxRatio,
		minSampleSize: minSample,
		cooldown:      cooldown,
	}
}

func (br *BcastRatio) Name() string {
	return "BcastRatio"
}

func (br *BcastRatio) Start(conn *packet.Conn, iface *net.Interface) error {
	log.Printf("✅ [BcastRatio:%s] Active. MaxRatio=%.0f%%, MinSample=%d", br.ifaceName, br.maxRatio*100, br.minSampleSize)

	// Goroutine para evaluar cada segundo
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			br.evaluate()
		}
	}()

	return nil
}

func (br *BcastRatio) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 6 {
		return
	}

	atomic.AddUint64(&br.totalCount, 1)

	// Check broadcast: FF:FF:FF:FF:FF:FF
	if data[0]&data[1]&data[2]&data[3]&data[4]&data[5] == 0xFF {
		atomic.AddUint64(&br.bcastCount, 1)
	}
}

func (br *BcastRatio) evaluate() {
	bcast := atomic.SwapUint64(&br.bcastCount, 0)
	total := atomic.SwapUint64(&br.totalCount, 0)

	if total < br.minSampleSize {
		return
	}

	ratio := float64(bcast) / float64(total)

	if ratio > br.maxRatio {
		br.mu.Lock()
		if time.Since(br.lastAlert) < br.cooldown {
			br.mu.Unlock()
			return
		}
		br.lastAlert = time.Now()
		br.mu.Unlock()

		telemetry.EngineHits.WithLabelValues(br.ifaceName, "BcastRatio", "HighBroadcast").Inc()

		topologyInfo := "Unknown (No LLDP/CDP detected)"
		if neighbor, found := br.store.Get(br.ifaceName); found {
			topologyInfo = neighbor.String()
		}

		alertMsg := fmt.Sprintf("[BcastRatio] ⚠️ HIGH BROADCAST RATIO DETECTED!\n"+
			"    INTERFACE:   %s\n"+
			"    RATIO:       %.1f%% broadcast (threshold: %.1f%%)\n"+
			"    SAMPLE:      %d packets/sec\n"+
			"    CONNECTED:   %s\n"+
			"    IMPACT:      Possible loop forming or broadcast storm building",
			br.ifaceName,
			ratio*100,
			br.maxRatio*100,
			total,
			topologyInfo)

		log.Printf("%s", alertMsg)
		go br.notify.Alert(alertMsg)
	}
}
