package detector

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/telemetry"
)

type VlanLeak struct {
	cfg       *config.VlanLeakConfig
	notify    *notifier.Notifier
	ifaceName string
	store     *TopologyStore

	mu         sync.Mutex
	macVlanMap map[[6]byte]map[uint16]time.Time // MAC -> VLAN -> lastSeen

	// Configuración efectiva
	prohibitedPairs map[uint16]map[uint16]bool // VLAN1 -> VLAN2 -> prohibited
	cooldown        time.Duration
	lastAlert       map[[6]byte]time.Time // Por MAC
}

func NewVlanLeak(cfg *config.VlanLeakConfig, notify *notifier.Notifier, ifaceName string, store *TopologyStore) *VlanLeak {
	vl := &VlanLeak{
		cfg:             cfg,
		notify:          notify,
		ifaceName:       ifaceName,
		store:           store,
		macVlanMap:      make(map[[6]byte]map[uint16]time.Time),
		prohibitedPairs: make(map[uint16]map[uint16]bool),
		lastAlert:       make(map[[6]byte]time.Time),
	}

	// Parsear pares prohibidos
	for _, pair := range cfg.ProhibitedPairs {
		if len(pair) == 2 {
			v1, v2 := uint16(pair[0]), uint16(pair[1])
			if vl.prohibitedPairs[v1] == nil {
				vl.prohibitedPairs[v1] = make(map[uint16]bool)
			}
			if vl.prohibitedPairs[v2] == nil {
				vl.prohibitedPairs[v2] = make(map[uint16]bool)
			}
			vl.prohibitedPairs[v1][v2] = true
			vl.prohibitedPairs[v2][v1] = true
		}
	}

	cooldown, _ := time.ParseDuration(cfg.AlertCooldown)
	if cooldown == 0 {
		cooldown = 60 * time.Second
	}
	vl.cooldown = cooldown

	return vl
}

func (vl *VlanLeak) Name() string {
	return "VlanLeak"
}

func (vl *VlanLeak) Start(conn *packet.Conn, iface *net.Interface) error {
	log.Printf("✅ [VlanLeak:%s] Active. Monitoring %d prohibited VLAN pairs", vl.ifaceName, len(vl.cfg.ProhibitedPairs))

	// Limpieza periódica de MACs viejas
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			vl.cleanup()
		}
	}()

	return nil
}

func (vl *VlanLeak) OnPacket(data []byte, length int, vlanID uint16) {
	if length < 14 || vlanID == 0 {
		return // Solo procesamos tráfico con VLAN tag
	}

	var srcMac [6]byte
	copy(srcMac[:], data[6:12])

	// Ignorar broadcast/multicast
	if srcMac[0]&0x01 != 0 {
		return
	}

	vl.mu.Lock()
	defer vl.mu.Unlock()

	now := time.Now()

	if vl.macVlanMap[srcMac] == nil {
		vl.macVlanMap[srcMac] = make(map[uint16]time.Time)
	}

	// Verificar si esta MAC fue vista en VLAN prohibida
	for previousVlan := range vl.macVlanMap[srcMac] {
		if vl.isProhibitedPair(previousVlan, vlanID) {
			// Verificar cooldown por MAC
			if lastTime, exists := vl.lastAlert[srcMac]; exists && now.Sub(lastTime) < vl.cooldown {
				continue
			}

			vl.lastAlert[srcMac] = now
			telemetry.EngineHits.WithLabelValues(vl.ifaceName, "VlanLeak", "VlanLeakage").Inc()

			topologyInfo := "Unknown (No LLDP/CDP detected)"
			if neighbor, found := vl.store.Get(vl.ifaceName); found {
				topologyInfo = neighbor.String()
			}

			alertMsg := fmt.Sprintf("[VlanLeak] ☣️ VLAN LEAKAGE DETECTED!\n"+
				"    INTERFACE:   %s\n"+
				"    SOURCE MAC:  %s\n"+
				"    VLAN PAIR:   %d <-> %d (PROHIBITED)\n"+
				"    CONNECTED:   %s\n"+
				"    RISK:        Traffic crossing isolated network segments\n"+
				"    ACTION:      Check trunk/access port configuration",
				vl.ifaceName,
				net.HardwareAddr(srcMac[:]).String(),
				previousVlan,
				vlanID,
				topologyInfo)

			go vl.notify.Alert(alertMsg)
			log.Printf("%s", alertMsg)
		}
	}

	// Actualizar tracking
	vl.macVlanMap[srcMac][vlanID] = now
}

func (vl *VlanLeak) isProhibitedPair(v1, v2 uint16) bool {
	if v1 == v2 {
		return false
	}
	if pairs, ok := vl.prohibitedPairs[v1]; ok {
		return pairs[v2]
	}
	return false
}

func (vl *VlanLeak) cleanup() {
	vl.mu.Lock()
	defer vl.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)

	for mac, vlans := range vl.macVlanMap {
		for vlan, lastSeen := range vlans {
			if lastSeen.Before(cutoff) {
				delete(vlans, vlan)
			}
		}
		if len(vlans) == 0 {
			delete(vl.macVlanMap, mac)
		}
	}

	// Limpiar alertas viejas
	for mac, t := range vl.lastAlert {
		if t.Before(cutoff) {
			delete(vl.lastAlert, mac)
		}
	}
}
