package detector

import (
	"fmt"
	"sync"
	"time"
)

// NeighborInfo contiene la "Ficha Técnica" del switch vecino.
type NeighborInfo struct {
	SystemName    string
	SystemDesc    string
	PortID        string
	ChassisID     string
	VLAN          uint16
	NativeVLAN    uint16 // VLAN nativa anunciada por vecino (de LLDP/CDP)
	ManagementIP  string
	Protocol      string        // "LLDP" o "CDP"
	AdvertisedTTL time.Duration // TTL dinámico reportado por el vecino
	LastSeen      time.Time
}

// String devuelve una representación legible para logs/alertas.
func (n NeighborInfo) String() string {
	if n.SystemName == "" && n.PortID == "" {
		return "Unknown Neighbor"
	}
	name := n.SystemName
	if name == "" {
		name = "Unknown-Switch"
	}
	port := n.PortID
	if port == "" {
		port = "Unknown-Port"
	}

	ipStr := ""
	if n.ManagementIP != "" {
		ipStr = fmt.Sprintf(", IP: %s", n.ManagementIP)
	}
	return fmt.Sprintf("%s (Port: %s%s) via %s", name, port, ipStr, n.Protocol)
}

// TopologyStore es el almacén centralizado thread-safe.
type TopologyStore struct {
	mu         sync.RWMutex
	neighbors  map[string]*NeighborInfo // Key: ifaceName (local) -> Info (remote)
	defaultTTL time.Duration            // Fallback si el vecino no envía TTL
}

func NewTopologyStore() *TopologyStore {
	return &TopologyStore{
		neighbors:  make(map[string]*NeighborInfo),
		defaultTTL: 180 * time.Second, // Standard industrial por defecto
	}
}

// Update actualiza la información de un vecino para una interfaz local.
func (ts *TopologyStore) Update(ifaceName string, info NeighborInfo) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Si el parser no extrajo TTL, usamos el default
	if info.AdvertisedTTL == 0 {
		info.AdvertisedTTL = ts.defaultTTL
	}

	ts.neighbors[ifaceName] = &info
}

// Get recupera la información del vecino de forma segura (copia para evitar data races).
func (ts *TopologyStore) Get(ifaceName string) (NeighborInfo, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	info, ok := ts.neighbors[ifaceName]
	if !ok || info == nil {
		return NeighborInfo{}, false
	}
	return *info, true
}

// GetAll devuelve una instantánea completa (copia profunda) de la tabla de vecinos.
// Thread-safe para ser consumido por la API HTTP (/topology).
func (ts *TopologyStore) GetAll() map[string]NeighborInfo {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	snapshot := make(map[string]NeighborInfo, len(ts.neighbors))
	for k, v := range ts.neighbors {
		// Al dereferenciar (*v), copiamos el struct por valor.
		snapshot[k] = *v
	}
	return snapshot
}

// Prune elimina vecinos que no han enviado paquetes en el periodo TTL.
func (ts *TopologyStore) Prune() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	deleted := 0

	for iface, info := range ts.neighbors {
		// Lógica dinámica: Cada vecino decide cuándo expira
		expiration := info.LastSeen.Add(info.AdvertisedTTL)

		if now.After(expiration) {
			delete(ts.neighbors, iface)
			deleted++
		}
	}
	return deleted
}

// StartCleanup inicia la rutina de limpieza automática.
func (ts *TopologyStore) StartCleanup() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ts.Prune()
		}
	}()
}
