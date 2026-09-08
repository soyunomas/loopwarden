package notifier

import (
	"strings"
	"testing"

	"github.com/soyunomas/loopwarden/internal/config"
)

func testNotifierWithSegments(segments []config.NetworkSegment) *Notifier {
	alerts := &config.AlertsConfig{
		Dampening: config.DampeningConfig{
			MaxAlertsPerMinute: 100,
			MuteDuration:       "1m",
		},
	}
	network := &config.NetworkConfig{Segments: segments}
	return NewNotifierWithNetwork(alerts, "TEST", network)
}

func TestNetworkEnrichment_UniqueInterfaceSegment(t *testing.T) {
	n := testNotifierWithSegments([]config.NetworkSegment{
		{Name: "CIFP-172", Interface: "ens18", CIDR: "172.16.0.0/16"},
	})

	msg := "[ens18] LOOP\n    INTERFACE: ens18\n    STATUS: test"
	got := n.enrichNetworkContext(msg)

	if !strings.Contains(got, "NETWORK:    CIFP-172") {
		t.Fatalf("expected network attribution, got: %s", got)
	}
	if !strings.Contains(got, "SUBNET:     172.16.0.0/16") {
		t.Fatalf("expected subnet attribution, got: %s", got)
	}
}

func TestNetworkEnrichment_UsesVLANWhenPresent(t *testing.T) {
	n := testNotifierWithSegments([]config.NetworkSegment{
		{Name: "USUARIOS", Interface: "eno1", VLAN: 10, CIDR: "172.16.10.0/24"},
		{Name: "SERVIDORES", Interface: "eno1", VLAN: 20, CIDR: "10.20.0.0/16"},
	})

	msg := "[EtherFuse] LOOP\n    INTERFACE: eno1\n    VLAN:        20\n    STATUS: test"
	got := n.enrichNetworkContext(msg)

	if !strings.Contains(got, "NETWORK:    SERVIDORES") {
		t.Fatalf("expected VLAN 20 segment, got: %s", got)
	}
	if !strings.Contains(got, "SUBNET:     10.20.0.0/16") {
		t.Fatalf("expected VLAN 20 subnet, got: %s", got)
	}
}

func TestNetworkEnrichment_AmbiguousInterfaceIsNotGuessed(t *testing.T) {
	n := testNotifierWithSegments([]config.NetworkSegment{
		{Name: "USUARIOS", Interface: "eno1", VLAN: 10, CIDR: "172.16.10.0/24"},
		{Name: "SERVIDORES", Interface: "eno1", VLAN: 20, CIDR: "10.20.0.0/16"},
	})

	msg := "[ActiveProbe] LOOP\n    INTERFACE: eno1\n    STATUS: test"
	got := n.enrichNetworkContext(msg)

	if strings.Contains(got, "NETWORK:") || strings.Contains(got, "SUBNET:") {
		t.Fatalf("ambiguous interface must not be attributed, got: %s", got)
	}
}

func TestNetworkEnrichment_NoSegmentsPreservesMessage(t *testing.T) {
	n := testNotifierWithSegments(nil)
	msg := "[ActiveProbe] LOOP\n    INTERFACE: ens18\n    STATUS: test"

	if got := n.enrichNetworkContext(msg); got != msg {
		t.Fatalf("message changed without segments: %s", got)
	}
}

func TestNetworkEnrichment_ParsesInterfaceWithDomainSuffix(t *testing.T) {
	n := testNotifierWithSegments([]config.NetworkSegment{
		{Name: "CIFP-172", Interface: "ens18", CIDR: "172.16.0.0/16"},
	})

	msg := "[ActiveProbe] LOOP\n    INTERFACE: ens18 (Domain: CIFP)\n    STATUS: test"
	got := n.enrichNetworkContext(msg)

	if !strings.Contains(got, "NETWORK:    CIFP-172") {
		t.Fatalf("expected interface parser to ignore domain suffix, got: %s", got)
	}
}
