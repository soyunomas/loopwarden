package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	System     SystemConfig    `toml:"system"`
	Network    NetworkConfig   `toml:"network"`
	Algorithms AlgorithmConfig `toml:"algorithms"`
	Alerts     AlertsConfig    `toml:"alerts"`
	Telemetry  TelemetryConfig `toml:"telemetry"`
}

type SystemConfig struct {
	LogFile    string `toml:"log_file"`
	SensorName string `toml:"sensor_name"`
}

type TelemetryConfig struct {
	Enabled       bool   `toml:"enabled"`
	ListenAddress string `toml:"listen_address"`
}

type NetworkConfig struct {
	Interfaces []string `toml:"interfaces"`
	SnapLen    int      `toml:"snaplen"`
}

type AlgorithmConfig struct {
	EtherFuse    EtherFuseConfig    `toml:"etherfuse"`
	ActiveProbe  ActiveProbeConfig  `toml:"active_probe"`
	MacStorm     MacStormConfig     `toml:"mac_storm"`
	FlapGuard    FlapGuardConfig    `toml:"flap_guard"`
	ArpWatch     ArpWatchConfig     `toml:"arp_watch"`
	DhcpHunter   DhcpHunterConfig   `toml:"dhcp_hunter"`
	FlowPanic    FlowPanicConfig    `toml:"flow_panic"`
	RaGuard      RaGuardConfig      `toml:"ra_guard"`
	McastPolicer McastPolicerConfig `toml:"mcast_policer"`
}

// --- ALGORITMOS CON OVERRIDES ---

type EtherFuseConfig struct {
	Enabled        bool   `toml:"enabled"`
	HistorySize    int    `toml:"history_size"`
	AlertThreshold int    `toml:"alert_threshold"`
	StormPPSLimit  uint64 `toml:"storm_pps_limit"`

	// Mapa: "interface_name" -> Config específica
	Overrides map[string]EtherFuseOverride `toml:"overrides"`
}

type EtherFuseOverride struct {
	AlertThreshold int    `toml:"alert_threshold"`
	StormPPSLimit  uint64 `toml:"storm_pps_limit"`
	// HistorySize no se permite en override porque afecta la alocación de memoria inicial
}

type ActiveProbeConfig struct {
	Enabled      bool   `toml:"enabled"`
	IntervalMs   int    `toml:"interval_ms"`
	Ethertype    uint16 `toml:"ethertype"`
	MagicPayload string `toml:"magic_payload"`
	TargetMAC    string `toml:"target_mac"`

	Overrides map[string]ActiveProbeOverride `toml:"overrides"`
}

type ActiveProbeOverride struct {
	IntervalMs int `toml:"interval_ms"`
	// Ethertype y Payload suelen ser globales para consistencia
}

type MacStormConfig struct {
	Enabled      bool   `toml:"enabled"`
	MaxPPSPerMac uint64 `toml:"max_pps_per_mac"`

	Overrides map[string]MacStormOverride `toml:"overrides"`
}

type MacStormOverride struct {
	MaxPPSPerMac uint64 `toml:"max_pps_per_mac"`
}

type FlapGuardConfig struct {
	Enabled   bool `toml:"enabled"`
	Threshold int  `toml:"threshold"`

	Overrides map[string]FlapGuardOverride `toml:"overrides"`
}

type FlapGuardOverride struct {
	Threshold int `toml:"threshold"`
}

type ArpWatchConfig struct {
	Enabled bool   `toml:"enabled"`
	MaxPPS  uint64 `toml:"max_pps"`

	Overrides map[string]ArpWatchOverride `toml:"overrides"`
}

type ArpWatchOverride struct {
	MaxPPS uint64 `toml:"max_pps"`
}

type DhcpHunterConfig struct {
	Enabled      bool     `toml:"enabled"`
	TrustedMacs  []string `toml:"trusted_macs"`
	TrustedCidrs []string `toml:"trusted_cidrs"`

	Overrides map[string]DhcpHunterOverride `toml:"overrides"`
}

type DhcpHunterOverride struct {
	TrustedMacs  []string `toml:"trusted_macs"`
	TrustedCidrs []string `toml:"trusted_cidrs"`
}

type FlowPanicConfig struct {
	Enabled     bool   `toml:"enabled"`
	MaxPausePPS uint64 `toml:"max_pause_pps"`

	Overrides map[string]FlowPanicOverride `toml:"overrides"`
}

type FlowPanicOverride struct {
	MaxPausePPS uint64 `toml:"max_pause_pps"`
}

type RaGuardConfig struct {
	Enabled     bool     `toml:"enabled"`
	TrustedMacs []string `toml:"trusted_macs"`

	Overrides map[string]RaGuardOverride `toml:"overrides"`
}

type RaGuardOverride struct {
	TrustedMacs []string `toml:"trusted_macs"`
}

type McastPolicerConfig struct {
	Enabled bool   `toml:"enabled"`
	MaxPPS  uint64 `toml:"max_pps"`

	Overrides map[string]McastPolicerOverride `toml:"overrides"`
}

type McastPolicerOverride struct {
	MaxPPS uint64 `toml:"max_pps"`
}

// --- ALERTAS ---

type AlertsConfig struct {
	SyslogServer string         `toml:"syslog_server"`
	Webhook      WebhookConfig  `toml:"webhook"`
	Smtp         SmtpConfig     `toml:"smtp"`
	Telegram     TelegramConfig `toml:"telegram"`
}

type WebhookConfig struct {
	Enabled bool   `toml:"enabled"`
	URL     string `toml:"url"`
}

type SmtpConfig struct {
	Enabled bool   `toml:"enabled"`
	Host    string `toml:"host"`
	Port    int    `toml:"port"`
	User    string `toml:"user"`
	Pass    string `toml:"pass"`
	To      string `toml:"to"`
	From    string `toml:"from"`
}

type TelegramConfig struct {
	Enabled bool   `toml:"enabled"`
	Token   string `toml:"token"`
	ChatID  string `toml:"chat_id"`
}

func LoadConfig(path string) (*Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
