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

// --- ALGORITMOS ---

type EtherFuseConfig struct {
	Enabled        bool   `toml:"enabled"`
	HistorySize    int    `toml:"history_size"`
	AlertThreshold int    `toml:"alert_threshold"`
	StormPPSLimit  uint64 `toml:"storm_pps_limit"`
	AlertCooldown  string `toml:"alert_cooldown"` // Nuevo: Duration string (ej: "5s")

	Overrides map[string]EtherFuseOverride `toml:"overrides"`
}

type EtherFuseOverride struct {
	AlertThreshold int    `toml:"alert_threshold"`
	StormPPSLimit  uint64 `toml:"storm_pps_limit"`
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
}

type MacStormConfig struct {
	Enabled        bool   `toml:"enabled"`
	MaxPPSPerMac   uint64 `toml:"max_pps_per_mac"`
	MaxTrackedMacs int    `toml:"max_tracked_macs"` // Nuevo: Protección de memoria
	AlertCooldown  string `toml:"alert_cooldown"`   // Nuevo: Duration string

	Overrides map[string]MacStormOverride `toml:"overrides"`
}

type MacStormOverride struct {
	MaxPPSPerMac uint64 `toml:"max_pps_per_mac"`
}

type FlapGuardConfig struct {
	Enabled       bool   `toml:"enabled"`
	Threshold     int    `toml:"threshold"`
	Window        string `toml:"window"`         // Nuevo: Duration string (ej: "1s")
	AlertCooldown string `toml:"alert_cooldown"` // Nuevo: Duration string

	Overrides map[string]FlapGuardOverride `toml:"overrides"`
}

type FlapGuardOverride struct {
	Threshold int    `toml:"threshold"`
	Window    string `toml:"window"` // Nuevo: Override de ventana de tiempo
}

type ArpWatchConfig struct {
	Enabled         bool   `toml:"enabled"`
	MaxPPS          uint64 `toml:"max_pps"`
	ScanIPThreshold int    `toml:"scan_ip_threshold"` // Nuevo: IPs únicas para considerar Scan
	ScanModePPS     uint64 `toml:"scan_mode_pps"`     // Nuevo: PPS límite en modo Scan
	AlertCooldown   string `toml:"alert_cooldown"`    // Nuevo: Duration string

	Overrides map[string]ArpWatchOverride `toml:"overrides"`
}

type ArpWatchOverride struct {
	MaxPPS          uint64 `toml:"max_pps"`
	ScanIPThreshold int    `toml:"scan_ip_threshold"` // Nuevo
	ScanModePPS     uint64 `toml:"scan_mode_pps"`     // Nuevo
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
	SyslogServer string          `toml:"syslog_server"`
	Dampening    DampeningConfig `toml:"dampening"` // Nuevo: Control de flujo de alertas
	Webhook      WebhookConfig   `toml:"webhook"`
	Smtp         SmtpConfig      `toml:"smtp"`
	Telegram     TelegramConfig  `toml:"telegram"`
}

type DampeningConfig struct {
	MaxAlertsPerMinute int    `toml:"max_alerts_per_minute"` // Nuevo
	MuteDuration       string `toml:"mute_duration"`         // Nuevo: Duration string
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
