package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Network    NetworkConfig   `toml:"network"`
	Algorithms AlgorithmConfig `toml:"algorithms"`
	Alerts     AlertsConfig    `toml:"alerts"`
}

type NetworkConfig struct {
	Interface string `toml:"interface"`
	SnapLen   int    `toml:"snaplen"`
}

type AlgorithmConfig struct {
	EtherFuse   EtherFuseConfig   `toml:"etherfuse"`
	ActiveProbe ActiveProbeConfig `toml:"active_probe"`
	MacStorm    MacStormConfig    `toml:"mac_storm"`
	// Nuevos algoritmos añadidos
	FlapGuard   FlapGuardConfig   `toml:"flap_guard"`
	ArpWatch    ArpWatchConfig    `toml:"arp_watch"`
}

type EtherFuseConfig struct {
	Enabled        bool   `toml:"enabled"`
	HistorySize    int    `toml:"history_size"`
	AlertThreshold int    `toml:"alert_threshold"`
	StormPPSLimit  uint64 `toml:"storm_pps_limit"`
}

type ActiveProbeConfig struct {
	Enabled      bool   `toml:"enabled"`
	IntervalMs   int    `toml:"interval_ms"`
	Ethertype    uint16 `toml:"ethertype"`
	MagicPayload string `toml:"magic_payload"`
}

type MacStormConfig struct {
	Enabled      bool   `toml:"enabled"`
	MaxPPSPerMac uint64 `toml:"max_pps_per_mac"`
}

// --- Nuevas Configuraciones ---

type FlapGuardConfig struct {
	Enabled   bool `toml:"enabled"`
	Threshold int  `toml:"threshold"` // Ej: 5 cambios de VLAN en 1 segundo
}

type ArpWatchConfig struct {
	Enabled bool   `toml:"enabled"`
	MaxPPS  uint64 `toml:"max_pps"`   // Ej: 500 requests/segundo
}

// ------------------------------

// Configuración de notificaciones externas
type AlertsConfig struct {
	WebhookURL   string `toml:"webhook_url"`   // Slack/Teams/Discord
	SyslogServer string `toml:"syslog_server"` // udp:192.168.1.50:514

	// Configuración SMTP
	SmtpEnabled bool   `toml:"smtp_enabled"`
	SmtpHost    string `toml:"smtp_host"`
	SmtpPort    int    `toml:"smtp_port"`
	SmtpUser    string `toml:"smtp_user"`
	SmtpPass    string `toml:"smtp_pass"`
	SmtpTo      string `toml:"smtp_to"`
	SmtpFrom    string `toml:"smtp_from"`
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
