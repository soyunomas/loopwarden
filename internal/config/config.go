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
	TargetMAC    string `toml:"target_mac"` // Nuevo: MAC de destino para la sonda (opcional)
}

type MacStormConfig struct {
	Enabled      bool   `toml:"enabled"`
	MaxPPSPerMac uint64 `toml:"max_pps_per_mac"`
}

type FlapGuardConfig struct {
	Enabled   bool `toml:"enabled"`
	Threshold int  `toml:"threshold"`
}

type ArpWatchConfig struct {
	Enabled bool   `toml:"enabled"`
	MaxPPS  uint64 `toml:"max_pps"`
}

// --- CONFIGURACIÓN DE ALERTAS (100% ESTRUCTURADA) ---

type AlertsConfig struct {
	SyslogServer string `toml:"syslog_server"` // Syslog se mantiene simple (opcional cambiarlo)

	// Ahora todos son objetos consistentes
	Webhook  WebhookConfig  `toml:"webhook"`
	Smtp     SmtpConfig     `toml:"smtp"`
	Telegram TelegramConfig `toml:"telegram"`
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
