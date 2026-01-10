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
	EtherFuse    EtherFuseConfig    `toml:"etherfuse"`
	ActiveProbe  ActiveProbeConfig  `toml:"active_probe"`
	MacStorm     MacStormConfig     `toml:"mac_storm"`
	FlapGuard    FlapGuardConfig    `toml:"flap_guard"`
	ArpWatch     ArpWatchConfig     `toml:"arp_watch"`
	
	// --- NUEVOS MOTORES ---
	DhcpHunter   DhcpHunterConfig   `toml:"dhcp_hunter"`
	FlowPanic    FlowPanicConfig    `toml:"flow_panic"`
	RaGuard      RaGuardConfig      `toml:"ra_guard"`
	McastPolicer McastPolicerConfig `toml:"mcast_policer"`
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
	TargetMAC    string `toml:"target_mac"`
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

// --- NUEVAS CONFIGURACIONES ---

type DhcpHunterConfig struct {
	Enabled      bool     `toml:"enabled"`
	TrustedMacs  []string `toml:"trusted_macs"`
	TrustedCidrs []string `toml:"trusted_cidrs"`
}

type FlowPanicConfig struct {
	Enabled     bool `toml:"enabled"`
	MaxPausePPS uint64 `toml:"max_pause_pps"`
}

type RaGuardConfig struct {
	Enabled     bool     `toml:"enabled"`
	TrustedMacs []string `toml:"trusted_macs"`
}

type McastPolicerConfig struct {
	Enabled bool   `toml:"enabled"`
	MaxPPS  uint64 `toml:"max_pps"`
}

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
