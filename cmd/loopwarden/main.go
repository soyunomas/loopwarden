package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/detector"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/sniffer"
)

func main() {
	// Flags
	configPath := flag.String("config", "configs/config.toml", "Path to configuration file")
	flag.Parse()

	// 1. Cargar Configuración
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("❌ Error loading config: %v", err)
	}

	// 2. Inicializar Sistema de Notificaciones
	notify := notifier.NewNotifier(&cfg.Alerts)

	// 3. Inicializar Motor de Detección 
	engine := detector.NewEngine(&cfg.Algorithms, notify)

	// --- 3.5 SERVIDOR DE MÉTRICAS (CONFIGURABLE) ---
	if cfg.Telemetry.Enabled {
		go func() {
			// Fallback seguro si viene vacío
			addr := cfg.Telemetry.ListenAddress
			if addr == "" {
				addr = ":9090"
			}

			// Precepto #14: Zero-Value Usability (Manejador por defecto)
			http.Handle("/metrics", promhttp.Handler())
			
			log.Printf("📊 Metrics server listening on %s", addr)
			
			// ListenAndServe es bloqueante, por eso está en goroutine
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("⚠️ Failed to start metrics server: %v", err)
			}
		}()
	} else {
		log.Println("🔇 Telemetry (Prometheus) is disabled in config.")
	}

	// Canal de cierre
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 4. Iniciar Sniffer
	fmt.Println("🛡️  LoopWarden starting...")
	notify.Alert("🟢 LoopWarden Started")

	if err := sniffer.Run(cfg, engine, sigChan); err != nil {
		notify.Alert(fmt.Sprintf("❌ Runtime critical error: %v", err))
		log.Fatalf("❌ Runtime error: %v", err)
	}

	notify.Alert("🔴 LoopWarden stopping")
	fmt.Println("\nLoopWarden stopping safely.")
}
