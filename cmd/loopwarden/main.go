package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
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
		fmt.Fprintf(os.Stderr, "❌ Error loading config: %v\n", err)
		os.Exit(1)
	}

	// 1.5 Logging
	if cfg.System.LogFile != "" {
		if cfg.System.LogFile == "/dev/null" {
			log.SetOutput(io.Discard)
		} else {
			f, err := os.OpenFile(cfg.System.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to open log: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			log.SetOutput(f)
		}
	}

	// 2. Notifier (SINGLETON - Compartido entre todos los motores)
	sensorName := cfg.System.SensorName
	if sensorName == "" { sensorName = "LoopWarden" }
	notify := notifier.NewNotifier(&cfg.Alerts, sensorName)

	// Validar interfaces
	if len(cfg.Network.Interfaces) == 0 {
		log.Fatal("❌ No interfaces defined in config (network.interfaces = [])")
	}

	// Canal de señales global
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 3. Orquestación Paralela
	var wg sync.WaitGroup
	
	fmt.Printf("🛡️  LoopWarden starting on %d interfaces...\n", len(cfg.Network.Interfaces))
	notify.Alert(fmt.Sprintf("🟢 LoopWarden Started (Monitors: %v)", cfg.Network.Interfaces))

	// Lanzamos un stack completo por cada interfaz
	for _, ifaceName := range cfg.Network.Interfaces {
		wg.Add(1)
		
		// Capture loop variable (aunque en Go 1.22 ya no es necesario, buena práctica legacy)
		currentIface := ifaceName 

		go func(iface string) {
			defer wg.Done()
			
			// 3.1 Motor Independiente (Memoria aislada)
			// Pasamos el nombre de la interfaz para que ActiveProbe sepa quién es.
			engine := detector.NewEngine(&cfg.Algorithms, notify, iface)

			// 3.2 Sniffer Dedicado
			log.Printf("🚀 Launching stack for %s", iface)
			if err := sniffer.Run(iface, cfg, engine, sigChan); err != nil {
				log.Printf("❌ Critical error on interface %s: %v", iface, err)
				// No matamos todo el proceso, quizás otras interfaces siguen vivas.
				notify.Alert(fmt.Sprintf("❌ Stack failure on %s: %v", iface, err))
			} else {
				log.Printf("⏹️ Stack stopped for %s", iface)
			}
		}(currentIface)
	}

	// 4. Telemetría
	if cfg.Telemetry.Enabled {
		go func() {
			addr := cfg.Telemetry.ListenAddress
			if addr == "" { addr = ":9090" }
			http.Handle("/metrics", promhttp.Handler())
			log.Printf("📊 Metrics server listening on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("⚠️ Failed to start metrics: %v", err)
			}
		}()
	}

	// Esperar señal de terminación (que cerrará los sniffers vía sigChan)
	// Como sniffer.Run recibe sigChan, saldrá cuando el canal reciba algo.
	// Esperamos a que todas las goroutines terminen.
	<-sigChan // Bloquea hasta CTRL+C
	fmt.Println("\nSignal received, shutting down stacks...")
	
	// Esperamos a que los sniffers limpien (Wait)
	wg.Wait()
	
	notify.Alert("🔴 LoopWarden stopped gracefully")
	fmt.Println("Goodbye.")
}
