package main

import (
	"context" 
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

	// 2. Notifier
	sensorName := cfg.System.SensorName
	if sensorName == "" { sensorName = "LoopWarden" }
	notify := notifier.NewNotifier(&cfg.Alerts, sensorName)

	if len(cfg.Network.Interfaces) == 0 {
		log.Fatal("❌ No interfaces defined in config (network.interfaces = [])")
	}

	// --- CAMBIO CRÍTICO: GESTIÓN DE SEÑALES CON CONTEXTO ---
	// Creamos un contexto cancelable para coordinar el apagado
	ctx, cancel := context.WithCancel(context.Background())
	
	// Canal de señales solo para el main
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 3. Orquestación Paralela
	var wg sync.WaitGroup
	
	fmt.Printf("🛡️  LoopWarden starting on %d interfaces...\n", len(cfg.Network.Interfaces))
	notify.Alert(fmt.Sprintf("🟢 LoopWarden Started (Monitors: %v)", cfg.Network.Interfaces))

	for _, ifaceName := range cfg.Network.Interfaces {
		wg.Add(1)
		currentIface := ifaceName 

		go func(iface string) {
			defer wg.Done()
			
			engine := detector.NewEngine(&cfg.Algorithms, notify, iface)

			log.Printf("🚀 Launching stack for %s", iface)
			
			// AHORA PASAMOS 'ctx' EN LUGAR DE 'sigChan'
			if err := sniffer.Run(ctx, iface, cfg, engine); err != nil {
				log.Printf("❌ Critical error on interface %s: %v", iface, err)
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
			// Servidor HTTP también debería cerrarse, pero en toolings simples se suele dejar morir con el proceso.
			// Para perfección, se podría usar server.Shutdown(ctx), pero no es crítico aquí.
			log.Printf("📊 Metrics server listening on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("⚠️ Failed to start metrics: %v", err)
			}
		}()
	}

	// BLOQUEO PRINCIPAL
	// Esperamos aquí hasta recibir la señal
	receivedSig := <-sigChan 
	fmt.Printf("\nSignal received (%v), shutting down stacks...\n", receivedSig)
	
	// 1. Ordenamos a todos los sniffers que paren
	cancel() 
	
	// 2. Esperamos a que terminen limpiamente
	wg.Wait()
	
	notify.Alert("🔴 LoopWarden stopped gracefully")
	fmt.Println("Goodbye.")
}
