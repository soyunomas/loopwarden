package main

import (
	"context" 
	"encoding/json" // <--- Importante
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/soyunomas/loopwarden/internal/config"
	"github.com/soyunomas/loopwarden/internal/detector"
	"github.com/soyunomas/loopwarden/internal/notifier"
	"github.com/soyunomas/loopwarden/internal/sniffer"
	"github.com/soyunomas/loopwarden/internal/telemetry"
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

	// 2.5 Topology Store (Shared State)
	topologyStore := detector.NewTopologyStore()
	topologyStore.StartCleanup() 

	// --- CAMBIO CRÍTICO: GESTIÓN DE SEÑALES ---
	ctx, cancel := context.WithCancel(context.Background())
	
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
			
			// Inyectamos el topologyStore
			engine := detector.NewEngine(&cfg.Algorithms, notify, iface, topologyStore)

			log.Printf("🚀 Launching stack for %s", iface)
			
			if err := sniffer.Run(ctx, iface, cfg, engine); err != nil {
				log.Printf("❌ Critical error on interface %s: %v", iface, err)
				notify.Alert(fmt.Sprintf("❌ Stack failure on %s: %v", iface, err))
			} else {
				log.Printf("⏹️ Stack stopped for %s", iface)
			}
		}(currentIface)
	}

	// 4. Telemetría y API de Topología
	telemetry.StartMemoryCollector(10 * time.Second)

	if cfg.Telemetry.Enabled {
		go func() {
			addr := cfg.Telemetry.ListenAddress
			if addr == "" { addr = ":9090" }

			// Endpoint Prometheus Estándar
			http.Handle("/metrics", promhttp.Handler())

			// --- NUEVO: Endpoint de Topología ---
			// Devuelve JSON con el estado actual de los vecinos
			http.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}

				snapshot := topologyStore.GetAll()
				
				w.Header().Set("Content-Type", "application/json")
				// Estructura de respuesta para facilitar parsing
				response := struct {
					Timestamp time.Time `json:"timestamp"`
					Sensor    string    `json:"sensor"`
					Count     int       `json:"neighbor_count"`
					Neighbors map[string]detector.NeighborInfo `json:"neighbors"`
				}{
					Timestamp: time.Now(),
					Sensor:    sensorName,
					Count:     len(snapshot),
					Neighbors: snapshot,
				}

				if err := json.NewEncoder(w).Encode(response); err != nil {
					log.Printf("⚠️ Error encoding topology JSON: %v", err)
				}
			})
			// ------------------------------------

			log.Printf("📊 Metrics & API server listening on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("⚠️ Failed to start metrics: %v", err)
			}
		}()
	}

	// BLOQUEO PRINCIPAL
	receivedSig := <-sigChan 
	fmt.Printf("\nSignal received (%v), shutting down stacks...\n", receivedSig)
	
	cancel() 
	wg.Wait()
	
	notify.Alert("🔴 LoopWarden stopped gracefully")
	fmt.Println("Goodbye.")
}
