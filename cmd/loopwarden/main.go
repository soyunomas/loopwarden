package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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
	// Arranca un worker en background que consume alertas
	notify := notifier.NewNotifier(&cfg.Alerts)

	// 3. Inicializar Motor de Detección 
	// Inyectamos el notifier para que los algoritmos puedan enviar mensajes
	engine := detector.NewEngine(&cfg.Algorithms, notify)

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
