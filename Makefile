# ==============================================================================
#  🛡️  LoopWarden Makefile
# ==============================================================================

# --- Variables del Proyecto ---
BINARY_NAME := loopwarden
BUILD_DIR   := bin
MAIN_PATH   := cmd/loopwarden/main.go
CONFIG_PATH := configs/config.toml

# --- Detectar OS y Arquitectura ---
GOOS        ?= linux
GOARCH      ?= $(shell go env GOARCH)

# --- Comandos de Go ---
GOCMD       := go
GOBUILD     := $(GOCMD) build
GOCLEAN     := $(GOCMD) clean
GOTEST      := $(GOCMD) test
GOMOD       := $(GOCMD) mod
GOVET       := $(GOCMD) vet

# --- Flags de Compilación ---
# -s: Omitir tabla de símbolos (menor tamaño)
# -w: Omitir información de depuración DWARF (menor tamaño)
# NOTA: Para OpenWRT añadimos -trimpath en el target específico
LDFLAGS     := -ldflags "-s -w"

# --- Colores para la terminal ---
COLOR_RESET = \033[0m
COLOR_CYAN  = \033[36m
COLOR_GREEN = \033[32m
COLOR_YELLOW= \033[33m
COLOR_RED   = \033[31m

# ==============================================================================
#  🎯 TARGETS
# ==============================================================================

.PHONY: all build clean run deps lint test setup help build-pi build-pi-32 build-openwrt build-openwrt-upx

## 🚀 Default: Descarga dependencias y compila
all: deps build

## 🔨 Build: Compila el binario estático optimizado
build:
	@echo "$(COLOR_CYAN)🔨 Compilando $(BINARY_NAME) para $(GOOS)/$(GOARCH)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✅ Build completado: $(BUILD_DIR)/$(BINARY_NAME)$(COLOR_RESET)"

## 🍓 Build Pi: Compila binario para Raspberry Pi (ARM64 - Pi 3/4/5/Zero2)
build-pi:
	@echo "$(COLOR_CYAN)🍓 Compilando $(BINARY_NAME) para Raspberry Pi (Linux/ARM64)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-pi-arm64 $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✅ Build Pi (ARM64) completado: $(BUILD_DIR)/$(BINARY_NAME)-pi-arm64$(COLOR_RESET)"

## 🍓 Build Pi 32bit: Compila binario para Raspberry Pi Legacy (ARMv7 - Pi 2/Zero)
build-pi-32:
	@echo "$(COLOR_CYAN)🍓 Compilando $(BINARY_NAME) para Raspberry Pi 32-bit (Linux/ARMv7)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-pi-arm7 $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✅ Build Pi 32-bit completado: $(BUILD_DIR)/$(BINARY_NAME)-pi-arm7$(COLOR_RESET)"

## 📶 Build OpenWRT: Compila para Routers Ramips (MIPSLE Softfloat) - SAFE MODE
build-openwrt:
	@echo "$(COLOR_CYAN)📶 Compilando $(BINARY_NAME) para OpenWRT Ramips (MIPSLE/Softfloat)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@# Añadido -trimpath para reducir paths absolutos y ahorrar unos KB extra de forma segura
	@CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOBUILD) $(LDFLAGS) -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-openwrt-ramips $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✅ Build OpenWRT completado: $(BUILD_DIR)/$(BINARY_NAME)-openwrt-ramips$(COLOR_RESET)"

## 📦 Build OpenWRT UPX: Compila y comprime (Requiere 'upx' instalado) - AGGRESSIVE MODE
build-openwrt-upx: build-openwrt
	@echo "$(COLOR_YELLOW)📦 Comprimiendo binario OpenWRT con UPX...$(COLOR_RESET)"
	@upx --lzma --best $(BUILD_DIR)/$(BINARY_NAME)-openwrt-ramips -o $(BUILD_DIR)/$(BINARY_NAME)-openwrt-ramips-compressed
	@echo "$(COLOR_GREEN)✅ Build OpenWRT Comprimido: $(BUILD_DIR)/$(BINARY_NAME)-openwrt-ramips-compressed$(COLOR_RESET)"

## 🏃 Run: Ejecuta la aplicación (usa sudo automáticamente)
run: build
	@echo "$(COLOR_YELLOW)🚀 Iniciando LoopWarden con privilegios de root...$(COLOR_RESET)"
	@sudo ./$(BUILD_DIR)/$(BINARY_NAME) -config $(CONFIG_PATH)

## 📦 Deps: Limpia y descarga dependencias del go.mod
deps:
	@echo "$(COLOR_CYAN)📦 Gestionando dependencias...$(COLOR_RESET)"
	@$(GOMOD) tidy
	@$(GOMOD) verify
	@echo "$(COLOR_GREEN)✅ Dependencias sincronizadas.$(COLOR_RESET)"

## 🧹 Clean: Elimina binarios y artefactos de compilación
clean:
	@echo "$(COLOR_YELLOW)🧹 Limpiando proyecto...$(COLOR_RESET)"
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@echo "$(COLOR_GREEN)✨ Limpieza completada.$(COLOR_RESET)"

## 🔍 Lint: Analiza el código en busca de errores (go vet)
lint:
	@echo "$(COLOR_CYAN)🔍 Analizando código (vet)...$(COLOR_RESET)"
	@$(GOVET) ./...
	@echo "$(COLOR_GREEN)✅ Código verificado.$(COLOR_RESET)"

## 🧪 Test: Ejecuta tests unitarios y benchmarks de rendimiento
test:
	@echo "$(COLOR_CYAN)🧪 Ejecutando tests y benchmarks...$(COLOR_RESET)"
	@$(GOTEST) -v -bench=. ./...
	@echo "$(COLOR_GREEN)✅ Tests completados.$(COLOR_RESET)"

## ⚙️  Setup: Crea la estructura de directorios necesaria si no existe
setup:
	@echo "$(COLOR_CYAN)⚙️  Verificando estructura de directorios...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR) configs deploy/systemd internal/detector internal/sniffer internal/notifier internal/config cmd/$(BINARY_NAME)
	@echo "$(COLOR_GREEN)✅ Estructura lista.$(COLOR_RESET)"

## ❓ Help: Muestra este mensaje de ayuda
help:
	@echo ""
	@echo "  $(COLOR_CYAN)🛡️  LoopWarden - Network Loop Detector$(COLOR_RESET)"
	@echo ""
	@echo "  $(COLOR_YELLOW)Uso:$(COLOR_RESET) make $(COLOR_GREEN)[target]$(COLOR_RESET)"
	@echo ""
	@echo "  $(COLOR_YELLOW)Targets disponibles:$(COLOR_RESET)"
	@awk '/^[a-zA-Z0-9_-]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  $(COLOR_GREEN)%-20s$(COLOR_RESET) %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)
	@echo ""
