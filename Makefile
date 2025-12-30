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
LDFLAGS     := -ldflags "-s -w"

# --- Colores para la terminal (Lo hace ver "chulo") ---
COLOR_RESET = \033[0m
COLOR_CYAN  = \033[36m
COLOR_GREEN = \033[32m
COLOR_YELLOW= \033[33m
COLOR_RED   = \033[31m

# ==============================================================================
#  🎯 TARGETS
# ==============================================================================

.PHONY: all build clean run deps lint test setup help

## 🚀 Default: Descarga dependencias y compila
all: deps build

## 🔨 Build: Compila el binario estático optimizado
build:
	@echo "$(COLOR_CYAN)🔨 Compilando $(BINARY_NAME) para $(GOOS)/$(GOARCH)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✅ Build completado: $(BUILD_DIR)/$(BINARY_NAME)$(COLOR_RESET)"

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
			printf "  $(COLOR_GREEN)%-10s$(COLOR_RESET) %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)
	@echo ""
