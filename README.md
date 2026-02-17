# 🛡️ LoopWarden

![Go Version](https://img.shields.io/badge/go-1.25%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Performance](https://img.shields.io/badge/performance-High%20Performance-brightgreen)

**LoopWarden** es un Detector de Bucles Ethernet (L2 Loop Detector) de alto rendimiento. Monitoriza la red en tiempo real para alertar sobre bucles físicos y tormentas de broadcast en milisegundos, reduciendo drásticamente el tiempo de diagnóstico (MTTR).

## 🚀 Características Principales

LoopWarden ejecuta **13 motores de detección concurrentes**. Cada uno busca una "firma" específica de fallo o amenaza en la red, proporcionando una visibilidad completa de Capa 2:

### 1. ActiveProbe (Inyección Activa Determinista) ⚡
*El "Sonar" de la red. La única forma de tener certeza.*

*   **🔬 Mecánica:** LoopWarden genera e inyecta una trama Ethernet broadcast (`FF:FF:FF:FF:FF:FF`) con un EtherType `0xFFFF` configurable. El payload contiene una firma mágica, la identidad de la interfaz y un **Dominio de Red** (Domain ID).
*   **🛡️ Lógica de Detección (Topology Awareness):**
    *   **Auto-Bucle (Hard Loop):** Si la sonda regresa con la **misma MAC de origen**, es un bucle físico en el propio puerto. (Alerta Crítica).
    *   **Vecino Legítimo:** Si la sonda viene de otra MAC pero tiene el **mismo Dominio** (ej: ambos son "VLAN10"), se considera otro sensor LoopWarden conviviendo en la misma red. (Silencio).
    *   **Bucle Cruzado (Cross-Domain):** Si la sonda viene de otra MAC con un **Dominio Diferente** (ej: recibo "VLAN10" en mi interfaz "VLAN20"), existe un puente físico crítico entre dos redes aisladas. (Alerta Crítica).
*   **💡 Valor Diferencial:** A diferencia de los métodos pasivos, ActiveProbe no genera falsos positivos en entornos con múltiples sensores. Permite monitorizar la misma VLAN desde distintos puntos sin que los sensores se "ataquen" entre sí.
*   **🎯 Qué detecta:**
    *   ✅ **Bucles Físicos:** Cable de parcheo conectado boca a boca.
    *   ✅ **Fugas de VLAN (VLAN Leaking):** Cables cruzados entre armarios de distintos departamentos.
    *   ✅ **Fallos de STP:** Switches donde Spanning Tree ha fallado o tarda en converger.


### 2. EtherFuse (Análisis Pasivo de Payload) 🧬
*Detección de "rebotes" mediante huella digital de hash rápido.*

*   **🔬 Mecánica:** Inspecciona pasivamente el tráfico Broadcast/Multicast entrante. Calcula un hash ultrarrápido (FNV-1a) del contenido (payload) de la trama. Almacena estos hashes en un buffer circular.
*   **🛡️ Lógica de Detección:** Si el sistema observa el mismo hash `N` veces en una ventana de tiempo de milisegundos, significa que la trama está "orbitando" la red infinitamente.
*   **💡 Valor Diferencial:** Capaz de detectar bucles **remotos**. Aunque el bucle no esté en tu switch local, recibirás la onda expansiva de los paquetes duplicados.
*   **🎯 Qué detecta:**
    *   ✅ **Bucles Remotos (Soft Loops):** Bucles en switches no gestionados aguas abajo.
    *   ✅ **Rebotes de Señal:** Paquetes duplicados por errores de configuración en enlaces redundantes.

### 3. MacStorm (Velocidad y Volumetría por Host) 🌪️
*Aislamiento de la fuente del problema.*

*   **🔬 Mecánica:** Mantiene una tabla de estado en tiempo real que rastrea los Paquetes Por Segundo (PPS) generados por cada dirección MAC origen única.
*   **🛡️ Lógica de Detección:** Aplica un límite de velocidad (Rate Limiting) lógico. Si una MAC individual supera el umbral definido, se marca como host hostil.
*   **💡 Valor Diferencial:** No solo te dice "hay un problema", te dice **quién** es el problema (MAC Address), permitiendo una acción de bloqueo precisa.
*   **🎯 Qué detecta:**
    *   ✅ **Tarjetas de Red Averiada (Jabbering NICs):** Hardware dañado enviando basura a la red.
    *   ✅ **Ataques DoS Volumétricos:** Intentos de saturación de ancho de banda.
    *   ✅ **Tráfico Anómalo:** Clientes P2P descontrolados o errores de software.

### 4. FlapGuard (Consistencia de Topología L2) 🦇
*Detección de fugas de VLAN e inestabilidad de puertos.*

*   **🔬 Mecánica:** Crea un mapa dinámico de la relación `MAC Address <-> VLAN ID`.
*   **🛡️ Lógica de Detección:** Monitoriza si una misma dirección MAC aparece en distintas VLANs en intervalos de tiempo muy cortos (Flapping).
*   **💡 Valor Diferencial:** Un síntoma clásico de configuraciones erróneas que STP no siempre bloquea.
*   **🎯 Qué detecta:**
    *   ✅ **VLAN Leaking:** Switches mal configurados dejando escapar tráfico etiquetado.
    *   ✅ **Cableado Cruzado:** Puentes físicos accidentales entre dos VLANs distintas.
    *   ✅ **Bucles Lógicos:** Rutas de red circular entre dominios de broadcast.

### 5. ArpWatchdog (Protección del Plano de Control) 🐶
*Sistema de alerta temprana y análisis de patrones.*

*   **🔬 Mecánica:** Realiza una inspección profunda (DPI) de paquetes ARP, analizando volumen, MAC origen e IPs destino (Rango Min/Max).
*   **🛡️ Lógica de Detección:** Analiza si el tráfico ARP corresponde a un comportamiento normal, un ataque o un fallo físico.
*   **💡 Valor Diferencial:** Distingue inteligentemente entre un bucle y un hacker basándose en la dispersión de IPs destino.
*   **🎯 Qué detecta:**
    *   ✅ **Escaneos de Red (Discovery):** Barridos secuenciales de IPs (`nmap`, `arp-scan`). El log mostrará `SUBNET SCANNING`.
    *   ✅ **Bucles de Red:** El mismo paquete ARP repitiéndose infinitamente hacia una sola IP. El log mostrará `SINGLE TARGET ATTACK`.
    *   ✅ **Virus/Malware:** Propagación lateral de gusanos intentando descubrir víctimas en la subred.
    *   ✅ **Gratuitous ARP Flood:** Inundación de paquetes GARP (Sender IP == Target IP) indicativos de conflictos IP, flapping VRRP/HSRP o ataques de ARP Poisoning.

### 6. DhcpHunter (Cazador de Rogue DHCP) 🦈
*Seguridad contra Man-in-the-Middle.*

*   **🔬 Mecánica:** Analiza paquetes UDP (Puerto 67/68) verificando la MAC de origen y la IP contra una lista blanca (`trusted_macs`).
*   **🛡️ Lógica de Detección:** Si un servidor desconocido ofrece una IP a un cliente, es inmediatamente marcado como Rogue.
*   **🎯 Qué detecta:**
    *   ✅ **Routers Domésticos:** Usuarios conectando TP-Link/D-Link por el puerto LAN.
    *   ✅ **Ataques MITM:** Suplantación de Gateway mediante DHCP Spoofing.
    *   ✅ **Errores de Configuración:** Servidores con roles DHCP activados accidentalmente.

### 7. FlowPanic (Detección de Pausas 802.3x) ⏸️
*Monitorización de salud física y DoS.*

*   **🔬 Mecánica:** Rastrea tramas de control Ethernet (`0x8808`) con OpCode `PAUSE`.
*   **🛡️ Lógica de Detección:** Una inundación de estas tramas indica que un dispositivo está colapsando o intentando detener la red.
*   **🎯 Qué detecta:**
    *   ✅ **Fallo de Hardware Crítico:** NICs o Switches a punto de morir por buffer lleno.
    *   ✅ **Ataques L2 DoS:** Inundación de tramas de pausa para congelar el tráfico sin saturar el ancho de banda.

### 8. RaGuard (IPv6 Router Advertisement Guard) 📡
*Protección de infraestructura IPv6.*

*   **🔬 Mecánica:** Inspecciona paquetes ICMPv6 buscando mensajes "Router Advertisement".
*   **🛡️ Lógica de Detección:** Solo permite RAs provenientes de las MACs de los routers Core autorizados.
*   **🎯 Qué detecta:**
    *   ✅ **Rogue IPv6 Gateways:** Dispositivos (móviles/Windows) anunciándose como routers y secuestrando tráfico.
    *   ✅ **Shadow IT:** Redes IPv6 paralelas no autorizadas creadas por dispositivos IoT.

### 9. McastPolicer (Control de Tormentas Multicast) 👻
*Gestión de clonación y streaming.*

*   **🔬 Mecánica:** Diferencia y mide tráfico Multicast (IPv4 `01:00:5E...` / IPv6 `33:33...`) separándolo del Broadcast.
*   **🛡️ Lógica de Detección:** Aplica límites de velocidad específicos, permitiendo distinguir una clase con vídeo de un bucle catastrófico.
*   **🎯 Qué detecta:**
    *   ✅ **Tormentas de Clonación:** Software como FOG/Clonezilla mal configurado.
    *   ✅ **Fugas de Vídeo:** Cámaras IP o IPTV inundando puertos de acceso.
    
### 10. BcastRatio (Ratio Broadcast vs Total) 📊
*Alerta temprana de degradación de red.*

*   **🔬 Mecánica:** Cuenta atómicamente todos los paquetes recibidos y los que son broadcast puro (`FF:FF:FF:FF:FF:FF`). Cada segundo calcula el porcentaje de broadcast sobre el total.
*   **🛡️ Lógica de Detección:** Si el ratio supera el umbral configurado (`max_ratio`, default 70%) con un mínimo de muestra (`min_sample_size`, default 100 pkts/s), genera una alerta de degradación.
*   **💡 Valor Diferencial:** Detecta la **formación** de una tormenta antes de que sea catastrófica. Un ratio broadcast del 80% indica que la red está al borde del colapso incluso si el PPS absoluto no ha disparado otros motores.
*   **🎯 Qué detecta:**
    *   ✅ **Tormentas Incipientes:** Bucles lentos que aún no generan suficiente PPS para EtherFuse pero ya degradan la red.
    *   ✅ **Degradación Gradual:** Redes donde el broadcast crece lentamente por acumulación de dispositivos mal configurados.

### 11. VlanLeak (Detector de Fugas entre VLANs) ☣️
*Vigilancia de aislamiento de segmentos de red.*

*   **🔬 Mecánica:** Rastrea qué VLANs visita cada MAC de origen. Mantiene un mapa `MAC → {VLAN → última vez vista}` y lo compara contra una lista de **pares de VLANs prohibidos** definidos en la configuración.
*   **🛡️ Lógica de Detección:** Si una misma MAC aparece en dos VLANs que están marcadas como prohibidas (ej: VLAN 10 de Servidores y VLAN 200 de Invitados), se genera una alerta inmediata de fuga de segmentación.
*   **💡 Valor Diferencial:** Mientras *FlapGuard* detecta cambios rápidos de VLAN (flapping), *VlanLeak* detecta tráfico que **nunca debería cruzar** entre segmentos, independientemente de la velocidad. Ideal para auditorías de cumplimiento (PCI-DSS, ISO 27001).
*   **🎯 Qué detecta:**
    *   ✅ **Fugas de Segmentación:** Tráfico de la VLAN de gestión apareciendo en la VLAN de invitados.
    *   ✅ **Errores de Trunk:** Puertos trunk permitiendo VLANs que no deberían.
    *   ✅ **Violaciones de Política:** Dispositivos accediendo a segmentos prohibidos por la política de red.

### 12. MetaEngine (Correlador Multi-Motor) 🧠
*Confirmación de alta confianza mediante correlación cruzada.*

*   **🔬 Mecánica:** Se suscribe al flujo de alertas del Notifier. Cada vez que un motor genera una alerta, el MetaEngine registra el evento con su timestamp. Mantiene una ventana deslizante de tiempo configurable.
*   **🛡️ Lógica de Detección:** Si **2 o más motores distintos** disparan alertas dentro de la misma ventana de tiempo (default: 2 segundos), el MetaEngine eleva la severidad a `CONFIRMED LOOP - MULTI-SIGNAL DETECTION`. Ejemplo: si *ActiveProbe* detecta un self-loop y *EtherFuse* detecta payloads repetidos simultáneamente, la confianza es máxima.
*   **💡 Valor Diferencial:** Reduce drásticamente los falsos positivos. Una alerta individual podría ser ruido, pero dos motores independientes confirmando el mismo evento en la misma ventana temporal es casi certeza absoluta.
*   **🎯 Qué detecta:**
    *   ✅ **Bucles Confirmados:** Correlación entre detección activa y pasiva.
    *   ✅ **Ataques Coordinados:** Múltiples anomalías simultáneas (DHCP Rogue + MAC Flood).
    *   ✅ **Fallos en Cascada:** Problemas de infraestructura que disparan múltiples alarmas.
*   **🔇 Modo Absorb (Reducción de Ruido):** Cuando `absorb = true`, las alertas individuales de los engines que participan en firmas de correlación (ActiveProbe, EtherFuse, MacStorm, FlapGuard, BcastRatio, McastPolicer) se **retienen temporalmente** durante la ventana de correlación. Si se confirma un bucle, solo se emite la alerta consolidada del MetaEngine, eliminando el ruido de alertas duplicadas. Si no hay correlación al expirar la ventana, las alertas retenidas se liberan normalmente. Los engines no correlacionables (DhcpHunter, RaGuard, FlowPanic, ArpWatch, VlanLeak) siempre pasan directo sin retención.

### 13. Multi-Stack Granular Tuning 🎛️
*Configuración jerárquica por interfaz.*

*   **🔬 Mecánica:** LoopWarden permite definir una política global de seguridad y aplicar **excepciones específicas** (Overrides) por interfaz.
*   **🛡️ Lógica:**
    *   **Global:** Define reglas estrictas para toda la red (ej: "Nadie puede escanear IPs").
    *   **Local:** Relaja o endurece las reglas para puertos específicos (ej: "La interfaz `vlan_guest` puede hacer más peticiones ARP, pero `mgmt` tiene tolerancia cero").
*   **💡 Valor Diferencial:** Permite desplegar una sola instancia de LoopWarden para monitorizar entornos heterogéneos (Servidores, IoT, Usuarios, Wi-Fi) sin generar falsos positivos en las zonas ruidosas.

#### 14. Neighbor Discovery (Conciencia de Topología) 🗺️
*Contexto físico para cada alerta.*

*   **🔬 Mecánica:** Un motor pasivo que decodifica tramas **LLDP** (Link Layer Discovery Protocol) y **CDP** (Cisco Discovery Protocol) en tiempo real. Extrae el Nombre del Sistema, Puerto, Chasis ID y **Dirección IP de Gestión** del switch vecino.
*   **🛡️ Lógica:** No genera alertas por sí mismo. Su función es mantener un "Mapa de Vecinos" en memoria (`TopologyStore`). Cuando otro motor (ej: *EtherFuse*) detecta un bucle, consulta este mapa para decirte no solo *que* hay un bucle, sino **exactamente en qué switch y puerto físico está conectado el sensor**.
*   **💡 Valor Diferencial:** Convierte una alerta genérica ("Bucle en eth0") en una orden de trabajo precisa ("Bucle en eth0, conectado al Switch-Core-01, Puerto Gi1/0/48, IP 10.10.1.1").

---

### 📊 Telemetría y Observabilidad (Prometheus & API)

LoopWarden está diseñado bajo la filosofía "Glass Box": visibilidad total interna y externa sin necesidad de agentes de terceros. El sistema expone un servidor HTTP ligero (default `:9090`) con dos endpoints clave para la operación diaria.

#### 1. Métricas de Rendimiento (`/metrics`)
Endpoint compatible nativamente con **Prometheus**. Permite visualizar la salud de la red y del motor de detección en tiempo real a través de Grafana.

*   **Forense de Capa 2:** Desglose granular del tráfico por protocolo (ARP, IPv4, IPv6, VLAN Tagged, LLDP, Control Frames) y tipo de transmisión (Broadcast vs Multicast). Identifica qué protocolo exacto está saturando el enlace.
*   **Salud del Kernel (Zero-Blindness):** Monitoriza directamente los contadores de descarte del driver de red (`rx_dropped`). Si el Kernel descarta paquetes por saturación de buffer antes de que LoopWarden pueda leerlos, la métrica `loopwarden_socket_drops_total` lo revelará, garantizando que no existan puntos ciegos operativos.
*   **Tendencias de Amenazas:** Contadores específicos para cada motor de detección (`loopwarden_engine_hits_total`). Permite correlacionar picos de CPU en los switches con tormentas ARP o bucles físicos detectados históricamente.
*   **Perfilado de Latencia:** Histogramas de precisión de nanosegundos (`loopwarden_processing_ns`) que miden el tiempo que tarda cada paquete en atravesar la pila de motores, validando el rendimiento "Fast-Path".

**Verificación Rápida:**
```bash
curl http://localhost:9090/metrics
```

#### 2. API de Topología en Vivo (`/topology`)
Gracias al motor *Neighbor Discovery*, LoopWarden mantiene un "mapa de vecindad" en tiempo real escuchando tramas LLDP y CDP. Este endpoint devuelve un snapshot **JSON** del estado actual de las conexiones físicas.

Es ideal para **Scripts de Automatización**, sistemas de Inventario Dinámico o simplemente para saber "¿A qué diablos está conectado este cable?" sin ir al rack.

**Ejemplo de Respuesta:**
```json
{
  "timestamp": "2025-02-07T10:00:00Z",
  "sensor": "LoopWarden-RackA",
  "neighbor_count": 2,
  "neighbors": {
    "eno1": {
      "SystemName": "Switch-Core-01",
      "SystemDesc": "Cisco IOS Software, C2960X Software (X86)...",
      "PortID": "GigabitEthernet1/0/48",
      "ManagementIP": "10.20.1.5",
      "Protocol": "CDP",
      "VLAN": 1,
      "AdvertisedTTL": 180000000000,
      "LastSeen": "2025-02-07T09:59:55Z"
    },
    "eno2": {
      "SystemName": "Access-Switch-Lab",
      "PortID": "eth0",
      "Protocol": "LLDP",
      "ManagementIP": "192.168.100.2",
      "LastSeen": "2025-02-07T09:58:30Z"
    }
  }
}
```

---

### 🔔 Notificaciones Inteligentes (Smart Silence & Dampening)

En una tormenta de broadcast, una red puede generar millones de eventos por segundo. Un sistema de alertas ingenuo tumbaría tu servidor de correo o bloquearía tu API de Slack. LoopWarden implementa **Higiene Operacional Configurable**:

*   **Global Dampening:** Configurable en la sección `[alerts.dampening]`. Si el sistema detecta una inundación de alertas que supera el umbral definido (default: 60 alertas/minuto), activa automáticamente un "Modo Pánico". Silencia las notificaciones globales durante el tiempo estipulado (`mute_duration`, default: 60s) y envía un único resumen consolidado al finalizar.
*   **Cooldowns Granulares:** Cada algoritmo posee tiempos de enfriamiento configurables (`alert_cooldown`). Por ejemplo, puedes configurar *ActiveProbe* para alertar cada 5 segundos, mientras obligas a *FlapGuard* a guardar silencio durante 5 minutos tras detectar un host inestable, adaptando el ruido a la criticidad del evento.
*   **Integraciones:** Webhooks JSON (Slack, Discord, Mattermost, Google Chat, Rocket.Chat), **Telegram Bots**, Syslog (RFC 3164) y SMTP (Email).

---

### ⚙️ Referencia de Configuración (`config.toml`)

A continuación se detallan todos los parámetros disponibles en el archivo de configuración.

LoopWarden utiliza un sistema de **Herencia de Configuración** para gestionar múltiples interfaces:
1.  **Valores Globales:** Se aplican por defecto a todas las interfaces.
2.  **Overrides (Excepciones):** Definidos por interfaz dentro de cada algoritmo. Si existen, reemplazan al valor global (para números/strings) o se suman a él (para listas).

### 🔌 Sistema y Red

| Sección | Parámetro | Default | Descripción |
| :--- | :--- | :--- | :--- |
| **[system]** | `sensor_name` | `"LoopWarden"` | Identificador único del despliegue (ej: "Rack-A1"). Se añade a todas las alertas. |
| | `log_file` | `""` | Ruta del archivo de log. Dejar vacío para consola o `/dev/null` para descartar. |
| **[network]** | `interfaces` | `["eno1"]` | **Crítico.** Lista de interfaces a monitorizar simultáneamente (ej: `["eno1", "eno2"]`). Se crea un motor independiente para cada una. |
| | `snaplen` | `2048` | Bytes a capturar por trama. |
| **[alerts]** | `syslog_server` | `""` | Dirección `IP:Puerto` del servidor Syslog (UDP). |
| **[alerts.dampening]**| `max_alerts_per_minute`| `60` | **Anti-Spam.** Límite de alertas globales antes de activar silencio. |
| | `mute_duration` | `"60s"` | Tiempo de silencio en modo pánico (ej: "1m", "30s"). |
| **[alerts.webhook]** | `enabled` | `false` | Activa/Desactiva notificaciones vía Webhook. |
| | `url` | `""` | URL del Webhook (Slack, Discord, Teams). |
| **[alerts.smtp]** | `enabled` | `false` | Activa el envío por correo electrónico. |
| | `host` | `"smtp.gmail.com"` | Servidor SMTP. |
| | `port` | `587` | Puerto SMTP (587 para TLS/STARTTLS). |
| | `user` | `""` | Usuario SMTP (email completo). |
| | `pass` | `""` | Contraseña o App Password. |
| | `to` | `""` | Destinatario de la alerta. |
| | `from` | `""` | Remitente (debe coincidir con el usuario en Gmail). |
| **[alerts.telegram]** | `enabled` | `false` | Activa notificaciones a Telegram. |
| | `token` | `""` | Token del bot proporcionado por @BotFather. |
| | `chat_id` | `""` | ID numérico del usuario o grupo (ej: `-100...` para grupos). |


### 🧠 Algoritmos de Detección

Esta tabla muestra los parámetros globales. **Nota:** La columna "Override" indica si el parámetro puede ser personalizado específicamente para una interfaz usando la sintaxis `[algorithms.X.overrides.interfaz]`.

| Sección | Parámetro | Default | Override | Descripción |
| :--- | :--- | :--- | :--- | :--- |
| **[algorithms.etherfuse]** | `enabled` | `true` | No | Activa/Desactiva el análisis de rebote de payloads. |
| | `history_size` | `4096` | ❌ No | Tamaño del buffer de memoria para hashes. Estático por alocación de RAM. |
| | `alert_threshold` | `200` | ✅ Sí | Cantidad de veces que un paquete debe repetirse para considerar bucle. |
| | `storm_pps_limit` | `15000` | ✅ Sí | Umbral de PPS global para considerar tormenta masiva. |
| | `alert_cooldown` | `"5s"` | ❌ No | Tiempo mínimo entre alertas repetidas del mismo hash. |
| **[algorithms.active_probe]**| `enabled` | `true` | No | Activa/Desactiva la inyección activa de sondas. |
| | `interval_ms` | `1000` | ✅ Sí | Frecuencia de envío de la sonda (milisegundos). |
| | `ethertype` | `65535` | ❌ No | Protocolo Ethernet (0xFFFF) usado. Global para interoperabilidad. |
| | `magic_payload` | `"LOOPWARDEN_PROBE"` | ❌ No | Firma mágica incluida en cada sonda. Debe ser idéntica en todos los sensores. |
| | `domain` | `"default"`| ✅ Sí | **Contexto de Red.** Etiqueta para agrupar sensores amigos (ej: "VLAN10"). Distinto dominio = Alerta de cruce. |
| **[algorithms.mac_storm]** | `enabled` | `true` | No | Activa/Desactiva el limitador de velocidad por host. |
| | `max_pps_per_mac`| `2000` | ✅ Sí | Máximo de paquetes/segundo permitidos por una única MAC. |
| | `max_tracked_macs`| `10000`| ❌ No | **Protección OOM.** Límite de hosts en memoria. |
| | `alert_cooldown` | `"30s"` | ❌ No | Tiempo de silencio tras detectar inundación de una MAC. |
| **[algorithms.flap_guard]**| `enabled` | `true` | No | Activa/Desactiva la detección de inestabilidad de VLANs. |
| | `threshold` | `5` | ✅ Sí | Número de cambios de VLAN permitidos en la ventana de tiempo. |
| | `window` | `"1s"` | ✅ Sí | Ventana de tiempo para contar cambios (ej: "500ms", "5s"). |
| | `alert_cooldown` | `"30s"` | ❌ No | Tiempo de silencio por host inestable. |
| **[algorithms.arp_watch]** | `enabled` | `true` | No | Activa/Desactiva la monitorización específica de ARP. |
| | `max_pps` | `500` | ✅ Sí | Límite global de peticiones ARP (`WHO-HAS`) por segundo. |
| | `scan_ip_threshold`| `10` | ✅ Sí | **Anti-Scan.** IPs destino únicas para considerar "Escaneo". |
| | `scan_mode_pps` | `100` | ✅ Sí | Límite estricto de PPS si se detecta modo escaneo. |
| | `garp_threshold` | `50` | ❌ No | Máximo de paquetes GARP (Gratuitous ARP) por segundo antes de alertar. |
| | `alert_cooldown` | `"30s"` | ❌ No | Frecuencia máxima de alertas por atacante. |
| **[algorithms.dhcp_hunter]** | `enabled` | `true` | No | Detección de servidores DHCP Rogue. |
| | `trusted_macs` | `[]` | ✅ Append | Lista de MACs autorizadas (Se suman Global + Override). |
| | `trusted_cidrs` | `[]` | ✅ Append | Lista de redes (CIDR) autorizadas (Se suman Global + Override). |
| **[algorithms.flow_panic]** | `enabled` | `true` | No | Detección de inundación de tramas PAUSE (802.3x). |
| | `max_pause_pps` | `50` | ✅ Sí | Máximo de tramas de pausa por segundo antes de alertar fallo/DoS. |
| **[algorithms.ra_guard]** | `enabled` | `true` | No | Protección contra Rogue IPv6 Router Advertisements. |
| | `trusted_macs` | `[]` | ✅ Append | Únicas MACs permitidas para actuar como Router IPv6 (Aditivo). |
| **[algorithms.mcast_policer]**| `enabled` | `true` | No | Control de tráfico Multicast. |
| | `max_pps` | `8000` | ✅ Sí | Límite global de paquetes multicast por segundo. |
| **[algorithms.bcast_ratio]** | `enabled` | `true` | No | Detección de ratio excesivo de broadcast sobre tráfico total. |
| | `max_ratio` | `0.7` | ✅ Sí | Porcentaje máximo de broadcast permitido (0.7 = 70%). |
| | `min_sample_size` | `100` | ✅ Sí | Mínimo de paquetes/segundo necesarios para evaluar el ratio. |
| | `alert_cooldown` | `"30s"` | ❌ No | Tiempo mínimo entre alertas repetidas. |
| **[algorithms.vlan_leak]** | `enabled` | `false` | No | Detección de tráfico cruzando entre pares de VLANs prohibidos. |
| | `prohibited_pairs` | `[]` | ❌ No | Lista de pares de VLANs que nunca deben compartir tráfico (ej: `[[10,200], [100,300]]`). |
| | `alert_cooldown` | `"60s"` | ❌ No | Tiempo mínimo entre alertas por MAC. |
| **[algorithms.meta_engine]** | `enabled` | `true` | No | Correlador multi-motor. Eleva severidad cuando múltiples motores disparan simultáneamente. |
| | `window` | `"2s"` | ❌ No | Ventana temporal para correlacionar alertas de distintos motores. |
| | `threshold` | `2` | ❌ No | Número mínimo de motores distintos que deben disparar para confirmar. |
| | `cooldown` | `"30s"` | ❌ No | Tiempo mínimo entre alertas de correlación. |
| | `absorb` | `true` | ❌ No | **Anti-Ruido.** Retiene alertas individuales correlacionables y solo emite la consolidada. |
| | `absorb_log` | `true` | ❌ No | Escribe alertas absorbidas en log local como red de seguridad forense. |
| **[algorithms.neighbor_discovery]** | `enabled` | `true` | No | Activa la escucha pasiva de LLDP/CDP. Es vital para enriquecer las alertas con datos del switch vecino. |

#### Ejemplo de Configuración con Overrides

```toml
[algorithms.mac_storm]
enabled = true
max_pps_per_mac = 1000  # Límite estricto por defecto (Servidores)

    # Excepción para Wi-Fi (wifi0): Más tolerante con usuarios
    [algorithms.mac_storm.overrides.wifi0]
    max_pps_per_mac = 5000

# CONFIGURACIÓN CRÍTICA PARA ACTIVE PROBE EN MULTI-VLAN
[algorithms.active_probe]
interval_ms = 1000

    # Interfaz en VLAN 10 (Servidores)
    [algorithms.active_probe.overrides.eno1]
    domain = "VLAN_10"   # Ignora a otros sensores "VLAN_10". Alerta si ve "VLAN_20".

    # Interfaz en VLAN 20 (Usuarios)
    [algorithms.active_probe.overrides.eno2]
    domain = "VLAN_20"   # Debe tener distinto dominio para detectar el cruce.

[algorithms.dhcp_hunter]
trusted_macs = ["AA:BB:CC:DD:EE:FF"] # DHCP Corporativo (Global)

    # Excepción para Laboratorio (eno3): Permite DHCP extra
    [algorithms.dhcp_hunter.overrides.eno3]
    trusted_macs = ["00:11:22:33:44:55"] # Resultado en eno3: Global + Local

# DETECCIÓN DE FUGAS ENTRE VLANS
[algorithms.vlan_leak]
enabled = true
prohibited_pairs = [[10, 200], [100, 300]]  # Pares que NUNCA deben compartir tráfico
alert_cooldown = "60s"

# CORRELADOR MULTI-MOTOR
[algorithms.meta_engine]
enabled = true
window = "2s"       # Ventana para correlacionar alertas
threshold = 2       # Motores mínimos para confirmar
cooldown = "30s"
```

### 📊 Telemetría

| Sección | Parámetro | Default | Descripción |
| :--- | :--- | :--- | :--- |
| **[telemetry]** | `enabled` | `true` | Activa el servidor HTTP de métricas Prometheus. |
| | `listen_address` | `":9090"` | Interfaz y puerto de escucha (ej: `127.0.0.1:9090` para local, `:9090` para todo). |

## 🎚️ Guía de Tuning y Calibración

LoopWarden viene configurado por defecto para entornos de tamaño medio (Oficinas/PyMEs). En entornos de alta densidad como **Centros Educativos, Universidades o Data Centers**, es necesario ajustar los umbrales para diferenciar tráfico legítimo de anomalías.

Usa esta guía para ajustar `config.toml` según el comportamiento de tu red.

### Estrategia de Configuración (Global vs Local)

Antes de ajustar los números, decide tu estrategia de despliegue para mantener el archivo `config.toml` mantenible.

1.  **La Regla del 80/20:** Configura los valores **Globales** pensando en tus servidores críticos o infraestructura core (donde quieres silencio absoluto y detección rápida). Esto cubrirá el 80% de tus puertos.
2.  **El "Pozo de Ruido":** Identifica las interfaces que conectan a redes de Usuarios, Wi-Fi de invitados o Laboratorios. Estas redes son ruidosas por naturaleza (mDNS, Broadcasts de Windows, Consolas).
    *   **No subas el límite global** para acomodar a los usuarios, o dejarás desprotegidos a los servidores.
    *   **Usa Overrides:** Crea una entrada específica para esa interfaz ruidosa:
        ```toml
        [algorithms.arp_watch.overrides.vlan_invitados]
        max_pps = 2000 # Permitir escaneos de descubrimiento en Wi-Fi
        ```
3.  **ActiveProbe en Core vs Acceso:**
    *   En enlaces **Core (10Gbps)**, usa un intervalo lento (ej: `5000ms`) para no saturar logs o gráficas.
    *   En enlaces de **Acceso**, usa un intervalo rápido (ej: `override interval_ms = 500`) para detectar el bucle en cuanto el usuario conecte mal el cable.

### 🧬 EtherFuse (Detección de Rebotes)
*Detecta paquetes duplicados idénticos.*

*   **`history_size` (Memoria de Hashes)**
    *   **📈 CUÁNDO SUBIR (ej: 8192 o 16384):**
        *   **Síntoma:** Bucles lentos o "Soft Loops" en redes muy grandes que no son detectados.
        *   **Causa:** En redes con mucho tráfico, el buffer circular se sobrescribe demasiado rápido antes de que el paquete duplicado vuelva. Aumentar esto consume más RAM pero "recuerda" los paquetes durante más tiempo.
    *   **📉 CUÁNDO BAJAR (ej: 1024):**
        *   **Síntoma:** Despliegues en hardware muy limitado (routers embebidos con poca RAM).
*   **`alert_threshold` (Sensibilidad de Repetición)**
    *   **📈 CUÁNDO SUBIR (ej: 200-500):**
        *   **Síntoma:** Alertas intermitentes sin caída de red.
        *   **Causa:** Software de aula (control de profesores), mDNS (Apple/Chromecast) o aplicaciones P2P en la LAN que envían el mismo payload muchas veces legítimamente.
    *   **📉 CUÁNDO BAJAR (ej: 20-50):**
        *   **Síntoma:** La red se vuelve lenta antes de que LoopWarden avise.
        *   **Causa:** Bucles lejanos con mucha atenuación o pérdida de paquetes.
*   **`storm_pps_limit` (Pánico Global)**
    *   **📈 CUÁNDO SUBIR (ej: 30000):**
        *   **Síntoma:** Alertas de "GLOBAL STORM" durante el inicio de jornada escolar o laboral.
        *   **Causa:** Cientos de dispositivos conectándose y haciendo Broadcast a la vez.

### ⚡ ActiveProbe (Sonda Activa)
*Inyección de tráfico para confirmación física.*

*   **`interval_ms` (Frecuencia de Sondeo)**
    *   **📈 CUÁNDO SUBIR (ej: 2000 ms):**
        *   **Síntoma:** Alto uso de CPU en el servidor LoopWarden o deseo de minimizar el ruido en capturas de Wireshark.
    *   **📉 CUÁNDO BAJAR (ej: 200-500 ms):**
        *   **Síntoma:** Protección de equipos críticos donde un bucle de 1 segundo es inaceptable. Detección casi instantánea.

### 🌪️ MacStorm (Límite por Host)
*Evita que una sola tarjeta de red sature el medio.*

*   **`max_pps_per_mac` (Velocidad Unicast)**
    *   **📈 CUÁNDO SUBIR (ej: 5000-8000):**
        *   **Síntoma:** Alertas sobre Servidores de Backups, NAS, NVRs de cámaras o servidores de clonación de imágenes.
        *   **Causa:** Transferencias de archivos masivas o tráfico legítimo de alta densidad.
    *   **📉 CUÁNDO BAJAR (ej: 1000):**
        *   **Síntoma:** Necesidad estricta de control de tráfico en redes de invitados o IoT.

### 🦇 FlapGuard (Baile de VLANs)
*Detecta cambios rápidos de puerto/VLAN.*

*   **`threshold` (Movimientos)**
    *   **📈 CUÁNDO SUBIR (ej: 20):**
        *   **Síntoma:** Alertas sobre usuarios WiFi (Roaming) o Servidores con LACP/Bonding.
        *   **Causa:** El cliente salta de AP rápidamente o el servidor balancea la carga entre interfaces físicas.
    *   **📉 CUÁNDO BAJAR (ej: 2-3):**
        *   **Síntoma:** Entornos estáticos (Datacenter) donde un cable nunca debe moverse. Detección inmediata de errores de cableado.
*   **`window` (Ventana de Tiempo)**
    *   **"1s" (Default):** Estándar.
    *   **"5s" (Larga):** Útil para detectar "flapping lento" en redes Wi-Fi complejas donde el cliente hace roaming de forma indecisa.

### 🐶 ArpWatchdog (Tormenta ARP)
*Monitoriza peticiones de resolución de direcciones.*

*   **`max_pps` (Peticiones Globales)**
    *   **📈 CUÁNDO SUBIR (ej: 2000):**
        *   **Síntoma:** Falsos positivos a primera hora de la mañana.
        *   **Causa:** Encendido masivo de aulas/oficinas (Boot Storm).
    *   **📉 CUÁNDO BAJAR (ej: 100):**
        *   **Síntoma:** Redes pequeñas o de seguridad crítica.
*   **Modo Escaneo (`scan_mode_pps`)**
    *   ArpWatchdog ahora distingue tráfico normal de un escaneo. Si un dispositivo toca más de `scan_ip_threshold` (10) IPs distintas, se le aplica un límite más estricto (`scan_mode_pps`, default 100) para detectar infecciones de malware (`nmap`, gusanos) rápidamente.

### 🦈 DhcpHunter y 📡 RaGuard (Seguridad)
*Listas Blancas de Infraestructura.*

*   **`trusted_macs` / `trusted_cidrs`**
    *   **Acción:** No son umbrales numéricos. Aquí debes añadir **EXPLICITAMENTE** las MACs de tus servidores DHCP legítimos y Routers. Cualquier cosa que no esté en esta lista y actúe como servidor, generará una alerta inmediata.

### ⏸️ FlowPanic (Tramas de Pausa)
*Salud Hardware y DoS.*

*   **`max_pause_pps`**
    *   **📈 CUÁNDO SUBIR (ej: 200):**
        *   **Síntoma:** Switches antiguos o enlaces muy saturados que usan Flow Control agresivamente.
    *   **📉 CUÁNDO BAJAR (ej: 10):**
        *   **Síntoma:** Quieres saber inmediatamente si una tarjeta de red o cable está defectuoso y negociando mal.

### 👻 McastPolicer (Tormenta Multicast)
*Control de tráfico de vídeo y clonación.*

*   **`max_pps`**
    *   **📈 CUÁNDO SUBIR (ej: 20000+):**
        *   **Síntoma:** Alertas al usar software de clonación (FOG, Clonezilla) o Videoconferencia HD.
        *   **Causa:** El tráfico Multicast es la base de estas herramientas.
    *   **📉 CUÁNDO BAJAR (ej: 1000):**
        *   **Síntoma:** La red WiFi colapsa pero la cableada no.
        *   **Causa:** El tráfico Multicast inunda el espectro aéreo (se transmite a velocidad base). Bajar esto protege la WiFi.

### 📊 BcastRatio (Ratio de Broadcast)
*Alerta temprana de degradación proporcional.*

*   **`max_ratio` (Porcentaje Máximo)**
    *   **📈 CUÁNDO SUBIR (ej: 0.85):**
        *   **Síntoma:** Alertas frecuentes en redes con muchos dispositivos Windows (NetBIOS) o IoT que generan broadcast legítimo.
    *   **📉 CUÁNDO BAJAR (ej: 0.5):**
        *   **Síntoma:** Redes críticas (Datacenter, SCADA) donde cualquier broadcast significativo es anormal.
*   **`min_sample_size` (Muestra Mínima)**
    *   **📈 CUÁNDO SUBIR (ej: 500):**
        *   **Síntoma:** Falsos positivos en interfaces con poco tráfico (ej: enlace de gestión con 50 pps donde 40 son ARP).
    *   **📉 CUÁNDO BAJAR (ej: 50):**
        *   **Síntoma:** Redes de baja velocidad donde 100 pps ya es significativo.

### ☣️ VlanLeak (Fugas entre VLANs)
*Vigilancia de segmentación de red.*

*   **`prohibited_pairs` (Pares Prohibidos)**
    *   **Acción:** Define explícitamente qué pares de VLANs **nunca** deben compartir tráfico. Ejemplo: `[[10, 200]]` prohibirá que una MAC vista en VLAN 10 aparezca en VLAN 200.
    *   **Planificación:** Revisa tu matriz de segmentación de red. Los pares típicos a prohibir son: Gestión vs Invitados, Servidores vs IoT, Producción vs Desarrollo.

### 🧠 MetaEngine (Correlación)
*Ajuste de sensibilidad de confirmación.*

*   **`threshold` (Motores Mínimos)**
    *   **📈 CUÁNDO SUBIR (ej: 3-4):**
        *   **Síntoma:** Alertas de correlación demasiado frecuentes. Quieres máxima certeza antes de escalar.
    *   **📉 CUÁNDO BAJAR (ej: 2):**
        *   **Síntoma:** Default. Dos motores independientes confirmando ya es alta confianza.
*   **`window` (Ventana de Correlación)**
    *   **"2s" (Default):** Estándar para bucles que disparan alertas casi instantáneamente.
    *   **"5s" (Amplia):** Útil si los motores tienen cooldowns largos y las alertas llegan con desfase.
*   **`absorb` (Modo Absorción de Ruido)**
    *   **`true` (Recomendado):** Las alertas individuales de engines correlacionables se retienen durante la ventana. Si hay correlación, solo se emite la alerta del MetaEngine. Si no la hay, las retenidas se liberan con un retardo de ~2 segundos.
    *   **`false`:** Comportamiento clásico. Todas las alertas se envían inmediatamente, incluyendo las del MetaEngine encima de las individuales.
    *   **⚠️ Riesgo:** Con `absorb = true`, las alertas aisladas (un solo engine sin correlación) se envían con un retardo igual a `window` (~2s). Este retardo no afecta la respuesta humana pero debe considerarse en automatizaciones con SLA estricto.
*   **`absorb_log` (Log Forense de Absorbidas)**
    *   **`true` (Recomendado):** Las alertas absorbidas se escriben igualmente en el log local como `[ABSORBED:interfaz]`. Actúa como red de seguridad: si el timer fallara, la evidencia sigue en el log.
    *   **`false`:** Las alertas absorbidas no dejan rastro en el log. Solo para entornos donde el volumen de log es crítico.
    *   **⚠️ Riesgo:** Si `absorb_log = false` y el timer de liberación falla, las alertas se pierden sin rastro. Mantener en `true` salvo necesidad extrema.

## 🚨 Playbook de Respuesta a Incidentes

Guía de actuación rápida para operadores de red (NOC) ante alertas críticas de LoopWarden:

| Alerta Recibida | Causa Probable | Acción Recomendada |
| :--- | :--- | :--- |
| **ActiveProbe:**<br>`LOOP CONFIRMED` | **Bucle Físico Cerrado.** | **ACCION INMEDIATA**<br>La alerta ahora incluye el campo `CONNECTED TO`. **Ve directamente a ese switch y puerto indicado** y desconecta el cable. No necesitas rastrear cables manualmente. |
| **FlapGuard:**<br>`MAC FLAPPING` | **Inestabilidad de Topología.**<br>Un cable puenteando dos VLANs o error de Native VLAN. | **INVESTIGAR CABLEADO**<br>1. Rastrea la MAC para ver entre qué puertos salta.<br>2. Verifica "Native VLAN" en Trunks. |
| **ArpWatchdog:**<br>`ARP STORM` | **Tormenta de Plano de Control.**<br>Síntoma temprano de bucle o escaneo masivo. | **CORRELACIONAR**<br>1. Si aparece con *EtherFuse*, es un bucle.<br>2. Si aparece sola, es un host infectado: localízalo y aíslalo. |
| **DhcpHunter:**<br>`ROGUE DHCP` | **Router doméstico conectado.**<br>Alguien conectó un router TP-Link/D-Link por el puerto LAN. | **BLOQUEO INMEDIATO**<br>La MAC reportada es el puerto del router intruso. Bloquea ese puerto en el switch o usa *BPDU Guard*. |
| **FlowPanic:**<br>`PAUSE FLOOD` | **Fallo Hardware / DoS.**<br>NIC muriendo o ataque de denegación de servicio a nivel L2. | **REEMPLAZO**<br>El dispositivo origen está defectuoso. Desconéctalo antes de que congele el switch entero. |
| **RaGuard:**<br>`ROGUE IPV6 RA` | **MITM IPv6.**<br>Un PC mal configurado o atacante se anuncia como Gateway IPv6. | **SEGURIDAD**<br>Investiga la MAC origen. Puede ser un intento de interceptar tráfico mediante autoconfiguración IPv6. |
| **McastPolicer:**<br>`MULTICAST STORM` | **Tormenta Multicast.**<br>Software de clonación, IPTV o cámaras IP fuera de control. | **INVESTIGAR ORIGEN**<br>Identifica la fuente multicast. Puede ser FOG/Clonezilla mal configurado o un bucle amplificando multicast. |
| **BcastRatio:**<br>`HIGH BROADCAST RATIO` | **Degradación de red.**<br>El porcentaje de broadcast supera el umbral configurado. | **MONITORIZAR**<br>Alerta temprana. Si supera el 80%, la red está al borde del colapso. Correlaciona con EtherFuse/ActiveProbe. |
| **VlanLeak:**<br>`VLAN LEAKAGE` | **Fuga de segmentación.**<br>Tráfico cruzando entre VLANs que deberían estar aisladas. | **AUDITORÍA INMEDIATA**<br>Revisa la configuración de trunks y puertos de acceso. Posible violación de políticas de segmentación (PCI-DSS). |
| **MetaEngine:**<br>`CONFIRMED LOOP` | **Bucle confirmado con alta confianza.**<br>Múltiples motores independientes han disparado simultáneamente. | **ACCIÓN INMEDIATA**<br>Es prácticamente certeza. Sigue las indicaciones de `CONNECTED TO` y desconecta el cable problemático. |
| **ArpWatchdog:**<br>`GRATUITOUS ARP FLOOD` | **Conflicto IP o ataque ARP.**<br>Inundación de paquetes GARP desde un host. | **INVESTIGAR**<br>Puede ser VRRP/HSRP flapping, conflicto de IPs duplicadas o un ataque de ARP Poisoning activo. |

## 🛠️ Instalación y Uso

LoopWarden está diseñado para ser compilado y ejecutado directamente desde su código fuente en entornos Linux. Se requiere Go 1.25+ y `make` para el proceso de compilación.

### Compilación y Ejecución Segura

```bash
# Paso 1: Clonar el repositorio de LoopWarden
# Obtiene la última versión del código fuente.
git clone https://github.com/soyunomas/LoopWarden.git
cd LoopWarden

# Paso 2: Descargar dependencias y compilar el binario optimizado
# 'make deps' sincroniza los módulos de Go.
# 'make build' compila el ejecutable, optimizándolo para producción (strip symbols, no debug info).
make deps
make build

# El binario resultante se encontrará en el directorio ./bin/loopwarden

# Paso 3: Asignar Capacidades de Red (Recomendado para Seguridad)
# En lugar de ejecutar como 'root' total, se otorgan únicamente los permisos necesarios
# para abrir sockets raw ('CAP_NET_RAW'). Esto mejora la postura de seguridad.
sudo setcap cap_net_raw=+ep ./bin/loopwarden

# Paso 4: Ejecutar LoopWarden
# El binario ahora puede ser ejecutado por un usuario no-root, leyendo la configuración.
# Asegúrate de ajustar 'configs/config.toml' según tu entorno.
./bin/loopwarden -config configs/config.toml
```

### Despliegue como Servicio de Sistema (systemd)

Para una operación continua y robusta en producción, se recomienda desplegar LoopWarden como un servicio `systemd`.

```bash
# Paso 1: Copiar el binario a una ubicación estándar del sistema
sudo cp bin/loopwarden /usr/local/bin/

# Paso 2: Crear el directorio de configuración del servicio
sudo mkdir -p /etc/loopwarden

# Paso 3: Copiar el archivo de configuración al directorio del servicio
sudo cp configs/config.toml /etc/loopwarden/

# Paso 4: Instalar el archivo de unidad de systemd
# Esto permite que systemd gestione el inicio, reinicio y monitoreo de LoopWarden.
sudo cp deploy/systemd/loopwarden.service /etc/systemd/system/

# Paso 5: Recargar systemd, habilitar y arrancar el servicio
# 'daemon-reload' actualiza systemd con la nueva unidad.
# 'enable --now' habilita el servicio para que inicie en el arranque y lo arranca de inmediato.
sudo systemctl daemon-reload
sudo systemctl enable --now loopwarden
```

### Compilación Cruzada (Raspberry Pi y OpenWRT)

LoopWarden soporta compilación cruzada para múltiples plataformas embebidas:

```bash
# Raspberry Pi 3/4/5/Zero2 (ARM64)
make build-pi
# Resultado: ./bin/loopwarden-pi-arm64

# Raspberry Pi 2/Zero Legacy (ARMv7 32-bit)
make build-pi-32
# Resultado: ./bin/loopwarden-pi-arm7

# OpenWRT Routers Ramips (MIPSLE Softfloat) - Sin compresión
make build-openwrt
# Resultado: ./bin/loopwarden-openwrt-ramips

# OpenWRT con compresión UPX (requiere 'upx' instalado)
make build-openwrt-upx
# Resultado: ./bin/loopwarden-openwrt-ramips-compressed
```

### Web Dashboard

LoopWarden incluye un dashboard web ligero en `web/dashboard/` que permite visualizar el estado del sensor y la topología de vecinos desde el navegador. Consulta los archivos `index.html` y `api.php` del directorio para su despliegue.

### Tuning para Alto Rendimiento (>10Gbps)

Para interfaces de red de alta velocidad (10Gbps o superior) en entornos de alta carga (ej. Core Routers, DMZ) o bajo ataques masivos, optimizar el subsistema de red del Kernel es fundamental para evitar la pérdida de paquetes.

1.  **Ajuste del Ring Buffer de la NIC:**
    *   **Comando:** `ethtool -G <nombre_interfaz> rx <tamaño_buffer>`
    *   **Ejemplo:** `sudo ethtool -G eno1 rx 4096`
    *   **Descripción:** Aumenta el tamaño del "anillo" de memoria (Ring Buffer) que la tarjeta de red utiliza para almacenar paquetes antes de que el Kernel los procese. Un buffer más grande reduce las caídas de paquetes (`rx_dropped`) bajo picos de tráfico. El valor óptimo es específico de cada NIC y su driver.

2.  **Ajuste de Buffers del Kernel para Sockets:**
    *   **Comandos:**
        *   `sudo sysctl -w net.core.rmem_max=26214400`
        *   `sudo sysctl -w net.core.rmem_default=26214400`
    *   **Descripción:** `rmem_max` y `rmem_default` controlan el tamaño máximo y por defecto del buffer de recepción para todos los sockets del Kernel. Valores más altos (aquí 25MB) permiten que los sockets raw de LoopWarden acumulen más datos en el Kernel antes de que la aplicación Go necesite leerlos, reduciendo el riesgo de sobrecarga del procesador y garantizando la captura completa incluso bajo tormentas severas. Para que sean permanentes, añadir al `/etc/sysctl.conf`.

> **¿Por qué LoopWarden si ya tengo STP?**
> Spanning Tree (STP/RSTP) es lento en converger y a menudo falla en "Edge Ports" donde los usuarios conectan switches no gestionados o cometen errores de cableado. LoopWarden detecta bucles, tormentas y anomalías de topología en **milisegundos**, proporcionando la telemetría que a los switches les falta.

## 🏗️ Arquitectura "Fast-Path"

LoopWarden está diseñado para procesar tráfico a velocidad de línea sin ahogar la CPU, utilizando una arquitectura de **Stacks Paralelos (Shared-Nothing)** para gestionar múltiples interfaces sin contención de bloqueos (Lock Contention):

```text
[ NETWORK WIRE ] <=== (Multiple Interfaces: eno1, eno2...)
      ||
[ NIC HARDWARE ]
      ||
[ KERNEL RING ] <--- (AF_PACKET RX_RING per Interface)
      ||
[ BPF FILTER ]  <--- "Drop Unicast. Keep Broadcast/Multicast/ARP/Tagged/Control"
      ||
[ GO RUNTIME ]  <--- (Parallel Stacks)
      ||
      +--> [ Engine Stack 1 (eno1) ]
      |      ||
      |      +-- 1. ActiveProbe (Identity Injection: "Magic|eno1")
      |      +-- 2. EtherFuse (Local State & Overrides)
      |      +-- ... (All Engines)
      |
      +--> [ Engine Stack 2 (eno2) ]
             ||
             +-- 1. ActiveProbe (Identity Injection: "Magic|eno2")
             +-- 2. EtherFuse (Local State & Overrides)
             +-- ... (All Engines)
             ||
[ NOTIFIER ] <-- (Centralized Deduplication & Throttling)
      ||
[ ALERTS ] ----> Slack / Syslog / Email (Tagged with [SensorName])
```

> **⚠️ Nota Técnica sobre Rendimiento (Kernel BPF):**
> LoopWarden utiliza Filtros BPF en Kernel-Space (cBPF JIT). Esto descarta el tráfico Unicast irrelevante antes de que cruce la frontera User-Space, evitando cambios de contexto costosos y garantizando el procesamiento a velocidad de línea sin saturar la CPU.


## 📜 Licencia

MIT License. Copyright (c) 2025 soyunomas.
