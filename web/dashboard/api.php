<?php
// api.php - LoopWarden Log Parser V3 (Raw Content Capable)
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$logFile = '/var/log/loopwarden.log';

if (!file_exists($logFile) || !is_readable($logFile)) {
    echo json_encode(["error" => "Log inaccesible"]);
    exit;
}

// Leer últimas 4000 líneas para tener contexto suficiente
function tailLines($filepath, $lines = 4000) {
    $f = fopen($filepath, "rb");
    if ($f === false) return [];
    fseek($f, -1, SEEK_END);
    if (ftell($f) <= 0) return [];
    $output = '';
    $chunkSize = 8192;
    while (ftell($f) > 0 && substr_count($output, "\n") < $lines) {
        $seek = min(ftell($f), $chunkSize);
        fseek($f, -$seek, SEEK_CUR);
        $output = ($chunk = fread($f, $seek)) . $output;
        fseek($f, -mb_strlen($chunk, '8bit'), SEEK_CUR);
    }
    fclose($f);
    return explode("\n", $output);
}

$rawLines = tailLines($logFile);
$events = [];
$currentEvent = null;

// Lista de ruido a ignorar (Inicialización, Telegram, Configuración)
$ignoreList = [
    '[Notifier]', 'Telegram failed', 'LoopWarden stopped', 'LoopWarden Started',
    'Sniffer active', 'Listening for LLDP', 'Config for', 'Stack stopped',
    'Metrics & API', 'Invalid AlertCooldown', 'Invalid Window', 'Active. Limit:',
    'Active. EtherType:', 'Active. Trusted', 'Active. AllowList', 'Active. Threshold',
    'KERNEL DROPS', 'Invalid MuteDuration', 'Launching stack'
];

// Regex fecha: "2026/02/09 15:21:39"
$dateRegex = '/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$/';

foreach ($rawLines as $line) {
    $line = trim($line, "\r\n"); // No usamos trim completo para preservar indentación visual si la hubiera
    if (empty(trim($line))) continue;

    if (preg_match($dateRegex, $line, $matches)) {
        
        $content = $matches[2];
        
        // Filtrar ruido
        $isIgnored = false;
        foreach ($ignoreList as $term) {
            if (strpos($content, $term) !== false) {
                $isIgnored = true;
                break;
            }
        }

        if (!$isIgnored) {
            if ($currentEvent) $events[] = $currentEvent;

            // Limpiar título
            $cleanTitle = preg_replace('/^(\[[^\]]+\]\s*)+/', '', $content);
            
            // Extraer Engine
            preg_match('/\[([a-zA-Z0-9_]+)\]/', $content, $engineMatch);
            $engine = $engineMatch[1] ?? 'System';

            $currentEvent = [
                'ts'        => $matches[1],
                'engine'    => $engine,
                'title'     => $cleanTitle,
                'details'   => [], // Array de líneas para el parsing rápido
                'full_text' => [$line], // Array de líneas crudas para el modal "Ver Todo"
                'mac'       => '',
                'ip'        => '',
                'iface'     => ''
            ];
        } else {
            $currentEvent = null; 
        }

    } else {
        // Línea de detalle
        if ($currentEvent) {
            // Guardamos la línea cruda para el modal
            $currentEvent['full_text'][] = $line;
            $currentEvent['details'][] = trim($line);

            // Parsing ligero para la tarjeta
            $trimLine = trim($line);
            
            // MAC Extractor (Soporta HOST, ROGUE MAC, SOURCE, SAMPLE SRC, MAC)
            if (empty($currentEvent['mac'])) {
                if (preg_match('/(HOST|ROGUE MAC|SOURCE|SAMPLE SRC|MAC):\s+([0-9a-fA-F:]{17})/', $trimLine, $m)) {
                    $currentEvent['mac'] = $m[2];
                }
            }
            // IP Extractor
            if (empty($currentEvent['ip'])) {
                if (preg_match('/(ROGUE IP|IP):\s+([0-9\.]+)/', $trimLine, $m)) {
                    $currentEvent['ip'] = $m[2];
                }
            }
            // Interface Extractor
            if (empty($currentEvent['iface'])) {
                if (strpos($trimLine, 'INTERFACE:') !== false) {
                    $parts = explode(':', $trimLine);
                    $currentEvent['iface'] = trim($parts[1] ?? '');
                }
            }
        }
    }
}
if ($currentEvent) $events[] = $currentEvent;

echo json_encode(array_reverse($events));
?>
