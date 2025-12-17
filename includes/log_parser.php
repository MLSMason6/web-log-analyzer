<?php 

function parseLogLine($line) {
    // Common Apache log format regex 
    $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+ "([^"]*)" "([^"]*)"/';

    if (preg_match($pattern, $line, $matches)) {
        return [
            'ip'        => $matches[1],
            'timestamp' => $matches[2],
            'request'   => $matches[3],
            'status'    => $matches[4],
            'referrer'  => $matches[5],
            'agent'     => $matches[6]
        ];
    }
    return null;
}

function detectThreats ($request, $agent) {
    $threats = [];

    $patterns = [
        'SQL Injection' => '/(union\s+select|select\s+.*from|or\s+1=1)/i',
        'Directory Traversal' => '/(\.\.\/|\.\.\\\\)/',
        'XSS Attempt' => '/(<script>|%3Cscript%3E)/i',
        'Command Injection' => '/(;|\|\||&&)/',
        'Suspicious User-Agent' => '/(sqlmap|nikto|nmap|curl|wget)/i'
    ];

    foreach ($patterns as $type => $regex) {
        if (preg_match($regex, $request) || preg_match($regex, $agent)) {
            $threats[] = $type;
        }
    }

    return $threats;
}