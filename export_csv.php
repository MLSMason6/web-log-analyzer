<?php
require_once "includes/log_parser.php";

if (!isset($_POST['logs'])) {
    die("No data to export.");
}

$logs = json_decode($_POST['logs'], true);

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="flagged_requests.csv"');

$output = fopen('php://output', 'w');

// CSV headers 
fputcsv($output, ['IP Address', 'Timestamp', 'Request', 'Status', 'Threats']);

foreach ($logs as $log) {
    fputcsv($output, [
        $log['ip'],
        $log['timestamp'],
        $log['request'], 
        $log['status'],
        implode(', ',$log['threats'])
    ]);
}

fclose($output);
exit;