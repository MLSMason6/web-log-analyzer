<?php 
require_once "includes/log_parser.php";

if (!isset($_FILES['logfile']) || $_FILES['logfile']['error'] !== 0) {
    die("Error uploading file.");
}

$filepath = $_FILES['logfile']['tmp_name'];
$lines = file($filepath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

$parsedLogs = [];
$statusCounts = [];
$ipCounts = [];
$timeBuckets = [];
$threatCount = 0;

foreach ($lines as $line) {
    $parsed = parseLogLine($line);

    if ($parsed) {
        $parsed['threats'] = detectThreats($parsed['request'], $parsed['agent']);
        if (!empty($parsed['threats'])) { 
            $threatCount++;
        }

        $parsedLogs[] = $parsed;

        // Status codes 
        $statusCounts[$parsed['status']] = ($statusCounts[$parsed['status']] ?? 0) + 1;

        // IP frequency
        $ipCounts[$parsed['ip']] = ($ipCounts[$parsed['ip']] ?? 0) + 1;

        // Parse timestamp into hour bucket
        $time = strtotime(explode(':', $parsed['timestamp'], 2)[0]);
        $hour = date('Y-m-d H:00', $time);

        $timeBuckets[$hour] = ($timeBuckets[$hour] ?? 0) + 1;
    }
}

ksort($timeBuckets);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Log Analysis Results</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

    <h1>📊 Log Analysis Results</h1>

    <p><strong>Total Requests Parsed:</strong> <?= count($parsedLogs) ?></p>
    <p><strong>Suspicious Requests</strong><?= $threatCount ?></p>

    <h2>Status Code Breakdown</h2>
    <canvas id="statusChart" width="400"></canvas>

    <script>
        const statusData = {
            labels: <?= json_encode(array_keys($statusCounts)) ?>
            datasets: [{
                data: <?= json_encode(array_values($statusCounts)) ?>
            }]
        };

        new Chart(document.getElementById('statusChart'), {
            type: 'pie',
            data: statusData
        });
    </script>

    <script>
        const timelineData = {
            labels: <?= json_encode(array_keys($timeBuckets)) ?>,
            datasets: [{
                label: 'Requests per Hour', 
                data: <?= json_encode(array_values($timeBuckets)) ?>,
                fill: false,
                borderwidth: 2
            }]
        };

        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: timelineData,
            options: {
                scales: {
                    x: {
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    }
                }
            }
        });
    </script>

    <h2>Request Volume Over Time</h2>
    <canvas id="timelineChart" width="600"></canvas>

    <h2>Top IP Addresses</h2>
    <ul>
        <?php
        arsort($ipCounts);
        foreach (array_slice($ipCounts, 0, 10, true) as $ip => $count) {
            echo "<li>$ip — $count requests</li>";
        }
        ?>
    </ul>

    <h2>Flagged Requests</h2>
    <table border="1" cellpadding="5">
        <tr>
            <th>IP</th>
            <th>Request</th>
            <th>Status</th>
            <th>Threats</th>
        </tr>

        <?php foreach ($parsedLogs as $log): ?>
            <?php if (!empty($log['threats'])): ?>
                <tr>
                   <td><?= htmlspecialchars($log['ip']) ?></td>
                   <td><?= htmlspecialchars($log['request']) ?></td>
                   <td><?= $log['status'] ?></td>
                   <td><?= implode(", ", $log['threats']) ?></td>
                </tr>
            <?php endif; ?>
        <?php endforeach; ?>
    </table>

    <form method="POST" action="export_csv.php">
        <input type="hidden" name="logs" value='<?= json_encode(array_filter($parsedLogs, fn($l) => !empty($l["threats"]))) ?>'>
        <button type="submit">⬇ Export Flagged Requests to CSV</button>
    </form>
</body>
</html>