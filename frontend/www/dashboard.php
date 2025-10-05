<?php
// Database configuration
$host = $_ENV['DB_HOST'] ?? '127.0.0.1';
$port = $_ENV['DB_PORT'] ?? '3306';
$user = $_ENV['DB_USER'] ?? 'scoutsuite_user';
$pass = $_ENV['DB_PASSWORD'] ?? 'your_password';
$db = $_ENV['DB_NAME'] ?? 'scoutsuite_db';

// Database health check function
function checkDatabaseHealth($host, $port, $user, $pass, $db) {
    $health = [
        'connected' => false,
        'database_exists' => false,
        'tables_exist' => false,
        'tables_populated' => false,
        'error' => null,
        'missing_tables' => [],
        'table_counts' => []
    ];
    
    try {
        // Test basic connection
        $pdo = new PDO("mysql:host=$host;port=$port", $user, $pass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $health['connected'] = true;
        
        // Check if database exists
        $stmt = $pdo->prepare("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?");
        $stmt->execute([$db]);
        if ($stmt->fetch()) {
            $health['database_exists'] = true;
            
            // Connect to specific database
            $pdo = new PDO("mysql:host=$host;port=$port;dbname=$db", $user, $pass);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Check required tables
            $required_tables = ['scout_scans', 'scout_findings', 'scout_events', 'scout_event_findings'];
            $existing_tables = [];
            
            $stmt = $pdo->query("SHOW TABLES");
            while ($row = $stmt->fetch(PDO::FETCH_NUM)) {
                $existing_tables[] = $row[0];
            }
            
            $health['missing_tables'] = array_diff($required_tables, $existing_tables);
            $health['tables_exist'] = empty($health['missing_tables']);
            
            // Check table populations if tables exist
            if ($health['tables_exist']) {
                foreach ($required_tables as $table) {
                    $stmt = $pdo->query("SELECT COUNT(*) FROM $table");
                    $count = $stmt->fetchColumn();
                    $health['table_counts'][$table] = $count;
                }
                $health['tables_populated'] = $health['table_counts']['scout_scans'] > 0;
            }
        }
        
        return [$pdo, $health];
        
    } catch (PDOException $e) {
        $health['error'] = $e->getMessage();
        return [null, $health];
    }
}

// Perform health check
list($pdo, $db_health) = checkDatabaseHealth($host, $port, $user, $pass, $db);

// If we have critical database issues, show error page
if (!$db_health['connected'] || !$db_health['database_exists'] || !$db_health['tables_exist']) {
    showDatabaseErrorPage($db_health);
    exit;
}

function showDatabaseErrorPage($health) {
    ?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="light">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>ScoutSuite Dashboard - Database Issue</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        </style>
    </head>
    <body class="bg-light">
    <nav class="navbar navbar-expand-lg gradient-bg text-white mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1 text-white">
                <i class="bi bi-shield-exclamation"></i> ScoutSuite Security Dashboard
            </span>
        </div>
    </nav>
    
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <?php if (!$health['connected']): ?>
                <div class="alert alert-danger" role="alert">
                    <h4 class="alert-heading"><i class="bi bi-exclamation-triangle-fill"></i> Database Connection Failed</h4>
                    <p>Unable to connect to the MySQL/MariaDB database server.</p>
                    <hr>
                    <p class="mb-0"><strong>Error:</strong> <?= htmlspecialchars($health['error']) ?></p>
                    <p class="mb-0"><strong>Host:</strong> <?= htmlspecialchars($GLOBALS['host']) ?>:<?= htmlspecialchars($GLOBALS['port']) ?></p>
                    <p class="mb-0"><strong>Database:</strong> <?= htmlspecialchars($GLOBALS['db']) ?></p>
                </div>
                
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h5 class="mb-0"><i class="bi bi-tools"></i> Troubleshooting Steps</h5>
                    </div>
                    <div class="card-body">
                        <ol>
                            <li><strong>Check Database Server:</strong> Ensure MySQL/MariaDB is running</li>
                            <li><strong>Verify Credentials:</strong> Check DB_HOST, DB_PORT, DB_USER, DB_PASSWORD in .env file</li>
                            <li><strong>Test Connection:</strong> <code>mysql -h <?= htmlspecialchars($GLOBALS['host']) ?> -P <?= htmlspecialchars($GLOBALS['port']) ?> -u <?= htmlspecialchars($GLOBALS['user']) ?> -p</code></li>
                            <li><strong>Check Firewall:</strong> Ensure port <?= htmlspecialchars($GLOBALS['port']) ?> is accessible</li>
                        </ol>
                    </div>
                </div>
                
                <?php elseif (!$health['database_exists']): ?>
                <div class="alert alert-warning" role="alert">
                    <h4 class="alert-heading"><i class="bi bi-database-exclamation"></i> Database Not Found</h4>
                    <p>Connected to MySQL server, but database <strong><?= htmlspecialchars($GLOBALS['db']) ?></strong> does not exist.</p>
                </div>
                
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0"><i class="bi bi-tools"></i> Setup Instructions</h5>
                    </div>
                    <div class="card-body">
                        <p>Create the database manually:</p>
                        <pre class="bg-light p-3 rounded"><code>mysql -u root -p -e "CREATE DATABASE <?= htmlspecialchars($GLOBALS['db']) ?>;"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON <?= htmlspecialchars($GLOBALS['db']) ?>.* TO '<?= htmlspecialchars($GLOBALS['user']) ?>'@'%';"
mysql -u root -p -e "FLUSH PRIVILEGES;"</code></pre>
                        <p class="mb-0">Then run the ScoutSuite parser to create tables automatically.</p>
                    </div>
                </div>
                
                <?php elseif (!$health['tables_exist']): ?>
                <div class="alert alert-info" role="alert">
                    <h4 class="alert-heading"><i class="bi bi-table"></i> Database Tables Missing</h4>
                    <p>Database exists but required ScoutSuite tables are missing.</p>
                    <p><strong>Missing tables:</strong> <?= implode(', ', $health['missing_tables']) ?></p>
                </div>
                
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="bi bi-play-circle"></i> Next Steps</h5>
                    </div>
                    <div class="card-body">
                        <p>Run the ScoutSuite parser to create the required tables:</p>
                        <pre class="bg-light p-3 rounded"><code># Run a scan to create tables automatically
python3 scout_runner.py --account your-account

# Or run parser with any results file
python3 scoutsuite_parser.py results.js</code></pre>
                        <p class="mb-0">Tables will be created automatically on first run.</p>
                    </div>
                </div>
                <?php endif; ?>
                
                <div class="mt-4 text-center">
                    <button class="btn btn-primary" onclick="location.reload()">
                        <i class="bi bi-arrow-clockwise"></i> Retry Connection
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
}

// Get filter parameters from POST or GET
$account = $_POST['account'] ?? $_GET['account'] ?? '';
$severity = $_POST['severity'] ?? $_GET['severity'] ?? '';
$resource_type = $_POST['resource_type'] ?? $_GET['resource_type'] ?? '';
$resolved = $_POST['resolved'] ?? $_GET['resolved'] ?? 'active';

// Get all accounts for dropdown
$accounts_sql = "SELECT DISTINCT account_id FROM scout_scans ORDER BY account_id";
$accounts = $pdo->query($accounts_sql)->fetchAll(PDO::FETCH_COLUMN);

// Build query
$where = [];
$params = [];

if ($account) {
    $where[] = "ss.account_id LIKE ?";
    $params[] = "%$account%";
}
if ($severity) {
    $where[] = "sf.level = ?";
    $params[] = $severity;
}
if ($resource_type) {
    $where[] = "se.resource_type = ?";
    $params[] = $resource_type;
}
if ($resolved === 'active') {
    $where[] = "se.resolved_at IS NULL";
} elseif ($resolved === 'resolved') {
    $where[] = "se.resolved_at IS NOT NULL";
}

$whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$sql = "
SELECT DISTINCT
    se.resource_id,
    se.resource_name,
    se.resource_type,
    se.region,
    sf.service,
    sf.level,
    sf.description,
    ss.account_id,
    se.first_seen,
    se.last_seen,
    se.resolved_at,
    se.notified
FROM scout_events se
JOIN scout_event_findings sef ON se.id = sef.event_id
JOIN scout_findings sf ON sef.finding_id = sf.id
JOIN scout_scans ss ON sf.scan_id = ss.id
$whereClause
GROUP BY se.id
ORDER BY se.last_seen DESC
LIMIT 1000
";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$events = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get filtered summary stats
$filtered_stats_sql = "
SELECT 
    COUNT(DISTINCT se.id) as total_events,
    COUNT(DISTINCT CASE WHEN se.resolved_at IS NULL THEN se.id END) as active_events,
    COUNT(DISTINCT CASE WHEN sf.level = 'good' AND se.resolved_at IS NULL THEN se.id END) as good,
    COUNT(DISTINCT CASE WHEN sf.level = 'warning' AND se.resolved_at IS NULL THEN se.id END) as warning,
    COUNT(DISTINCT CASE WHEN sf.level = 'danger' AND se.resolved_at IS NULL THEN se.id END) as danger,
    COUNT(DISTINCT ss.account_id) as accounts
FROM scout_events se
JOIN scout_event_findings sef ON se.id = sef.event_id
JOIN scout_findings sf ON sef.finding_id = sf.id
JOIN scout_scans ss ON sf.scan_id = ss.id
$whereClause
";

$stmt_stats = $pdo->prepare($filtered_stats_sql);
$stmt_stats->execute($params);
$stats = $stmt_stats->fetch(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ScoutSuite Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/simple-icons@v10/icons/amazonaws.svg" rel="preload" as="image">
    <style>
        .stat-card { transition: transform 0.2s; cursor: pointer; }
        .stat-card:hover { transform: translateY(-5px); }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .table-hover tbody tr:hover { background-color: rgba(0,0,0,.075); }
        .severity-critical { background: linear-gradient(45deg, #dc3545, #c82333) !important; }
        .severity-high { background: linear-gradient(45deg, #fd7e14, #e55a00) !important; }
        .severity-medium { background: linear-gradient(45deg, #0dcaf0, #0aa2c0) !important; }
        .severity-low { background: linear-gradient(45deg, #6c757d, #545b62) !important; }
        .severity-warning { background: linear-gradient(45deg, #ffc107, #e0a800) !important; }
        .severity-danger { background: linear-gradient(45deg, #dc3545, #b02a37) !important; }
        .aws-logo { filter: invert(1); }
        [data-bs-theme="dark"] .aws-logo { filter: invert(0); }
    </style>
</head>
<body class="bg-light">
<nav class="navbar navbar-expand-lg gradient-bg text-white mb-4">
    <div class="container-fluid">
        <span class="navbar-brand mb-0 h1 text-white">
            <i class="bi bi-shield-check"></i> ScoutSuite Security Dashboard
        </span>
        <button class="btn btn-outline-light btn-sm" onclick="toggleTheme()">
            <i class="bi bi-moon-fill" id="theme-icon"></i>
        </button>
    </div>
</nav>

<div class="container-fluid">
    <!-- Database Health Warning -->
    <?php if (!$db_health['tables_populated']): ?>
    <div class="alert alert-warning alert-dismissible fade show" role="alert">
        <h5 class="alert-heading"><i class="bi bi-info-circle"></i> No Data Available</h5>
        <p>Database tables exist but contain no scan data. Run ScoutSuite scans to populate the dashboard.</p>
        <hr>
        <p class="mb-0">
            <strong>Quick start:</strong> <code>python3 scout_runner.py --account your-account</code>
        </p>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
    <?php endif; ?>
    
    <!-- Stats Cards -->
    <div class="row mb-4">
        <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
            <div class="card stat-card h-100 border-0 shadow-sm">
                <div class="card-body text-center">
                    <i class="bi bi-list-ul text-primary fs-1"></i>
                    <h3 class="card-title mt-2"><?= number_format($stats['total_events']) ?></h3>
                    <p class="card-text text-muted">Total Events</p>
                </div>
            </div>
        </div>
        <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
            <div class="card stat-card h-100 border-0 shadow-sm">
                <div class="card-body text-center">
                    <i class="bi bi-exclamation-triangle text-warning fs-1"></i>
                    <h3 class="card-title mt-2"><?= number_format($stats['active_events']) ?></h3>
                    <p class="card-text text-muted">Active Events</p>
                </div>
            </div>
        </div>
        <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
            <div class="card stat-card h-100 border-0 shadow-sm bg-success text-white">
                <div class="card-body text-center">
                    <i class="bi bi-check-circle-fill fs-1"></i>
                    <h3 class="card-title mt-2"><?= number_format($stats['good']) ?></h3>
                    <p class="card-text">Good</p>
                </div>
            </div>
        </div>
        <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
            <div class="card stat-card h-100 border-0 shadow-sm severity-warning text-dark">
                <div class="card-body text-center">
                    <i class="bi bi-exclamation-triangle-fill fs-1"></i>
                    <h3 class="card-title mt-2"><?= number_format($stats['warning']) ?></h3>
                    <p class="card-text">Warning</p>
                </div>
            </div>
        </div>
        <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
            <div class="card stat-card h-100 border-0 shadow-sm severity-danger text-white">
                <div class="card-body text-center">
                    <i class="bi bi-shield-exclamation fs-1"></i>
                    <h3 class="card-title mt-2"><?= number_format($stats['danger']) ?></h3>
                    <p class="card-text">Danger</p>
                </div>
            </div>
        </div>
        <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
            <div class="card stat-card h-100 border-0 shadow-sm bg-info text-white">
                <div class="card-body text-center">
                    <img src="https://cdn.jsdelivr.net/npm/simple-icons@v10/icons/amazonaws.svg" alt="AWS" width="48" height="48" class="mb-2 aws-logo">
                    <h3 class="card-title mt-2"><?= number_format($stats['accounts']) ?></h3>
                    <p class="card-text">AWS Accounts</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-white">
            <h5 class="card-title mb-0"><i class="bi bi-funnel"></i> Filters</h5>
        </div>
        <div class="card-body">
            <form method="POST" class="row g-3">
                <div class="col-md-3">
                    <label class="form-label">Account ID</label>
                    <select class="form-select" name="account">
                        <option value="">All Accounts</option>
                        <?php foreach ($accounts as $acc): ?>
                            <option value="<?= htmlspecialchars($acc) ?>" <?= $account === $acc ? 'selected' : '' ?>><?= htmlspecialchars($acc) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label">Severity</label>
                    <select class="form-select" name="severity">
                        <option value="">All Severities</option>
                        <option value="good" <?= $severity === 'good' ? 'selected' : '' ?>>Good</option>
                        <option value="warning" <?= $severity === 'warning' ? 'selected' : '' ?>>Warning</option>
                        <option value="danger" <?= $severity === 'danger' ? 'selected' : '' ?>>Danger</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label">Resource Type</label>
                    <input type="text" class="form-control" name="resource_type" placeholder="e.g. instance" value="<?= htmlspecialchars($resource_type) ?>">
                </div>
                <div class="col-md-2">
                    <label class="form-label">Status</label>
                    <select class="form-select" name="resolved">
                        <option value="active" <?= $resolved === 'active' ? 'selected' : '' ?>>Active Only</option>
                        <option value="resolved" <?= $resolved === 'resolved' ? 'selected' : '' ?>>Resolved Only</option>
                        <option value="all" <?= $resolved === 'all' ? 'selected' : '' ?>>All Events</option>
                    </select>
                </div>
                <div class="col-md-3 d-flex align-items-end">
                    <button type="submit" class="btn btn-primary me-2"><i class="bi bi-search"></i> Filter</button>
                    <a href="/" class="btn btn-outline-secondary"><i class="bi bi-arrow-clockwise"></i> Clear</a>
                </div>
            </form>
        </div>
    </div>

    <!-- Events Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0"><i class="bi bi-table"></i> Security Events</h5>
            <span class="badge bg-primary"><?= count($events) ?> events</span>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover mb-0" id="eventsTable">
                    <thead class="table-dark">
                        <tr>
                            <th><i class="bi bi-building"></i> Account</th>
                            <th><i class="bi bi-hdd"></i> Resource</th>
                            <th><i class="bi bi-tag"></i> Type</th>
                            <th><i class="bi bi-geo"></i> Region</th>
                            <th><i class="bi bi-gear"></i> Service</th>
                            <th><i class="bi bi-exclamation-triangle"></i> Severity</th>
                            <th><i class="bi bi-info-circle"></i> Description</th>
                            <th><i class="bi bi-calendar-plus"></i> First Seen</th>
                            <th><i class="bi bi-calendar-check"></i> Last Seen</th>
                            <th><i class="bi bi-flag"></i> Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($events as $event): ?>
                        <tr>
                            <td><span class="badge bg-light text-dark"><?= htmlspecialchars($event['account_id']) ?></span></td>
                            <td>
                                <div class="fw-bold"><?= htmlspecialchars($event['resource_name'] ?: $event['resource_id']) ?></div>
                                <small class="text-muted"><?= htmlspecialchars($event['resource_id']) ?></small>
                            </td>
                            <td><span class="badge bg-secondary"><?= htmlspecialchars($event['resource_type']) ?></span></td>
                            <td><?= htmlspecialchars($event['region'] ?: 'global') ?></td>
                            <td><span class="badge bg-info"><?= htmlspecialchars($event['service']) ?></span></td>
                            <td>
                                <?php
                                $badgeClass = match($event['level']) {
                                    'good' => 'bg-success',
                                    'warning' => 'bg-warning text-dark',
                                    'danger' => 'bg-danger',
                                    default => 'bg-light text-dark'
                                };
                                ?>
                                <span class="badge <?= $badgeClass ?>"><?= htmlspecialchars($event['level']) ?></span>
                            </td>
                            <td>
                                <span class="description-text" data-bs-toggle="tooltip" title="<?= htmlspecialchars($event['description']) ?>">
                                    <?= htmlspecialchars(substr($event['description'], 0, 80)) ?><?= strlen($event['description']) > 80 ? '...' : '' ?>
                                </span>
                            </td>
                            <td><small><?= date('M j, Y H:i', strtotime($event['first_seen'])) ?></small></td>
                            <td><small><?= date('M j, Y H:i', strtotime($event['last_seen'])) ?></small></td>
                            <td>
                                <?php if ($event['resolved_at']): ?>
                                    <span class="badge bg-success"><i class="bi bi-check-circle"></i> Resolved</span>
                                <?php else: ?>
                                    <span class="badge bg-danger"><i class="bi bi-exclamation-circle"></i> Active</span>
                                <?php endif; ?>
                                <?php if ($event['notified']): ?>
                                    <span class="badge bg-primary"><i class="bi bi-bell"></i> Notified</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <?php if (count($events) === 1000): ?>
    <div class="alert alert-info mt-3"><i class="bi bi-info-circle"></i> Showing first 1000 results. Use filters to narrow down results.</div>
    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Initialize tooltips
const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

// Theme toggle
function toggleTheme() {
    const html = document.documentElement;
    const icon = document.getElementById('theme-icon');
    const currentTheme = html.getAttribute('data-bs-theme');
    
    if (currentTheme === 'dark') {
        html.setAttribute('data-bs-theme', 'light');
        icon.className = 'bi bi-moon-fill';
        localStorage.setItem('theme', 'light');
    } else {
        html.setAttribute('data-bs-theme', 'dark');
        icon.className = 'bi bi-sun-fill';
        localStorage.setItem('theme', 'dark');
    }
}

// Load saved theme
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    document.getElementById('theme-icon').className = savedTheme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
}

// Auto-refresh every 5 minutes
setTimeout(() => {
    location.reload();
}, 300000);

// Add click handlers to stat cards for filtering
document.querySelectorAll('.stat-card').forEach(card => {
    card.addEventListener('click', function() {
        const text = this.querySelector('.card-text').textContent.toLowerCase();
        if (text.includes('good') || text.includes('warning') || text.includes('danger')) {
            const severity = text.replace(' ', '');
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `<input type="hidden" name="severity" value="${severity}">`;
            document.body.appendChild(form);
            form.submit();
        }
    });
});
</script>
</body>
</html>