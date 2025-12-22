// Initialize variables
let systemUptime = 0;
let isDarkTheme = true;
let sidebarCollapsed = false;
let refreshInterval;
let alertSound = new Audio('https://assets.mixkit.co/sfx/preview/mixkit-alarm-digital-clock-beep-989.mp3');
let socket = null;
let alertNotificationContainer = null;

// DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    initRealtimeUpdates();
    startLiveUpdates();
    setupEventListeners();
    updateBadgeCounts();
    
    // Initialize cyberpunk effects
    initCyberpunkEffects();
    
    // Start auto-refresh for current page
    startPageAutoRefresh();
});

// Initialize Real-time WebSocket Updates
function initRealtimeUpdates() {
    // Check if SocketIO is available
    if (typeof io === 'undefined') {
        console.warn('SocketIO not loaded. Real-time features disabled.');
        return;
    }
    
    try {
        // Connect to WebSocket server
        socket = io('/alerts');
        
        socket.on('connect', function() {
            console.log('Connected to real-time alert system');
            updateConnectionStatus(true);
            
            // Request initial stats
            socket.emit('request_stats');
        });
        
        socket.on('connected', function(data) {
            console.log('WebSocket handshake complete:', data.message);
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from real-time alert system');
            updateConnectionStatus(false);
        });
        
        socket.on('new_alert', function(data) {
            console.log('New real-time alert received:', data);
            handleNewAlert(data);
        });
        
        socket.on('stats_update', function(stats) {
            console.log('Real-time stats update received');
            updateLiveStats(stats);
        });
        
        socket.on('recent_attacks', function(attacks) {
            console.log('Recent attacks update received');
            if (window.location.pathname.includes('intrusion')) {
                updateRecentAttacks(attacks);
            }
        });
        
        socket.on('error', function(error) {
            console.error('WebSocket error:', error);
            showNotification('WebSocket connection error', 'danger');
        });
        
    } catch (error) {
        console.error('Failed to initialize WebSocket:', error);
    }
}

// Update WebSocket connection status
function updateConnectionStatus(connected) {
    const statusIndicator = document.getElementById('systemStatus');
    const vtStatus = document.getElementById('vtStatus');
    
    if (!vtStatus) return;
    
    if (connected) {
        vtStatus.textContent = 'REAL-TIME';
        vtStatus.className = 'fw-bold text-success';
        vtStatus.style.textShadow = '0 0 10px var(--neon-green)';
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator active';
            statusIndicator.title = 'REAL-TIME MONITORING ACTIVE';
        }
    } else {
        vtStatus.textContent = 'OFFLINE';
        vtStatus.className = 'fw-bold text-danger';
        vtStatus.style.textShadow = '0 0 10px var(--neon-red)';
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator inactive';
            statusIndicator.title = 'REAL-TIME MONITORING OFFLINE';
        }
    }
}

// Handle new alerts from WebSocket
function handleNewAlert(alert) {
    // Play alert sound for critical alerts
    if (alert.severity === 'critical') {
        playAlertSound();
    }
    
    // Show notification
    showAlertNotification(alert);
    
    // Update badge counts
    updateBadgeCounts();
    
    // Update dashboard if we're on the dashboard page
    if (window.location.pathname === '/' || window.location.pathname.includes('dashboard')) {
        if (typeof refreshAlerts === 'function') {
            refreshAlerts();
        }
    }
    
    // Update intrusion page if we're on it
    if (window.location.pathname.includes('intrusion')) {
        if (typeof refreshIntrusions === 'function') {
            refreshIntrusions();
        }
    }
    
    // Add to alert history
    addToAlertHistory(alert);
}

// Add alert to history display
function addToAlertHistory(alert) {
    const alertHistory = document.getElementById('alertHistory');
    if (!alertHistory) return;
    
    const alertElement = document.createElement('div');
    alertElement.className = `alert-item alert-${alert.severity}`;
    alertElement.innerHTML = `
        <div class="d-flex justify-content-between">
            <strong>${alert.type}</strong>
            <small class="text-muted">${new Date(alert.timestamp).toLocaleTimeString()}</small>
        </div>
        <div class="small">${alert.message}</div>
        ${alert.ip ? `<div class="small mt-1">IP: <code>${alert.ip}</code></div>` : ''}
    `;
    
    // Add to top of history
    if (alertHistory.firstChild) {
        alertHistory.insertBefore(alertElement, alertHistory.firstChild);
    } else {
        alertHistory.appendChild(alertElement);
    }
    
    // Limit history to 50 items
    const items = alertHistory.querySelectorAll('.alert-item');
    if (items.length > 50) {
        items[items.length - 1].remove();
    }
}

// Show alert notification
function showAlertNotification(alert) {
    if (!alertNotificationContainer) {
        createNotificationContainer();
    }
    
    const notification = document.createElement('div');
    notification.className = `alert-notification alert-${alert.severity}`;
    notification.innerHTML = `
        <div class="d-flex align-items-start">
            <i class="fas fa-${getAlertIcon(alert.severity)} me-2 mt-1"></i>
            <div class="flex-grow-1">
                <div class="d-flex justify-content-between">
                    <strong>${alert.type}</strong>
                    <button type="button" class="btn-close btn-close-white btn-sm" onclick="this.parentElement.parentElement.parentElement.remove()"></button>
                </div>
                <div class="small">${alert.message}</div>
                ${alert.ip ? `<div class="small mt-1">IP: <code>${alert.ip}</code></div>` : ''}
                <div class="text-end">
                    <small class="text-muted">${timeAgo(new Date(alert.timestamp))}</small>
                </div>
            </div>
        </div>
    `;
    
    alertNotificationContainer.appendChild(notification);
    
    // Auto-remove after 10 seconds for non-critical alerts
    if (alert.severity !== 'critical') {
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }
        }, 10000);
    }
}

// Get appropriate icon for alert severity
function getAlertIcon(severity) {
    switch(severity) {
        case 'critical': return 'skull-crossbones';
        case 'warning': return 'exclamation-triangle';
        case 'info': return 'info-circle';
        default: return 'bell';
    }
}

// Time ago function
function timeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    let interval = Math.floor(seconds / 31536000);
    if (interval >= 1) return interval + " year" + (interval > 1 ? "s" : "") + " ago";
    
    interval = Math.floor(seconds / 2592000);
    if (interval >= 1) return interval + " month" + (interval > 1 ? "s" : "") + " ago";
    
    interval = Math.floor(seconds / 86400);
    if (interval >= 1) return interval + " day" + (interval > 1 ? "s" : "") + " ago";
    
    interval = Math.floor(seconds / 3600);
    if (interval >= 1) return interval + " hour" + (interval > 1 ? "s" : "") + " ago";
    
    interval = Math.floor(seconds / 60);
    if (interval >= 1) return interval + " minute" + (interval > 1 ? "s" : "") + " ago";
    
    return "just now";
}

// Create notification container
function createNotificationContainer() {
    alertNotificationContainer = document.createElement('div');
    alertNotificationContainer.id = 'alertNotifications';
    alertNotificationContainer.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        z-index: 9999;
        max-width: 400px;
        max-height: 80vh;
        overflow-y: auto;
        scrollbar-width: thin;
    `;
    document.body.appendChild(alertNotificationContainer);
    return alertNotificationContainer;
}

// Update live stats from WebSocket
function updateLiveStats(stats) {
    // Update all stat elements
    const statElements = {
        'totalAlerts': stats.total_alerts,
        'criticalAlerts': stats.critical_alerts,
        'filesScanned': stats.files_scanned,
        'maliciousFiles': stats.malicious_files,
        'recentIntrusions': stats.recent_intrusions,
        'blockedIPs': stats.blocked_ips,
        'ddosAttacks': stats.ddos_attacks,
        'portScans': stats.port_scans,
        'recentAttacks5min': stats.recent_attacks_5min
    };
    
    for (const [id, value] of Object.entries(statElements)) {
        const element = document.getElementById(id);
        if (element) {
            // Add animation for value changes
            const oldValue = parseInt(element.textContent) || 0;
            if (value !== oldValue && oldValue > 0) {
                element.classList.add('value-changed');
                setTimeout(() => element.classList.remove('value-changed'), 1000);
            }
            element.textContent = value;
        }
    }
    
    // Update connection status if stats are flowing
    if (stats.total_alerts !== undefined) {
        updateConnectionStatus(true);
    }
}

// Update recent attacks on intrusion page
function updateRecentAttacks(attacks) {
    if (!window.location.pathname.includes('intrusion')) return;
    
    const table = document.getElementById('intrusionsTable');
    if (!table) return;
    
    // Only update if we're not manually refreshing
    if (table.dataset.updating === 'true') return;
    
    // Add new attacks
    attacks.forEach(attack => {
        // Check if this attack already exists in the table
        const existingRow = Array.from(table.rows).find(row => 
            row.cells[1]?.textContent?.includes(attack.ip) && 
            new Date(row.cells[0]?.textContent).getTime() === new Date(attack.timestamp).getTime()
        );
        
        if (!existingRow) {
            const newRow = table.insertRow(1); // Insert after header
            newRow.innerHTML = `
                <td>${new Date(attack.timestamp).toLocaleString()}</td>
                <td><code class="text-danger">${attack.ip}</code></td>
                <td>${attack.type || 'Failed Password Attempt'}</td>
                <td><span class="badge-cyber-danger">Active</span></td>
                <td>
                    <button class="btn btn-sm btn-cyber-outline" onclick="showBlockIPModal('${attack.ip}')">
                        <i class="fas fa-ban"></i> Block
                    </button>
                </td>
            `;
            
            // Highlight new row
            newRow.style.animation = 'highlightRow 2s ease';
        }
    });
    
    // Update statistics
    updateAttackStatistics();
}

// Setup Event Listeners
function setupEventListeners() {
    // Theme Toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', toggleSidebar);
    }
    
    // Update badge counts on page visibility change
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden) {
            updateBadgeCounts();
            if (socket && !socket.connected) {
                socket.connect();
            }
        }
    });
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+Shift+S for system scan
        if (e.ctrlKey && e.shiftKey && e.key === 'S') {
            startSystemScan();
            e.preventDefault();
        }
        
        // Ctrl+Shift+F for file scanner
        if (e.ctrlKey && e.shiftKey && e.key === 'F') {
            openFileScanner();
            e.preventDefault();
        }
        
        // Ctrl+Shift+R for refresh
        if (e.ctrlKey && e.shiftKey && e.key === 'R') {
            location.reload();
            e.preventDefault();
        }
        
        // Ctrl+Shift+M for mute alerts
        if (e.ctrlKey && e.shiftKey && e.key === 'M') {
            toggleAlertSound();
            e.preventDefault();
        }
    });
    
    // Listen for manual refresh buttons
    document.addEventListener('click', function(e) {
        if (e.target.closest('[onclick*="refresh"]')) {
            // Update connection status when user manually refreshes
            if (socket && socket.connected) {
                updateConnectionStatus(true);
            }
        }
    });
}

// Initialize Cyberpunk Effects
function initCyberpunkEffects() {
    // Add hover effects to all buttons
    const buttons = document.querySelectorAll('.btn-cyber, .btn-cyber-outline');
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px) scale(1.02)';
            this.style.transition = 'all 0.3s ease';
            this.style.boxShadow = '0 5px 15px rgba(0, 243, 255, 0.4)';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
            this.style.boxShadow = '';
        });
    });
    
    // Add ripple effect to buttons
    document.addEventListener('click', function(e) {
        if (e.target.closest('.btn-cyber')) {
            createRipple(e, e.target.closest('.btn-cyber'));
        }
    });
    
    // Add pulsing effect to critical elements
    setInterval(() => {
        const criticalElements = document.querySelectorAll('.badge-cyber-danger, .status-indicator.critical');
        criticalElements.forEach(el => {
            if (el.classList.contains('pulse')) {
                el.classList.remove('pulse');
                setTimeout(() => el.classList.add('pulse'), 100);
            }
        });
    }, 2000);
}

// Rest of the functions remain the same from your original main.js
// ... (Keep all the other functions: createRipple, toggleTheme, showNotification, etc.)

// Update Uptime
function updateUptime() {
    systemUptime++;
    const hours = Math.floor(systemUptime / 3600);
    const minutes = Math.floor((systemUptime % 3600) / 60);
    const seconds = systemUptime % 60;
    
    const uptimeElement = document.getElementById('uptimeCounter');
    if (uptimeElement) {
        uptimeElement.textContent = 
            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        
        // Add subtle glow animation every 10 seconds
        if (seconds % 10 === 0) {
            uptimeElement.style.textShadow = '0 0 10px var(--neon-green)';
            setTimeout(() => {
                uptimeElement.style.textShadow = 'none';
            }, 500);
        }
    }
}

// Update System Status
function updateSystemStatus() {
    const statusIndicator = document.getElementById('systemStatus');
    if (!statusIndicator) return;
    
    fetch('/api/health')
    .then(response => response.json())
    .then(data => {
        if (data.success && data.status === 'healthy') {
            // WebSocket status takes precedence
            if (socket && socket.connected) {
                statusIndicator.className = 'status-indicator active';
                statusIndicator.title = 'REAL-TIME MONITORING ACTIVE';
                statusIndicator.style.animation = 'cyber-pulse 2s infinite';
            } else {
                statusIndicator.className = 'status-indicator';
                statusIndicator.title = 'SYSTEM STATUS: NORMAL';
                statusIndicator.style.animation = 'cyber-pulse 2s infinite';
            }
        } else {
            statusIndicator.className = 'status-indicator warning';
            statusIndicator.title = 'SYSTEM DEGRADED';
            statusIndicator.style.animation = 'cyber-pulse 1s infinite';
        }
    })
    .catch(() => {
        statusIndicator.className = 'status-indicator inactive';
        statusIndicator.title = 'SYSTEM OFFLINE';
    });
}

// Update badge counts
function updateBadgeCounts() {
    fetch('/api/get-stats')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update all badges
            const badges = {
                malware: document.getElementById('malwareAlertCount'),
                intrusion: document.getElementById('intrusionAlertCount'),
                evidence: document.getElementById('evidenceAlertCount')
            };
            
            if (badges.malware) {
                badges.malware.textContent = data.stats.malicious_files || 0;
                if (data.stats.malicious_files > 0) {
                    badges.malware.classList.add('pulse');
                } else {
                    badges.malware.classList.remove('pulse');
                }
            }
            
            if (badges.intrusion) {
                badges.intrusion.textContent = data.stats.recent_intrusions || 0;
                if (data.stats.recent_intrusions > 0) {
                    badges.intrusion.classList.add('pulse');
                } else {
                    badges.intrusion.classList.remove('pulse');
                }
            }
            
            if (badges.evidence) {
                badges.evidence.textContent = data.stats.files_scanned || 0;
            }
        }
    });
}

// Page-specific auto-refresh
function startPageAutoRefresh() {
    // Clear any existing interval
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    // Get current page
    const currentPath = window.location.pathname;
    
    // Set refresh interval based on page
    if (currentPath.includes('intrusion')) {
        // Refresh intrusions every 3 seconds (fallback if WebSocket fails)
        refreshInterval = setInterval(() => {
            if (typeof refreshIntrusions === 'function') {
                refreshIntrusions();
            }
        }, 3000);
    } else if (currentPath === '/' || currentPath.includes('dashboard')) {
        // Refresh dashboard every 5 seconds (fallback)
        refreshInterval = setInterval(() => {
            if (typeof fetchStats === 'function') {
                fetchStats();
            }
            if (typeof refreshAlerts === 'function') {
                refreshAlerts();
            }
        }, 5000);
    } else if (currentPath.includes('malware')) {
        // Refresh malware stats every 10 seconds
        refreshInterval = setInterval(() => {
            updateBadgeCounts();
        }, 10000);
    }
}

// Start Live Updates
function startLiveUpdates() {
    // Load saved theme
    const savedTheme = localStorage.getItem('sentineleye-theme') || 'dark';
    if (savedTheme === 'light') {
        document.documentElement.setAttribute('data-bs-theme', 'light');
        const icon = document.getElementById('themeIcon');
        if (icon) {
            icon.className = 'fas fa-sun';
            icon.style.color = '#ffc107';
            icon.style.filter = 'drop-shadow(0 0 10px #ffc107)';
        }
        isDarkTheme = false;
    } else {
        const icon = document.getElementById('themeIcon');
        if (icon) {
            icon.style.color = '#00f3ff';
            icon.style.filter = 'drop-shadow(0 0 10px #00f3ff)';
        }
    }
    
    // Load saved sidebar state
    const savedSidebar = localStorage.getItem('sentineleye-sidebar');
    if (savedSidebar === 'collapsed') {
        sidebarCollapsed = true;
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.getElementById('mainContent');
        if (sidebar && mainContent && window.innerWidth >= 992) {
            sidebar.style.transform = 'translateX(-280px)';
            mainContent.style.marginLeft = '0';
        }
    }
    
    // Start uptime counter
    setInterval(updateUptime, 1000);
    
    // Update system status periodically
    setInterval(updateSystemStatus, 10000);
    
    // Update badge counts periodically (fallback)
    setInterval(updateBadgeCounts, 15000);
    
    // Add CSS for animations
    addDynamicStyles();
}

// Add dynamic CSS styles for real-time features
function addDynamicStyles() {
    const style = document.createElement('style');
    style.textContent = `
        @keyframes critical-pulse {
            0%, 100% { 
                opacity: 1; 
                transform: scale(1); 
                box-shadow: 0 0 10px var(--neon-red), 0 0 20px var(--neon-red);
            }
            50% { 
                opacity: 0.5; 
                transform: scale(1.2); 
                box-shadow: 0 0 20px var(--neon-red), 0 0 40px var(--neon-red);
            }
        }
        
        .pulse {
            animation: badge-pulse 1s infinite;
        }
        
        @keyframes badge-pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        .typing-effect {
            border-right: 2px solid var(--neon-blue);
            animation: blink-caret 0.75s step-end infinite;
            overflow: hidden;
            white-space: nowrap;
        }
        
        @keyframes blink-caret {
            from, to { border-color: transparent }
            50% { border-color: var(--neon-blue) }
        }
        
        .dashboard-card:hover .card-icon {
            animation: icon-float 1s ease-in-out infinite alternate;
        }
        
        @keyframes icon-float {
            from { transform: translateY(0); }
            to { transform: translateY(-5px); }
        }
        
        .sidebar-backdrop {
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .alert-notification {
            background: var(--cyber-bg);
            border-left: 4px solid var(--cyber-primary);
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.5);
            animation: slideIn 0.3s ease;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 243, 255, 0.2);
        }
        
        .alert-notification.alert-critical {
            border-left-color: var(--neon-red);
            background: rgba(220, 53, 69, 0.1);
        }
        
        .alert-notification.alert-warning {
            border-left-color: var(--neon-yellow);
            background: rgba(255, 193, 7, 0.1);
        }
        
        .alert-notification.alert-info {
            border-left-color: var(--neon-blue);
            background: rgba(13, 202, 240, 0.1);
        }
        
        @keyframes slideIn {
            from { 
                transform: translateX(100%); 
                opacity: 0; 
            }
            to { 
                transform: translateX(0); 
                opacity: 1; 
            }
        }
        
        @keyframes slideOut {
            from { 
                transform: translateX(0); 
                opacity: 1; 
            }
            to { 
                transform: translateX(100%); 
                opacity: 0; 
            }
        }
        
        .value-changed {
            animation: valueChange 0.5s ease;
        }
        
        @keyframes valueChange {
            0%, 100% { color: inherit; }
            50% { color: var(--neon-yellow); text-shadow: 0 0 10px var(--neon-yellow); }
        }
        
        @keyframes highlightRow {
            0% { background-color: rgba(255, 193, 7, 0.3); }
            100% { background-color: transparent; }
        }
        
        #alertNotifications::-webkit-scrollbar {
            width: 6px;
        }
        
        #alertNotifications::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.2);
            border-radius: 3px;
        }
        
        #alertNotifications::-webkit-scrollbar-thumb {
            background: var(--cyber-primary);
            border-radius: 3px;
        }
        
        .alert-item {
            padding: 10px;
            margin-bottom: 8px;
            border-left: 3px solid var(--cyber-primary);
            background: rgba(0,0,0,0.2);
            border-radius: 3px;
        }
        
        .alert-item.alert-critical {
            border-left-color: var(--neon-red);
        }
        
        .alert-item.alert-warning {
            border-left-color: var(--neon-yellow);
        }
        
        .alert-item.alert-info {
            border-left-color: var(--neon-blue);
        }
    `;
    document.head.appendChild(style);
}

// Check VirusTotal API status
function checkVirusTotalStatus() {
    const vtStatus = document.getElementById('vtStatus');
    if (!vtStatus) return;
    
    fetch('/api/health')
    .then(response => response.json())
    .then(data => {
        if (data.success && data.status === 'healthy') {
            vtStatus.textContent = 'CONNECTED';
            vtStatus.className = 'fw-bold text-success';
            vtStatus.style.textShadow = '0 0 10px var(--neon-green)';
        } else {
            vtStatus.textContent = 'DEGRADED';
            vtStatus.className = 'fw-bold text-warning';
            vtStatus.style.textShadow = '0 0 10px var(--neon-yellow)';
        }
    })
    .catch(() => {
        vtStatus.textContent = 'OFFLINE';
        vtStatus.className = 'fw-bold text-danger';
        vtStatus.style.textShadow = '0 0 10px var(--neon-red)';
    });
}

// Utility function to show loading spinner
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;"></div>
                <h5 class="mt-3 text-gradient">ANALYZING DATA</h5>
                <p class="text-muted">Please wait while we process your request</p>
                <div class="progress mt-3" style="height: 8px;">
                    <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
                </div>
            </div>
        `;
    }
}

// Utility function to show error
function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="alert-cyber alert-cyber-danger">
                <div class="d-flex align-items-center">
                    <i class="fas fa-exclamation-triangle me-2" style="font-size: 1.5rem;"></i>
                    <div>
                        <h6 class="mb-1">SYSTEM ERROR</h6>
                        <p class="mb-0">${message}</p>
                    </div>
                </div>
            </div>
        `;
    }
}

// Play alert sound
function playAlertSound() {
    try {
        const muteAlerts = localStorage.getItem('muteAlerts') === 'true';
        if (muteAlerts) return;
        
        alertSound.volume = 0.3;
        alertSound.currentTime = 0;
        alertSound.play().catch(e => console.log('Audio playback failed:', e));
    } catch (e) {
        console.log('Audio error:', e);
    }
}

// Toggle alert sound
function toggleAlertSound() {
    const muteAlerts = localStorage.getItem('muteAlerts') === 'true';
    localStorage.setItem('muteAlerts', !muteAlerts);
    showNotification(`Alert sounds ${!muteAlerts ? 'muted' : 'enabled'}`, !muteAlerts ? 'warning' : 'info');
}

// Update attack statistics
function updateAttackStatistics() {
    const table = document.getElementById('intrusionsTable');
    if (!table) return;
    
    const rows = table.getElementsByTagName('tr');
    const attackCount = Math.max(0, rows.length - 1); // Subtract header row
    
    const uniqueIPs = new Set();
    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    let recentAttacks = 0;
    
    // Count unique IPs and recent attacks
    for (let i = 1; i < rows.length; i++) {
        const cells = rows[i].getElementsByTagName('td');
        if (cells.length >= 2) {
            const ip = cells[1].textContent.match(/\d+\.\d+\.\d+\.\d+/);
            if (ip) uniqueIPs.add(ip[0]);
            
            const timestamp = new Date(cells[0].textContent);
            if (timestamp > twentyFourHoursAgo) {
                recentAttacks++;
            }
        }
    }
    
    // Update statistics display
    const totalAttacks = document.getElementById('totalAttacks');
    const uniqueIPsElement = document.getElementById('uniqueIPs');
    const recentAttacksElement = document.getElementById('recentAttacks');
    
    if (totalAttacks) totalAttacks.textContent = attackCount;
    if (uniqueIPsElement) uniqueIPsElement.textContent = uniqueIPs.size;
    if (recentAttacksElement) recentAttacksElement.textContent = recentAttacks;
}

// Export functions for use in other scripts
window.SentinelEye = {
    toggleTheme,
    toggleSidebar,
    updateBadgeCounts,
    showLoading,
    showError,
    playAlertSound,
    showNotification,
    updateAttackStatistics,
    // WebSocket functions
    getSocket: () => socket,
    requestStats: () => {
        if (socket && socket.connected) {
            socket.emit('request_stats');
        }
    }
};

// Initialize on page load
window.addEventListener('load', function() {
    // Request initial stats via WebSocket
    if (socket && socket.connected) {
        socket.emit('request_stats');
    }
    
    // Check health status
    checkVirusTotalStatus();
});
