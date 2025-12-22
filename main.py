from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
import os
import threading
import sqlite3
import json
import tempfile
import hashlib
import requests
import subprocess
import time
import random
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from collections import defaultdict

# Import your modules
from modules.malware_scan import scan_with_virustotal
from modules.hashing import calculate_hash
from modules.metadata import get_metadata
from modules.filesystem_info import get_filesystems
from modules.system_scan import scan_system
from modules.deleted_content import search_deleted_files
from modules.log_monitor import LogMonitor

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'sentineleye-forensic-tool-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['DATABASE'] = 'database/forensic.db'

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# DDoS Detection Setup
request_tracker = defaultdict(list)  # Track requests per IP
IP_RATE_LIMIT = 100  # Max requests per minute
REQUEST_WINDOW = 60   # Time window in seconds

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('database', exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

# Initialize database
def init_database():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Create tables - UPDATED with all necessary tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        description TEXT,
        source TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        severity TEXT DEFAULT 'medium'
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scanned_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_hash TEXT,
        file_size INTEGER,
        scan_result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        findings TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Blocked IPs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        reason TEXT,
        duration TEXT,
        blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        status TEXT DEFAULT 'active',
        UNIQUE(ip)
    )
    ''')
    
    # Evidence items table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS evidence_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_type TEXT NOT NULL,
        content TEXT,
        hash TEXT,
        source TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Forensic sessions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS forensic_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_name TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ended_at DATETIME
    )
    ''')
    
    # File metadata table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_path TEXT,
        file_size INTEGER,
        created_time TEXT,
        modified_time TEXT,
        permissions TEXT,
        owner TEXT,
        group_name TEXT,
        hash_sha256 TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Enhanced intrusion detection tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS brute_force (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        attack_type TEXT,
        attempts INTEGER,
        message TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ddos_attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        request_count INTEGER,
        duration_seconds INTEGER,
        target_port INTEGER,
        attack_type TEXT,
        log_source TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS port_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        ports_scanned INTEGER,
        target_ports TEXT,
        message TEXT
    )
    ''')
    
    conn.commit()
    conn.close()
    print("[+] Database initialized with enhanced tables")

# Real-time alert broadcasting function
def broadcast_alert(alert_type, message, severity='medium', ip=None):
    """Broadcast alert to all connected clients"""
    alert_data = {
        'type': alert_type,
        'message': message,
        'severity': severity,
        'ip': ip,
        'timestamp': datetime.now().isoformat()
    }
    
    # Broadcast via WebSocket
    socketio.emit('new_alert', alert_data, namespace='/alerts')
    
    # Also add to database
    add_alert(alert_type, message, 'Real-time Monitor', severity)
    
    print(f"[REALTIME] {severity.upper()}: {alert_type} - {message}")

# WebSocket event handlers
@socketio.on('connect', namespace='/alerts')
def handle_connect():
    client_id = request.sid
    print(f'[WEBSOCKET] Client connected: {client_id}')
    emit('connected', {'message': 'Connected to real-time alert system', 'client_id': client_id})

@socketio.on('disconnect', namespace='/alerts')
def handle_disconnect():
    print(f'[WEBSOCKET] Client disconnected: {request.sid}')

@socketio.on('request_stats', namespace='/alerts')
def handle_stats_request():
    """Handle real-time stats requests from clients"""
    stats = get_dashboard_stats()
    emit('stats_update', stats)

# DDoS Detection Functions
def detect_flask_ddos(client_ip):
    """Detect DDoS attacks from Flask requests"""
    try:
        current_time = time.time()
        
        # Track the request
        request_tracker[client_ip].append(current_time)
        
        # Clean old requests (older than 1 minute)
        request_tracker[client_ip] = [
            t for t in request_tracker[client_ip] 
            if current_time - t < REQUEST_WINDOW
        ]
        
        request_count = len(request_tracker[client_ip])
        
        # Check if threshold exceeded
        if request_count >= IP_RATE_LIMIT:
            # Log to database
            conn = sqlite3.connect(app.config['DATABASE'])
            cursor = conn.cursor()
            
            timestamp = datetime.now().isoformat()
            
            # Insert into ddos_attacks table
            cursor.execute("""
            INSERT INTO ddos_attacks 
            (timestamp, ip, request_count, duration_seconds, target_port, attack_type, log_source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                client_ip,
                request_count,
                REQUEST_WINDOW,
                5000,  # Flask port
                "HTTP Flood",
                "Flask App"
            ))
            
            # Add alert
            alert_msg = f"DDoS attack detected from {client_ip} ({request_count} requests/minute)"
            add_alert(
                'DDoS Attack',
                alert_msg,
                'Flask Request Monitor',
                'critical'
            )
            
            # Broadcast via WebSocket
            broadcast_alert(
                'DDoS Attack',
                alert_msg,
                'critical',
                client_ip
            )
            
            # Auto-block if extreme
            if request_count >= 200:
                # Add to blocked IPs
                expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
                cursor.execute("""
                INSERT OR REPLACE INTO blocked_ips 
                (ip, reason, duration, expires_at, status)
                VALUES (?, ?, ?, ?, 'active')
                """, (
                    client_ip,
                    f'DDoS Attack ({request_count} requests/min)',
                    '1hour',
                    expires_at
                ))
                
                # Execute firewall block
                execute_firewall_block(client_ip)
                
                print(f"[DDoS BLOCK] Blocked {client_ip} for DDoS attack")
            
            conn.commit()
            conn.close()
            
            print(f"[DDoS DETECTED] {client_ip}: {request_count} requests in {REQUEST_WINDOW}s")
            
            return True  # Attack detected
            
        return False  # No attack detected
        
    except Exception as e:
        print(f"[ERROR] DDoS detection failed: {e}")
        return False

# Middleware to detect DDoS on every request
@app.before_request
def before_request():
    """Check for DDoS attacks on each request"""
    try:
        # Skip detection for certain paths if needed
        skip_paths = ['/static/', '/api/health', '/favicon.ico']
        if any(request.path.startswith(path) for path in skip_paths):
            return
        
        client_ip = request.remote_addr
        
        # Detect DDoS
        detect_flask_ddos(client_ip)
            
    except Exception as e:
        # Don't crash the app if detection fails
        print(f"[WARNING] DDoS middleware error: {e}")

def cleanup_request_tracker():
    """Periodically clean old entries from request tracker"""
    while True:
        try:
            current_time = time.time()
            for ip in list(request_tracker.keys()):
                # Remove entries older than 5 minutes
                request_tracker[ip] = [
                    t for t in request_tracker[ip]
                    if current_time - t < 300  # 5 minutes
                ]
                # Remove IP if no recent requests
                if not request_tracker[ip]:
                    del request_tracker[ip]
            
            time.sleep(60)  # Clean every minute
        except Exception as e:
            print(f"[ERROR] Request tracker cleanup failed: {e}")
            time.sleep(10)

# Real-time stats broadcaster thread
def broadcast_stats():
    """Continuously broadcast system stats to all connected clients"""
    while True:
        try:
            stats = get_dashboard_stats()
            socketio.emit('stats_update', stats, namespace='/alerts')
            
            # Broadcast recent attacks
            recent_attacks = get_recent_attacks(5)
            if recent_attacks:
                socketio.emit('recent_attacks', recent_attacks, namespace='/alerts')
            
            time.sleep(5)  # Update every 5 seconds
            
        except Exception as e:
            print(f"[ERROR] Stats broadcast failed: {e}")
            time.sleep(10)

# Start stats broadcaster
def start_stats_broadcaster():
    stats_thread = threading.Thread(target=broadcast_stats, daemon=True)
    stats_thread.start()
    print("[+] Real-time stats broadcaster started")

# Initialize log monitor
log_monitor = None
def start_log_monitor():
    global log_monitor
    try:
        log_monitor = LogMonitor()
        t = threading.Thread(target=log_monitor.start_monitoring, daemon=True)
        t.start()
        print("[+] Enhanced log monitor started")
        
        # Start demo data generator for testing (if enabled)
        if os.environ.get('DEMO_MODE', '0') == '1':
            threading.Thread(target=generate_demo_attacks, daemon=True).start()
            print("[+] Demo attack generator started")
            
    except Exception as e:
        print(f"[-] Could not start log monitor: {e}")
        create_demo_intrusion_data()

# Demo attack generator (for testing)
def generate_demo_attacks():
    """Generate realistic demo attacks for testing UI"""
    demo_ips = [
        '192.168.1.100', '10.0.0.15', '172.16.0.23', 
        '203.0.113.45', '198.51.100.23', '141.101.120.34',
        '185.220.101.4', '45.61.185.200', '91.92.109.43'
    ]
    
    attack_types = [
        'SSH Brute Force', 'Web Login Attack', 'DDoS Attack',
        'Port Scan', 'SQL Injection', 'XSS Attack', 'FTP Brute Force'
    ]
    
    while True:
        try:
            # Randomly generate attacks (30% chance per iteration)
            if random.random() < 0.3:
                ip = random.choice(demo_ips)
                attack = random.choice(attack_types)
                attempts = random.randint(5, 50)
                
                # Add to database
                conn = sqlite3.connect(app.config['DATABASE'])
                cursor = conn.cursor()
                
                if attack == 'DDoS Attack':
                    # Add DDoS attack
                    cursor.execute("""
                    INSERT INTO ddos_attacks (timestamp, ip, request_count, duration_seconds, 
                                            target_port, attack_type, log_source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        datetime.now().isoformat(),
                        ip,
                        random.randint(100, 500),
                        60,
                        80,
                        "HTTP Flood",
                        "Demo Generator"
                    ))
                else:
                    # Add brute force attack
                    cursor.execute("""
                    INSERT INTO brute_force (timestamp, ip, attack_type, attempts, message)
                    VALUES (?, ?, ?, ?, ?)
                    """, (
                        datetime.now().isoformat(),
                        ip,
                        attack,
                        attempts,
                        f"Demo {attack} from {ip} - {attempts} attempts"
                    ))
                
                conn.commit()
                conn.close()
                
                # Broadcast alert (50% of demo attacks trigger alerts)
                if random.random() < 0.5:
                    severity = 'critical' if 'DDoS' in attack or attempts > 30 else 'warning'
                    broadcast_alert(
                        attack, 
                        f"Demo {attack} detected from {ip} ({attempts} attempts)",
                        severity,
                        ip
                    )
            
            # Random interval between attacks
            time.sleep(random.randint(10, 60))
            
        except Exception as e:
            print(f"[DEMO] Error: {e}")
            time.sleep(10)

def create_demo_intrusion_data():
    """Create demo intrusion data for testing"""
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Add some demo data
        demo_ips = ['192.168.1.100', '10.0.0.15', '172.16.0.23', '203.0.113.45']
        for i in range(15):
            ip = random.choice(demo_ips)
            attempts = random.randint(3, 25)
            cursor.execute(
                """INSERT INTO brute_force (timestamp, ip, attack_type, attempts, message) 
                   VALUES (?, ?, ?, ?, ?)""",
                (datetime.now().isoformat(), ip, 'SSH Brute Force', attempts, 
                 f"Failed password for root from {ip} port 22 ssh2 - {attempts} attempts")
            )
        
        # Add demo DDoS attacks
        for i in range(3):
            ip = random.choice(demo_ips)
            cursor.execute("""
            INSERT INTO ddos_attacks (timestamp, ip, request_count, duration_seconds, 
                                     target_port, attack_type, log_source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                ip,
                random.randint(150, 300),
                60,
                random.choice([80, 443, 22]),
                random.choice(["HTTP Flood", "HTTPS Flood", "SSH Flood"]),
                "Demo Data"
            ))
        
        conn.commit()
        conn.close()
        print("[+] Created demo intrusion data")
    except Exception as e:
        print(f"[-] Error creating demo data: {e}")

# Helper functions
def get_recent_alerts(limit=50):
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT alert_type, description, source, timestamp, severity 
    FROM alerts 
    ORDER BY timestamp DESC 
    LIMIT ?
    ''', (limit,))
    
    alerts = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts
    return [{
        'type': alert[0],
        'description': alert[1],
        'source': alert[2],
        'timestamp': alert[3],
        'severity': alert[4]
    } for alert in alerts]

def add_alert(alert_type, description, source, severity='medium'):
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO alerts (alert_type, description, source, severity) 
    VALUES (?, ?, ?, ?)
    ''', (alert_type, description, source, severity))
    conn.commit()
    conn.close()
    
    # Broadcast to WebSocket clients
    alert_data = {
        'type': alert_type,
        'message': description,
        'severity': severity,
        'source': source,
        'timestamp': datetime.now().isoformat()
    }
    socketio.emit('new_alert', alert_data, namespace='/alerts')

def get_dashboard_stats():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    stats = {}
    
    # Total alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    stats['total_alerts'] = cursor.fetchone()[0]
    
    # Critical alerts
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'critical'")
    stats['critical_alerts'] = cursor.fetchone()[0]
    
    # Total files scanned
    cursor.execute("SELECT COUNT(*) FROM scanned_files")
    stats['files_scanned'] = cursor.fetchone()[0]
    
    # Malicious files
    cursor.execute("SELECT COUNT(*) FROM scanned_files WHERE scan_result LIKE '%malicious%' OR scan_result LIKE '%\"malicious\":%'")
    malicious_count = cursor.fetchone()[0]
    stats['malicious_files'] = malicious_count
    
    # Blocked IPs
    cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE status = 'active'")
    stats['blocked_ips'] = cursor.fetchone()[0]
    
    # Evidence items
    cursor.execute("SELECT COUNT(*) FROM evidence_items")
    stats['evidence_items'] = cursor.fetchone()[0]
    
    # Active intrusions (last 24 hours)
    twenty_four_hours_ago = (datetime.now() - timedelta(hours=24)).isoformat()
    cursor.execute("SELECT COUNT(*) FROM brute_force WHERE timestamp > ?", (twenty_four_hours_ago,))
    stats['recent_intrusions'] = cursor.fetchone()[0]
    
    # Recent attacks (last 5 minutes)
    five_minutes_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
    cursor.execute("SELECT COUNT(*) FROM brute_force WHERE timestamp > ?", (five_minutes_ago,))
    stats['recent_attacks_5min'] = cursor.fetchone()[0]
    
    # DDoS attacks (last 24 hours)
    cursor.execute("SELECT COUNT(*) FROM ddos_attacks WHERE timestamp > ?", (twenty_four_hours_ago,))
    stats['ddos_attacks'] = cursor.fetchone()[0]
    
    # Port scans (last 24 hours)
    cursor.execute("SELECT COUNT(*) FROM port_scans WHERE timestamp > ?", (twenty_four_hours_ago,))
    stats['port_scans'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

def get_recent_attacks(limit=10):
    """Get recent attacks for real-time display"""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Get brute force attacks
    cursor.execute("""
    SELECT timestamp, ip, attack_type, attempts, 'brute_force' as source
    FROM brute_force 
    ORDER BY timestamp DESC 
    LIMIT ?
    """, (limit,))
    
    brute_force = cursor.fetchall()
    
    # Get DDoS attacks
    cursor.execute("""
    SELECT timestamp, ip, attack_type, request_count, 'ddos' as source
    FROM ddos_attacks 
    ORDER BY timestamp DESC 
    LIMIT ?
    """, (limit,))
    
    ddos = cursor.fetchall()
    
    conn.close()
    
    attacks = []
    
    # Combine both types
    for attack in brute_force + ddos:
        attacks.append({
            'timestamp': attack[0],
            'ip': attack[1],
            'type': attack[2],
            'attempts': attack[3] if attack[4] == 'brute_force' else f"{attack[3]} requests",
            'source': attack[4]
        })
    
    # Sort by timestamp
    attacks.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return attacks[:limit]

# Routes
@app.route('/')
def index():
    stats = get_dashboard_stats()
    alerts = get_recent_alerts(10)
    return render_template('dashboard.html', 
                         stats=stats, 
                         alerts=alerts,
                         active_page='dashboard')

@app.route('/dashboard')
def dashboard():
    return index()

@app.route('/malware')
def malware_dashboard():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scanned_files ORDER BY timestamp DESC LIMIT 20")
    files = cursor.fetchall()
    conn.close()
    
    file_data = []
    for f in files:
        try:
            result = json.loads(f[4]) if f[4] else {}
        except:
            result = {}
        
        file_data.append({
            'id': f[0],
            'filename': f[1],
            'hash': f[2],
            'size': f[3],
            'result': result,
            'timestamp': f[5]
        })
    
    return render_template('malware.html', 
                         files=file_data,
                         active_page='malware')

@app.route('/intrusion')
def intrusion_dashboard():
    # Get brute force attempts
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    try:
        # Get brute force attacks
        cursor.execute("""
        SELECT timestamp, ip, attack_type, attempts, message 
        FROM brute_force 
        ORDER BY timestamp DESC 
        LIMIT 50
        """)
        
        intrusion_data = cursor.fetchall()
        print(f"[DEBUG] Found {len(intrusion_data)} intrusion records")
        
        intrusions = []
        for data in intrusion_data:
            intrusions.append({
                'timestamp': data[0],
                'ip': data[1],
                'attack_type': data[2],
                'attempts': data[3],
                'message': data[4]
            })
        
    except Exception as e:
        print(f"[ERROR] Error fetching intrusions: {e}")
        intrusions = []
    
    # Get DDoS attacks
    try:
        cursor.execute("""
        SELECT timestamp, ip, request_count, duration_seconds, target_port, attack_type, log_source
        FROM ddos_attacks 
        ORDER BY timestamp DESC 
        LIMIT 10
        """)
        ddos_attacks = cursor.fetchall()
        
        ddos = []
        for attack in ddos_attacks:
            ddos.append({
                'timestamp': attack[0],
                'ip': attack[1],
                'requests': attack[2],
                'duration': attack[3],
                'port': attack[4],
                'type': attack[5],
                'source': attack[6]
            })
        
        print(f"[DEBUG] Found {len(ddos)} DDoS attacks")
    except Exception as e:
        print(f"[ERROR] Error fetching DDoS attacks: {e}")
        ddos = []
    
    # Get blocked IPs
    try:
        cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT 10")
        blocked_ips = cursor.fetchall()
        
        blocked = []
        for ip in blocked_ips:
            if len(ip) >= 7:
                blocked.append({
                    'id': ip[0],
                    'ip': ip[1],
                    'reason': ip[2],
                    'duration': ip[3],
                    'blocked_at': ip[4],
                    'expires_at': ip[5],
                    'status': ip[6]
                })
            elif len(ip) >= 4:
                blocked.append({
                    'id': ip[0],
                    'ip': ip[1],
                    'reason': ip[2],
                    'blocked_at': ip[3],
                    'status': 'active'
                })
        
        print(f"[DEBUG] Found {len(blocked)} blocked IPs")
    except Exception as e:
        print(f"[ERROR] Error fetching blocked IPs: {e}")
        blocked = []
    
    conn.close()
    
    return render_template('intrusion.html', 
                         intrusions=intrusions,
                         blocked_ips=blocked,
                         ddos_attacks=ddos,
                         active_page='intrusion')

@app.route('/evidence')
def evidence_browser():
    # Get available file systems
    filesystems = get_filesystems()
    
    # Get recent system scans
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM system_scans ORDER BY timestamp DESC LIMIT 5")
    system_scans = cursor.fetchall()
    conn.close()
    
    scans = []
    for scan in system_scans:
        try:
            findings = json.loads(scan[2]) if scan[2] else []
        except:
            findings = []
        
        scans.append({
            'id': scan[0],
            'type': scan[1],
            'findings': findings,
            'timestamp': scan[3]
        })
    
    # Get evidence items
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence_items ORDER BY timestamp DESC LIMIT 10")
    evidence_items = cursor.fetchall()
    conn.close()
    
    evidence = []
    for item in evidence_items:
        evidence.append({
            'id': item[0],
            'type': item[1],
            'content': item[2][:100] + "..." if item[2] and len(item[2]) > 100 else item[2],
            'hash': item[3],
            'source': item[4],
            'timestamp': item[5]
        })
    
    return render_template('evidence.html', 
                         filesystems=filesystems,
                         system_scans=scans,
                         evidence_items=evidence,
                         active_page='evidence')

# API Endpoints
@app.route('/api/scan-file', methods=['POST'])
def api_scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save file temporarily
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Calculate hash
        file_hash = calculate_hash(filepath)
        
        # Get metadata
        metadata = get_metadata(filepath)
        
        # Save file metadata to database
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO file_metadata (filename, file_path, file_size, created_time, 
                                  modified_time, permissions, hash_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (filename, filepath, metadata['size'], metadata['created'], 
              metadata['last_modified'], metadata['permissions'], file_hash))
        
        # Scan with VirusTotal
        vt_result = scan_with_virustotal(filepath)
        
        # Save to scanned files
        cursor.execute('''
        INSERT INTO scanned_files (filename, file_hash, file_size, scan_result)
        VALUES (?, ?, ?, ?)
        ''', (filename, file_hash, metadata['size'], json.dumps(vt_result)))
        
        # Save as evidence item
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, hash, source)
        VALUES (?, ?, ?, ?)
        ''', ('scanned_file', json.dumps({
            'filename': filename,
            'metadata': metadata,
            'virustotal': vt_result
        }), file_hash, 'File Scanner'))
        
        conn.commit()
        conn.close()
        
        # Add alert if malicious
        if 'malicious' in vt_result and vt_result['malicious'] > 0:
            add_alert('Malware Detected', 
                     f'File {filename} detected as malicious by {vt_result["malicious"]} engines',
                     'VirusTotal API', 
                     'critical')
        else:
            add_alert('File Scanned', 
                     f'File {filename} scanned successfully',
                     'File Scanner', 
                     'info')
        
        # Clean up
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'hash': file_hash,
            'metadata': metadata,
            'virustotal': vt_result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-system', methods=['POST'])
def api_scan_system():
    try:
        data = request.json
        directory = data.get('directory', '/home')
        file_types = data.get('file_types', ['.exe', '.bat', '.sh', '.py'])
        
        # If file_types is a string, split it
        if isinstance(file_types, str):
            file_types = [ft.strip() for ft in file_types.split(',')]
        
        suspicious_files = []
        
        # Perform the scan
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ft) for ft in file_types):
                    full_path = os.path.join(root, file)
                    suspicious_files.append(full_path)
        
        # Save scan results
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO system_scans (scan_type, findings)
        VALUES (?, ?)
        ''', ('System Scan', json.dumps(suspicious_files)))
        
        # Save as evidence item
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, source)
        VALUES (?, ?, ?)
        ''', ('system_scan', json.dumps({
            'directory': directory,
            'file_types': file_types,
            'files_found': suspicious_files,
            'count': len(suspicious_files)
        }), 'System Scanner'))
        
        conn.commit()
        conn.close()
        
        # Add alert if suspicious files found
        if suspicious_files:
            add_alert('Suspicious Files Found',
                     f'Found {len(suspicious_files)} suspicious files in {directory}',
                     'System Scanner',
                     'warning')
        else:
            add_alert('System Scan Complete',
                     f'No suspicious files found in {directory}',
                     'System Scanner',
                     'info')
        
        return jsonify({
            'success': True,
            'directory': directory,
            'file_types': file_types,
            'suspicious_files': suspicious_files,
            'count': len(suspicious_files)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-deleted-content', methods=['GET'])
def api_get_deleted_content():
    try:
        content = search_deleted_files()
        
        # Save as evidence item
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, source)
        VALUES (?, ?, ?)
        ''', ('deleted_content', content[:5000], 'Deleted Content Scanner'))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'content': content[:5000]  # Limit output
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-filesystems', methods=['GET'])
def api_get_filesystems():
    try:
        filesystems = get_filesystems()
        
        # Save as evidence item
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, source)
        VALUES (?, ?, ?)
        ''', ('filesystem_info', json.dumps(filesystems), 'File System Scanner'))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'filesystems': filesystems
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-alerts', methods=['GET'])
def api_get_alerts():
    limit = request.args.get('limit', 50, type=int)
    alerts = get_recent_alerts(limit)
    return jsonify({
        'success': True,
        'alerts': alerts
    })

@app.route('/api/get-stats', methods=['GET'])
def api_get_stats():
    stats = get_dashboard_stats()
    return jsonify({
        'success': True,
        'stats': stats
    })

@app.route('/api/get-latest-intrusions', methods=['GET'])
def api_get_latest_intrusions():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("""
    SELECT timestamp, ip, attack_type, attempts, message 
    FROM brute_force 
    ORDER BY timestamp DESC 
    LIMIT 50
    """)
    intrusions = cursor.fetchall()
    conn.close()
    
    intrusion_data = []
    for i in intrusions:
        intrusion_data.append({
            'timestamp': i[0],
            'ip': i[1],
            'attack_type': i[2],
            'attempts': i[3],
            'message': i[4]
        })
    
    return jsonify({
        'success': True,
        'intrusions': intrusion_data
    })

@app.route('/api/get-recent-attacks', methods=['GET'])
def api_get_recent_attacks():
    """Get recent attacks for real-time display"""
    limit = request.args.get('limit', 10, type=int)
    attacks = get_recent_attacks(limit)
    return jsonify({
        'success': True,
        'attacks': attacks,
        'count': len(attacks)
    })

@app.route('/api/get-ddos-attacks', methods=['GET'])
def api_get_ddos_attacks():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("""
    SELECT timestamp, ip, request_count, duration_seconds, target_port, attack_type, log_source
    FROM ddos_attacks 
    ORDER BY timestamp DESC 
    LIMIT 20
    """)
    ddos_attacks = cursor.fetchall()
    conn.close()
    
    attacks = []
    for attack in ddos_attacks:
        attacks.append({
            'timestamp': attack[0],
            'ip': attack[1],
            'requests': attack[2],
            'duration': attack[3],
            'port': attack[4],
            'type': attack[5],
            'source': attack[6]
        })
    
    return jsonify({
        'success': True,
        'ddos_attacks': attacks,
        'count': len(attacks)
    })

# IP Blocking API Endpoints
@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    try:
        data = request.json
        ip = data.get('ip')
        duration = data.get('duration', 'permanent')
        reason = data.get('reason', 'Security threat')
        
        if not ip:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Calculate expiration time
        expires_at = None
        if duration != 'permanent':
            try:
                hours = int(duration)
                expires_at = (datetime.now() + timedelta(hours=hours)).isoformat()
            except:
                expires_at = None
        
        # Save to database
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Check if IP is already blocked
        cursor.execute("SELECT id FROM blocked_ips WHERE ip = ? AND status = 'active'", (ip,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': f'IP {ip} is already blocked'}), 400
        
        cursor.execute('''
        INSERT INTO blocked_ips (ip, reason, duration, expires_at)
        VALUES (?, ?, ?, ?)
        ''', (ip, reason, duration, expires_at))
        
        # Add as evidence item
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, source)
        VALUES (?, ?, ?)
        ''', ('blocked_ip', json.dumps({
            'ip': ip,
            'reason': reason,
            'duration': duration,
            'expires_at': expires_at
        }), 'Intrusion Detection'))
        
        conn.commit()
        conn.close()
        
        # Add alert and broadcast
        alert_msg = f'IP address {ip} blocked: {reason}'
        add_alert('IP Blocked', alert_msg, 'Firewall', 'warning')
        
        # Broadcast real-time update
        broadcast_alert('IP Blocked', alert_msg, 'warning', ip)
        
        # Execute actual firewall block
        execute_firewall_block(ip)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip} blocked successfully',
            'ip': ip,
            'duration': duration,
            'reason': reason,
            'expires_at': expires_at
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def execute_firewall_block(ip):
    """Execute actual firewall blocking commands"""
    try:
        commands = [
            f"sudo iptables -A INPUT -s {ip} -j DROP",
            f"sudo ip6tables -A INPUT -s {ip} -j DROP"
        ]
        
        for cmd in commands:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    print(f"[FIREWALL] Successfully blocked {ip}")
                else:
                    print(f"[FIREWALL WARNING] Command failed: {result.stderr}")
            except subprocess.CalledProcessError as e:
                print(f"[WARNING] Failed to execute {cmd}: {e}")
            except subprocess.TimeoutExpired:
                print(f"[WARNING] Timeout executing {cmd}")
                
    except Exception as e:
        print(f"[ERROR] Firewall block failed: {e}")

@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    try:
        data = request.json
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP address is required'}), 400
        
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Update status to inactive
        cursor.execute("UPDATE blocked_ips SET status = 'inactive' WHERE ip = ?", (ip,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': f'IP {ip} not found or already unblocked'}), 404
        
        # Add as evidence item
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, source)
        VALUES (?, ?, ?)
        ''', ('unblocked_ip', json.dumps({'ip': ip}), 'Intrusion Detection'))
        
        conn.commit()
        conn.close()
        
        # Add alert
        add_alert('IP Unblocked', 
                 f'IP address {ip} unblocked',
                 'Firewall', 
                 'info')
        
        # Remove from firewall
        execute_firewall_unblock(ip)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip} unblocked successfully',
            'ip': ip
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def execute_firewall_unblock(ip):
    """Remove IP from firewall block list"""
    try:
        commands = [
            f"sudo iptables -D INPUT -s {ip} -j DROP",
            f"sudo ip6tables -D INPUT -s {ip} -j DROP"
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=False, timeout=5)
                print(f"[FIREWALL] Unblocked {ip} successfully")
            except:
                pass  # Command might fail if rule doesn't exist
            
    except Exception as e:
        print(f"[ERROR] Firewall unblock failed: {e}")

@app.route('/api/analyze-metadata', methods=['POST'])
def api_analyze_metadata():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save file temporarily
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Get metadata
        metadata = get_metadata(filepath)
        
        # Calculate hash
        file_hash = calculate_hash(filepath)
        
        # Save to file_metadata table
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO file_metadata (filename, file_path, file_size, created_time, 
                                  modified_time, permissions, hash_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (filename, filepath, metadata['size'], metadata['created'], 
              metadata['last_modified'], metadata['permissions'], file_hash))
        
        # Save as evidence item
        cursor.execute('''
        INSERT INTO evidence_items (item_type, content, hash, source)
        VALUES (?, ?, ?, ?)
        ''', ('file_metadata', json.dumps(metadata), file_hash, 'Metadata Analyzer'))
        
        conn.commit()
        conn.close()
        
        # Add alert
        add_alert('Metadata Analyzed', 
                 f'File {filename} metadata analyzed',
                 'Metadata Analyzer', 
                 'info')
        
        # Clean up
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'hash': file_hash,
            'metadata': metadata
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-all-evidence', methods=['GET'])
def api_get_all_evidence():
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Get all data
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
        alerts = cursor.fetchall()
        
        cursor.execute("SELECT * FROM brute_force ORDER BY timestamp DESC LIMIT 100")
        intrusions = cursor.fetchall()
        
        cursor.execute("SELECT * FROM scanned_files ORDER BY timestamp DESC LIMIT 50")
        files = cursor.fetchall()
        
        cursor.execute("SELECT * FROM system_scans ORDER BY timestamp DESC LIMIT 20")
        scans = cursor.fetchall()
        
        cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT 50")
        blocked = cursor.fetchall()
        
        cursor.execute("SELECT * FROM evidence_items ORDER BY timestamp DESC LIMIT 100")
        evidence = cursor.fetchall()
        
        cursor.execute("SELECT * FROM file_metadata ORDER BY timestamp DESC LIMIT 50")
        file_metadata = cursor.fetchall()
        
        cursor.execute("SELECT * FROM ddos_attacks ORDER BY timestamp DESC LIMIT 20")
        ddos_attacks = cursor.fetchall()
        
        cursor.execute("SELECT * FROM port_scans ORDER BY timestamp DESC LIMIT 20")
        port_scans = cursor.fetchall()
        
        conn.close()
        
        # Format data
        evidence_data = {
            'alerts': [
                {
                    'id': alert[0],
                    'type': alert[1],
                    'description': alert[2],
                    'source': alert[3],
                    'timestamp': alert[4],
                    'severity': alert[5]
                } for alert in alerts
            ],
            'intrusions': [
                {
                    'id': intrusion[0],
                    'timestamp': intrusion[1],
                    'ip': intrusion[2],
                    'attack_type': intrusion[3],
                    'attempts': intrusion[4],
                    'message': intrusion[5]
                } for intrusion in intrusions
            ],
            'scanned_files': [
                {
                    'id': file[0],
                    'filename': file[1],
                    'hash': file[2],
                    'size': file[3],
                    'scan_result': json.loads(file[4]) if file[4] else {},
                    'timestamp': file[5]
                } for file in files
            ],
            'system_scans': [
                {
                    'id': scan[0],
                    'type': scan[1],
                    'findings': json.loads(scan[2]) if scan[2] else [],
                    'timestamp': scan[3]
                } for scan in scans
            ],
            'blocked_ips': [
                {
                    'id': ip[0],
                    'ip': ip[1],
                    'reason': ip[2],
                    'duration': ip[3],
                    'blocked_at': ip[4],
                    'expires_at': ip[5],
                    'status': ip[6]
                } for ip in blocked
            ],
            'evidence_items': [
                {
                    'id': item[0],
                    'type': item[1],
                    'content': item[2],
                    'hash': item[3],
                    'source': item[4],
                    'timestamp': item[5]
                } for item in evidence
            ],
            'file_metadata': [
                {
                    'id': meta[0],
                    'filename': meta[1],
                    'file_path': meta[2],
                    'file_size': meta[3],
                    'created_time': meta[4],
                    'modified_time': meta[5],
                    'permissions': meta[6],
                    'owner': meta[7],
                    'group': meta[8],
                    'hash': meta[9],
                    'timestamp': meta[10]
                } for meta in file_metadata
            ],
            'ddos_attacks': [
                {
                    'id': attack[0],
                    'timestamp': attack[1],
                    'ip': attack[2],
                    'requests': attack[3],
                    'duration': attack[4],
                    'port': attack[5],
                    'type': attack[6],
                    'source': attack[7]
                } for attack in ddos_attacks
            ],
            'port_scans': [
                {
                    'id': scan[0],
                    'timestamp': scan[1],
                    'ip': scan[2],
                    'ports_scanned': scan[3],
                    'target_ports': scan[4],
                    'message': scan[5]
                } for scan in port_scans
            ],
            'export_timestamp': datetime.now().isoformat(),
            'filesystems': get_filesystems(),
            'export_info': {
                'tool': 'SentinelEye',
                'version': '2.1',
                'export_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        
        return jsonify({
            'success': True,
            'evidence': evidence_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export-evidence', methods=['GET'])
def api_export_evidence():
    try:
        # Get all evidence data
        response = api_get_all_evidence()
        data = response.get_json()
        
        if not data or not data.get('success'):
            return jsonify({'error': 'Failed to gather evidence data'}), 500
        
        # Create a temporary file for export
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data['evidence'], f, indent=2, default=str)
            temp_path = f.name
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'sentineleye_evidence_export_{timestamp}.json'
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-blocked-ips', methods=['GET'])
def api_get_blocked_ips():
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_ips WHERE status = 'active' ORDER BY blocked_at DESC")
        blocked_ips = cursor.fetchall()
        conn.close()
        
        ips = []
        for ip in blocked_ips:
            ips.append({
                'id': ip[0],
                'ip': ip[1],
                'reason': ip[2],
                'duration': ip[3],
                'blocked_at': ip[4],
                'expires_at': ip[5],
                'status': ip[6]
            })
        
        return jsonify({
            'success': True,
            'blocked_ips': ips,
            'count': len(ips)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-evidence', methods=['POST'])
def api_clear_evidence():
    try:
        confirmation = request.json.get('confirmation', '')
        
        if confirmation != 'DELETE_ALL_EVIDENCE':
            return jsonify({'error': 'Confirmation required. Send {"confirmation": "DELETE_ALL_EVIDENCE"}'}), 400
        
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Clear evidence tables (keep structure)
        tables = ['evidence_items', 'alerts', 'scanned_files', 'system_scans', 'blocked_ips', 'file_metadata']
        for table in tables:
            cursor.execute(f"DELETE FROM {table}")
        
        # Reset intrusion tables
        cursor.execute("DELETE FROM brute_force")
        cursor.execute("DELETE FROM ddos_attacks")
        cursor.execute("DELETE FROM port_scans")
        
        conn.commit()
        conn.close()
        
        add_alert('Evidence Cleared', 
                 'All evidence data has been cleared',
                 'System', 
                 'warning')
        
        return jsonify({
            'success': True,
            'message': 'All evidence data cleared successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def api_health():
    try:
        # Check database connection
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        db_ok = cursor.fetchone() is not None
        conn.close()
        
        # Check upload directory
        upload_ok = os.path.exists(app.config['UPLOAD_FOLDER'])
        
        # Check if modules are importable
        modules_ok = all([
            'scan_with_virustotal' in dir(),
            'calculate_hash' in dir(),
            'get_metadata' in dir(),
            'get_filesystems' in dir(),
            'scan_system' in dir(),
            'search_deleted_files' in dir()
        ])
        
        # Check WebSocket status
        ws_ok = socketio is not None
        
        # Check DDoS detection status
        ddos_active = len(request_tracker) >= 0  # Always true if initialized
        
        return jsonify({
            'success': True,
            'status': 'healthy',
            'components': {
                'database': 'ok' if db_ok else 'error',
                'upload_directory': 'ok' if upload_ok else 'error',
                'modules': 'ok' if modules_ok else 'error',
                'log_monitor': 'running' if log_monitor else 'stopped',
                'websocket': 'running' if ws_ok else 'stopped',
                'ddos_detection': 'active' if ddos_active else 'inactive',
                'tracked_ips': len(request_tracker)
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Initialize the application
if __name__ == '__main__':
    print("[+] Initializing SentinelEye Cybersecurity Platform...")
    init_database()
    start_log_monitor()
    start_stats_broadcaster()
    
    # Start request tracker cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_request_tracker, daemon=True)
    cleanup_thread.start()
    print("[+] Request tracker cleanup started")
    
    print("[+] Starting SentinelEye Flask application with WebSocket...")
    print("[+] Access the dashboard at http://localhost:5000")
    print("[+] WebSocket available at ws://localhost:5000/alerts")
    print("[+] DDoS Detection: Active (threshold: 100 requests/min)")
    print("[+] Auto-blocking: Enabled for >200 requests/min")
    print("[+] API Documentation:")
    print("    - GET  /api/health              - Health check")
    print("    - GET  /api/stats               - Dashboard statistics")
    print("    - GET  /api/alerts              - Recent alerts")
    print("    - POST /api/scan-file           - Scan file for malware")
    print("    - POST /api/scan-system         - Scan system for suspicious files")
    print("    - POST /api/block-ip            - Block malicious IP address")
    print("    - GET  /api/get-recent-attacks  - Get recent intrusion attempts")
    print("    - GET  /api/export-evidence     - Export all evidence as JSON")
    
    # Run with SocketIO
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
