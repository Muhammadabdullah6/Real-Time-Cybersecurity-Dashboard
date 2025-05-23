import os
import sys
import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import random

# Try to import required libraries, install if missing
def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        print(f"Installing {package}...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install required packages
install_and_import('flask')
install_and_import('psutil')

from flask import Flask, render_template_string, jsonify
import psutil

app = Flask(__name__)

class SimpleCyberDashboard:
    def __init__(self):
        self.threats = []
        self.alerts = []
        self.connections = []
        self.system_stats = []
        self.is_monitoring = False
        self.start_time = datetime.now()
        
        # Simple threat indicators
        self.suspicious_ips = {
            "185.220.100.240", "198.96.155.3", "89.234.157.254",
            "192.42.116.16", "185.220.101.40", "199.87.154.255"
        }
        
        self.suspicious_ports = {22, 23, 135, 139, 445, 1433, 3389, 5900}
        
        print("🛡️ Simple Cyber Dashboard Starting...")
        self.start_monitoring()
    
    def get_system_info(self):
        """Get basic system information"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Disk usage
            try:
                disk = psutil.disk_usage('/' if os.name != 'nt' else 'C:')
                disk_percent = (disk.used / disk.total) * 100
            except:
                disk_percent = 0
            
            # Network
            try:
                net_io = psutil.net_io_counters()
                network_sent = net_io.bytes_sent / (1024 * 1024)  # MB
                network_recv = net_io.bytes_recv / (1024 * 1024)  # MB
            except:
                network_sent = network_recv = 0
            
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk_percent,
                'network_sent': network_sent,
                'network_recv': network_recv,
                'processes': len(psutil.pids())
            }
        except Exception as e:
            print(f"Error getting system info: {e}")
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_percent': 0,
                'network_sent': 0,
                'network_recv': 0,
                'processes': 0
            }
    
    def get_network_connections(self):
        """Get active network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Check if suspicious
                    is_suspicious = (
                        remote_ip in self.suspicious_ips or
                        remote_port in self.suspicious_ports
                    )
                    
                    # Get process name
                    try:
                        process = psutil.Process(conn.pid) if conn.pid else None
                        process_name = process.name() if process else "Unknown"
                    except:
                        process_name = "Unknown"
                    
                    connection = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_addr': f"{remote_ip}:{remote_port}",
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'process': process_name,
                        'suspicious': is_suspicious,
                        'timestamp': datetime.now().strftime('%H:%M:%S')
                    }
                    
                    connections.append(connection)
                    
                    # Create alert for suspicious connections
                    if is_suspicious:
                        self.create_alert(
                            "Suspicious Connection",
                            f"Connection to {remote_ip}:{remote_port}",
                            "Medium" if remote_ip in self.suspicious_ips else "Low"
                        )
        except Exception as e:
            print(f"Error getting connections: {e}")
        
        return connections
    
    def scan_processes(self):
        """Scan for suspicious processes"""
        suspicious_processes = []
        suspicious_names = ['nc.exe', 'netcat', 'telnet', 'psexec', 'mimikatz']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    # Check for suspicious names or high CPU
                    is_suspicious = (
                        any(sus_name in proc_name for sus_name in suspicious_names) or
                        proc_info['cpu_percent'] > 80
                    )
                    
                    if is_suspicious:
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'reason': 'Suspicious name' if any(sus_name in proc_name for sus_name in suspicious_names) else 'High CPU'
                        })
                        
                        self.create_alert(
                            "Suspicious Process",
                            f"Process {proc_info['name']} (PID: {proc_info['pid']})",
                            "High" if any(sus_name in proc_name for sus_name in suspicious_names) else "Medium"
                        )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error scanning processes: {e}")
        
        return suspicious_processes
    
    def create_alert(self, alert_type, message, severity):
        """Create a security alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert_type,
            'message': message,
            'severity': severity
        }
        
        self.alerts.append(alert)
        self.threats.append(alert)
        
        # Keep only recent alerts
        if len(self.alerts) > 50:
            self.alerts = self.alerts[-50:]
        
        print(f"🚨 {severity} Alert: {alert_type} - {message}")
    
    def start_monitoring(self):
        """Start monitoring in background"""
        self.is_monitoring = True
        
        def monitor_loop():
            while self.is_monitoring:
                try:
                    # Get system stats
                    stats = self.get_system_info()
                    self.system_stats.append(stats)
                    
                    # Keep only recent stats
                    if len(self.system_stats) > 60:
                        self.system_stats = self.system_stats[-60:]
                    
                    # Monitor connections
                    self.connections = self.get_network_connections()
                    
                    # Scan processes occasionally
                    if len(self.system_stats) % 6 == 0:  # Every 30 seconds
                        self.scan_processes()
                    
                    # Check for system anomalies
                    if stats['cpu_percent'] > 90:
                        self.create_alert("High CPU Usage", f"CPU at {stats['cpu_percent']:.1f}%", "Medium")
                    
                    if stats['memory_percent'] > 95:
                        self.create_alert("High Memory Usage", f"Memory at {stats['memory_percent']:.1f}%", "Medium")
                    
                    time.sleep(5)  # Update every 5 seconds
                    
                except Exception as e:
                    print(f"Error in monitoring loop: {e}")
                    time.sleep(5)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        print("✅ Monitoring started successfully")
    
    def get_dashboard_data(self):
        """Get all dashboard data"""
        # Calculate summary stats
        total_threats = len(self.threats)
        critical_threats = len([t for t in self.threats if t.get('severity') == 'High'])
        active_connections = len(self.connections)
        suspicious_connections = len([c for c in self.connections if c.get('suspicious', False)])
        
        # Get latest system stats
        latest_stats = self.system_stats[-1] if self.system_stats else {}
        
        # Threat distribution
        threat_types = Counter([t.get('type', 'Unknown') for t in self.threats])
        
        return {
            'summary': {
                'total_threats': total_threats,
                'critical_threats': critical_threats,
                'active_connections': active_connections,
                'suspicious_connections': suspicious_connections,
                'uptime': str(datetime.now() - self.start_time).split('.')[0]
            },
            'system_stats': latest_stats,
            'recent_alerts': self.alerts[-10:],
            'connections': self.connections[-15:],
            'threat_distribution': dict(threat_types),
            'system_timeline': self.system_stats[-20:]
        }

# Initialize dashboard
dashboard = SimpleCyberDashboard()

# Simple HTML template
SIMPLE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Cybersecurity Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #0f0f23;
            color: #fff;
            margin: 0;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 2px solid #e94560;
        }
        
        .header h1 {
            margin: 0;
            color: #e94560;
            font-size: 2.5rem;
        }
        
        .live-indicator {
            background: #4ecca3;
            color: #000;
            padding: 5px 15px;
            border-radius: 15px;
            display: inline-block;
            margin-top: 10px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #e94560;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #e94560;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #b0b0b0;
        }
        
        .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .panel {
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #333;
        }
        
        .panel h3 {
            margin-top: 0;
            color: #e94560;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }
        
        .alert-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #ffbd69;
        }
        
        .alert-high { border-left-color: #ff5e5b; }
        .alert-medium { border-left-color: #ffbd69; }
        .alert-low { border-left-color: #4ecca3; }
        
        .connection-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 8px;
            margin: 8px 0;
            border-radius: 5px;
            font-size: 0.9rem;
        }
        
        .suspicious {
            border-left: 4px solid #ff5e5b;
            background: rgba(255, 94, 91, 0.1);
        }
        
        .system-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .metric {
            background: #1a1a2e;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .metric-label {
            color: #b0b0b0;
            font-size: 0.9rem;
        }
        
        .progress-bar {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            margin-top: 8px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: #4ecca3;
            border-radius: 3px;
            transition: width 0.3s ease;
        }
        
        .progress-fill.warning { background: #ffbd69; }
        .progress-fill.danger { background: #ff5e5b; }
        
        .footer {
            text-align: center;
            color: #666;
            margin-top: 20px;
            padding: 15px;
            border-top: 1px solid #333;
        }
        
        .last-update {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #1a1a2e;
            padding: 8px 12px;
            border-radius: 15px;
            font-size: 0.9rem;
            border: 1px solid #333;
        }
        
        @media (max-width: 768px) {
            .content { grid-template-columns: 1fr; }
            .stats { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Cybersecurity Dashboard</h1>
        <div class="live-indicator">🔴 LIVE MONITORING</div>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value" id="total-threats">0</div>
            <div class="stat-label">Total Threats</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="critical-threats">0</div>
            <div class="stat-label">Critical Threats</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="active-connections">0</div>
            <div class="stat-label">Active Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="uptime">00:00:00</div>
            <div class="stat-label">Uptime</div>
        </div>
    </div>
    
    <div class="system-metrics">
        <div class="metric">
            <div class="metric-value" id="cpu-usage">0%</div>
            <div class="metric-label">CPU Usage</div>
            <div class="progress-bar">
                <div class="progress-fill" id="cpu-progress"></div>
            </div>
        </div>
        <div class="metric">
            <div class="metric-value" id="memory-usage">0%</div>
            <div class="metric-label">Memory Usage</div>
            <div class="progress-bar">
                <div class="progress-fill" id="memory-progress"></div>
            </div>
        </div>
        <div class="metric">
            <div class="metric-value" id="disk-usage">0%</div>
            <div class="metric-label">Disk Usage</div>
            <div class="progress-bar">
                <div class="progress-fill" id="disk-progress"></div>
            </div>
        </div>
        <div class="metric">
            <div class="metric-value" id="processes">0</div>
            <div class="metric-label">Active Processes</div>
        </div>
    </div>
    
    <div class="content">
        <div class="panel">
            <h3>🚨 Recent Security Alerts</h3>
            <div id="alerts-list">
                <div style="text-align: center; color: #4ecca3; padding: 20px;">
                    ✅ No threats detected
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h3>🌐 Network Connections</h3>
            <div id="connections-list">
                <div style="text-align: center; color: #b0b0b0; padding: 20px;">
                    Loading connections...
                </div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        🔒 Real-Time Cybersecurity Monitoring System
    </div>
    
    <div class="last-update">
        Last Update: <span id="last-update">Never</span>
    </div>
    
    <script>
        function updateDashboard() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    // Update summary stats
                    document.getElementById('total-threats').textContent = data.summary.total_threats;
                    document.getElementById('critical-threats').textContent = data.summary.critical_threats;
                    document.getElementById('active-connections').textContent = data.summary.active_connections;
                    document.getElementById('uptime').textContent = data.summary.uptime;
                    
                    // Update system metrics
                    if (data.system_stats) {
                        const stats = data.system_stats;
                        
                        // CPU
                        document.getElementById('cpu-usage').textContent = stats.cpu_percent.toFixed(1) + '%';
                        const cpuProgress = document.getElementById('cpu-progress');
                        cpuProgress.style.width = stats.cpu_percent + '%';
                        cpuProgress.className = 'progress-fill ' + (stats.cpu_percent > 80 ? 'danger' : stats.cpu_percent > 60 ? 'warning' : '');
                        
                        // Memory
                        document.getElementById('memory-usage').textContent = stats.memory_percent.toFixed(1) + '%';
                        const memProgress = document.getElementById('memory-progress');
                        memProgress.style.width = stats.memory_percent + '%';
                        memProgress.className = 'progress-fill ' + (stats.memory_percent > 90 ? 'danger' : stats.memory_percent > 70 ? 'warning' : '');
                        
                        // Disk
                        document.getElementById('disk-usage').textContent = stats.disk_percent.toFixed(1) + '%';
                        const diskProgress = document.getElementById('disk-progress');
                        diskProgress.style.width = stats.disk_percent + '%';
                        diskProgress.className = 'progress-fill ' + (stats.disk_percent > 95 ? 'danger' : stats.disk_percent > 80 ? 'warning' : '');
                        
                        // Processes
                        document.getElementById('processes').textContent = stats.processes;
                    }
                    
                    // Update alerts
                    updateAlerts(data.recent_alerts);
                    
                    // Update connections
                    updateConnections(data.connections);
                    
                    // Update timestamp
                    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('last-update').textContent = 'Error';
                });
        }
        
        function updateAlerts(alerts) {
            const alertsList = document.getElementById('alerts-list');
            
            if (!alerts || alerts.length === 0) {
                alertsList.innerHTML = '<div style="text-align: center; color: #4ecca3; padding: 20px;">✅ No threats detected</div>';
                return;
            }
            
            let html = '';
            alerts.forEach(alert => {
                const severityClass = 'alert-' + alert.severity.toLowerCase();
                html += `
                    <div class="alert-item ${severityClass}">
                        <strong>${alert.type}</strong> - ${alert.severity}<br>
                        <small>${alert.timestamp}</small><br>
                        ${alert.message}
                    </div>
                `;
            });
            
            alertsList.innerHTML = html;
        }
        
        function updateConnections(connections) {
            const connectionsList = document.getElementById('connections-list');
            
            if (!connections || connections.length === 0) {
                connectionsList.innerHTML = '<div style="text-align: center; color: #b0b0b0; padding: 20px;">No active connections</div>';
                return;
            }
            
            let html = '';
            connections.slice(0, 8).forEach(conn => {
                const suspiciousClass = conn.suspicious ? 'suspicious' : '';
                const status = conn.suspicious ? '⚠️ SUSPICIOUS' : '✅ Clean';
                
                html += `
                    <div class="connection-item ${suspiciousClass}">
                        <strong>${conn.remote_ip}:${conn.remote_port}</strong> ${status}<br>
                        <small>Process: ${conn.process} | ${conn.timestamp}</small>
                    </div>
                `;
            });
            
            connectionsList.innerHTML = html;
        }
        
        // Start updates
        updateDashboard();
        setInterval(updateDashboard, 3000); // Update every 3 seconds
    </script>
</body>
</html>
'''

@app.route('/')
def dashboard_page():
    return render_template_string(SIMPLE_TEMPLATE)

@app.route('/api/data')
def api_data():
    return jsonify(dashboard.get_dashboard_data())

if __name__ == '__main__':
    print("🚀 Starting Simple Cybersecurity Dashboard...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔴 Real-time monitoring active!")
    print("=" * 50)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Trying alternative port 8080...")
        app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)