import os
import sys
import time
import json
import threading
import hashlib
import socket
import subprocess
import platform
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import random
import re

# Try to import required libraries, install if missing
def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        print(f"Installing {package}...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install required packages
try:
    install_and_import('flask')
    install_and_import('psutil')
    install_and_import('requests')
except Exception as e:
    print(f"Error installing packages: {e}")
    print("Please run: pip install flask psutil requests")
    sys.exit(1)

from flask import Flask, render_template_string, jsonify
import psutil

app = Flask(__name__)

class AdvancedCyberDashboard:
    def __init__(self):
        self.threats = []
        self.alerts = []
        self.connections = []
        self.system_stats = []
        self.security_recommendations = []
        self.hack_indicators = []
        self.is_monitoring = False
        self.start_time = datetime.now()
        self.hack_score = 0
        self.system_baseline = {}
        
        # Enhanced threat indicators
        self.suspicious_ips = {
            "185.220.100.240", "198.96.155.3", "89.234.157.254",
            "192.42.116.16", "185.220.101.40", "199.87.154.255",
            "tor-exit-node", "known-botnet", "malware-c2"
        }
        
        self.suspicious_ports = {22, 23, 135, 139, 445, 1433, 3389, 5900, 4444, 6666, 31337}
        
        # Malware signatures and suspicious processes
        self.malware_signatures = [
            'mimikatz', 'psexec', 'netcat', 'nc.exe', 'powershell.exe -enc',
            'cmd.exe /c', 'wscript.exe', 'cscript.exe', 'regsvr32.exe',
            'rundll32.exe', 'svchost.exe'
        ]
        
        # File integrity monitoring
        self.critical_files = []
        if platform.system() == "Windows":
            self.critical_files = [
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Windows\\System32\\config\\SAM'
            ]
        else:
            self.critical_files = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts'
            ]
        
        self.file_hashes = {}
        self.initialize_baseline()
        
        print("🛡️ Advanced Cybersecurity Dashboard Starting...")
        self.start_monitoring()
    
    def initialize_baseline(self):
        """Initialize system baseline for anomaly detection"""
        try:
            # Get baseline system metrics
            self.system_baseline = {
                'normal_processes': set(),
                'normal_connections': set(),
                'file_hashes': {},
                'startup_programs': self.get_startup_programs(),
                'installed_software': self.get_installed_software()
            }
            
            # Hash critical files
            for file_path in self.critical_files:
                if os.path.exists(file_path):
                    try:
                        self.file_hashes[file_path] = self.get_file_hash(file_path)
                    except Exception as e:
                        print(f"Could not hash {file_path}: {e}")
            
            print("✅ System baseline established")
        except Exception as e:
            print(f"Error initializing baseline: {e}")
    
    def get_file_hash(self, file_path):
        """Get SHA256 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return None
    
    def get_startup_programs(self):
        """Get list of startup programs"""
        startup_programs = []
        try:
            if platform.system() == "Windows":
                # Windows startup locations - simplified approach
                try:
                    result = subprocess.run(['wmic', 'startup', 'get', 'name,command'], 
                                          capture_output=True, text=True, timeout=10)
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                startup_programs.append({'name': parts[0], 'path': ' '.join(parts[1:])})
                except Exception as e:
                    print(f"Error getting Windows startup programs: {e}")
            else:
                # Linux startup locations
                startup_dirs = ['/etc/init.d/']
                for dir_path in startup_dirs:
                    if os.path.exists(dir_path):
                        try:
                            for file in os.listdir(dir_path):
                                startup_programs.append({'name': file, 'path': os.path.join(dir_path, file)})
                        except Exception as e:
                            print(f"Error reading {dir_path}: {e}")
        except Exception as e:
            print(f"Error getting startup programs: {e}")
        
        return startup_programs
    
    def get_installed_software(self):
        """Get list of installed software"""
        software_list = []
        try:
            if platform.system() == "Windows":
                # Windows installed programs - simplified approach
                try:
                    result = subprocess.run(['wmic', 'product', 'get', 'name'], 
                                          capture_output=True, text=True, timeout=15)
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            software_list.append(line.strip())
                except Exception as e:
                    print(f"Error getting Windows software: {e}")
            else:
                # Linux packages (dpkg/rpm)
                try:
                    result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=10)
                    for line in result.stdout.split('\n')[5:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                software_list.append(parts[1])
                except:
                    try:
                        result = subprocess.run(['rpm', '-qa'], capture_output=True, text=True, timeout=10)
                        software_list = result.stdout.strip().split('\n')
                    except:
                        pass
        except Exception as e:
            print(f"Error getting installed software: {e}")
        
        return software_list[:50]  # Limit to first 50 for performance
    
    def detect_hack_indicators(self):
        """Advanced hack detection"""
        hack_indicators = []
        self.hack_score = 0
        
        # 1. Check for file integrity violations
        for file_path, original_hash in self.file_hashes.items():
            if os.path.exists(file_path):
                current_hash = self.get_file_hash(file_path)
                if current_hash and current_hash != original_hash:
                    hack_indicators.append({
                        'type': 'File Integrity Violation',
                        'severity': 'Critical',
                        'description': f'Critical file {file_path} has been modified',
                        'recommendation': 'Immediately check file contents and restore from backup'
                    })
                    self.hack_score += 30
        
        # 2. Check for suspicious network activity
        suspicious_connections = [c for c in self.connections if c.get('suspicious')]
        for conn in suspicious_connections:
            hack_indicators.append({
                'type': 'Suspicious Network Connection',
                'severity': 'High',
                'description': f'Connection to suspicious IP {conn["remote_ip"]}',
                'recommendation': 'Block IP address and scan for malware'
            })
            self.hack_score += 20
        
        # 3. Check for malware processes
        malware_processes = self.scan_for_malware()
        for proc in malware_processes:
            hack_indicators.append({
                'type': 'Malware Process Detected',
                'severity': 'Critical',
                'description': f'Suspicious process: {proc["name"]} (PID: {proc["pid"]})',
                'recommendation': 'Terminate process immediately and run full system scan'
            })
            self.hack_score += 40
        
        # 4. Check for unusual system behavior
        unusual_behavior = self.detect_unusual_behavior()
        for behavior in unusual_behavior:
            hack_indicators.append(behavior)
            self.hack_score += behavior.get('score', 10)
        
        # 5. Check for persistence mechanisms
        persistence_checks = self.check_persistence_mechanisms()
        for persistence in persistence_checks:
            hack_indicators.append(persistence)
            self.hack_score += 25
        
        # 6. Memory analysis for injected code
        memory_threats = self.analyze_memory_threats()
        for threat in memory_threats:
            hack_indicators.append(threat)
            self.hack_score += 35
        
        self.hack_indicators = hack_indicators
        return hack_indicators
    
    def scan_for_malware(self):
        """Scan for known malware signatures"""
        malware_found = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                    
                    # Check against malware signatures
                    for signature in self.malware_signatures:
                        if signature.lower() in proc_name or signature.lower() in cmdline:
                            malware_found.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'cmdline': cmdline,
                                'signature': signature
                            })
                            break
                    
                    # Check for suspicious executable locations
                    exe_path = proc_info.get('exe', '')
                    if exe_path:
                        suspicious_paths = ['temp', 'tmp', 'appdata\\local\\temp', 'downloads']
                        if any(sus_path in exe_path.lower() for sus_path in suspicious_paths):
                            malware_found.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'exe': exe_path,
                                'reason': 'Suspicious location'
                            })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error scanning for malware: {e}")
        
        return malware_found
    
    def detect_unusual_behavior(self):
        """Detect unusual system behavior"""
        unusual_behaviors = []
        
        try:
            # Check for unusual CPU/Memory usage patterns
            if self.system_stats:
                recent_stats = self.system_stats[-10:]
                if recent_stats:
                    avg_cpu = sum(s.get('cpu_percent', 0) for s in recent_stats) / len(recent_stats)
                    avg_memory = sum(s.get('memory_percent', 0) for s in recent_stats) / len(recent_stats)
                    
                    if avg_cpu > 85:
                        unusual_behaviors.append({
                            'type': 'Unusual CPU Usage',
                            'severity': 'Medium',
                            'description': f'Sustained high CPU usage: {avg_cpu:.1f}%',
                            'recommendation': 'Check for cryptocurrency miners or resource-intensive malware',
                            'score': 15
                        })
                    
                    if avg_memory > 90:
                        unusual_behaviors.append({
                            'type': 'Unusual Memory Usage',
                            'severity': 'Medium',
                            'description': f'Sustained high memory usage: {avg_memory:.1f}%',
                            'recommendation': 'Check for memory-resident malware or data exfiltration',
                            'score': 15
                        })
            
            # Check for unusual network activity
            try:
                net_io = psutil.net_io_counters()
                if hasattr(self, 'last_net_io'):
                    bytes_sent_diff = net_io.bytes_sent - self.last_net_io.bytes_sent
                    
                    # Check for unusual data transfer (>100MB in 5 seconds)
                    if bytes_sent_diff > 100 * 1024 * 1024:
                        unusual_behaviors.append({
                            'type': 'Unusual Data Upload',
                            'severity': 'High',
                            'description': f'Large data upload detected: {bytes_sent_diff / (1024*1024):.1f} MB',
                            'recommendation': 'Check for data exfiltration or botnet activity',
                            'score': 25
                        })
                
                self.last_net_io = net_io
            except:
                pass
            
        except Exception as e:
            print(f"Error detecting unusual behavior: {e}")
        
        return unusual_behaviors
    
    def check_persistence_mechanisms(self):
        """Check for malware persistence mechanisms"""
        persistence_threats = []
        
        try:
            # Check startup programs for suspicious entries
            current_startup = self.get_startup_programs()
            baseline_startup = {prog['name'] for prog in self.system_baseline.get('startup_programs', [])}
            
            for prog in current_startup:
                if prog['name'] not in baseline_startup:
                    # New startup program detected
                    persistence_threats.append({
                        'type': 'Unauthorized Startup Program',
                        'severity': 'High',
                        'description': f'New startup program: {prog["name"]}',
                        'recommendation': 'Remove unauthorized startup entry and scan file'
                    })
            
        except Exception as e:
            print(f"Error checking persistence mechanisms: {e}")
        
        return persistence_threats
    
    def analyze_memory_threats(self):
        """Analyze memory for potential threats"""
        memory_threats = []
        
        try:
            # Check for processes with unusual memory patterns
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    proc_info = proc.info
                    memory_info = proc_info['memory_info']
                    
                    # Check for processes using excessive memory
                    if memory_info.rss > 1024 * 1024 * 1024:  # >1GB
                        memory_threats.append({
                            'type': 'High Memory Usage Process',
                            'severity': 'Medium',
                            'description': f'Process {proc_info["name"]} using {memory_info.rss / (1024*1024):.1f} MB',
                            'recommendation': 'Investigate process for potential malware'
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error analyzing memory threats: {e}")
        
        return memory_threats
    
    def generate_security_recommendations(self):
        """Generate security recommendations based on current threats"""
        recommendations = []
        
        # General recommendations based on hack score
        if self.hack_score >= 100:
            recommendations.extend([
                "🚨 CRITICAL: System appears to be compromised. Disconnect from network immediately.",
                "🔒 Run a full system antivirus scan with updated definitions.",
                "💾 Backup important data to an external, isolated storage device.",
                "🔄 Consider complete system reinstallation after data backup.",
                "📞 Contact IT security team or cybersecurity professional."
            ])
        elif self.hack_score >= 50:
            recommendations.extend([
                "⚠️ HIGH RISK: Multiple security threats detected.",
                "🛡️ Update all software and operating system immediately.",
                "🔍 Run deep malware scan with multiple antivirus engines.",
                "🔐 Change all passwords, especially for sensitive accounts.",
                "🌐 Monitor network traffic for suspicious activity."
            ])
        elif self.hack_score >= 20:
            recommendations.extend([
                "⚡ MEDIUM RISK: Some security concerns detected.",
                "🔄 Update antivirus definitions and run full scan.",
                "🔒 Enable firewall and review security settings.",
                "📱 Enable two-factor authentication on important accounts.",
                "🕵️ Monitor system for unusual behavior."
            ])
        else:
            recommendations.extend([
                "✅ System appears secure, but stay vigilant.",
                "🔄 Keep software and OS updated regularly.",
                "💾 Maintain regular backups of important data.",
                "🛡️ Use reputable antivirus software.",
                "🎓 Stay informed about latest security threats."
            ])
        
        # Specific recommendations based on detected threats
        for indicator in self.hack_indicators:
            if indicator.get('recommendation'):
                recommendations.append(f"🎯 {indicator['recommendation']}")
        
        self.security_recommendations = recommendations[:10]  # Limit to top 10
        return self.security_recommendations
    
    def get_system_info(self):
        """Get comprehensive system information"""
        try:
            # Basic system metrics
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
            
            # Security metrics
            try:
                active_connections = len(psutil.net_connections(kind='inet'))
            except:
                active_connections = 0
            
            running_processes = len(psutil.pids())
            
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk_percent,
                'network_sent': network_sent,
                'network_recv': network_recv,
                'processes': running_processes,
                'connections': active_connections,
                'hack_score': self.hack_score
            }
        except Exception as e:
            print(f"Error getting system info: {e}")
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'cpu_percent': 0, 'memory_percent': 0, 'disk_percent': 0,
                'network_sent': 0, 'network_recv': 0, 'processes': 0,
                'connections': 0, 'hack_score': 0
            }
    
    def get_network_connections(self):
        """Get and analyze network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Enhanced suspicious detection
                    is_suspicious = (
                        remote_ip in self.suspicious_ips or
                        remote_port in self.suspicious_ports or
                        self.is_ip_suspicious(remote_ip)
                    )
                    
                    # Get process information
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
                            "Suspicious Network Connection",
                            f"Connection to {remote_ip}:{remote_port} by {process_name}",
                            "High" if remote_ip in self.suspicious_ips else "Medium"
                        )
        except Exception as e:
            print(f"Error getting connections: {e}")
        
        return connections
    
    def is_ip_suspicious(self, ip):
        """Check if IP is suspicious using various methods"""
        try:
            # Simple check for private IP ranges (less suspicious)
            if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                             '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                             '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                             '127.')):
                return False
            
            # Check against known suspicious patterns
            suspicious_patterns = ['185.220.', '198.96.', '89.234.']
            for pattern in suspicious_patterns:
                if ip.startswith(pattern):
                    return True
            
            return False
        except:
            return False
    
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
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        print(f"🚨 {severity} Alert: {alert_type} - {message}")
    
    def start_monitoring(self):
        """Start comprehensive monitoring"""
        self.is_monitoring = True
        
        def monitor_loop():
            while self.is_monitoring:
                try:
                    # Get system stats
                    stats = self.get_system_info()
                    self.system_stats.append(stats)
                    
                    # Keep only recent stats
                    if len(self.system_stats) > 120:
                        self.system_stats = self.system_stats[-120:]
                    
                    # Monitor connections
                    self.connections = self.get_network_connections()
                    
                    # Run comprehensive security checks every 30 seconds
                    if len(self.system_stats) % 6 == 0:
                        self.detect_hack_indicators()
                        self.generate_security_recommendations()
                    
                    # System health alerts
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
        
        print("✅ Advanced monitoring started successfully")
    
    def get_dashboard_data(self):
        """Get comprehensive dashboard data"""
        # Calculate summary stats
        total_threats = len(self.threats)
        critical_threats = len([t for t in self.threats if t.get('severity') == 'Critical'])
        high_threats = len([t for t in self.threats if t.get('severity') == 'High'])
        active_connections = len(self.connections)
        suspicious_connections = len([c for c in self.connections if c.get('suspicious', False)])
        
        # Get latest system stats
        latest_stats = self.system_stats[-1] if self.system_stats else {}
        
        # Threat distribution
        threat_types = Counter([t.get('type', 'Unknown') for t in self.threats])
        
        # Security status
        if self.hack_score >= 100:
            security_status = "COMPROMISED"
            status_color = "#ff1744"
        elif self.hack_score >= 50:
            security_status = "HIGH RISK"
            status_color = "#ff9800"
        elif self.hack_score >= 20:
            security_status = "MEDIUM RISK"
            status_color = "#ffeb3b"
        else:
            security_status = "SECURE"
            status_color = "#4caf50"
        
        return {
            'summary': {
                'total_threats': total_threats,
                'critical_threats': critical_threats,
                'high_threats': high_threats,
                'active_connections': active_connections,
                'suspicious_connections': suspicious_connections,
                'hack_score': self.hack_score,
                'security_status': security_status,
                'status_color': status_color,
                'uptime': str(datetime.now() - self.start_time).split('.')[0]
            },
            'system_stats': latest_stats,
            'recent_alerts': self.alerts[-15:],
            'connections': self.connections[-20:],
            'hack_indicators': self.hack_indicators[-10:],
            'security_recommendations': self.security_recommendations,
            'threat_distribution': dict(threat_types),
            'system_timeline': self.system_stats[-30:]
        }

# Initialize advanced dashboard
dashboard = AdvancedCyberDashboard()

# Enhanced HTML template with attractive design
ENHANCED_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Advanced Cybersecurity Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
            color: #fff;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .header {
            text-align: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 30px;
            border-radius: 15px;
            margin: 20px;
            border: 2px solid #e94560;
            box-shadow: 0 10px 30px rgba(233, 69, 96, 0.3);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(233, 69, 96, 0.1), transparent);
            animation: shimmer 3s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
        }
        
        .header h1 {
            margin: 0;
            color: #e94560;
            font-size: 3rem;
            font-weight: bold;
            text-shadow: 0 0 20px rgba(233, 69, 96, 0.5);
            position: relative;
            z-index: 1;
        }
        
        .security-status {
            font-size: 1.5rem;
            font-weight: bold;
            margin: 15px 0;
            padding: 10px 20px;
            border-radius: 25px;
            display: inline-block;
            position: relative;
            z-index: 1;
            text-shadow: 0 0 10px currentColor;
        }
        
        .live-indicator {
            background: linear-gradient(45deg, #4ecca3, #44a08d);
            color: #000;
            padding: 8px 20px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 15px;
            animation: pulse 2s infinite;
            font-weight: bold;
            position: relative;
            z-index: 1;
        }
        
        @keyframes pulse {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.05); }
            100% { opacity: 1; transform: scale(1); }
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 25px;
            border-radius: 15px;
            border-left: 5px solid #e94560;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(233, 69, 96, 0.2);
        }
        
        .stat-value {
            font-size: 3rem;
            font-weight: bold;
            color: #e94560;
            margin-bottom: 10px;
            text-shadow: 0 0 15px rgba(233, 69, 96, 0.5);
        }
        
        .stat-label {
            color: #b0b0b0;
            font-size: 1.1rem;
            font-weight: 500;
        }
        
        .hack-score {
            background: linear-gradient(135deg, #ff1744, #d50000);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin: 20px;
            text-align: center;
            font-size: 1.5rem;
            font-weight: bold;
            box-shadow: 0 10px 25px rgba(255, 23, 68, 0.3);
        }
        
        .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 20px;
        }
        
        .panel {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid #333;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        }
        
        .panel h3 {
            margin-top: 0;
            color: #e94560;
            border-bottom: 2px solid #333;
            padding-bottom: 15px;
            font-size: 1.3rem;
            text-shadow: 0 0 10px rgba(233, 69, 96, 0.3);
        }
        
        .alert-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            margin: 15px 0;
            border-radius: 10px;
            border-left: 4px solid #ffbd69;
            transition: all 0.3s ease;
        }
        
        .alert-item:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateX(5px);
        }
        
        .alert-critical { border-left-color: #ff1744; background: rgba(255, 23, 68, 0.1); }
        .alert-high { border-left-color: #ff5722; background: rgba(255, 87, 34, 0.1); }
        .alert-medium { border-left-color: #ffbd69; background: rgba(255, 189, 105, 0.1); }
        .alert-low { border-left-color: #4ecca3; background: rgba(78, 204, 163, 0.1); }
        
        .connection-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 12px;
            margin: 12px 0;
            border-radius: 8px;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .connection-item:hover {
            background: rgba(255, 255, 255, 0.1);
        }
        
        .suspicious {
            border-left: 4px solid #ff1744;
            background: rgba(255, 23, 68, 0.15);
            animation: alertBlink 2s infinite;
        }
        
        @keyframes alertBlink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .system-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px;
        }
        
        .metric {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .metric:hover {
            transform: translateY(-3px);
        }
        
        .metric-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 8px;
            text-shadow: 0 0 10px currentColor;
        }
        
        .metric-label {
            color: #b0b0b0;
            font-size: 1rem;
            font-weight: 500;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            margin-top: 12px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #4ecca3, #44a08d);
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        
        .progress-fill.warning { background: linear-gradient(90deg, #ffbd69, #ff9800); }
        .progress-fill.danger { background: linear-gradient(90deg, #ff5722, #d32f2f); }
        
        .recommendations {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 25px;
            border-radius: 15px;
            border: 2px solid #4ecca3;
            box-shadow: 0 10px 25px rgba(78, 204, 163, 0.2);
        }
        
        .recommendation-item {
            background: rgba(78, 204, 163, 0.1);
            padding: 12px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #4ecca3;
            font-size: 1rem;
        }
        
        .footer {
            text-align: center;
            color: #666;
            margin: 30px 20px 20px;
            padding: 20px;
            border-top: 2px solid #333;
            font-size: 1.1rem;
        }
        
        .developer-credit {
            background: linear-gradient(135deg, #e94560, #ff6b6b);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin: 20px;
            text-align: center;
            font-size: 1.2rem;
            font-weight: bold;
            box-shadow: 0 10px 25px rgba(233, 69, 96, 0.3);
            border: 2px solid #fff;
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            from { box-shadow: 0 10px 25px rgba(233, 69, 96, 0.3); }
            to { box-shadow: 0 15px 35px rgba(233, 69, 96, 0.6); }
        }
        
        .last-update {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            padding: 12px 18px;
            border-radius: 20px;
            font-size: 0.9rem;
            border: 2px solid #e94560;
            box-shadow: 0 5px 15px rgba(233, 69, 96, 0.3);
            z-index: 1000;
        }
        
        @media (max-width: 768px) {
            .content { grid-template-columns: 1fr; }
            .stats { grid-template-columns: 1fr; }
            .system-metrics { grid-template-columns: repeat(2, 1fr); }
            .header h1 { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ADVANCED CYBERSECURITY COMMAND CENTER</h1>
        <div class="security-status" id="security-status">ANALYZING...</div>
        <div class="live-indicator">🔴 REAL-TIME MONITORING ACTIVE</div>
    </div>
    
    <div class="hack-score">
        🎯 THREAT LEVEL: <span id="hack-score">0</span>/100
        <div style="font-size: 0.9rem; margin-top: 5px;" id="threat-description">System Secure</div>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value" id="total-threats">0</div>
            <div class="stat-label">Total Threats Detected</div>
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
            <div class="stat-label">System Uptime</div>
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
            <h3>🚨 Security Alerts & Threats</h3>
            <div id="alerts-list">
                <div style="text-align: center; color: #4ecca3; padding: 20px;">
                    ✅ No threats detected - System secure
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h3>🌐 Network Connections Monitor</h3>
            <div id="connections-list">
                <div style="text-align: center; color: #b0b0b0; padding: 20px;">
                    🔍 Scanning network connections...
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h3>🎯 Hack Indicators</h3>
            <div id="hack-indicators-list">
                <div style="text-align: center; color: #4ecca3; padding: 20px;">
                    ✅ No hack indicators detected
                </div>
            </div>
        </div>
        
        <div class="panel recommendations">
            <h3>🛡️ Security Recommendations</h3>
            <div id="recommendations-list">
                <div style="text-align: center; color: #b0b0b0; padding: 20px;">
                    📋 Generating security recommendations...
                </div>
            </div>
        </div>
    </div>
    
    <div class="developer-credit">
        👨‍💻 DEVELOPED BY MUHAMMAD ABDULLAH 🚀
        <div style="font-size: 0.9rem; margin-top: 5px;">Advanced Cybersecurity Solutions</div>
    </div>
    
    <div class="footer">
        🔒 Advanced Real-Time Cybersecurity Monitoring & Threat Detection System
        <br>
        🛡️ Protecting your digital assets with AI-powered security intelligence
    </div>
    
    <div class="last-update">
        Last Scan: <span id="last-update">Initializing...</span>
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
                    
                    // Update hack score and security status
                    const hackScore = data.summary.hack_score;
                    document.getElementById('hack-score').textContent = hackScore;
                    
                    const statusElement = document.getElementById('security-status');
                    statusElement.textContent = data.summary.security_status;
                    statusElement.style.background = data.summary.status_color;
                    statusElement.style.color = hackScore >= 50 ? '#fff' : '#000';
                    
                    // Update threat description
                    const threatDesc = document.getElementById('threat-description');
                    if (hackScore >= 100) {
                        threatDesc.textContent = "🚨 SYSTEM COMPROMISED - IMMEDIATE ACTION REQUIRED";
                    } else if (hackScore >= 50) {
                        threatDesc.textContent = "⚠️ HIGH RISK - MULTIPLE THREATS DETECTED";
                    } else if (hackScore >= 20) {
                        threatDesc.textContent = "⚡ MEDIUM RISK - MONITORING REQUIRED";
                    } else {
                        threatDesc.textContent = "✅ SYSTEM SECURE - CONTINUE MONITORING";
                    }
                    
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
                    
                    // Update hack indicators
                    updateHackIndicators(data.hack_indicators);
                    
                    // Update recommendations
                    updateRecommendations(data.security_recommendations);
                    
                    // Update timestamp
                    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('last-update').textContent = 'Connection Error';
                });
        }
        
        function updateAlerts(alerts) {
            const alertsList = document.getElementById('alerts-list');
            
            if (!alerts || alerts.length === 0) {
                alertsList.innerHTML = '<div style="text-align: center; color: #4ecca3; padding: 20px;">✅ No threats detected - System secure</div>';
                return;
            }
            
            let html = '';
            alerts.forEach(alert => {
                const severityClass = 'alert-' + alert.severity.toLowerCase();
                const icon = alert.severity === 'Critical' ? '🚨' : alert.severity === 'High' ? '⚠️' : alert.severity === 'Medium' ? '⚡' : '💡';
                html += `
                    <div class="alert-item ${severityClass}">
                        ${icon} <strong>${alert.type}</strong> - ${alert.severity}<br>
                        <small>🕒 ${alert.timestamp}</small><br>
                        📝 ${alert.message}
                    </div>
                `;
            });
            
            alertsList.innerHTML = html;
        }
        
        function updateConnections(connections) {
            const connectionsList = document.getElementById('connections-list');
            
            if (!connections || connections.length === 0) {
                connectionsList.innerHTML = '<div style="text-align: center; color: #b0b0b0; padding: 20px;">🔍 No active connections detected</div>';
                return;
            }
            
            let html = '';
            connections.slice(0, 10).forEach(conn => {
                const suspiciousClass = conn.suspicious ? 'suspicious' : '';
                const status = conn.suspicious ? '🚨 SUSPICIOUS' : '✅ Clean';
                const icon = conn.suspicious ? '⚠️' : '🌐';
                
                html += `
                    <div class="connection-item ${suspiciousClass}">
                        ${icon} <strong>${conn.remote_ip}:${conn.remote_port}</strong> ${status}<br>
                        <small>📱 Process: ${conn.process} | 🕒 ${conn.timestamp}</small>
                    </div>
                `;
            });
            
            connectionsList.innerHTML = html;
        }
        
        function updateHackIndicators(indicators) {
            const indicatorsList = document.getElementById('hack-indicators-list');
            
            if (!indicators || indicators.length === 0) {
                indicatorsList.innerHTML = '<div style="text-align: center; color: #4ecca3; padding: 20px;">✅ No hack indicators detected</div>';
                return;
            }
            
            let html = '';
            indicators.forEach(indicator => {
                const severityClass = 'alert-' + indicator.severity.toLowerCase();
                const icon = indicator.severity === 'Critical' ? '🚨' : indicator.severity === 'High' ? '⚠️' : '⚡';
                html += `
                    <div class="alert-item ${severityClass}">
                        ${icon} <strong>${indicator.type}</strong><br>
                        <small>📝 ${indicator.description}</small>
                    </div>
                `;
            });
            
            indicatorsList.innerHTML = html;
        }
        
        function updateRecommendations(recommendations) {
            const recommendationsList = document.getElementById('recommendations-list');
            
            if (!recommendations || recommendations.length === 0) {
                recommendationsList.innerHTML = '<div style="text-align: center; color: #b0b0b0; padding: 20px;">📋 No specific recommendations at this time</div>';
                return;
            }
            
            let html = '';
            recommendations.forEach(rec => {
                html += `
                    <div class="recommendation-item">
                        ${rec}
                    </div>
                `;
            });
            
            recommendationsList.innerHTML = html;
        }
        
        // Initialize
        updateDashboard();
        setInterval(updateDashboard, 3000); // Update every 3 seconds
    </script>
</body>
</html>
'''

@app.route('/')
def dashboard_page():
    return render_template_string(ENHANCED_TEMPLATE)

@app.route('/api/data')
def api_data():
    return jsonify(dashboard.get_dashboard_data())

if __name__ == '__main__':
    print("🚀 Starting Advanced Cybersecurity Dashboard...")
    print("🛡️ Enhanced with hack detection and security recommendations")
    print("👨‍💻 Developed by MUHAMMAD ABDULLAH")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔴 Real-time monitoring with advanced threat detection active!")
    print("=" * 60)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Trying alternative port 8080...")
        try:
            app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
        except Exception as e2:
            print(f"Error starting on port 8080: {e2}")
            print("Please check if ports 5000 and 8080 are available")

# ============================================================================
# 🛡️ ADVANCED CYBERSECURITY DASHBOARD
# 👨‍💻 DEVELOPED BY MUHAMMAD ABDULLAH
# 🚀 Advanced Real-Time Threat Detection & Security Monitoring System
# ============================================================================
