import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
import threading
import time

# Import utility modules
from network_scanner import NetworkScanner
from security_analyzer import SecurityAnalyzer
from deauth_detector import DeauthDetector
from brute_force import BruteForceWPA

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "wifi_security_default_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database (SQLite for simplicity)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///wifi_scanner.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Global variables for scan status
scan_active = False
scan_thread = None
scan_results = []
detected_rogue_aps = []

# Initialize scanner, analyzer, and detector
scanner = None  # Will be initialized on first use
analyzer = SecurityAnalyzer()
deauth_detector = DeauthDetector()
brute_forcer = BruteForceWPA()

def initialize_scanner():
    """Initialize the network scanner if not already initialized"""
    global scanner
    if scanner is None:
        try:
            # Get available interfaces
            from utils import get_wifi_interfaces
            interfaces = get_wifi_interfaces()
            
            if interfaces:
                # Default to the first Alfa interface if found, otherwise use the first available
                alfa_interfaces = [iface for iface in interfaces if "alfa" in iface.lower()]
                interface = alfa_interfaces[0] if alfa_interfaces else interfaces[0]
                scanner = NetworkScanner(interface)
                logger.info(f"Scanner initialized with interface: {interface}")
                return True
            else:
                logger.error("No WiFi interfaces found")
                return False
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {str(e)}")
            return False
    return True

def background_scan():
    """Background scan function to run in a separate thread"""
    global scan_active, scan_results, detected_rogue_aps
    
    if not initialize_scanner():
        scan_active = False
        return
    
    try:
        logger.info("Starting background scan")
        # Continuously scan while scan_active is True
        while scan_active:
            # Scan for networks
            networks = scanner.scan_networks()
            
            # Analyze security of the networks
            analyzed_networks = []
            for network in networks:
                security_info = analyzer.analyze_network(network)
                analyzed_networks.append({**network, **security_info})
            
            # Detect deauthentication attacks
            deauth_results = deauth_detector.detect_deauth(scanner.interface)
            
            # Update global results
            scan_results = analyzed_networks
            detected_rogue_aps = deauth_results
            
            # Brief pause before next scan
            time.sleep(2)
            
    except Exception as e:
        logger.error(f"Error in background scan: {str(e)}")
    finally:
        scan_active = False
        logger.info("Background scan stopped")

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Start or stop scanning for WiFi networks"""
    global scan_active, scan_thread
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start' and not scan_active:
            # Start scanning in a background thread
            scan_active = True
            scan_thread = threading.Thread(target=background_scan)
            scan_thread.daemon = True
            scan_thread.start()
            flash('Scanning started', 'success')
            
        elif action == 'stop' and scan_active:
            # Stop scanning
            scan_active = False
            if scan_thread:
                scan_thread.join(timeout=5.0)
            flash('Scanning stopped', 'info')
            
        return redirect(url_for('networks'))
    
    # GET request - show the current status
    return render_template('networks.html', 
                           scan_active=scan_active,
                           networks=scan_results,
                           rogue_aps=detected_rogue_aps)

@app.route('/networks')
def networks():
    """Show detected networks"""
    return render_template('networks.html', 
                         scan_active=scan_active,
                         networks=scan_results,
                         rogue_aps=detected_rogue_aps)

@app.route('/api/networks')
def api_networks():
    """API endpoint for network data (for AJAX updates)"""
    return jsonify({
        'scan_active': scan_active,
        'networks': scan_results,
        'rogue_aps': detected_rogue_aps
    })

@app.route('/brute-force', methods=['GET', 'POST'])
def brute_force():
    """Brute force page and functionality"""
    results = None
    target_info = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start_brute_force':
            ssid = request.form.get('ssid')
            bssid = request.form.get('bssid')
            security = request.form.get('security')
            wordlist = request.form.get('wordlist', 'data/wordlist.txt')
            
            if ssid and bssid and security:
                target_info = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'security': security
                }
                
                try:
                    # Start brute force attack
                    flash('Starting brute force attempt. This may take some time...', 'info')
                    result = brute_forcer.crack_password(ssid, bssid, security, wordlist)
                    if result:
                        flash(f'Password found: {result}', 'success')
                        results = {'password': result, 'status': 'success'}
                    else:
                        flash('Password not found in wordlist', 'warning')
                        results = {'status': 'failed'}
                except Exception as e:
                    flash(f'Error: {str(e)}', 'danger')
                    results = {'status': 'error', 'message': str(e)}
            else:
                flash('Missing required information', 'danger')
    
    # Get available interfaces for the form
    from utils import get_wifi_interfaces
    interfaces = get_wifi_interfaces()
    
    return render_template('brute_force.html', 
                          networks=scan_results,
                          results=results,
                          target_info=target_info,
                          interfaces=interfaces)

@app.route('/interfaces')
def interfaces():
    """Get available wireless interfaces"""
    from utils import get_wifi_interfaces
    interfaces = get_wifi_interfaces()
    return jsonify({'interfaces': interfaces})

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

with app.app_context():
    # Import models and create tables
    import models
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
