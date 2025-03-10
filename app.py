#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Main Application
This module serves as the entry point for the Syslog management system.
It initializes the Flask web server and the Syslog server.
"""

import os
import json
import threading
import logging
import ssl
import psutil
import time
import syslog_handler
from system_monitor import get_monitor
from syslog_handler import get_system_metrics, queue_manager
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from monitoring import get_monitoring_status, update_monitoring_config, start_monitoring, stop_monitoring, monitoring_config as mc
from config import Config
from auth import User, init_users, save_users
from syslog_handler import start_syslog_server, get_source_stats, parse_logs_for_timerange

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("syslog_manager.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add datetime function to templates
@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure required directories exist
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('certs', exist_ok=True)

# Initialize users
users = init_users()

# Certificate upload form
class CertificateForm(FlaskForm):
    cert_file = FileField('Certificate File (PEM)', validators=[DataRequired()])
    key_file = FileField('Private Key File (PEM)', validators=[DataRequired()])
    submit = SubmitField('Upload')

# Load source configurations
def load_sources():
    if os.path.exists('data/sources.json'):
        with open('data/sources.json', 'r') as f:
            return json.load(f)
    return {}

def save_sources(sources):
    with open('data/sources.json', 'w') as f:
        json.dump(sources, f, indent=4)

sources = load_sources()

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
@login_required
def index():
    """Render the main dashboard."""
    # Get updated stats for each source
    source_stats = get_source_stats(sources)
    
    # If this is the first login with default credentials, redirect to change password
    if current_user.id == 'admin' and current_user.must_change_password:
        flash('You must change your password before proceeding.', 'warning')
        return redirect(url_for('change_password'))
        
    return render_template('dashboard.html', sources=source_stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users.get(username)
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/monitor')
@login_required
def monitor():
    """Render the monitoring configuration page."""
    # If this is the first login with default credentials, redirect to change password
    if current_user.id == 'admin' and current_user.must_change_password:
        flash('You must change your password before proceeding.', 'warning')
        return redirect(url_for('change_password'))
        
    return render_template('monitor.html')
    
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Handle password change."""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
        else:
            # Update password
            current_user.password_hash = generate_password_hash(new_password)
            current_user.must_change_password = False
            save_users(users)
            flash('Password changed successfully', 'success')
            return redirect(url_for('index'))
            
    return render_template('change_password.html')

@app.route('/certificates', methods=['GET', 'POST'])
@login_required
def certificates():
    """Handle SSL certificate management."""
    form = CertificateForm()
    cert_status = {
        'has_cert': os.path.exists(os.path.join('certs', 'certificate.pem')),
        'has_key': os.path.exists(os.path.join('certs', 'private_key.pem')),
        'is_valid': False
    }
    
    # Check if certificate and key are valid
    if cert_status['has_cert'] and cert_status['has_key']:
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                os.path.join('certs', 'certificate.pem'),
                os.path.join('certs', 'private_key.pem')
            )
            cert_status['is_valid'] = True
        except Exception as e:
            logger.error(f"Error validating certificate: {str(e)}")
    
    if form.validate_on_submit():
        # Save certificate file
        cert_file = form.cert_file.data
        cert_filename = 'certificate.pem'
        cert_path = os.path.join('certs', cert_filename)
        cert_file.save(cert_path)
        
        # Save private key file
        key_file = form.key_file.data
        key_filename = 'private_key.pem'
        key_path = os.path.join('certs', key_filename)
        key_file.save(key_path)
        
        # Verify the certificate and key
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            flash('SSL certificate and private key uploaded successfully. Restart the server to apply changes.', 'success')
            return redirect(url_for('certificates'))
        except Exception as e:
            os.remove(cert_path)
            os.remove(key_path)
            flash(f'Invalid certificate or private key: {str(e)}', 'danger')
    
    return render_template('certificates.html', form=form, cert_status=cert_status)

@csrf.exempt
@app.route('/api/monitoring', methods=['GET', 'POST'])
@login_required
def api_monitoring():
    """API endpoint for monitoring configuration."""
    if request.method == 'POST':
        try:
            config_data = request.json
            if not config_data:
                return jsonify({'status': 'error', 'message': 'Invalid JSON data received'}), 400
            
            # Update monitoring configuration
            status = update_monitoring_config(config_data)
            return jsonify({'status': 'success', 'data': status})
        except Exception as e:
            logger.error(f"Error updating monitoring configuration: {str(e)}", exc_info=True)
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # GET request - return current monitoring status
    try:
        status = get_monitoring_status()
        return jsonify({'status': 'success', 'data': status})
    except Exception as e:
        logger.error(f"Error getting monitoring status: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@csrf.exempt
@app.route('/api/monitoring/test', methods=['POST'])
@login_required
def api_monitoring_test():
    """API endpoint to test monitoring heartbeat."""
    try:
        # Get current metrics
        metrics = mc._collect_metrics()
        
        # If HEC is configured, try to send a test heartbeat
        if mc.hec_url and mc.hec_token:
            mc._send_heartbeat(metrics)
            return jsonify({
                'status': 'success',
                'message': 'Test heartbeat sent successfully',
                'data': metrics
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'HEC URL or token not configured',
                'data': metrics
            }), 400
    except Exception as e:
        logger.error(f"Error testing monitoring heartbeat: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


# Exempt CSRF for API sources endpoint
@csrf.exempt
@app.route('/api/sources', methods=['GET', 'POST'])
@login_required
def api_sources():
    """API endpoint for source management."""
    global sources
    
    if request.method == 'POST':
        try:
            source_data = request.json
            if not source_data:
                logger.error("Invalid JSON data received")
                return jsonify({'status': 'error', 'message': 'Invalid JSON data received'}), 400
                
            source_id = source_data.get('id')
            
            # Log received data for debugging
            logger.info(f"Received source data: {source_data}")
            
            # Validate source data
            if not source_data.get('name'):
                return jsonify({'status': 'error', 'message': 'Source name is required'}), 400
                
            if not source_data.get('target_directory'):
                return jsonify({'status': 'error', 'message': 'Target directory is required'}), 400
                
            if not source_data.get('source_ips') or not isinstance(source_data.get('source_ips'), list):
                return jsonify({'status': 'error', 'message': 'At least one source IP is required'}), 400
            
            # Validate target directory access
            target_dir = source_data.get('target_directory')
            logger.info(f"Validating target directory: {target_dir}")
            
            if not os.path.exists(target_dir):
                try:
                    logger.info(f"Creating target directory: {target_dir}")
                    os.makedirs(target_dir, exist_ok=True)
                    # Verify we can write to it
                    test_file = os.path.join(target_dir, '.test_write')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    logger.info(f"Successfully created and verified write access to: {target_dir}")
                except PermissionError as e:
                    logger.error(f"Permission error accessing target directory {target_dir}: {str(e)}")
                    return jsonify({'status': 'error', 'message': f'Permission denied to target directory: {str(e)}'}), 400
                except Exception as e:
                    logger.error(f"Error accessing target directory {target_dir}: {str(e)}")
                    return jsonify({'status': 'error', 'message': f'Cannot access target directory: {str(e)}'}), 400
            
            # Update sources and save
            try:
                if source_id:
                    # Update existing source
                    logger.info(f"Updating existing source: {source_id}")
                    sources[source_id] = source_data
                else:
                    # Add new source with auto-generated ID
                    import uuid
                    new_id = str(uuid.uuid4())
                    source_data['id'] = new_id
                    logger.info(f"Creating new source with ID: {new_id}")
                    sources[new_id] = source_data
                    
                    # Create empty JSON file for this source
                    source_json_path = os.path.join('data', f'{new_id}.json')
                    logger.info(f"Creating JSON file: {source_json_path}")
                    with open(source_json_path, 'w') as f:
                        json.dump([], f)
                
                # Save sources configuration
                logger.info("Saving sources configuration")
                save_sources(sources)
                
                return jsonify({'status': 'success', 'sources': sources})
            except Exception as e:
                logger.error(f"Error saving source data: {str(e)}", exc_info=True)
                return jsonify({'status': 'error', 'message': f'Error saving source: {str(e)}'}), 500
                
        except Exception as e:
            logger.error(f"Unexpected error in API sources: {str(e)}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Unexpected error: {str(e)}'}), 500
    
    # GET request - return all sources with stats
    try:
        source_stats = get_source_stats(sources)
        return jsonify({'status': 'success', 'sources': source_stats})
    except Exception as e:
        logger.error(f"Error getting source stats: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error retrieving sources: {str(e)}'}), 500

# Exempt CSRF for API endpoints
@csrf.exempt
@app.route('/api/sources/<source_id>', methods=['GET', 'DELETE'])
@login_required
def api_source(source_id):
    """API endpoint for individual source operations."""
    global sources
    
    if source_id not in sources:
        return jsonify({'status': 'error', 'message': 'Source not found'}), 404
    
    if request.method == 'DELETE':
        del sources[source_id]
        save_sources(sources)
        return jsonify({'status': 'success'})
    
    # GET request - return specific source with stats
    source_data = sources[source_id]
    stats = get_source_stats({source_id: source_data})
    return jsonify({'status': 'success', 'source': stats.get(source_id, {})})


@csrf.exempt
@app.route('/api/investigate/<source_id>', methods=['POST'])
@login_required
def api_investigate(source_id):
    """API endpoint for log investigation."""
    if source_id not in sources:
        return jsonify({'status': 'error', 'message': 'Source not found'}), 404
    
    timerange = request.json
    start_time = timerange.get('start')
    end_time = timerange.get('end')
    
    # Get pagination parameters
    page = int(timerange.get('page', 1))
    page_size = int(timerange.get('page_size', 1000))
    
    # Validate pagination
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 5000:
        page_size = 1000
    
    if not start_time or not end_time:
        return jsonify({'status': 'error', 'message': 'Invalid time range'}), 400
    
    try:
        # Calculate effective max_results based on pagination
        max_results = page * page_size
        
        # Get logs with streaming parser
        log_data = parse_logs_for_timerange(source_id, start_time, end_time, max_results)
        
        # Apply pagination
        total_count = len(log_data)
        start_index = (page - 1) * page_size
        end_index = min(start_index + page_size, total_count)
        
        paginated_data = log_data[start_index:end_index]
        
        # Return paginated results with metadata
        return jsonify({
            'status': 'success', 
            'data': paginated_data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_count': total_count,
                'total_pages': (total_count + page_size - 1) // page_size
            },
            'has_more': end_index < total_count
        })
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error processing logs: {str(e)}'}), 500

@app.route('/api/system_stats', methods=['GET'])
@login_required
def api_system_stats():
    """API endpoint for system performance statistics."""
    try:
        # Get system metrics
        stats = syslog_handler.get_system_metrics()
        
        return jsonify({
            "status": "success",
            "stats": stats
        })
    except Exception as e:
        logger.error(f"Error getting system stats: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Error retrieving system stats: {str(e)}"
        }), 500
        
def get_ssl_context():
    """Get SSL context for HTTPS if certificate and key exist."""
    cert_path = os.path.join('certs', 'certificate.pem')
    key_path = os.path.join('certs', 'private_key.pem')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            return context
        except Exception as e:
            logger.error(f"Error loading SSL certificate: {str(e)}")
    
    return None

def start_web_server():
    """Start the web server based on environment and SSL configuration."""
    flask_env = os.environ.get('FLASK_ENV', 'production').lower()
    ssl_context = get_ssl_context()
    
    if flask_env == 'development':
        logger.info(f"Starting Flask development server on {Config.FLASK_HOST}:{Config.FLASK_PORT}")
        app.run(
            host=Config.FLASK_HOST,
            port=Config.FLASK_PORT,
            debug=Config.DEBUG,
            ssl_context=ssl_context
        )
    else:
        # Production mode - use Waitress with SSL if available
        from waitress import serve
        threads = int(os.environ.get('WAITRESS_THREADS', 4))
        
        if ssl_context:
            # For SSL with Waitress, we need to use a TLS-enabled server adapter
            import ssl
            from waitress.server import create_server
            
            server = create_server(
                app,
                host=Config.FLASK_HOST,
                port=Config.FLASK_PORT,
                threads=threads,
                url_scheme='https'
            )
            
            # Wrap the socket with SSL
            server.socket = ssl_context.wrap_socket(
                server.socket,
                server_side=True
            )
            
            logger.info(f"Starting Waitress production server with HTTPS on {Config.FLASK_HOST}:{Config.FLASK_PORT} with {threads} threads")
            server.run()
        else:
            logger.info(f"Starting Waitress production server on {Config.FLASK_HOST}:{Config.FLASK_PORT} with {threads} threads")
            serve(
                app, 
                host=Config.FLASK_HOST, 
                port=Config.FLASK_PORT,
                threads=threads
            )

@csrf.exempt
@app.route('/api/monitor')
@login_required
def api_monitor():
    """API endpoint for monitoring data."""
    try:
        # Get metrics from the queue manager
        queue_metrics = get_system_metrics()
        
        # Get system monitor metrics
        sys_monitor = get_monitor()
        system_metrics = sys_monitor.get_current_metrics()
        history_metrics = sys_monitor.get_history_metrics()
        
        # Debug worker status
        active_workers = 0
        max_workers = 0
        worker_status = []
        
        if queue_manager:
            active_workers = queue_manager.active_workers
            max_workers = queue_manager.max_workers
            worker_status = [{"name": t.name, "alive": t.is_alive()} for t in queue_manager.workers]
            logger.debug(f"Queue manager workers: active={active_workers}, total={len(queue_manager.workers)}")
            logger.debug(f"Worker status: {worker_status}")
        else:
            logger.warning("Queue manager is not initialized")
        
        # Combine metrics for the response
        response_data = {
            # Current values
            'current_eps': queue_metrics.get('current_eps', 0),
            'cpu_usage': system_metrics.get('cpu_usage', 0),
            'memory_usage': system_metrics.get('memory_usage', 0),
            'queue_size': queue_metrics.get('queue_size', 0),
            'queue_capacity': 200000,  # This should match the queue_size parameter in QueueManager
            'active_workers': active_workers,
            'max_workers': max_workers,
            'messages_processed': queue_metrics.get('messages_processed', 0),
            'worker_status': worker_status,
            
            # Historical data for charts
            'eps_history': {
                'timestamps': history_metrics.get('timestamp', []),
                'values': history_metrics.get('eps', [])
            },
            'resource_history': {
                'timestamps': history_metrics.get('timestamp', []),
                'cpu': history_metrics.get('cpu_usage', []),
                'memory': history_metrics.get('memory_usage', [])
            }
        }
        
        # Update EPS in system monitor
        if 'current_eps' in queue_metrics:
            sys_monitor.update_eps(queue_metrics['current_eps'])
        
        return jsonify({'status': 'success', 'data': response_data})
    except Exception as e:
        logger.error(f"Error getting monitoring data: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error retrieving monitoring data: {str(e)}'}), 500
        
    
if __name__ == '__main__':
    # Start log workers (4 workers by default - adjust based on your needs)
    syslog_handler.start_log_worker(num_workers=4)
    logger.info("Started log processing workers")
    
    # Start syslog server in a separate thread
    syslog_thread = threading.Thread(
        target=syslog_handler.start_syslog_server,
        args=(sources,),
        daemon=True
    )
    syslog_thread.start()
    logger.info("Started syslog server thread")
    
    # Give the servers a moment to initialize
    time.sleep(1)
    
    # Start web server
    start_web_server()
    start_monitoring()