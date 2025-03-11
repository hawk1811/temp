#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Event Logs Module
This module handles functionality related to viewing and managing application event logs.
"""

import os
import re
import logging
from flask import jsonify, request, render_template
from flask_login import login_required

logger = logging.getLogger(__name__)

def init_event_logs_routes(app):
    """
    Initialize event logs routes.
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/event_logs')
    @login_required
    def manage_event_logs():
        """Render the event logs page."""
        return render_template('event_logs.html')
    
    @app.route('/api/event_logs', methods=['GET'])
    @login_required
    def api_event_logs():
        """API endpoint for fetching event logs."""
        try:
            logs = parse_event_log_file()
            return jsonify({
                'status': 'success',
                'logs': logs
            })
        except Exception as e:
            logger.error(f"Error parsing event logs: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Error fetching event logs: {str(e)}'
            }), 500
    
    @app.route('/api/event_logs/clear', methods=['POST'])
    @login_required
    def api_clear_event_logs():
        """API endpoint for clearing event logs."""
        try:
            clear_event_log_file()
            return jsonify({
                'status': 'success',
                'message': 'Event logs cleared successfully'
            })
        except Exception as e:
            logger.error(f"Error clearing event logs: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Error clearing event logs: {str(e)}'
            }), 500

def parse_event_log_file():
    """
    Parse the application event log file.
    
    Returns:
        list: List of parsed log entries
    """
    log_file = 'syslog_manager.log'
    log_entries = []
    
    if not os.path.exists(log_file):
        return log_entries
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Parse log line
                entry = parse_log_line(line)
                if entry:
                    log_entries.append(entry)
        
        # Sort by timestamp (newest first)
        log_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return log_entries
    except Exception as e:
        logger.error(f"Error reading log file: {str(e)}")
        raise

def parse_log_line(line):
    """
    Parse a single log line into a structured format.
    
    Args:
        line (str): The log line to parse
        
    Returns:
        dict: Parsed log entry or None if parsing failed
    """
    # Match log format: YYYY-MM-DD HH:MM:SS,SSS - module - LEVEL - message
    pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - ([^-]+) - ([A-Z]+) - (.+)$'
    match = re.match(pattern, line.strip())
    
    if match:
        timestamp, module, level, message = match.groups()
        return {
            'timestamp': timestamp,
            'module': module.strip(),
            'level': level.strip(),
            'message': message.strip()
        }
    
    return None

def clear_event_log_file():
    """Clear the application event log file."""
    log_file = 'syslog_manager.log'
    
    if os.path.exists(log_file):
        try:
            # Create a backup before clearing
            backup_file = f"{log_file}.bak"
            if os.path.exists(backup_file):
                os.remove(backup_file)
            
            os.rename(log_file, backup_file)
            
            # Create new empty log file
            with open(log_file, 'w') as f:
                pass
            
            logger.info("Event log file cleared")
        except Exception as e:
            logger.error(f"Error clearing log file: {str(e)}")
            raise