#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Investigation Module
This module handles log investigation functionality.
"""

import os
import json
import logging
import csv
import io
from flask import render_template, request, jsonify, url_for, flash, redirect, Response
from flask_login import login_required, current_user
from datetime import datetime
from dateutil import parser

logger = logging.getLogger(__name__)

def init_investigation_routes(app, sources):
    """
    Initialize investigation routes.
    
    Args:
        app: Flask application instance
        sources: Source configurations dictionary
    """
    
    @app.route('/investigation')
    @login_required
    def investigation():
        """Render the investigation page."""
        # If this is the first login with default credentials, redirect to change password
        if current_user.id == 'admin' and current_user.must_change_password:
            flash('You must change your password before proceeding.', 'warning')
            return redirect(url_for('change_password'))
        
        # Get folder-based sources only
        folder_sources = {k: v for k, v in sources.items() if v.get('target_type', 'folder') == 'folder'}
        
        return render_template('investigation.html', sources=folder_sources)
    
    @app.route('/api/export_logs', methods=['POST'])
    @login_required
    def export_logs():
        """Export logs to CSV."""
        try:
            source_id = request.form.get('source_id')
            start_time = request.form.get('start')
            end_time = request.form.get('end')
            
            if not source_id or not start_time or not end_time:
                flash('Missing required parameters for export', 'danger')
                return redirect(url_for('investigation'))
            
            # Get source name
            source_name = sources.get(source_id, {}).get('name', 'unknown')
            
            # Generate filename based on source and time range
            filename = f"{source_name}_logs_{start_time.replace(' ', 'T').replace(':', '-')}_to_{end_time.replace(' ', 'T').replace(':', '-')}.csv"
            
            # Get logs - without pagination limits to get all logs
            logs = fetch_logs_for_export(source_id, start_time, end_time)
            
            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Timestamp', 'Source IP', 'Message', 'Filename'])
            
            # Write log data
            for log in logs:
                writer.writerow([
                    log.get('timestamp', ''),
                    log.get('source_ip', ''),
                    log.get('message', ''),
                    log.get('filename', '')
                ])
            
            # Create response
            response = Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error exporting logs: {str(e)}", exc_info=True)
            flash(f'Error exporting logs: {str(e)}', 'danger')
            return redirect(url_for('investigation'))

def fetch_logs_for_timerange(source_id, start_time, end_time, page=1, page_size=25):
    """
    Parse logs for a specific source and time range with pagination.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        page (int): The page number for pagination
        page_size (int): The number of logs per page
        
    Returns:
        tuple: (logs_list, pagination_info)
    """
    from syslog_handler import parse_logs_for_timerange as base_parse_logs
    
    try:
        # Calculate effective max_results based on pagination
        max_results = page * page_size
        
        # Call base function to get logs
        log_data = base_parse_logs(source_id, start_time, end_time, max_results)
        
        # Calculate total count without limits for pagination info
        total_count = len(log_data)
        
        # Apply pagination manually
        start_index = (page - 1) * page_size
        end_index = min(start_index + page_size, total_count)
        
        paginated_data = log_data[start_index:end_index]
        
        # Prepare pagination info
        pagination_info = {
            'page': page,
            'page_size': page_size,
            'total_count': total_count,
            'total_pages': (total_count + page_size - 1) // page_size if page_size > 0 else 1
        }
        
        return paginated_data, pagination_info
    except Exception as e:
        logger.error(f"Error fetching logs for time range: {str(e)}", exc_info=True)
        raise

def fetch_logs_for_export(source_id, start_time, end_time):
    """
    Fetch all logs for export without pagination limits.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        
    Returns:
        list: All logs in the specified time range
    """
    from syslog_handler import parse_logs_for_timerange as base_parse_logs
    
    try:
        # Get all logs without limit
        log_data = base_parse_logs(source_id, start_time, end_time, max_results=0)
        return log_data
    except Exception as e:
        logger.error(f"Error fetching logs for export: {str(e)}", exc_info=True)
        raise