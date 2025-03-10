#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Syslog Handler
This module handles the reception and processing of syslog messages.
"""

import os
import json
import time
import socket
import logging
import threading
import socketserver
import ipaddress
from datetime import datetime
import pandas as pd
from dateutil import parser
import re

from config import Config
from utils import check_memory_usage, is_ip_in_network
from queue_manager import QueueManager

# Configure logging
logger = logging.getLogger(__name__)

# Global queue manager
queue_manager = None

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """
    UDP handler for syslog messages.
    Processes incoming syslog messages and enqueues them for processing.
    """
    
    def handle(self):
        """Handle incoming syslog message."""
        global queue_manager
        
        try:
            # Get data and client address
            data = bytes.decode(self.request[0].strip(), 'utf-8')
            socket = self.request[1]
            client_address = self.client_address[0]
            
            # Parse timestamp from syslog message
            timestamp = self.extract_timestamp(data)
            if not timestamp:
                timestamp = datetime.now()
            
            # Enqueue the message for processing
            if queue_manager:
                queue_manager.enqueue_message(client_address, data, timestamp)
            else:
                logger.error("Queue manager not initialized, dropping message")
            
        except Exception as e:
            logger.error(f"Error handling syslog message: {str(e)}", exc_info=True)
    
    def extract_timestamp(self, message):
        """
        Extract timestamp from syslog message.
        
        Args:
            message (str): The syslog message
            
        Returns:
            datetime: The extracted timestamp or None if not found
        """
        # Try RFC5424 format first: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        rfc5424_pattern = r'^<\d+>\d+ (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+|-)\d{2}:\d{2}) '
        rfc5424_match = re.search(rfc5424_pattern, message)
        if rfc5424_match:
            try:
                return parser.parse(rfc5424_match.group(1))
            except Exception:
                pass
        
        # Try RFC3164 format: <PRI>TIMESTAMP HOSTNAME
        rfc3164_pattern = r'^<\d+>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        rfc3164_match = re.search(rfc3164_pattern, message)
        if rfc3164_match:
            try:
                # Add current year as RFC3164 doesn't include it
                current_year = datetime.now().year
                timestamp_str = f"{rfc3164_match.group(1)} {current_year}"
                return parser.parse(timestamp_str)
            except Exception:
                pass
        
        # No timestamp found, return None
        return None

def start_syslog_server(sources):
    """
    Start the syslog server to receive messages.
    
    Args:
        sources (dict): The source configurations
    """
    global queue_manager
    
    # Initialize queue manager with source configurations
    # Calculate reasonable defaults based on system resources
    import multiprocessing
    cpu_count = multiprocessing.cpu_count()
    
    # Start with worker count based on CPUs, but cap based on expected load
    min_workers = max(2, cpu_count // 2)  # At least 2 workers
    max_workers = max(min_workers * 2, cpu_count * 2)  # Scale based on CPUs
    
    # Initialize the queue manager
    logger.info(f"Initializing QueueManager with min_workers={min_workers}, max_workers={max_workers}")
    queue_manager = QueueManager(
        sources=sources,
        max_workers=max_workers,
        min_workers=min_workers,
        queue_size=200000  # Buffer up to 200k messages (adjust based on memory)
    )
    
    host = Config.SYSLOG_HOST
    port = Config.SYSLOG_PORT
    
    try:
        # For high throughput, use a more efficient server
        class SyslogUDPServer(socketserver.ThreadingUDPServer):
            # Increase socket buffer size for high volume
            def server_bind(self):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)  # 8MB buffer
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                socketserver.ThreadingUDPServer.server_bind(self)
        
        server = SyslogUDPServer((host, port), SyslogUDPHandler)
        logger.info(f"Starting syslog server on {host}:{port}")
        server.serve_forever()
    except Exception as e:
        logger.error(f"Error starting syslog server: {str(e)}", exc_info=True)

def get_source_stats(sources):
    """
    Get statistics for each source.
    
    Args:
        sources (dict): The source configurations
        
    Returns:
        dict: The source statistics
    """
    stats = {}
    
    for source_id, source_config in sources.items():
        # Look for date-based metadata
        metadata_file = os.path.join('data', f'{source_id}_dates.json')
        dates = []
        log_count = 0
        last_log_time = None
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    content = f.read()
                    if not content.strip():
                        # File exists but is empty, initialize with empty structure
                        metadata = {"dates": [], "files": {}}
                        with open(metadata_file, 'w') as f_write:
                            json.dump(metadata, f_write, indent=2)
                    else:
                        metadata = json.loads(content)
                
                # Handle different metadata formats
                if isinstance(metadata, list):
                    dates = metadata
                    if dates:
                        most_recent_date = dates[-1]
                    else:
                        most_recent_date = None
                elif isinstance(metadata, dict):
                    dates = metadata.get("dates", [])
                    if dates:
                        most_recent_date = dates[-1]
                    else:
                        most_recent_date = None
                else:
                    logger.warning(f"Unexpected metadata format for source {source_id}, initializing new format")
                    metadata = {"dates": [], "files": {}}
                    with open(metadata_file, 'w') as f_write:
                        json.dump(metadata, f_write, indent=2)
                    most_recent_date = None
                
                # If we have dates, calculate log count and last log time
                if most_recent_date:
                    # Get target directory
                    target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
                    
                    # Get all files for this date
                    files_for_date = []
                    if isinstance(metadata, dict) and "files" in metadata:
                        files_for_date = metadata["files"].get(most_recent_date, [])
                    
                    if not files_for_date:
                        files_for_date = [f"{most_recent_date}.json"]
                    
                    # Calculate total log count and find last log time
                    for filename in files_for_date:
                        log_file = os.path.join(target_dir, filename)
                        
                        if os.path.exists(log_file):
                            try:
                                with open(log_file, 'r') as f:
                                    logs = json.load(f)
                                    
                                    # Count logs
                                    log_count += len(logs)
                                    
                                    # Get last log time
                                    if logs:
                                        file_last_time = logs[-1]['timestamp']
                                        if last_log_time is None or file_last_time > last_log_time:
                                            last_log_time = file_last_time
                            except Exception as e:
                                logger.error(f"Error reading log file {log_file}: {str(e)}")
            except Exception as e:
                logger.error(f"Error reading metadata for source {source_id}: {str(e)}", exc_info=True)
                # Create empty metadata file with proper structure
                metadata = {"dates": [], "files": {}}
                try:
                    with open(metadata_file, 'w') as f:
                        json.dump(metadata, f, indent=2)
                except Exception as write_error:
                    logger.error(f"Failed to initialize metadata file: {str(write_error)}")
        
        # Create stats
        stats[source_id] = source_config.copy()
        stats[source_id]['log_count'] = log_count
        stats[source_id]['last_log_time'] = last_log_time
        stats[source_id]['date_range'] = dates
    
    return stats

def parse_logs_for_timerange(source_id, start_time, end_time, max_results=1000):
    """
    Parse logs for a specific source and time range using streaming processing.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        max_results (int, optional): Maximum number of results to return
        
    Returns:
        list: The parsed log data
    """
    import ijson  # Incremental JSON parser for streaming
    
    # Parse time range
    try:
        start_dt = parser.parse(start_time)
        end_dt = parser.parse(end_time)
    except Exception as e:
        logger.error(f"Error parsing time range: {str(e)}")
        raise ValueError(f"Invalid time format: {str(e)}")
    
    # Format dates for filename lookup
    start_date = start_dt.date()
    end_date = end_dt.date()
    
    # Get metadata for this source
    metadata_file = os.path.join('data', f'{source_id}_dates.json')
    if not os.path.exists(metadata_file):
        return []
    
    try:
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
            
            # Handle metadata format (old or new)
            if isinstance(metadata, list):
                available_dates = metadata
                file_mapping = {date_str: [f"{date_str}.json"] for date_str in metadata}
            else:
                available_dates = metadata.get("dates", [])
                file_mapping = metadata.get("files", {})
    except Exception as e:
        logger.error(f"Error reading metadata: {str(e)}")
        raise ValueError(f"Error reading source data: {str(e)}")
    
    # Get source config to determine directory
    sources_file = os.path.join('data', 'sources.json')
    target_dir = os.path.join('logs', source_id)
    
    try:
        if os.path.exists(sources_file):
            with open(sources_file, 'r') as f:
                sources = json.load(f)
                if source_id in sources:
                    target_dir = sources[source_id].get('target_directory', target_dir)
    except Exception as e:
        logger.error(f"Error reading sources config: {str(e)}")
    
    # Find all dates in range
    relevant_dates = []
    for date_str in available_dates:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if start_date <= date <= end_date:
                relevant_dates.append(date_str)
        except ValueError:
            logger.warning(f"Invalid date format in metadata: {date_str}")
    
    # Read logs from each relevant date using streaming
    all_logs = []
    
    for date_str in relevant_dates:
        # Get all files for this date
        date_files = file_mapping.get(date_str, [f"{date_str}.json"])
        
        for filename in date_files:
            log_file = os.path.join(target_dir, filename)
            
            if not os.path.exists(log_file):
                continue
            
            try:
                # Use streaming JSON parser to avoid loading the entire file into memory
                with open(log_file, 'rb') as f:
                    # Stream the array items
                    parser = ijson.items(f, 'item')
                    
                    for log in parser:
                        try:
                            log_time = parser.parse(log.get('timestamp', ''))
                            
                            # Filter by time range
                            if start_dt <= log_time <= end_dt:
                                # Format the log for display
                                all_logs.append({
                                    'timestamp': log.get('timestamp', ''),
                                    'source_ip': log.get('source_ip', ''),
                                    'message': log.get('message', ''),
                                    'filename': filename
                                })
                                
                                # Check if we've reached the result limit
                                if len(all_logs) >= max_results:
                                    logger.info(f"Result limit reached ({max_results}), stopping log collection")
                                    break
                                    
                        except Exception as e:
                            logger.warning(f"Error parsing log entry: {str(e)}")
                            continue
                    
                    # Stop if we've reached the result limit
                    if len(all_logs) >= max_results:
                        break
                        
            except Exception as e:
                logger.error(f"Error processing log file {log_file}: {str(e)}")
        
        # Stop if we've reached the result limit
        if len(all_logs) >= max_results:
            break
    
    # Sort logs by timestamp
    all_logs.sort(key=lambda x: x.get('timestamp', ''))
    
    # Apply max results limit
    return all_logs[:max_results]

def get_system_metrics():
    """
    Get system performance metrics.
    
    Returns:
        dict: System metrics including CPU, memory, and EPS rates
    """
    global queue_manager
    
    if queue_manager:
        return queue_manager.get_metrics()
    else:
        return {
            'queue_size': 0,
            'messages_processed': 0,
            'current_eps': 0,
            'eps_history': [],
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.Process().memory_percent()
        }