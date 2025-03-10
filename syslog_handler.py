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

# Configure logging
logger = logging.getLogger(__name__)

# Global source configuration
global_sources = {}
source_locks = {}  # For thread-safe access to source metadata

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """
    UDP handler for syslog messages.
    Processes incoming syslog messages and stores them in the appropriate files.
    """
    
    def handle(self):
        """Handle incoming syslog message."""
        try:
            # Get data and client address
            data = bytes.decode(self.request[0].strip(), 'utf-8')
            socket = self.request[1]
            client_address = self.client_address[0]
            
            # Process the syslog message
            self.process_syslog(client_address, data)
            
        except Exception as e:
            logger.error(f"Error handling syslog message: {str(e)}", exc_info=True)
    
    def process_syslog(self, client_ip, message):
        """
        Process a syslog message and store it in the appropriate file.
        
        Args:
            client_ip (str): The IP address of the client sending the message
            message (str): The syslog message content
        """
        # Skip if memory usage is too high
        if check_memory_usage() > Config.MAX_MEMORY_USAGE:
            logger.warning("Memory usage too high, dropping syslog message")
            return
        
        # Parse timestamp from syslog message (RFC3164/RFC5424 formats)
        timestamp = self.extract_timestamp(message)
        if not timestamp:
            timestamp = datetime.now()
        
        # Find matching source for this client IP
        source_id = self.find_matching_source(client_ip)
        if not source_id:
            # No matching source found, store in default location
            target_dir = os.path.join('logs', 'unknown')
            os.makedirs(target_dir, exist_ok=True)
            self.store_log(target_dir, timestamp, client_ip, message)
            return
        
        # Get source configuration
        source_config = global_sources.get(source_id, {})
        target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
        
        # Make sure target directory exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Store the log
        log_filename = self.store_log(target_dir, timestamp, client_ip, message)
        
        # Update source metadata
        self.update_source_metadata(source_id, timestamp, log_filename)
    
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
    
    def find_matching_source(self, client_ip):
        """
        Find the source configuration that matches the client IP.
        
        Args:
            client_ip (str): The client IP address
            
        Returns:
            str: The source ID or None if not found
        """
        for source_id, source_config in global_sources.items():
            source_ips = source_config.get('source_ips', [])
            for ip_entry in source_ips:
                if is_ip_in_network(client_ip, ip_entry):
                    return source_id
        
        return None
    
    def store_log(self, target_dir, timestamp, client_ip, message):
        """
        Store log message in a file.
        
        Args:
            target_dir (str): The target directory
            timestamp (datetime): The message timestamp
            client_ip (str): The client IP address
            message (str): The syslog message
            
        Returns:
            str: The log filename
        """
        # Create filename based on timestamp
        filename = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{timestamp.microsecond:06d}.log"
        filepath = os.path.join(target_dir, filename)
        
        # Store log with metadata
        with open(filepath, 'w') as f:
            f.write(f"Timestamp: {timestamp.isoformat()}\n")
            f.write(f"Source IP: {client_ip}\n")
            f.write(f"Message: {message}\n")
        
        return filename
    
    def update_source_metadata(self, source_id, timestamp, log_filename):
        """
        Update source metadata with new log entry.
        
        Args:
            source_id (str): The source ID
            timestamp (datetime): The message timestamp
            log_filename (str): The log filename
        """
        # Acquire lock for this source
        lock = source_locks.get(source_id)
        if not lock:
            lock = threading.Lock()
            source_locks[source_id] = lock
        
        with lock:
            # Load existing metadata
            metadata_file = os.path.join('data', f'{source_id}.json')
            metadata = []
            
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                except json.JSONDecodeError:
                    # If file is corrupted, start with empty metadata
                    metadata = []
            
            # Add new log entry
            target_dir = global_sources[source_id].get('target_directory', os.path.join('logs', source_id))
            metadata.append({
                'timestamp': timestamp.isoformat(),
                'filename': log_filename,
                'path': os.path.join(target_dir, log_filename)
            })
            
            # Save metadata (append mode to handle large volumes)
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=4)

def start_syslog_server(sources):
    """
    Start the syslog server to receive messages.
    
    Args:
        sources (dict): The source configurations
    """
    global global_sources
    global_sources = sources
    
    host = Config.SYSLOG_HOST
    port = Config.SYSLOG_PORT
    
    try:
        server = socketserver.ThreadingUDPServer((host, port), SyslogUDPHandler)
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
        metadata_file = os.path.join('data', f'{source_id}.json')
        log_count = 0
        last_log_time = None
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                log_count = len(metadata)
                
                if metadata:
                    # Sort by timestamp to find the most recent log
                    sorted_metadata = sorted(metadata, key=lambda x: x.get('timestamp', ''), reverse=True)
                    last_log_time = sorted_metadata[0].get('timestamp')
            except Exception as e:
                logger.error(f"Error reading metadata for source {source_id}: {str(e)}")
        
        # Create stats
        stats[source_id] = source_config.copy()
        stats[source_id]['log_count'] = log_count
        stats[source_id]['last_log_time'] = last_log_time
    
    return stats

def parse_logs_for_timerange(source_id, start_time, end_time):
    """
    Parse logs for a specific source and time range.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        
    Returns:
        list: The parsed log data
    """
    # Parse time range
    try:
        start_dt = parser.parse(start_time)
        end_dt = parser.parse(end_time)
    except Exception as e:
        logger.error(f"Error parsing time range: {str(e)}")
        raise ValueError(f"Invalid time format: {str(e)}")
    
    # Get metadata for this source
    metadata_file = os.path.join('data', f'{source_id}.json')
    if not os.path.exists(metadata_file):
        return []
    
    try:
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
    except Exception as e:
        logger.error(f"Error reading metadata: {str(e)}")
        raise ValueError(f"Error reading source data: {str(e)}")
    
    # Filter logs by time range
    logs_in_range = []
    for log_entry in metadata:
        log_time = parser.parse(log_entry.get('timestamp', ''))
        if start_dt <= log_time <= end_dt:
            logs_in_range.append(log_entry)
    
    # Read and parse log content for the filtered logs
    parsed_logs = []
    for log_entry in logs_in_range:
        log_path = log_entry.get('path')
        if not log_path or not os.path.exists(log_path):
            continue
        
        try:
            with open(log_path, 'r') as f:
                log_content = f.read()
            
            # Parse log content
            timestamp_match = re.search(r'Timestamp: (.*)', log_content)
            source_ip_match = re.search(r'Source IP: (.*)', log_content)
            message_match = re.search(r'Message: (.*)', log_content)
            
            parsed_logs.append({
                'timestamp': timestamp_match.group(1) if timestamp_match else '',
                'source_ip': source_ip_match.group(1) if source_ip_match else '',
                'message': message_match.group(1) if message_match else '',
                'filename': os.path.basename(log_path)
            })
        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {str(e)}")
    
    return parsed_logs