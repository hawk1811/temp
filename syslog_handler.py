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
import uuid
from datetime import datetime, timedelta
import pandas as pd
from dateutil import parser
import re
from queue import Queue
from threading import Thread
import psutil

from config import Config
from utils import check_memory_usage, is_ip_in_network

# Configure logging
logger = logging.getLogger(__name__)

# Global source configuration
global_sources = {}
source_locks = {}  # For thread-safe access to source metadata

# Global log queue
log_queue = Queue(maxsize=100000)  # Set a reasonable limit

# Global variable to track the server instance
syslog_server = None

class QueueManager:
    """Manager for handling log processing queue"""
    
    def __init__(self, max_size=100000):
        self.queue = Queue(maxsize=max_size)
        self.workers = []
        self.running = False
    
    def start(self, num_workers=4):
        """Start processing workers"""
        self.running = True
        for _ in range(num_workers):
            worker = Thread(target=self._process_queue, daemon=True)
            worker.start()
            self.workers.append(worker)
            logger.info(f"Started log processing worker")
    
    def stop(self):
        """Stop all workers"""
        self.running = False
        # Send termination signals
        for _ in range(len(self.workers)):
            self.queue.put(None)
    
    def add_task(self, task, block=False):
        """Add a task to the queue"""
        try:
            self.queue.put(task, block=block)
            return True
        except:  # Queue.Full or other exceptions
            logger.warning("Log queue full, dropping message")
            return False
    
    def _process_queue(self):
        """Process logs from the queue in background"""
        while self.running:
            try:
                log_task = self.queue.get()
                if log_task is None:  # Poison pill
                    break
                    
                # Unpack the log task
                # The last element is the target type (folder or hec)
                if len(log_task) == 5:
                    target_dir, log_entry, source_id, timestamp, target_type = log_task
                else:
                    # Backward compatibility with old format
                    target_dir, log_entry, source_id, timestamp = log_task
                    target_type = 'folder'
                
                if target_type == 'hec':
                    # Send to HEC endpoint
                    self._send_to_hec(source_id, log_entry, timestamp)
                else:
                    # Write to folder
                    # Make sure target directory exists
                    os.makedirs(target_dir, exist_ok=True)
                    
                    # Write to hourly log file
                    hour_bucket = timestamp.strftime('%Y%m%d_%H')
                    filename = f"{hour_bucket}.log"
                    filepath = os.path.join(target_dir, filename)
                    
                    with open(filepath, 'a') as f:
                        f.write(json.dumps(log_entry) + '\n')
                
                # Update index for both types
                update_background_index(source_id, timestamp, log_entry["id"])
                
            except Exception as e:
                logger.error(f"Error in log worker: {str(e)}")
            finally:
                if not self.queue.empty():
                    self.queue.task_done()

    def _send_to_hec(self, source_id, log_entry, timestamp):
        """
        Send a log entry to a HEC endpoint.
        
        Args:
            source_id (str): Source ID
            log_entry (dict): Log data
            timestamp (datetime): Log timestamp
        """
        try:
            # Get source configuration
            source_config = global_sources.get(source_id, {})
            
            # Get HEC URL and token
            hec_url = source_config.get('hec_url')
            hec_token = source_config.get('hec_token')
            
            if not hec_url or not hec_token:
                logger.error(f"Missing HEC URL or token for source {source_id}")
                return
            
            # Prepare HEC payload
            payload = {
                "time": int(timestamp.timestamp()),
                "host": log_entry.get('source_ip', 'unknown'),
                "source": f"syslog:{source_id}",
                "sourcetype": "syslog",
                "index": "main",  # Default index
                "event": log_entry
            }
            
            # Set headers
            headers = {
                "Authorization": f"Splunk {hec_token}",
                "Content-Type": "application/json"
            }
            
            # Send to HEC endpoint with timeout
            response = requests.post(
                hec_url,
                json=payload,
                headers=headers,
                timeout=5.0  # 5 second timeout
            )
            
            # Check response
            if response.status_code != 200:
                logger.warning(f"HEC endpoint returned non-200 status: {response.status_code}, message: {response.text}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending to HEC endpoint for source {source_id}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error sending to HEC for source {source_id}: {str(e)}")

# Create queue manager
queue_manager = QueueManager()

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
    Process a syslog message using the improved storage system.
    """
    # Skip if memory usage is too high
    if check_memory_usage() > Config.MAX_MEMORY_USAGE:
        logger.warning("Memory usage too high, dropping syslog message")
        return
    
    # Parse timestamp from syslog message
    timestamp = self.extract_timestamp(message)
    if not timestamp:
        timestamp = datetime.now()
    
    # Find matching source
    source_id = self.find_matching_source(client_ip)
    if not source_id:
        # No matching source found, store in default location
        target_dir = os.path.join('logs', 'unknown')
        log_entry = {
            "timestamp": timestamp.isoformat(),
            "source_ip": client_ip,
            "message": message,
            "id": f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{timestamp.microsecond:06d}"
        }
        # Queue the log for background processing
        queue_manager.add_task((target_dir, log_entry, "unknown", timestamp))
        return
    
    # Get source configuration
    source_config = global_sources.get(source_id, {})
    
    # Prepare log entry
    log_entry = {
        "timestamp": timestamp.isoformat(),
        "source_ip": client_ip,
        "message": message,
        "id": f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{timestamp.microsecond:06d}"
    }
    
    # Check if this source uses HEC or folder target
    if source_config.get('target_type') == 'hec':
        # Send to HEC endpoint
        queue_manager.add_task((None, log_entry, source_id, timestamp, 'hec'))
    else:
        # Default to folder target
        target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
        queue_manager.add_task((target_dir, log_entry, source_id, timestamp, 'folder'))
    
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

def start_log_worker(num_workers=2):
    """Start worker threads to handle log writing"""
    queue_manager.start(num_workers)

def process_log_queue():
    """Process logs from the queue in background (legacy function)"""
    while True:
        try:
            log_task = log_queue.get()
            if log_task is None:  # Poison pill
                break
                
            # Unpack the log task
            target_dir, log_entry, source_id, timestamp = log_task
            
            # Make sure target directory exists
            os.makedirs(target_dir, exist_ok=True)
            
            # Write to hourly log file
            hour_bucket = timestamp.strftime('%Y%m%d_%H')
            filename = f"{hour_bucket}.log"
            filepath = os.path.join(target_dir, filename)
            
            with open(filepath, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Update index
            update_background_index(source_id, timestamp, log_entry["id"])
            
        except Exception as e:
            logger.error(f"Error in log worker: {str(e)}")
        finally:
            log_queue.task_done()

def update_background_index(source_id, timestamp, log_id):
    """Update the index file for a source (background worker version)"""
    # Acquire lock for this source
    lock = source_locks.get(source_id)
    if not lock:
        lock = threading.Lock()
        source_locks[source_id] = lock
    
    with lock:
        # Get the index file path
        index_file = os.path.join('data', f'{source_id}_index.json')
        
        # Update index information
        hour_bucket = timestamp.strftime('%Y%m%d_%H')
        
        try:
            # Load existing index if it exists
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    index = json.load(f)
            else:
                index = {"buckets": {}, "last_log": None, "total_count": 0}
            
            # Update bucket information
            if hour_bucket not in index["buckets"]:
                index["buckets"][hour_bucket] = 1
            else:
                index["buckets"][hour_bucket] += 1
            
            # Update last log info
            index["last_log"] = {
                "timestamp": timestamp.isoformat(),
                "id": log_id
            }
            
            # Update total count
            index["total_count"] += 1
            
            # Write index back to file
            with open(index_file, 'w') as f:
                json.dump(index, f)
                
        except Exception as e:
            logger.error(f"Error updating index for source {source_id}: {str(e)}")

def get_system_metrics():
    """
    Get system metrics for monitoring.
    
    Returns:
        dict: System metrics including CPU, memory, queue stats, and worker utilization
    """
    try:
        # Get CPU usage
        cpu_percent = psutil.cpu_percent()
        
        # Get memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Get worker utilization (from the current syslog server instance)
        worker_stats = {
            "active_workers": getattr(syslog_server, "active_workers", 0),
            "max_workers": getattr(syslog_server, "max_workers", 1),
            "utilization": (getattr(syslog_server, "active_workers", 0) / 
                           getattr(syslog_server, "max_workers", 1) * 100) 
                           if getattr(syslog_server, "max_workers", 1) > 0 else 0
        }
        
        # Get queue stats
        queue_stats = {
            "size": queue_manager.queue.qsize(),
            "is_full": queue_manager.queue.full()
        }
        
        # Get logs rate
        logs_rate = 0
        if hasattr(syslog_server, "get_logs_per_second"):
            logs_rate = syslog_server.get_logs_per_second()
        
        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "worker_stats": worker_stats,
            "queue_stats": queue_stats,
            "logs_rate": logs_rate
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {str(e)}")
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "worker_stats": {"active_workers": 0, "max_workers": 1, "utilization": 0},
            "queue_stats": {"size": 0, "is_full": False},
            "logs_rate": 0
        }

def start_syslog_server(sources):
    """
    Start the syslog server with dynamic worker scaling.
    """
    global global_sources, syslog_server
    global_sources = sources
    
    host = Config.SYSLOG_HOST
    port = Config.SYSLOG_PORT
    
    # Calculate optimal number of workers based on CPU cores
    # Use 75% of available cores for workers
    num_workers = max(1, int(os.cpu_count() * 0.75))
    
    try:
        class ScalableUDPServer(socketserver.ThreadingUDPServer):
            """Custom UDP server with worker scaling capabilities"""
            # Set larger request queue size
            request_queue_size = 50000
            
            def __init__(self, *args, **kwargs):
                self.active_workers = 0
                self.max_workers = num_workers
                self.worker_semaphore = threading.Semaphore(self.max_workers)
                self.processed_count = 0
                self.last_report_time = time.time()
                self.last_processed_count = 0
                super().__init__(*args, **kwargs)
            
            def process_request(self, request, client_address):
                """Override to track active workers"""
                self.active_workers += 1
                self.processed_count += 1
                super().process_request(request, client_address)
                self.active_workers -= 1
                
            def get_logs_per_second(self):
                """Calculate current logs per second"""
                now = time.time()
                elapsed = now - self.last_report_time
                if elapsed < 1:
                    return 0
                    
                rate = (self.processed_count - self.last_processed_count) / elapsed
                
                # Update counters
                self.last_report_time = now
                self.last_processed_count = self.processed_count
                
                return rate
        
        # Allow socket reuse to prevent "address already in use" errors
        ScalableUDPServer.allow_reuse_address = True
        
        server = ScalableUDPServer((host, port), SyslogUDPHandler)
        syslog_server = server  # Store in global for stats access
        
        # Start stats reporting thread
        stats_thread = threading.Thread(
            target=report_server_stats,
            args=(server,),
            daemon=True
        )
        stats_thread.start()
        
        logger.info(f"Starting syslog server on {host}:{port} with {num_workers} workers")
        server.serve_forever()
        
    except Exception as e:
        logger.error(f"Error starting syslog server: {str(e)}", exc_info=True)

def report_server_stats(server):
    """Report server statistics periodically"""
    while True:
        active = server.active_workers
        max_workers = server.max_workers
        rate = server.get_logs_per_second()
        
        logger.info(f"Worker utilization: {active}/{max_workers} ({(active/max_workers*100 if max_workers > 0 else 0):.1f}%) - Processing {rate:.1f} logs/sec")
        time.sleep(30)  # Report every 30 seconds

def get_source_stats(sources):
    """
    Get statistics for each source.
    
    Args:
        sources (dict): The source configurations
        
    Returns:
        dict: The source statistics
    """
    stats = {}
    total_log_count = 0
    
    for source_id, source_config in sources.items():
        metadata_file = os.path.join('data', f'{source_id}.json')
        log_count = 0
        last_log_time = None
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                log_count = len(metadata)
                total_log_count += log_count
                
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
    
    # Update EPS in monitoring module
    from monitoring import update_eps
    update_eps(total_log_count)
    
    return stats

def parse_logs_for_timerange(source_id, start_time, end_time, max_results=1000):
    """
    Parse logs for a specific source and time range using the new storage format.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        max_results (int): Maximum number of results to return
        
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
    
    # Get source config
    source_config = global_sources.get(source_id, {})
    target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
    
    # Get index for this source
    index_file = os.path.join('data', f'{source_id}_index.json')
    if not os.path.exists(index_file):
        return []
    
    try:
        with open(index_file, 'r') as f:
            index = json.load(f)
    except Exception as e:
        logger.error(f"Error reading index: {str(e)}")
        raise ValueError(f"Error reading source data: {str(e)}")
    
    # Determine which bucket files to check based on timerange
    current_hour = start_dt.replace(minute=0, second=0, microsecond=0)
    relevant_buckets = []
    
    while current_hour <= end_dt:
        bucket_name = current_hour.strftime('%Y%m%d_%H')
        if bucket_name in index.get("buckets", {}):
            relevant_buckets.append(bucket_name)
        
        # Move to next hour
        current_hour = current_hour + timedelta(hours=1)
    
    # Read and parse log content for the filtered logs
    parsed_logs = []
    
    for bucket in relevant_buckets:
        log_path = os.path.join(target_dir, f"{bucket}.log")
        if not os.path.exists(log_path):
            continue
        
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        log_time = parser.parse(log_entry.get('timestamp', ''))
                        
                        # Check if log is within the requested timerange
                        if start_dt <= log_time <= end_dt:
                            parsed_logs.append({
                                'timestamp': log_entry.get('timestamp', ''),
                                'source_ip': log_entry.get('source_ip', ''),
                                'message': log_entry.get('message', ''),
                                'filename': log_entry.get('id', '')
                            })
                            
                            # If we've reached the maximum results, stop processing
                            if max_results > 0 and len(parsed_logs) >= max_results:
                                break
                    except Exception as e:
                        logger.error(f"Error parsing log entry in {log_path}: {str(e)}")
                        
            # If we've reached the maximum results, stop processing
            if max_results > 0 and len(parsed_logs) >= max_results:
                break
        except Exception as e:
            logger.error(f"Error reading log file {log_path}: {str(e)}")
    
    # Sort by timestamp (newest first)
    parsed_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Limit results based on max_results
    if max_results > 0 and len(parsed_logs) > max_results:
        return parsed_logs[:max_results]
    
    return parsed_logs