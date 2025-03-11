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
import requests
from datetime import datetime, timedelta
import pandas as pd
from dateutil import parser
import re
from queue import Queue, Empty  # Fixed import for `Empty`
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
    """Manages queues and workers for processing syslog messages at high volume."""

    def __init__(self, max_size=100000, batch_size=100, batch_timeout=5.0):
        """
        Initialize the queue manager.

        Args:
            max_size (int): Maximum queue size
            batch_size (int): Number of logs to process in a batch
            batch_timeout (float): Maximum time to wait before processing a batch
        """
        self.queue = Queue(maxsize=max_size)
        self.workers = []
        self.running = False
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.active_workers = 0
        self.max_workers = 10
        self.min_workers = 2

        # Performance metrics
        self.metrics = {
            'queue_size': 0,
            'messages_processed': 0,
            'current_eps': 0,
            'eps_history': [],
        }
        self.metrics_lock = threading.Lock()
        self.worker_lock = threading.Lock()  # Shared lock for thread safety
        self.last_count_time = time.time()
        self.message_count_interval = 0

    def start(self, num_workers=4):
        """Start processing workers"""
        self.running = True
        self.active_workers = num_workers
        self.max_workers = max(num_workers * 2, 10)  # Set max workers to at least double initial or 10
        for _ in range(num_workers):
            worker = Thread(target=self._process_queue, daemon=True)
            worker.start()
            self.workers.append(worker)
            logger.info(f"Started log processing worker")

        # Start auto-scaler thread
        scaler_thread = Thread(target=self._auto_scale_workers, daemon=True)
        scaler_thread.start()

    def stop(self):
        """Stop all workers"""
        self.running = False
        for _ in range(len(self.workers)):
            self.queue.put(None)

    def add_task(self, task, block=False):
        """Add a task to the queue"""
        try:
            self.queue.put(task, block=block)

            # Update metrics
            with self.metrics_lock:
                self.message_count_interval += 1
                self.metrics['queue_size'] = self.queue.qsize()

            return True
        except:
            logger.warning("Log queue full, dropping message")
            return False

    def get_metrics(self):
        """Get current metrics"""
        with self.metrics_lock:
            return self.metrics.copy()

    def _process_queue(self):
        """Process logs from the queue in batches"""
        folder_batches = {}  # {(target_dir, hour_bucket): [log entries]}
        hec_batches = {}     # {source_id: [log entries]}

        last_process_time = time.time()

        while self.running:
            try:
                queue_size = self.queue.qsize()
                timeout = 0.1 if queue_size > 5000 else 0.5

                try:
                    log_task = self.queue.get(timeout=timeout)
                except Empty:  # Fixed incorrect reference to `queue.Empty`
                    # Process any pending batches if timeout reached
                    current_time = time.time()
                    if current_time - last_process_time >= self.batch_timeout and (folder_batches or hec_batches):
                        self._process_batches(folder_batches, hec_batches)
                        folder_batches.clear()
                        hec_batches.clear()
                        last_process_time = current_time
                    continue

                # Extract log details
                client_ip = log_task['client_ip']
                message = log_task['message']
                timestamp = log_task['timestamp']

                # Mark task as done immediately
                self.queue.task_done()
                from queue_manager import QueueManager  # Ensure correct import

                # Load global sources (modify this if sources are loaded differently)
                global_sources = {}  # This should be populated from a valid config or DB

                # Initialize QueueManager with correct arguments
                queue_manager = QueueManager(sources=global_sources, max_workers=3, min_workers=1, queue_size=100000)
                # Find matching source
                source_id = self._find_matching_source(client_ip)
                if not source_id:
                    logger.warning(f"Received syslog from undefined source IP: {client_ip}")
                    source_id = "unknown"

                # Prepare log entry
                log_entry = {
                    "timestamp": timestamp.isoformat(),
                    "source_ip": client_ip,
                    "message": message,
                    "id": f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{timestamp.microsecond:06d}",
                    "source_id": source_id
                }

                # Get source configuration
                source_config = global_sources.get(source_id, {})

                # Check if this source uses HEC or folder target
                if source_config.get('target_type') == 'hec':
                    if source_id not in hec_batches:
                        hec_batches[source_id] = []
                    hec_batches[source_id].append((log_entry, timestamp))
                else:
                    target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
                    hour_bucket = timestamp.strftime('%Y%m%d_%H')
                    batch_key = (target_dir, hour_bucket)

                    if batch_key not in folder_batches:
                        folder_batches[batch_key] = []
                    folder_batches[batch_key].append((log_entry, timestamp))

                # Process batches if batch size is reached
                batch_sizes = sum(len(batch) for batch in folder_batches.values()) + sum(len(batch) for batch in hec_batches.values())
                if batch_sizes >= self.batch_size:
                    self._process_batches(folder_batches, hec_batches)
                    folder_batches.clear()
                    hec_batches.clear()
                    last_process_time = time.time()

                # Update metrics
                with self.metrics_lock:
                    self.metrics['messages_processed'] += 1
                    self.metrics['queue_size'] = self.queue.qsize()

            except Exception as e:
                logger.error(f"Error in worker: {str(e)}", exc_info=True)

    def _auto_scale_workers(self):
        """Automatically scale workers based on queue size and system load."""
        while True:
            try:
                queue_size = self.queue.qsize()
                cpu_usage = psutil.cpu_percent()
                memory_usage = psutil.virtual_memory().percent
                cpu_count = psutil.cpu_count() or 2

                optimal_workers = max(self.min_workers, min(cpu_count * 2, self.max_workers))

                with self.worker_lock:  # Ensures thread safety when modifying `self.active_workers`
                    if queue_size > 5000 and self.active_workers < optimal_workers:
                        self.active_workers += 1
                        worker = Thread(target=self._process_queue, daemon=True)
                        worker.start()
                        self.workers.append(worker)
                        logger.info(f"Added worker, now {self.active_workers} active")

                    elif queue_size < 1000 and self.active_workers > self.min_workers:
                        self.active_workers = max(self.min_workers, self.active_workers - 1)
                        logger.info(f"Removed worker, now {self.active_workers} active")

            except Exception as e:
                logger.error(f"Error in auto-scaler: {str(e)}")

            time.sleep(5)  # Adjust worker count every 5 seconds



# Create queue manager
queue_manager = QueueManager()
queue_manager.start(num_workers=4)

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
            # No matching source found, log warning and store in default location
            logger.warning(f"Received syslog from undefined source IP: {client_ip}")
            if queue_manager is not None:
                queue_manager.add_task({
                    'client_ip': client_ip,
                    'message': message,
                    'timestamp': timestamp,
                    'enqueue_time': time.time()
                })
                return
        
        # Add to processing queue
        queue_manager.add_task({
            'client_ip': client_ip,
            'message': message,
            'timestamp': timestamp,
            'enqueue_time': time.time()
        })
    
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
        
        # No matching source found
        return None

def update_background_index(source_id, timestamp, log_id):
    """Update the index file for a source (background worker version)"""
    # Get lock for this source
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
                    try:
                        index = json.load(f)
                    except json.JSONDecodeError:
                        # Handle corrupt index file
                        index = {"buckets": {}, "last_log": None, "total_count": 0}
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
        # Get index for this source instead of static metadata file
        index_file = os.path.join('data', f'{source_id}_index.json')
        log_count = 0
        last_log_time = None
        
        if os.path.exists(index_file):
            try:
                with open(index_file, 'r') as f:
                    index_data = json.load(f)
                
                # Get log count from index
                log_count = index_data.get("total_count", 0)
                total_log_count += log_count
                
                # Get last log timestamp from index
                last_log = index_data.get("last_log", {})
                if last_log:
                    last_log_time = last_log.get("timestamp")
            except Exception as e:
                logger.error(f"Error reading index for source {source_id}: {str(e)}")
        
        # Create stats
        stats[source_id] = source_config.copy()
        stats[source_id]['log_count'] = log_count
        stats[source_id]['last_log_time'] = last_log_time
    
    # Update EPS in monitoring module
    from monitoring import update_eps
    update_eps(total_log_count)
    
    return stats

def start_log_worker(num_workers=4):
    """Start worker threads to handle log writing"""
    # Use more workers for high throughput
    cpu_count = psutil.cpu_count() or 4
    optimal_workers = max(num_workers, int(cpu_count * 0.75))
    
    # Initialize with higher worker count for high EPS
    queue_manager.start(optimal_workers)
    logger.info(f"Started {optimal_workers} log processing workers")

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
    # Use 75% of available cores for workers, minimum 3
    cpu_count = psutil.cpu_count() or 4
    num_workers = max(3, int(cpu_count * 0.75))
    
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
        
        # Update queue manager metrics
        queue_metrics = queue_manager.get_metrics()
        
        # Log queue stats
        logger.info(f"Queue size: {queue_metrics.get('queue_size', 0)} - Messages processed: {queue_metrics.get('messages_processed', 0)} - Current EPS: {queue_metrics.get('current_eps', 0):.1f}")
        
        time.sleep(30)  # Report every 30 seconds

def parse_logs_for_timerange(source_id, start_time, end_time, max_results=1000):
    """
    Parse logs for a specific source and time range using the new storage format.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        max_results (int): Maximum number of results to return (0 for unlimited)
        
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
    
    # Check if target directory exists
    if not os.path.exists(target_dir):
        logger.warning(f"Target directory {target_dir} for source {source_id} does not exist")
        return []
    
    # Get index for this source
    index_file = os.path.join('data', f'{source_id}_index.json')
    if not os.path.exists(index_file):
        logger.warning(f"Index file for source {source_id} does not exist")
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
                                'filename': os.path.basename(log_path)
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
    
    # Limit results based on max_results (if not already limited during processing)
    if max_results > 0 and len(parsed_logs) > max_results:
        return parsed_logs[:max_results]
    
    return parsed_logs