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
from queue import Queue, Empty, Full  

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

class SourceQueueManager:
    """Manages per-source queues with dedicated processing threads."""
    
    def __init__(self):
        """Initialize the source queue manager."""
        self.source_queues = {}  # {source_id: Queue}
        self.source_threads = {}  # {source_id: (queue_thread, process_thread)}
        self.running = True
        self.metrics = {
            'queue_sizes': {},
            'messages_processed': {},
            'current_eps': 0,
            'total_processed': 0
        }
        self.metrics_lock = threading.Lock()
        self.last_count_time = time.time()
        self.message_count_interval = 0
    
    def start(self, sources):
        """Start queue and processing threads for each source."""
        self.running = True
        for source_id, source_config in sources.items():
            self.add_source(source_id, source_config)
    
    def add_source(self, source_id, source_config):
        """Add a new source with its own queue and processing threads."""
        if source_id in self.source_queues:
            return  # Source already exists
        
        # Create queue for this source
        self.source_queues[source_id] = Queue(maxsize=100000)
        
        # Initialize metrics for this source
        with self.metrics_lock:
            self.metrics['queue_sizes'][source_id] = 0
            self.metrics['messages_processed'][source_id] = 0
        
        # Create and start queue thread
        queue_thread = threading.Thread(
            target=self._queue_worker,
            args=(source_id,),
            daemon=True,
            name=f"Queue-{source_id}"
        )
        
        # Create and start processing thread
        process_thread = threading.Thread(
            target=self._process_worker,
            args=(source_id, source_config),
            daemon=True,
            name=f"Process-{source_id}"
        )
        
        # Start threads
        queue_thread.start()
        process_thread.start()
        
        # Store thread references
        self.source_threads[source_id] = (queue_thread, process_thread)
        
        logger.info(f"Started queue and processing threads for source {source_id}")
    
    def remove_source(self, source_id):
        """Remove a source and stop its threads."""
        if source_id not in self.source_queues:
            return  # Source doesn't exist
        
        # Clean up metrics
        with self.metrics_lock:
            if source_id in self.metrics['queue_sizes']:
                del self.metrics['queue_sizes'][source_id]
            if source_id in self.metrics['messages_processed']:
                del self.metrics['messages_processed'][source_id]
        
        # Remove queue
        del self.source_queues[source_id]
        
        # Remove thread references
        if source_id in self.source_threads:
            del self.source_threads[source_id]
        
        logger.info(f"Removed source {source_id}")
    
    def update_source(self, source_id, source_config):
        """Update a source's configuration."""
        self.remove_source(source_id)
        self.add_source(source_id, source_config)
    
    def stop(self):
        """Stop all threads and clear queues."""
        self.running = False
        
        # Clear all queues
        for source_id, queue in self.source_queues.items():
            while not queue.empty():
                try:
                    queue.get_nowait()
                    queue.task_done()
                except Empty:
                    break
        
        # Wait for threads to exit
        time.sleep(1)
        
        self.source_queues.clear()
        self.source_threads.clear()
        
        logger.info("Stopped source queue manager")
    
    def enqueue_message(self, client_ip, message, timestamp=None):
        """Add a message to the appropriate source queue."""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Find matching source
        source_id = self._find_matching_source(client_ip)
        if not source_id:
            # No matching source, use "unknown"
            source_id = "unknown"
            
        # Check if queue exists for this source
        if source_id not in self.source_queues:
            source_config = global_sources.get(source_id, {})
            self.add_source(source_id, source_config)
        
        # Try to parse message as JSON
        event_data = message
        try:
            json_data = json.loads(message)
            if isinstance(json_data, dict):
                event_data = json_data
        except (json.JSONDecodeError, TypeError):
            # Not valid JSON, use message as string
            pass
        
        # Create log entry
        log_entry = {
            'time': time.time(),
            'event': event_data,
            'source': source_id,
            'client_ip': client_ip,
            'timestamp': timestamp
        }
        
        # Add to source queue
        try:
            queue = self.source_queues.get(source_id)
            if queue:
                queue.put(log_entry, block=False)
                
                # Update metrics
                with self.metrics_lock:
                    self.message_count_interval += 1
                    self.metrics['queue_sizes'][source_id] = queue.qsize()
                
                return True
            else:
                logger.error(f"Queue for source {source_id} not found")
                return False
        except Full:
            logger.warning(f"Queue for source {source_id} is full, dropping message")
            return False
    
    def get_metrics(self):
        """Get current performance metrics."""
        with self.metrics_lock:
            # Calculate current EPS
            current_time = time.time()
            elapsed = current_time - self.last_count_time
            
            if elapsed >= 1.0:
                current_eps = int(self.message_count_interval / elapsed)
                self.metrics['current_eps'] = current_eps
                self.message_count_interval = 0
                self.last_count_time = current_time
            
            return self.metrics.copy()
    
    def _queue_worker(self, source_id):
        """Thread that manages the queue for a specific source."""
        logger.info(f"Started queue worker for source {source_id}")
        
        while self.running:
            try:
                time.sleep(0.01)  # Small sleep to prevent tight loop
            except Exception as e:
                logger.error(f"Error in queue worker for source {source_id}: {str(e)}")
    
    def _process_worker(self, source_id, source_config):
        """Thread that processes batches of logs for a specific source."""
        logger.info(f"Started process worker for source {source_id}")
        
        queue = self.source_queues.get(source_id)
        if not queue:
            logger.error(f"Queue for source {source_id} not found in process worker")
            return
        
        # Determine target type and batch size
        target_type = source_config.get('target_type', 'folder')
        batch_size = 5000 if target_type == 'folder' else 500
        
        # Initialize batch
        current_batch = []
        last_process_time = time.time()
        
        while self.running:
            try:
                # Try to get a message from the queue
                try:
                    log_entry = queue.get(timeout=0.5)
                    queue.task_done()
                    
                    # Add to current batch
                    current_batch.append(log_entry)
                    
                    # Update metrics
                    with self.metrics_lock:
                        if source_id in self.metrics['messages_processed']:
                            self.metrics['messages_processed'][source_id] += 1
                        else:
                            self.metrics['messages_processed'][source_id] = 1
                        
                        self.metrics['total_processed'] += 1
                        
                        if source_id in self.metrics['queue_sizes']:
                            self.metrics['queue_sizes'][source_id] = queue.qsize()
                        else:
                            self.metrics['queue_sizes'][source_id] = 0
                except Empty:
                    # No message available, check if we should process the current batch
                    if not current_batch:
                        continue
                    
                    current_time = time.time()
                    # Process batch if it's full or if timeout reached (30 seconds)
                    if len(current_batch) >= batch_size or (current_time - last_process_time >= 30):
                        self._process_batch(source_id, source_config, current_batch)
                        current_batch = []
                        last_process_time = current_time
                    
                    continue
                
                # Process batch if it's full
                if len(current_batch) >= batch_size:
                    self._process_batch(source_id, source_config, current_batch)
                    current_batch = []
                    last_process_time = time.time()
            
            except Exception as e:
                logger.error(f"Error in process worker for source {source_id}: {str(e)}", exc_info=True)
                time.sleep(1)  # Sleep on error to prevent tight loop
    
    def _process_batch(self, source_id, source_config, batch):
        """Process a batch of logs for a specific source."""
        if not batch:
            return
        
        target_type = source_config.get('target_type', 'folder')
        
        try:
            if target_type == 'folder':
                self._process_folder_batch(source_id, source_config, batch)
            else:  # HEC
                self._process_hec_batch(source_id, source_config, batch)
        except Exception as e:
            logger.error(f"Error processing batch for source {source_id}: {str(e)}", exc_info=True)
    
    def _process_folder_batch(self, source_id, source_config, batch):
        """Process a batch of logs for a folder target."""
        if not batch:
            return
        
        # Get target directory
        target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
        
        # Ensure target directory exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Sort batch by timestamp
        batch.sort(key=lambda x: x.get('timestamp', datetime.now()))
        
        # Get filename based on first event timestamp
        first_event = batch[0]
        first_timestamp = first_event.get('timestamp', datetime.now())
        filename = first_timestamp.strftime('%Y%m%d_%H%M%S') + '.json'
        filepath = os.path.join(target_dir, filename)
        
        # Write batch to file
        try:
            with open(filepath, 'w') as f:
                json.dump(batch, f)
            
            logger.debug(f"Wrote batch of {len(batch)} logs to {filepath}")
        except Exception as e:
            logger.error(f"Error writing batch to {filepath}: {str(e)}", exc_info=True)
    
    def _process_hec_batch(self, source_id, source_config, batch):
        """Process a batch of logs for a HEC target."""
        if not batch:
            return
        
        # Get HEC configuration
        hec_url = source_config.get('hec_url')
        hec_token = source_config.get('hec_token')
        
        if not hec_url or not hec_token:
            logger.error(f"Missing HEC URL or token for source {source_id}")
            return
        
        # Prepare data in required format
        data_lines = []
        for log_entry in batch:
            entry_data = {
                'time': log_entry.get('time'),
                'event': log_entry.get('event'),
                'source': log_entry.get('source')
            }
            data_lines.append(json.dumps(entry_data))
        
        # Join with newlines for NDJSON format
        data = '\n'.join(data_lines)
        
        # Send to HEC
        try:
            headers = {
                'Authorization': f'Bearer {hec_token}',
                'Content-Type': 'text/plain; charset=utf-8'
            }
            
            response = requests.post(
                hec_url,
                data=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code >= 400:
                logger.error(f"HEC error for source {source_id}: {response.status_code} - {response.text}")
            else:
                logger.debug(f"Sent batch of {len(batch)} logs to HEC for source {source_id}")
        
        except Exception as e:
            logger.error(f"Error sending batch to HEC for source {source_id}: {str(e)}", exc_info=True)
    
    def _find_matching_source(self, client_ip):
        """Find the source ID that matches a client IP."""
        global global_sources
        
        for source_id, source_config in global_sources.items():
            source_ips = source_config.get('source_ips', [])
            for ip_entry in source_ips:
                if is_ip_in_network(client_ip, ip_entry):
                    return source_id
        
        return None


# Create queue manager
queue_manager = SourceQueueManager()

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
        Process a syslog message using the source queue manager.
        """
        # Skip if memory usage is too high
        if check_memory_usage() > Config.MAX_MEMORY_USAGE:
            logger.warning("Memory usage too high, dropping syslog message")
            return
        
        # Parse timestamp from syslog message
        timestamp = self.extract_timestamp(message)
        if not timestamp:
            timestamp = datetime.now()
        
        # Add to processing queue
        queue_manager.enqueue_message(client_ip, message, timestamp)
        
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
        # Get index for this source
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
    try:
        from monitoring import update_eps
        update_eps(total_log_count)
    except Exception as e:
        logger.warning(f"Could not update EPS monitoring: {str(e)}")
    
    return stats

def start_log_worker(num_workers=4):
    """Start worker threads to handle log writing"""
    # Use more workers for high throughput
    cpu_count = psutil.cpu_count() or 4
    optimal_workers = max(num_workers, int(cpu_count * 0.75))
    
    # Initialize the queue manager
    global global_sources
    queue_manager.start(global_sources)
    
    logger.info(f"Started log processing with {optimal_workers} workers")

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
        
        # Get worker utilization from the queue manager
        metrics = queue_manager.get_metrics()
        
        # Get total queue size
        total_queue_size = 0
        is_full = False
        if hasattr(queue_manager, 'source_queues'):
            for source_id, queue in queue_manager.source_queues.items():
                queue_size = queue.qsize() if queue else 0
                total_queue_size += queue_size
                if queue and queue.full():
                    is_full = True
        
        # Queue stats
        queue_stats = {
            "size": total_queue_size,
            "is_full": is_full
        }
        
        # Get current EPS
        current_eps = metrics.get('current_eps', 0)
        
        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "worker_stats": {
                "active_workers": len(queue_manager.source_threads) * 2,  # Each source has 2 threads
                "max_workers": 20,  # Some reasonable maximum
                "utilization": 50  # Default value, hard to calculate precisely
            },
            "queue_stats": queue_stats,
            "logs_rate": current_eps
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
    Start the syslog server with dynamic worker scaling and multiple listeners.
    """
    global global_sources, syslog_server
    global_sources = sources
    
    # Dictionary to track running servers by (protocol, port)
    servers = {}
    active_ports = set()
    
    # Create UDP and TCP server classes with worker scaling
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
    
    class ScalableTCPServer(socketserver.ThreadingTCPServer):
        """Custom TCP server with worker scaling capabilities"""
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
    
    class SyslogTCPHandler(socketserver.BaseRequestHandler):
        """
        TCP handler for syslog messages.
        """
        
        def handle(self):
            """Handle incoming TCP syslog message."""
            try:
                # For TCP connections, we need to handle multiple messages over the same connection
                data = b''
                socket = self.request
                client_address = self.client_address[0]
                
                # Set a timeout for receiving data
                socket.settimeout(5.0)
                
                while True:
                    try:
                        chunk = socket.recv(4096)
                        if not chunk:
                            break
                        
                        data += chunk
                        
                        # Process complete messages (split by newlines)
                        if b'\n' in data:
                            messages = data.split(b'\n')
                            # Last item might be incomplete
                            data = messages.pop()
                            
                            # Process complete messages
                            for msg in messages:
                                if msg:  # Skip empty lines
                                    try:
                                        message = bytes.decode(msg.strip(), 'utf-8')
                                        # Create a dummy handler and call its process_syslog method
                                        dummy_handler = SyslogUDPHandler(None, None, None)
                                        dummy_handler.process_syslog(client_address, message)
                                    except Exception as e:
                                        logger.error(f"Error processing TCP message: {str(e)}")
                    except socket.timeout:
                        # Process any remaining data on timeout
                        if data:
                            try:
                                message = bytes.decode(data.strip(), 'utf-8')
                                # Create a dummy handler and call its process_syslog method
                                dummy_handler = SyslogUDPHandler(None, None, None)
                                dummy_handler.process_syslog(client_address, message)
                            except Exception as e:
                                logger.error(f"Error processing final TCP message: {str(e)}")
                        break
                    except ConnectionResetError:
                        # Client closed connection
                        break
                    
            except Exception as e:
                logger.error(f"Error handling TCP syslog message: {str(e)}", exc_info=True)
    
    # Allow socket reuse to prevent "address already in use" errors
    ScalableUDPServer.allow_reuse_address = True
    ScalableTCPServer.allow_reuse_address = True
    
    # Calculate optimal number of workers based on CPU cores
    # Use 75% of available cores for workers, minimum 3
    cpu_count = psutil.cpu_count() or 4
    num_workers = max(3, int(cpu_count * 0.75))
    
    # Create default server on standard port
    host = Config.SYSLOG_HOST
    port = Config.SYSLOG_PORT
    
    # Track ports we need to listen on
    needed_ports = set()
    
    # Collect all unique port/protocol combinations
    for source_id, source in sources.items():
        protocol = source.get('protocol', 'udp').lower()
        source_port = source.get('port', 514)
        needed_ports.add((protocol, source_port))
    
    # Add default port if no sources defined
    if not needed_ports:
        needed_ports.add(('udp', port))
    
    # Start stats reporting thread for all servers
    stats_thread = threading.Thread(
        target=report_servers_stats,
        args=(servers,),
        daemon=True
    )
    stats_thread.start()
    
    # Start servers for each port/protocol
    for protocol, port in needed_ports:
        try:
            if protocol == 'tcp':
                queue_manager.start(global_sources)
                server = ScalableTCPServer((host, port), SyslogTCPHandler)
                logger.info(f"Starting TCP syslog server on {host}:{port} with {num_workers} workers")
            else:  # Default to UDP
                queue_manager.start(global_sources)
                server = ScalableUDPServer((host, port), SyslogUDPHandler)
                logger.info(f"Starting UDP syslog server on {host}:{port} with {num_workers} workers")
            
            # Store server reference
            servers[(protocol, port)] = server
            
            # Start server in a separate thread
            server_thread = threading.Thread(
                target=server.serve_forever,
                daemon=True
            )
            server_thread.start()
            
            # Store main server for stats access
            if protocol == 'udp' and port == 514:
                syslog_server = server
                
        except Exception as e:
            logger.error(f"Error starting {protocol.upper()} syslog server on port {port}: {str(e)}", exc_info=True)

    # Start retry thread for HEC submissions
    retry_thread = threading.Thread(
        target=run_retry_scheduler,
        daemon=True
    )
    retry_thread.start()
    logger.info("Started HEC retry scheduler thread")
    
    # Keep the main thread alive
    while True:
        # Check for changes in sources (new ports/protocols)
        current_needed_ports = set()
        for source_id, source in global_sources.items():
            protocol = source.get('protocol', 'udp').lower()
            source_port = source.get('port', 514)
            current_needed_ports.add((protocol, source_port))
        
        # Start new servers if needed
        for protocol, port in current_needed_ports:
            if (protocol, port) not in servers:
                try:
                    if protocol == 'tcp':
                        server = ScalableTCPServer((host, port), SyslogTCPHandler)
                        logger.info(f"Starting new TCP syslog server on {host}:{port} with {num_workers} workers")
                    else:  # Default to UDP
                        server = ScalableUDPServer((host, port), SyslogUDPHandler)
                        logger.info(f"Starting new UDP syslog server on {host}:{port} with {num_workers} workers")
                    
                    # Store server reference
                    servers[(protocol, port)] = server
                    
                    # Start server in a separate thread
                    server_thread = threading.Thread(
                        target=server.serve_forever,
                        daemon=True
                    )
                    server_thread.start()
                    
                except Exception as e:
                    logger.error(f"Error starting new {protocol.upper()} syslog server on port {port}: {str(e)}", exc_info=True)
        
        # Sleep before checking again
        time.sleep(60)

def report_servers_stats(servers):
    """Report server statistics periodically for all server instances"""
    while True:
        total_active = 0
        total_max = 0
        total_rate = 0
        
        for (protocol, port), server in servers.items():
            active = server.active_workers
            max_workers = server.max_workers
            rate = server.get_logs_per_second()
            
            total_active += active
            total_max += max_workers
            total_rate += rate
            
            logger.debug(f"{protocol.upper()}:{port} - Worker utilization: {active}/{max_workers} ({(active/max_workers*100 if max_workers > 0 else 0):.1f}%) - Processing {rate:.1f} logs/sec")
        
        # Log overall stats
        logger.info(f"Total worker utilization: {total_active}/{total_max} ({(total_active/total_max*100 if total_max > 0 else 0):.1f}%) - Processing {total_rate:.1f} logs/sec")
        
        # Update queue manager metrics
        queue_metrics = queue_manager.get_metrics()
        
        # Log queue stats
        logger.info(f"Queue size: {queue_metrics.get('queue_size', 0)} - Messages processed: {queue_metrics.get('messages_processed', 0)} - Current EPS: {queue_metrics.get('current_eps', 0):.1f}")
        
        time.sleep(30)  # Report every 30 seconds

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
    Parse logs for a specific source and time range using JSON batch files.
    
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
    
    # Find all JSON files in the target directory
    log_files = []
    for filename in os.listdir(target_dir):
        if filename.endswith('.json'):
            try:
                # Parse timestamp from filename (format: YYYYMMDD_HHMMSS.json)
                file_time_str = filename.split('.')[0]
                file_time = datetime.strptime(file_time_str, '%Y%m%d_%H%M%S')
                
                # Check if file might contain logs in the requested timerange
                # Files are named after their first event, so we need to check all files
                # that were created before the end time
                if file_time <= end_dt:
                    log_files.append((filename, file_time))
            except Exception as e:
                logger.error(f"Error parsing timestamp from filename {filename}: {str(e)}")
    
    # Sort log files by timestamp (oldest first)
    log_files.sort(key=lambda x: x[1])
    
    # Read and parse log content
    parsed_logs = []
    
    for filename, _ in log_files:
        log_path = os.path.join(target_dir, filename)
        
        try:
            with open(log_path, 'r') as f:
                log_batch = json.load(f)
                
                for log_entry in log_batch:
                    try:
                        log_time = log_entry.get('timestamp')
                        if isinstance(log_time, str):
                            log_time = parser.parse(log_time)
                        
                        # Check if log is within the requested timerange
                        if start_dt <= log_time <= end_dt:
                            # Extract event data
                            event = log_entry.get('event')
                            if isinstance(event, dict):
                                # JSON event
                                message = json.dumps(event)
                            else:
                                # String event
                                message = str(event)
                            
                            parsed_logs.append({
                                'timestamp': log_entry.get('timestamp').isoformat() if hasattr(log_entry.get('timestamp'), 'isoformat') else log_entry.get('timestamp'),
                                'source_ip': log_entry.get('client_ip'),
                                'message': message,
                                'filename': filename
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
    
def retry_failed_hec_submissions():
    """
    Retry sending previously failed HEC submissions from the backup directory.
    This can be run periodically to ensure no events are lost.
    """
    backup_dir = os.path.join('data', 'hec_failures')
    if not os.path.exists(backup_dir):
        return
    
    for filename in os.listdir(backup_dir):
        if not filename.endswith('.json'):
            continue
        
        filepath = os.path.join(backup_dir, filename)
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            hec_url = data.get('url')
            events = data.get('events', [])
            
            if not hec_url or not events:
                logger.warning(f"Invalid HEC backup file: {filepath}")
                os.remove(filepath)
                continue
            
            # Extract source_id from filename
            source_id = filename.split('_')[0]
            
            # Get the HEC token
            source_config = global_sources.get(source_id, {})
            hec_token = source_config.get('hec_token')
            
            if not hec_token:
                logger.warning(f"Could not find HEC token for source {source_id}")
                continue
            
            # Attempt to send the events
            headers = {
                "Authorization": f"Splunk {hec_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                hec_url,
                headers=headers,
                json={"events": events},
                timeout=15
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully retried HEC submission for {filepath}")
                os.remove(filepath)
            else:
                logger.warning(f"Failed to retry HEC submission: {response.status_code} - {response.text}")
        
        except Exception as e:
            logger.error(f"Error retrying HEC submission {filepath}: {str(e)}")

def run_retry_scheduler():
    """Run the retry scheduler in a loop"""
    while True:
        try:
            retry_failed_hec_submissions()
        except Exception as e:
            logger.error(f"Error in retry scheduler: {str(e)}")
        
        # Run every 5 minutes
        time.sleep(300)