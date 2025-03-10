#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Queue Manager
This module manages message queues and worker threads for high-volume syslog processing.
"""

import os
import json
import time
import threading
import logging
import queue
import random
from datetime import datetime
import psutil
from dateutil import parser

logger = logging.getLogger(__name__)

class QueueManager:
    """Manages queues and workers for processing syslog messages at high volume."""
    
    def __init__(self, sources, max_workers=10, min_workers=2, queue_size=100000):
        """
        Initialize the queue manager.
        
        Args:
            sources (dict): Source configurations
            max_workers (int): Maximum number of worker threads
            min_workers (int): Minimum number of worker threads
            queue_size (int): Maximum queue size
        """
        self.sources = sources
        self.max_workers = max_workers
        self.min_workers = min_workers
        self.message_queue = queue.Queue(maxsize=queue_size)
        
        # Worker management
        self.workers = []
        self.active_workers = 0
        self.worker_lock = threading.Lock()
        
        # Performance metrics
        self.metrics = {
            'queue_size': 0,
            'messages_processed': 0,
            'current_eps': 0,
            'eps_history': [],
            'cpu_usage': 0,
            'memory_usage': 0
        }
        self.metrics_lock = threading.Lock()
        self.last_count_time = time.time()
        self.message_count_interval = 0
        
        # File locks for each source and date
        self.file_locks = {}
        self.file_locks_lock = threading.Lock()
        
        # Start metrics collection
        self.metrics_thread = threading.Thread(target=self._collect_metrics, daemon=True)
        self.metrics_thread.start()
        
        # Start initial workers
        self._start_workers(min_workers)
        
        # Start the scaler thread
        self.scaler_thread = threading.Thread(target=self._auto_scale_workers, daemon=True)
        self.scaler_thread.start()
        
        logger.info(f"Queue manager initialized with {min_workers} workers and queue size {queue_size}")
    
    def enqueue_message(self, client_ip, message, timestamp=None):
        """
        Add a message to the processing queue.
        
        Args:
            client_ip (str): Client IP address
            message (str): Syslog message
            timestamp (datetime, optional): Message timestamp
        
        Returns:
            bool: True if message was enqueued, False if queue is full
        """
        try:
            if timestamp is None:
                timestamp = datetime.now()
                
            self.message_queue.put({
                'client_ip': client_ip,
                'message': message,
                'timestamp': timestamp,
                'enqueue_time': time.time()
            }, block=False)
            
            # Update count for EPS calculation
            with self.metrics_lock:
                self.message_count_interval += 1
                self.metrics['queue_size'] = self.message_queue.qsize()
            
            return True
        except queue.Full:
            logger.warning("Message queue is full, dropping message")
            return False
    
    def get_metrics(self):
        """
        Get current performance metrics.
        
        Returns:
            dict: Performance metrics
        """
        with self.metrics_lock:
            return self.metrics.copy()
    
    def _start_workers(self, count):
        """
        Start worker threads.
        
        Args:
            count (int): Number of workers to start
        """
        with self.worker_lock:
            logger.info(f"Starting {count} worker threads (current active workers: {self.active_workers})")
            for i in range(count):
                try:
                    worker = threading.Thread(target=self._worker_process, daemon=True)
                    worker.name = f"QueueWorker-{len(self.workers)+1}"
                    worker.start()
                    self.workers.append(worker)
                    self.active_workers += 1
                    logger.info(f"Started worker thread {worker.name}")
                except Exception as e:
                    logger.error(f"Failed to start worker thread: {str(e)}", exc_info=True)
            
            logger.info(f"After startup: {self.active_workers} active workers, {len(self.workers)} worker threads")
    
    def _stop_workers(self, count):
        """
        Signal workers to stop.
        
        Args:
            count (int): Number of workers to stop
        """
        with self.worker_lock:
            # We don't actually stop threads, just reduce the count
            # Workers will exit when they see active_workers is lower than their index
            self.active_workers = max(self.min_workers, self.active_workers - count)
            logger.info(f"Requested {count} workers to stop, active workers set to: {self.active_workers}")
    
    def _worker_process(self):
        """Worker thread that processes messages from the queue."""
        worker_id = threading.get_ident()
        logger.info(f"Worker {worker_id} started")
        
        while True:
            try:
                # Check if this worker should exit
                with self.worker_lock:
                    worker_index = self.workers.index(threading.current_thread())
                    if worker_index >= self.active_workers:
                        self.workers.remove(threading.current_thread())
                        logger.info(f"Worker {worker_id} shutting down")
                        return
                
                # Get a message from the queue
                try:
                    message_data = self.message_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process the message
                self._process_message(message_data)
                
                # Mark task as done
                self.message_queue.task_done()
                
                # Update processed count
                with self.metrics_lock:
                    self.metrics['messages_processed'] += 1
                    self.metrics['queue_size'] = self.message_queue.qsize()
                    
            except Exception as e:
                logger.error(f"Error in worker {worker_id}: {str(e)}", exc_info=True)
    
    def _process_message(self, message_data):
        """
        Process a message and store it in the appropriate file.
        
        Args:
            message_data (dict): Message data including client_ip, message, and timestamp
        """
        client_ip = message_data['client_ip']
        message = message_data['message']
        timestamp = message_data['timestamp']
        
        # Find matching source for this client IP
        source_id = self._find_matching_source(client_ip)
        if not source_id:
            # No matching source found, store in default location
            self._store_log('unknown', timestamp, client_ip, message)
            return
        
        # Get source configuration
        source_config = self.sources.get(source_id, {})
        
        # Store the log
        self._store_log(source_id, timestamp, client_ip, message, source_config)
    
    def _find_matching_source(self, client_ip):
        """
        Find the source configuration that matches the client IP.
        
        Args:
            client_ip (str): The client IP address
            
        Returns:
            str: The source ID or None if not found
        """
        from utils import is_ip_in_network
        
        for source_id, source_config in self.sources.items():
            source_ips = source_config.get('source_ips', [])
            for ip_entry in source_ips:
                if is_ip_in_network(client_ip, ip_entry):
                    return source_id
        
        return None
    
    def _get_file_lock(self, source_id, date_str):
        """
        Get a lock for a specific source and date.
        
        Args:
            source_id (str): Source ID
            date_str (str): Date string in YYYY-MM-DD format
            
        Returns:
            threading.Lock: The lock object
        """
        lock_key = f"{source_id}_{date_str}"
        
        with self.file_locks_lock:
            if lock_key not in self.file_locks:
                self.file_locks[lock_key] = threading.RLock()  # Use RLock instead of Lock
            
            return self.file_locks[lock_key]
    
    def _store_log(self, source_id, timestamp, client_ip, message, source_config=None):
        """
        Store a log message in the appropriate date-based JSON file.
        
        Args:
            source_id (str): Source ID
            timestamp (datetime): Message timestamp
            client_ip (str): Client IP address
            message (str): Syslog message
            source_config (dict, optional): Source configuration
        """
        # Format date for filename
        date_str = timestamp.strftime('%Y-%m-%d')
        
        # Get target directory
        target_dir = None
        if source_config:
            target_dir = source_config.get('target_directory')
        
        if not target_dir:
            target_dir = os.path.join('logs', source_id)
        
        # Ensure target directory exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Maximum file size (100MB in bytes)
        MAX_FILE_SIZE = 104857600  # 100MB
        
        # Prepare log entry
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'source_ip': client_ip,
            'message': message
        }
        
        # Get lock for this source and date
        file_lock = self._get_file_lock(source_id, date_str)
        
        # Process the file with locking to handle concurrent writes
        with file_lock:
            # Find the appropriate file to use (checking size limits)
            file_index = 1
            while True:
                # Construct filename with optional index suffix
                if file_index == 1:
                    filename = f"{date_str}.json"
                else:
                    filename = f"{date_str}_{file_index}.json"
                
                filepath = os.path.join(target_dir, filename)
                
                # Check if file exists and its size
                if os.path.exists(filepath):
                    file_size = os.path.getsize(filepath)
                    # If file is too large, try the next index
                    if file_size >= MAX_FILE_SIZE:
                        file_index += 1
                        continue
                
                # Found an appropriate file (either existing with room or new)
                break
            
            logs = []
            
            # Read existing logs if file exists
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        file_content = f.read().strip()
                        if file_content:
                            logs = json.loads(file_content)
                        # If file exists but is empty or invalid, logs remains an empty list
                except json.JSONDecodeError:
                    logger.error(f"Error reading log file {filepath}, creating new file")
                    # Backup corrupt file for investigation
                    if os.path.exists(filepath):
                        backup_path = f"{filepath}.corrupt.{int(time.time())}"
                        try:
                            os.rename(filepath, backup_path)
                            logger.warning(f"Backed up corrupt log file to {backup_path}")
                        except Exception as e:
                            logger.error(f"Failed to backup corrupt file: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error reading {filepath}: {str(e)}", exc_info=True)
            
            # Add new log entry
            logs.append(log_entry)
            
            # Sort logs by timestamp
            logs.sort(key=lambda x: x['timestamp'])
            
            # Write back to file - make sure we're not truncating the file before writing
            try:
                # Create a unique temporary filename with random component
                random_suffix = str(random.randint(10000, 99999))
                tmp_path = f"{filepath}.tmp.{random_suffix}.{os.getpid()}"
                
                # Write to temporary file
                with open(tmp_path, 'w') as f:
                    json.dump(logs, f)
                
                # Try to replace the original file atomically with retries
                max_retries = 5
                retry_count = 0
                replaced = False
                
                while not replaced and retry_count < max_retries:
                    try:
                        os.replace(tmp_path, filepath)
                        replaced = True
                    except PermissionError:
                        retry_count += 1
                        logger.debug(f"File locked, retrying replace operation ({retry_count}/{max_retries})")
                        time.sleep(0.1 * retry_count)  # Increasing delay with each retry
                
                # If all retries failed, log the error
                if not replaced:
                    logger.warning(f"Could not replace file after {max_retries} attempts, using direct write fallback")
                    # Try direct write as fallback
                    try:
                        with open(filepath, 'w') as f:
                            json.dump(logs, f)
                    except Exception as direct_error:
                        logger.error(f"Failed direct write fallback: {str(direct_error)}")
                
                # Cleanup temporary file if it still exists
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass  # Ignore cleanup errors
                        
            except Exception as e:
                logger.error(f"Error writing to log file {filepath}: {str(e)}", exc_info=True)
                # Try direct write as fallback
                try:
                    with open(filepath, 'w') as f:
                        json.dump(logs, f)
                except Exception as direct_error:
                    logger.error(f"Failed direct write fallback: {str(direct_error)}")
            
            # Update metadata with filename (including suffix if any)
            base_filename = os.path.basename(filepath)
            self._update_source_metadata(source_id, date_str, base_filename)
    
    def _update_source_metadata(self, source_id, date_str, filename=None):
        """
        Update source metadata with new log date and filename.
        
        Args:
            source_id (str): Source ID
            date_str (str): Date string in YYYY-MM-DD format
            filename (str, optional): The actual filename used (with potential suffix)
        """
        metadata_file = os.path.join('data', f'{source_id}_dates.json')
        
        # Get lock for this source's metadata
        metadata_lock = self._get_file_lock(source_id, 'metadata')
        
        with metadata_lock:
            metadata = {}
            
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        file_content = f.read().strip()
                        if file_content:
                            metadata = json.loads(file_content)
                        else:
                            metadata = {"dates": [], "files": {}}
                except json.JSONDecodeError:
                    metadata = {"dates": [], "files": {}}
                except Exception as e:
                    logger.error(f"Error reading metadata file {metadata_file}: {str(e)}")
                    metadata = {"dates": [], "files": {}}
                    
            # Initialize the metadata structure if needed
            if isinstance(metadata, list):
                # Convert old format (just a list of dates) to new structure
                metadata = {"dates": metadata, "files": {}}
            elif not isinstance(metadata, dict):
                metadata = {"dates": [], "files": {}}
            
            if "dates" not in metadata:
                metadata["dates"] = []
            if "files" not in metadata:
                metadata["files"] = {}
            
            # Add date if not already in the list
            if date_str not in metadata["dates"]:
                metadata["dates"].append(date_str)
                metadata["dates"].sort()
            
            # Add filename to the date's file list
            if filename:
                if date_str not in metadata["files"]:
                    metadata["files"][date_str] = []
                
                if filename not in metadata["files"][date_str]:
                    metadata["files"][date_str].append(filename)
                    # Sort filenames to handle numerical suffixes correctly
                    metadata["files"][date_str].sort()
            
            # Write metadata with the same careful approach as log files
            try:
                # Create a unique temporary filename
                random_suffix = str(random.randint(10000, 99999))
                tmp_path = f"{metadata_file}.tmp.{random_suffix}"
                
                # Write to temporary file
                with open(tmp_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                # Try to replace the original file atomically with retries
                max_retries = 5
                retry_count = 0
                replaced = False
                
                while not replaced and retry_count < max_retries:
                    try:
                        os.replace(tmp_path, metadata_file)
                        replaced = True
                    except PermissionError:
                        retry_count += 1
                        time.sleep(0.1 * retry_count)  # Increasing delay with each retry
                
                # If all retries failed, log the error
                if not replaced:
                    logger.warning(f"Could not replace metadata file after {max_retries} attempts, using direct write")
                    with open(metadata_file, 'w') as f:
                        json.dump(metadata, f, indent=2)
                
                # Cleanup temporary file if it still exists
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass  # Ignore cleanup errors
                        
            except Exception as e:
                logger.error(f"Error updating metadata: {str(e)}", exc_info=True)
                # Direct write fallback
                try:
                    with open(metadata_file, 'w') as f:
                        json.dump(metadata, f, indent=2)
                except Exception as fallback_error:
                    logger.error(f"Failed metadata fallback write: {str(fallback_error)}")
    
    def _collect_metrics(self):
        """Collect performance metrics periodically."""
        while True:
            try:
                # Calculate EPS
                current_time = time.time()
                elapsed = current_time - self.last_count_time
                
                if elapsed >= 1.0:  # Update metrics every second
                    with self.metrics_lock:
                        # Calculate current EPS
                        current_eps = int(self.message_count_interval / elapsed)
                        self.metrics['current_eps'] = current_eps
                        
                        # Add to EPS history (keep last 60 samples for a minute of history)
                        self.metrics['eps_history'].append(current_eps)
                        if len(self.metrics['eps_history']) > 60:
                            self.metrics['eps_history'].pop(0)
                        
                        # Reset counter
                        self.message_count_interval = 0
                        self.last_count_time = current_time
                
                # Update CPU and memory usage
                with self.metrics_lock:
                    self.metrics['cpu_usage'] = psutil.cpu_percent()
                    self.metrics['memory_usage'] = psutil.Process().memory_percent()
                    self.metrics['queue_size'] = self.message_queue.qsize()
                
                time.sleep(0.2)  # Short sleep to prevent tight loop
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {str(e)}", exc_info=True)
                time.sleep(1)  # Longer sleep on error
    
    def _auto_scale_workers(self):
        """Automatically scale workers based on queue size and system load."""
        while True:
            try:
                # Get current metrics
                metrics = self.get_metrics()
                queue_size = metrics['queue_size']
                cpu_usage = metrics['cpu_usage']
                memory_usage = metrics['memory_usage']
                
                # Log current state for debugging
                logger.debug(f"Auto-scaler check: queue_size={queue_size}, active_workers={self.active_workers}, cpu={cpu_usage}%, memory={memory_usage}%")
                
                # Scale up if queue is filling and resources available
                if queue_size > 1000 and self.active_workers < self.max_workers:
                    if cpu_usage < 80 and memory_usage < 70:
                        # Add workers proportionally to queue size
                        workers_to_add = min(
                            2,  # Add at most 2 workers at a time
                            self.max_workers - self.active_workers
                        )
                        if workers_to_add > 0:
                            logger.info(f"Scaling up by {workers_to_add} workers due to queue size {queue_size}")
                            self._start_workers(workers_to_add)
                
                # Scale down if queue is small and we have excess workers
                elif queue_size < 100 and self.active_workers > self.min_workers:
                    workers_to_remove = min(
                        1,  # Remove at most 1 worker at a time
                        self.active_workers - self.min_workers
                    )
                    if workers_to_remove > 0:
                        logger.info(f"Scaling down by {workers_to_remove} workers due to low queue size {queue_size}")
                        self._stop_workers(workers_to_remove)
                
                # Also scale down if memory usage is too high
                elif memory_usage > 80 and self.active_workers > self.min_workers:
                    workers_to_remove = min(
                        2,  # Remove up to 2 workers at a time when memory is high
                        self.active_workers - self.min_workers
                    )
                    if workers_to_remove > 0:
                        logger.info(f"Scaling down by {workers_to_remove} workers due to high memory usage {memory_usage}%")
                        self._stop_workers(workers_to_remove)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in auto-scaler: {str(e)}", exc_info=True)
                time.sleep(10)  # Longer sleep on error