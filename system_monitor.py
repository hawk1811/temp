#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - System Monitor
This module provides system resource monitoring and performance metrics.
"""

import os
import json
import time
import threading
import logging
import psutil
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SystemMonitor:
    """Monitors system resources and performance metrics."""
    
    def __init__(self, history_size=300):
        """
        Initialize the system monitor.
        
        Args:
            history_size (int): Number of historical data points to keep
        """
        self.history_size = history_size
        self.metrics = {
            'timestamp': [],
            'cpu_usage': [],
            'memory_usage': [],
            'swap_usage': [],
            'disk_usage': [],
            'network_sent': [],
            'network_received': [],
            'eps': []
        }
        
        self.metrics_lock = threading.Lock()
        self.last_network_sent = 0
        self.last_network_recv = 0
        self.last_network_time = time.time()
        
        # Start background monitoring
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self.monitor_thread.start()
        
        logger.info("System monitor initialized")
    
    def get_current_metrics(self):
        """
        Get the current system metrics.
        
        Returns:
            dict: Current system metrics
        """
        with self.metrics_lock:
            if not self.metrics['timestamp']:
                return {
                    'cpu_usage': 0,
                    'memory_usage': 0,
                    'swap_usage': 0,
                    'disk_usage': 0,
                    'network_sent': 0,
                    'network_received': 0,
                    'eps': 0
                }
            
            return {
                'cpu_usage': self.metrics['cpu_usage'][-1],
                'memory_usage': self.metrics['memory_usage'][-1],
                'swap_usage': self.metrics['swap_usage'][-1],
                'disk_usage': self.metrics['disk_usage'][-1],
                'network_sent': self.metrics['network_sent'][-1],
                'network_received': self.metrics['network_received'][-1],
                'eps': self.metrics['eps'][-1]
            }
    
    def get_history_metrics(self):
        """
        Get historical metrics for graphing.
        
        Returns:
            dict: Historical metrics with timestamps
        """
        with self.metrics_lock:
            return {k: v.copy() for k, v in self.metrics.items()}
    
    def update_eps(self, eps_value):
        """
        Update the current EPS (Events Per Second) value.
        
        Args:
            eps_value (int): Current EPS value
        """
        with self.metrics_lock:
            current_time = datetime.now().strftime('%H:%M:%S')
            
            self.metrics['timestamp'].append(current_time)
            self.metrics['eps'].append(eps_value)
            
            # Trim history if needed
            if len(self.metrics['timestamp']) > self.history_size:
                self.metrics['timestamp'] = self.metrics['timestamp'][-self.history_size:]
                self.metrics['eps'] = self.metrics['eps'][-self.history_size:]
    
    def _monitor_resources(self):
        """Background thread that collects system metrics."""
        while self.running:
            try:
                # Get current time
                current_time = datetime.now().strftime('%H:%M:%S')
                
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=None)
                
                # Memory usage
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Swap usage
                swap = psutil.swap_memory()
                swap_percent = swap.percent
                
                # Disk usage for the logs directory
                logs_dir = os.path.abspath('logs')
                if not os.path.exists(logs_dir):
                    logs_dir = os.path.dirname(os.path.abspath(__file__))
                
                disk = psutil.disk_usage(logs_dir)
                disk_percent = disk.percent
                
                # Network I/O
                net_io = psutil.net_io_counters()
                current_time_s = time.time()
                time_diff = current_time_s - self.last_network_time
                
                # Calculate network rates
                if self.last_network_sent > 0 and time_diff > 0:
                    sent_rate = (net_io.bytes_sent - self.last_network_sent) / time_diff / 1024  # KB/s
                    recv_rate = (net_io.bytes_recv - self.last_network_recv) / time_diff / 1024  # KB/s
                else:
                    sent_rate = 0
                    recv_rate = 0
                
                self.last_network_sent = net_io.bytes_sent
                self.last_network_recv = net_io.bytes_recv
                self.last_network_time = current_time_s
                
                # Update metrics with lock to prevent race conditions
                with self.metrics_lock:
                    # Only update timestamps and other metrics in sync
                    self.metrics['timestamp'].append(current_time)
                    self.metrics['cpu_usage'].append(cpu_percent)
                    self.metrics['memory_usage'].append(memory_percent)
                    self.metrics['swap_usage'].append(swap_percent)
                    self.metrics['disk_usage'].append(disk_percent)
                    self.metrics['network_sent'].append(sent_rate)
                    self.metrics['network_received'].append(recv_rate)
                    
                    # Note: EPS is updated externally by the queue manager
                    # Fill with 0 if not yet updated to keep arrays in sync
                    if len(self.metrics['eps']) < len(self.metrics['timestamp']):
                        self.metrics['eps'].append(0)
                    
                    # Trim history if needed
                    if len(self.metrics['timestamp']) > self.history_size:
                        for key in self.metrics:
                            self.metrics[key] = self.metrics[key][-self.history_size:]
                
                # Sleep for a second before next collection
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error monitoring system resources: {str(e)}", exc_info=True)
                time.sleep(5)  # Sleep longer on error
    
    def stop(self):
        """Stop the monitoring thread."""
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        logger.info("System monitor stopped")

# Singleton instance
_monitor_instance = None

def get_monitor():
    """
    Get or create the singleton monitor instance.
    
    Returns:
        SystemMonitor: The system monitor instance
    """
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = SystemMonitor()
    return _monitor_instance