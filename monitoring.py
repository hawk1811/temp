#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Monitoring Module
This module handles system monitoring and sending heartbeats to a HEC endpoint.
"""

import os
import json
import time
import logging
import threading
import requests
import psutil
import socket
from datetime import datetime

logger = logging.getLogger(__name__)

class MonitoringConfig:
    """Configuration for the HEC monitoring."""
    
    def __init__(self):
        self.enabled = False
        self.hec_url = ""
        self.hec_token = ""
        self.interval = 60  # Default: 60 seconds
        self.metrics = ["cpu", "memory", "eps", "disk"]
        self.hostname = socket.gethostname()
        self.monitor_thread = None
        self.stop_event = threading.Event()
        self.last_eps_time = datetime.now()
        self.last_log_count = 0
        self.current_eps = 0
        
        # Load configuration from file if it exists
        self.load_config()
    
    def load_config(self):
        """Load monitoring configuration from file."""
        config_path = os.path.join('data', 'monitoring.json')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                self.enabled = config.get('enabled', False)
                self.hec_url = config.get('hec_url', "")
                self.hec_token = config.get('hec_token', "")
                self.interval = config.get('interval', 60)
                self.metrics = config.get('metrics', ["cpu", "memory", "eps", "disk"])
            except Exception as e:
                logger.error(f"Error loading monitoring configuration: {str(e)}")
    
    def save_config(self):
        """Save monitoring configuration to file."""
        config_path = os.path.join('data', 'monitoring.json')
        try:
            with open(config_path, 'w') as f:
                json.dump({
                    'enabled': self.enabled,
                    'hec_url': self.hec_url,
                    'hec_token': self.hec_token,
                    'interval': self.interval,
                    'metrics': self.metrics
                }, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving monitoring configuration: {str(e)}")
    
    def update_config(self, config_data):
        """Update configuration with new data."""
        self.enabled = config_data.get('enabled', self.enabled)
        self.hec_url = config_data.get('hec_url', self.hec_url)
        self.hec_token = config_data.get('hec_token', self.hec_token)
        self.interval = config_data.get('interval', self.interval)
        self.metrics = config_data.get('metrics', self.metrics)
        
        # Save updated configuration
        self.save_config()
        
        # If enabled, start monitoring; otherwise stop
        if self.enabled:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start the monitoring thread if not already running."""
        if not self.monitor_thread or not self.monitor_thread.is_alive():
            self.stop_event.clear()
            self.monitor_thread = threading.Thread(
                target=self._monitoring_task,
                daemon=True
            )
            self.monitor_thread.start()
            logger.info("Monitoring thread started")
    
    def stop_monitoring(self):
        """Stop the monitoring thread if running."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.stop_event.set()
            self.monitor_thread.join(timeout=5.0)
            logger.info("Monitoring thread stopped")
    
    def update_eps(self, log_count):
        """Update events per second calculation."""
        now = datetime.now()
        time_diff = (now - self.last_eps_time).total_seconds()
        
        if time_diff > 0:
            count_diff = log_count - self.last_log_count
            self.current_eps = count_diff / time_diff
            
            self.last_eps_time = now
            self.last_log_count = log_count
    
    def _monitoring_task(self):
        """Background task to send heartbeats."""
        logger.info(f"Starting monitoring heartbeat (interval: {self.interval}s)")
        
        while not self.stop_event.is_set():
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                
                # Send heartbeat to HEC
                self._send_heartbeat(metrics)
                
                # Sleep until next interval
                self.stop_event.wait(self.interval)
            except Exception as e:
                logger.error(f"Error in monitoring task: {str(e)}")
                # Sleep a bit and try again
                self.stop_event.wait(10)
    
    def _collect_metrics(self):
        """Collect system metrics."""
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "type": "heartbeat"
        }
        
        # CPU usage (per core and average)
        if "cpu" in self.metrics:
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            metrics["cpu"] = {
                "per_cpu": cpu_percent,
                "average": sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0
            }
        
        # Memory usage
        if "memory" in self.metrics:
            memory = psutil.virtual_memory()
            metrics["memory"] = {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": memory.percent
            }
        
        # Disk usage
        if "disk" in self.metrics:
            disk = psutil.disk_usage('/')
            metrics["disk"] = {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            }
        
        # Events per second
        if "eps" in self.metrics:
            metrics["eps"] = self.current_eps
        
        # Process information
        if "process" in self.metrics:
            process = psutil.Process(os.getpid())
            with process.oneshot():
                metrics["process"] = {
                    "cpu_percent": process.cpu_percent(),
                    "memory_info": {
                        "rss": process.memory_info().rss,
                        "vms": process.memory_info().vms
                    },
                    "threads": len(process.threads()),
                    "connections": len(process.connections())
                }
        
        return metrics
    
    def _send_heartbeat(self, metrics):
        """Send heartbeat to HEC endpoint."""
        if not self.hec_url or not self.hec_token:
            logger.warning("HEC URL or token not configured, skipping heartbeat")
            return
        
        try:
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "event": metrics,
                "source": "syslog_manager",
                "sourcetype": "syslog_manager:heartbeat"
            }
            
            response = requests.post(
                self.hec_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Error sending heartbeat to HEC: {response.status_code} - {response.text}")
            else:
                logger.debug("Heartbeat sent successfully")
        except Exception as e:
            logger.error(f"Error sending heartbeat: {str(e)}")

# Global monitoring configuration instance
monitoring_config = MonitoringConfig()

def get_monitoring_status():
    """Get current monitoring status."""
    return {
        "enabled": monitoring_config.enabled,
        "hec_url": monitoring_config.hec_url,
        "hec_token": "****" if monitoring_config.hec_token else "",
        "interval": monitoring_config.interval,
        "metrics": monitoring_config.metrics,
        "hostname": monitoring_config.hostname,
        "is_running": monitoring_config.monitor_thread is not None and monitoring_config.monitor_thread.is_alive()
    }

def update_monitoring_config(config):
    """Update monitoring configuration."""
    monitoring_config.update_config(config)
    return get_monitoring_status()

def start_monitoring():
    """Start monitoring if enabled."""
    if monitoring_config.enabled:
        monitoring_config.start_monitoring()

def stop_monitoring():
    """Stop monitoring."""
    monitoring_config.stop_monitoring()

def update_eps(log_count):
    """Update the EPS calculation."""
    monitoring_config.update_eps(log_count)