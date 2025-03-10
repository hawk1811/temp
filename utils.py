#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Utility Functions
This module contains utility functions for the application.
"""

import os
import sys
import psutil
import logging
import ipaddress
import paramiko
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def check_memory_usage():
    """
    Check current memory usage.
    
    Returns:
        float: Memory usage as percentage
    """
    try:
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        system_memory = psutil.virtual_memory()
        
        # Calculate percentage of system memory used by this process
        usage_percent = (memory_info.rss / system_memory.total) * 100
        
        return usage_percent
    except Exception as e:
        logger.error(f"Error checking memory usage: {str(e)}")
        return 0.0

def is_ip_in_network(ip, network_spec):
    """
    Check if an IP address is in a network.
    
    Args:
        ip (str): The IP address to check
        network_spec (str): Network specification (single IP, CIDR, or range)
        
    Returns:
        bool: True if the IP is in the network, False otherwise
    """
    try:
        # Case 1: Single IP
        if '/' not in network_spec and '-' not in network_spec:
            return ip == network_spec
        
        # Case 2: CIDR notation
        if '/' in network_spec:
            network = ipaddress.ip_network(network_spec, strict=False)
            return ipaddress.ip_address(ip) in network
        
        # Case 3: IP range (e.g. 192.168.1.1-192.168.1.10)
        if '-' in network_spec:
            start_ip, end_ip = network_spec.split('-')
            ip_int = int(ipaddress.ip_address(ip))
            start_int = int(ipaddress.ip_address(start_ip))
            end_int = int(ipaddress.ip_address(end_ip))
            return start_int <= ip_int <= end_int
        
        return False
    except Exception as e:
        logger.error(f"Error checking IP {ip} against network {network_spec}: {str(e)}")
        return False

def check_network_share_access(path):
    """
    Check if a network share path is accessible.
    
    Args:
        path (str): The network share path
        
    Returns:
        tuple: (bool, str) - (Success, Error message if any)
    """
    # Check if path is local
    if os.path.isabs(path) and not path.startswith('//') and not path.startswith('\\\\'):
        try:
            # Create directory if it doesn't exist
            os.makedirs(path, exist_ok=True)
            
            # Check write permissions by attempting to create a test file
            test_file = os.path.join(path, '.test_access')
            with open(test_file, 'w') as f:
                f.write('test')
            
            # Remove test file
            os.remove(test_file)
            
            return True, ""
        except Exception as e:
            return False, str(e)
    
    # Handle network paths (simple check)
    if path.startswith('//') or path.startswith('\\\\'):
        try:
            # Convert to proper format if needed
            normalized_path = path.replace('\\', '/')
            
            # Extract server and share from UNC path
            parts = normalized_path.strip('/').split('/')
            if len(parts) < 2:
                return False, "Invalid network path format"
            
            # Try to connect to the share
            # This is a simplified approach - in production, you'd want to use
            # proper authentication and more robust connection handling
            test_path = os.path.join(path, '.test_access')
            try:
                with open(test_path, 'w') as f:
                    f.write('test')
                os.remove(test_path)
                return True, ""
            except Exception as e:
                return False, f"Cannot write to network share: {str(e)}"
        except Exception as e:
            return False, str(e)
    
    return False, "Unsupported path format"

def clean_old_logs(retention_days=30):
    """
    Clean up log files older than the specified retention period.
    
    Args:
        retention_days (int): Number of days to retain logs
    """
    try:
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # Clean logs directory
        for root, dirs, files in os.walk('logs'):
            for file in files:
                if file.endswith('.log'):
                    file_path = os.path.join(root, file)
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_date:
                        try:
                            os.remove(file_path)
                            logger.info(f"Removed old log file: {file_path}")
                        except Exception as e:
                            logger.error(f"Error removing old log file {file_path}: {str(e)}")
    except Exception as e:
        logger.error(f"Error cleaning old logs: {str(e)}")

def parse_syslog_message(message):
    """
    Parse a syslog message into structured data.
    
    Args:
        message (str): The syslog message
        
    Returns:
        dict: Parsed syslog data
    """
    # Initialize parsed data
    parsed = {
        'priority': None,
        'facility': None,
        'severity': None,
        'timestamp': None,
        'hostname': None,
        'app_name': None,
        'proc_id': None,
        'msg_id': None,
        'message': message
    }
    
    try:
        # Try to extract PRI part (RFC3164/RFC5424)
        pri_match = re.match(r'^<(\d+)>(.*)', message)
        if pri_match:
            priority = int(pri_match.group(1))
            message = pri_match.group(2)
            
            # Calculate facility and severity
            facility = priority // 8
            severity = priority % 8
            
            parsed['priority'] = priority
            parsed['facility'] = facility
            parsed['severity'] = severity
            parsed['message'] = message
            
            # Further parsing could be done here for specific syslog formats
            # This would depend on your specific requirements
        
        return parsed
    except Exception as e:
        logger.error(f"Error parsing syslog message: {str(e)}")
        return parsed