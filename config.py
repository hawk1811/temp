#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Configuration
This module contains the configuration settings for the application.
"""

import os
import secrets

class Config:
    """Configuration class for the application."""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.environ.get('FLASK_PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Syslog server configuration
    SYSLOG_HOST = os.environ.get('SYSLOG_HOST', '0.0.0.0')
    SYSLOG_PORT = int(os.environ.get('SYSLOG_PORT', 514))
    
    # Application configuration
    MAX_MEMORY_USAGE = int(os.environ.get('MAX_MEMORY_USAGE', 80))  # Percentage of available system memory
    LOG_ROTATION_SIZE = int(os.environ.get('LOG_ROTATION_SIZE', 10))  # Size in MB
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 30))
    
    # Default credentials (only used for first login)
    DEFAULT_ADMIN_USERNAME = 'admin'
    DEFAULT_ADMIN_PASSWORD = 'password'