/**
 * SyslogManager - Monitoring JavaScript
 * Handles client-side functionality for the monitoring configuration.
 */

$(document).ready(function() {
    // Get CSRF token for AJAX requests
    const csrfToken = $('meta[name="csrf-token"]').attr('content');
    
    // Load current monitoring configuration
    loadMonitoringConfig();
    
    // Handle monitoring form submission
    $('#monitoringForm').on('submit', function(e) {
        e.preventDefault();
        saveMonitoringConfig();
    });
    
    // Handle test heartbeat button
    $('#testHeartbeatBtn').on('click', function() {
        testHeartbeat();
    });
    
    // Function to load current monitoring configuration
    function loadMonitoringConfig() {
        $.ajax({
            url: '/api/monitoring',
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    populateMonitoringForm(response.data);
                    updateMonitoringStatus(response.data);
                } else {
                    showError('Error loading monitoring configuration: ' + response.message);
                }
            },
            error: function(xhr) {
                handleAjaxError(xhr, 'Error loading monitoring configuration');
            }
        });
    }
    
    // Function to save monitoring configuration
    function saveMonitoringConfig() {
        // Get selected metrics
        const selectedMetrics = [];
        $('.metric-checkbox:checked').each(function() {
            selectedMetrics.push($(this).val());
        });
        
        // Prepare configuration data
        const configData = {
            enabled: $('#monitoringEnabled').is(':checked'),
            hec_url: $('#hecUrl').val().trim(),
            hec_token: $('#hecToken').val().trim(),
            interval: parseInt($('#interval').val()) || 60,
            metrics: selectedMetrics
        };
        
        // Validate configuration
        if (configData.enabled) {
            if (!configData.hec_url) {
                showError('HEC URL is required when monitoring is enabled');
                return;
            }
            
            if (!configData.hec_token) {
                showError('HEC Token is required when monitoring is enabled');
                return;
            }
            
            if (configData.interval < 10) {
                showError('Heartbeat interval must be at least 10 seconds');
                return;
            }
        }
        
        // Save configuration
        $.ajax({
            url: '/api/monitoring',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(configData),
            headers: {
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
                if (response.status === 'success') {
                    // Show success message
                    showSuccess('Monitoring configuration saved successfully');
                    
                    // Update status display
                    updateMonitoringStatus(response.data);
                    
                    // If token was changed, clear the input
                    if (configData.hec_token) {
                        $('#hecToken').val('');
                    }
                } else {
                    showError('Error saving monitoring configuration: ' + response.message);
                }
            },
            error: function(xhr) {
                handleAjaxError(xhr, 'Error saving monitoring configuration');
            }
        });
    }
    
    // Function to test heartbeat
    function testHeartbeat() {
        // Show test modal
        $('#testResultModal').modal('show');
        $('#testResultContainer').html('<div class="alert alert-info">Sending test heartbeat...</div>');
        $('#heartbeatJson').text('Loading...');
        
        $.ajax({
            url: '/api/monitoring/test',
            type: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
                if (response.status === 'success') {
                    $('#testResultContainer').html('<div class="alert alert-success">Test heartbeat sent successfully!</div>');
                    $('#heartbeatJson').text(JSON.stringify(response.data, null, 2));
                } else {
                    $('#testResultContainer').html('<div class="alert alert-danger">Error sending test heartbeat: ' + response.message + '</div>');
                    $('#heartbeatJson').text(JSON.stringify(response.data || {}, null, 2));
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    $('#testResultContainer').html('<div class="alert alert-danger">Error: ' + response.message + '</div>');
                } catch (e) {
                    $('#testResultContainer').html('<div class="alert alert-danger">An error occurred while sending the test heartbeat.</div>');
                }
                $('#heartbeatJson').text('No data available');
            }
        });
    }
    
    // Function to populate form with current configuration
    function populateMonitoringForm(config) {
        $('#monitoringEnabled').prop('checked', config.enabled);
        $('#hecUrl').val(config.hec_url);
        $('#interval').val(config.interval);
        
        // Reset all checkboxes first
        $('.metric-checkbox').prop('checked', false);
        
        // Check the configured metrics
        if (config.metrics && Array.isArray(config.metrics)) {
            config.metrics.forEach(function(metric) {
                $('#metric' + metric.charAt(0).toUpperCase() + metric.slice(1)).prop('checked', true);
            });
        }
    }
    
    // Function to update monitoring status display
    function updateMonitoringStatus(config) {
        let statusHtml = '';
        
        if (config.is_running) {
            statusHtml = `
                <div class="d-flex align-items-center">
                    <span class="badge bg-success me-2">Active</span>
                    <span>Monitoring is running on host <strong>${config.hostname}</strong> with interval <strong>${config.interval} seconds</strong></span>
                </div>
            `;
        } else if (config.enabled) {
            statusHtml = `
                <div class="d-flex align-items-center">
                    <span class="badge bg-warning me-2">Starting</span>
                    <span>Monitoring is enabled but not yet running. It will start shortly.</span>
                </div>
            `;
        } else {
            statusHtml = `
                <div class="d-flex align-items-center">
                    <span class="badge bg-secondary me-2">Disabled</span>
                    <span>Monitoring is currently disabled. Enable it to start sending heartbeats.</span>
                </div>
            `;
        }
        
        $('#monitoringStatus').html(statusHtml);
    }
    
    // Helper function to show error message
    function showError(message) {
        const alertHtml = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        
        // Insert alert before the form
        $('#monitoringForm').before(alertHtml);
        
        // Scroll to the alert
        $('html, body').animate({
            scrollTop: $('.alert-danger').offset().top - 70
        }, 200);
    }
    
    // Helper function to show success message
    function showSuccess(message) {
        const alertHtml = `
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        
        // Insert alert before the form
        $('#monitoringForm').before(alertHtml);
        
        // Scroll to the alert
        $('html, body').animate({
            scrollTop: $('.alert-success').offset().top - 70
        }, 200);
        
        // Auto-dismiss after 5 seconds
        setTimeout(function() {
            $('.alert-success').alert('close');
        }, 5000);
    }
    
    // Helper function to handle AJAX errors
    function handleAjaxError(xhr, defaultMessage) {
        try {
            const response = JSON.parse(xhr.responseText);
            showError(defaultMessage + ': ' + response.message);
        } catch (e) {
            showError(defaultMessage + '. Check server logs for details.');
        }
    }
});