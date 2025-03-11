/**
 * SyslogManager - Event Logs JavaScript
 * Handles client-side functionality for viewing and managing application event logs.
 */

$(document).ready(function() {
    // Setup CSRF token for all AJAX requests
    const csrfToken = $('meta[name="csrf-token"]').attr('content');
    
    // Add CSRF token to all AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrfToken);
            }
        }
    });

    // Initialize DataTables
    const eventLogsTable = $('#eventLogsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']], // Sort by timestamp descending
        pageLength: 25,
        lengthMenu: [10, 25, 50, 100],
        columns: [
            { data: 'timestamp' },
            { data: 'level' },
            { data: 'module' },
            { data: 'message' }
        ],
        columnDefs: [
            { 
                targets: 1, // Level column
                render: function(data, type, row) {
                    let badgeClass = 'bg-secondary';
                    
                    if (data === 'ERROR') {
                        badgeClass = 'bg-danger';
                    } else if (data === 'WARNING') {
                        badgeClass = 'bg-warning';
                    } else if (data === 'INFO') {
                        badgeClass = 'bg-info';
                    } else if (data === 'DEBUG') {
                        badgeClass = 'bg-success';
                    }
                    
                    return `<span class="badge ${badgeClass}">${data}</span>`;
                }
            }
        ]
    });

    // Load initial logs
    loadEventLogs();

    // Handle refresh button click
    $('#refreshLogsBtn').on('click', function() {
        loadEventLogs();
    });

    // Handle clear logs button click
    $('#clearLogsBtn').on('click', function() {
        $('#clearLogsModal').modal('show');
    });

    // Handle confirm clear logs button click
    $('#confirmClearLogsBtn').on('click', function() {
        clearEventLogs();
    });

    // Handle log search
    $('#logSearch').on('input', function() {
        eventLogsTable.search($(this).val()).draw();
    });

    // Function to load event logs
    function loadEventLogs() {
        $.ajax({
            url: '/api/event_logs',
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    // Clear and reload the table
                    eventLogsTable.clear();
                    
                    if (response.logs && response.logs.length > 0) {
                        eventLogsTable.rows.add(response.logs).draw();
                    } else {
                        $('#eventLogsTable tbody').html('<tr><td colspan="4" class="text-center">No logs found.</td></tr>');
                    }
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while loading event logs.');
                }
            }
        });
    }

    // Function to clear event logs
    function clearEventLogs() {
        $.ajax({
            url: '/api/event_logs/clear',
            type: 'POST',
            success: function(response) {
                if (response.status === 'success') {
                    // Close modal
                    $('#clearLogsModal').modal('hide');
                    
                    // Show success message
                    alert('Event logs cleared successfully');
                    
                    // Reload logs
                    loadEventLogs();
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while clearing event logs.');
                }
            }
        });
    }
});