/**
 * SyslogManager - Investigation JavaScript
 * Handles client-side functionality for log investigation.
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
    const logsTable = $('#logsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']], // Sort by timestamp descending
        pageLength: 25,
        dom: 'rtip', // Remove the default search box
        columns: [
            { data: 'timestamp' },
            { data: 'source_ip' },
            { data: 'message' },
            { data: 'filename' }
        ]
    });

    // Initialize DateRangePicker
    $('#timeRange').daterangepicker({
        timePicker: true,
        timePicker24Hour: true,
        timePickerSeconds: true,
        startDate: moment().subtract(1, 'day'),
        endDate: moment(),
        locale: {
            format: 'YYYY-MM-DD HH:mm:ss'
        }
    });

    // Pagination variables
    let currentPage = 1;
    let totalPages = 1;
    let currentSearchParams = {};

    // Handle investigation form submission
    $('#investigateForm').on('submit', function(e) {
        e.preventDefault();
        
        const sourceId = $('#sourceSelect').val();
        const timeRange = $('#timeRange').data('daterangepicker');
        
        if (!sourceId) {
            alert('Please select a source to investigate');
            return;
        }
        
        const startTime = timeRange.startDate.format('YYYY-MM-DD HH:mm:ss');
        const endTime = timeRange.endDate.format('YYYY-MM-DD HH:mm:ss');
        
        // Show source name and time range
        $('#currentSourceName').text($('#sourceSelect option:selected').text());
        $('#currentTimeRange').text(startTime + ' to ' + endTime);
        
        // Save search parameters for pagination
        currentSearchParams = {
            start: startTime,
            end: endTime,
            page: 1,  // Reset to first page for new searches
            page_size: 25  // Match the DataTable page size
        };
        
        // Reset pagination
        currentPage = 1;
        
        // Show logs container and hide no source message
        $('#logsContainer').show();
        $('#noSourceSelected').hide();
        
        // Show loading indicator
        logsTable.clear().draw();
        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Loading logs...</td></tr>');
        $('#paginationControls').hide();
        
        // Fetch logs
        fetchLogs(sourceId);
    });

    // Handle export logs button
    $('#exportLogsBtn').on('click', function() {
        exportLogs();
    });

    // Click handler for log message expansion
    $('#logsTable tbody').on('click', 'td:nth-child(3)', function() {
        const tr = $(this).closest('tr');
        const row = logsTable.row(tr);
        const data = row.data();
        
        // Show log details in modal
        $('#detailTimestamp').text(data.timestamp);
        $('#detailSourceIP').text(data.source_ip);
        $('#detailMessage').text(data.message);
        $('#detailFilename').text(data.filename);
        
        $('#logDetailsModal').modal('show');
    });

    // Check if a source parameter is in the URL
    const urlParams = new URLSearchParams(window.location.search);
    const preselectedSource = urlParams.get('source');
    
    if (preselectedSource) {
        $('#sourceSelect').val(preselectedSource);
        // If there's a source selected, submit the form to load logs
        if ($('#sourceSelect').val()) {
            $('#investigateForm').submit();
        }
    }

    // Function to fetch logs with pagination
    function fetchLogs(sourceId) {
        // Update page in params
        currentSearchParams.page = currentPage;
        
        $.ajax({
            url: '/api/investigate/' + sourceId,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(currentSearchParams),
            success: function(response) {
                if (response.status === 'success') {
                    // Load data into DataTable
                    logsTable.clear();
                    
                    if (response.data.length > 0) {
                        logsTable.rows.add(response.data).draw();
                        
                        // Update pagination information
                        if (response.pagination) {
                            totalPages = response.pagination.total_pages;
                            updatePaginationControls(response.pagination);
                        }
                    } else {
                        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">No logs found for the selected time range.</td></tr>');
                        $('#paginationControls').hide();
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
                    alert('An error occurred while fetching logs.');
                }
                $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Error loading logs.</td></tr>');
                $('#paginationControls').hide();
            }
        });
    }

    // Function to update pagination controls
    function updatePaginationControls(pagination) {
        const total_pages = pagination.total_pages;
        const current_page = pagination.page;
        
        let paginationHtml = '<nav><ul class="pagination justify-content-center">';
        
        // Previous button
        paginationHtml += `<li class="page-item ${current_page === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${current_page - 1}">Previous</a>
        </li>`;
        
        // Page numbers
        const startPage = Math.max(1, current_page - 2);
        const endPage = Math.min(total_pages, startPage + 4);
        
        for (let i = startPage; i <= endPage; i++) {
            paginationHtml += `<li class="page-item ${i === current_page ? 'active' : ''}">
                <a class="page-link" href="#" data-page="${i}">${i}</a>
            </li>`;
        }
        
        // Next button
        paginationHtml += `<li class="page-item ${current_page === total_pages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${current_page + 1}">Next</a>
        </li>`;
        
        paginationHtml += '</ul></nav>';
        
        // Add summary text
        paginationHtml += `<div class="text-center text-muted mt-2">
            Showing page ${current_page} of ${total_pages}
            (${pagination.total_count} total logs)
        </div>`;
        
        // Update pagination controls
        $('#paginationControls').html(paginationHtml).show();
        
        // Add click handlers to pagination links
        $('.page-link').on('click', function(e) {
            e.preventDefault();
            const page = parseInt($(this).data('page'));
            
            if (page > 0 && page <= total_pages) {
                currentPage = page;
                fetchLogs($('#sourceSelect').val());
            }
        });
    }

    // Function to export logs
    function exportLogs() {
        const sourceId = $('#sourceSelect').val();
        const timeRange = $('#timeRange').data('daterangepicker');
        
        if (!sourceId) {
            alert('Please select a source to export');
            return;
        }
        
        const startTime = timeRange.startDate.format('YYYY-MM-DD HH:mm:ss');
        const endTime = timeRange.endDate.format('YYYY-MM-DD HH:mm:ss');
        
        // Create a form and submit it to download the CSV
        const form = $('<form></form>');
        form.attr('method', 'post');
        form.attr('action', '/api/export_logs');
        
        // Add CSRF token
        form.append($('<input></input>').attr('type', 'hidden').attr('name', 'csrf_token').attr('value', csrfToken));
        
        // Add source ID
        form.append($('<input></input>').attr('type', 'hidden').attr('name', 'source_id').attr('value', sourceId));
        
        // Add time range
        form.append($('<input></input>').attr('type', 'hidden').attr('name', 'start').attr('value', startTime));
        form.append($('<input></input>').attr('type', 'hidden').attr('name', 'end').attr('value', endTime));
        
        // Add to body, submit, and remove
        form.appendTo('body').submit().remove();
    }
});