/**
 * SyslogManager - Investigation JavaScript
 * Handles client-side functionality for the log investigation.
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

    // Pagination variables
    let currentPage = 1;
    let totalPages = 1;
    let currentSearchParams = {};

    // Initialize DataTables
    const logsTable = $('#logsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']], // Sort by timestamp descending
        pageLength: 25,
        searching: true,
        lengthChange: true,
        columns: [
            { data: 'timestamp' },
            { data: 'source_ip' },
            { data: 'message' },
            { data: 'filename' }
        ],
        columnDefs: [
            {
                // Truncate message column and add click handler
                targets: 2,
                render: function(data, type, row) {
                    if (type === 'display') {
                        // Truncate to 100 characters for display
                        if (data.length > 100) {
                            return '<span class="truncated-message" title="Click to view full message">' + 
                                   data.substr(0, 100) + '...</span>';
                        }
                    }
                    return data;
                }
            }
        ],
        dom: '<"row"<"col-md-6"l><"col-md-6"f>>rtip',
        paging: false // We handle pagination separately
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

    // Check if a source ID was passed in the URL
    const urlParams = new URLSearchParams(window.location.search);
    const sourceId = urlParams.get('source');
    
    if (sourceId) {
        // Select the source in the dropdown
        $('#sourceSelect').val(sourceId);
        
        // If a valid source was selected, trigger search
        if ($('#sourceSelect').val() === sourceId) {
            // A slight delay to make sure everything is initialized
            setTimeout(() => {
                $('#investigateForm').submit();
            }, 500);
        }
    }

    // Handle investigate form submission
    $('#investigateForm').on('submit', function(e) {
        e.preventDefault();
        
        // Form validation
        if (this.checkValidity() === false) {
            e.stopPropagation();
            $(this).addClass('was-validated');
            return;
        }
        
        const sourceId = $('#sourceSelect').val();
        const timeRange = $('#timeRange').data('daterangepicker');
        const sourceName = $('#sourceSelect option:selected').text();
        
        const startTime = timeRange.startDate.format('YYYY-MM-DD HH:mm:ss');
        const endTime = timeRange.endDate.format('YYYY-MM-DD HH:mm:ss');
        
        // Update UI
        $('#currentSourceName').text(sourceName);
        $('#currentTimeRange').text(startTime + ' to ' + endTime);
        $('#noSourceSelected').hide();
        $('#logsContainer').show();
        
        // Save search parameters for pagination
        currentSearchParams = {
            start: startTime,
            end: endTime,
            page: 1,  // Reset to first page for new searches
            page_size: 25  // Match the DataTable page size
        };
        
        // Reset pagination
        currentPage = 1;
        
        // Show loading indicator
        logsTable.clear().draw();
        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Loading logs...</td></tr>');
        $('#paginationControls').hide();
        
        // Fetch logs
        fetchLogs();
    });
    
    // Handle log message click to show details
    $('#logsTable tbody').on('click', '.truncated-message', function() {
        const tr = $(this).closest('tr');
        const row = logsTable.row(tr).data();
        
        // Populate and show modal
        $('#detailTimestamp').text(moment(row.timestamp).format('YYYY-MM-DD HH:mm:ss'));
        $('#detailSourceIP').text(row.source_ip);
        $('#detailMessage').text(row.message);
        $('#detailFilename').text(row.filename);
        
        $('#logDetailsModal').modal('show');
    });
    
    // Handle export logs button click
    $('#exportLogsBtn').on('click', function() {
        const sourceId = $('#sourceSelect').val();
        const sourceName = $('#sourceSelect option:selected').text();
        const timeRange = $('#timeRange').data('daterangepicker');
        
        // Get current search parameters
        const exportParams = {
            source_id: sourceId,
            start: timeRange.startDate.format('YYYY-MM-DD HH:mm:ss'),
            end: timeRange.endDate.format('YYYY-MM-DD HH:mm:ss'),
            export: true
        };
        
        // Create form and submit it for download
        const form = $('<form></form>')
            .attr('method', 'post')
            .attr('action', '/api/export_logs');
        
        // Add CSRF token
        $('<input>')
            .attr('type', 'hidden')
            .attr('name', 'csrf_token')
            .attr('value', csrfToken)
            .appendTo(form);
        
        // Add parameters
        for (const key in exportParams) {
            $('<input>')
                .attr('type', 'hidden')
                .attr('name', key)
                .attr('value', exportParams[key])
                .appendTo(form);
        }
        
        // Submit form
        form.appendTo('body').submit().remove();
    });

    // Function to fetch logs with pagination
    function fetchLogs() {
        const sourceId = $('#sourceSelect').val();
        
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
        const totalPages = pagination.total_pages;
        const currentPage = pagination.page;
        
        let paginationHtml = '<nav><ul class="pagination justify-content-center">';
        
        // Previous button
        paginationHtml += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${currentPage - 1}">Previous</a>
        </li>`;
        
        // Page numbers
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, startPage + 4);
        
        for (let i = startPage; i <= endPage; i++) {
            paginationHtml += `<li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" data-page="${i}">${i}</a>
            </li>`;
        }
        
        // Next button
        paginationHtml += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${currentPage + 1}">Next</a>
        </li>`;
        
        paginationHtml += '</ul></nav>';
        
        // Add summary text
        paginationHtml += `<div class="text-center text-muted mt-2">
            Showing page ${currentPage} of ${totalPages}
            (${pagination.total_count} total logs)
        </div>`;
        
        // Update pagination controls
        $('#paginationControls').html(paginationHtml).show();
        
        // Add click handlers to pagination links
        $('.page-link').on('click', function(e) {
            e.preventDefault();
            const page = parseInt($(this).data('page'));
            
            if (page > 0 && page <= totalPages) {
                currentPage = page;
                fetchLogs();
                
                // Scroll to top of table
                $('html, body').animate({
                    scrollTop: $('#logsTable').offset().top - 20
                }, 200);
            }
        });
    }
});