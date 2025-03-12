/**
 * SyslogManager - Investigation JavaScript
 * Handles client-side functionality for the log investigation.
 */

$(document).ready(function() {
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
    
    // Set source if provided in URL
    const urlParams = new URLSearchParams(window.location.search);
    const sourceParam = urlParams.get('source');
    if (sourceParam) {
        $('#sourceSelect').val(sourceParam);
    }
    
    // Initialize DataTables with explicit column definitions
    const logsTable = $('#logsTable').DataTable({
        responsive: true,
        ordering: true,
        searching: true,
        paging: false, // We're handling pagination manually
        columns: [
            { data: 'timestamp', title: 'Timestamp' },
            { data: 'source_ip', title: 'Source IP' },
            { data: 'message', title: 'Message' },
            { data: 'filename', title: 'Filename' }
        ],
        order: [[0, 'desc']] // Sort by timestamp descending
    });
    
    // Handle form submission
    $('#investigateForm').on('submit', function(e) {
        e.preventDefault();
        
        // Validate form
        if (!$('#sourceSelect').val()) {
            alert('Please select a source to investigate.');
            return;
        }
        
        // Get source ID and time range
        const sourceId = $('#sourceSelect').val();
        const sourceName = $('#sourceSelect option:selected').text();
        const timeRange = $('#timeRange').data('daterangepicker');
        const startTime = timeRange.startDate.format('YYYY-MM-DD HH:mm:ss');
        const endTime = timeRange.endDate.format('YYYY-MM-DD HH:mm:ss');
        
        // Update UI
        $('#currentSourceName').text(sourceName);
        $('#currentTimeRange').text(startTime + ' to ' + endTime);
        
        // Show loading indicator
        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></td></tr>');
        $('#logsContainer').show();
        $('#noSourceSelected').hide();
        
        // Store search parameters for pagination
        window.currentSearchParams = {
            source_id: sourceId,
            start: startTime,
            end: endTime,
            page: 1,
            page_size: 25
        };
        
        // Fetch logs
        fetchLogs();
    });
    
    // Handle log row click to show details
    $('#logsTable tbody').on('click', 'tr', function() {
        const data = logsTable.row(this).data();
        if (data) {
            // Populate modal
            $('#detailTimestamp').text(data.timestamp);
            $('#detailSourceIP').text(data.source_ip);
            $('#detailMessage').text(data.message);
            $('#detailFilename').text(data.filename);
            
            // Show modal
            $('#logDetailsModal').modal('show');
        }
    });
    
    // Handle pagination click
    $(document).on('click', '.page-link', function(e) {
        e.preventDefault();
        
        const page = parseInt($(this).data('page'));
        if (page > 0 && page <= window.totalPages) {
            window.currentSearchParams.page = page;
            fetchLogs();
        }
    });
    
    // Handle export button click
    $('#exportLogsBtn').on('click', function() {
        if (!window.currentSearchParams) {
            alert('Please search for logs first.');
            return;
        }
        
        // Create form for export
        const form = $('<form></form>')
            .attr('method', 'post')
            .attr('action', '/api/export_logs');
        
        // Add CSRF token
        $('<input>')
            .attr('type', 'hidden')
            .attr('name', 'csrf_token')
            .attr('value', $('meta[name="csrf-token"]').attr('content'))
            .appendTo(form);
        
        // Add parameters
        $('<input>')
            .attr('type', 'hidden')
            .attr('name', 'source_id')
            .attr('value', window.currentSearchParams.source_id)
            .appendTo(form);
        
        $('<input>')
            .attr('type', 'hidden')
            .attr('name', 'start')
            .attr('value', window.currentSearchParams.start)
            .appendTo(form);
        
        $('<input>')
            .attr('type', 'hidden')
            .attr('name', 'end')
            .attr('value', window.currentSearchParams.end)
            .appendTo(form);
        
        // Append form to body and submit
        form.appendTo('body').submit().remove();
    });
    
    // Function to fetch logs with pagination
    function fetchLogs() {
        const params = window.currentSearchParams;
        
        if (!params) {
            return;
        }
        
        $.ajax({
            url: '/api/investigate/' + params.source_id,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                start: params.start,
                end: params.end,
                page: params.page,
                page_size: params.page_size
            }),
            success: function(response) {
                if (response.status === 'success') {
                    // Clear existing data
                    logsTable.clear();
                    
                    if (response.data && response.data.length > 0) {
                        // Add data and draw
                        logsTable.rows.add(response.data).draw();
                        
                        // Update pagination
                        if (response.pagination) {
                            window.totalPages = response.pagination.total_pages;
                            updatePaginationControls(response.pagination);
                        }
                    } else {
                        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">No logs found for the selected time range.</td></tr>');
                        $('#paginationControls').hide();
                    }
                } else {
                    $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Error: ' + response.message + '</td></tr>');
                    $('#paginationControls').hide();
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Error: ' + response.message + '</td></tr>');
                } catch (e) {
                    $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">An error occurred while fetching logs.</td></tr>');
                }
                $('#paginationControls').hide();
            }
        });
    }
    
    // Function to update pagination controls
    function updatePaginationControls(pagination) {
        const totalPages = pagination.total_pages;
        const currentPage = pagination.page;
        
        if (totalPages <= 1) {
            $('#paginationControls').hide();
            return;
        }
        
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