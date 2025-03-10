/**
 * SyslogManager - Main JavaScript
 * Handles client-side functionality for the SyslogManager application.
 */

// Add pagination variables
let currentPage = 1;
let totalPages = 1;
let currentSearchParams = {};

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
    const sourcesTable = $('#sourcesTable').DataTable({
        responsive: true,
        order: [[0, 'asc']], // Sort by source name
        columnDefs: [
            { targets: 1, orderable: false }, // Source IPs column
            { targets: 5, orderable: false }  // Actions column
        ]
    });

    const logsTable = $('#logsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']], // Sort by timestamp descending
        pageLength: 25,
        columns: [
            { data: 'timestamp' },
            { data: 'source_ip' },
            { data: 'message' },
            { data: 'filename' }
        ]
    });

    // Format timestamps
    formatTimestamps();

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

    // Handle source form submission
    $('#saveSourceBtn').on('click', function() {
        const sourceData = {
            id: $('#sourceId').val(),
            name: $('#sourceName').val(),
            target_directory: $('#targetDirectory').val(),
            source_ips: JSON.parse($('#sourceIPsHidden').val() || '[]')
        };

        // Validate form
        if (!sourceData.name) {
            alert('Source name is required');
            return;
        }
        if (!sourceData.target_directory) {
            alert('Target directory is required');
            return;
        }
        if (sourceData.source_ips.length === 0) {
            alert('At least one source IP/network is required');
            return;
        }

        // Show loading indicator
        $('#saveSourceBtn').html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...');
        $('#saveSourceBtn').prop('disabled', true);

        // Save source
        $.ajax({
            url: '/api/sources',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(sourceData),
            success: function(response) {
                if (response.status === 'success') {
                    // Close modal and reload page
                    $('#addSourceModal').modal('hide');
                    location.reload();
                } else {
                    // Show error message
                    alert('Error: ' + response.message);
                    // Reset button state
                    $('#saveSourceBtn').html('Save');
                    $('#saveSourceBtn').prop('disabled', false);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    console.error('Error response:', xhr.responseText);
                    alert('An error occurred while saving the source. Check the browser console and server logs for details.');
                }
                // Reset button state
                $('#saveSourceBtn').html('Save');
                $('#saveSourceBtn').prop('disabled', false);
            }
        });
    });

    // Handle add IP button click
    $('.add-ip-btn').on('click', function() {
        const ipInput = $('.source-ip-input');
        const ipValue = ipInput.val().trim();
        
        if (ipValue) {
            addSourceIP(ipValue);
            ipInput.val('');
        }
    });

    // Handle source IP input enter key
    $('.source-ip-input').on('keypress', function(e) {
        if (e.which === 13) {
            e.preventDefault();
            const ipValue = $(this).val().trim();
            
            if (ipValue) {
                addSourceIP(ipValue);
                $(this).val('');
            }
        }
    });

    // Handle remove IP button click (delegated)
    $(document).on('click', '.remove-ip-btn', function() {
        const ip = $(this).data('ip');
        removeSourceIP(ip);
    });

    // Handle edit source button click
    $(document).on('click', '.edit-source-btn', function() {
        const sourceId = $(this).data('source-id');
        
        // Fetch source data
        $.ajax({
            url: '/api/sources/' + sourceId,
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    const source = response.source;
                    
                    // Reset form
                    resetSourceForm();
                    
                    // Populate form
                    $('#sourceId').val(sourceId);
                    $('#sourceName').val(source.name);
                    $('#targetDirectory').val(source.target_directory);
                    
                    // Add source IPs
                    source.source_ips.forEach(function(ip) {
                        addSourceIP(ip);
                    });
                    
                    // Update modal title and show
                    $('#addSourceModalLabel').text('Edit Syslog Source');
                    $('#addSourceModal').modal('show');
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while fetching the source data.');
                }
            }
        });
    });

    // Handle delete source button click
    $(document).on('click', '.delete-source-btn', function() {
        const sourceId = $(this).data('source-id');
        const sourceName = $(this).data('source-name');
        
        $('#deleteSourceName').text(sourceName);
        $('#confirmDeleteBtn').data('source-id', sourceId);
        $('#deleteConfirmModal').modal('show');
    });

    // Handle delete confirmation
    $('#confirmDeleteBtn').on('click', function() {
        const sourceId = $(this).data('source-id');
        
        $.ajax({
            url: '/api/sources/' + sourceId,
            type: 'DELETE',
            success: function(response) {
                if (response.status === 'success') {
                    // Close modal and reload page
                    $('#deleteConfirmModal').modal('hide');
                    location.reload();
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while deleting the source.');
                }
            }
        });
    });

    // Handle investigate button click
    $(document).on('click', '.investigate-btn', function() {
        const sourceId = $(this).data('source-id');
        const sourceName = $(this).data('source-name');
        
        // Reset and prepare the investigation modal
        $('#investigateModalLabel').text('Investigate Logs: ' + sourceName);
        $('#investigateSourceId').val(sourceId);
        logsTable.clear().draw();
        
        // Show modal
        $('#investigateModal').modal('show');
    });

    // Handle investigate form submission
	

	$('#investigateForm').on('submit', function(e) {
		e.preventDefault();
		
		const sourceId = $('#investigateSourceId').val();
		const timeRange = $('#timeRange').data('daterangepicker');
		
		const startTime = timeRange.startDate.format('YYYY-MM-DD HH:mm:ss');
		const endTime = timeRange.endDate.format('YYYY-MM-DD HH:mm:ss');
		
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

function fetchLogs() {
    const sourceId = $('#investigateSourceId').val();
    
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

	function fetchLogs() {
		const sourceId = $('#investigateSourceId').val();
		
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
			}
		});
	}

    // Handle add source modal show
    $('#addSourceModal').on('show.bs.modal', function(e) {
        // If not triggered by edit button, reset the form
        if (!$(e.relatedTarget).hasClass('edit-source-btn')) {
            resetSourceForm();
            $('#addSourceModalLabel').text('Add Syslog Source');
        }
    });

    // Click handler for log message expansion
    $('#logsTable tbody').on('click', 'td:nth-child(3)', function() {
        const td = $(this);
        if (td.hasClass('expanded-message')) {
            // Collapse
            td.removeClass('expanded-message');
            td.css('white-space', 'nowrap');
        } else {
            // Expand
            td.addClass('expanded-message');
            td.css('white-space', 'pre-wrap');
        }
    });

    // Auto-refresh dashboard every 60 seconds
    setInterval(function() {
        refreshSourceStats();
    }, 60000);

    // Helper functions
    function resetSourceForm() {
        $('#sourceForm')[0].reset();
        $('#sourceId').val('');
        $('.source-ips-list').empty();
        $('#sourceIPsHidden').val('[]');
    }

    function addSourceIP(ip) {
        const currentIPs = JSON.parse($('#sourceIPsHidden').val() || '[]');
        
        // Check if IP already exists
        if (currentIPs.includes(ip)) {
            return;
        }
        
        // Add to hidden input
        currentIPs.push(ip);
        $('#sourceIPsHidden').val(JSON.stringify(currentIPs));
        
        // Add to visual list
        const badge = $('<span class="source-ip-badge"></span>')
            .text(ip)
            .append('<button type="button" class="remove-ip-btn" data-ip="' + ip + '">&times;</button>');
        
        $('.source-ips-list').append(badge);
    }

    function removeSourceIP(ip) {
        const currentIPs = JSON.parse($('#sourceIPsHidden').val() || '[]');
        const index = currentIPs.indexOf(ip);
        
        if (index !== -1) {
            // Remove from hidden input
            currentIPs.splice(index, 1);
            $('#sourceIPsHidden').val(JSON.stringify(currentIPs));
            
            // Remove from visual list
            $('.source-ips-list .source-ip-badge').each(function() {
                const badge = $(this);
                if (badge.text().replace('×', '').trim() === ip) {
                    badge.remove();
                }
            });
        }
    }

    function formatTimestamps() {
        $('.last-log-time').each(function() {
            const timestamp = $(this).data('timestamp');
            if (timestamp) {
                $(this).text(moment(timestamp).format('YYYY-MM-DD HH:mm:ss'));
            }
        });
    }

    function refreshSourceStats() {
        $.ajax({
            url: '/api/sources',
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    updateSourceTable(response.sources);
                }
            }
        });
    }

    function updateSourceTable(sources) {
        sourcesTable.clear();
        
        Object.entries(sources).forEach(([sourceId, source]) => {
            const sourceIPs = source.source_ips.map(ip => 
                '<span class="badge bg-secondary">' + ip + '</span>'
            ).join(' ');
            
            const lastLogTime = source.last_log_time ? 
                '<span class="last-log-time" data-timestamp="' + source.last_log_time + '">' +
                moment(source.last_log_time).format('YYYY-MM-DD HH:mm:ss') + '</span>' :
                'No logs yet';
            
            const actions = 
                '<div class="btn-group" role="group">' +
                    '<button type="button" class="btn btn-sm btn-primary investigate-btn" ' +
                    'data-source-id="' + sourceId + '" data-source-name="' + source.name + '">' +
                    'Investigate</button>' +
                    '<button type="button" class="btn btn-sm btn-warning edit-source-btn" ' +
                    'data-source-id="' + sourceId + '">' +
                    'Edit</button>' +
                    '<button type="button" class="btn btn-sm btn-danger delete-source-btn" ' +
                    'data-source-id="' + sourceId + '" data-source-name="' + source.name + '">' +
                    'Delete</button>' +
                '</div>';
            
            sourcesTable.row.add([
                source.name,
                sourceIPs,
                source.target_directory,
                source.log_count,
                lastLogTime,
                actions
            ]);
        });
        
        sourcesTable.draw();
    }

	// System performance monitoring
	if ($('#cpuUsage').length > 0) {
		// Initial load
		updateSystemStats();
		
		// Set up periodic refresh (every 5 seconds)
		setInterval(updateSystemStats, 5000);
		
		// Manual refresh button
		$('#refreshStatsBtn').on('click', function() {
			updateSystemStats();
		});
	}

	// Function to update system stats
	function updateSystemStats() {
		$.ajax({
			url: '/api/system_stats',
			type: 'GET',
			success: function(response) {
				if (response.status === 'success') {
					const stats = response.stats;
					
					// Update CPU usage
					$('#cpuUsage').text(stats.cpu_percent.toFixed(1) + '%');
					$('#cpuProgressBar').css('width', stats.cpu_percent + '%');
					updateProgressBarColor($('#cpuProgressBar'), stats.cpu_percent);
					
					// Update memory usage
					$('#memoryUsage').text(stats.memory_percent.toFixed(1) + '%');
					$('#memoryProgressBar').css('width', stats.memory_percent + '%');
					updateProgressBarColor($('#memoryProgressBar'), stats.memory_percent);
					
					// Update worker utilization
					const workerUtil = stats.worker_stats.utilization;
					$('#workerUtilization').text(
						stats.worker_stats.active_workers + '/' + 
						stats.worker_stats.max_workers + 
						' (' + workerUtil.toFixed(1) + '%)'
					);
					$('#workerProgressBar').css('width', workerUtil + '%');
					updateProgressBarColor($('#workerProgressBar'), workerUtil);
					
					// Update logs rate
					$('#logsRate').text(stats.logs_rate.toFixed(1) + ' logs/sec');
					$('#queueStatus').text('Queue: ' + stats.queue_stats.size + 
										(stats.queue_stats.is_full ? ' (FULL)' : ''));
					
					if (stats.queue_stats.is_full) {
						$('#queueStatus').addClass('text-danger');
					} else {
						$('#queueStatus').removeClass('text-danger');
					}
				}
			}
		});
	}

	// Function to update progress bar color based on value
	function updateProgressBarColor(progressBar, value) {
		if (value < 50) {
			progressBar.removeClass('bg-warning bg-danger').addClass('bg-success');
		} else if (value < 80) {
			progressBar.removeClass('bg-success bg-danger').addClass('bg-warning');
		} else {
			progressBar.removeClass('bg-success bg-warning').addClass('bg-danger');
		}
	}

});