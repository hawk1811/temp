/**
 * SyslogManager - Sources JavaScript
 * Handles client-side functionality for the sources management.
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
    const sourcesTable = $('#sourcesTable').DataTable({
        responsive: true,
        order: [[0, 'asc']], // Sort by source name
        columnDefs: [
            { targets: 1, orderable: false }, // Source IPs column
            { targets: 5, orderable: false }  // Actions column
        ]
    });

    // Format timestamps and check for inactive sources
    formatTimestamps();

    // Handle target type change
    $('#targetType').on('change', function() {
        const targetType = $(this).val();
        
        // Show/hide appropriate settings based on target type
        if (targetType === 'folder') {
            $('#folderSettings').show();
            $('#hecSettings').hide();
        } else if (targetType === 'hec') {
            $('#folderSettings').hide();
            $('#hecSettings').show();
        }
    });

    // Handle source form submission
    $('#saveSourceBtn').on('click', function() {
        const targetType = $('#targetType').val();
        
		// Base source data
		const sourceData = {
			id: $('#sourceId').val(),
			name: $('#sourceName').val(),
			target_type: targetType,
			protocol: $('#sourceProtocol').val(),
			port: parseInt($('#sourcePort').val(), 10),
			source_ips: JSON.parse($('#sourceIPsHidden').val() || '[]')
		};

        // Add target-specific data
        if (targetType === 'folder') {
            sourceData.target_directory = $('#targetDirectory').val();
        } else if (targetType === 'hec') {
            sourceData.hec_url = $('#hecUrl').val();
            sourceData.hec_token = $('#hecToken').val();
        }

        // Validate form
        if (!sourceData.name) {
            alert('Source name is required');
            return;
        }
        
        if (targetType === 'folder' && !sourceData.target_directory) {
            alert('Target directory is required');
            return;
        }
        
        if (targetType === 'hec' && (!sourceData.hec_url || !sourceData.hec_token)) {
            alert('HEC URL and token are required');
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
					
					// Set target type and show appropriate settings
					const targetType = source.target_type || 'folder';
					$('#targetType').val(targetType);
					
					if (targetType === 'hec') {
						$('#folderSettings').hide();
						$('#hecSettings').show();
						$('#hecUrl').val(source.hec_url || '');
						$('#hecToken').val(source.hec_token || '');
					} else {
						$('#folderSettings').show();
						$('#hecSettings').hide();
						$('#targetDirectory').val(source.target_directory || '');
					}
					
					// Add source IPs
					if (source.source_ips && Array.isArray(source.source_ips)) {
						source.source_ips.forEach(function(ip) {
							addSourceIP(ip);
						});
					}
					
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
        
        // Redirect to investigation page with source preselected
        window.location.href = '/investigation?source=' + sourceId;
    });

    // Handle add source modal show
    $('#addSourceModal').on('show.bs.modal', function(e) {
        // If not triggered by edit button, reset the form
        if (!$(e.relatedTarget).hasClass('edit-source-btn')) {
            resetSourceForm();
            $('#addSourceModalLabel').text('Add Syslog Source');
        }
    });

    // Auto-refresh sources every 60 seconds
    setInterval(function() {
        refreshSources();
    }, 60000);

    // Helper functions
    function resetSourceForm() {
        $('#sourceForm')[0].reset();
        $('#sourceId').val('');
        $('.source-ips-list').empty();
        $('#sourceIPsHidden').val('[]');
        $('#folderSettings').show();
        $('#hecSettings').hide();
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

    function refreshSources() {
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
        // Clear table
        sourcesTable.clear();
        
        // Add sources to table
        Object.entries(sources).forEach(([sourceId, source]) => {
            const sourceIPs = source.source_ips.map(ip => 
                '<span class="badge bg-secondary">' + ip + '</span>'
            ).join(' ');
            
            // Determine target type badge and details
            let targetTypeBadge = '';
            let targetDetails = '';
            
            if (source.target_type === 'hec') {
                targetTypeBadge = '<span class="badge bg-info">HEC</span>';
                targetDetails = '<span class="text-muted">HEC Endpoint</span>';
            } else {
                targetTypeBadge = '<span class="badge bg-success">Folder</span>';
                targetDetails = source.target_directory;
            }
            
            // Format last log time and add warning if inactive
            let lastLogTime = 'No logs yet';
            if (source.last_log_time) {
                const momentTime = moment(source.last_log_time);
                const hoursSince = moment().diff(momentTime, 'hours');
                
                let warningIcon = '';
                if (hoursSince > 5) {
                    warningIcon = '<i class="bi bi-exclamation-triangle-fill text-warning me-2" title="Inactive for ' + hoursSince + ' hours"></i>';
                }
                
                lastLogTime = 
                    '<div class="d-flex align-items-center">' +
                    warningIcon +
                    '<span class="last-log-time" data-timestamp="' + source.last_log_time + '">' +
                    momentTime.format('YYYY-MM-DD HH:mm:ss') + '</span></div>';
            }
            
            // Create action buttons
            let actions = '<div class="btn-group" role="group">';
            
            // Add investigate button only for folder-type sources
            if (source.target_type !== 'hec') {
                actions += '<button type="button" class="btn btn-sm btn-primary investigate-btn" ' +
                        'data-source-id="' + sourceId + '" data-source-name="' + source.name + '">' +
                        'Investigate</button>';
            }
            
            // Add edit and delete buttons for all sources
            actions += '<button type="button" class="btn btn-sm btn-warning edit-source-btn" ' +
                    'data-source-id="' + sourceId + '">' +
                    'Edit</button>' +
                    '<button type="button" class="btn btn-sm btn-danger delete-source-btn" ' +
                    'data-source-id="' + sourceId + '" data-source-name="' + source.name + '">' +
                    'Delete</button>' +
                    '</div>';
            
            // Add row to table
            sourcesTable.row.add([
                source.name,
                sourceIPs,
                targetTypeBadge,
                targetDetails,
                lastLogTime,
                actions
            ]);
        });
        
        // Redraw table
        sourcesTable.draw();
        
        // Format timestamps
        formatTimestamps();
    }
});