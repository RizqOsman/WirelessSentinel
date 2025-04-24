/**
 * Main JavaScript file for the WiFi Security Scanner
 */

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Enable all tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Enable all popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Add alert dismissal functionality
    const alertList = document.querySelectorAll('.alert');
    alertList.forEach(function(alert) {
        const closeButton = alert.querySelector('.btn-close');
        if (closeButton) {
            closeButton.addEventListener('click', function() {
                alert.classList.add('fade');
                setTimeout(function() {
                    alert.remove();
                }, 150);
            });
        }
    });
    
    // Auto-close alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert:not(.alert-danger):not(.alert-warning)');
        alerts.forEach(function(alert) {
            alert.classList.add('fade');
            setTimeout(function() {
                alert.remove();
            }, 150);
        });
    }, 5000);
    
    // Format MAC addresses
    const macAddresses = document.querySelectorAll('.mac-address');
    macAddresses.forEach(function(element) {
        const mac = element.textContent;
        if (mac) {
            // Format as XX:XX:XX:XX:XX:XX
            const formatted = mac.replace(/([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})/, '$1:$2:$3:$4:$5:$6');
            element.textContent = formatted;
        }
    });
    
    // BSSID validation
    const bssidInput = document.getElementById('bssid');
    if (bssidInput) {
        bssidInput.addEventListener('blur', function() {
            let value = this.value.trim();
            
            // Check if it's a valid MAC address format
            const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
            if (!macRegex.test(value)) {
                // If it's not in correct format, try to format it
                value = value.replace(/[^0-9A-Fa-f]/g, '');
                if (value.length === 12) {
                    value = value.match(/.{1,2}/g).join(':');
                    this.value = value;
                } else {
                    // Invalid MAC address
                    this.classList.add('is-invalid');
                    return;
                }
            }
            
            this.classList.remove('is-invalid');
            this.classList.add('is-valid');
        });
    }
    
    // Add confirmation for brute force testing
    const bruteForceForm = document.querySelector('form[action*="brute-force"]');
    if (bruteForceForm) {
        bruteForceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const confirmation = confirm(
                "IMPORTANT: You should only perform brute force testing on networks you own or have explicit permission to test. " +
                "Unauthorized testing may be illegal. Do you confirm you have permission to test this network?"
            );
            
            if (confirmation) {
                this.submit();
            }
        });
    }
});

/**
 * Formats a dBm signal strength value into a human-readable format
 * @param {number} dbm - The signal strength in dBm (negative value)
 * @returns {string} - A human-readable signal strength description
 */
function formatSignalStrength(dbm) {
    if (dbm === null || dbm === undefined) return 'Unknown';
    
    if (dbm >= -50) return 'Excellent';
    if (dbm >= -60) return 'Good';
    if (dbm >= -70) return 'Fair';
    if (dbm >= -80) return 'Poor';
    return 'Very poor';
}

/**
 * Gets a color class based on security level
 * @param {string} level - The security level (High, Medium, Low)
 * @returns {string} - Bootstrap color class
 */
function getSecurityLevelColor(level) {
    switch (level) {
        case 'High':
            return 'success';
        case 'Medium':
            return 'warning';
        case 'Low':
            return 'danger';
        default:
            return 'secondary';
    }
}
