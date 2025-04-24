/**
 * Chart.js implementation for network security visualization
 */

/**
 * Updates the charts with new network data
 * @param {Array} networks - Array of network objects
 */
function updateCharts(networks) {
    if (!networks || networks.length === 0) {
        return;
    }
    
    updateSecurityChart(networks);
    updateEncryptionChart(networks);
}

/**
 * Updates the security type distribution chart
 * @param {Array} networks - Array of network objects
 */
function updateSecurityChart(networks) {
    const securityCtx = document.getElementById('security-chart');
    if (!securityCtx) return;
    
    // Collect security types
    const securityTypes = {};
    networks.forEach(network => {
        const security = network.security || 'Unknown';
        securityTypes[security] = (securityTypes[security] || 0) + 1;
    });
    
    // Prepare data for the chart
    const labels = Object.keys(securityTypes);
    const data = Object.values(securityTypes);
    
    // Define colors based on security level
    const backgroundColors = labels.map(label => {
        if (label === 'WPA3') return 'rgba(40, 167, 69, 0.7)';  // green
        if (label === 'WPA2') return 'rgba(0, 123, 255, 0.7)';  // blue
        if (label === 'WPA') return 'rgba(255, 193, 7, 0.7)';   // yellow
        if (label === 'WEP') return 'rgba(220, 53, 69, 0.7)';   // red
        if (label === 'Open') return 'rgba(108, 117, 125, 0.7)'; // gray
        return 'rgba(23, 162, 184, 0.7)';  // info color for others
    });
    
    // Create or update the chart
    if (window.securityChart) {
        window.securityChart.data.labels = labels;
        window.securityChart.data.datasets[0].data = data;
        window.securityChart.data.datasets[0].backgroundColor = backgroundColors;
        window.securityChart.update();
    } else {
        window.securityChart = new Chart(securityCtx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: backgroundColors,
                    borderColor: backgroundColors.map(color => color.replace('0.7', '1')),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Security Types Distribution',
                        color: '#fff'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
}

/**
 * Updates the encryption type distribution chart
 * @param {Array} networks - Array of network objects
 */
function updateEncryptionChart(networks) {
    const encryptionCtx = document.getElementById('encryption-chart');
    if (!encryptionCtx) return;
    
    // Collect security levels
    const securityLevels = {
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Unknown': 0
    };
    
    networks.forEach(network => {
        const level = network.security_level || 'Unknown';
        securityLevels[level] = (securityLevels[level] || 0) + 1;
    });
    
    // Prepare data for the chart
    const labels = Object.keys(securityLevels);
    const data = Object.values(securityLevels);
    
    // Define colors based on security level
    const backgroundColors = {
        'High': 'rgba(40, 167, 69, 0.7)',    // green
        'Medium': 'rgba(255, 193, 7, 0.7)',  // yellow
        'Low': 'rgba(220, 53, 69, 0.7)',     // red
        'Unknown': 'rgba(108, 117, 125, 0.7)' // gray
    };
    
    const colors = labels.map(label => backgroundColors[label] || 'rgba(23, 162, 184, 0.7)');
    
    // Create or update the chart
    if (window.encryptionChart) {
        window.encryptionChart.data.labels = labels;
        window.encryptionChart.data.datasets[0].data = data;
        window.encryptionChart.data.datasets[0].backgroundColor = colors;
        window.encryptionChart.update();
    } else {
        window.encryptionChart = new Chart(encryptionCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderColor: colors.map(color => color.replace('0.7', '1')),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Security Level Distribution',
                        color: '#fff'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
}
