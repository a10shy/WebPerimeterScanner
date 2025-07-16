class SecurityDashboard {
    constructor(assessmentId, data) {
        this.assessmentId = assessmentId;
        this.data = data;
        this.charts = {};
    }
    
    initialize() {
        this.renderCharts();
        this.renderVulnerabilities();
        this.renderMisconfigurations();
        this.renderNetworkInfo();
        this.renderTechnologyStack();
        this.renderRecommendations();
        
        // Initialize feather icons
        feather.replace();
    }
    
    renderCharts() {
        this.renderScoreChart();
        this.renderRiskChart();
    }
    
    renderScoreChart() {
        const ctx = document.getElementById('scoreChart');
        if (!ctx) return;
        
        // Create sample security score breakdown
        const scoreData = {
            'Network Security': 85,
            'Web Security': 70,
            'Email Security': 90,
            'DNS Security': 95,
            'SSL/TLS': 80,
            'Configuration': 60,
            'Vulnerability Mgmt': 75,
            'Data Protection': 65
        };
        
        this.charts.scoreChart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: Object.keys(scoreData),
                datasets: [{
                    label: 'Security Score',
                    data: Object.values(scoreData),
                    backgroundColor: 'rgba(13, 110, 253, 0.2)',
                    borderColor: 'rgba(13, 110, 253, 1)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgba(13, 110, 253, 1)',
                    pointBorderColor: '#fff',
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            stepSize: 20,
                            color: '#6c757d'
                        },
                        grid: {
                            color: '#495057'
                        },
                        angleLines: {
                            color: '#495057'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#fff'
                        }
                    }
                }
            }
        });
    }
    
    renderRiskChart() {
        const ctx = document.getElementById('riskChart');
        if (!ctx) return;
        
        // Extract risk categories from assessment data
        let riskData = {
            'Data Breach': 25,
            'Compliance': 40,
            'Reputation': 35,
            'Operational': 30
        };
        
        // Try to get actual risk data from assessment
        if (this.data.phases && this.data.phases.risk_assessment) {
            const riskAssessment = this.data.phases.risk_assessment;
            if (riskAssessment.risk_categories) {
                riskData = riskAssessment.risk_categories;
            }
        }
        
        this.charts.riskChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(riskData),
                datasets: [{
                    label: 'Risk Level (%)',
                    data: Object.values(riskData),
                    backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(13, 110, 253, 0.8)',
                        'rgba(25, 135, 84, 0.8)'
                    ],
                    borderColor: [
                        'rgba(220, 53, 69, 1)',
                        'rgba(255, 193, 7, 1)',
                        'rgba(13, 110, 253, 1)',
                        'rgba(25, 135, 84, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            color: '#6c757d'
                        },
                        grid: {
                            color: '#495057'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#6c757d'
                        },
                        grid: {
                            color: '#495057'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#fff'
                        }
                    }
                }
            }
        });
    }
    
    renderVulnerabilities() {
        const container = document.getElementById('vulnerabilities-container');
        if (!container) return;
        
        let vulnerabilities = [];
        
        // Collect vulnerabilities from different phases
        if (this.data.phases) {
            // From vulnerability scan
            if (this.data.phases.vulnerability_scan && this.data.phases.vulnerability_scan.vulnerabilities) {
                vulnerabilities = vulnerabilities.concat(this.data.phases.vulnerability_scan.vulnerabilities);
            }
            
            // From nuclei scan
            if (this.data.phases.nuclei_scan && this.data.phases.nuclei_scan.vulnerabilities) {
                vulnerabilities = vulnerabilities.concat(this.data.phases.nuclei_scan.vulnerabilities);
            }
        }
        
        if (vulnerabilities.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i data-feather="check-circle" class="mb-2" style="width: 32px; height: 32px;"></i>
                    <p class="mb-0">No vulnerabilities detected</p>
                </div>
            `;
        } else {
            container.innerHTML = vulnerabilities.map(vuln => `
                <div class="vulnerability-item mb-3 ${this.getVulnerabilitySeverity(vuln)}">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h6 class="mb-0">${vuln.type || 'Unknown Vulnerability'}</h6>
                        <span class="badge ${this.getSeverityBadgeClass(vuln)}">
                            ${this.getVulnerabilitySeverity(vuln).toUpperCase()}
                        </span>
                    </div>
                    <p class="mb-1 small">${vuln.description || 'No description available'}</p>
                    ${vuln.url ? `<div class="small text-muted"><strong>URL:</strong> ${vuln.url}</div>` : ''}
                    ${vuln.status_code ? `<div class="small text-muted"><strong>Status:</strong> ${vuln.status_code}</div>` : ''}
                </div>
            `).join('');
        }
        
        feather.replace();
    }
    
    renderMisconfigurations() {
        const container = document.getElementById('misconfigurations-container');
        if (!container) return;
        
        let misconfigurations = [];
        
        if (this.data.phases && this.data.phases.misconfiguration_detection) {
            misconfigurations = this.data.phases.misconfiguration_detection.misconfigurations || [];
        }
        
        if (misconfigurations.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i data-feather="check-circle" class="mb-2" style="width: 32px; height: 32px;"></i>
                    <p class="mb-0">No misconfigurations detected</p>
                </div>
            `;
        } else {
            container.innerHTML = misconfigurations.map(config => `
                <div class="mb-3 p-3 border rounded">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h6 class="mb-0">${config.type || 'Configuration Issue'}</h6>
                        <span class="badge bg-warning">Warning</span>
                    </div>
                    <p class="mb-1 small">${config.description || 'No description available'}</p>
                    ${config.domain ? `<div class="small text-muted"><strong>Domain:</strong> ${config.domain}</div>` : ''}
                    ${config.header ? `<div class="small text-muted"><strong>Header:</strong> ${config.header}</div>` : ''}
                </div>
            `).join('');
        }
        
        feather.replace();
    }
    
    renderNetworkInfo() {
        const container = document.getElementById('network-info-container');
        if (!container) return;
        
        let networkData = {};
        
        if (this.data.phases) {
            if (this.data.phases.ip_identification) {
                networkData.ips = this.data.phases.ip_identification.ips || [];
            }
            if (this.data.phases.network_security) {
                networkData.openPorts = this.data.phases.network_security.open_ports || {};
                networkData.sslInfo = this.data.phases.network_security.ssl_info || {};
            }
        }
        
        let html = '';
        
        // IP Addresses
        if (networkData.ips && networkData.ips.length > 0) {
            html += `
                <div class="mb-4">
                    <h6><i data-feather="server" class="me-2"></i>IP Addresses</h6>
                    <div class="row">
                        ${networkData.ips.slice(0, 6).map(ipData => `
                            <div class="col-md-6 mb-2">
                                <div class="border rounded p-2 small">
                                    <strong>${ipData.domain || 'N/A'}</strong><br>
                                    <code>${ipData.ip || 'N/A'}</code>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        // Open Ports
        if (networkData.openPorts && Object.keys(networkData.openPorts).length > 0) {
            html += `
                <div class="mb-4">
                    <h6><i data-feather="wifi" class="me-2"></i>Open Ports</h6>
                    ${Object.entries(networkData.openPorts).map(([ip, ports]) => `
                        <div class="mb-2 p-2 border rounded small">
                            <strong>${ip}:</strong> ${ports.join(', ')}
                        </div>
                    `).join('')}
                </div>
            `;
        }
        
        // SSL Information
        if (networkData.sslInfo && Object.keys(networkData.sslInfo).length > 0) {
            html += `
                <div class="mb-4">
                    <h6><i data-feather="lock" class="me-2"></i>SSL/TLS Information</h6>
                    ${Object.entries(networkData.sslInfo).map(([domain, ssl]) => `
                        <div class="mb-2 p-2 border rounded small">
                            <strong>${domain}</strong><br>
                            Version: ${ssl.version || 'N/A'}<br>
                            ${ssl.cert_subject ? `Issued to: ${ssl.cert_subject.CN || 'N/A'}<br>` : ''}
                            ${ssl.not_after ? `Expires: ${ssl.not_after}` : ''}
                        </div>
                    `).join('')}
                </div>
            `;
        }
        
        if (!html) {
            html = `
                <div class="text-center text-muted py-4">
                    <i data-feather="info" class="mb-2" style="width: 32px; height: 32px;"></i>
                    <p class="mb-0">No network information available</p>
                </div>
            `;
        }
        
        container.innerHTML = html;
        feather.replace();
    }
    
    renderTechnologyStack() {
        const container = document.getElementById('technology-container');
        if (!container) return;
        
        let technologies = {};
        
        if (this.data.phases && this.data.phases.web_technologies) {
            technologies = this.data.phases.web_technologies.technologies || {};
        }
        
        if (Object.keys(technologies).length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i data-feather="code" class="mb-2" style="width: 32px; height: 32px;"></i>
                    <p class="mb-0">No technology information available</p>
                </div>
            `;
        } else {
            container.innerHTML = Object.entries(technologies).map(([domain, tech]) => `
                <div class="mb-3 p-3 border rounded">
                    <h6 class="mb-2">${domain}</h6>
                    <div class="row small">
                        ${tech.server ? `
                            <div class="col-md-6 mb-1">
                                <strong>Server:</strong> ${tech.server}
                            </div>
                        ` : ''}
                        ${tech.x_powered_by ? `
                            <div class="col-md-6 mb-1">
                                <strong>Powered by:</strong> ${tech.x_powered_by}
                            </div>
                        ` : ''}
                        ${tech.content_type ? `
                            <div class="col-md-6 mb-1">
                                <strong>Content Type:</strong> ${tech.content_type}
                            </div>
                        ` : ''}
                        ${tech.status_code ? `
                            <div class="col-md-6 mb-1">
                                <strong>Status:</strong> ${tech.status_code}
                            </div>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }
        
        feather.replace();
    }
    
    renderRecommendations() {
        const container = document.getElementById('recommendations-container');
        if (!container) return;
        
        let recommendations = [];
        
        if (this.data.phases && this.data.phases.risk_assessment) {
            recommendations = this.data.phases.risk_assessment.recommendations || [];
        }
        
        // Add default recommendations based on findings
        const defaultRecommendations = [
            {
                icon: 'shield',
                title: 'Implement Security Headers',
                description: 'Add security headers like HSTS, CSP, and X-Frame-Options to protect against common attacks.',
                priority: 'High'
            },
            {
                icon: 'lock',
                title: 'Update SSL/TLS Configuration',
                description: 'Ensure all services use modern TLS versions and secure cipher suites.',
                priority: 'High'
            },
            {
                icon: 'eye-off',
                title: 'Secure Exposed Endpoints',
                description: 'Review and restrict access to administrative interfaces and sensitive files.',
                priority: 'Medium'
            },
            {
                icon: 'mail',
                title: 'Enhance Email Security',
                description: 'Implement SPF, DKIM, and DMARC records to prevent email spoofing.',
                priority: 'Medium'
            },
            {
                icon: 'refresh-cw',
                title: 'Regular Security Assessments',
                description: 'Conduct regular security assessments to identify new vulnerabilities.',
                priority: 'Low'
            }
        ];
        
        if (recommendations.length === 0) {
            recommendations = defaultRecommendations;
        }
        
        container.innerHTML = recommendations.map(rec => `
            <div class="row mb-3">
                <div class="col-auto">
                    <div class="rounded-circle bg-primary d-flex align-items-center justify-content-center" 
                         style="width: 40px; height: 40px;">
                        <i data-feather="${rec.icon || 'check'}" class="text-white" style="width: 20px; height: 20px;"></i>
                    </div>
                </div>
                <div class="col">
                    <div class="d-flex justify-content-between align-items-start mb-1">
                        <h6 class="mb-0">${rec.title || rec}</h6>
                        ${rec.priority ? `<span class="badge ${this.getPriorityBadgeClass(rec.priority)}">${rec.priority}</span>` : ''}
                    </div>
                    ${rec.description ? `<p class="text-muted small mb-0">${rec.description}</p>` : ''}
                </div>
            </div>
        `).join('');
        
        feather.replace();
    }
    
    getVulnerabilitySeverity(vuln) {
        // Simple severity assessment based on type
        const type = (vuln.type || '').toLowerCase();
        
        if (type.includes('critical') || type.includes('high')) return 'high';
        if (type.includes('medium') || type.includes('moderate')) return 'medium';
        if (type.includes('low') || type.includes('info')) return 'low';
        
        // Default to medium for unknown
        return 'medium';
    }
    
    getSeverityBadgeClass(vuln) {
        const severity = this.getVulnerabilitySeverity(vuln);
        switch (severity) {
            case 'high': return 'bg-danger';
            case 'medium': return 'bg-warning';
            case 'low': return 'bg-info';
            default: return 'bg-secondary';
        }
    }
    
    getPriorityBadgeClass(priority) {
        switch (priority.toLowerCase()) {
            case 'high': return 'bg-danger';
            case 'medium': return 'bg-warning';
            case 'low': return 'bg-info';
            default: return 'bg-secondary';
        }
    }
}

// Export for use in templates
window.SecurityDashboard = SecurityDashboard;
