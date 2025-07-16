class ScanMonitor {
    constructor(assessmentId) {
        this.assessmentId = assessmentId;
        this.isRunning = false;
        this.autoRefresh = true;
        this.pollInterval = 2000; // 2 seconds
        this.pollTimer = null;
        
        this.phases = [
            { key: 'subdomain_enumeration', name: 'Subdomain Enumeration', icon: 'search' },
            { key: 'amass_discovery', name: 'Enhanced Discovery (Amass)', icon: 'globe' },
            { key: 'ip_identification', name: 'IP Address Identification', icon: 'server' },
            { key: 'dns_security', name: 'DNS Security Analysis', icon: 'shield' },
            { key: 'email_security', name: 'Email Security Assessment', icon: 'mail' },
            { key: 'network_security', name: 'Network Security Evaluation', icon: 'wifi' },
            { key: 'vulnerability_scan', name: 'Vulnerability Scanning', icon: 'alert-triangle' },
            { key: 'nuclei_scan', name: 'Nuclei Security Scans', icon: 'target' },
            { key: 'data_exposure', name: 'Data Exposure Detection', icon: 'eye' },
            { key: 'misconfiguration_detection', name: 'Misconfiguration Detection', icon: 'settings' },
            { key: 'email_compromises', name: 'Email Compromise Detection', icon: 'user-x' },
            { key: 'credential_leaks', name: 'Credential Leak Checks', icon: 'key' },
            { key: 'reputation_check', name: 'Domain Reputation Analysis', icon: 'thumbs-up' },
            { key: 'web_technologies', name: 'Web Technology Detection', icon: 'code' },
            { key: 'cve_gathering', name: 'CVE Information Gathering', icon: 'database' },
            { key: 'shodan_scan', name: 'Shodan Intelligence', icon: 'compass' },
            { key: 'trufflehog_scan', name: 'Sensitive Data Scanning', icon: 'search' },
            { key: 'risk_assessment', name: 'Risk Assessment', icon: 'pie-chart' }
        ];
        
        this.initializeUI();
    }
    
    initializeUI() {
        this.renderPhases();
        this.setupEventListeners();
    }
    
    renderPhases() {
        const container = document.getElementById('phases-container');
        container.innerHTML = '';
        
        this.phases.forEach((phase, index) => {
            const phaseCard = this.createPhaseCard(phase, index);
            container.appendChild(phaseCard);
        });
    }
    
    createPhaseCard(phase, index) {
        const card = document.createElement('div');
        card.className = 'card phase-card mb-3';
        card.id = `phase-${phase.key}`;
        
        card.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <span class="badge bg-secondary me-3">${index + 1}</span>
                    <i data-feather="${phase.icon}" class="me-2"></i>
                    <h6 class="mb-0">${phase.name}</h6>
                </div>
                <span class="badge status-badge bg-secondary" id="status-${phase.key}">Pending</span>
            </div>
            <div class="card-body">
                <div class="progress mb-3">
                    <div class="progress-bar" id="progress-${phase.key}" 
                         role="progressbar" style="width: 0%"></div>
                </div>
                <div class="findings-container">
                    <div id="findings-${phase.key}" class="text-muted small">
                        Waiting to start...
                    </div>
                </div>
            </div>
        `;
        
        return card;
    }
    
    setupEventListeners() {
        const autoRefreshBtn = document.getElementById('auto-refresh');
        autoRefreshBtn.addEventListener('click', () => {
            this.toggleAutoRefresh();
        });
    }
    
    toggleAutoRefresh() {
        this.autoRefresh = !this.autoRefresh;
        const btn = document.getElementById('auto-refresh');
        const icon = btn.querySelector('[data-feather]');
        
        if (this.autoRefresh) {
            btn.innerHTML = '<i data-feather="refresh-cw" class="me-1"></i>Auto-refresh: On';
            btn.className = 'btn btn-sm btn-outline-primary w-100';
            if (this.isRunning) {
                this.startPolling();
            }
        } else {
            btn.innerHTML = '<i data-feather="pause" class="me-1"></i>Auto-refresh: Off';
            btn.className = 'btn btn-sm btn-outline-secondary w-100';
            this.stopPolling();
        }
        
        feather.replace();
    }
    
    start() {
        this.isRunning = true;
        if (this.autoRefresh) {
            this.startPolling();
        }
        this.fetchStatus(); // Initial fetch
    }
    
    stop() {
        this.isRunning = false;
        this.stopPolling();
    }
    
    startPolling() {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
        }
        
        this.pollTimer = setInterval(() => {
            this.fetchStatus();
        }, this.pollInterval);
    }
    
    stopPolling() {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }
    
    async fetchStatus() {
        try {
            const response = await fetch(`/api/status/${this.assessmentId}`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.updateUI(data);
            
            // Check if assessment is complete
            if (data.status === 'completed') {
                this.handleCompletion();
            } else if (data.status === 'error') {
                this.handleError(data.error);
            }
            
        } catch (error) {
            console.error('Error fetching status:', error);
            this.handleFetchError(error);
        }
    }
    
    updateUI(data) {
        // Update overall progress
        const overallProgress = data.overall_progress || 0;
        document.getElementById('overall-progress').style.width = `${overallProgress}%`;
        document.getElementById('overall-percentage').textContent = `${overallProgress}%`;
        
        // Count phase statuses
        let pending = 0, running = 0, completed = 0, errors = 0;
        
        // Update individual phases
        this.phases.forEach(phase => {
            const phaseData = data.phases[phase.key];
            if (phaseData) {
                this.updatePhaseCard(phase.key, phaseData);
                
                // Count statuses
                switch (phaseData.status) {
                    case 'pending': pending++; break;
                    case 'running': running++; break;
                    case 'completed': completed++; break;
                    case 'error': errors++; break;
                }
            } else {
                pending++;
            }
        });
        
        // Update status summary
        document.getElementById('pending-count').textContent = pending;
        document.getElementById('running-count').textContent = running;
        document.getElementById('completed-count').textContent = completed;
        document.getElementById('error-count').textContent = errors;
    }
    
    updatePhaseCard(phaseKey, phaseData) {
        const card = document.getElementById(`phase-${phaseKey}`);
        const status = phaseData.status;
        const progress = phaseData.progress || 0;
        const findings = phaseData.findings || [];
        
        // Update card styling
        card.className = `card phase-card mb-3 ${status}`;
        
        // Update status badge
        const statusBadge = document.getElementById(`status-${phaseKey}`);
        statusBadge.textContent = this.capitalizeFirst(status);
        statusBadge.className = `badge status-badge ${this.getStatusBadgeClass(status)}`;
        
        // Update progress bar
        const progressBar = document.getElementById(`progress-${phaseKey}`);
        progressBar.style.width = `${progress}%`;
        progressBar.className = `progress-bar ${this.getProgressBarClass(status)}`;
        
        if (status === 'running') {
            progressBar.className += ' progress-bar-striped progress-bar-animated';
        }
        
        // Update findings
        const findingsContainer = document.getElementById(`findings-${phaseKey}`);
        if (findings.length > 0) {
            findingsContainer.innerHTML = findings.map(finding => 
                `<div class="mb-1"><i data-feather="chevron-right" class="me-1"></i>${finding}</div>`
            ).join('');
        } else {
            const defaultMessage = this.getDefaultMessage(status);
            findingsContainer.innerHTML = `<div class="text-muted">${defaultMessage}</div>`;
        }
        
        // Re-initialize feather icons for this card
        feather.replace();
    }
    
    getStatusBadgeClass(status) {
        switch (status) {
            case 'pending': return 'bg-secondary';
            case 'running': return 'bg-primary';
            case 'completed': return 'bg-success';
            case 'error': return 'bg-danger';
            default: return 'bg-secondary';
        }
    }
    
    getProgressBarClass(status) {
        switch (status) {
            case 'running': return 'progress-bar bg-primary';
            case 'completed': return 'progress-bar bg-success';
            case 'error': return 'progress-bar bg-danger';
            default: return 'progress-bar bg-secondary';
        }
    }
    
    getDefaultMessage(status) {
        switch (status) {
            case 'pending': return 'Waiting to start...';
            case 'running': return 'Phase in progress...';
            case 'completed': return 'Phase completed successfully';
            case 'error': return 'Phase encountered an error';
            default: return 'Unknown status';
        }
    }
    
    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
    
    handleCompletion() {
        this.stop();
        
        // Show completion notice
        const completionNotice = document.getElementById('completion-notice');
        completionNotice.classList.remove('d-none');
        
        // Set up dashboard link
        const dashboardLink = document.getElementById('view-dashboard');
        dashboardLink.href = `/dashboard/${this.assessmentId}`;
        
        // Auto-redirect after 5 seconds
        setTimeout(() => {
            window.location.href = `/dashboard/${this.assessmentId}`;
        }, 5000);
        
        // Update auto-refresh button
        const autoRefreshBtn = document.getElementById('auto-refresh');
        autoRefreshBtn.innerHTML = '<i data-feather="check" class="me-1"></i>Assessment Complete';
        autoRefreshBtn.className = 'btn btn-sm btn-success w-100';
        autoRefreshBtn.disabled = true;
        
        feather.replace();
    }
    
    handleError(error) {
        this.stop();
        
        // Show error notification
        const errorHtml = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i data-feather="alert-triangle" class="me-2"></i>
                <strong>Assessment Error:</strong> ${error}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        const container = document.querySelector('.container-fluid');
        container.insertAdjacentHTML('afterbegin', errorHtml);
        
        feather.replace();
    }
    
    handleFetchError(error) {
        console.error('Fetch error:', error);
        
        // Don't show error for temporary network issues
        // Just log and continue trying if auto-refresh is on
    }
}

// Export for use in templates
window.ScanMonitor = ScanMonitor;
