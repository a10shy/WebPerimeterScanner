import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from flask_executor import Executor
from flask_cors import CORS
import logging

from security_assessment import SecurityAssessmentRunner
from models import db, Assessment, AssessmentPhase, Finding, Subdomain, Port, Certificate

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
CORS(app)

# Database configuration
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # Fallback for development
    database_url = "sqlite:///security_assessment.db"

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "connect_args": {"sslmode": "require"} if database_url and "postgresql" in database_url else {}
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db.init_app(app)

# Add custom filter for JSON serialization
@app.template_filter('tojsonfilter')
def to_json_filter(obj):
    return json.dumps(obj)

# Initialize Flask-Executor for background tasks
executor = Executor(app)

# Global storage for active assessments
active_assessments = {}
assessment_lock = threading.Lock()

# Initialize database tables
try:
    with app.app_context():
        db.create_all()
except Exception as e:
    app.logger.warning(f"Database initialization skipped: {str(e)}")
    # Continue without database for now

@app.route('/')
def index():
    """Landing page with domain input form"""
    return render_template('index.html')

@app.route('/history')
def assessment_history():
    """View assessment history"""
    # For now, show recent assessments from memory
    recent_assessments = []
    with assessment_lock:
        for assessment_id, data in list(active_assessments.items())[-10:]:
            recent_assessments.append({
                'id': assessment_id,
                'domain': data['domain'],
                'status': data['status'],
                'start_time': data['start_time'],
                'overall_progress': data.get('overall_progress', 0)
            })
    
    return render_template('history.html', assessments={'items': recent_assessments})

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new security assessment"""
    domain = request.form.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Basic domain validation
    if not is_valid_domain(domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    # Create assessment ID
    assessment_id = f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Define assessment phases
    phase_definitions = [
        ('Subdomain Enumeration', 'subdomain_enumeration'),
        ('Amass Discovery', 'amass_discovery'),
        ('IP Identification', 'ip_identification'),
        ('DNS Security', 'dns_security'),
        ('Email Security', 'email_security'),
        ('Network Security', 'network_security'),
        ('Vulnerability Scan', 'vulnerability_scan'),
        ('Nuclei Scan', 'nuclei_scan'),
        ('Data Exposure', 'data_exposure'),
        ('Misconfiguration Detection', 'misconfiguration_detection'),
        ('Email Compromises', 'email_compromises'),
        ('Credential Leaks', 'credential_leaks'),
        ('Reputation Check', 'reputation_check'),
        ('Web Technologies', 'web_technologies'),
        ('CVE Gathering', 'cve_gathering'),
        ('Shodan Scan', 'shodan_scan'),
        ('Trufflehog Scan', 'trufflehog_scan'),
        ('Risk Assessment', 'risk_assessment')
    ]
    
    # Initialize assessment status in memory for real-time updates
    with assessment_lock:
        active_assessments[assessment_id] = {
            'domain': domain,
            'status': 'initializing',
            'start_time': datetime.now(),
            'phases': {phase_key: {'status': 'pending', 'progress': 0, 'findings': []} 
                      for _, phase_key in phase_definitions},
            'results_dir': None,
            'overall_progress': 0,
            'error': None
        }
    
    # Start assessment in background
    executor.submit(run_security_assessment, assessment_id, domain)
    
    return redirect(url_for('scan', assessment_id=assessment_id))

@app.route('/scan/<assessment_id>')
def scan(assessment_id):
    """Real-time progress tracking page"""
    with assessment_lock:
        if assessment_id not in active_assessments:
            return render_template('index.html', error='Assessment not found')
        
        assessment = active_assessments[assessment_id]
    
    return render_template('scan.html', 
                         assessment_id=assessment_id, 
                         domain=assessment['domain'])

@app.route('/api/status/<assessment_id>')
def get_status(assessment_id):
    """API endpoint to get current assessment status"""
    with assessment_lock:
        if assessment_id not in active_assessments:
            return jsonify({'error': 'Assessment not found'}), 404
        
        assessment = active_assessments[assessment_id].copy()
    
    return jsonify(assessment)

@app.route('/dashboard/<assessment_id>')
def dashboard(assessment_id):
    """Final results dashboard"""
    with assessment_lock:
        if assessment_id not in active_assessments:
            return render_template('index.html', error='Assessment not found')
        
        assessment = active_assessments[assessment_id]
        
        if assessment['status'] != 'completed':
            return redirect(url_for('scan', assessment_id=assessment_id))
    
    # Load final results
    results_dir = assessment['results_dir']
    if not results_dir or not os.path.exists(results_dir):
        return render_template('index.html', error='Results not available')
    
    # Load comprehensive results
    results = load_assessment_results(results_dir)
    
    return render_template('dashboard.html', 
                         assessment_id=assessment_id,
                         domain=assessment['domain'],
                         results=results)

@app.route('/api/results/<assessment_id>')
def get_results(assessment_id):
    """API endpoint to get assessment results"""
    with assessment_lock:
        if assessment_id not in active_assessments:
            return jsonify({'error': 'Assessment not found'}), 404
        
        assessment = active_assessments[assessment_id]
        results_dir = assessment.get('results_dir')
    
    if not results_dir or not os.path.exists(results_dir):
        return jsonify({'error': 'Results not available'}), 404
    
    results = load_assessment_results(results_dir)
    return jsonify(results)

@app.route('/download_report/<assessment_id>')
def download_report(assessment_id):
    """Download PDF report"""
    with assessment_lock:
        if assessment_id not in active_assessments:
            return jsonify({'error': 'Assessment not found'}), 404
        
        assessment = active_assessments[assessment_id]
        results_dir = assessment.get('results_dir')
    
    if not results_dir:
        return jsonify({'error': 'Results not available'}), 404
    
    # Look for PDF report
    pdf_files = [f for f in os.listdir(results_dir) if f.endswith('.pdf')]
    if not pdf_files:
        return jsonify({'error': 'PDF report not found'}), 404
    
    pdf_path = os.path.join(results_dir, pdf_files[0])
    return send_file(pdf_path, as_attachment=True, 
                    download_name=f"security_report_{assessment['domain']}.pdf")

def run_security_assessment(assessment_id, domain):
    """Run the complete security assessment in background"""
    try:
        app.logger.info(f"Starting security assessment for {domain}")
        
        # Update status
        with assessment_lock:
            active_assessments[assessment_id]['status'] = 'running'
        
        # Create assessment runner
        runner = SecurityAssessmentRunner(domain, assessment_id, update_callback)
        
        # Run assessment
        results_dir = runner.run_assessment()
        
        # Update final status
        with assessment_lock:
            active_assessments[assessment_id]['status'] = 'completed'
            active_assessments[assessment_id]['results_dir'] = results_dir
            active_assessments[assessment_id]['overall_progress'] = 100
        
        app.logger.info(f"Security assessment completed for {domain}")
        
    except Exception as e:
        app.logger.error(f"Error in security assessment for {domain}: {str(e)}")
        with assessment_lock:
            active_assessments[assessment_id]['status'] = 'error'
            active_assessments[assessment_id]['error'] = str(e)

def update_callback(assessment_id, phase_name, status, progress, findings=None):
    """Callback function to update assessment progress"""
    with assessment_lock:
        if assessment_id in active_assessments:
            phase_key = phase_name.lower().replace(' ', '_').replace('-', '_')
            if phase_key in active_assessments[assessment_id]['phases']:
                active_assessments[assessment_id]['phases'][phase_key]['status'] = status
                active_assessments[assessment_id]['phases'][phase_key]['progress'] = progress
                if findings:
                    active_assessments[assessment_id]['phases'][phase_key]['findings'].extend(findings)
            
            # Calculate overall progress
            total_phases = len(active_assessments[assessment_id]['phases'])
            completed_phases = sum(1 for p in active_assessments[assessment_id]['phases'].values() 
                                 if p['status'] == 'completed')
            overall_progress = int((completed_phases / total_phases) * 100)
            active_assessments[assessment_id]['overall_progress'] = overall_progress

def is_valid_domain(domain):
    """Basic domain validation"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None

def load_assessment_results(results_dir):
    """Load all assessment results from directory"""
    results = {}
    
    try:
        # Load summary results
        summary_file = os.path.join(results_dir, 'assessment_summary.json')
        if os.path.exists(summary_file):
            with open(summary_file, 'r') as f:
                results['summary'] = json.load(f)
        
        # Load phase results
        results['phases'] = {}
        for filename in os.listdir(results_dir):
            if filename.endswith('.json') and filename != 'assessment_summary.json':
                phase_name = filename.replace('.json', '')
                with open(os.path.join(results_dir, filename), 'r') as f:
                    results['phases'][phase_name] = json.load(f)
        
        return results
        
    except Exception as e:
        app.logger.error(f"Error loading results from {results_dir}: {str(e)}")
        return {}

if __name__ == '__main__':
    # Ensure results directory exists
    os.makedirs('results', exist_ok=True)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
