"""
Database models for Security Assessment Application
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import json

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class Assessment(db.Model):
    """Main assessment record"""
    __tablename__ = 'assessments'
    
    id = db.Column(db.String(128), primary_key=True)  # assessment_id
    domain = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, running, completed, error
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    overall_progress = db.Column(db.Integer, default=0)
    overall_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))
    error_message = db.Column(db.Text)
    results_directory = db.Column(db.String(512))
    
    # Relationships
    phases = db.relationship('AssessmentPhase', backref='assessment', lazy=True, cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='assessment', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'status': self.status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'overall_progress': self.overall_progress,
            'overall_score': self.overall_score,
            'risk_level': self.risk_level,
            'error_message': self.error_message,
            'results_directory': self.results_directory
        }

class AssessmentPhase(db.Model):
    """Individual phase tracking"""
    __tablename__ = 'assessment_phases'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(128), db.ForeignKey('assessments.id'), nullable=False)
    phase_name = db.Column(db.String(100), nullable=False)
    phase_key = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, error
    progress = db.Column(db.Integer, default=0)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    findings_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'phase_name': self.phase_name,
            'phase_key': self.phase_key,
            'status': self.status,
            'progress': self.progress,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'findings_count': self.findings_count,
            'error_message': self.error_message
        }

class Finding(db.Model):
    """Security findings from assessments"""
    __tablename__ = 'findings'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(128), db.ForeignKey('assessments.id'), nullable=False)
    phase_key = db.Column(db.String(100), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)  # vulnerability, misconfiguration, exposure, etc.
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(512))
    target = db.Column(db.String(255))  # IP, domain, endpoint affected
    status_code = db.Column(db.Integer)
    evidence = db.Column(db.Text)  # JSON string with additional data
    recommendation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'phase_key': self.phase_key,
            'finding_type': self.finding_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'url': self.url,
            'target': self.target,
            'status_code': self.status_code,
            'evidence': json.loads(self.evidence) if self.evidence else None,
            'recommendation': self.recommendation,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Subdomain(db.Model):
    """Discovered subdomains"""
    __tablename__ = 'subdomains'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(128), db.ForeignKey('assessments.id'), nullable=False)
    subdomain = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    discovery_method = db.Column(db.String(50))  # dns_enum, amass, crt_sh, etc.
    is_active = db.Column(db.Boolean, default=True)
    response_time = db.Column(db.Float)
    http_status = db.Column(db.Integer)
    technologies = db.Column(db.Text)  # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'subdomain': self.subdomain,
            'ip_address': self.ip_address,
            'discovery_method': self.discovery_method,
            'is_active': self.is_active,
            'response_time': self.response_time,
            'http_status': self.http_status,
            'technologies': json.loads(self.technologies) if self.technologies else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Port(db.Model):
    """Open ports discovered"""
    __tablename__ = 'ports'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(128), db.ForeignKey('assessments.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')  # tcp, udp
    service = db.Column(db.String(100))
    version = db.Column(db.String(255))
    state = db.Column(db.String(20), default='open')
    banner = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'service': self.service,
            'version': self.version,
            'state': self.state,
            'banner': self.banner,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Certificate(db.Model):
    """SSL/TLS certificates"""
    __tablename__ = 'certificates'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(128), db.ForeignKey('assessments.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    issuer = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    serial_number = db.Column(db.String(255))
    not_before = db.Column(db.DateTime)
    not_after = db.Column(db.DateTime)
    signature_algorithm = db.Column(db.String(100))
    key_size = db.Column(db.Integer)
    tls_version = db.Column(db.String(20))
    cipher_suite = db.Column(db.String(255))
    is_expired = db.Column(db.Boolean, default=False)
    is_self_signed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'issuer': self.issuer,
            'subject': self.subject,
            'serial_number': self.serial_number,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'signature_algorithm': self.signature_algorithm,
            'key_size': self.key_size,
            'tls_version': self.tls_version,
            'cipher_suite': self.cipher_suite,
            'is_expired': self.is_expired,
            'is_self_signed': self.is_self_signed,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }