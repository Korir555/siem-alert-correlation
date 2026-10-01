"""
SIEM Alert Tuning & Correlation Engine - Backend
Reduces false positives through rule-based correlation and MITRE ATT&CK mapping
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///siem_correlator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =====================
# DATABASE MODELS
# =====================

class SiemAlert(db.Model):
    """Raw SIEM alert from Wazuh/Suricata"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    alert_type = db.Column(db.String(100), nullable=False)
    rule_id = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    raw_data = db.Column(db.Text, nullable=True)  # JSON raw alert
    is_filtered = db.Column(db.Boolean, default=False)
    filter_reason = db.Column(db.String(200), nullable=True)

class CorrelatedIncident(db.Model):
    """Correlated group of alerts representing single incident"""
    id = db.Column(db.Integer, primary_key=True)
    incident_hash = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    incident_type = db.Column(db.String(100), nullable=False)
    mitre_technique = db.Column(db.String(20), nullable=True)  # e.g., T1110 (Brute Force)
    confidence_score = db.Column(db.Float, default=0.5)
    severity = db.Column(db.String(20), default='medium')
    source_ip = db.Column(db.String(45), nullable=False)
    target_resource = db.Column(db.String(200), nullable=True)
    alert_count = db.Column(db.Integer, default=1)
    timeline = db.Column(db.Text, nullable=True)  # JSON timeline
    recommendation = db.Column(db.Text, nullable=True)

class CorrelationRule(db.Model):
    """Rules for alert correlation and false positive filtering"""
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(200), nullable=False)
    alert_pattern = db.Column(db.Text, nullable=False)  # JSON criteria
    correlation_key = db.Column(db.String(200), nullable=False)  # Field(s) to group by
    time_window = db.Column(db.Integer, default=300)  # seconds
    min_alert_count = db.Column(db.Integer, default=1)
    incident_type = db.Column(db.String(100), nullable=False)
    mitre_technique = db.Column(db.String(20), nullable=True)
    is_enabled = db.Column(db.Boolean, default=True)

class FalsePositiveFilter(db.Model):
    """Rules to suppress known false positives"""
    id = db.Column(db.Integer, primary_key=True)
    filter_name = db.Column(db.String(200), nullable=False)
    source_ip_pattern = db.Column(db.String(200), nullable=True)
    alert_type = db.Column(db.String(100), nullable=True)
    rule_id = db.Column(db.String(50), nullable=True)
    reason = db.Column(db.String(200), nullable=False)
    is_enabled = db.Column(db.Boolean, default=True)

# =====================
# MITRE ATT&CK MAPPING
# =====================

MITRE_TECHNIQUES = {
    'T1110': {
        'name': 'Brute Force',
        'tactic': 'Credential Access',
        'alert_patterns': ['failed login', 'authentication failure', 'password attempt'],
        'indicators': {
            'high_login_failures': 10,  # failures within time window
            'multiple_accounts': 3,  # unique accounts targeted
        }
    },
    'T1078': {
        'name': 'Valid Accounts',
        'tactic': 'Initial Access',
        'alert_patterns': ['successful login', 'authentication success', 'session created'],
        'risk_factors': ['unusual_time', 'unusual_location', 'impossible_travel']
    },
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'alert_patterns': ['sql injection', 'xss', 'rce', 'web exploit'],
    },
    'T1133': {
        'name': 'External Remote Services',
        'tactic': 'Persistence',
        'alert_patterns': ['rdp login', 'ssh login', 'vpn', 'remote access'],
    },
    'T1021': {
        'name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'alert_patterns': ['smb', 'psexec', 'wmi', 'ssh lateral'],
    },
    'T1583': {
        'name': 'Acquire Infrastructure',
        'tactic': 'Resource Development',
        'alert_patterns': ['dns query suspicious', 'c2 domain', 'beacon'],
    },
    'T1566': {
        'name': 'Phishing',
        'tactic': 'Initial Access',
        'alert_patterns': ['phishing', 'malicious email', 'attachment', 'url redirect'],
    }
}

# =====================
# ALERT CORRELATION ENGINE
# =====================

class AlertCorrelator:
    """Correlate and deduplicate SIEM alerts"""
    
    @staticmethod
    def create_correlation_key(alert, key_fields):
        """Create hash key for grouping related alerts"""
        key_parts = []
        alert_dict = json.loads(alert.raw_data) if isinstance(alert.raw_data, str) else alert.raw_data or {}
        
        for field in key_fields:
            if field == 'source_ip':
                key_parts.append(alert.source_ip)
            elif field == 'destination_ip':
                key_parts.append(alert.destination_ip)
            elif field == 'alert_type':
                key_parts.append(alert.alert_type)
            elif field in alert_dict:
                key_parts.append(str(alert_dict[field]))
        
        key_string = '|'.join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    @staticmethod
    def correlate_alerts(alerts, time_window=300):
        """Group and correlate related alerts"""
        groups = defaultdict(list)
        
        for alert in alerts:
            key = f"{alert.source_ip}|{alert.alert_type}"
            groups[key].append(alert)
        
        incidents = []
        for key, alert_group in groups.items():
            if len(alert_group) >= 2:
                # Multi-alert incident
                incident = AlertCorrelator.create_incident(alert_group)
                incidents.append(incident)
        
        return incidents
    
    @staticmethod
    def create_incident(alerts):
        """Convert correlated alert group into incident"""
        alerts.sort(key=lambda x: x.timestamp)
        first_alert = alerts[0]
        
        incident_hash = hashlib.sha256(
            f"{first_alert.source_ip}|{first_alert.alert_type}|{first_alert.timestamp}".encode()
        ).hexdigest()
        
        # Detect MITRE technique
        mitre_tech = AlertCorrelator.detect_mitre_technique(alerts)
        
        # Generate timeline
        timeline = [
            {
                'time': alert.timestamp.isoformat(),
                'type': alert.alert_type,
                'severity': alert.severity
            } for alert in alerts
        ]
        
        return {
            'incident_hash': incident_hash,
            'incident_type': AlertCorrelator.classify_incident(alerts),
            'mitre_technique': mitre_tech,
            'source_ip': first_alert.source_ip,
            'alert_count': len(alerts),
            'severity': AlertCorrelator.calculate_incident_severity(alerts),
            'timeline': timeline,
            'recommendation': AlertCorrelator.generate_recommendation(alerts, mitre_tech)
        }
    
    @staticmethod
    def detect_mitre_technique(alerts):
        """Map alerts to MITRE ATT&CK techniques"""
        for tech_id, tech_data in MITRE_TECHNIQUES.items():
            patterns = tech_data.get('alert_patterns', [])
            alert_messages = ' '.join([a.message.lower() or '' for a in alerts])
            
            for pattern in patterns:
                if pattern.lower() in alert_messages:
                    return tech_id
        
        return None
    
    @staticmethod
    def classify_incident(alerts):
        """Classify incident type from alert group"""
        types = [a.alert_type for a in alerts]
        type_counts = defaultdict(int)
        for t in types:
            type_counts[t] += 1
        
        most_common = max(type_counts.items(), key=lambda x: x[1])[0]
        
        if 'login' in most_common.lower() or 'auth' in most_common.lower():
            return 'Authentication Anomaly'
        elif 'injection' in most_common.lower():
            return 'Application Attack'
        elif 'scan' in most_common.lower() or 'port' in most_common.lower():
            return 'Reconnaissance'
        else:
            return 'Security Event'
    
    @staticmethod
    def calculate_incident_severity(alerts):
        """Calculate incident severity from alert severities"""
        severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        weights = [severity_weights.get(a.severity, 1) for a in alerts]
        avg_weight = sum(weights) / len(weights) if weights else 1
        
        if avg_weight >= 3.5:
            return 'critical'
        elif avg_weight >= 2.5:
            return 'high'
        elif avg_weight >= 1.5:
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def generate_recommendation(alerts, mitre_tech):
        """Generate incident response recommendation"""
        recommendations = {
            'T1110': 'Investigate source IP for credential stuffing. Check for account lockouts. Enable MFA.',
            'T1078': 'Validate user activity. Check impossible travel scenarios. Review access logs.',
            'T1190': 'Patch vulnerable application immediately. Check for successful exploitation. Review access logs.',
            'T1133': 'Validate remote access session. Review session logs. Check for lateral movement.',
            'T1021': 'Investigate lateral movement path. Check for privilege escalation. Isolate affected systems.',
            'T1583': 'Block suspicious domain. Check for C2 communication. Review network logs.',
            'T1566': 'Quarantine email sender. Check for malware delivery. User security training.',
        }
        
        if mitre_tech in recommendations:
            return recommendations[mitre_tech]
        
        return 'Monitor source IP. Investigate alert context. Escalate if activity continues.'

# =====================
# FALSE POSITIVE FILTERING
# =====================

class FalsePositiveDetector:
    """Detect and filter known false positives"""
    
    # Built-in known false positive patterns
    COMMON_FP_PATTERNS = [
        {
            'name': 'Backup system scan',
            'source_ips': ['10.0.0.50'],  # Backup server
            'alert_types': ['port scan'],
            'reason': 'Daily backup scans from backup server'
        },
        {
            'name': 'Monitoring system heartbeat',
            'source_ips': ['10.0.0.100'],  # Monitoring server
            'alert_types': ['ping flood', 'connectivity check'],
            'reason': 'Monitoring system health checks'
        },
        {
            'name': 'Developer testing',
            'alert_types': ['sql injection attempt', 'xss attempt'],
            'rule_ids': ['5001', '5002'],
            'reason': 'DVWA/test environment legitimate testing'
        },
    ]
    
    @staticmethod
    def is_false_positive(alert):
        """Check if alert matches false positive patterns"""
        for pattern in FalsePositiveDetector.COMMON_FP_PATTERNS:
            if FalsePositiveDetector.matches_pattern(alert, pattern):
                return True, pattern['reason']
        
        return False, None
    
    @staticmethod
    def matches_pattern(alert, pattern):
        """Check if alert matches pattern criteria"""
        if 'source_ips' in pattern:
            if alert.source_ip not in pattern['source_ips']:
                return False
        
        if 'alert_types' in pattern:
            if alert.alert_type not in pattern['alert_types']:
                return False
        
        if 'rule_ids' in pattern:
            if alert.rule_id not in pattern['rule_ids']:
                return False
        
        return True

# =====================
# API ENDPOINTS
# =====================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'SIEM Alert Correlator'})

@app.route('/api/alerts/ingest', methods=['POST'])
def ingest_alerts():
    """Ingest raw SIEM alerts (Wazuh/Suricata JSON)"""
    data = request.json
    alerts = data.get('alerts', [])
    
    ingested = 0
    filtered = 0
    
    for alert_data in alerts:
        is_fp, reason = FalsePositiveDetector.is_false_positive(
            type('obj', (object,), alert_data)()
        )
        
        if is_fp:
            filtered += 1
        
        alert = SiemAlert(
            source_ip=alert_data.get('source_ip', '0.0.0.0'),
            destination_ip=alert_data.get('destination_ip', '0.0.0.0'),
            alert_type=alert_data.get('type', alert_data.get('rule_name', 'unknown')),
            rule_id=alert_data.get('rule_id', '0'),
            message=alert_data.get('message', ''),
            severity=alert_data.get('severity', 'medium'),
            raw_data=json.dumps(alert_data),
            is_filtered=is_fp,
            filter_reason=reason
        )
        db.session.add(alert)
        ingested += 1
    
    db.session.commit()
    
    return jsonify({
        'ingested': ingested,
        'filtered': filtered,
        'message': f'Ingested {ingested} alerts, filtered {filtered} false positives'
    })

@app.route('/api/incidents/correlate', methods=['POST'])
def correlate_alerts():
    """Correlate raw alerts into incidents"""
    # Get recent unfiltered alerts
    recent_alerts = SiemAlert.query.filter(
        SiemAlert.is_filtered == False,
        SiemAlert.timestamp >= datetime.utcnow() - timedelta(minutes=10)
    ).all()
    
    if not recent_alerts:
        return jsonify({'incidents': [], 'message': 'No alerts to correlate'})
    
    # Correlate
    correlated = AlertCorrelator.correlate_alerts(recent_alerts)
    
    # Save incidents
    saved_incidents = []
    for incident_data in correlated:
        existing = CorrelatedIncident.query.filter_by(
            incident_hash=incident_data['incident_hash']
        ).first()
        
        if not existing:
            incident = CorrelatedIncident(
                incident_hash=incident_data['incident_hash'],
                incident_type=incident_data['incident_type'],
                mitre_technique=incident_data.get('mitre_technique'),
                severity=incident_data['severity'],
                source_ip=incident_data['source_ip'],
                alert_count=incident_data['alert_count'],
                timeline=json.dumps(incident_data.get('timeline', [])),
                recommendation=incident_data.get('recommendation', '')
            )
            db.session.add(incident)
            saved_incidents.append(incident_data)
    
    db.session.commit()
    
    return jsonify({
        'incidents_found': len(saved_incidents),
        'incidents': saved_incidents
    })

@app.route('/api/incidents', methods=['GET'])
def list_incidents():
    """List all correlated incidents"""
    incidents = CorrelatedIncident.query.all()
    
    return jsonify([{
        'id': i.id,
        'incident_type': i.incident_type,
        'mitre_technique': i.mitre_technique,
        'source_ip': i.source_ip,
        'severity': i.severity,
        'alert_count': i.alert_count,
        'created_at': i.created_at.isoformat(),
        'recommendation': i.recommendation
    } for i in incidents])

@app.route('/api/incidents/<int:incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get incident details"""
    incident = CorrelatedIncident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    timeline = json.loads(incident.timeline) if incident.timeline else []
    
    return jsonify({
        'id': incident.id,
        'incident_type': incident.incident_type,
        'mitre_technique': incident.mitre_technique,
        'mitre_name': MITRE_TECHNIQUES.get(incident.mitre_technique, {}).get('name', 'Unknown'),
        'mitre_tactic': MITRE_TECHNIQUES.get(incident.mitre_technique, {}).get('tactic', 'Unknown'),
        'source_ip': incident.source_ip,
        'severity': incident.severity,
        'alert_count': incident.alert_count,
        'timeline': timeline,
        'recommendation': incident.recommendation,
        'created_at': incident.created_at.isoformat()
    })

@app.route('/api/rules', methods=['GET'])
def list_rules():
    """List correlation rules"""
    rules = CorrelationRule.query.filter_by(is_enabled=True).all()
    
    return jsonify([{
        'id': r.id,
        'rule_name': r.rule_name,
        'incident_type': r.incident_type,
        'mitre_technique': r.mitre_technique,
        'min_alert_count': r.min_alert_count,
        'time_window': r.time_window
    } for r in rules])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get SIEM statistics"""
    total_alerts = SiemAlert.query.count()
    filtered_alerts = SiemAlert.query.filter_by(is_filtered=True).count()
    incidents = CorrelatedIncident.query.count()
    
    severity_breakdown = db.session.query(
        SiemAlert.severity,
        db.func.count(SiemAlert.id)
    ).group_by(SiemAlert.severity).all()
    
    return jsonify({
        'total_alerts': total_alerts,
        'filtered_alerts': filtered_alerts,
        'fp_reduction_rate': (filtered_alerts / total_alerts * 100) if total_alerts > 0 else 0,
        'correlated_incidents': incidents,
        'severity_breakdown': {s: c for s, c in severity_breakdown},
        'avg_alerts_per_incident': total_alerts / incidents if incidents > 0 else 0
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
