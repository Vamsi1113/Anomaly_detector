"""
Rule-Based Threat Detectors
Pure Python functions for threat classification (NO ML)
"""
import re
from urllib.parse import unquote
from typing import Optional
import pandas as pd


# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

# XSS Patterns
XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror=", r"onload=",
    r"<iframe", r"alert\(", r"<img.*onerror", r"eval\(",
    r"document\.cookie", r"<svg.*onload"
]

# SQL Injection Patterns
SQLI_PATTERNS = [
    r"sqlmap", r"union\s+select", r"union.*select",
    r"' or '1'='1", r"' or ", r"--", r";--",
    r"drop\s+table", r"insert\s+into",
    r"select\s+\*\s+from", r"select.*from",
    r"1=1", r"' or 1=1", r"admin'--", r"' OR '1"
]

# Path Traversal / LFI Patterns
TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"\.\.",
    r"%2e%2e", r"%252e%252e", r"%2e",
    r"/etc/passwd", r"/etc/shadow",
    r"/proc/self", r"/windows/system32",
    r"password\.properties", r"license\.txt",
    r"CFIDE", r"administrator",
    r"\.\.\/\.\.\/", r"file:///"
]

# Command Injection / RCE Patterns
CMD_PATTERNS = [
    r"rm\s+-rf", r";\s*cat\s+/etc/", r"cat /etc",
    r"&&\s*whoami", r"\|\s*bash", r"whoami",
    r";\s*wget", r"`cat", r"; ls", r"&& ls",
    r"cmd=", r"exec\(", r"system\(", r"shell_exec",
    r"\$\{.*\}", r"bash -c"
]

# SSRF Patterns
SSRF_PATTERNS = [
    r"169\.254\.169\.254",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"localhost", r"127\.0\.0\.1",
    r"0\.0\.0\.0", r"::1",
    r"url=http://", r"fetch\?url=",
    r"redirect.*http://"
]

# IDOR Patterns
IDOR_PATTERNS = [
    r"/api/user/\d{5,}",  # Large user IDs
    r"/profile/\d{5,}",
    r"user_id=\d{5,}",
    r"account=\d{5,}"
]

# SSTI (Server-Side Template Injection) Patterns
SSTI_PATTERNS = [
    r"\{\{.*\}\}",  # Jinja2, Twig
    r"\$\{.*\}",    # Freemarker
    r"<%.*%>",      # JSP
    r"#\{.*\}"      # Ruby
]

# Open Redirect Patterns
OPEN_REDIRECT_PATTERNS = [
    r"redirect\?url=http://",
    r"next=http://",
    r"return_to=http://",
    r"goto=http://",
    r"url=//evil"
]

# Sensitive File Disclosure Patterns
SENSITIVE_FILE_PATTERNS = [
    r"\.env", r"\.git", r"\.svn",
    r"config\.php", r"web\.config",
    r"credentials", r"password",
    r"\.bak", r"\.backup",
    r"\.sql", r"dump\.sql"
]

# Privilege Escalation Patterns
PRIV_ESC_PATTERNS = [
    r"/admin", r"administrator", r"sudo", 
    r"privilege", r"/root", r"escalate",
    r"role=admin", r"isAdmin=true"
]

# Data Exfiltration Patterns
EXFIL_PATTERNS = [
    r"/export", r"/download", r"/backup",
    r"/dump", r"\.zip", r"\.tar\.gz",
    r"data=.*base64"
]

# Suspicious User Agents
BAD_AGENTS = [
    "sqlmap", "nikto", "nmap", "curl", 
    "python-requests", "masscan", "metasploit", 
    "burp", "scanner", "bot", "crawler",
    "acunetix", "nessus", "openvas"
]


# ============================================================================
# THREAT DETECTORS
# ============================================================================

# ============================================================================
# THREAT DETECTORS
# ============================================================================

def detect_xss(uri: str) -> bool:
    """Detect XSS attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in XSS_PATTERNS)


def detect_sql_injection(uri: str) -> bool:
    """Detect SQL injection attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in SQLI_PATTERNS)


def detect_path_traversal(uri: str) -> bool:
    """Detect path traversal / LFI attempts"""
    if not uri:
        return False
    decoded = unquote(uri.lower())
    return any(re.search(p, decoded) for p in TRAVERSAL_PATTERNS)


def detect_command_injection(uri: str) -> bool:
    """Detect command injection / RCE attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in CMD_PATTERNS)


def detect_ssrf(uri: str) -> bool:
    """Detect SSRF attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in SSRF_PATTERNS)


def detect_idor(uri: str) -> bool:
    """Detect IDOR attempts"""
    if not uri:
        return False
    return any(re.search(p, uri) for p in IDOR_PATTERNS)


def detect_ssti(uri: str) -> bool:
    """Detect SSTI attempts"""
    if not uri:
        return False
    return any(re.search(p, uri) for p in SSTI_PATTERNS)


def detect_open_redirect(uri: str) -> bool:
    """Detect open redirect attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in OPEN_REDIRECT_PATTERNS)


def detect_sensitive_file_access(uri: str) -> bool:
    """Detect sensitive file disclosure attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in SENSITIVE_FILE_PATTERNS)


def detect_privilege_escalation(uri: str) -> bool:
    """Detect privilege escalation attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(p in uri for p in PRIV_ESC_PATTERNS)


def detect_data_exfiltration(uri: str, response_size: int) -> bool:
    """Detect data exfiltration attempts"""
    if not uri:
        return False
    return (
        any(p in uri.lower() for p in EXFIL_PATTERNS) or
        response_size > 1_000_000
    )


def detect_bruteforce(records, current_ip: str, window: int = 60, threshold: int = 5) -> bool:
    """Detect brute force attempts (behavioral)"""
    if not records or not current_ip:
        return False
    
    failures = sum(
        1 for r in records
        if hasattr(r, 'client_ip') and r.client_ip == current_ip
        and hasattr(r, 'status_code') and r.status_code in [401, 403]
    )
    return failures >= threshold


def detect_suspicious_agent(user_agent: str) -> bool:
    """Detect suspicious user agents"""
    if not user_agent:
        return False
    ua = user_agent.lower()
    return any(a in ua for a in BAD_AGENTS)


# ============================================================================
# THREAT CLASSIFIER WITH CONFIDENCE
# ============================================================================

def classify_threat_with_confidence(uri: str, user_agent: str, response_size: int, status_code: int, records=None, client_ip: str = None) -> tuple:
    """
    Classify threat type using deterministic rules with confidence score
    
    Returns:
        (threat_type: str, confidence: float)
    """
    # Priority 1: Code Execution Threats (Most Critical) - High Confidence
    if detect_command_injection(uri):
        return "Command Injection", 0.95
    
    if detect_ssti(uri):
        return "SSTI", 0.95
    
    # Priority 2: Injection Attacks - High Confidence
    if detect_sql_injection(uri):
        return "SQL Injection", 0.90
    
    if detect_xss(uri):
        return "XSS", 0.90
    
    # Priority 3: File Access Attacks - High Confidence
    if detect_path_traversal(uri):
        return "Path Traversal", 0.92
    
    if detect_sensitive_file_access(uri):
        return "Sensitive File Disclosure", 0.88
    
    # Priority 4: Network Attacks - Medium-High Confidence
    if detect_ssrf(uri):
        return "SSRF", 0.85
    
    # Priority 5: Authorization Attacks - Medium Confidence
    if detect_idor(uri):
        return "IDOR", 0.75
    
    if detect_privilege_escalation(uri):
        return "Privilege Escalation", 0.80
    
    # Priority 6: Data Attacks - Medium Confidence
    if detect_data_exfiltration(uri, response_size):
        return "Data Exfiltration", 0.78
    
    # Priority 7: Redirect Attacks - Medium Confidence
    if detect_open_redirect(uri):
        return "Open Redirect", 0.82
    
    # Priority 8: Behavioral Attacks - Lower Confidence
    if records and client_ip and detect_bruteforce(records, client_ip):
        return "Brute Force", 0.70
    
    if detect_suspicious_agent(user_agent):
        return "Reconnaissance", 0.65
    
    return "Other", 0.0


def classify_threat(uri: str, user_agent: str, response_size: int, status_code: int, records=None, client_ip: str = None) -> str:
    """
    Classify threat type using deterministic rules (backward compatibility)
    
    Returns:
        Threat type string
    """
    threat_type, _ = classify_threat_with_confidence(uri, user_agent, response_size, status_code, records, client_ip)
    return threat_type


# ============================================================================
# CORRELATION ENGINE - Multi-Stage Attack Detection
# ============================================================================

class ThreatCorrelationEngine:
    """Detects multi-stage attacks and attack campaigns"""
    
    def __init__(self):
        self.ip_activity = {}  # Track activity per IP
    
    def analyze_attack_chain(self, results: list) -> dict:
        """
        Analyze results for multi-stage attack patterns
        
        Returns:
            Dictionary with correlation findings
        """
        # Group threats by IP
        ip_threats = {}
        for result in results:
            if result.get('severity') != 'normal':
                ip = result.get('identifier', '')
                if ip not in ip_threats:
                    ip_threats[ip] = []
                ip_threats[ip].append({
                    'threat_type': result.get('threat_type'),
                    'timestamp': result.get('timestamp'),
                    'severity': result.get('severity')
                })
        
        # Detect attack campaigns
        campaigns = []
        for ip, threats in ip_threats.items():
            if len(threats) >= 3:
                threat_types = [t['threat_type'] for t in threats]
                
                # Pattern 1: Reconnaissance → Exploitation → Exfiltration
                if self._has_attack_progression(threat_types):
                    campaigns.append({
                        'ip': ip,
                        'type': 'Advanced Persistent Threat (APT)',
                        'threat_count': len(threats),
                        'severity': 'CRITICAL',
                        'description': f'Multi-stage attack detected: {" → ".join(set(threat_types[:3]))}'
                    })
                
                # Pattern 2: Multiple injection attempts
                elif self._has_repeated_attacks(threat_types):
                    campaigns.append({
                        'ip': ip,
                        'type': 'Automated Attack Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Repeated attack attempts: {len(threats)} threats from same source'
                    })
        
        return {
            'campaigns': campaigns,
            'total_campaigns': len(campaigns),
            'affected_ips': list(ip_threats.keys())
        }
    
    def _has_attack_progression(self, threat_types: list) -> bool:
        """Check if threats show progression pattern"""
        recon_types = ['Reconnaissance', 'Sensitive File Disclosure']
        exploit_types = ['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal', 'SSTI', 'RCE']
        exfil_types = ['Data Exfiltration', 'Privilege Escalation']
        
        has_recon = any(t in recon_types for t in threat_types)
        has_exploit = any(t in exploit_types for t in threat_types)
        has_exfil = any(t in exfil_types for t in threat_types)
        
        return has_recon and has_exploit and has_exfil
    
    def _has_repeated_attacks(self, threat_types: list) -> bool:
        """Check if same attack type repeated"""
        from collections import Counter
        counts = Counter(threat_types)
        return any(count >= 3 for count in counts.values())
