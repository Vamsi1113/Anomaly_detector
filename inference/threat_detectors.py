"""
Rule-Based Threat Detectors
Pure Python functions for threat classification (NO ML)
Enhanced with context-aware detection and false positive reduction
"""
import re
from urllib.parse import unquote
from typing import Optional
import pandas as pd


# ============================================================================
# LEGITIMATE TRAFFIC WHITELIST
# ============================================================================

# Legitimate paths that should NOT be flagged
LEGITIMATE_PATHS = [
    # App Store / Mobile App Downloads
    r"/appmart/rest/download(IPA|APK|Plist)",
    r"/app/rails/active_storage/blobs/",
    
    # Authentication Systems (SiteMinder, SAML, OAuth)
    r"/utxLogin/(login|sLogin)",
    r"/auth/",
    r"/sso/",
    r"/saml/",
    r"/oauth/",
    
    # Learning Management Systems
    r"/ScormEngineInterface/",
    r"/lms/",
    
    # Content Management Systems
    r"/CMSApp/",
    r"/cms/",
    
    # API Endpoints
    r"/api/",
    r"/rest/",
    
    # Static Resources
    r"/assets/",
    r"/static/",
    r"/resources/",
    r"\.css$",
    r"\.js$",
    r"\.png$",
    r"\.jpg$",
    r"\.gif$",
    r"\.ico$"
]

# Legitimate User Agents
LEGITIMATE_AGENTS = [
    r"com\.apple\.appstored",  # Apple App Store
    r"Mozilla/5\.0.*Safari",   # Real browsers
    r"Chrome/",
    r"Firefox/",
    r"Edge/"
]

# Legitimate parameters that contain encoded data
LEGITIMATE_ENCODED_PARAMS = [
    "jwt",           # JSON Web Tokens
    "token",         # Authentication tokens
    "REALMOID",      # SiteMinder realm ID
    "SMAGENTNAME",   # SiteMinder agent
    "TARGET",        # SiteMinder target
    "GUID",          # Global unique identifier
    "saml",          # SAML assertions
    "state",         # OAuth state
    "code"           # OAuth authorization code
]


# ============================================================================
# ENHANCED THREAT DETECTION PATTERNS
# ============================================================================

# XSS Patterns (More Precise)
XSS_PATTERNS = [
    r"<script[^>]*>.*</script>",
    r"javascript:\s*alert\s*\(",
    r"onerror\s*=\s*[\"'].*[\"']",
    r"onload\s*=\s*[\"'].*[\"']",
    r"<iframe[^>]*src\s*=\s*[\"']javascript:",
    r"eval\s*\(\s*[\"'].*[\"']\s*\)",
    r"document\.cookie\s*=",
    r"<svg[^>]*onload\s*="
]

# SQL Injection Patterns (Context-Aware)
SQLI_PATTERNS = [
    r"sqlmap",
    r"union\s+select\s+",
    r"'\s*or\s*'1'\s*=\s*'1",
    r"'\s*or\s*1\s*=\s*1",
    r"admin'\s*--",
    r"'\s*;\s*drop\s+table",
    r"'\s*;\s*insert\s+into",
    r"select\s+\*\s+from\s+\w+",
    r"'\s*union\s+select\s+null",
    r"'\s*and\s+1\s*=\s*0\s+union\s+select",
    r"benchmark\s*\(\s*\d+",
    r"sleep\s*\(\s*\d+\s*\)",
    r"waitfor\s+delay\s+",
    r"pg_sleep\s*\("
]

# Path Traversal / LFI Patterns (More Specific)
TRAVERSAL_PATTERNS = [
    r"\.\.\/\.\.\/",           # Multiple directory traversals
    r"\.\.\\\.\.\\",           # Windows traversal
    r"%2e%2e%2f%2e%2e%2f",    # URL encoded traversal
    r"%252e%252e%252f",        # Double URL encoded
    r"/etc/passwd",
    r"/etc/shadow",
    r"/proc/self/environ",
    r"/windows/system32/",
    r"file:///etc/",
    r"file:///c:/",
    r"\.\.\/.*\.\.\/.*etc",
    r"\.\.\\.*\.\.\\.*windows"
]

# Command Injection / RCE Patterns (Precise)
CMD_PATTERNS = [
    r";\s*rm\s+-rf",
    r";\s*cat\s+/etc/passwd",
    r"&&\s*whoami",
    r"\|\s*bash\s*-c",
    r";\s*wget\s+http",
    r"`.*`",                   # Command substitution
    r"\$\(.*\)",              # Command substitution
    r"exec\s*\(\s*[\"'].*[\"']\s*\)",
    r"system\s*\(\s*[\"'].*[\"']\s*\)",
    r"shell_exec\s*\(",
    r"passthru\s*\(",
    r"eval\s*\(\s*\$_"
]

# SSRF Patterns (Specific)
SSRF_PATTERNS = [
    r"169\.254\.169\.254",     # AWS metadata
    r"metadata\.google\.internal",
    r"url=https?://localhost",
    r"url=https?://127\.0\.0\.1",
    r"url=https?://0\.0\.0\.0",
    r"redirect=https?://",
    r"fetch\?url=https?://",
    r"proxy\?url=https?://"
]

# IDOR Patterns (High Confidence)
IDOR_PATTERNS = [
    r"/api/users?/\d{6,}",     # Large user IDs (6+ digits)
    r"/profile/\d{6,}",
    r"user_?id=\d{6,}",
    r"account_?id=\d{6,}",
    r"/admin/users?/\d+",
    r"/api/orders?/\d{6,}"
]

# SSTI (Server-Side Template Injection) Patterns
SSTI_PATTERNS = [
    r"\{\{\s*.*\s*\}\}",      # Jinja2, Twig
    r"\$\{\s*.*\s*\}",        # Freemarker, Spring EL
    r"<%\s*.*\s*%>",          # JSP, ASP
    r"#\{\s*.*\s*\}",         # Ruby ERB
    r"\{\%\s*.*\s*\%\}"       # Twig
]

# Open Redirect Patterns (Specific)
OPEN_REDIRECT_PATTERNS = [
    r"redirect\?url=https?://(?![\w.-]+\.company\.net)",
    r"next=https?://(?![\w.-]+\.company\.net)",
    r"return_?to=https?://(?![\w.-]+\.company\.net)",
    r"goto=https?://(?![\w.-]+\.company\.net)",
    r"url=//(?![\w.-]+\.company\.net)"
]

# Sensitive File Disclosure Patterns
SENSITIVE_FILE_PATTERNS = [
    r"\.env$",
    r"\.git/config",
    r"\.svn/entries",
    r"config\.php$",
    r"web\.config$",
    r"\.htaccess$",
    r"\.htpasswd$",
    r"credentials\.txt",
    r"password\.txt",
    r"\.bak$",
    r"\.backup$",
    r"\.sql$",
    r"dump\.sql$",
    r"phpinfo\.php"
]

# Privilege Escalation Patterns (Context-Aware)
PRIV_ESC_PATTERNS = [
    r"/admin(?!/assets|/css|/js|/images)",  # Exclude static resources
    r"role=admin(?!istrator)",              # Exclude "administrator"
    r"isAdmin=true",
    r"privilege=1",
    r"sudo\s+",
    r"/root/",
    r"escalate"
]

# Data Exfiltration Patterns (Refined)
EXFIL_PATTERNS = [
    r"/export/(?!css|js|images)",          # Exclude static exports
    r"/backup(?!/css|/js|/images)",        # Exclude static backups
    r"/dump(?!/css|/js|/images)",          # Exclude static dumps
    r"\.zip$",
    r"\.tar\.gz$",
    r"\.rar$",
    r"data=.*base64",
    r"download.*\.sql",
    r"export.*\.csv"
]

# PHP Object Injection Patterns (NEW)
PHP_OBJECT_INJECTION_PATTERNS = [
    r"O:\d+:",                             # PHP serialized object
    r"a:\d+:\{",                          # PHP serialized array
    r"s:\d+:",                            # PHP serialized string
    r"i:\d+;",                            # PHP serialized integer
    r"b:[01];",                           # PHP serialized boolean
    r"N;",                                # PHP serialized null
    r"__wakeup",                          # PHP magic method
    r"__destruct",                        # PHP magic method
    r"__toString",                        # PHP magic method
    r"unserialize\s*\(",                  # PHP unserialize function
    r"eval\s*\(\s*base64_decode"          # Common payload pattern
]

# Suspicious User Agents (Refined)
BAD_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "metasploit",
    "burp", "acunetix", "nessus", "openvas", "w3af",
    "dirbuster", "gobuster", "ffuf", "wfuzz",
    "python-requests/", "curl/", "wget/",
    "scanner", "bot", "crawler"
]


# ============================================================================
# WHITELIST CHECKING FUNCTIONS
# ============================================================================

def is_legitimate_path(uri: str) -> bool:
    """Check if URI matches legitimate traffic patterns"""
    if not uri:
        return False
    
    return any(re.search(pattern, uri, re.IGNORECASE) for pattern in LEGITIMATE_PATHS)


def is_legitimate_agent(user_agent: str) -> bool:
    """Check if user agent is legitimate"""
    if not user_agent:
        return False
    
    return any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in LEGITIMATE_AGENTS)


def has_legitimate_encoded_params(uri: str) -> bool:
    """Check if URI contains legitimate encoded parameters"""
    if not uri:
        return False
    
    # Check if URI contains legitimate parameters that might have encoded data
    return any(param in uri.lower() for param in LEGITIMATE_ENCODED_PARAMS)


def is_false_positive_context(uri: str, user_agent: str) -> bool:
    """
    Specific false positive detection - only for very obvious legitimate traffic
    Returns True if this is likely legitimate traffic
    """
    # Only check very specific legitimate patterns - be conservative
    if is_legitimate_path(uri) and is_legitimate_agent(user_agent):
        # Both path AND agent must be legitimate for whitelist
        return True
    
    # Check for common false positive patterns (static resources only)
    static_patterns = [
        r"apple-touch-icon",      # Apple touch icons
        r"favicon\.ico",          # Favicons
        r"manifest\.json",        # Web app manifests
        r"robots\.txt",           # Robots.txt
        r"sitemap\.xml",          # Sitemaps
        r"\.well-known/",         # Well-known URIs
        r"\.(css|js|png|jpg|gif|ico|svg)$"  # Static files
    ]
    
    return any(re.search(pattern, uri, re.IGNORECASE) for pattern in static_patterns)


# ============================================================================
# ENHANCED THREAT DETECTORS
# ============================================================================

def detect_xss(uri: str, user_agent: str = "") -> bool:
    """Detect XSS attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in XSS_PATTERNS)


def detect_sql_injection(uri: str, user_agent: str = "") -> bool:
    """Detect SQL injection attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip if it's static resources or very obvious legitimate traffic
    if is_false_positive_context(uri, user_agent):
        return False
    
    # Special handling for legitimate encoded parameters - be more specific
    if user_agent and "com.apple.appstored" in user_agent.lower():
        # Apple App Store requests with tokens are legitimate
        if any(param in uri.lower() for param in ["token=", "jwt="]):
            return False
    
    # Check for SiteMinder SSO - only skip if it's clearly SSO
    if "/utxLogin/" in uri and any(param in uri for param in ["REALMOID=", "SMAGENTNAME=", "TYPE="]):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in SQLI_PATTERNS)


def detect_path_traversal(uri: str, user_agent: str = "") -> bool:
    """Detect path traversal / LFI attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    decoded = unquote(uri.lower())
    return any(re.search(p, decoded, re.IGNORECASE) for p in TRAVERSAL_PATTERNS)


def detect_command_injection(uri: str, user_agent: str = "") -> bool:
    """Detect command injection / RCE attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in CMD_PATTERNS)
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in CMD_PATTERNS)


def detect_ssrf(uri: str, user_agent: str = "") -> bool:
    """Detect SSRF attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in SSRF_PATTERNS)


def detect_idor(uri: str, user_agent: str = "") -> bool:
    """Detect IDOR attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    return any(re.search(p, uri, re.IGNORECASE) for p in IDOR_PATTERNS)


def detect_ssti(uri: str, user_agent: str = "") -> bool:
    """Detect SSTI attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    return any(re.search(p, uri, re.IGNORECASE) for p in SSTI_PATTERNS)


def detect_open_redirect(uri: str, user_agent: str = "") -> bool:
    """Detect open redirect attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in OPEN_REDIRECT_PATTERNS)


def detect_sensitive_file_access(uri: str, user_agent: str = "") -> bool:
    """Detect sensitive file disclosure attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in SENSITIVE_FILE_PATTERNS)


def detect_privilege_escalation(uri: str, user_agent: str = "") -> bool:
    """Detect privilege escalation attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in PRIV_ESC_PATTERNS)


def detect_data_exfiltration(uri: str, response_size: int, user_agent: str = "") -> bool:
    """Detect data exfiltration attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    # Allow large downloads ONLY from specific legitimate app store with legitimate user agent
    if (re.search(r"/appmart/rest/download", uri, re.IGNORECASE) and 
        user_agent and "com.apple.appstored" in user_agent.lower()):
        return False
    
    # Allow large API responses for specific legitimate endpoints (be more restrictive)
    if (re.search(r"/(api|rest)/", uri, re.IGNORECASE) and 
        response_size < 10_000_000 and  # Reduced from 50MB to 10MB
        not any(suspicious in uri.lower() for suspicious in ["export", "dump", "backup"])):
        return False
    
    return (
        any(re.search(p, uri.lower(), re.IGNORECASE) for p in EXFIL_PATTERNS) or
        response_size > 50_000_000  # Reduced from 100MB to 50MB
    )


def detect_php_object_injection(uri: str, user_agent: str = "") -> bool:
    """Detect PHP Object Injection attempts with targeted false positive reduction"""
    if not uri:
        return False
    
    # Only skip static resources
    if is_false_positive_context(uri, user_agent):
        return False
    
    # Decode URL to catch encoded payloads
    decoded = unquote(uri)
    return any(re.search(p, decoded, re.IGNORECASE) for p in PHP_OBJECT_INJECTION_PATTERNS)


def detect_bruteforce(records, current_ip: str, window: int = 60, threshold: int = 10) -> bool:
    """Detect brute force attempts (behavioral) with higher threshold"""
    if not records or not current_ip:
        return False
    
    failures = sum(
        1 for r in records
        if hasattr(r, 'client_ip') and r.client_ip == current_ip
        and hasattr(r, 'status_code') and r.status_code in [401, 403, 429]
    )
    return failures >= threshold


def detect_suspicious_agent(user_agent: str) -> bool:
    """Detect suspicious user agents with false positive reduction"""
    if not user_agent:
        return False
    
    # Skip legitimate agents
    if is_legitimate_agent(user_agent):
        return False
    
    ua = user_agent.lower()
    return any(a in ua for a in BAD_AGENTS)


# ============================================================================
# THREAT CLASSIFIER WITH CONFIDENCE
# ============================================================================

def classify_threat_with_confidence(uri: str, user_agent: str, response_size: int, status_code: int, records=None, client_ip: str = None) -> tuple:
    """
    Classify threat type using deterministic rules with confidence score
    Enhanced with targeted false positive reduction and PHP Object Injection detection
    
    Returns:
        (threat_type: str, confidence: float)
    """
    # Priority 1: Code Execution Threats (Most Critical) - High Confidence
    if detect_command_injection(uri, user_agent):
        return "Command Injection", 0.95
    
    if detect_ssti(uri, user_agent):
        return "SSTI", 0.95
    
    # Priority 2: Injection Attacks - High Confidence
    if detect_php_object_injection(uri, user_agent):  # NEW
        return "PHP Object Injection", 0.92
    
    if detect_sql_injection(uri, user_agent):
        return "SQL Injection", 0.90
    
    if detect_xss(uri, user_agent):
        return "XSS", 0.90
    
    # Priority 3: File Access Attacks - High Confidence
    if detect_path_traversal(uri, user_agent):
        return "Path Traversal", 0.92
    
    if detect_sensitive_file_access(uri, user_agent):
        return "Sensitive File Disclosure", 0.88
    
    # Priority 4: Network Attacks - Medium-High Confidence
    if detect_ssrf(uri, user_agent):
        return "SSRF", 0.85
    
    # Priority 5: Authorization Attacks - Medium Confidence
    if detect_idor(uri, user_agent):
        return "IDOR", 0.75
    
    if detect_privilege_escalation(uri, user_agent):
        return "Privilege Escalation", 0.80
    
    # Priority 6: Data Attacks - Medium Confidence
    if detect_data_exfiltration(uri, response_size, user_agent):
        return "Data Exfiltration", 0.78
    
    # Priority 7: Redirect Attacks - Medium Confidence
    if detect_open_redirect(uri, user_agent):
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
