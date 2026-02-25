"""
Signature Detection Engine - Layer 1
Deterministic pattern matching for known attack signatures
"""
import re
from urllib.parse import unquote
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class SignatureResult:
    """Result from signature detection"""
    signature_flag: bool
    threat_type: str
    signature_confidence: float
    matched_patterns: list


# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror=", r"onload=",
    r"<iframe", r"alert\(", r"<img.*onerror", r"eval\(",
    r"document\.cookie", r"<svg.*onload"
]

SQLI_PATTERNS = [
    r"sqlmap", r"union\s+select", r"union.*select",
    r"' or '1'='1", r"' or ", r"--", r";--",
    r"drop\s+table", r"insert\s+into",
    r"select\s+\*\s+from", r"select.*from",
    r"1=1", r"' or 1=1", r"admin'--", r"' OR '1"
]

TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"\.\.",
    r"%2e%2e", r"%252e%252e", r"%2e",
    r"/etc/passwd", r"/etc/shadow",
    r"/proc/self", r"/windows/system32",
    r"password\.properties", r"license\.txt",
    r"CFIDE", r"administrator",
    r"\.\.\/\.\.\/", r"file:///"
]

CMD_PATTERNS = [
    r"rm\s+-rf", r";\s*cat\s+/etc/", r"cat /etc",
    r"&&\s*whoami", r"\|\s*bash", r"whoami",
    r";\s*wget", r"`cat", r"; ls", r"&& ls",
    r"cmd=", r"exec\(", r"system\(", r"shell_exec",
    r"\$\{.*\}", r"bash -c"
]

SSRF_PATTERNS = [
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"localhost", r"127\.0\.0\.1",
    r"0\.0\.0\.0", r"::1",
    r"url=http://", r"fetch\?url=",
    r"redirect.*http://"
]

IDOR_PATTERNS = [
    r"/api/user/\d{5,}",
    r"/profile/\d{5,}",
    r"user_id=\d{5,}",
    r"account=\d{5,}"
]

SSTI_PATTERNS = [
    r"\{\{.*\}\}",
    r"\$\{.*\}",
    r"<%.*%>",
    r"#\{.*\}"
]

OPEN_REDIRECT_PATTERNS = [
    r"redirect\?url=http://",
    r"next=http://",
    r"return_to=http://",
    r"goto=http://",
    r"url=//evil"
]

SENSITIVE_FILE_PATTERNS = [
    r"\.env", r"\.git", r"\.svn",
    r"config\.php", r"web\.config",
    r"credentials", r"password",
    r"\.bak", r"\.backup",
    r"\.sql", r"dump\.sql"
]

PRIV_ESC_PATTERNS = [
    r"/admin", r"administrator", r"sudo",
    r"privilege", r"/root", r"escalate",
    r"role=admin", r"isAdmin=true"
]

EXFIL_PATTERNS = [
    r"/export", r"/download", r"/backup",
    r"/dump", r"\.zip", r"\.tar\.gz",
    r"data=.*base64"
]

BAD_AGENTS = [
    "sqlmap", "nikto", "nmap", "curl",
    "python-requests", "masscan", "metasploit",
    "burp", "scanner", "bot", "crawler",
    "acunetix", "nessus", "openvas"
]


# ============================================================================
# SIGNATURE DETECTION FUNCTIONS
# ============================================================================

def _match_patterns(text: str, patterns: list) -> tuple:
    """Match patterns and return (matched, matched_patterns)"""
    if not text:
        return False, []
    matched = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)
    return len(matched) > 0, matched


class SignatureEngine:
    """Layer 1: Signature-based threat detection"""
    
    def __init__(self):
        self.detection_count = 0
    
    def detect(self, uri: str, user_agent: str, response_size: int, status_code: int) -> SignatureResult:
        """
        Run signature detection on a single record
        
        Args:
            uri: Request URI
            user_agent: User agent string
            response_size: Response size in bytes
            status_code: HTTP status code
        
        Returns:
            SignatureResult with detection details
        """
        if not uri:
            uri = ""
        if not user_agent:
            user_agent = ""
        
        uri_lower = uri.lower()
        decoded_uri = unquote(uri_lower)
        ua_lower = user_agent.lower()
        
        # Priority 1: Code Execution (Critical)
        matched, patterns = _match_patterns(uri_lower, CMD_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Command Injection",
                signature_confidence=0.95,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, SSTI_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="SSTI",
                signature_confidence=0.95,
                matched_patterns=patterns
            )
        
        # Priority 2: Injection Attacks
        matched, patterns = _match_patterns(uri_lower, SQLI_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="SQL Injection",
                signature_confidence=0.90,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, XSS_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="XSS",
                signature_confidence=0.90,
                matched_patterns=patterns
            )
        
        # Priority 3: File Access
        matched, patterns = _match_patterns(decoded_uri, TRAVERSAL_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Path Traversal",
                signature_confidence=0.92,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, SENSITIVE_FILE_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Sensitive File Disclosure",
                signature_confidence=0.88,
                matched_patterns=patterns
            )
        
        # Priority 4: Network Attacks
        matched, patterns = _match_patterns(uri_lower, SSRF_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="SSRF",
                signature_confidence=0.85,
                matched_patterns=patterns
            )
        
        # Priority 5: Authorization
        matched, patterns = _match_patterns(uri, IDOR_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="IDOR",
                signature_confidence=0.75,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, PRIV_ESC_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Privilege Escalation",
                signature_confidence=0.80,
                matched_patterns=patterns
            )
        
        # Priority 6: Data Exfiltration
        matched, patterns = _match_patterns(uri_lower, EXFIL_PATTERNS)
        if matched or response_size > 1_000_000:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Data Exfiltration",
                signature_confidence=0.78,
                matched_patterns=patterns if matched else ["large_response"]
            )
        
        # Priority 7: Redirects
        matched, patterns = _match_patterns(uri_lower, OPEN_REDIRECT_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Open Redirect",
                signature_confidence=0.82,
                matched_patterns=patterns
            )
        
        # Priority 8: Reconnaissance
        if any(agent in ua_lower for agent in BAD_AGENTS):
            self.detection_count += 1
            matched_agents = [a for a in BAD_AGENTS if a in ua_lower]
            return SignatureResult(
                signature_flag=True,
                threat_type="Reconnaissance",
                signature_confidence=0.65,
                matched_patterns=matched_agents
            )
        
        # No signature match
        return SignatureResult(
            signature_flag=False,
            threat_type="Other",
            signature_confidence=0.0,
            matched_patterns=[]
        )
