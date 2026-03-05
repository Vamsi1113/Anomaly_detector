"""
MITRE ATT&CK Mapping Module
Deterministic mapping between detected threats and MITRE ATT&CK framework
"""
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping"""
    technique_id: str
    technique_name: str
    tactic: str
    attack_stage: str
    description: str
    severity_modifier: float  # Multiplier for risk score (0.8-1.2)


# ============================================================================
# MITRE ATT&CK TECHNIQUE MAPPINGS
# ============================================================================

MITRE_MAPPINGS = {
    # Injection Attacks
    "SQL Injection": MITREMapping(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        attack_stage="Exploitation",
        description="SQL injection to exploit database vulnerabilities",
        severity_modifier=1.2
    ),
    
    "XSS": MITREMapping(
        technique_id="T1059.007",
        technique_name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        attack_stage="Exploitation",
        description="Cross-site scripting to execute malicious JavaScript",
        severity_modifier=1.1
    ),
    
    "Command Injection": MITREMapping(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        attack_stage="Exploitation",
        description="OS command injection for arbitrary code execution",
        severity_modifier=1.3
    ),
    
    "SSTI": MITREMapping(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        attack_stage="Exploitation",
        description="Server-side template injection for code execution",
        severity_modifier=1.3
    ),
    
    "RCE": MITREMapping(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        attack_stage="Exploitation",
        description="Remote code execution vulnerability",
        severity_modifier=1.3
    ),
    
    # File Access & Traversal
    "Path Traversal": MITREMapping(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        attack_stage="Reconnaissance",
        description="Directory traversal to access unauthorized files",
        severity_modifier=1.1
    ),
    
    "Sensitive File Disclosure": MITREMapping(
        technique_id="T1005",
        technique_name="Data from Local System",
        tactic="Collection",
        attack_stage="Collection",
        description="Unauthorized access to sensitive configuration files",
        severity_modifier=1.0
    ),
    
    # Network Attacks
    "SSRF": MITREMapping(
        technique_id="T1090",
        technique_name="Proxy",
        tactic="Command and Control",
        attack_stage="Lateral Movement",
        description="Server-side request forgery for internal network access",
        severity_modifier=1.2
    ),
    
    # Authentication & Authorization
    "Brute Force": MITREMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        attack_stage="Credential Access",
        description="Brute force attack to guess credentials",
        severity_modifier=1.1
    ),
    
    "IDOR": MITREMapping(
        technique_id="T1134",
        technique_name="Access Token Manipulation",
        tactic="Privilege Escalation",
        attack_stage="Privilege Escalation",
        description="Insecure direct object reference for unauthorized access",
        severity_modifier=1.0
    ),
    
    "Privilege Escalation": MITREMapping(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        attack_stage="Privilege Escalation",
        description="Attempt to gain elevated privileges",
        severity_modifier=1.2
    ),
    
    # Data Exfiltration
    "Data Exfiltration": MITREMapping(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        attack_stage="Exfiltration",
        description="Large data transfer indicating potential exfiltration",
        severity_modifier=1.2
    ),
    
    # Reconnaissance
    "Reconnaissance": MITREMapping(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic="Reconnaissance",
        attack_stage="Reconnaissance",
        description="Active scanning using automated tools",
        severity_modifier=0.9
    ),
    
    # Redirects & Phishing
    "Open Redirect": MITREMapping(
        technique_id="T1566",
        technique_name="Phishing",
        tactic="Initial Access",
        attack_stage="Initial Access",
        description="Open redirect vulnerability for phishing attacks",
        severity_modifier=0.9
    ),
    
    # Behavioral Patterns
    "Rate Abuse": MITREMapping(
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        tactic="Impact",
        attack_stage="Impact",
        description="Excessive requests causing resource exhaustion",
        severity_modifier=0.8
    ),
    
    "Enumeration": MITREMapping(
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="Discovery",
        attack_stage="Reconnaissance",
        description="Systematic enumeration of resources or accounts",
        severity_modifier=0.9
    ),
    
    "Burst Activity": MITREMapping(
        technique_id="T1595.001",
        technique_name="Active Scanning: Scanning IP Blocks",
        tactic="Reconnaissance",
        attack_stage="Reconnaissance",
        description="Burst of automated scanning activity",
        severity_modifier=0.8
    ),
}


# ============================================================================
# MITRE ATTACK MAPPER
# ============================================================================

class MITREAttackMapper:
    """Maps detected threats to MITRE ATT&CK framework"""
    
    @staticmethod
    def get_mapping(threat_type: str) -> Optional[MITREMapping]:
        """
        Get MITRE ATT&CK mapping for a threat type
        
        Args:
            threat_type: Detected threat type
        
        Returns:
            MITREMapping if found, None otherwise
        """
        return MITRE_MAPPINGS.get(threat_type)
    
    @staticmethod
    def get_all_mappings() -> Dict[str, MITREMapping]:
        """Get all MITRE mappings"""
        return MITRE_MAPPINGS.copy()
    
    @staticmethod
    def get_tactics() -> List[str]:
        """Get all unique tactics"""
        return list(set(m.tactic for m in MITRE_MAPPINGS.values()))
    
    @staticmethod
    def get_attack_stages() -> List[str]:
        """Get all unique attack stages"""
        return list(set(m.attack_stage for m in MITRE_MAPPINGS.values()))
    
    @staticmethod
    def enrich_threat_with_mitre(threat_dict: Dict) -> Dict:
        """
        Enrich threat detection with MITRE ATT&CK information
        
        Args:
            threat_dict: Threat detection dictionary
        
        Returns:
            Enriched threat dictionary with MITRE fields
        """
        threat_type = threat_dict.get('threat_type', 'Other')
        mapping = MITREAttackMapper.get_mapping(threat_type)
        
        if mapping:
            threat_dict['mitre_technique'] = mapping.technique_id
            threat_dict['mitre_technique_name'] = mapping.technique_name
            threat_dict['mitre_tactic'] = mapping.tactic
            threat_dict['attack_stage'] = mapping.attack_stage
            threat_dict['mitre_description'] = mapping.description
        else:
            threat_dict['mitre_technique'] = "N/A"
            threat_dict['mitre_technique_name'] = "N/A"
            threat_dict['mitre_tactic'] = "N/A"
            threat_dict['attack_stage'] = "Unknown"
            threat_dict['mitre_description'] = "No MITRE mapping available"
        
        return threat_dict
    
    @staticmethod
    def get_severity_modifier(threat_type: str) -> float:
        """
        Get severity modifier for threat type
        
        Args:
            threat_type: Detected threat type
        
        Returns:
            Severity modifier (0.8-1.3)
        """
        mapping = MITREAttackMapper.get_mapping(threat_type)
        return mapping.severity_modifier if mapping else 1.0
