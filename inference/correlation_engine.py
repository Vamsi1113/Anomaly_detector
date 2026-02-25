"""
Correlation Engine - Layer 5
Multi-stage attack and campaign detection
"""
from typing import List, Dict, Any
from collections import Counter, defaultdict
import logging

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Layer 5: Attack campaign and multi-stage threat correlation"""
    
    def __init__(self):
        self.ip_activity = {}
    
    def analyze_attack_chain(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze results for multi-stage attack patterns and campaigns
        
        Args:
            results: List of threat detection results
        
        Returns:
            Dictionary with correlation findings
        """
        logger.info(f"Running correlation analysis on {len(results)} results")
        
        # Group threats by IP
        ip_threats = defaultdict(list)
        for result in results:
            if result.get('severity') != 'normal':
                ip = result.get('identifier', '')
                if ip:
                    ip_threats[ip].append({
                        'threat_type': result.get('threat_type'),
                        'timestamp': result.get('timestamp'),
                        'severity': result.get('severity'),
                        'confidence': result.get('confidence', 0.0),
                        'uri': result.get('uri', '')
                    })
        
        # Detect attack campaigns
        campaigns = []
        apt_campaigns = []
        automated_campaigns = []
        
        for ip, threats in ip_threats.items():
            if len(threats) >= 3:
                threat_types = [t['threat_type'] for t in threats]
                
                # Pattern 1: Advanced Persistent Threat (APT)
                if self._has_attack_progression(threat_types):
                    campaign = {
                        'ip': ip,
                        'type': 'Advanced Persistent Threat (APT)',
                        'threat_count': len(threats),
                        'severity': 'CRITICAL',
                        'description': f'Multi-stage attack: {" → ".join(set(threat_types[:3]))}',
                        'threat_types': list(set(threat_types))
                    }
                    campaigns.append(campaign)
                    apt_campaigns.append(campaign)
                    logger.warning(f"⚠️  APT detected from {ip}: {len(threats)} threats")
                
                # Pattern 2: Automated Attack Campaign
                elif self._has_repeated_attacks(threat_types):
                    campaign = {
                        'ip': ip,
                        'type': 'Automated Attack Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Repeated attacks: {len(threats)} threats from same source',
                        'threat_types': list(set(threat_types))
                    }
                    campaigns.append(campaign)
                    automated_campaigns.append(campaign)
                    logger.warning(f"⚠️  Automated campaign from {ip}: {len(threats)} threats")
                
                # Pattern 3: Reconnaissance Campaign
                elif self._has_reconnaissance_pattern(threat_types):
                    campaign = {
                        'ip': ip,
                        'type': 'Reconnaissance Campaign',
                        'threat_count': len(threats),
                        'severity': 'MEDIUM',
                        'description': f'Scanning activity: {len(threats)} reconnaissance attempts',
                        'threat_types': list(set(threat_types))
                    }
                    campaigns.append(campaign)
                    logger.info(f"Reconnaissance campaign from {ip}: {len(threats)} attempts")
        
        # Compute correlation statistics
        total_threats = sum(len(threats) for threats in ip_threats.values())
        unique_ips = len(ip_threats)
        
        correlation_results = {
            'campaigns': campaigns,
            'total_campaigns': len(campaigns),
            'apt_campaigns': len(apt_campaigns),
            'automated_campaigns': len(automated_campaigns),
            'affected_ips': list(ip_threats.keys()),
            'total_threats_analyzed': total_threats,
            'unique_threat_sources': unique_ips,
            'campaign_details': {
                'apt': apt_campaigns,
                'automated': automated_campaigns
            }
        }
        
        if len(campaigns) > 0:
            logger.warning(f"⚠️  {len(campaigns)} attack campaigns detected!")
        
        return correlation_results
    
    def _has_attack_progression(self, threat_types: List[str]) -> bool:
        """
        Check if threats show APT progression pattern:
        Reconnaissance → Exploitation → Exfiltration
        """
        recon_types = ['Reconnaissance', 'Sensitive File Disclosure', 'IDOR']
        exploit_types = [
            'SQL Injection', 'XSS', 'Command Injection',
            'Path Traversal', 'SSTI', 'RCE', 'SSRF'
        ]
        exfil_types = ['Data Exfiltration', 'Privilege Escalation']
        
        has_recon = any(t in recon_types for t in threat_types)
        has_exploit = any(t in exploit_types for t in threat_types)
        has_exfil = any(t in exfil_types for t in threat_types)
        
        return has_recon and has_exploit and has_exfil
    
    def _has_repeated_attacks(self, threat_types: List[str]) -> bool:
        """Check if same attack type repeated (automated tool)"""
        counts = Counter(threat_types)
        return any(count >= 3 for count in counts.values())
    
    def _has_reconnaissance_pattern(self, threat_types: List[str]) -> bool:
        """Check if threats are primarily reconnaissance"""
        recon_types = ['Reconnaissance', 'Sensitive File Disclosure', 'IDOR']
        recon_count = sum(1 for t in threat_types if t in recon_types)
        return recon_count >= len(threat_types) * 0.7
    
    def reset(self):
        """Reset correlation state"""
        self.ip_activity.clear()
