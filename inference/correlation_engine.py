"""
Enhanced Correlation Engine - Layer 5
Advanced multi-stage attack and campaign detection with MITRE ATT&CK context
"""
from typing import List, Dict, Any
from collections import Counter, defaultdict
import logging

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Layer 5: Enhanced attack campaign and multi-stage threat correlation"""
    
    def __init__(self):
        self.ip_activity = {}
    
    def analyze_attack_chain(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enhanced analysis for multi-stage attack patterns and campaigns
        
        Args:
            results: List of threat detection results with MITRE mappings
        
        Returns:
            Dictionary with enhanced correlation findings
        """
        logger.info(f"Running enhanced correlation analysis on {len(results)} results")
        
        # Group threats by IP with MITRE context
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
                        'uri': result.get('uri', ''),
                        'mitre_technique': result.get('mitre_technique', 'N/A'),
                        'mitre_tactic': result.get('mitre_tactic', 'N/A'),
                        'attack_stage': result.get('attack_stage', 'Unknown')
                    })
        
        # Detect attack campaigns
        campaigns = []
        apt_campaigns = []
        automated_campaigns = []
        reconnaissance_campaigns = []
        
        for ip, threats in ip_threats.items():
            if len(threats) >= 3:
                threat_types = [t['threat_type'] for t in threats]
                attack_stages = [t['attack_stage'] for t in threats]
                tactics = [t['mitre_tactic'] for t in threats]
                
                # Pattern 1: Advanced Persistent Threat (APT) - Multi-stage with progression
                if self._has_attack_progression(attack_stages, tactics):
                    campaign = {
                        'ip': ip,
                        'type': 'Advanced Persistent Threat (APT)',
                        'threat_count': len(threats),
                        'severity': 'CRITICAL',
                        'description': f'Multi-stage attack progression detected: {self._get_attack_chain_summary(attack_stages)}',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics)),
                        'kill_chain_coverage': self._calculate_kill_chain_coverage(attack_stages)
                    }
                    campaigns.append(campaign)
                    apt_campaigns.append(campaign)
                    logger.warning(f"⚠️  APT detected from {ip}: {len(threats)} threats across {len(set(attack_stages))} stages")
                
                # Pattern 2: Automated Attack Campaign - Repeated attacks
                elif self._has_repeated_attacks(threat_types):
                    campaign = {
                        'ip': ip,
                        'type': 'Automated Attack Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Automated tool detected: {len(threats)} repeated attacks',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics)),
                        'automation_confidence': self._calculate_automation_confidence(threat_types)
                    }
                    campaigns.append(campaign)
                    automated_campaigns.append(campaign)
                    logger.warning(f"⚠️  Automated campaign from {ip}: {len(threats)} threats")
                
                # Pattern 3: Reconnaissance Campaign - Scanning activity
                elif self._has_reconnaissance_pattern(attack_stages):
                    campaign = {
                        'ip': ip,
                        'type': 'Reconnaissance Campaign',
                        'threat_count': len(threats),
                        'severity': 'MEDIUM',
                        'description': f'Active scanning detected: {len(threats)} reconnaissance attempts',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics)),
                        'scan_intensity': 'High' if len(threats) > 10 else 'Medium'
                    }
                    campaigns.append(campaign)
                    reconnaissance_campaigns.append(campaign)
                    logger.info(f"Reconnaissance campaign from {ip}: {len(threats)} attempts")
                
                # Pattern 4: Lateral Movement - Multiple exploitation attempts
                elif self._has_lateral_movement(attack_stages, tactics):
                    campaign = {
                        'ip': ip,
                        'type': 'Lateral Movement Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Lateral movement detected: {len(threats)} exploitation attempts',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics))
                    }
                    campaigns.append(campaign)
                    logger.warning(f"⚠️  Lateral movement from {ip}: {len(threats)} threats")
        
        # Compute enhanced correlation statistics
        total_threats = sum(len(threats) for threats in ip_threats.values())
        unique_ips = len(ip_threats)
        
        # Analyze MITRE tactic distribution
        all_tactics = []
        all_stages = []
        for threats in ip_threats.values():
            all_tactics.extend([t['mitre_tactic'] for t in threats if t['mitre_tactic'] != 'N/A'])
            all_stages.extend([t['attack_stage'] for t in threats if t['attack_stage'] != 'Unknown'])
        
        tactic_distribution = Counter(all_tactics)
        stage_distribution = Counter(all_stages)
        
        correlation_results = {
            'campaigns': campaigns,
            'total_campaigns': len(campaigns),
            'apt_campaigns': len(apt_campaigns),
            'automated_campaigns': len(automated_campaigns),
            'reconnaissance_campaigns': len(reconnaissance_campaigns),
            'affected_ips': list(ip_threats.keys()),
            'total_threats_analyzed': total_threats,
            'unique_threat_sources': unique_ips,
            'mitre_tactic_distribution': dict(tactic_distribution),
            'attack_stage_distribution': dict(stage_distribution),
            'campaign_details': {
                'apt': apt_campaigns,
                'automated': automated_campaigns,
                'reconnaissance': reconnaissance_campaigns
            }
        }
        
        if len(campaigns) > 0:
            logger.warning(f"⚠️  {len(campaigns)} attack campaigns detected!")
        
        return correlation_results
    
    def _has_attack_progression(self, attack_stages: List[str], tactics: List[str]) -> bool:
        """
        Enhanced APT detection using MITRE ATT&CK kill chain
        Checks for progression: Reconnaissance → Initial Access → Execution → Exfiltration
        """
        stage_set = set(attack_stages)
        tactic_set = set(tactics)
        
        # Check for kill chain progression
        has_recon = 'Reconnaissance' in stage_set
        has_initial_access = 'Initial Access' in stage_set or 'Exploitation' in stage_set
        has_execution = 'Execution' in stage_set or 'Exploitation' in stage_set
        has_impact = 'Exfiltration' in stage_set or 'Impact' in stage_set or 'Collection' in stage_set
        
        # APT requires at least 3 stages including reconnaissance
        stages_count = sum([has_recon, has_initial_access, has_execution, has_impact])
        
        return stages_count >= 3 and has_recon
    
    def _has_repeated_attacks(self, threat_types: List[str]) -> bool:
        """Check if same attack type repeated (automated tool signature)"""
        counts = Counter(threat_types)
        # Automated if any single threat type appears 3+ times
        return any(count >= 3 for count in counts.values())
    
    def _has_reconnaissance_pattern(self, attack_stages: List[str]) -> bool:
        """Check if threats are primarily reconnaissance"""
        recon_count = sum(1 for stage in attack_stages if stage == 'Reconnaissance')
        return recon_count >= len(attack_stages) * 0.7
    
    def _has_lateral_movement(self, attack_stages: List[str], tactics: List[str]) -> bool:
        """Detect lateral movement patterns"""
        has_exploitation = 'Exploitation' in attack_stages
        has_privilege_esc = 'Privilege Escalation' in attack_stages
        has_lateral_tactic = 'Lateral Movement' in tactics
        
        return (has_exploitation and has_privilege_esc) or has_lateral_tactic
    
    def _get_attack_chain_summary(self, attack_stages: List[str]) -> str:
        """Generate human-readable attack chain summary"""
        unique_stages = []
        seen = set()
        for stage in attack_stages:
            if stage not in seen and stage != 'Unknown':
                unique_stages.append(stage)
                seen.add(stage)
        
        return " → ".join(unique_stages[:4])  # Show first 4 stages
    
    def _calculate_kill_chain_coverage(self, attack_stages: List[str]) -> float:
        """Calculate what percentage of the kill chain is covered"""
        kill_chain_stages = {
            'Reconnaissance', 'Initial Access', 'Execution',
            'Persistence', 'Privilege Escalation', 'Defense Evasion',
            'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Impact'
        }
        
        covered_stages = set(attack_stages) & kill_chain_stages
        return len(covered_stages) / len(kill_chain_stages)
    
    def _calculate_automation_confidence(self, threat_types: List[str]) -> float:
        """Calculate confidence that attacks are automated"""
        counts = Counter(threat_types)
        max_repeat = max(counts.values()) if counts else 0
        
        # Higher repetition = higher automation confidence
        return min(0.95, 0.5 + (max_repeat * 0.1))
    
    def reset(self):
        """Reset correlation state"""
        self.ip_activity.clear()
