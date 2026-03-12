"""
Entity Risk Scoring and IP Tracking - Layer 8
Maintains stateful risk scores per IP address, tracking events, campaigns, and attack paths over time.
Provides entity-level Threat Scoring Graphs similar to industry XDR.
"""
from typing import Dict, List, Any
from collections import defaultdict
import datetime
import logging

logger = logging.getLogger(__name__)

class IPRiskTracker:
    """Tracks and scores risk at the entity (IP address) level over time."""
    
    def __init__(self):
        # IP -> { score: float, event_count: int, campaigns: int, attack_paths: List[str], ... }
        self.ip_profiles = defaultdict(lambda: {
            'risk_score': 0.0,
            'event_count': 0,
            'campaign_count': 0,
            'first_seen': None,
            'last_seen': None,
            'threat_types': set(),
            'attack_stages': set(),
            'attack_paths': []
        })
    
    def update_from_threats(self, threats: List[Dict[str, Any]]):
        """Update IP profiles based on individual threat detections."""
        for threat in threats:
            ip = threat.get('identifier', 'unknown')
            if ip == 'unknown':
                continue
            
            profile = self.ip_profiles[ip]
            profile['event_count'] += 1
            
            # Simple timestamp tracking
            ts = threat.get('timestamp')
            if ts:
                if not profile['first_seen'] or ts < profile['first_seen']:
                    profile['first_seen'] = ts
                if not profile['last_seen'] or ts > profile['last_seen']:
                    profile['last_seen'] = ts
            
            threat_type = threat.get('threat_type')
            if threat_type:
                profile['threat_types'].add(threat_type)
            
            stage = threat.get('attack_stage')
            if stage and stage != 'Unknown':
                profile['attack_stages'].add(stage)
                
            # Increment base risk score - higher severity adds more to the rolling score
            severity = threat.get('severity', 'low')
            if severity == 'critical':
                profile['risk_score'] += 2.0
            elif severity == 'high':
                profile['risk_score'] += 1.0
            elif severity == 'medium':
                profile['risk_score'] += 0.5
            elif severity == 'low':
                profile['risk_score'] += 0.1
                
            # Cap risk score
            profile['risk_score'] = min(max(profile['risk_score'], 0.0), 100.0)
            
    def update_from_campaigns(self, campaigns: List[Any]):
        """Update IP profiles based on clustered campaigns (stronger signals)."""
        for campaign in campaigns:
            ip = campaign.source_ip
            if not ip or ip == 'unknown':
                continue
                
            profile = self.ip_profiles[ip]
            profile['campaign_count'] += 1
            
            # Significant boost for coordinated campaigns
            severity = campaign.severity
            if severity == 'critical':
                profile['risk_score'] += 15.0
            elif severity == 'high':
                profile['risk_score'] += 10.0
            elif severity == 'medium':
                profile['risk_score'] += 5.0
                
            # Track attack paths (progression of stages)
            if campaign.attack_stages:
                path = " -> ".join(campaign.attack_stages)
                if path not in profile['attack_paths']:
                    profile['attack_paths'].append(path)
                    
            profile['risk_score'] = min(max(profile['risk_score'], 0.0), 100.0)

    def get_top_risky_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the highest risk IPs with their stats."""
        scored_ips = []
        for ip, stats in self.ip_profiles.items():
            if stats['risk_score'] > 0:
                scored_ips.append({
                    'ip': ip,
                    'risk_score': round(stats['risk_score'], 2),
                    'event_count': stats['event_count'],
                    'campaign_count': stats['campaign_count'],
                    'threat_types': list(stats['threat_types']),
                    'attack_stages': list(stats['attack_stages']),
                    'attack_paths': stats['attack_paths']
                })
        
        scored_ips.sort(key=lambda x: x['risk_score'], reverse=True)
        return scored_ips[:limit]
        
    def reset(self):
        """Reset the risk tracker."""
        self.ip_profiles.clear()
