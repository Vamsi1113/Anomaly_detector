"""
Behavioral Detection Engine - Layer 2
Stateful analysis across multiple records to detect behavioral anomalies
"""
from typing import List, Dict, Any
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime


@dataclass
class BehaviorResult:
    """Result from behavioral detection"""
    behavior_flag: bool
    behavior_type: str
    behavior_confidence: float
    behavior_details: dict


class BehaviorEngine:
    """Layer 2: Behavioral threat detection"""
    
    def __init__(self):
        self.ip_activity = defaultdict(dict)
        self.detection_count = 0
    
    def analyze_record(self, record, all_records: List) -> BehaviorResult:
        """
        Analyze behavioral patterns for a single record in context of all records
        
        Args:
            record: Current record being analyzed
            all_records: All records for context (NOT USED for performance)
        
        Returns:
            BehaviorResult with detection details
        """
        # Extract record details
        if hasattr(record, 'client_ip'):
            client_ip = record.client_ip
            status_code = getattr(record, 'status_code', 0)
            method = getattr(record, 'method', '')
            uri = getattr(record, 'uri', '')
            
            # Update activity tracking (lightweight counters only)
            activity = self.ip_activity[client_ip]
            activity['request_count'] = activity.get('request_count', 0) + 1
            
            if status_code in [401, 403]:
                activity['failures'] = activity.get('failures', 0) + 1
            
            # Track unique methods and URIs (limited to prevent memory bloat)
            if 'methods' not in activity:
                activity['methods'] = set()
            if 'uris' not in activity:
                activity['uris'] = set()
            
            if len(activity['methods']) < 10:
                activity['methods'].add(method)
            if len(activity['uris']) < 100:
                activity['uris'].add(uri)
            
            # Check for brute force (using tracked failures)
            brute_force_result = self._detect_brute_force_fast(client_ip)
            if brute_force_result.behavior_flag:
                self.detection_count += 1
                return brute_force_result
            
            # Check for rate abuse
            rate_abuse_result = self._detect_rate_abuse_fast(client_ip)
            if rate_abuse_result.behavior_flag:
                self.detection_count += 1
                return rate_abuse_result
            
            # Check for enumeration
            enum_result = self._detect_enumeration_fast(client_ip)
            if enum_result.behavior_flag:
                self.detection_count += 1
                return enum_result
            
            # Check for burst activity
            burst_result = self._detect_burst_activity_fast(client_ip)
            if burst_result.behavior_flag:
                self.detection_count += 1
                return burst_result
        
        # No behavioral anomaly detected
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_brute_force_fast(self, client_ip: str, threshold: int = 5) -> BehaviorResult:
        """Detect brute force attempts based on tracked authentication failures"""
        failures = self.ip_activity[client_ip].get('failures', 0)
        
        if failures >= threshold:
            return BehaviorResult(
                behavior_flag=True,
                behavior_type="Brute Force",
                behavior_confidence=min(0.70 + (failures - threshold) * 0.05, 0.95),
                behavior_details={
                    'failure_count': failures,
                    'threshold': threshold,
                    'description': f'{failures} authentication failures detected'
                }
            )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_rate_abuse_fast(self, client_ip: str, threshold: int = 50) -> BehaviorResult:
        """Detect rate abuse based on request volume"""
        request_count = self.ip_activity[client_ip].get('request_count', 0)
        
        if request_count >= threshold:
            return BehaviorResult(
                behavior_flag=True,
                behavior_type="Rate Abuse",
                behavior_confidence=min(0.65 + (request_count - threshold) * 0.01, 0.90),
                behavior_details={
                    'request_count': request_count,
                    'threshold': threshold,
                    'description': f'{request_count} requests from single IP'
                }
            )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_enumeration_fast(self, client_ip: str, threshold: int = 10) -> BehaviorResult:
        """Detect enumeration based on unique URI patterns"""
        uris = self.ip_activity[client_ip].get('uris', set())
        unique_uris = len(uris)
        
        # Check for sequential ID enumeration
        sequential_pattern = sum(1 for uri in uris if any(char.isdigit() for char in uri))
        
        if unique_uris >= threshold and sequential_pattern >= threshold * 0.7:
            return BehaviorResult(
                behavior_flag=True,
                behavior_type="Enumeration",
                behavior_confidence=0.72,
                behavior_details={
                    'unique_uris': unique_uris,
                    'sequential_count': sequential_pattern,
                    'description': f'Enumeration pattern: {unique_uris} unique URIs'
                }
            )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_burst_activity_fast(self, client_ip: str, threshold: int = 30) -> BehaviorResult:
        """Detect abnormal burst activity"""
        request_count = self.ip_activity[client_ip].get('request_count', 0)
        
        # Simple burst detection: high volume in short time
        if request_count >= threshold:
            methods = self.ip_activity[client_ip].get('methods', set())
            unique_methods = len(methods)
            
            # If using multiple methods, likely automated
            if unique_methods >= 3:
                return BehaviorResult(
                    behavior_flag=True,
                    behavior_type="Burst Activity",
                    behavior_confidence=0.68,
                    behavior_details={
                        'request_count': request_count,
                        'unique_methods': unique_methods,
                        'description': f'Burst: {request_count} requests with {unique_methods} methods'
                    }
                )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def reset(self):
        """Reset behavioral state for new analysis"""
        self.ip_activity.clear()
        self.detection_count = 0
