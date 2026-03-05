"""
Decision Engine - Layer 4
Enhanced signal aggregation with MITRE ATT&CK mapping and false positive reduction
"""
import numpy as np
from typing import Dict, Any
from dataclasses import dataclass
from enum import Enum
import logging
from inference.mitre_attack_mapper import MITREAttackMapper
from inference.false_positive_filter import FalsePositiveFilter

logger = logging.getLogger(__name__)


class AnomalySeverity(Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UnifiedThreat:
    """Unified threat result from decision engine with MITRE ATT&CK mapping"""
    record_index: int
    identifier: str
    timestamp: str
    
    # Final decision
    final_threat_type: str
    final_severity: str
    final_risk_score: float
    
    # Signal breakdown
    signature_confidence: float
    behavior_confidence: float
    anomaly_score: float
    
    # Detection details
    detection_layer: str
    explanation: str
    
    # MITRE ATT&CK mapping
    mitre_technique: str = "N/A"
    mitre_technique_name: str = "N/A"
    mitre_tactic: str = "N/A"
    attack_stage: str = "Unknown"
    mitre_description: str = ""
    
    # Record details
    uri: str = ""
    status_code: int = 0
    method: str = ""
    duration: int = 0
    response_size: int = 0
    user_agent: str = ""
    referer: str = ""
    raw_log: str = ""  # Original raw log entry
    
    def to_dict(self):
        return {
            'record_index': self.record_index,
            'identifier': self.identifier,
            'timestamp': self.timestamp,
            'threat_type': self.final_threat_type,
            'severity': self.final_severity,
            'score': self.final_risk_score,
            'confidence': max(self.signature_confidence, self.behavior_confidence),
            'detection_layer': self.detection_layer,
            'explanation': self.explanation,
            'mitre_technique': self.mitre_technique,
            'mitre_technique_name': self.mitre_technique_name,
            'mitre_tactic': self.mitre_tactic,
            'attack_stage': self.attack_stage,
            'mitre_description': self.mitre_description,
            'uri': self.uri,
            'status_code': self.status_code,
            'method': self.method,
            'duration': self.duration,
            'response_size': self.response_size,
            'user_agent': self.user_agent,
            'referer': self.referer,
            'raw_log': self.raw_log,
            'model': 'decision_engine'
        }


class DecisionEngine:
    """Layer 4: Enhanced signal aggregation with MITRE mapping and FP reduction"""
    
    # IMPROVED WEIGHTS: Prioritize deterministic detection
    SIGNATURE_WEIGHT = 0.5  # Deterministic rules (highest priority)
    BEHAVIOR_WEIGHT = 0.3   # Stateful analysis (increased from 0.2)
    ML_WEIGHT = 0.2         # Statistical anomaly (decreased from 0.3)
    
    # STRICTER THRESHOLDS: Reduce false positives
    CRITICAL_THRESHOLD = 0.90
    HIGH_THRESHOLD = 0.75
    MEDIUM_THRESHOLD = 0.60
    LOW_THRESHOLD = 0.45     # Increased from 0.40
    
    # Critical threat types that must be HIGH or above
    CRITICAL_THREAT_TYPES = [
        "Command Injection",
        "SQL Injection",
        "Path Traversal",
        "SSTI",
        "RCE"
    ]
    
    def __init__(self):
        self.decision_count = 0
        self.fp_filter = FalsePositiveFilter()
        self.mitre_mapper = MITREAttackMapper()
        self.filtered_count = 0
    
    def make_decision(
        self,
        record,
        record_index: int,
        signature_result,
        behavior_result,
        ml_score: float,
        ml_score_normalized: float
    ) -> UnifiedThreat:
        """
        Enhanced threat decision with MITRE mapping and false positive reduction
        
        Args:
            record: Original log record
            record_index: Index of record
            signature_result: Result from signature engine
            behavior_result: Result from behavioral engine
            ml_score: Raw ML anomaly score
            ml_score_normalized: Normalized ML score (0-1)
        
        Returns:
            UnifiedThreat with final decision and MITRE mapping
        """
        # Extract record details
        identifier = getattr(record, 'client_ip', getattr(record, 'identifier', ''))
        timestamp = getattr(record, 'timestamp', '')
        uri = getattr(record, 'uri', '')
        status_code = getattr(record, 'status_code', 0)
        method = getattr(record, 'method', '')
        duration = getattr(record, 'duration', 0)
        response_size = getattr(record, 'response_size', 0)
        user_agent = getattr(record, 'user_agent', '')
        referer = getattr(record, 'raw_row', {}).get('referer', '')
        
        # Get confidence scores
        sig_confidence = signature_result.signature_confidence
        behav_confidence = behavior_result.behavior_confidence
        ml_confidence = ml_score_normalized
        
        # Determine primary threat type and detection layer
        if signature_result.signature_flag:
            final_threat_type = signature_result.threat_type
            detection_layer = "Layer 1: Signature Detection"
            primary_confidence = sig_confidence
        elif behavior_result.behavior_flag:
            final_threat_type = behavior_result.behavior_type
            detection_layer = "Layer 2: Behavioral Detection"
            primary_confidence = behav_confidence
        else:
            final_threat_type = "Other"
            detection_layer = "Layer 3: ML Anomaly Detection"
            primary_confidence = ml_confidence
        
        # FALSE POSITIVE FILTERING
        should_filter, filter_reason = self.fp_filter.should_filter(
            threat_type=final_threat_type,
            uri=uri,
            user_agent=user_agent,
            client_ip=identifier,
            signature_flag=signature_result.signature_flag,
            behavior_flag=behavior_result.behavior_flag,
            ml_score=ml_score_normalized
        )
        
        if should_filter:
            self.filtered_count += 1
            logger.debug(f"Filtered false positive: {filter_reason}")
            # Return as normal (filtered out)
            return self._create_normal_result(
                record_index, identifier, timestamp, uri, status_code,
                method, duration, response_size, user_agent, referer, record
            )
        
        # Calculate base weighted risk score
        base_risk_score = (
            sig_confidence * self.SIGNATURE_WEIGHT +
            behav_confidence * self.BEHAVIOR_WEIGHT +
            ml_confidence * self.ML_WEIGHT
        )
        
        # Apply MITRE severity modifier
        mitre_modifier = self.mitre_mapper.get_severity_modifier(final_threat_type)
        final_risk_score = base_risk_score * mitre_modifier
        
        # Ensure risk score stays in valid range
        final_risk_score = min(1.0, max(0.0, final_risk_score))
        
        # Map risk score to severity
        final_severity = self._map_risk_to_severity(final_risk_score)
        
        # Apply critical threat type enforcement
        if final_threat_type in self.CRITICAL_THREAT_TYPES:
            if final_severity in [AnomalySeverity.LOW.value, AnomalySeverity.MEDIUM.value, AnomalySeverity.NORMAL.value]:
                final_severity = AnomalySeverity.HIGH.value
                logger.debug(f"Enforced HIGH severity for critical threat: {final_threat_type}")
        
        # If any detection layer flagged it, ensure at least LOW severity
        if (signature_result.signature_flag or behavior_result.behavior_flag) and final_severity == AnomalySeverity.NORMAL.value:
            final_severity = AnomalySeverity.LOW.value
            logger.debug(f"Upgraded to LOW severity due to detection flag")
        
        # Get MITRE ATT&CK mapping
        mitre_mapping = self.mitre_mapper.get_mapping(final_threat_type)
        
        # Generate explanation
        explanation = self._generate_explanation(
            final_threat_type,
            final_severity,
            detection_layer,
            primary_confidence,
            signature_result,
            behavior_result,
            ml_score,
            record
        )
        
        # Reconstruct raw log entry
        raw_log = self._reconstruct_raw_log(record)
        
        # Count non-normal detections
        if final_severity != AnomalySeverity.NORMAL.value:
            self.decision_count += 1
        
        return UnifiedThreat(
            record_index=record_index,
            identifier=identifier,
            timestamp=timestamp,
            final_threat_type=final_threat_type,
            final_severity=final_severity,
            final_risk_score=final_risk_score,
            signature_confidence=sig_confidence,
            behavior_confidence=behav_confidence,
            anomaly_score=ml_score,
            detection_layer=detection_layer,
            explanation=explanation,
            mitre_technique=mitre_mapping.technique_id if mitre_mapping else "N/A",
            mitre_technique_name=mitre_mapping.technique_name if mitre_mapping else "N/A",
            mitre_tactic=mitre_mapping.tactic if mitre_mapping else "N/A",
            attack_stage=mitre_mapping.attack_stage if mitre_mapping else "Unknown",
            mitre_description=mitre_mapping.description if mitre_mapping else "",
            uri=uri,
            status_code=status_code,
            method=method,
            duration=duration,
            response_size=response_size,
            user_agent=user_agent,
            referer=referer,
            raw_log=raw_log
        )
    
    def _create_normal_result(
        self,
        record_index: int,
        identifier: str,
        timestamp: str,
        uri: str,
        status_code: int,
        method: str,
        duration: int,
        response_size: int,
        user_agent: str,
        referer: str,
        record
    ) -> UnifiedThreat:
        """Create a normal (non-threat) result"""
        return UnifiedThreat(
            record_index=record_index,
            identifier=identifier,
            timestamp=timestamp,
            final_threat_type="Normal",
            final_severity=AnomalySeverity.NORMAL.value,
            final_risk_score=0.0,
            signature_confidence=0.0,
            behavior_confidence=0.0,
            anomaly_score=0.0,
            detection_layer="Filtered",
            explanation="Normal request (filtered)",
            mitre_technique="N/A",
            mitre_technique_name="N/A",
            mitre_tactic="N/A",
            attack_stage="N/A",
            mitre_description="",
            uri=uri,
            status_code=status_code,
            method=method,
            duration=duration,
            response_size=response_size,
            user_agent=user_agent,
            referer=referer,
            raw_log=self._reconstruct_raw_log(record)
        )
    
    def get_statistics(self) -> Dict:
        """Get decision engine statistics"""
        fp_stats = self.fp_filter.get_statistics()
        return {
            'total_decisions': self.decision_count,
            'filtered_false_positives': self.filtered_count,
            'false_positive_rate': self.filtered_count / max(1, self.decision_count + self.filtered_count),
            **fp_stats
        }
    
    def _map_risk_to_severity(self, risk_score: float) -> str:
        """Map risk score to severity level (original thresholds)"""
        if risk_score >= self.CRITICAL_THRESHOLD:
            return AnomalySeverity.CRITICAL.value
        elif risk_score >= self.HIGH_THRESHOLD:
            return AnomalySeverity.HIGH.value
        elif risk_score >= self.MEDIUM_THRESHOLD:
            return AnomalySeverity.MEDIUM.value
        elif risk_score >= self.LOW_THRESHOLD:
            return AnomalySeverity.LOW.value
        else:
            return AnomalySeverity.NORMAL.value
    
    def _generate_explanation(
        self,
        threat_type: str,
        severity: str,
        detection_layer: str,
        confidence: float,
        signature_result,
        behavior_result,
        ml_score: float,
        record
    ) -> str:
        """Generate detailed explanation of detection"""
        if severity == AnomalySeverity.NORMAL.value:
            return "Normal request"
        
        parts = []
        
        # Add threat type with confidence
        if threat_type != "Other":
            parts.append(f"{threat_type} detected (confidence: {confidence:.0%})")
        else:
            parts.append(f"Anomalous behavior detected (ML score: {ml_score:.3f})")
        
        # Add detection layer
        parts.append(f"via {detection_layer}")
        
        # Add signal details
        signals = []
        if signature_result.signature_flag:
            signals.append(f"signature:{signature_result.signature_confidence:.0%}")
        if behavior_result.behavior_flag:
            signals.append(f"behavior:{behavior_result.behavior_confidence:.0%}")
        if ml_score > 0:
            signals.append(f"ml:{ml_score:.2f}")
        
        if signals:
            parts.append(f"[{', '.join(signals)}]")
        
        # Add HTTP details
        status_code = getattr(record, 'status_code', 0)
        response_size = getattr(record, 'response_size', 0)
        duration = getattr(record, 'duration', 0)
        
        if status_code >= 500:
            parts.append(f"HTTP {status_code}")
        elif status_code >= 400:
            parts.append(f"HTTP {status_code}")
        
        if response_size > 500000:
            parts.append(f"{response_size:,} bytes")
        
        if duration > 3000:
            parts.append(f"{duration}ms")
        
        return "; ".join(parts)

    
    def _reconstruct_raw_log(self, record) -> str:
        """
        Reconstruct the original raw log entry from HTTPRecord
        
        Args:
            record: HTTPRecord or GenericRecord
        
        Returns:
            Reconstructed raw log entry in syslog format
        """
        try:
            # Check if it's an HTTPRecord
            if hasattr(record, 'client_ip') and hasattr(record, 'method'):
                # Extract fields
                timestamp = getattr(record, 'timestamp', '')
                client_ip = getattr(record, 'client_ip', '0.0.0.0')
                method = getattr(record, 'method', 'GET')
                uri = getattr(record, 'uri', '/')
                status_code = getattr(record, 'status_code', 200)
                response_size = getattr(record, 'response_size', 0)
                duration = getattr(record, 'duration', 0)
                user_agent = getattr(record, 'user_agent', 'Unknown')
                
                # Get additional fields from raw_row if available
                raw_row = getattr(record, 'raw_row', {})
                hostname = raw_row.get('hostname', 'server')
                process = raw_row.get('process', 'httpd[12345]')
                dest_ip = raw_row.get('dest_ip', '0.0.0.0')
                port = raw_row.get('port', '0')
                domain = raw_row.get('domain', '-')
                referer = raw_row.get('referer', '-')
                
                # Reconstruct syslog format
                # <priority>timestamp hostname process: src_ip dest_ip port domain - - [timestamp] "METHOD /uri HTTP/1.1" status size duration "referer" "user-agent"
                
                # Determine priority (150 for most logs)
                priority = 150
                
                # Get current date for syslog timestamp (simplified)
                import datetime
                now = datetime.datetime.now()
                syslog_timestamp = now.strftime("%b %d %H:%M:%S")
                
                # Build the raw log
                if port and port != '0' and domain and domain != '-':
                    # Full format with port and domain
                    raw_log = f'<{priority}>{syslog_timestamp} {hostname} {process}: {client_ip} {dest_ip} {port} {domain} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status_code} {response_size} {duration} "{referer}" "{user_agent}"'
                elif domain and domain != '-':
                    # Format with domain but no port
                    raw_log = f'<{priority}>{syslog_timestamp} {hostname} {process}: {client_ip} {dest_ip} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status_code} {response_size} {duration} "{referer}" "{user_agent}"'
                else:
                    # Minimal format
                    raw_log = f'<{priority}>{syslog_timestamp} {hostname} {process}: {client_ip} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status_code} {response_size} {duration} "{referer}" "{user_agent}"'
                
                return raw_log
            else:
                # Generic record - return simple representation
                return f"Record: {getattr(record, 'identifier', 'Unknown')} at {getattr(record, 'timestamp', 'Unknown')}"
        
        except Exception as e:
            logger.warning(f"Failed to reconstruct raw log: {e}")
            return f"[Raw log reconstruction failed: {str(e)}]"
