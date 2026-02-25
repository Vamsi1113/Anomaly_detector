"""
Decision Engine - Layer 4
Signal aggregation and final risk scoring
"""
import numpy as np
from typing import Dict, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AnomalySeverity(Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UnifiedThreat:
    """Unified threat result from decision engine"""
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
    
    # Record details
    uri: str
    status_code: int
    method: str
    duration: int
    response_size: int
    user_agent: str
    referer: str
    
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
            'uri': self.uri,
            'status_code': self.status_code,
            'method': self.method,
            'duration': self.duration,
            'response_size': self.response_size,
            'user_agent': self.user_agent,
            'referer': self.referer,
            'model': 'decision_engine'
        }


class DecisionEngine:
    """Layer 4: Signal aggregation and risk scoring"""
    
    # Weights for signal aggregation
    SIGNATURE_WEIGHT = 0.5
    BEHAVIOR_WEIGHT = 0.2
    ML_WEIGHT = 0.3
    
    # Severity thresholds (original values - kept for accurate classification)
    CRITICAL_THRESHOLD = 0.90
    HIGH_THRESHOLD = 0.75
    MEDIUM_THRESHOLD = 0.60
    LOW_THRESHOLD = 0.40
    
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
        Aggregate signals and make final threat decision
        
        Args:
            record: Original log record
            record_index: Index of record
            signature_result: Result from signature engine
            behavior_result: Result from behavioral engine
            ml_score: Raw ML anomaly score
            ml_score_normalized: Normalized ML score (0-1)
        
        Returns:
            UnifiedThreat with final decision
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
        
        # Calculate weighted risk score
        final_risk_score = (
            sig_confidence * self.SIGNATURE_WEIGHT +
            behav_confidence * self.BEHAVIOR_WEIGHT +
            ml_confidence * self.ML_WEIGHT
        )
        
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
            uri=uri,
            status_code=status_code,
            method=method,
            duration=duration,
            response_size=response_size,
            user_agent=user_agent,
            referer=referer
        )
    
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
