"""
Signature Detection Engine - Layer 1
Deterministic pattern matching for known attack signatures
Enhanced with false positive reduction
"""
import re
from urllib.parse import unquote
from typing import Dict, Any
from dataclasses import dataclass
from inference.threat_detectors import classify_threat_with_confidence


@dataclass
class SignatureResult:
    """Result from signature detection"""
    signature_flag: bool
    threat_type: str
    signature_confidence: float
    matched_patterns: list


class SignatureEngine:
    """Layer 1: Signature-based threat detection with enhanced false positive reduction"""
    
    def __init__(self):
        self.detection_count = 0
    
    def detect(self, uri: str, user_agent: str, response_size: int, status_code: int) -> SignatureResult:
        """
        Run signature detection on a single record using enhanced detection
        
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
        
        # Use enhanced threat classification with false positive reduction
        threat_type, confidence = classify_threat_with_confidence(
            uri=uri,
            user_agent=user_agent,
            response_size=response_size,
            status_code=status_code,
            records=None,  # Not available at this layer
            client_ip=None  # Not available at this layer
        )
        
        # Check if a threat was detected
        if threat_type != "Other" and confidence > 0.0:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type=threat_type,
                signature_confidence=confidence,
                matched_patterns=[f"{threat_type.lower()}_pattern"]
            )
        
        # No signature match
        return SignatureResult(
            signature_flag=False,
            threat_type="Other",
            signature_confidence=0.0,
            matched_patterns=[]
        )
