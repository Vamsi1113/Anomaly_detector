# SOC-Grade Inference Engine - Multi-Layer Detection Architecture
import numpy as np
from typing import List, Dict, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
from parsing import HTTPRecord, GenericRecord
from features import UniversalFeatureExtractor
from models import IsolationForestInference, AutoencoderInference

logger = logging.getLogger(__name__)


# ============================================================================
# DETECTION LAYER ENUM
# ============================================================================

class DetectionLayer(Enum):
    """Multi-layer detection architecture"""
    SIGNATURE = "Layer 1: Signature Detection"
    BEHAVIORAL = "Layer 2: Behavioral Detection"
    ML_ANOMALY = "Layer 3: ML Anomaly Detection"
    CORRELATION = "Layer 4: Correlation Engine"

class AnomalySeverity(Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnomalyResult:
    record_index: int
    identifier: str
    timestamp: str
    score: float
    severity: str
    model: str
    threat_type: str
    explanation: str
    confidence: float = 0.0  # NEW: Confidence score for threat classification
    detection_layer: str = ""  # NEW: Which layer detected the threat
    uri: str = ""
    status_code: int = 0
    method: str = ""
    duration: int = 0
    response_size: int = 0
    user_agent: str = ""
    referer: str = ""
    
    def to_dict(self):
        return {
            'record_index': self.record_index,
            'identifier': self.identifier,
            'timestamp': self.timestamp,
            'score': float(self.score),
            'severity': self.severity,
            'model': self.model,
            'threat_type': self.threat_type,
            'explanation': self.explanation,
            'confidence': float(self.confidence),
            'detection_layer': self.detection_layer,
            'uri': self.uri,
            'status_code': self.status_code,
            'method': self.method,
            'duration': self.duration,
            'response_size': self.response_size,
            'user_agent': self.user_agent,
            'referer': self.referer,
        }


class PercentileSeverityClassifier:
    def __init__(self, scores: np.ndarray):
        self.thresholds = {
            'critical': np.percentile(scores, 99),
            'high': np.percentile(scores, 95),
            'medium': np.percentile(scores, 90),
            'low': np.percentile(scores, 80),
        }
        logger.info(f"Percentile thresholds: {self.thresholds}")
    
    def classify(self, score: float) -> str:
        if score >= self.thresholds['critical']:
            return AnomalySeverity.CRITICAL.value
        elif score >= self.thresholds['high']:
            return AnomalySeverity.HIGH.value
        elif score >= self.thresholds['medium']:
            return AnomalySeverity.MEDIUM.value
        elif score >= self.thresholds['low']:
            return AnomalySeverity.LOW.value
        else:
            return AnomalySeverity.NORMAL.value


class ExplanationGenerator:
    @staticmethod
    def generate_explanation(threat_type: str, severity: str, score: float, record: HTTPRecord, confidence: float, detection_layer: str) -> str:
        """Generate detailed explanation with confidence and detection layer"""
        if severity == AnomalySeverity.NORMAL.value:
            return "Normal request"
        
        parts = []
        
        # Add threat type with confidence
        if threat_type != "Other":
            parts.append(f"{threat_type} detected (confidence: {confidence:.0%})")
        else:
            parts.append(f"Anomalous behavior detected (ML score: {score:.3f})")
        
        # Add detection layer
        parts.append(f"via {detection_layer}")
        
        # Add HTTP details
        if record.status_code >= 500:
            parts.append(f"HTTP {record.status_code}")
        elif record.status_code >= 400:
            parts.append(f"HTTP {record.status_code}")
        
        if record.response_size > 500000:
            parts.append(f"{record.response_size:,} bytes")
        
        if record.duration > 3000:
            parts.append(f"{record.duration}ms")
        
        return "; ".join(parts)


class AnomalyDetectionEngine:
    def __init__(self):
        self.feature_extractor = UniversalFeatureExtractor()
        self.isolation_forest = IsolationForestInference()
        self.autoencoder = AutoencoderInference()
    
    def retrain_model_on_data(self, model_type: str, training_data: np.ndarray):
        from models import train_isolation_forest, save_model, train_autoencoder, save_autoencoder
        from config import ISOLATION_FOREST_CONFIG, AUTOENCODER_CONFIG, ISOLATION_FOREST_MODEL_PATH, AUTOENCODER_MODEL_PATH
        logger.info(f"Retraining {model_type} with {training_data.shape} data")
        if model_type == 'isolation_forest':
            model, scaler = train_isolation_forest(ISOLATION_FOREST_CONFIG, training_data)
            save_model(model, scaler, ISOLATION_FOREST_MODEL_PATH)
            self.isolation_forest = IsolationForestInference()
            logger.info(f"Isolation Forest retrained with {training_data.shape[1]} features")
        elif model_type == 'autoencoder':
            ae_model, ae_scaler, ae_encoder = train_autoencoder(AUTOENCODER_CONFIG, training_data=training_data)
            if ae_model is not None:
                save_autoencoder(ae_model, ae_scaler, ae_encoder, AUTOENCODER_MODEL_PATH)
            # Force reload with explicit path to ensure new model is loaded
            import time
            time.sleep(0.1)  # Small delay to ensure file system sync
            self.autoencoder = AutoencoderInference(model_path=AUTOENCODER_MODEL_PATH)
            logger.info(f"Autoencoder retrained with {training_data.shape[1]} features")
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    
    def detect_anomalies(self, records: List[Union[HTTPRecord, GenericRecord]], features: np.ndarray, file_type: str, model_type: str, feature_info: Dict[str, Any]) -> Tuple[List[AnomalyResult], Dict[str, Any]]:
        from inference.threat_detectors import classify_threat_with_confidence, ThreatCorrelationEngine
        
        logger.info(f"Starting multi-layer detection with {model_type} on {len(records)} records")
        
        # ========================================================================
        # LAYER 3: ML ANOMALY DETECTION
        # ========================================================================
        if model_type == 'isolation_forest':
            scores, is_anomaly = self.isolation_forest.predict(features)
        elif model_type == 'autoencoder':
            scores, metadata = self.autoencoder.predict(features)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        classifier = PercentileSeverityClassifier(scores)
        explanation_gen = ExplanationGenerator()
        results = []
        
        # ========================================================================
        # LAYER 1: SIGNATURE DETECTION + LAYER 2: BEHAVIORAL DETECTION
        # ========================================================================
        for idx, (record, score) in enumerate(zip(records, scores)):
            # Get ML-based severity
            ml_severity = classifier.classify(score)
            
            # Default values
            threat_type = "Other"
            confidence = 0.0
            detection_layer = DetectionLayer.ML_ANOMALY.value
            final_severity = ml_severity
            
            # Run signature + behavioral detection for HTTP records
            if isinstance(record, HTTPRecord):
                threat_type, confidence = classify_threat_with_confidence(
                    uri=record.uri,
                    user_agent=record.user_agent,
                    response_size=record.response_size,
                    status_code=record.status_code,
                    records=records,
                    client_ip=record.client_ip
                )
                
                # Determine detection layer
                if threat_type != "Other":
                    if threat_type in ["Brute Force"]:
                        detection_layer = DetectionLayer.BEHAVIORAL.value
                    else:
                        detection_layer = DetectionLayer.SIGNATURE.value
                    
                    # Severity boosting for critical threats
                    if threat_type in ["Command Injection", "SQL Injection", "Path Traversal", "SSTI", "RCE"]:
                        if final_severity in [AnomalySeverity.LOW.value, AnomalySeverity.MEDIUM.value]:
                            final_severity = AnomalySeverity.HIGH.value
                            logger.debug(f"Boosted severity to HIGH for critical threat: {threat_type}")
                    
                    # If threat detected but ML says normal, upgrade to at least LOW
                    if final_severity == AnomalySeverity.NORMAL.value:
                        final_severity = AnomalySeverity.LOW.value
                        logger.debug(f"Upgraded severity to LOW for detected threat: {threat_type}")
                else:
                    # No signature match, use ML detection
                    detection_layer = DetectionLayer.ML_ANOMALY.value
            
            # Generate explanation
            if isinstance(record, HTTPRecord):
                explanation = explanation_gen.generate_explanation(
                    threat_type, final_severity, score, record, confidence, detection_layer
                )
            else:
                explanation = f"Anomalous pattern detected (score: {score:.3f})"
            
            # Extract record details
            if isinstance(record, HTTPRecord):
                identifier = record.client_ip
                timestamp = record.timestamp
                uri = record.uri
                status_code = record.status_code
                method = record.method
                duration = record.duration
                response_size = record.response_size
                user_agent = record.user_agent
                referer = record.raw_row.get('referer', '')
            else:
                identifier = record.identifier
                timestamp = record.timestamp
                uri = ""
                status_code = 0
                method = ""
                duration = 0
                response_size = 0
                user_agent = ""
                referer = ""
            
            result = AnomalyResult(
                record_index=idx,
                identifier=identifier,
                timestamp=timestamp,
                score=float(score),
                severity=final_severity,
                model=model_type,
                threat_type=threat_type,
                explanation=explanation,
                confidence=confidence,
                detection_layer=detection_layer,
                uri=uri,
                status_code=status_code,
                method=method,
                duration=duration,
                response_size=response_size,
                user_agent=user_agent,
                referer=referer
            )
            results.append(result)
        
        # ========================================================================
        # LAYER 4: CORRELATION ENGINE
        # ========================================================================
        correlation_engine = ThreatCorrelationEngine()
        correlation_results = correlation_engine.analyze_attack_chain([r.to_dict() for r in results])
        
        # Compute statistics
        stats = self._compute_statistics(results, records, model_type, correlation_results)
        
        logger.info(f"Detection complete: {len(results)} records, {sum(1 for r in results if r.severity != 'normal')} anomalies")
        if correlation_results['total_campaigns'] > 0:
            logger.warning(f"⚠️  {correlation_results['total_campaigns']} attack campaigns detected!")
        
        return results, stats

    
    @staticmethod
    def _compute_statistics(results: List[AnomalyResult], records: List[HTTPRecord], model_type: str, correlation_results: Dict[str, Any]) -> Dict[str, Any]:
        severities = [r.severity for r in results]
        threat_types = [r.threat_type for r in results if r.severity != 'normal']
        threat_type_counts = {}
        for tt in threat_types:
            threat_type_counts[tt] = threat_type_counts.get(tt, 0) + 1
        
        # Detection layer statistics
        layer_counts = {}
        for r in results:
            if r.severity != 'normal':
                layer = r.detection_layer
                layer_counts[layer] = layer_counts.get(layer, 0) + 1
        
        stats = {
            'total_records': len(records),
            'total_anomalies': sum(1 for s in severities if s != 'normal'),
            'anomaly_percentage': 100.0 * sum(1 for s in severities if s != 'normal') / len(records),
            'severity_distribution': {
                'critical': sum(1 for s in severities if s == 'critical'),
                'high': sum(1 for s in severities if s == 'high'),
                'medium': sum(1 for s in severities if s == 'medium'),
                'low': sum(1 for s in severities if s == 'low'),
                'normal': sum(1 for s in severities if s == 'normal'),
            },
            'threat_type_distribution': threat_type_counts,
            'detection_layer_distribution': layer_counts,
            'correlation_findings': correlation_results,
            'mean_score': float(np.mean([r.score for r in results])),
            'std_score': float(np.std([r.score for r in results])),
            'model': model_type,
        }
        return stats
