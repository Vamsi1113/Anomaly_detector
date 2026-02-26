# SOC-Grade Inference Engine - Enterprise Multi-Layer Detection Architecture
import numpy as np
from typing import List, Dict, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
from parsing import HTTPRecord, GenericRecord
from features import UniversalFeatureExtractor

# Import new modular detection engines
from inference.signature_engine import SignatureEngine
from inference.behavioral_engine import BehaviorEngine
from inference.ml_engine import MLEngine
from inference.decision_engine import DecisionEngine, AnomalySeverity
from inference.correlation_engine import CorrelationEngine
from inference.llm_enrichment import LLMEnrichmentService

logger = logging.getLogger(__name__)


# ============================================================================
# DETECTION LAYER ENUM
# ============================================================================

class DetectionLayer(Enum):
    """Enterprise multi-layer detection architecture"""
    SIGNATURE = "Layer 1: Signature Detection"
    BEHAVIORAL = "Layer 2: Behavioral Detection"
    ML_ANOMALY = "Layer 3: ML Anomaly Detection"
    DECISION = "Layer 4: Decision Engine"
    CORRELATION = "Layer 5: Correlation Engine"
    LLM_ENRICHMENT = "Layer 6: LLM Intelligence (Optional)"


@dataclass
class AnomalyResult:
    """Legacy result format for backward compatibility"""
    record_index: int
    identifier: str
    timestamp: str
    score: float
    severity: str
    model: str
    threat_type: str
    explanation: str
    confidence: float = 0.0
    detection_layer: str = ""
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


class AnomalyDetectionEngine:
    """
    Enterprise-Grade Multi-Layer Detection Engine
    
    Architecture:
        Layer 1: Signature Engine (deterministic pattern matching)
        Layer 2: Behavioral Engine (stateful analysis)
        Layer 3: ML Engine (statistical anomaly scoring)
        Layer 4: Decision Engine (signal aggregation)
        Layer 5: Correlation Engine (campaign detection)
        Layer 6: LLM Intelligence (post-detection enrichment) - OPTIONAL
    """
    
    def __init__(self, enable_llm: bool = False, openai_api_key: str = None):
        self.feature_extractor = UniversalFeatureExtractor()
        
        # Initialize detection engines
        self.signature_engine = SignatureEngine()
        self.behavioral_engine = BehaviorEngine()
        self.ml_engine = MLEngine()
        self.decision_engine = DecisionEngine()
        self.correlation_engine = CorrelationEngine()
        
        # Initialize LLM enrichment (optional)
        self.llm_service = LLMEnrichmentService(
            api_key=openai_api_key,
            enabled=enable_llm
        )
        
        logger.info(f"Initialized enterprise detection engine with {'6 layers (LLM enabled)' if enable_llm else '5 layers'}")
    
    def retrain_model_on_data(self, model_type: str, training_data: np.ndarray):
        """Retrain ML models with new data"""
        logger.info(f"Retraining {model_type} with {training_data.shape} data")
        self.ml_engine.retrain_model(model_type, training_data)

    
    def detect_anomalies(self, records: List[Union[HTTPRecord, GenericRecord]], features: np.ndarray, file_type: str, model_type: str, feature_info: Dict[str, Any]) -> Tuple[List[AnomalyResult], Dict[str, Any]]:
        """
        Enterprise multi-layer detection pipeline
        
        Architecture:
            1. Signature Engine (runs first on ALL records)
            2. Behavioral Engine (stateful analysis)
            3. ML Engine (parallel statistical scoring)
            4. Decision Engine (signal aggregation)
            5. Correlation Engine (campaign detection)
        """
        logger.info(f"Starting enterprise detection pipeline on {len(records)} records")
        
        # Reset behavioral and correlation engines for new analysis
        self.behavioral_engine.reset()
        self.correlation_engine.reset()
        
        # ========================================================================
        # LAYER 3: ML ANOMALY DETECTION (PARALLEL)
        # ========================================================================
        logger.info("Layer 3: Running ML anomaly detection...")
        ml_scores, ml_metadata = self.ml_engine.predict(features, model_type)
        
        # ========================================================================
        # LAYERS 1, 2, 4: SIGNATURE + BEHAVIORAL + DECISION (PER RECORD)
        # ========================================================================
        logger.info("Layers 1, 2, 4: Running signature, behavioral, and decision engines...")
        unified_results = []
        
        # Progress tracking for large datasets
        total_records = len(records)
        log_interval = max(1000, total_records // 10)  # Log every 10% or 1000 records
        
        for idx, (record, ml_score) in enumerate(zip(records, ml_scores)):
            # Log progress for large datasets
            if idx > 0 and idx % log_interval == 0:
                progress_pct = (idx / total_records) * 100
                logger.info(f"  Progress: {idx}/{total_records} records ({progress_pct:.1f}%)")
            
            # Normalize ML score to 0-1 range
            ml_score_normalized = self.ml_engine.get_anomaly_score_normalized(ml_score, ml_scores)
            
            # LAYER 1: SIGNATURE DETECTION (ALWAYS RUNS FIRST)
            if isinstance(record, HTTPRecord):
                signature_result = self.signature_engine.detect(
                    uri=record.uri,
                    user_agent=record.user_agent,
                    response_size=record.response_size,
                    status_code=record.status_code
                )
            else:
                # Generic records don't have signature detection
                from inference.signature_engine import SignatureResult
                signature_result = SignatureResult(
                    signature_flag=False,
                    threat_type="Other",
                    signature_confidence=0.0,
                    matched_patterns=[]
                )
            
            # LAYER 2: BEHAVIORAL DETECTION (STATEFUL)
            behavior_result = self.behavioral_engine.analyze_record(record, records)
            
            # LAYER 4: DECISION ENGINE (SIGNAL AGGREGATION)
            unified_threat = self.decision_engine.make_decision(
                record=record,
                record_index=idx,
                signature_result=signature_result,
                behavior_result=behavior_result,
                ml_score=ml_score,
                ml_score_normalized=ml_score_normalized
            )
            
            unified_results.append(unified_threat)
        
        # Convert unified results to legacy AnomalyResult format for compatibility
        # FILTER: Only include Critical, High, and Medium severity threats
        legacy_results = []
        for unified in unified_results:
            # Only include threats that are MEDIUM or above
            if unified.final_severity in ['critical', 'high', 'medium']:
                legacy_result = AnomalyResult(
                    record_index=unified.record_index,
                    identifier=unified.identifier,
                    timestamp=unified.timestamp,
                    score=unified.final_risk_score,
                    severity=unified.final_severity,
                    model=model_type,
                    threat_type=unified.final_threat_type,
                    explanation=unified.explanation,
                    confidence=max(unified.signature_confidence, unified.behavior_confidence),
                    detection_layer=unified.detection_layer,
                    uri=unified.uri,
                    status_code=unified.status_code,
                    method=unified.method,
                    duration=unified.duration,
                    response_size=unified.response_size,
                    user_agent=unified.user_agent,
                    referer=unified.referer
                )
                legacy_results.append(legacy_result)
        
        # ========================================================================
        # LAYER 5: CORRELATION ENGINE (CAMPAIGN DETECTION)
        # ========================================================================
        logger.info("Layer 5: Running correlation engine...")
        # Only analyze filtered results (Critical/High/Medium) for campaigns
        correlation_results = self.correlation_engine.analyze_attack_chain(
            [r.to_dict() for r in legacy_results]
        )
        
        # ========================================================================
        # LAYER 6: LLM INTELLIGENCE (POST-DETECTION ENRICHMENT) - OPTIONAL
        # ========================================================================
        llm_enrichment = {}
        if self.llm_service.enabled:
            logger.info("Layer 6: Running LLM enrichment analysis...")
            llm_enrichment = self.llm_service.enrich_results(
                [r.to_dict() for r in legacy_results]
            )
        else:
            llm_enrichment = {
                'enabled': False,
                'clusters_analyzed': 0,
                'novel_patterns_detected': 0,
                'llm_insights': []
            }
        
        # Compute statistics
        stats = self._compute_statistics(legacy_results, records, model_type, correlation_results, llm_enrichment)
        
        # Log detection summary
        logger.info(f"Detection complete: {len(records)} records analyzed")
        logger.info(f"  - Signature detections: {self.signature_engine.detection_count}")
        logger.info(f"  - Behavioral detections: {self.behavioral_engine.detection_count}")
        logger.info(f"  - ML anomalies: {self.ml_engine.detection_count}")
        logger.info(f"  - Final threats (Critical/High/Medium only): {len(legacy_results)}")
        
        if correlation_results['total_campaigns'] > 0:
            logger.warning(f"⚠️  {correlation_results['total_campaigns']} attack campaigns detected!")
        
        return legacy_results, stats

    
    @staticmethod
    def _compute_statistics(results: List[AnomalyResult], records: List[HTTPRecord], model_type: str, correlation_results: Dict[str, Any], llm_enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """Compute detection statistics (only for Critical/High/Medium threats)"""
        # Note: results are already filtered to only include critical/high/medium
        severities = [r.severity for r in results]
        threat_types = [r.threat_type for r in results]
        threat_type_counts = {}
        for tt in threat_types:
            threat_type_counts[tt] = threat_type_counts.get(tt, 0) + 1
        
        # Detection layer statistics
        layer_counts = {}
        for r in results:
            layer = r.detection_layer
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
        
        stats = {
            'total_records': len(records),
            'total_anomalies': len(results),  # Only critical/high/medium
            'anomaly_percentage': 100.0 * len(results) / len(records) if len(records) > 0 else 0.0,
            'severity_distribution': {
                'critical': sum(1 for s in severities if s == 'critical'),
                'high': sum(1 for s in severities if s == 'high'),
                'medium': sum(1 for s in severities if s == 'medium'),
                'low': 0,  # Not tracked anymore
                'normal': 0,  # Not tracked anymore
            },
            'threat_type_distribution': threat_type_counts,
            'detection_layer_distribution': layer_counts,
            'correlation_findings': correlation_results,
            'llm_enrichment': llm_enrichment,  # NEW: LLM insights
            'mean_score': float(np.mean([r.score for r in results])) if len(results) > 0 else 0.0,
            'std_score': float(np.std([r.score for r in results])) if len(results) > 0 else 0.0,
            'model': model_type,
        }
        return stats
