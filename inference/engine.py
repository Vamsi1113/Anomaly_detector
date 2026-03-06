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
from inference.threat_graph_engine import ThreatGraphEngine
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
    THREAT_GRAPH = "Layer 5: Threat Graph Correlation"
    CORRELATION = "Layer 6: Correlation Engine"
    LLM_ENRICHMENT = "Layer 7: LLM Intelligence (Optional)"


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
    raw_log: str = ""  # Original raw log entry
    
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
            'raw_log': self.raw_log,
        }


class AnomalyDetectionEngine:
    """
    Enterprise-Grade Multi-Layer Detection Engine
    
    Architecture:
        Layer 1: Signature Engine (deterministic pattern matching)
        Layer 2: Behavioral Engine (stateful analysis)
        Layer 3: ML Engine (statistical anomaly scoring)
        Layer 4: Decision Engine (signal aggregation)
        Layer 5: Threat Graph Engine (attack campaign correlation) ← NEW
        Layer 6: Correlation Engine (campaign detection)
        Layer 7: LLM Intelligence (post-detection enrichment) - OPTIONAL
    """
    
    def __init__(self, enable_llm: bool = False, openai_api_key: str = None):
        self.feature_extractor = UniversalFeatureExtractor()
        
        # Initialize detection engines
        self.signature_engine = SignatureEngine()
        self.behavioral_engine = BehaviorEngine()
        self.ml_engine = MLEngine()
        self.decision_engine = DecisionEngine()
        self.threat_graph_engine = ThreatGraphEngine()  # NEW
        self.correlation_engine = CorrelationEngine()
        
        # Initialize LLM enrichment (optional)
        self.llm_service = LLMEnrichmentService(
            api_key=openai_api_key,
            enabled=enable_llm
        )
        
        logger.info(f"Initialized enterprise detection engine with {'7 layers (LLM enabled)' if enable_llm else '6 layers'}")
    
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
            5. Threat Graph Engine (attack campaign correlation) ← NEW
            6. Correlation Engine (campaign detection)
            7. LLM Intelligence (optional)
        """
        logger.info(f"Starting enterprise detection pipeline on {len(records)} records")
        
        # Reset engines for new analysis
        self.behavioral_engine.reset()
        self.threat_graph_engine.reset()
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
                    referer=unified.referer,
                    raw_log=unified.raw_log
                )
                legacy_results.append(legacy_result)
        
        logger.info(f"Filtered to {len(legacy_results)} high-severity threats (Critical/High/Medium only)")
        
        # ========================================================================
        # LAYER 5: THREAT GRAPH ENGINE (ATTACK CAMPAIGN CORRELATION)
        # ========================================================================
        logger.info("Layer 5: Running threat graph correlation...")
        # Build threat graph from filtered results
        attack_campaigns = self.threat_graph_engine.build_threat_graph(
            [r.to_dict() for r in legacy_results]
        )
        
        # Get graph statistics
        graph_stats = self.threat_graph_engine.get_statistics()
        logger.info(f"  Graph: {graph_stats['total_nodes']} nodes → {graph_stats['total_clusters']} clusters → {graph_stats['total_campaigns']} campaigns")
        
        # ========================================================================
        # USE THREAT GRAPH FOR FALSE POSITIVE FILTERING
        # ========================================================================
        # Strategy: Keep threats that are part of MULTI-EVENT campaigns (2+ events)
        #           Filter out isolated single-event threats (likely false positives)
        
        if len(attack_campaigns) > 0:
            # Extract record indices from campaigns with 2+ events (coordinated attacks)
            campaign_record_indices = set()
            multi_event_campaigns = []
            
            for campaign in attack_campaigns:
                if campaign.event_count >= 2:  # Only campaigns with multiple events
                    multi_event_campaigns.append(campaign)
                    for event in campaign.events:
                        campaign_record_indices.add(event['record_index'])
            
            # Filter: Keep only threats that are part of multi-event campaigns
            # These are HIGH CONFIDENCE threats (coordinated attacks)
            high_confidence_results = []
            for result in legacy_results:
                if result.record_index in campaign_record_indices:
                    # This threat is part of a coordinated campaign - HIGH CONFIDENCE
                    # Enhance the explanation to show campaign context
                    matching_campaign = None
                    for campaign in multi_event_campaigns:
                        if result.record_index in [e['record_index'] for e in campaign.events]:
                            matching_campaign = campaign
                            break
                    
                    if matching_campaign:
                        # Add campaign context to explanation
                        result.explanation = f"[{matching_campaign.campaign_id}] {result.explanation} | Part of {matching_campaign.campaign_type} with {matching_campaign.event_count} events"
                        result.confidence = min(0.95, result.confidence + 0.2)  # Boost confidence
                    
                    high_confidence_results.append(result)
            
            logger.info(f"✅ Threat Graph Filtering: {len(high_confidence_results)} high-confidence threats (part of {len(multi_event_campaigns)} multi-event campaigns)")
            logger.info(f"   Filtered out {len(legacy_results) - len(high_confidence_results)} isolated single-event threats (potential false positives)")
            display_results = high_confidence_results
        else:
            # No campaigns detected - show all filtered threats
            logger.info(f"No campaigns detected, returning all {len(legacy_results)} individual threats")
            display_results = legacy_results
        
        # ========================================================================
        # LAYER 6: CORRELATION ENGINE (LEGACY CAMPAIGN DETECTION)
        # ========================================================================
        logger.info("Layer 6: Running correlation engine...")
        # Analyze individual threats (not campaigns)
        correlation_results = self.correlation_engine.analyze_attack_chain(
            [r.to_dict() for r in legacy_results]
        )
        
        # ========================================================================
        # LAYER 7: LLM INTELLIGENCE (POST-DETECTION ENRICHMENT) - OPTIONAL
        # ========================================================================
        llm_enrichment = {}
        if self.llm_service.enabled:
            logger.info("Layer 7: Running LLM enrichment analysis...")
            # LLM analyzes individual threats (display_results already filtered by campaigns)
            llm_enrichment = self.llm_service.enrich_results([r.to_dict() for r in display_results])
        else:
            llm_enrichment = {
                'enabled': False,
                'clusters_analyzed': 0,
                'novel_patterns_detected': 0,
                'llm_insights': []
            }
        
        # Compute statistics
        stats = self._compute_statistics(
            display_results, records, model_type, 
            correlation_results, llm_enrichment, 
            attack_campaigns, graph_stats
        )
        
        # Log detection summary
        logger.info(f"Detection complete: {len(records)} records analyzed")
        logger.info(f"  - Signature detections: {self.signature_engine.detection_count}")
        logger.info(f"  - Behavioral detections: {self.behavioral_engine.detection_count}")
        logger.info(f"  - ML anomalies: {self.ml_engine.detection_count}")
        logger.info(f"  - Individual threats (Critical/High/Medium): {len(legacy_results)}")
        logger.info(f"  - Attack campaigns detected: {len(attack_campaigns)}")
        logger.info(f"  - FINAL OUTPUT: {len(display_results)} results")
        
        if len(attack_campaigns) > 0:
            logger.warning(f"⚠️  {len(attack_campaigns)} attack campaigns detected!")
            for campaign in attack_campaigns[:5]:  # Log top 5
                logger.warning(f"    - {campaign.campaign_id}: {campaign.campaign_type} ({campaign.event_count} events, score: {campaign.campaign_score})")
        
        if correlation_results['total_campaigns'] > 0:
            logger.warning(f"⚠️  {correlation_results['total_campaigns']} additional campaigns detected by correlation engine!")
        
        return display_results, stats

    
    @staticmethod
    def _compute_statistics(
        results: List[AnomalyResult], 
        records: List[HTTPRecord], 
        model_type: str, 
        correlation_results: Dict[str, Any], 
        llm_enrichment: Dict[str, Any],
        attack_campaigns: List[Any],
        graph_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
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
        
        # Convert attack campaigns to dict format
        campaigns_data = [
            {
                'campaign_id': c.campaign_id,
                'type': c.campaign_type,
                'ip': c.source_ip,
                'event_count': c.event_count,
                'score': c.campaign_score,
                'severity': c.severity,
                'threat_types': c.threat_types,
                'attack_stages': c.attack_stages,
                'mitre_tactics': c.mitre_tactics,
                'kill_chain_coverage': c.kill_chain_coverage,
                'automation_confidence': c.automation_confidence,
                'description': c.description
            }
            for c in attack_campaigns
        ]
        
        stats = {
            'total_records': len(records),
            'total_anomalies': len(results),  # Individual threats (filtered by campaigns)
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
            'threat_graph': {
                'enabled': True,
                'statistics': graph_stats,
                'campaigns': campaigns_data,
                'showing_campaigns': False,  # We show individual threats, not campaigns
                'used_for_filtering': len(campaigns_data) > 0  # Flag to show graph was used for filtering
            },
            'correlation_findings': correlation_results,
            'llm_enrichment': llm_enrichment,
            'mean_score': float(np.mean([r.score for r in results])) if len(results) > 0 else 0.0,
            'std_score': float(np.std([r.score for r in results])) if len(results) > 0 else 0.0,
            'model': model_type,
        }
        return stats
