"""
LLM Intelligence Layer - Post-Detection Enrichment
Analyzes high-severity threats for behavioral patterns and novel threat discovery
"""
import os
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# OpenAI SDK import (optional - only if API key is configured)
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI SDK not installed. LLM enrichment will be disabled.")


class ThreatCluster:
    """Represents a cluster of similar threats for LLM analysis"""
    
    def __init__(self, ip: str, threat_types: List[str], time_window: str):
        self.ip = ip
        self.threat_types = threat_types
        self.threats = []
        self.time_window = time_window
        self.request_count = 0
        self.avg_anomaly_score = 0.0
        self.severity_distribution = defaultdict(int)
    
    def add_threat(self, threat: Dict[str, Any]):
        """Add a threat to this cluster"""
        self.threats.append(threat)
        self.request_count += 1
        self.severity_distribution[threat['severity']] += 1
    
    def calculate_stats(self):
        """Calculate cluster statistics"""
        if self.threats:
            self.avg_anomaly_score = sum(t['score'] for t in self.threats) / len(self.threats)
    
    def get_sample_logs(self, max_samples: int = 5) -> List[Dict[str, Any]]:
        """Get representative sample logs from cluster"""
        # Get diverse samples (different threat types if possible)
        samples = []
        seen_types = set()
        
        for threat in self.threats:
            if threat['threat_type'] not in seen_types or len(samples) < max_samples:
                samples.append({
                    'uri': threat['uri'],
                    'method': threat['method'],
                    'threat_type': threat['threat_type'],
                    'severity': threat['severity'],
                    'timestamp': threat['timestamp']
                })
                seen_types.add(threat['threat_type'])
                if len(samples) >= max_samples:
                    break
        
        return samples
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cluster to dictionary for LLM analysis"""
        self.calculate_stats()
        return {
            'ip': self.ip,
            'threat_types': list(set(self.threat_types)),
            'request_count': self.request_count,
            'time_window': self.time_window,
            'avg_anomaly_score': round(self.avg_anomaly_score, 3),
            'severity_distribution': dict(self.severity_distribution),
            'sample_logs': self.get_sample_logs()
        }


class LLMEnrichmentService:
    """
    LLM Intelligence Layer for post-detection threat enrichment
    
    IMPORTANT: LLM does NOT:
    - Assign severity
    - Override detection logic
    - Replace deterministic rules
    - Replace ML
    
    LLM ONLY:
    - Analyzes behavioral patterns
    - Discovers novel threat patterns
    - Generates analyst summaries
    - Provides threat intelligence
    """
    
    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        self.enabled = enabled and OPENAI_AVAILABLE
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.client = None
        self.max_clusters_per_file = 10  # Cost control
        self.max_tokens = 500  # Cost control
        
        if self.enabled and self.api_key:
            try:
                # Azure OpenAI configuration using OpenAI client with custom base_url
                endpoint = "https://rhea-mm1vfuyh-eastus2.cognitiveservices.azure.com/openai/v1/"
                self.client = OpenAI(
                    base_url=endpoint,
                    api_key=self.api_key
                )
                logger.info("LLM Enrichment Service initialized with Azure OpenAI")
                logger.info(f"Azure Endpoint: {endpoint}")
            except Exception as e:
                logger.error(f"Failed to initialize Azure OpenAI client: {e}")
                self.enabled = False
        else:
            logger.info("LLM Enrichment Service disabled (no API key or SDK not available)")
    
    def filter_high_severity(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter only Critical, High, and Medium severity threats"""
        return [r for r in results if r['severity'] in ['critical', 'high', 'medium']]
    
    def cluster_threats(self, threats: List[Dict[str, Any]], time_window_minutes: int = 5) -> List[ThreatCluster]:
        """
        Cluster threats by IP, time window, and threat type
        
        Args:
            threats: List of threat detections
            time_window_minutes: Time window for clustering (default 5 min)
        
        Returns:
            List of ThreatCluster objects
        """
        clusters_by_ip = defaultdict(lambda: defaultdict(list))
        
        # Group by IP and threat type
        for threat in threats:
            ip = threat['identifier']
            threat_type = threat['threat_type']
            clusters_by_ip[ip][threat_type].append(threat)
        
        # Create cluster objects
        clusters = []
        for ip, threat_groups in clusters_by_ip.items():
            # Only create clusters for IPs with multiple threats
            total_threats = sum(len(threats) for threats in threat_groups.values())
            if total_threats >= 3:  # Minimum 3 threats to form a cluster
                threat_types = list(threat_groups.keys())
                cluster = ThreatCluster(
                    ip=ip,
                    threat_types=threat_types,
                    time_window=f"{time_window_minutes} minutes"
                )
                
                for threat_list in threat_groups.values():
                    for threat in threat_list:
                        cluster.add_threat(threat)
                
                clusters.append(cluster)
        
        # Sort by severity and threat count (most severe first)
        clusters.sort(key=lambda c: (
            c.severity_distribution.get('critical', 0),
            c.severity_distribution.get('high', 0),
            c.request_count
        ), reverse=True)
        
        return clusters[:self.max_clusters_per_file]
    
    def prepare_llm_payload(self, cluster: ThreatCluster) -> str:
        """Prepare structured prompt for LLM analysis"""
        cluster_data = cluster.to_dict()
        
        prompt = f"""You are a cybersecurity threat analyst. Analyze this threat cluster and provide behavioral insights.

**Threat Cluster Summary:**
- Source IP: {cluster_data['ip']}
- Threat Types Detected: {', '.join(cluster_data['threat_types'])}
- Total Requests: {cluster_data['request_count']}
- Time Window: {cluster_data['time_window']}
- Average Anomaly Score: {cluster_data['avg_anomaly_score']}
- Severity Distribution: {cluster_data['severity_distribution']}

**Sample Attack Requests:**
"""
        for i, sample in enumerate(cluster_data['sample_logs'], 1):
            prompt += f"\n{i}. [{sample['threat_type']}] {sample['method']} {sample['uri']}"
        
        prompt += """

**Analysis Required:**
1. What attack pattern does this resemble?
2. Is there a multi-stage attack pattern visible?
3. Does this indicate automated or manual attack?
4. What is the likely attacker objective?
5. Are there any novel or unusual threat patterns?
6. Risk assessment summary for SOC analysts

Provide concise, actionable insights in 3-4 sentences."""
        
        return prompt
    
    def analyze_with_llm(self, cluster: ThreatCluster) -> Optional[Dict[str, Any]]:
        """
        Send cluster to LLM for behavioral analysis
        
        Returns:
            Dictionary with LLM insights or None if disabled/failed
        """
        if not self.enabled or not self.client:
            return None
        
        try:
            prompt = self.prepare_llm_payload(cluster)
            
            # Azure OpenAI deployment name - MUST match your Azure deployment
            deployment_name = "gpt-4o-mini"
            
            logger.info(f"Calling Azure OpenAI with deployment: {deployment_name}")
            
            response = self.client.chat.completions.create(
                model=deployment_name,  # This is your Azure deployment name
                messages=[
                    {"role": "system", "content": "You are a cybersecurity threat intelligence analyst providing behavioral insights on detected threats."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=0.3  # Lower temperature for more focused analysis
            )
            
            analysis = response.choices[0].message.content
            
            return {
                'cluster_ip': cluster.ip,
                'threat_types': cluster.threat_types,
                'request_count': cluster.request_count,
                'llm_analysis': analysis,
                'llm_model': deployment_name,
                'analyzed_at': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"LLM analysis failed for cluster {cluster.ip}: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            if hasattr(e, 'response'):
                logger.error(f"Response: {e.response}")
            return None
    
    def detect_novel_patterns(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect potential novel threat patterns
        
        Criteria: High anomaly score BUT no signature match
        """
        novel_patterns = []
        
        for threat in threats:
            # High ML score but "Other" threat type = potential novel pattern
            if threat['score'] > 0.8 and threat['threat_type'] == 'Other':
                novel_patterns.append({
                    'uri': threat['uri'],
                    'ip': threat['identifier'],
                    'anomaly_score': threat['score'],
                    'timestamp': threat['timestamp'],
                    'detection_layer': threat['detection_layer']
                })
        
        return novel_patterns
    
    def enrich_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main enrichment function - analyzes high-severity threats with LLM
        
        Args:
            results: List of all detection results
        
        Returns:
            Dictionary with LLM enrichment data
        """
        if not self.enabled:
            return {
                'enabled': False,
                'clusters_analyzed': 0,
                'novel_patterns_detected': 0,
                'llm_insights': []
            }
        
        logger.info("Starting LLM enrichment analysis...")
        
        # Step 1: Filter high-severity threats
        high_severity_threats = self.filter_high_severity(results)
        logger.info(f"Filtered {len(high_severity_threats)} high-severity threats for LLM analysis")
        
        if len(high_severity_threats) == 0:
            return {
                'enabled': True,
                'clusters_analyzed': 0,
                'novel_patterns_detected': 0,
                'llm_insights': []
            }
        
        # Step 2: Cluster threats
        clusters = self.cluster_threats(high_severity_threats)
        logger.info(f"Created {len(clusters)} threat clusters")
        
        # Step 3: Analyze clusters with LLM
        llm_insights = []
        for cluster in clusters:
            insight = self.analyze_with_llm(cluster)
            if insight:
                llm_insights.append(insight)
        
        # Step 4: Detect novel patterns
        novel_patterns = self.detect_novel_patterns(high_severity_threats)
        
        logger.info(f"LLM enrichment complete: {len(llm_insights)} clusters analyzed, {len(novel_patterns)} novel patterns detected")
        
        return {
            'enabled': True,
            'clusters_analyzed': len(clusters),
            'novel_patterns_detected': len(novel_patterns),
            'llm_insights': llm_insights,
            'novel_patterns': novel_patterns[:5]  # Limit to top 5
        }
