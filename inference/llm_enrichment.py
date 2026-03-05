"""
LLM Intelligence Layer - Mandatory Behavioral Analysis
Performs comprehensive threat intelligence analysis on ALL high-severity threat clusters
"""
import os
import json
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
    """Represents a cluster of similar threats for comprehensive LLM behavioral analysis"""
    
    def __init__(self, cluster_id: str, ip: str, threat_types: List[str]):
        self.cluster_id = cluster_id
        self.ip = ip
        self.threat_types = threat_types
        self.threats = []
        self.request_count = 0
        self.avg_anomaly_score = 0.0
        self.severity_distribution = defaultdict(int)
        self.first_seen = None
        self.last_seen = None
        self.unique_uris = set()
        self.unique_methods = set()
        self.status_codes = defaultdict(int)
    
    def add_threat(self, threat: Dict[str, Any]):
        """Add a threat to this cluster and update statistics"""
        self.threats.append(threat)
        self.request_count += 1
        self.severity_distribution[threat['severity']] += 1
        
        # Track temporal information
        timestamp = threat.get('timestamp', '')
        if not self.first_seen or timestamp < self.first_seen:
            self.first_seen = timestamp
        if not self.last_seen or timestamp > self.last_seen:
            self.last_seen = timestamp
        
        # Track request patterns
        if threat.get('uri'):
            self.unique_uris.add(threat['uri'])
        if threat.get('method'):
            self.unique_methods.add(threat['method'])
        if threat.get('status_code'):
            self.status_codes[threat['status_code']] += 1
    
    def calculate_stats(self):
        """Calculate comprehensive cluster statistics"""
        if self.threats:
            self.avg_anomaly_score = sum(t['score'] for t in self.threats) / len(self.threats)
    
    def get_structured_samples(self, max_samples: int = 5) -> List[Dict[str, Any]]:
        """Get structured sample requests for LLM analysis"""
        samples = []
        seen_types = set()
        
        for threat in self.threats:
            if threat['threat_type'] not in seen_types or len(samples) < max_samples:
                samples.append({
                    'method': threat.get('method', 'UNKNOWN'),
                    'uri': threat.get('uri', 'N/A'),
                    'status': threat.get('status_code', 0),
                    'response_size': threat.get('response_size', 0),
                    'threat_type': threat['threat_type'],
                    'severity': threat['severity'],
                    'timestamp': threat.get('timestamp', 'N/A')
                })
                seen_types.add(threat['threat_type'])
                if len(samples) >= max_samples:
                    break
        
        return samples
    
    def to_structured_dict(self) -> Dict[str, Any]:
        """Convert cluster to structured format for LLM analysis"""
        self.calculate_stats()
        
        # Calculate time delta
        time_delta = "Unknown"
        if self.first_seen and self.last_seen:
            try:
                # Simple time delta calculation
                time_delta = f"{self.first_seen} to {self.last_seen}"
            except:
                pass
        
        return {
            'cluster_id': self.cluster_id,
            'source_ip': self.ip,
            'threat_types': list(set(self.threat_types)),
            'total_threats': self.request_count,
            'severity_distribution': dict(self.severity_distribution),
            'time_range': time_delta,
            'avg_anomaly_score': round(self.avg_anomaly_score, 3),
            'unique_uri_count': len(self.unique_uris),
            'unique_methods': list(self.unique_methods),
            'most_frequent_uri': max(self.unique_uris, key=lambda uri: sum(1 for t in self.threats if t.get('uri') == uri)) if self.unique_uris else 'N/A',
            'status_code_distribution': dict(self.status_codes),
            'sample_requests': self.get_structured_samples()
        }


class LLMEnrichmentService:
    """
    LLM Intelligence Layer - Mandatory Behavioral Analysis
    
    CRITICAL: LLM ALWAYS analyzes ALL high-severity threat clusters
    
    LLM does NOT:
    - Assign severity (Decision Engine does this)
    - Override detection logic (Rules remain deterministic)
    - Replace signature/behavioral/ML detection
    
    LLM ALWAYS:
    - Performs comprehensive behavioral intelligence analysis
    - Generates SOC-ready threat intelligence reports
    - Analyzes attacker intent and sophistication
    - Provides actionable recommendations
    """
    
    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        self.enabled = enabled and OPENAI_AVAILABLE
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.client = None
        self.max_clusters_per_file = 10  # Cost control
        self.max_tokens = 800  # Increased for detailed analysis
        
        if self.enabled and self.api_key:
            try:
                # Azure OpenAI configuration using OpenAI client with custom base_url
                # Read endpoint from environment or use default
                endpoint = os.getenv('OPENAI_BASE_URL', 'https://rhea-mm1vfuyh-eastus2.cognitiveservices.azure.com/openai/v1/')
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
    
    def cluster_threats(self, threats: List[Dict[str, Any]]) -> List[ThreatCluster]:
        """
        Cluster threats by IP and threat type for comprehensive analysis
        
        Args:
            threats: List of threat detections
        
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
        cluster_counter = 1
        
        for ip, threat_groups in clusters_by_ip.items():
            # Create clusters for ALL IPs with threats (no minimum threshold)
            total_threats = sum(len(threats) for threats in threat_groups.values())
            if total_threats >= 1:  # Analyze even single threats if high severity
                threat_types = list(threat_groups.keys())
                cluster_id = f"CLUSTER-{cluster_counter:03d}"
                cluster = ThreatCluster(
                    cluster_id=cluster_id,
                    ip=ip,
                    threat_types=threat_types
                )
                
                for threat_list in threat_groups.values():
                    for threat in threat_list:
                        cluster.add_threat(threat)
                
                clusters.append(cluster)
                cluster_counter += 1
        
        # Sort by severity and threat count (most severe first)
        clusters.sort(key=lambda c: (
            c.severity_distribution.get('critical', 0),
            c.severity_distribution.get('high', 0),
            c.request_count
        ), reverse=True)
        
        return clusters[:self.max_clusters_per_file]
    
    def prepare_behavioral_analysis_prompt(self, cluster: ThreatCluster) -> str:
        """
        Prepare comprehensive behavioral intelligence prompt for LLM with MITRE context
        
        Uses structured JSON format for better LLM understanding
        """
        cluster_data = cluster.to_structured_dict()
        
        # Add MITRE ATT&CK context for each threat type
        mitre_context = []
        for threat in cluster.threats:
            threat_type = threat.get('threat_type', 'Unknown')
            mitre_technique = threat.get('mitre_technique', 'N/A')
            mitre_tactic = threat.get('mitre_tactic', 'N/A')
            attack_stage = threat.get('attack_stage', 'Unknown')
            
            if mitre_technique != 'N/A':
                mitre_context.append({
                    'threat_type': threat_type,
                    'mitre_technique': mitre_technique,
                    'mitre_tactic': mitre_tactic,
                    'attack_stage': attack_stage
                })
        
        # Remove duplicates
        unique_mitre = {m['threat_type']: m for m in mitre_context}.values()
        cluster_data['mitre_context'] = list(unique_mitre)
        
        cluster_json = json.dumps(cluster_data, indent=2)
        
        prompt = f"""You are a senior cybersecurity threat intelligence analyst.
Analyze the following clustered security events and provide a detailed behavioral intelligence assessment.

CLUSTER DATA (with MITRE ATT&CK context):
{cluster_json}

IMPORTANT: Use the MITRE ATT&CK context provided to inform your analysis. The techniques, tactics, and attack stages are already mapped.

Your analysis must include:

1. **Behavioral Pattern Summary**
   - What type of attack behavior is observed?
   - Reference the MITRE tactics and attack stages provided.
   - Is this reconnaissance, exploitation, lateral movement, or exfiltration?

2. **Attack Progression Analysis**
   - Does this resemble a multi-stage attack?
   - Describe the likely sequence of attacker actions using the MITRE kill chain.
   - Reference specific MITRE techniques observed.

3. **Attacker Profile Assessment**
   - Automated bot, scripted attack, or skilled manual attacker?
   - Level of sophistication (Low / Medium / High).
   - Consider the complexity of MITRE techniques used.

4. **Impact Assessment**
   - Potential business impact based on MITRE tactics.
   - Data exposure risk.
   - Privilege escalation likelihood.

5. **Campaign Classification**
   - Is this an APT-style behavior?
   - Is this an automated scanning campaign?
   - Is this opportunistic exploitation?
   - Reference MITRE ATT&CK framework patterns.

6. **Novel or Emerging Indicators**
   - Any suspicious pattern not covered by standard rule-based detection?
   - Suggest if new detection rules should be created.
   - Consider if this represents a new TTP (Tactics, Techniques, Procedures).

Respond in structured JSON format:
{{
  "behavior_summary": "...",
  "attack_progression": "...",
  "attacker_profile": "...",
  "sophistication_level": "Low|Medium|High",
  "impact_assessment": "...",
  "campaign_type": "...",
  "novel_indicators": "...",
  "recommendations": "..."
}}

Do not say "no insights" or "insufficient data". Always provide a full intelligence assessment based on available information."""
        
        return prompt
    
    def analyze_with_llm(self, cluster: ThreatCluster) -> Dict[str, Any]:
        """
        Perform mandatory behavioral intelligence analysis on threat cluster
        
        CRITICAL: This ALWAYS returns analysis, never None
        
        Returns:
            Dictionary with comprehensive LLM behavioral intelligence
        """
        if not self.enabled or not self.client:
            # Return fallback analysis if LLM is disabled
            return {
                'cluster_id': cluster.cluster_id,
                'cluster_ip': cluster.ip,
                'threat_types': cluster.threat_types,
                'request_count': cluster.request_count,
                'llm_analysis': 'LLM analysis disabled - API key not configured',
                'behavior_summary': 'N/A - LLM disabled',
                'attack_progression': 'N/A - LLM disabled',
                'attacker_profile': 'N/A - LLM disabled',
                'sophistication_level': 'Unknown',
                'impact_assessment': 'N/A - LLM disabled',
                'campaign_type': 'N/A - LLM disabled',
                'novel_indicators': 'N/A - LLM disabled',
                'recommendations': 'Enable LLM for behavioral analysis',
                'llm_model': 'N/A',
                'analyzed_at': datetime.now().isoformat()
            }
        
        try:
            prompt = self.prepare_behavioral_analysis_prompt(cluster)
            deployment_name = "gpt-4o-mini"
            
            logger.info(f"Analyzing {cluster.cluster_id} with Azure OpenAI ({deployment_name})")
            
            response = self.client.chat.completions.create(
                model=deployment_name,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity threat intelligence analyst providing comprehensive behavioral analysis on detected threats. Always provide detailed, actionable intelligence."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=0.3
            )
            
            analysis_text = response.choices[0].message.content
            
            # Clean up markdown code blocks if present
            cleaned_text = analysis_text.strip()
            if cleaned_text.startswith('```json'):
                cleaned_text = cleaned_text[7:]  # Remove ```json
            if cleaned_text.startswith('```'):
                cleaned_text = cleaned_text[3:]  # Remove ```
            if cleaned_text.endswith('```'):
                cleaned_text = cleaned_text[:-3]  # Remove trailing ```
            cleaned_text = cleaned_text.strip()
            
            # Try to parse JSON response
            try:
                analysis_json = json.loads(cleaned_text)
                return {
                    'cluster_id': cluster.cluster_id,
                    'cluster_ip': cluster.ip,
                    'threat_types': cluster.threat_types,
                    'request_count': cluster.request_count,
                    'llm_analysis': analysis_text,
                    'behavior_summary': analysis_json.get('behavior_summary', 'N/A'),
                    'attack_progression': analysis_json.get('attack_progression', 'N/A'),
                    'attacker_profile': analysis_json.get('attacker_profile', 'N/A'),
                    'sophistication_level': analysis_json.get('sophistication_level', 'Unknown'),
                    'impact_assessment': analysis_json.get('impact_assessment', 'N/A'),
                    'campaign_type': analysis_json.get('campaign_type', 'N/A'),
                    'novel_indicators': analysis_json.get('novel_indicators', 'None detected'),
                    'recommendations': analysis_json.get('recommendations', 'Continue monitoring'),
                    'llm_model': deployment_name,
                    'analyzed_at': datetime.now().isoformat()
                }
            except json.JSONDecodeError:
                # If LLM doesn't return JSON, use raw text
                return {
                    'cluster_id': cluster.cluster_id,
                    'cluster_ip': cluster.ip,
                    'threat_types': cluster.threat_types,
                    'request_count': cluster.request_count,
                    'llm_analysis': analysis_text,
                    'behavior_summary': analysis_text[:500] if len(analysis_text) > 500 else analysis_text,
                    'attack_progression': 'See full analysis',
                    'attacker_profile': 'See full analysis',
                    'sophistication_level': 'Unknown',
                    'impact_assessment': 'See full analysis',
                    'campaign_type': 'See full analysis',
                    'novel_indicators': 'See full analysis',
                    'recommendations': 'See full analysis',
                    'llm_model': deployment_name,
                    'analyzed_at': datetime.now().isoformat()
                }
        
        except Exception as e:
            logger.error(f"LLM analysis failed for {cluster.cluster_id}: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            
            # Return error analysis instead of None
            return {
                'cluster_id': cluster.cluster_id,
                'cluster_ip': cluster.ip,
                'threat_types': cluster.threat_types,
                'request_count': cluster.request_count,
                'llm_analysis': f'LLM analysis failed: {str(e)}',
                'behavior_summary': 'Analysis failed - see error',
                'attack_progression': 'N/A - analysis error',
                'attacker_profile': 'N/A - analysis error',
                'sophistication_level': 'Unknown',
                'impact_assessment': 'N/A - analysis error',
                'campaign_type': 'N/A - analysis error',
                'novel_indicators': 'N/A - analysis error',
                'recommendations': 'Retry analysis or check LLM configuration',
                'llm_model': 'gpt-4o-mini',
                'analyzed_at': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def enrich_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        MANDATORY behavioral intelligence analysis on ALL high-severity threat clusters
        
        CRITICAL: This ALWAYS performs analysis when clusters exist
        
        Args:
            results: List of all detection results
        
        Returns:
            Dictionary with comprehensive LLM behavioral intelligence
        """
        if not self.enabled:
            logger.warning("LLM enrichment disabled - no API key configured")
            return {
                'enabled': False,
                'clusters_analyzed': 0,
                'llm_insights': [],
                'message': 'LLM enrichment disabled - configure OPENAI_API_KEY in .env to enable'
            }
        
        logger.info("Starting MANDATORY LLM behavioral intelligence analysis...")
        
        # Step 1: Filter high-severity threats (Critical, High, Medium)
        high_severity_threats = self.filter_high_severity(results)
        logger.info(f"Filtered {len(high_severity_threats)} high-severity threats for mandatory LLM analysis")
        
        if len(high_severity_threats) == 0:
            logger.info("No high-severity threats detected - LLM analysis not required")
            return {
                'enabled': True,
                'clusters_analyzed': 0,
                'llm_insights': [],
                'message': 'No high-severity threats detected'
            }
        
        # Step 2: Cluster threats for analysis
        clusters = self.cluster_threats(high_severity_threats)
        logger.info(f"Created {len(clusters)} threat clusters for MANDATORY behavioral analysis")
        
        if len(clusters) == 0:
            logger.warning("No clusters formed from high-severity threats")
            return {
                'enabled': True,
                'clusters_analyzed': 0,
                'llm_insights': [],
                'message': 'High-severity threats detected but no clusters formed'
            }
        
        # Step 3: MANDATORY analysis of ALL clusters
        # CRITICAL: analyze_with_llm ALWAYS returns a result (never None)
        llm_insights = []
        for i, cluster in enumerate(clusters, 1):
            logger.info(f"Analyzing cluster {i}/{len(clusters)}: {cluster.cluster_id} ({cluster.ip})")
            insight = self.analyze_with_llm(cluster)
            llm_insights.append(insight)  # Always append (never None)
        
        logger.info(f"✓ LLM behavioral intelligence complete: {len(llm_insights)} clusters analyzed")
        
        # Step 4: Detect novel patterns (supplementary analysis)
        novel_patterns = self.detect_novel_patterns(high_severity_threats)
        if novel_patterns:
            logger.info(f"Detected {len(novel_patterns)} novel threat patterns")
        
        return {
            'enabled': True,
            'clusters_analyzed': len(clusters),
            'llm_insights': llm_insights,  # ALWAYS contains analysis
            'novel_patterns': novel_patterns[:5],  # Limit to top 5
            'message': f'Successfully analyzed {len(llm_insights)} threat clusters'
        }
    
    def detect_novel_patterns(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect potential novel threat patterns (supplementary analysis)
        
        Criteria: High anomaly score BUT no signature match
        """
        novel_patterns = []
        
        for threat in threats:
            # High ML score but "Other" threat type = potential novel pattern
            if threat['score'] > 0.8 and threat['threat_type'] == 'Other':
                novel_patterns.append({
                    'uri': threat.get('uri', 'N/A'),
                    'ip': threat['identifier'],
                    'anomaly_score': threat['score'],
                    'timestamp': threat.get('timestamp', 'N/A'),
                    'detection_layer': threat.get('detection_layer', 'Unknown')
                })
        
        return novel_patterns
