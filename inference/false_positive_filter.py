"""
False Positive Reduction Filters
Implements whitelist filtering, frequency analysis, and pattern-based filtering
"""
import re
from typing import Dict, List, Set
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# WHITELIST CONFIGURATIONS
# ============================================================================

# Safe endpoints that should never be flagged
SAFE_ENDPOINTS = {
    '/health', '/healthcheck', '/ping', '/status',
    '/favicon.ico', '/robots.txt', '/sitemap.xml',
    '/static/', '/assets/', '/css/', '/js/', '/images/',
    '/api/health', '/api/status', '/metrics',
    '/.well-known/', '/manifest.json'
}

# Safe file extensions
SAFE_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.woff', '.woff2', '.ttf', '.eot', '.ico', '.webp',
    '.mp4', '.webm', '.mp3', '.pdf'
}

# Known good user agents (legitimate services)
SAFE_USER_AGENTS = {
    'googlebot', 'bingbot', 'slackbot', 'facebookexternalhit',
    'twitterbot', 'linkedinbot', 'whatsapp', 'telegrambot',
    'uptimerobot', 'pingdom', 'newrelic', 'datadog'
}

# Common legitimate query parameters that might look suspicious
SAFE_QUERY_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_content',
    'fbclid', 'gclid', 'ref', 'source', 'redirect_uri',
    'return_url', 'next', 'callback'
}


# ============================================================================
# FALSE POSITIVE FILTER
# ============================================================================

class FalsePositiveFilter:
    """Filters false positives using whitelists and pattern analysis"""
    
    def __init__(self):
        self.ip_frequency = defaultdict(lambda: defaultdict(int))
        self.uri_frequency = Counter()
        self.filtered_count = 0
    
    def should_filter(
        self,
        threat_type: str,
        uri: str,
        user_agent: str,
        client_ip: str,
        signature_flag: bool,
        behavior_flag: bool,
        ml_score: float
    ) -> tuple[bool, str]:
        """
        Determine if a detection should be filtered as false positive
        
        Args:
            threat_type: Detected threat type
            uri: Request URI
            user_agent: User agent string
            client_ip: Client IP address
            signature_flag: Whether signature detection triggered
            behavior_flag: Whether behavioral detection triggered
            ml_score: ML anomaly score
        
        Returns:
            Tuple of (should_filter, reason)
        """
        # CRITICAL RULE: ML alone cannot classify threats
        if not signature_flag and not behavior_flag:
            self.filtered_count += 1
            return True, "ML-only detection (no signature or behavioral match)"
        
        # Whitelist: Safe endpoints
        if self._is_safe_endpoint(uri):
            self.filtered_count += 1
            return True, "Whitelisted safe endpoint"
        
        # Whitelist: Safe file extensions
        if self._has_safe_extension(uri):
            self.filtered_count += 1
            return True, "Safe file extension"
        
        # Whitelist: Known good user agents
        if self._is_safe_user_agent(user_agent):
            self.filtered_count += 1
            return True, "Whitelisted user agent (legitimate service)"
        
        # Frequency filter: Repetitive normal traffic
        if self._is_repetitive_normal_traffic(uri, client_ip):
            self.filtered_count += 1
            return True, "Repetitive normal traffic pattern"
        
        # Pattern filter: Safe query parameters
        if self._has_only_safe_params(uri) and threat_type in ['XSS', 'SQL Injection']:
            self.filtered_count += 1
            return True, "Only safe query parameters detected"
        
        # Low confidence ML with no strong indicators
        if ml_score < 0.7 and not signature_flag and behavior_flag:
            # Behavioral only with low ML score - likely false positive
            if threat_type in ['Rate Abuse', 'Burst Activity']:
                self.filtered_count += 1
                return True, "Low confidence behavioral detection"
        
        # Not filtered
        return False, ""
    
    def _is_safe_endpoint(self, uri: str) -> bool:
        """Check if URI is a whitelisted safe endpoint"""
        if not uri:
            return False
        
        uri_lower = uri.lower()
        
        # Exact match
        if uri_lower in SAFE_ENDPOINTS:
            return True
        
        # Prefix match for directories
        for safe_path in SAFE_ENDPOINTS:
            if safe_path.endswith('/') and uri_lower.startswith(safe_path):
                return True
        
        return False
    
    def _has_safe_extension(self, uri: str) -> bool:
        """Check if URI has a safe file extension"""
        if not uri:
            return False
        
        uri_lower = uri.lower()
        return any(uri_lower.endswith(ext) for ext in SAFE_EXTENSIONS)
    
    def _is_safe_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is from a known legitimate service"""
        if not user_agent:
            return False
        
        ua_lower = user_agent.lower()
        return any(safe_ua in ua_lower for safe_ua in SAFE_USER_AGENTS)
    
    def _is_repetitive_normal_traffic(self, uri: str, client_ip: str, threshold: int = 10) -> bool:
        """
        Check if this is repetitive normal traffic
        If the same URI from same IP appears many times, it's likely legitimate
        """
        if not uri or not client_ip:
            return False
        
        # Track frequency
        self.ip_frequency[client_ip][uri] += 1
        self.uri_frequency[uri] += 1
        
        # If this exact URI+IP combination is very frequent, it's likely normal
        ip_uri_count = self.ip_frequency[client_ip][uri]
        if ip_uri_count > threshold:
            return True
        
        # If this URI is accessed by many different IPs, it's likely legitimate
        if self.uri_frequency[uri] > threshold * 2:
            return True
        
        return False
    
    def _has_only_safe_params(self, uri: str) -> bool:
        """Check if URI only contains safe query parameters"""
        if not uri or '?' not in uri:
            return False
        
        try:
            query_string = uri.split('?', 1)[1]
            params = query_string.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=', 1)[0].lower()
                    if key not in SAFE_QUERY_PARAMS:
                        return False
            
            return True
        except:
            return False
    
    def get_statistics(self) -> Dict:
        """Get filter statistics"""
        return {
            'total_filtered': self.filtered_count,
            'unique_ips_tracked': len(self.ip_frequency),
            'unique_uris_tracked': len(self.uri_frequency)
        }
    
    def reset(self):
        """Reset filter state"""
        self.ip_frequency.clear()
        self.uri_frequency.clear()
        self.filtered_count = 0
