"""
Feature Extraction Module
Extracts numerical features from ANY CSV data for ML models
Features inform ML about rarity, NOT classification
"""
import numpy as np
from typing import List, Dict, Tuple, Any, Union
import logging
import re
from urllib.parse import unquote

from parsing import HTTPRecord, GenericRecord

logger = logging.getLogger(__name__)


# ============================================================================
# HTTP LOG FEATURE EXTRACTION
# ============================================================================

class HTTPFeatureExtractor:
    """Extract features from HTTP log records"""
    
    # Security patterns for binary features (inform ML, don't classify)
    TRAVERSAL_PATTERNS = [r"\.\./", r"\.\.\\", r"%2e%2e", r"%252e", r"/etc/passwd"]
    SQLI_PATTERNS = [r"sqlmap", r"union\s+select", r"' or '", r"--"]
    XSS_PATTERNS = [r"<script>", r"javascript:", r"onerror="]
    CMD_PATTERNS = [r"rm\s+-rf", r";\s*cat", r"&&\s*whoami"]
    PRIV_ESC_PATTERNS = [r"/admin", r"sudo", r"privilege"]
    BAD_AGENTS = ["sqlmap", "nikto", "nmap", "curl", "python"]
    
    def extract_features(self, records: List[HTTPRecord]) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Extract features from HTTP log records"""
        features_list = []
        
        # Calculate global statistics
        response_sizes = [r.response_size for r in records]
        durations = [r.duration for r in records]
        uri_lengths = [len(r.uri or '') for r in records]
        
        # IP-based statistics
        ip_request_counts = {}
        ip_uri_sets = {}
        for r in records:
            ip = r.client_ip
            ip_request_counts[ip] = ip_request_counts.get(ip, 0) + 1
            if ip not in ip_uri_sets:
                ip_uri_sets[ip] = set()
            ip_uri_sets[ip].add(r.uri)
        
        stats = {
            'mean_response_size': np.mean(response_sizes) if response_sizes else 0,
            'std_response_size': np.std(response_sizes) if response_sizes else 1,
            'mean_duration': np.mean(durations) if durations else 0,
            'std_duration': np.std(durations) if durations else 1,
            'mean_uri_length': np.mean(uri_lengths) if uri_lengths else 0,
            'std_uri_length': np.std(uri_lengths) if uri_lengths else 1,
        }
        
        for record in records:
            features = self._extract_single_record(record, stats, ip_request_counts, ip_uri_sets)
            features_list.append(features)
        
        feature_matrix = np.array(features_list, dtype=np.float32)
        
        feature_info = {
            'feature_names': [
                'uri_length',
                'response_size',
                'duration',
                'status_code',
                'request_rate_per_ip',
                'unique_uri_count_per_ip',
                'has_path_traversal',
                'has_sql_injection',
                'has_xss',
                'has_command_injection',
                'has_privilege_escalation',
                'has_data_exfiltration',
                'has_suspicious_agent',
                'is_client_error',
                'is_server_error',
                'is_post_method',
                'uri_length_zscore',
                'response_size_zscore',
                'duration_zscore',
            ],
            'num_features': feature_matrix.shape[1],
            'num_records': len(records),
        }
        
        logger.info(f"Extracted {feature_matrix.shape[0]} records with {feature_matrix.shape[1]} features")
        
        return feature_matrix, feature_info
    
    def _extract_single_record(
        self, 
        record: HTTPRecord, 
        stats: Dict[str, float],
        ip_request_counts: Dict[str, int],
        ip_uri_sets: Dict[str, set]
    ) -> List[float]:
        """Extract feature vector for a single HTTP record"""
        features = []
        
        uri_str = record.uri or ''
        user_agent_str = record.user_agent or ''
        decoded_uri = unquote(uri_str.lower())
        
        # 0: URI length (numeric)
        features.append(float(len(uri_str)))
        
        # 1: Response size (numeric)
        features.append(float(record.response_size))
        
        # 2: Duration (numeric)
        features.append(float(record.duration))
        
        # 3: Status code (numeric)
        features.append(float(record.status_code))
        
        # 4: Request rate per IP (numeric)
        features.append(float(ip_request_counts.get(record.client_ip, 1)))
        
        # 5: Unique URI count per IP (numeric)
        features.append(float(len(ip_uri_sets.get(record.client_ip, set()))))
        
        # 6: Has path traversal (binary - informs ML, doesn't classify)
        has_traversal = any(re.search(p, decoded_uri) for p in self.TRAVERSAL_PATTERNS)
        features.append(float(has_traversal))
        
        # 7: Has SQL injection (binary)
        has_sqli = any(re.search(p, uri_str.lower()) for p in self.SQLI_PATTERNS)
        features.append(float(has_sqli))
        
        # 8: Has XSS (binary)
        has_xss = any(p in uri_str.lower() for p in self.XSS_PATTERNS)
        features.append(float(has_xss))
        
        # 9: Has command injection (binary)
        has_cmd = any(re.search(p, uri_str.lower()) for p in self.CMD_PATTERNS)
        features.append(float(has_cmd))
        
        # 10: Has privilege escalation (binary)
        has_priv = any(re.search(p, uri_str.lower()) for p in self.PRIV_ESC_PATTERNS)
        features.append(float(has_priv))
        
        # 11: Has data exfiltration (binary)
        has_exfil = (
            "/export" in uri_str.lower() or
            "/download" in uri_str.lower() or
            "/backup" in uri_str.lower() or
            record.response_size > 1_000_000
        )
        features.append(float(has_exfil))
        
        # 12: Has suspicious agent (binary)
        has_bad_agent = any(a in user_agent_str.lower() for a in self.BAD_AGENTS)
        features.append(float(has_bad_agent))
        
        # 13: Is client error (binary)
        features.append(float(400 <= record.status_code < 500))
        
        # 14: Is server error (binary)
        features.append(float(500 <= record.status_code < 600))
        
        # 15: Is POST method (binary)
        features.append(float(record.method == 'POST'))
        
        # 16: URI length z-score (numeric)
        if stats['std_uri_length'] > 0:
            zscore = (len(uri_str) - stats['mean_uri_length']) / stats['std_uri_length']
        else:
            zscore = 0.0
        features.append(np.clip(zscore, -5, 5))
        
        # 17: Response size z-score (numeric)
        if stats['std_response_size'] > 0:
            zscore = (record.response_size - stats['mean_response_size']) / stats['std_response_size']
        else:
            zscore = 0.0
        features.append(np.clip(zscore, -5, 5))
        
        # 18: Duration z-score (numeric)
        if stats['std_duration'] > 0:
            zscore = (record.duration - stats['mean_duration']) / stats['std_duration']
        else:
            zscore = 0.0
        features.append(np.clip(zscore, -5, 5))
        
        return features


# ============================================================================
# GENERIC FEATURE EXTRACTION
# ============================================================================

class GenericFeatureExtractor:
    """Extract features from any CSV data"""
    
    def extract_features(
        self, 
        records: List[GenericRecord], 
        schema_info: Dict[str, Any]
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Extract features from generic CSV records"""
        if not records:
            raise ValueError("No records to extract features from")
        
        numeric_columns = schema_info['numeric_columns']
        categorical_columns = schema_info['categorical_columns']
        
        logger.info(f"Extracting features: {len(numeric_columns)} numeric, {len(categorical_columns)} categorical")
        
        features_list = []
        feature_names = []
        
        # Extract numeric features
        for col in numeric_columns:
            values = []
            for record in records:
                try:
                    val = float(record.data.get(col, 0))
                    values.append(val)
                except (ValueError, TypeError):
                    values.append(0.0)
            
            features_list.append(values)
            feature_names.append(f"numeric_{col}")
        
        # Extract categorical features (one-hot encoding for top categories)
        for col in categorical_columns[:5]:
            unique_values = set()
            for record in records:
                val = str(record.data.get(col, ''))
                if val:
                    unique_values.add(val)
            
            value_counts = {}
            for record in records:
                val = str(record.data.get(col, ''))
                value_counts[val] = value_counts.get(val, 0) + 1
            
            top_values = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_value_set = {v[0] for v in top_values}
            
            for top_val in top_value_set:
                binary_feature = [1.0 if str(record.data.get(col, '')) == top_val else 0.0 
                                 for record in records]
                features_list.append(binary_feature)
                feature_names.append(f"cat_{col}_{top_val[:20]}")
        
        feature_matrix = np.array(features_list, dtype=np.float32).T
        
        if feature_matrix.shape[1] == 0:
            logger.warning("No features extracted, creating dummy feature")
            feature_matrix = np.ones((len(records), 1), dtype=np.float32)
            feature_names = ['dummy_feature']
        
        feature_info = {
            'feature_names': feature_names,
            'num_features': feature_matrix.shape[1],
            'num_records': len(records),
            'numeric_columns': numeric_columns,
            'categorical_columns': categorical_columns,
        }
        
        logger.info(f"Extracted {feature_matrix.shape[0]} records with {feature_matrix.shape[1]} features")
        
        return feature_matrix, feature_info


# ============================================================================
# UNIVERSAL FEATURE EXTRACTOR
# ============================================================================

class UniversalFeatureExtractor:
    """Main feature extractor that handles both HTTP logs and generic CSV"""
    
    def __init__(self):
        self.http_extractor = HTTPFeatureExtractor()
        self.generic_extractor = GenericFeatureExtractor()
    
    def extract(
        self,
        records: List[Union[HTTPRecord, GenericRecord]],
        file_type: str,
        schema_info: Dict[str, Any] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Extract features from any type of records"""
        if file_type == 'http':
            return self.http_extractor.extract_features(records)
        elif file_type == 'generic':
            if schema_info is None:
                raise ValueError("schema_info required for generic file type")
            return self.generic_extractor.extract_features(records, schema_info)
        else:
            raise ValueError(f"Unknown file type: {file_type}")
