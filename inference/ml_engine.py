"""
ML Anomaly Detection Engine - Layer 3
Statistical anomaly scoring using ML models
"""
import numpy as np
from typing import Tuple, Dict, Any
from dataclasses import dataclass
from models import IsolationForestInference, AutoencoderInference
import logging

logger = logging.getLogger(__name__)


@dataclass
class MLResult:
    """Result from ML anomaly detection"""
    anomaly_score: float
    is_anomaly: bool
    ml_metadata: dict


class MLEngine:
    """Layer 3: ML-based anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForestInference()
        self.autoencoder = AutoencoderInference()
        self.detection_count = 0
    
    def predict(self, features: np.ndarray, model_type: str) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Run ML anomaly detection on feature vectors
        
        Args:
            features: Feature matrix (n_samples, n_features)
            model_type: 'isolation_forest' or 'autoencoder'
        
        Returns:
            Tuple of (anomaly_scores, metadata)
        """
        logger.info(f"Running ML anomaly detection with {model_type} on {features.shape[0]} records")
        
        if model_type == 'isolation_forest':
            scores, is_anomaly = self.isolation_forest.predict(features)
            metadata = {
                'model': 'isolation_forest',
                'anomaly_count': int(np.sum(is_anomaly)),
                'mean_score': float(np.mean(scores)),
                'std_score': float(np.std(scores))
            }
            self.detection_count = int(np.sum(is_anomaly))
            return scores, metadata
        
        elif model_type == 'autoencoder':
            scores, ae_metadata = self.autoencoder.predict(features)
            metadata = {
                'model': 'autoencoder',
                'mean_score': float(np.mean(scores)),
                'std_score': float(np.std(scores)),
                **ae_metadata
            }
            # Count anomalies using threshold
            threshold = np.percentile(scores, 80)
            self.detection_count = int(np.sum(scores >= threshold))
            return scores, metadata
        
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def get_anomaly_score_normalized(self, score: float, all_scores: np.ndarray) -> float:
        """
        Normalize anomaly score to 0-1 range
        
        Args:
            score: Raw anomaly score
            all_scores: All scores for normalization
        
        Returns:
            Normalized score between 0 and 1
        """
        min_score = np.min(all_scores)
        max_score = np.max(all_scores)
        
        if max_score == min_score:
            return 0.5
        
        normalized = (score - min_score) / (max_score - min_score)
        return float(np.clip(normalized, 0.0, 1.0))
    
    def retrain_model(self, model_type: str, training_data: np.ndarray):
        """
        Retrain ML model with new data
        
        Args:
            model_type: 'isolation_forest' or 'autoencoder'
            training_data: Training feature matrix
        """
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
            import time
            time.sleep(0.1)
            self.autoencoder = AutoencoderInference(model_path=AUTOENCODER_MODEL_PATH)
            logger.info(f"Autoencoder retrained with {training_data.shape[1]} features")
        
        else:
            raise ValueError(f"Unknown model type: {model_type}")
