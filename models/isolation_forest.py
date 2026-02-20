"""
Isolation Forest Model Training and Inference
Statistical anomaly detection using Isolation Forest
"""
import numpy as np
import pickle
from pathlib import Path
from typing import Tuple, List, Dict, Any
import logging

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ============================================================================
# TRAINING DATA GENERATION
# ============================================================================

def generate_training_data() -> np.ndarray:
    """
    Generate synthetic training data for initial model training
    Simulates normal log behavior with known distributions (11 features)
    """
    np.random.seed(42)
    
    # Normal log patterns
    n_samples = 2000
    
    # Most logs are normal (11 features to match HTTP feature extraction)
    normal_samples = np.random.randn(int(n_samples * 0.9), 11) * 0.5
    
    # Add some structured patterns
    normal_samples[:, 0] = np.random.binomial(1, 0.05, int(n_samples * 0.9))  # 5% client errors
    normal_samples[:, 1] = np.random.binomial(1, 0.02, int(n_samples * 0.9))  # 2% server errors
    normal_samples[:, 4] = np.random.binomial(1, 0.03, int(n_samples * 0.9))  # 3% large responses
    normal_samples[:, 5] = np.random.binomial(1, 0.01, int(n_samples * 0.9))  # 1% suspicious URIs
    
    # Some anomalies in training (for robust model)
    anomaly_samples = np.random.uniform(-3, 3, (int(n_samples * 0.1), 11))
    anomaly_samples[:, 0] = np.random.binomial(1, 0.5, int(n_samples * 0.1))
    anomaly_samples[:, 1] = np.random.binomial(1, 0.3, int(n_samples * 0.1))
    
    training_data = np.vstack([normal_samples, anomaly_samples])
    
    logger.info(f"Generated {training_data.shape[0]} training samples for Isolation Forest")
    return training_data


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_isolation_forest(
    config: Dict[str, Any],
    training_data: np.ndarray = None
) -> Tuple[IsolationForest, StandardScaler]:
    """
    Train Isolation Forest model
    
    Args:
        config: Model configuration dictionary
        training_data: Training data array. If None, generates synthetic data
        
    Returns:
        Tuple of (trained_model, scaler)
    """
    if training_data is None:
        training_data = generate_training_data()
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(training_data)
    
    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=config['n_estimators'],
        max_samples=config['max_samples'],
        contamination=config['contamination'],
        random_state=config['random_state'],
        n_jobs=config['n_jobs']
    )
    
    model.fit(X_scaled)
    
    logger.info("Isolation Forest model trained successfully")
    return model, scaler


# ============================================================================
# MODEL SERIALIZATION
# ============================================================================

def save_model(model: IsolationForest, scaler: StandardScaler, filepath: Path) -> None:
    """Save trained model and scaler to disk"""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    with open(filepath, 'wb') as f:
        pickle.dump({'model': model, 'scaler': scaler}, f)
    
    logger.info(f"Model saved to {filepath}")


def load_model(filepath: Path) -> Tuple[IsolationForest, StandardScaler]:
    """Load trained model and scaler from disk"""
    filepath = Path(filepath)
    
    if not filepath.exists():
        logger.warning(f"Model file not found: {filepath}. Training new model...")
        from config import ISOLATION_FOREST_CONFIG
        model, scaler = train_isolation_forest(ISOLATION_FOREST_CONFIG)
        save_model(model, scaler, filepath)
        return model, scaler
    
    with open(filepath, 'rb') as f:
        data = pickle.load(f)
        model = data['model']
        scaler = data['scaler']
    
    logger.info(f"Model loaded from {filepath}")
    return model, scaler


# ============================================================================
# INFERENCE
# ============================================================================

class IsolationForestInference:
    """Isolation Forest inference engine"""
    
    def __init__(self, model_path: Path = None):
        """Initialize with optional custom model path"""
        if model_path is None:
            from config import ISOLATION_FOREST_MODEL_PATH
            model_path = ISOLATION_FOREST_MODEL_PATH
        
        self.model, self.scaler = load_model(model_path)
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies on UPLOADED DATA
        
        Args:
            X: Feature matrix from UPLOADED FILE (num_samples, num_features)
            
        Returns:
            Tuple of (anomaly_scores, is_anomaly)
            - anomaly_scores: Normalized scores 0-1 (higher = more anomalous)
            - is_anomaly: -1 for anomalies, 1 for normal
        """
        # CRITICAL: Transform uploaded data using trained scaler
        X_scaled = self.scaler.transform(X)
        
        # Get raw anomaly scores from uploaded data
        # Isolation Forest returns -1 for anomalies, 1 for inliers
        is_anomaly = self.model.predict(X_scaled)
        
        # Get raw scores (lower = more anomalous)
        raw_scores = self.model.score_samples(X_scaled)
        
        # Normalize scores to 0-1 range based on THIS data
        anomaly_scores = self._normalize_scores(raw_scores)
        
        return anomaly_scores, is_anomaly
    
    @staticmethod
    def _normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
        """
        Normalize raw anomaly scores to 0-1 range
        Lower raw scores (more anomalous) → higher normalized scores (0.7-1.0)
        Higher raw scores (more normal) → lower normalized scores (0.0-0.3)
        
        CRITICAL: This normalization is based on the CURRENT data distribution
        """
        # Min-max normalization on current data
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        
        if max_score == min_score:
            # All scores are the same
            return np.full_like(raw_scores, 0.5)
        
        # Normalize to 0-1
        normalized = (raw_scores - min_score) / (max_score - min_score)
        
        # Invert so that anomalies (low raw scores) have high normalized scores
        inverted = 1.0 - normalized
        
        return inverted
