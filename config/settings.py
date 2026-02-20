"""
Configuration and Settings for Enterprise Log Anomaly Detection System
"""
import os
from pathlib import Path

# ============================================================================
# PROJECT PATHS
# ============================================================================
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = DATA_DIR / "models"
UPLOADS_DIR = PROJECT_ROOT / "uploads"
SESSION_DIR = PROJECT_ROOT / "sessions"

# Create directories if they don't exist
for directory in [DATA_DIR, MODELS_DIR, UPLOADS_DIR, SESSION_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ============================================================================
# MODEL PATHS
# ============================================================================
# CRITICAL: Each model has separate artifacts to ensure independence
ISOLATION_FOREST_MODEL_PATH = MODELS_DIR / "isolation_forest.pkl"
AUTOENCODER_MODEL_PATH = MODELS_DIR / "autoencoder"  # Base path for autoencoder files

# ============================================================================
# ISOLATION FOREST CONFIGURATION
# ============================================================================
ISOLATION_FOREST_CONFIG = {
    "n_estimators": 150,
    "max_samples": 256,
    "contamination": 0.08,  # Expect ~8% anomalies in new dataset
    "random_state": 42,
    "n_jobs": -1,
}

# Anomaly scoring thresholds for Isolation Forest
# Normalized to 0-1: higher score = more anomalous
ISOLATION_FOREST_SEVERITY_THRESHOLDS = {
    "critical": 0.92,   # Top 8% most anomalous
    "high": 0.80,       # 8-20% anomaly range
    "medium": 0.60,     # 20-40% anomaly range
    "low": 0.40,        # 40-60% anomaly range
    "normal": 0.00,     # Bottom 40%
}

# ============================================================================
# AUTOENCODER CONFIGURATION
# ============================================================================
AUTOENCODER_CONFIG = {
    "encoding_dim": 8,
    "input_dim": None,  # Will be set based on feature count
    "epochs": 50,
    "batch_size": 32,
    "validation_split": 0.2,
    "random_seed": 42,
}

# Reconstruction error percentile-based thresholds for Autoencoder
# Scores are reconstruction errors normalized to 0-1
AUTOENCODER_SEVERITY_THRESHOLDS = {
    "critical": 0.90,   # Top 10% reconstruction errors
    "high": 0.75,       # 75-90% errors
    "medium": 0.60,     # 60-75% errors
    "low": 0.40,        # 40-60% errors
    "normal": 0.00,     # 0-40% errors
}

# ============================================================================
# FEATURE EXTRACTION CONFIGURATION
# ============================================================================
FEATURE_EXTRACTION_CONFIG = {
    # Log-specific features
    "log_features": {
        "response_code_4xx": bool,
        "response_code_5xx": bool,
        "large_response_bytes": bool,
        "slow_response_time": bool,
        "unusual_user_agent": bool,
        "suspicious_uri": bool,
        "high_request_rate": bool,
    },
    
    # CSV-specific features (statistical)
    "csv_features": {
        "numerical_outliers": bool,
        "missing_values": bool,
        "categorical_anomalies": bool,
    },
}

# ============================================================================
# FLASK CONFIGURATION
# ============================================================================
FLASK_CONFIG = {
    "SECRET_KEY": "enterprise-log-anomaly-detector-2026",
    "MAX_CONTENT_LENGTH": 100 * 1024 * 1024,  # 100MB max upload
    "UPLOAD_EXTENSIONS": {".log", ".csv", ".txt"},
    "SESSION_TIMEOUT": 3600,  # 1 hour
}

# ============================================================================
# SEVERITY MAPPING
# ============================================================================
SEVERITY_LEVELS = ["normal", "low", "medium", "high", "critical"]

SEVERITY_COLORS = {
    "normal": "#28a745",
    "low": "#ffc107",
    "medium": "#fd7e14",
    "high": "#dc3545",
    "critical": "#721c24",
}

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'
