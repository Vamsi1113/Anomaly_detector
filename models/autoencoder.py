"""
Autoencoder Model Training and Inference
Reconstruction error-based anomaly detection using Deep Learning
"""
import numpy as np
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
import logging
import json
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    from sklearn.preprocessing import StandardScaler
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available. Autoencoder will use mock implementation.")


# ============================================================================
# TRAINING DATA GENERATION
# ============================================================================

def generate_autoencoder_training_data(num_features: int = 11) -> np.ndarray:
    """
    Generate synthetic training data for Autoencoder
    Similar to normal log patterns (11 features for HTTP logs)
    """
    np.random.seed(42)
    
    n_samples = 2000
    
    # Normal distribution with some structure
    normal_data = np.random.randn(n_samples, num_features) * 0.5
    
    # Add some patterns
    normal_data[:, 0] = np.clip(normal_data[:, 0], -2, 2)  # Bounded
    normal_data[:, 1] = np.abs(normal_data[:, 1])  # Always positive
    
    logger.info(f"Generated {normal_data.shape} training data for Autoencoder")
    return normal_data


# ============================================================================
# AUTOENCODER ARCHITECTURE
# ============================================================================

def build_autoencoder(input_dim: int, encoding_dim: int) -> Tuple[Any, Any]:
    """
    Build encoder and autoencoder models
    
    Args:
        input_dim: Input feature dimension
        encoding_dim: Dimension of encoded representation
        
    Returns:
        Tuple of (encoder_model, autoencoder_model)
    """
    if not TENSORFLOW_AVAILABLE:
        logger.warning("TensorFlow not available, returning None for models")
        return None, None
    
    # Encoder
    input_img = keras.Input(shape=(input_dim,))
    encoded = layers.Dense(32, activation='relu')(input_img)
    encoded = layers.Dense(16, activation='relu')(encoded)
    encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
    
    encoder = keras.Model(input_img, encoded)
    
    # Decoder
    encoded_input = keras.Input(shape=(encoding_dim,))
    decoded = layers.Dense(16, activation='relu')(encoded_input)
    decoded = layers.Dense(32, activation='relu')(decoded)
    decoded = layers.Dense(input_dim, activation='linear')(decoded)
    
    decoder = keras.Model(encoded_input, decoded)
    
    # Autoencoder
    output = decoder(encoder(input_img))
    autoencoder = keras.Model(input_img, output)
    
    autoencoder.compile(optimizer='adam', loss='mse')
    
    logger.info(f"Built Autoencoder: input_dim={input_dim}, encoding_dim={encoding_dim}")
    
    return encoder, autoencoder


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_autoencoder(
    config: Dict[str, Any],
    training_data: np.ndarray = None,
    input_dim: int = None
) -> Tuple[Optional[Any], Optional[StandardScaler], Optional[Any]]:
    """
    Train Autoencoder model
    
    Args:
        config: Model configuration
        training_data: Training data array
        input_dim: Input dimension (auto-detected from training_data)
        
    Returns:
        Tuple of (autoencoder_model, scaler, encoder_model)
    """
    if training_data is None:
        if input_dim is None:
            input_dim = 18
        training_data = generate_autoencoder_training_data(input_dim)
    else:
        input_dim = training_data.shape[1]
    
    # Standardize data - ALWAYS fit the scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(training_data)
    
    if not TENSORFLOW_AVAILABLE:
        logger.warning("TensorFlow not available, returning mock models with fitted scaler")
        return None, scaler, None
    
    # Build model
    encoder, autoencoder = build_autoencoder(input_dim, config['encoding_dim'])
    
    if autoencoder is None:
        logger.warning("Could not build autoencoder, returning None")
        return None, scaler, None
    
    # Train
    autoencoder.fit(
        X_scaled, X_scaled,
        epochs=config['epochs'],
        batch_size=config['batch_size'],
        validation_split=config['validation_split'],
        verbose=0,
        shuffle=True
    )
    
    logger.info("Autoencoder model trained successfully")
    return autoencoder, scaler, encoder


# ============================================================================
# MODEL SERIALIZATION
# ============================================================================

def save_autoencoder(
    autoencoder: Optional[Any],
    scaler: StandardScaler,
    encoder: Optional[Any],
    filepath: Path
) -> None:
    """Save trained autoencoder and scaler"""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    if TENSORFLOW_AVAILABLE and autoencoder is not None:
        # Save Keras models
        autoencoder.save(str(filepath.with_suffix('.h5')))
        encoder.save(str(filepath.with_stem(filepath.stem + '_encoder').with_suffix('.h5')))
    
    # Save scaler
    import pickle
    with open(filepath.with_stem(filepath.stem + '_scaler').with_suffix('.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    
    logger.info(f"Autoencoder models saved to {filepath}")


def load_autoencoder(filepath: Path) -> Tuple[Optional[Any], StandardScaler, Optional[Any]]:
    """Load trained autoencoder and scaler"""
    filepath = Path(filepath)
    
    # Check if the actual model files exist (not just the base path)
    h5_path = filepath.with_suffix('.h5')
    scaler_path = filepath.with_stem(filepath.stem + '_scaler').with_suffix('.pkl')
    
    if not h5_path.exists() and not scaler_path.exists():
        logger.error(f"Model files not found at {filepath}. Cannot load autoencoder.")
        return None, StandardScaler(), None
    
    import pickle
    
    # Load scaler
    if scaler_path.exists():
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        logger.info(f"Loaded scaler from {scaler_path}")
    else:
        logger.warning(f"Scaler not found at {scaler_path}")
        scaler = StandardScaler()
    
    # Load models if TensorFlow available
    autoencoder = None
    encoder = None
    if TENSORFLOW_AVAILABLE:
        try:
            if h5_path.exists():
                autoencoder = keras.models.load_model(str(h5_path))
                logger.info(f"Loaded autoencoder from {h5_path}")
                
            encoder_path = filepath.with_stem(filepath.stem + '_encoder').with_suffix('.h5')
            if encoder_path.exists():
                encoder = keras.models.load_model(str(encoder_path))
                logger.info(f"Loaded encoder from {encoder_path}")
        except Exception as e:
            logger.error(f"Error loading Keras models: {e}")
    
    return autoencoder, scaler, encoder


# ============================================================================
# INFERENCE
# ============================================================================

class AutoencoderInference:
    """Autoencoder inference engine"""
    
    def __init__(self, model_path: Path = None):
        """Initialize with optional custom model path"""
        if model_path is None:
            from config import AUTOENCODER_MODEL_PATH
            model_path = AUTOENCODER_MODEL_PATH
        
        self.autoencoder, self.scaler, self.encoder = load_autoencoder(model_path)
        self.reconstruction_errors = None
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Predict reconstruction errors and anomaly scores on UPLOADED DATA
        
        Args:
            X: Feature matrix from UPLOADED FILE (num_samples, num_features)
            
        Returns:
            Tuple of (anomaly_scores, metadata)
        """
        # CRITICAL: Standardize uploaded data using trained scaler
        X_scaled = self.scaler.transform(X)
        
        if self.autoencoder is None:
            # Fallback: use statistical method
            logger.warning("Autoencoder model not available, using fallback method")
            return self._fallback_predict(X_scaled)
        
        # Get reconstructions from uploaded data
        X_reconstructed = self.autoencoder.predict(X_scaled, verbose=0)
        
        # Calculate reconstruction errors for THIS data
        reconstruction_errors = np.mean(np.square(X_scaled - X_reconstructed), axis=1)
        
        # Normalize to 0-1 based on THIS data distribution
        anomaly_scores = self._normalize_reconstruction_errors(reconstruction_errors)
        
        metadata = {
            'mean_error': float(np.mean(reconstruction_errors)),
            'std_error': float(np.std(reconstruction_errors)),
            'max_error': float(np.max(reconstruction_errors)),
            'min_error': float(np.min(reconstruction_errors)),
        }
        
        return anomaly_scores, metadata
    
    @staticmethod
    def _normalize_reconstruction_errors(errors: np.ndarray) -> np.ndarray:
        """
        Normalize reconstruction errors to 0-1 range
        Higher error → higher anomaly score
        
        CRITICAL: This normalization is based on the CURRENT data distribution
        """
        # Min-max normalization on current data
        if len(errors) == 0:
            return np.array([])
        
        error_min = np.min(errors)
        error_max = np.max(errors)
        
        if error_max == error_min:
            return np.full_like(errors, 0.5)
        
        # Normalize to 0-1 where high error = high score
        normalized = (errors - error_min) / (error_max - error_min)
        
        return normalized
    
    def _fallback_predict(self, X_scaled: np.ndarray) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Fallback prediction using statistical method"""
        # Use mean absolute deviation as proxy for reconstruction error
        deviations = np.abs(X_scaled - np.mean(X_scaled, axis=0))
        mean_deviation = np.mean(deviations, axis=1)
        
        # Normalize
        if np.max(mean_deviation) == 0:
            anomaly_scores = np.full_like(mean_deviation, 0.5)
        else:
            anomaly_scores = mean_deviation / np.max(mean_deviation)
        
        metadata = {
            'mean_error': float(np.mean(mean_deviation)),
            'std_error': float(np.std(mean_deviation)),
            'max_error': float(np.max(mean_deviation)),
            'min_error': float(np.min(mean_deviation)),
            'method': 'fallback_statistical',
        }
        
        return anomaly_scores, metadata
