"""
Model Retraining Script
Trains Isolation Forest and Autoencoder on CLEAN traffic only
"""
import numpy as np
import logging
from pathlib import Path

from parsing import UniversalParser
from features import UniversalFeatureExtractor
from models import train_isolation_forest, train_autoencoder, save_model, save_autoencoder
from config import ISOLATION_FOREST_CONFIG, AUTOENCODER_CONFIG, ISOLATION_FOREST_MODEL_PATH, AUTOENCODER_MODEL_PATH, PROJECT_ROOT

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main():
    training_file = PROJECT_ROOT / "orglog1.csv"
    
    if not training_file.exists():
        logger.error(f"Training file not found: {training_file}")
        logger.info("Run: python generate_advanced_logs.py")
        return
    
    logger.info(f"{'='*60}")
    logger.info(f"RETRAINING MODELS ON: {training_file.name}")
    logger.info(f"{'='*60}")
    
    parser = UniversalParser()
    records, errors, file_type, schema_info = parser.parse(training_file)
    logger.info(f"Parsed {len(records)} records ({file_type} format)")
    
    if errors:
        logger.warning(f"Parsing errors: {len(errors)}")
    
    feature_extractor = UniversalFeatureExtractor()
    if file_type == 'generic':
        features, feature_info = feature_extractor.extract(records, file_type, schema_info)
    else:
        features, feature_info = feature_extractor.extract(records, file_type)
    
    logger.info(f"Extracted {features.shape[1]} features from {features.shape[0]} records")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"TRAINING ISOLATION FOREST")
    logger.info(f"{'='*60}")
    
    iso_model, iso_scaler = train_isolation_forest(ISOLATION_FOREST_CONFIG, features)
    save_model(iso_model, iso_scaler, ISOLATION_FOREST_MODEL_PATH)
    logger.info(f"✓ Isolation Forest saved")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"TRAINING AUTOENCODER")
    logger.info(f"{'='*60}")
    
    ae_model, ae_scaler, ae_encoder = train_autoencoder(AUTOENCODER_CONFIG, training_data=features)
    
    if ae_model is not None:
        save_autoencoder(ae_model, ae_scaler, ae_encoder, AUTOENCODER_MODEL_PATH)
        logger.info(f"✓ Autoencoder saved")
    else:
        logger.warning("Autoencoder training failed")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"RETRAINING COMPLETE!")
    logger.info(f"{'='*60}")
    logger.info(f"Models trained on {features.shape[0]} records with {features.shape[1]} features")
    logger.info(f"\nNext: python app.py")


if __name__ == "__main__":
    main()
