"""
Enterprise Log Anomaly Detection System
Main Flask application
"""
import os
import logging
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session as flask_session
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from config import (
    FLASK_CONFIG,
    PROJECT_ROOT,
    UPLOADS_DIR,
)
from parsing import UniversalParser
from features import UniversalFeatureExtractor
from inference import AnomalyDetectionEngine
from storage import create_session, get_session, cleanup_sessions

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app = Flask(__name__, template_folder='ui/templates', static_folder='ui/static')
app.config.update(FLASK_CONFIG)

# Initialize detection engine with optional LLM enrichment
# Set ENABLE_LLM=true and OPENAI_API_KEY in environment to enable
ENABLE_LLM = os.getenv('ENABLE_LLM', 'false').lower() == 'true'
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', None)

detection_engine = AnomalyDetectionEngine(
    enable_llm=ENABLE_LLM,
    openai_api_key=OPENAI_API_KEY
)
parser = UniversalParser()
feature_extractor = UniversalFeatureExtractor()

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_or_create_session():
    """Get or create user session"""
    if 'session_id' not in flask_session:
        sess = create_session()
        flask_session['session_id'] = sess.session_id
        logger.info(f"Created new session: {sess.session_id}")
        return sess
    else:
        session_id = flask_session['session_id']
        sess = get_session(session_id)
        if sess is None:
            sess = create_session()
            flask_session['session_id'] = sess.session_id
            logger.info(f"Previous session not found, created new: {sess.session_id}")
        return sess


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'log', 'csv', 'txt'}


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main dashboard"""
    sess = get_or_create_session()
    
    # Retrieve session data - ensure results are dictionaries
    results = sess.get('results')
    
    # Handle corrupted or old session data
    if results:
        try:
            if isinstance(results, list) and len(results) > 0:
                # Check if first item is a dictionary
                if isinstance(results[0], dict):
                    # Already in correct format
                    pass
                elif isinstance(results[0], str):
                    # Corrupted data - clear it
                    logger.warning("Corrupted session data detected (strings instead of dicts), clearing session")
                    sess.clear()
                    results = None
                elif hasattr(results[0], 'to_dict'):
                    # Convert objects to dictionaries
                    results = [r.to_dict() for r in results]
                else:
                    # Unknown format - clear
                    logger.warning(f"Unknown session data format: {type(results[0])}, clearing session")
                    sess.clear()
                    results = None
        except Exception as e:
            logger.error(f"Error processing session results: {e}")
            # Clear corrupted session data
            sess.clear()
            results = None
    
    session_data = {
        'current_file': sess.get('current_file'),
        'current_model': sess.get('current_model'),
        'stats': sess.get('stats'),
        'results': results,
    }
    
    return render_template('dashboard.html', session_data=session_data)


@app.route('/detect', methods=['POST'])
def detect():
    """Run anomaly detection with automatic model retraining on mismatch"""
    try:
        # Get or create session
        sess = get_or_create_session()
        
        # Check if this is a re-run on existing file
        is_rerun = request.form.get('rerun') == 'true'
        logger.info(f"Detection request - is_rerun: {is_rerun}, has_file: {'file' in request.files}")
        
        if is_rerun:
            # Re-run detection on previously uploaded file
            current_file = sess.get('current_file')
            logger.info(f"Re-run mode - current_file in session: {current_file}")
            
            if not current_file:
                logger.error("Re-run requested but no file in session")
                return jsonify({'success': False, 'error': 'No file in session. Please upload a new file.'}), 400
            
            # Find the most recent file with this name
            matching_files = sorted(UPLOADS_DIR.glob(f"*_{current_file}"), reverse=True)
            logger.info(f"Found {len(matching_files)} matching files for: {current_file}")
            
            if not matching_files:
                logger.error(f"No matching files found in {UPLOADS_DIR}")
                return jsonify({'success': False, 'error': 'Previous file not found. Please upload a new file.'}), 400
            
            filepath = matching_files[0]
            filename = current_file
            logger.info(f"Re-running detection on: {filepath}")
            
            # Clear session data AFTER we've retrieved the file info
            sess.clear()
        else:
            # New file upload
            # Clear session data first for new uploads
            sess.clear()
            
            # Get uploaded file
            if 'file' not in request.files:
                logger.error("No file in request.files")
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                logger.error("Empty filename")
                return jsonify({'success': False, 'error': 'No file selected'}), 400
            
            if not allowed_file(file.filename):
                logger.error(f"Invalid file type: {file.filename}")
                return jsonify({'success': False, 'error': 'Invalid file type'}), 400
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            filepath = UPLOADS_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            filepath.parent.mkdir(parents=True, exist_ok=True)
            file.save(str(filepath))
            logger.info(f"File saved: {filepath}")
        
        # Get model selection
        model = request.form.get('model', 'isolation_forest')
        logger.info(f"Model selected: {model}")
        
        if model not in ['isolation_forest', 'autoencoder']:
            return jsonify({'success': False, 'error': 'Invalid model'}), 400
        
        # Parse file
        try:
            records, parse_errors, file_type, schema_info = parser.parse(filepath)
            logger.info(f"Parsed {len(records)} records from {file_type} file")
            if parse_errors:
                logger.warning(f"Parsing encountered {len(parse_errors)} errors")
        except Exception as e:
            logger.error(f"Parsing error: {e}")
            return jsonify({'success': False, 'error': f'Failed to parse file: {str(e)}'}), 400
        
        # Extract features FROM UPLOADED FILE
        try:
            if file_type == 'generic':
                features, feature_info = feature_extractor.extract(records, file_type, schema_info)
            else:
                features, feature_info = feature_extractor.extract(records, file_type)
            logger.info(f"Extracted {features.shape[1]} features from {features.shape[0]} records")
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return jsonify({'success': False, 'error': f'Failed to extract features: {str(e)}'}), 400
        
        # Run detection ON UPLOADED DATA with automatic model retraining
        max_retries = 2
        for attempt in range(max_retries):
            try:
                results, stats = detection_engine.detect_anomalies(
                    records=records,
                    features=features,
                    file_type=file_type,
                    model_type=model,
                    feature_info=feature_info
                )
                logger.info(f"Detection complete: {len(results)} records, {stats['total_anomalies']} anomalies")
                break  # Success!
                
            except ValueError as e:
                error_msg = str(e)
                
                # Check if it's a feature mismatch error
                if 'features' in error_msg and 'expecting' in error_msg:
                    if attempt < max_retries - 1:
                        logger.warning(f"Feature mismatch detected: {error_msg}")
                        logger.info(f"Auto-retraining {model} model with {features.shape[1]} features from uploaded data...")
                        
                        # Retrain the model using the uploaded data
                        try:
                            detection_engine.retrain_model_on_data(
                                model_type=model,
                                training_data=features
                            )
                            logger.info(f"✓ Model retrained successfully with {features.shape[1]} features")
                            # Retry detection with newly trained model
                            continue
                        except Exception as retrain_error:
                            logger.error(f"Failed to retrain model: {retrain_error}")
                            return jsonify({
                                'success': False, 
                                'error': f'Model mismatch and retraining failed: {str(retrain_error)}'
                            }), 500
                    else:
                        return jsonify({
                            'success': False, 
                            'error': f'Feature mismatch persists after retraining: {error_msg}'
                        }), 500
                else:
                    # Different ValueError, don't retry
                    raise
                    
            except Exception as e:
                logger.error(f"Detection error: {e}")
                return jsonify({'success': False, 'error': f'Failed to run detection: {str(e)}'}), 400
        
        # Store results in session
        results_data = [r.to_dict() for r in results]
        sess.set('current_file', filename)
        sess.set('current_model', model)
        sess.set('results', results_data)
        sess.set('stats', stats)
        sess.set('file_type', file_type)
        sess.set('record_count', len(records))
        
        logger.info(f"Results stored in session {sess.session_id}")
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.exception(f"Unexpected error in /detect: {e}")
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500


@app.route('/api/session')
def get_session_info():
    """Get current session info (API)"""
    sess = get_or_create_session()
    
    return jsonify({
        'session_id': sess.session_id,
        'current_file': sess.get('current_file'),
        'current_model': sess.get('current_model'),
        'has_results': sess.get('results') is not None,
    })


@app.route('/clear-session', methods=['POST'])
def clear_session_route():
    """Clear current session"""
    if 'session_id' in flask_session:
        session_id = flask_session['session_id']
        sess = get_session(session_id)
        if sess:
            sess.clear()
    
    flask_session.pop('session_id', None)
    return jsonify({'success': True})


@app.route('/new-session')
def new_session():
    """Start a new session (clear current and redirect)"""
    if 'session_id' in flask_session:
        session_id = flask_session['session_id']
        sess = get_session(session_id)
        if sess:
            sess.clear()
    
    flask_session.pop('session_id', None)
    logger.info("New session started - cleared previous session")
    return render_template('dashboard.html', session_data={
        'current_file': None,
        'current_model': None,
        'stats': None,
        'results': None,
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large"""
    return jsonify({'success': False, 'error': 'File too large. Maximum size is 100MB'}), 413


@app.errorhandler(404)
def not_found(error):
    """Handle 404"""
    return jsonify({'success': False, 'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500"""
    logger.error(f"Internal server error: {error}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


# ============================================================================
# BEFORE/AFTER HANDLERS
# ============================================================================

@app.before_request
def before_request():
    """Execute before each request"""
    # Cleanup expired sessions periodically
    if request.path == '/':
        cleanup_sessions()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    logger.info(f"Starting Enterprise Log Anomaly Detection System")
    logger.info(f"Project root: {PROJECT_ROOT}")
    logger.info(f"Uploads directory: {UPLOADS_DIR}")
    
    # Create necessary directories
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=False
    )
