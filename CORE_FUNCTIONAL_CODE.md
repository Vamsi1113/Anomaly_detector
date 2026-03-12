# Core Functional Codes - Anomaly Detector\n\n## File Uploading & Main Application\n\n### File: app.py\n\n`python\n"""
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
# override=True ensures .env values take precedence over system environment
load_dotenv(override=True)

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
\n`\n\n## Parsing & Feature Extraction\n\n### File: parsing/parser.py\n\n`python\n"""
Log and CSV File Parsing Module
Universal parser that handles ANY CSV file format
"""
import re
import csv
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class GenericRecord:
    """Represents a single row from any CSV file"""
    row_index: int
    data: Dict[str, Any]
    identifier: str = ""  # Best guess at unique identifier
    timestamp: str = ""   # Best guess at timestamp
    
    def __post_init__(self):
        """Auto-detect identifier and timestamp after initialization"""
        if not self.identifier:
            self.identifier = self._find_identifier()
        if not self.timestamp:
            self.timestamp = self._find_timestamp()
    
    def _find_identifier(self) -> str:
        """Find the best column to use as identifier"""
        # Priority: id, ip, email, user, name, or first column
        priority_keys = ['id', 'ip', 'client_ip', 'email', 'user', 'username', 'name']
        
        for key in priority_keys:
            for col_name, value in self.data.items():
                if key in col_name.lower():
                    return str(value)
        
        # Fallback: use first column value
        if self.data:
            return str(list(self.data.values())[0])
        
        return f"row_{self.row_index}"
    
    def _find_timestamp(self) -> str:
        """Find the best column to use as timestamp"""
        # Priority: timestamp, time, date, created
        priority_keys = ['timestamp', 'time', 'date', 'created', 'datetime']
        
        for key in priority_keys:
            for col_name, value in self.data.items():
                if key in col_name.lower():
                    return str(value)
        
        return ""


@dataclass
class HTTPRecord:
    """Represents a single HTTP log entry (legacy support)"""
    timestamp: str
    client_ip: str
    method: str
    uri: str
    status_code: int
    response_size: int
    duration: int
    user_agent: str
    raw_row: Dict[str, Any]


# ============================================================================
# UNIVERSAL CSV PARSER
# ============================================================================

class UniversalCSVParser:
    """Parse ANY CSV file format"""
    
    def parse(self, filepath: Path) -> Tuple[List[GenericRecord], List[str], Dict[str, Any]]:
        """
        Parse any CSV file
        
        Returns:
            Tuple of (records, error_messages, schema_info)
        """
        records = []
        errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Auto-detect dialect
                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = 'excel'
                
                f.seek(0)
                reader = csv.DictReader(f, dialect=dialect)
                
                # Validate headers
                if not reader.fieldnames:
                    raise ValueError("CSV file has no headers")
                
                columns = list(reader.fieldnames)
                logger.info(f"Detected {len(columns)} columns: {columns}")
                
                # Parse all rows
                for row_idx, row in enumerate(reader):
                    try:
                        record = GenericRecord(
                            row_index=row_idx,
                            data=dict(row)
                        )
                        records.append(record)
                    except Exception as e:
                        errors.append(f"Line {row_idx + 2}: {str(e)}")
                        continue
                
                # Analyze schema
                schema_info = self._analyze_schema(columns, records)
                
                logger.info(f"Parsed {len(records)} records from {filepath.name}")
                if errors:
                    logger.warning(f"Encountered {len(errors)} parsing errors")
                
                return records, errors, schema_info
        
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {str(e)}")
            raise
    
    def _analyze_schema(self, columns: List[str], records: List[GenericRecord]) -> Dict[str, Any]:
        """Analyze the CSV schema to understand data types"""
        if not records:
            return {'columns': columns, 'types': {}, 'numeric_columns': [], 'categorical_columns': []}
        
        # Sample first few records to detect types
        sample_size = min(100, len(records))
        sample_records = records[:sample_size]
        
        column_types = {}
        numeric_columns = []
        categorical_columns = []
        
        for col in columns:
            # Collect sample values
            values = [r.data.get(col) for r in sample_records if r.data.get(col) not in [None, '', 'None']]
            
            if not values:
                column_types[col] = 'empty'
                continue
            
            # Try to detect type
            numeric_count = 0
            for val in values:
                try:
                    float(str(val))
                    numeric_count += 1
                except (ValueError, TypeError):
                    pass
            
            # If >80% numeric, treat as numeric
            if numeric_count / len(values) > 0.8:
                column_types[col] = 'numeric'
                numeric_columns.append(col)
            else:
                column_types[col] = 'categorical'
                categorical_columns.append(col)
        
        return {
            'columns': columns,
            'types': column_types,
            'numeric_columns': numeric_columns,
            'categorical_columns': categorical_columns,
            'total_columns': len(columns),
            'total_records': len(records)
        }


# ============================================================================
# SYSLOG PARSER
# ============================================================================

class SyslogParser:
    """Parse raw syslog format entries"""
    
    def parse(self, filepath: Path) -> Tuple[List[HTTPRecord], List[str]]:
        """Parse syslog format file with flexible pattern matching"""
        records = []
        errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Preprocessing: Normalize log entries
            # 1. Replace escaped quotes and backslashes
            content = content.replace('\\"', '"')
            content = content.replace('""', '"')
            content = content.replace('\\GET', 'GET')
            content = content.replace('\\POST', 'POST')
            content = content.replace('\\PUT', 'PUT')
            content = content.replace('\\DELETE', 'DELETE')
            content = content.replace('\\PATCH', 'PATCH')
            content = content.replace('\\HEAD', 'HEAD')
            content = content.replace('\\OPTIONS', 'OPTIONS')
            content = content.replace('HTTP/1.1\\', 'HTTP/1.1')
            content = content.replace('HTTP/1.0\\', 'HTTP/1.0')
            content = content.replace('HTTP/2.0\\', 'HTTP/2.0')
            
            # 2. Convert literal \n to actual newlines (for files with escaped newlines)
            content = content.replace(',\\n', '\n')
            content = content.replace('\\n', '\n')
            content = content.replace(',\n', '\n')
            
            # 3. Normalize multiple spaces to single space (but preserve newlines)
            lines = content.split('\n')
            lines = [re.sub(r'[ \t]+', ' ', line.strip()) for line in lines if line.strip()]
            content = '\n'.join(lines)
            
            # Split by syslog entry start pattern OR by newlines
            # First try splitting by newlines (for properly formatted files)
            if '\n' in content:
                log_entries = [line.strip() for line in content.split('\n') if line.strip() and '<' in line]
            else:
                # Fallback: split by syslog pattern (for single-line files)
                log_entries = re.split(r'(?=<\d+>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)', content)
                log_entries = [e.strip() for e in log_entries if e.strip()]
            
            total_entries = len(log_entries)
            logger.info(f"Found {total_entries} log entries to parse")
            
            for line_num, log_line in enumerate(log_entries, 1):
                if not log_line.strip():
                    continue
                
                log_line = log_line.strip()
                
                try:
                    # Pattern 1: Full format with port and domain
                    # <150>Jan 28 08:59:59 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1 12345 abc.example.net - - [timestamp] "GET /uri HTTP/1.1" 200 size duration "ref" "ua"
                    # Handles both [28/Jan/2026:12:40:35 +0530] and [28/Jan/2026:12:40:35 0530]
                    pattern1 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'(?P<port>\d+)\s+(?P<domain>\S+)\s+'
                        r'[^\[]*\[(?P<timestamp>[^\]]+)\]\s+'
                        r'(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)\s+(?P<duration>[\d\-]+)'
                        r'(?:\s+(?P<referer>\S+))?'
                        r'(?:\s+(?P<user_agent>.+?))?$'
                    )
                    
                    # Pattern 2: Format without port (has - - instead)
                    # <150>Jan 28 08:59:59 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1 - - [timestamp] "POST /uri HTTP/1.1" 200 size duration
                    # Also handles: IP1 IP2 - - [timestamp] or IP - - [timestamp]
                    pattern2 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)(?:\s+(?P<dest_ip>[\d\.]+))?\s+'
                        r'-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+(?P<referer>\S+))?'
                        r'(?:\s+(?P<user_agent>.+?))?$'
                    )
                    
                    # Pattern 3: Format with port number instead of dash
                    # <150>Jan 28 09:00:01 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1 - 365560 - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern3 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'-\s+(?P<port>\d+)\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 4: Different hostname format
                    # <150>Jan 28 14:09:16 INMUPA0100LSG12 httpd[2338514]: 172.17.249.64 - - localhost - - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern4 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+-\s+-\s+(?P<domain>\S+)\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 5: Minimal format (IP - - - [timestamp])
                    # <150>Jan 28 12:31:48 inmura0364lw01 httpd[320519]: 10.61.194.7 - - - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern5 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+-\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?(?:\s+(?P<extra>\d+))?'
                        r'(?:\s+(?P<referer>\S+))?'
                        r'(?:\s+(?P<user_agent>.+?))?$'
                    )
                    
                    # Pattern 6: Minimal format with 4 dashes (IP - - - - [timestamp])
                    # <150>Jan 28 12:31:48 inmura0364lw01 httpd[320542]: 10.61.194.7 - - - - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern6 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+-\s+-\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 7: Format with comma in IP field (IP1, IP2 - - [timestamp])
                    # <150>Jan 28 08:10:00 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1, 10.52.156.33 - - [timestamp] "GET / HTTP/1.1" 200 size duration
                    pattern7 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+[\d\.]+,\s+[\d\.]+\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+\d+)?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 8: Format with -- instead of - - (IP dest_ip port domain -- [timestamp])
                    # <100> Feb 19 08:21:01 testserver httpd[12345]: 192.168.1.10 10.0.0.7 55301 abc.test.net --[20/Jan/2026:08:21:01 +0530] "GET /home HTTP/1.1" 200 4521 "-" "Mozilla..."
                    pattern8 = re.compile(
                        r'<\d+>\s*(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'(?P<port>\d+)\s+(?P<domain>\S+)\s+'
                        r'--\[(?P<timestamp>[^\]]+)\]\s+'
                        r'(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)'
                        r'(?:\s+(?P<referer>\S+))?'
                        r'(?:\s+(?P<user_agent>.+?))?$'
                    )
                    
                    # Pattern 9: Format with trailing -- 0 @ number --
                    # <150>Feb 19 18:00:37 testingserver567 httpd[17308]: 10.61.109.4 23.96.179.243 - - [18/Feb/2026:18:00:37 +0530] "GET / HTTP/1.1" 200 2493 "-" "Azure Traffic Manager Endpoint Monitor" -- 0 @ 872 --
                    pattern9 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                        r'(?:\s+--\s+\d+\s+@\s+\d+\s+--)?'
                    )
                    
                    # Pattern 10: Fallback - Very flexible pattern to catch most variations
                    # Matches: <priority>timestamp hostname process: IP ... [timestamp] "METHOD /uri HTTP/x.x" status size ...
                    pattern10 = re.compile(
                        r'<\d+>\s*(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+'
                        r'.*?\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)'
                    )
                    
                    # Try all patterns (specific patterns first, fallback last)
                    match = None
                    for pattern in [pattern8, pattern1, pattern2, pattern3, pattern4, pattern5, pattern6, pattern7, pattern9, pattern10]:
                        match = pattern.search(log_line)
                        if match:
                            break
                    
                    if not match:
                        if '<' in log_line and 'HTTP' in log_line:
                            errors.append(f"Line {line_num}: Could not parse - {log_line[:150]}")
                        continue
                    
                    groups = match.groupdict()
                    
                    # Handle missing or dash values with better defaults
                    response_size = groups.get('response_size', '0')
                    if response_size == '-' or not response_size or response_size == 'None':
                        response_size = '0'
                    
                    duration = groups.get('duration', '0')
                    if duration == '-' or not duration or duration is None or duration == 'None':
                        duration = '0'
                    
                    port = groups.get('port', '0')
                    if not port or port == '-' or port == 'None':
                        port = '0'
                    
                    dest_ip = groups.get('dest_ip', '0.0.0.0')
                    if not dest_ip or dest_ip == '-' or dest_ip == 'None':
                        dest_ip = '0.0.0.0'
                    
                    user_agent = groups.get('user_agent', '')
                    if not user_agent or user_agent == '-' or user_agent == 'None':
                        user_agent = 'Unknown'
                    
                    referer = groups.get('referer', '')
                    if not referer or referer == '-' or referer == 'None':
                        referer = ''
                    
                    uri = groups.get('uri', '/')
                    if not uri:
                        uri = '/'
                    
                    domain = groups.get('domain', '')
                    if not domain or domain == '-' or domain == 'None':
                        domain = ''
                    
                    # Clean fields - remove extra quotes
                    uri = uri.strip('"').strip()
                    user_agent = user_agent.strip('"').strip()
                    referer = referer.strip('"').strip()
                    
                    record = HTTPRecord(
                        timestamp=groups.get('timestamp', ''),
                        client_ip=groups.get('source_ip', '0.0.0.0'),
                        method=groups.get('method', '').upper(),
                        uri=uri,
                        status_code=int(groups.get('status_code', 0)),
                        response_size=int(response_size),
                        duration=int(duration),
                        user_agent=user_agent,
                        raw_row={
                            'hostname': groups.get('hostname', ''),
                            'process': groups.get('process', ''),
                            'dest_ip': dest_ip,
                            'port': port,
                            'domain': domain,
                            'referer': referer,
                        }
                    )
                    records.append(record)
                
                except (ValueError, KeyError, TypeError) as e:
                    error_msg = f"Line {line_num}: Could not parse - {log_line[:150]}"
                    errors.append(error_msg)
                    logger.debug(f"Parse error: {str(e)}")
                    continue
            
            logger.info(f"Parsed {len(records)} syslog records from {filepath.name} (expected {total_entries})")
            if errors:
                logger.warning(f"Encountered {len(errors)} parsing errors")
                for error in errors[:5]:
                    logger.warning(error)
            
            return records, errors
        
        except Exception as e:
            logger.error(f"Error reading syslog file {filepath}: {str(e)}")
            raise


# ============================================================================
# HTTP LOG PARSER (Legacy Support)
# ============================================================================

class HTTPLogParser:
    """Parse HTTP log format (legacy support)"""
    
    REQUIRED_FIELDS = {'timestamp', 'client_ip', 'method', 'uri', 
                      'status_code', 'response_size', 'duration', 'user_agent'}
    
    def parse(self, filepath: Path) -> Tuple[List[HTTPRecord], List[str]]:
        """Parse HTTP log CSV file"""
        records = []
        errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = 'excel'
                
                f.seek(0)
                reader = csv.DictReader(f, dialect=dialect)
                
                if not reader.fieldnames:
                    raise ValueError("CSV file has no headers")
                
                actual_fields = set(reader.fieldnames)
                
                if not self.REQUIRED_FIELDS.issubset(actual_fields):
                    missing = self.REQUIRED_FIELDS - actual_fields
                    raise ValueError(f"Missing required fields: {missing}")
                
                for line_num, row in enumerate(reader, 2):
                    try:
                        record = HTTPRecord(
                            timestamp=str(row['timestamp']).strip(),
                            client_ip=str(row['client_ip']).strip(),
                            method=str(row['method']).strip().upper(),
                            uri=str(row['uri']).strip(),
                            status_code=int(row['status_code']),
                            response_size=int(row['response_size']),
                            duration=int(row['duration']),
                            user_agent=str(row['user_agent']).strip(),
                            raw_row=row
                        )
                        records.append(record)
                    except (ValueError, KeyError, TypeError) as e:
                        errors.append(f"Line {line_num}: {str(e)}")
                        continue
            
            logger.info(f"Parsed {len(records)} HTTP records from {filepath.name}")
            if errors:
                logger.warning(f"Encountered {len(errors)} parsing errors")
            
            return records, errors
        
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {str(e)}")
            raise


# ============================================================================
# UNIVERSAL PARSER
# ============================================================================

class UniversalParser:
    """Main parser that handles ANY CSV file"""
    
    def __init__(self):
        self.universal_parser = UniversalCSVParser()
        self.http_parser = HTTPLogParser()
        self.syslog_parser = SyslogParser()
    
    def parse(self, filepath: Path) -> Tuple[List[Any], List[str], str, Optional[Dict[str, Any]]]:
        """
        Parse file - tries syslog, then HTTP format, then falls back to universal
        
        Returns:
            Tuple of (records, errors, file_type, schema_info)
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        suffix = filepath.suffix.lower()
        
        if suffix not in ['.log', '.txt', '.csv']:
            raise ValueError(f"Unsupported file type: {suffix}")
        
        # Try syslog format first (for raw log files)
        try:
            records, errors = self.syslog_parser.parse(filepath)
            if records:  # Only accept if we got some records
                logger.info(f"Parsed as syslog format")
                return records, errors, 'http', None
        except Exception as e:
            logger.debug(f"Not syslog format: {e}")
        
        # Try HTTP format (for structured CSV with HTTP columns)
        try:
            records, errors = self.http_parser.parse(filepath)
            logger.info(f"Parsed as HTTP log format")
            return records, errors, 'http', None
        except ValueError as e:
            # Not HTTP format, use universal parser
            logger.info(f"Not HTTP format ({e}), using universal parser")
            records, errors, schema_info = self.universal_parser.parse(filepath)
            return records, errors, 'generic', schema_info
        
        if not records:
            raise ValueError("No valid records could be parsed from file")

\n`\n\n### File: features/extractor.py\n\n`python\n"""
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
\n`\n\n## ML Models\n\n### File: models/autoencoder.py\n\n`python\n"""
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
\n`\n\n### File: models/isolation_forest.py\n\n`python\n"""
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
\n`\n\n### File: inference/ml_engine.py\n\n`python\n"""
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
\n`\n\n## Rule-Based Detection\n\n### File: inference/signature_engine.py\n\n`python\n"""
Signature Detection Engine - Layer 1
Deterministic pattern matching for known attack signatures
"""
import re
from urllib.parse import unquote
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class SignatureResult:
    """Result from signature detection"""
    signature_flag: bool
    threat_type: str
    signature_confidence: float
    matched_patterns: list


# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror=", r"onload=",
    r"<iframe", r"alert\(", r"<img.*onerror", r"eval\(",
    r"document\.cookie", r"<svg.*onload"
]

SQLI_PATTERNS = [
    r"sqlmap", r"union\s+select", r"union.*select",
    r"' or '1'='1", r"' or ", r"--", r";--",
    r"drop\s+table", r"insert\s+into",
    r"select\s+\*\s+from", r"select.*from",
    r"1=1", r"' or 1=1", r"admin'--", r"' OR '1"
]

TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"\.\.",
    r"%2e%2e", r"%252e%252e", r"%2e",
    r"/etc/passwd", r"/etc/shadow",
    r"/proc/self", r"/windows/system32",
    r"password\.properties", r"license\.txt",
    r"CFIDE", r"administrator",
    r"\.\.\/\.\.\/", r"file:///"
]

CMD_PATTERNS = [
    r"rm\s+-rf", r";\s*cat\s+/etc/", r"cat /etc",
    r"&&\s*whoami", r"\|\s*bash", r"whoami",
    r";\s*wget", r"`cat", r"; ls", r"&& ls",
    r"cmd=", r"exec\(", r"system\(", r"shell_exec",
    r"\$\{.*\}", r"bash -c"
]

SSRF_PATTERNS = [
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"localhost", r"127\.0\.0\.1",
    r"0\.0\.0\.0", r"::1",
    r"url=http://", r"fetch\?url=",
    r"redirect.*http://"
]

IDOR_PATTERNS = [
    r"/api/user/\d{5,}",
    r"/profile/\d{5,}",
    r"user_id=\d{5,}",
    r"account=\d{5,}"
]

SSTI_PATTERNS = [
    r"\{\{.*\}\}",
    r"\$\{.*\}",
    r"<%.*%>",
    r"#\{.*\}"
]

OPEN_REDIRECT_PATTERNS = [
    r"redirect\?url=http://",
    r"next=http://",
    r"return_to=http://",
    r"goto=http://",
    r"url=//evil"
]

SENSITIVE_FILE_PATTERNS = [
    r"\.env", r"\.git", r"\.svn",
    r"config\.php", r"web\.config",
    r"credentials", r"password",
    r"\.bak", r"\.backup",
    r"\.sql", r"dump\.sql"
]

PRIV_ESC_PATTERNS = [
    r"/admin", r"administrator", r"sudo",
    r"privilege", r"/root", r"escalate",
    r"role=admin", r"isAdmin=true"
]

EXFIL_PATTERNS = [
    r"/export", r"/download", r"/backup",
    r"/dump", r"\.zip", r"\.tar\.gz",
    r"data=.*base64"
]

BAD_AGENTS = [
    "sqlmap", "nikto", "nmap", "curl",
    "python-requests", "masscan", "metasploit",
    "burp", "scanner", "bot", "crawler",
    "acunetix", "nessus", "openvas"
]


# ============================================================================
# SIGNATURE DETECTION FUNCTIONS
# ============================================================================

def _match_patterns(text: str, patterns: list) -> tuple:
    """Match patterns and return (matched, matched_patterns)"""
    if not text:
        return False, []
    matched = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)
    return len(matched) > 0, matched


class SignatureEngine:
    """Layer 1: Signature-based threat detection"""
    
    def __init__(self):
        self.detection_count = 0
    
    def detect(self, uri: str, user_agent: str, response_size: int, status_code: int) -> SignatureResult:
        """
        Run signature detection on a single record
        
        Args:
            uri: Request URI
            user_agent: User agent string
            response_size: Response size in bytes
            status_code: HTTP status code
        
        Returns:
            SignatureResult with detection details
        """
        if not uri:
            uri = ""
        if not user_agent:
            user_agent = ""
        
        uri_lower = uri.lower()
        decoded_uri = unquote(uri_lower)
        ua_lower = user_agent.lower()
        
        # Priority 1: Code Execution (Critical)
        matched, patterns = _match_patterns(uri_lower, CMD_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Command Injection",
                signature_confidence=0.95,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, SSTI_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="SSTI",
                signature_confidence=0.95,
                matched_patterns=patterns
            )
        
        # Priority 2: Injection Attacks
        matched, patterns = _match_patterns(uri_lower, SQLI_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="SQL Injection",
                signature_confidence=0.90,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, XSS_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="XSS",
                signature_confidence=0.90,
                matched_patterns=patterns
            )
        
        # Priority 3: File Access
        matched, patterns = _match_patterns(decoded_uri, TRAVERSAL_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Path Traversal",
                signature_confidence=0.92,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, SENSITIVE_FILE_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Sensitive File Disclosure",
                signature_confidence=0.88,
                matched_patterns=patterns
            )
        
        # Priority 4: Network Attacks
        matched, patterns = _match_patterns(uri_lower, SSRF_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="SSRF",
                signature_confidence=0.85,
                matched_patterns=patterns
            )
        
        # Priority 5: Authorization
        matched, patterns = _match_patterns(uri, IDOR_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="IDOR",
                signature_confidence=0.75,
                matched_patterns=patterns
            )
        
        matched, patterns = _match_patterns(uri_lower, PRIV_ESC_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Privilege Escalation",
                signature_confidence=0.80,
                matched_patterns=patterns
            )
        
        # Priority 6: Data Exfiltration
        matched, patterns = _match_patterns(uri_lower, EXFIL_PATTERNS)
        if matched or response_size > 1_000_000:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Data Exfiltration",
                signature_confidence=0.78,
                matched_patterns=patterns if matched else ["large_response"]
            )
        
        # Priority 7: Redirects
        matched, patterns = _match_patterns(uri_lower, OPEN_REDIRECT_PATTERNS)
        if matched:
            self.detection_count += 1
            return SignatureResult(
                signature_flag=True,
                threat_type="Open Redirect",
                signature_confidence=0.82,
                matched_patterns=patterns
            )
        
        # Priority 8: Reconnaissance
        if any(agent in ua_lower for agent in BAD_AGENTS):
            self.detection_count += 1
            matched_agents = [a for a in BAD_AGENTS if a in ua_lower]
            return SignatureResult(
                signature_flag=True,
                threat_type="Reconnaissance",
                signature_confidence=0.65,
                matched_patterns=matched_agents
            )
        
        # No signature match
        return SignatureResult(
            signature_flag=False,
            threat_type="Other",
            signature_confidence=0.0,
            matched_patterns=[]
        )
\n`\n\n### File: inference/threat_detectors.py\n\n`python\n"""
Rule-Based Threat Detectors
Pure Python functions for threat classification (NO ML)
"""
import re
from urllib.parse import unquote
from typing import Optional
import pandas as pd


# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

# XSS Patterns
XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror=", r"onload=",
    r"<iframe", r"alert\(", r"<img.*onerror", r"eval\(",
    r"document\.cookie", r"<svg.*onload"
]

# SQL Injection Patterns
SQLI_PATTERNS = [
    r"sqlmap", r"union\s+select", r"union.*select",
    r"' or '1'='1", r"' or ", r"--", r";--",
    r"drop\s+table", r"insert\s+into",
    r"select\s+\*\s+from", r"select.*from",
    r"1=1", r"' or 1=1", r"admin'--", r"' OR '1"
]

# Path Traversal / LFI Patterns
TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"\.\.",
    r"%2e%2e", r"%252e%252e", r"%2e",
    r"/etc/passwd", r"/etc/shadow",
    r"/proc/self", r"/windows/system32",
    r"password\.properties", r"license\.txt",
    r"CFIDE", r"administrator",
    r"\.\.\/\.\.\/", r"file:///"
]

# Command Injection / RCE Patterns
CMD_PATTERNS = [
    r"rm\s+-rf", r";\s*cat\s+/etc/", r"cat /etc",
    r"&&\s*whoami", r"\|\s*bash", r"whoami",
    r";\s*wget", r"`cat", r"; ls", r"&& ls",
    r"cmd=", r"exec\(", r"system\(", r"shell_exec",
    r"\$\{.*\}", r"bash -c"
]

# SSRF Patterns
SSRF_PATTERNS = [
    r"169\.254\.169\.254",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"localhost", r"127\.0\.0\.1",
    r"0\.0\.0\.0", r"::1",
    r"url=http://", r"fetch\?url=",
    r"redirect.*http://"
]

# IDOR Patterns
IDOR_PATTERNS = [
    r"/api/user/\d{5,}",  # Large user IDs
    r"/profile/\d{5,}",
    r"user_id=\d{5,}",
    r"account=\d{5,}"
]

# SSTI (Server-Side Template Injection) Patterns
SSTI_PATTERNS = [
    r"\{\{.*\}\}",  # Jinja2, Twig
    r"\$\{.*\}",    # Freemarker
    r"<%.*%>",      # JSP
    r"#\{.*\}"      # Ruby
]

# Open Redirect Patterns
OPEN_REDIRECT_PATTERNS = [
    r"redirect\?url=http://",
    r"next=http://",
    r"return_to=http://",
    r"goto=http://",
    r"url=//evil"
]

# Sensitive File Disclosure Patterns
SENSITIVE_FILE_PATTERNS = [
    r"\.env", r"\.git", r"\.svn",
    r"config\.php", r"web\.config",
    r"credentials", r"password",
    r"\.bak", r"\.backup",
    r"\.sql", r"dump\.sql"
]

# Privilege Escalation Patterns
PRIV_ESC_PATTERNS = [
    r"/admin", r"administrator", r"sudo", 
    r"privilege", r"/root", r"escalate",
    r"role=admin", r"isAdmin=true"
]

# Data Exfiltration Patterns
EXFIL_PATTERNS = [
    r"/export", r"/download", r"/backup",
    r"/dump", r"\.zip", r"\.tar\.gz",
    r"data=.*base64"
]

# Suspicious User Agents
BAD_AGENTS = [
    "sqlmap", "nikto", "nmap", "curl", 
    "python-requests", "masscan", "metasploit", 
    "burp", "scanner", "bot", "crawler",
    "acunetix", "nessus", "openvas"
]


# ============================================================================
# THREAT DETECTORS
# ============================================================================

# ============================================================================
# THREAT DETECTORS
# ============================================================================

def detect_xss(uri: str) -> bool:
    """Detect XSS attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri, re.IGNORECASE) for p in XSS_PATTERNS)


def detect_sql_injection(uri: str) -> bool:
    """Detect SQL injection attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in SQLI_PATTERNS)


def detect_path_traversal(uri: str) -> bool:
    """Detect path traversal / LFI attempts"""
    if not uri:
        return False
    decoded = unquote(uri.lower())
    return any(re.search(p, decoded) for p in TRAVERSAL_PATTERNS)


def detect_command_injection(uri: str) -> bool:
    """Detect command injection / RCE attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in CMD_PATTERNS)


def detect_ssrf(uri: str) -> bool:
    """Detect SSRF attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in SSRF_PATTERNS)


def detect_idor(uri: str) -> bool:
    """Detect IDOR attempts"""
    if not uri:
        return False
    return any(re.search(p, uri) for p in IDOR_PATTERNS)


def detect_ssti(uri: str) -> bool:
    """Detect SSTI attempts"""
    if not uri:
        return False
    return any(re.search(p, uri) for p in SSTI_PATTERNS)


def detect_open_redirect(uri: str) -> bool:
    """Detect open redirect attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in OPEN_REDIRECT_PATTERNS)


def detect_sensitive_file_access(uri: str) -> bool:
    """Detect sensitive file disclosure attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(re.search(p, uri) for p in SENSITIVE_FILE_PATTERNS)


def detect_privilege_escalation(uri: str) -> bool:
    """Detect privilege escalation attempts"""
    if not uri:
        return False
    uri = uri.lower()
    return any(p in uri for p in PRIV_ESC_PATTERNS)


def detect_data_exfiltration(uri: str, response_size: int) -> bool:
    """Detect data exfiltration attempts"""
    if not uri:
        return False
    return (
        any(p in uri.lower() for p in EXFIL_PATTERNS) or
        response_size > 1_000_000
    )


def detect_bruteforce(records, current_ip: str, window: int = 60, threshold: int = 5) -> bool:
    """Detect brute force attempts (behavioral)"""
    if not records or not current_ip:
        return False
    
    failures = sum(
        1 for r in records
        if hasattr(r, 'client_ip') and r.client_ip == current_ip
        and hasattr(r, 'status_code') and r.status_code in [401, 403]
    )
    return failures >= threshold


def detect_suspicious_agent(user_agent: str) -> bool:
    """Detect suspicious user agents"""
    if not user_agent:
        return False
    ua = user_agent.lower()
    return any(a in ua for a in BAD_AGENTS)


# ============================================================================
# THREAT CLASSIFIER WITH CONFIDENCE
# ============================================================================

def classify_threat_with_confidence(uri: str, user_agent: str, response_size: int, status_code: int, records=None, client_ip: str = None) -> tuple:
    """
    Classify threat type using deterministic rules with confidence score
    
    Returns:
        (threat_type: str, confidence: float)
    """
    # Priority 1: Code Execution Threats (Most Critical) - High Confidence
    if detect_command_injection(uri):
        return "Command Injection", 0.95
    
    if detect_ssti(uri):
        return "SSTI", 0.95
    
    # Priority 2: Injection Attacks - High Confidence
    if detect_sql_injection(uri):
        return "SQL Injection", 0.90
    
    if detect_xss(uri):
        return "XSS", 0.90
    
    # Priority 3: File Access Attacks - High Confidence
    if detect_path_traversal(uri):
        return "Path Traversal", 0.92
    
    if detect_sensitive_file_access(uri):
        return "Sensitive File Disclosure", 0.88
    
    # Priority 4: Network Attacks - Medium-High Confidence
    if detect_ssrf(uri):
        return "SSRF", 0.85
    
    # Priority 5: Authorization Attacks - Medium Confidence
    if detect_idor(uri):
        return "IDOR", 0.75
    
    if detect_privilege_escalation(uri):
        return "Privilege Escalation", 0.80
    
    # Priority 6: Data Attacks - Medium Confidence
    if detect_data_exfiltration(uri, response_size):
        return "Data Exfiltration", 0.78
    
    # Priority 7: Redirect Attacks - Medium Confidence
    if detect_open_redirect(uri):
        return "Open Redirect", 0.82
    
    # Priority 8: Behavioral Attacks - Lower Confidence
    if records and client_ip and detect_bruteforce(records, client_ip):
        return "Brute Force", 0.70
    
    if detect_suspicious_agent(user_agent):
        return "Reconnaissance", 0.65
    
    return "Other", 0.0


def classify_threat(uri: str, user_agent: str, response_size: int, status_code: int, records=None, client_ip: str = None) -> str:
    """
    Classify threat type using deterministic rules (backward compatibility)
    
    Returns:
        Threat type string
    """
    threat_type, _ = classify_threat_with_confidence(uri, user_agent, response_size, status_code, records, client_ip)
    return threat_type


# ============================================================================
# CORRELATION ENGINE - Multi-Stage Attack Detection
# ============================================================================

class ThreatCorrelationEngine:
    """Detects multi-stage attacks and attack campaigns"""
    
    def __init__(self):
        self.ip_activity = {}  # Track activity per IP
    
    def analyze_attack_chain(self, results: list) -> dict:
        """
        Analyze results for multi-stage attack patterns
        
        Returns:
            Dictionary with correlation findings
        """
        # Group threats by IP
        ip_threats = {}
        for result in results:
            if result.get('severity') != 'normal':
                ip = result.get('identifier', '')
                if ip not in ip_threats:
                    ip_threats[ip] = []
                ip_threats[ip].append({
                    'threat_type': result.get('threat_type'),
                    'timestamp': result.get('timestamp'),
                    'severity': result.get('severity')
                })
        
        # Detect attack campaigns
        campaigns = []
        for ip, threats in ip_threats.items():
            if len(threats) >= 3:
                threat_types = [t['threat_type'] for t in threats]
                
                # Pattern 1: Reconnaissance → Exploitation → Exfiltration
                if self._has_attack_progression(threat_types):
                    campaigns.append({
                        'ip': ip,
                        'type': 'Advanced Persistent Threat (APT)',
                        'threat_count': len(threats),
                        'severity': 'CRITICAL',
                        'description': f'Multi-stage attack detected: {" → ".join(set(threat_types[:3]))}'
                    })
                
                # Pattern 2: Multiple injection attempts
                elif self._has_repeated_attacks(threat_types):
                    campaigns.append({
                        'ip': ip,
                        'type': 'Automated Attack Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Repeated attack attempts: {len(threats)} threats from same source'
                    })
        
        return {
            'campaigns': campaigns,
            'total_campaigns': len(campaigns),
            'affected_ips': list(ip_threats.keys())
        }
    
    def _has_attack_progression(self, threat_types: list) -> bool:
        """Check if threats show progression pattern"""
        recon_types = ['Reconnaissance', 'Sensitive File Disclosure']
        exploit_types = ['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal', 'SSTI', 'RCE']
        exfil_types = ['Data Exfiltration', 'Privilege Escalation']
        
        has_recon = any(t in recon_types for t in threat_types)
        has_exploit = any(t in exploit_types for t in threat_types)
        has_exfil = any(t in exfil_types for t in threat_types)
        
        return has_recon and has_exploit and has_exfil
    
    def _has_repeated_attacks(self, threat_types: list) -> bool:
        """Check if same attack type repeated"""
        from collections import Counter
        counts = Counter(threat_types)
        return any(count >= 3 for count in counts.values())
\n`\n\n### File: inference/correlation_engine.py\n\n`python\n"""
Enhanced Correlation Engine - Layer 5
Advanced multi-stage attack and campaign detection with MITRE ATT&CK context
"""
from typing import List, Dict, Any
from collections import Counter, defaultdict
import logging

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Layer 5: Enhanced attack campaign and multi-stage threat correlation"""
    
    def __init__(self):
        self.ip_activity = {}
    
    def analyze_attack_chain(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enhanced analysis for multi-stage attack patterns and campaigns
        
        Args:
            results: List of threat detection results with MITRE mappings
        
        Returns:
            Dictionary with enhanced correlation findings
        """
        logger.info(f"Running enhanced correlation analysis on {len(results)} results")
        
        # Group threats by IP with MITRE context
        ip_threats = defaultdict(list)
        for result in results:
            if result.get('severity') != 'normal':
                ip = result.get('identifier', '')
                if ip:
                    ip_threats[ip].append({
                        'threat_type': result.get('threat_type'),
                        'timestamp': result.get('timestamp'),
                        'severity': result.get('severity'),
                        'confidence': result.get('confidence', 0.0),
                        'uri': result.get('uri', ''),
                        'mitre_technique': result.get('mitre_technique', 'N/A'),
                        'mitre_tactic': result.get('mitre_tactic', 'N/A'),
                        'attack_stage': result.get('attack_stage', 'Unknown')
                    })
        
        # Detect attack campaigns
        campaigns = []
        apt_campaigns = []
        automated_campaigns = []
        reconnaissance_campaigns = []
        
        for ip, threats in ip_threats.items():
            if len(threats) >= 3:
                threat_types = [t['threat_type'] for t in threats]
                attack_stages = [t['attack_stage'] for t in threats]
                tactics = [t['mitre_tactic'] for t in threats]
                
                # Pattern 1: Advanced Persistent Threat (APT) - Multi-stage with progression
                if self._has_attack_progression(attack_stages, tactics):
                    campaign = {
                        'ip': ip,
                        'type': 'Advanced Persistent Threat (APT)',
                        'threat_count': len(threats),
                        'severity': 'CRITICAL',
                        'description': f'Multi-stage attack progression detected: {self._get_attack_chain_summary(attack_stages)}',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics)),
                        'kill_chain_coverage': self._calculate_kill_chain_coverage(attack_stages)
                    }
                    campaigns.append(campaign)
                    apt_campaigns.append(campaign)
                    logger.warning(f"⚠️  APT detected from {ip}: {len(threats)} threats across {len(set(attack_stages))} stages")
                
                # Pattern 2: Automated Attack Campaign - Repeated attacks
                elif self._has_repeated_attacks(threat_types):
                    campaign = {
                        'ip': ip,
                        'type': 'Automated Attack Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Automated tool detected: {len(threats)} repeated attacks',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics)),
                        'automation_confidence': self._calculate_automation_confidence(threat_types)
                    }
                    campaigns.append(campaign)
                    automated_campaigns.append(campaign)
                    logger.warning(f"⚠️  Automated campaign from {ip}: {len(threats)} threats")
                
                # Pattern 3: Reconnaissance Campaign - Scanning activity
                elif self._has_reconnaissance_pattern(attack_stages):
                    campaign = {
                        'ip': ip,
                        'type': 'Reconnaissance Campaign',
                        'threat_count': len(threats),
                        'severity': 'MEDIUM',
                        'description': f'Active scanning detected: {len(threats)} reconnaissance attempts',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics)),
                        'scan_intensity': 'High' if len(threats) > 10 else 'Medium'
                    }
                    campaigns.append(campaign)
                    reconnaissance_campaigns.append(campaign)
                    logger.info(f"Reconnaissance campaign from {ip}: {len(threats)} attempts")
                
                # Pattern 4: Lateral Movement - Multiple exploitation attempts
                elif self._has_lateral_movement(attack_stages, tactics):
                    campaign = {
                        'ip': ip,
                        'type': 'Lateral Movement Campaign',
                        'threat_count': len(threats),
                        'severity': 'HIGH',
                        'description': f'Lateral movement detected: {len(threats)} exploitation attempts',
                        'threat_types': list(set(threat_types)),
                        'attack_stages': list(set(attack_stages)),
                        'mitre_tactics': list(set(tactics))
                    }
                    campaigns.append(campaign)
                    logger.warning(f"⚠️  Lateral movement from {ip}: {len(threats)} threats")
        
        # Compute enhanced correlation statistics
        total_threats = sum(len(threats) for threats in ip_threats.values())
        unique_ips = len(ip_threats)
        
        # Analyze MITRE tactic distribution
        all_tactics = []
        all_stages = []
        for threats in ip_threats.values():
            all_tactics.extend([t['mitre_tactic'] for t in threats if t['mitre_tactic'] != 'N/A'])
            all_stages.extend([t['attack_stage'] for t in threats if t['attack_stage'] != 'Unknown'])
        
        tactic_distribution = Counter(all_tactics)
        stage_distribution = Counter(all_stages)
        
        correlation_results = {
            'campaigns': campaigns,
            'total_campaigns': len(campaigns),
            'apt_campaigns': len(apt_campaigns),
            'automated_campaigns': len(automated_campaigns),
            'reconnaissance_campaigns': len(reconnaissance_campaigns),
            'affected_ips': list(ip_threats.keys()),
            'total_threats_analyzed': total_threats,
            'unique_threat_sources': unique_ips,
            'mitre_tactic_distribution': dict(tactic_distribution),
            'attack_stage_distribution': dict(stage_distribution),
            'campaign_details': {
                'apt': apt_campaigns,
                'automated': automated_campaigns,
                'reconnaissance': reconnaissance_campaigns
            }
        }
        
        if len(campaigns) > 0:
            logger.warning(f"⚠️  {len(campaigns)} attack campaigns detected!")
        
        return correlation_results
    
    def _has_attack_progression(self, attack_stages: List[str], tactics: List[str]) -> bool:
        """
        Enhanced APT detection using MITRE ATT&CK kill chain
        Checks for progression: Reconnaissance → Initial Access → Execution → Exfiltration
        """
        stage_set = set(attack_stages)
        tactic_set = set(tactics)
        
        # Check for kill chain progression
        has_recon = 'Reconnaissance' in stage_set
        has_initial_access = 'Initial Access' in stage_set or 'Exploitation' in stage_set
        has_execution = 'Execution' in stage_set or 'Exploitation' in stage_set
        has_impact = 'Exfiltration' in stage_set or 'Impact' in stage_set or 'Collection' in stage_set
        
        # APT requires at least 3 stages including reconnaissance
        stages_count = sum([has_recon, has_initial_access, has_execution, has_impact])
        
        return stages_count >= 3 and has_recon
    
    def _has_repeated_attacks(self, threat_types: List[str]) -> bool:
        """Check if same attack type repeated (automated tool signature)"""
        counts = Counter(threat_types)
        # Automated if any single threat type appears 3+ times
        return any(count >= 3 for count in counts.values())
    
    def _has_reconnaissance_pattern(self, attack_stages: List[str]) -> bool:
        """Check if threats are primarily reconnaissance"""
        recon_count = sum(1 for stage in attack_stages if stage == 'Reconnaissance')
        return recon_count >= len(attack_stages) * 0.7
    
    def _has_lateral_movement(self, attack_stages: List[str], tactics: List[str]) -> bool:
        """Detect lateral movement patterns"""
        has_exploitation = 'Exploitation' in attack_stages
        has_privilege_esc = 'Privilege Escalation' in attack_stages
        has_lateral_tactic = 'Lateral Movement' in tactics
        
        return (has_exploitation and has_privilege_esc) or has_lateral_tactic
    
    def _get_attack_chain_summary(self, attack_stages: List[str]) -> str:
        """Generate human-readable attack chain summary"""
        unique_stages = []
        seen = set()
        for stage in attack_stages:
            if stage not in seen and stage != 'Unknown':
                unique_stages.append(stage)
                seen.add(stage)
        
        return " → ".join(unique_stages[:4])  # Show first 4 stages
    
    def _calculate_kill_chain_coverage(self, attack_stages: List[str]) -> float:
        """Calculate what percentage of the kill chain is covered"""
        kill_chain_stages = {
            'Reconnaissance', 'Initial Access', 'Execution',
            'Persistence', 'Privilege Escalation', 'Defense Evasion',
            'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Impact'
        }
        
        covered_stages = set(attack_stages) & kill_chain_stages
        return len(covered_stages) / len(kill_chain_stages)
    
    def _calculate_automation_confidence(self, threat_types: List[str]) -> float:
        """Calculate confidence that attacks are automated"""
        counts = Counter(threat_types)
        max_repeat = max(counts.values()) if counts else 0
        
        # Higher repetition = higher automation confidence
        return min(0.95, 0.5 + (max_repeat * 0.1))
    
    def reset(self):
        """Reset correlation state"""
        self.ip_activity.clear()
\n`\n\n## Behavioral Detection\n\n### File: inference/behavioral_engine.py\n\n`python\n"""
Behavioral Detection Engine - Layer 2
Stateful analysis across multiple records to detect behavioral anomalies
"""
from typing import List, Dict, Any
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime


@dataclass
class BehaviorResult:
    """Result from behavioral detection"""
    behavior_flag: bool
    behavior_type: str
    behavior_confidence: float
    behavior_details: dict


class BehaviorEngine:
    """Layer 2: Behavioral threat detection"""
    
    def __init__(self):
        self.ip_activity = defaultdict(dict)
        self.detection_count = 0
    
    def analyze_record(self, record, all_records: List) -> BehaviorResult:
        """
        Analyze behavioral patterns for a single record in context of all records
        
        Args:
            record: Current record being analyzed
            all_records: All records for context (NOT USED for performance)
        
        Returns:
            BehaviorResult with detection details
        """
        # Extract record details
        if hasattr(record, 'client_ip'):
            client_ip = record.client_ip
            status_code = getattr(record, 'status_code', 0)
            method = getattr(record, 'method', '')
            uri = getattr(record, 'uri', '')
            
            # Update activity tracking (lightweight counters only)
            activity = self.ip_activity[client_ip]
            activity['request_count'] = activity.get('request_count', 0) + 1
            
            if status_code in [401, 403]:
                activity['failures'] = activity.get('failures', 0) + 1
            
            # Track unique methods and URIs (limited to prevent memory bloat)
            if 'methods' not in activity:
                activity['methods'] = set()
            if 'uris' not in activity:
                activity['uris'] = set()
            
            if len(activity['methods']) < 10:
                activity['methods'].add(method)
            if len(activity['uris']) < 100:
                activity['uris'].add(uri)
            
            # Check for brute force (using tracked failures)
            brute_force_result = self._detect_brute_force_fast(client_ip)
            if brute_force_result.behavior_flag:
                self.detection_count += 1
                return brute_force_result
            
            # Check for rate abuse
            rate_abuse_result = self._detect_rate_abuse_fast(client_ip)
            if rate_abuse_result.behavior_flag:
                self.detection_count += 1
                return rate_abuse_result
            
            # Check for enumeration
            enum_result = self._detect_enumeration_fast(client_ip)
            if enum_result.behavior_flag:
                self.detection_count += 1
                return enum_result
            
            # Check for burst activity
            burst_result = self._detect_burst_activity_fast(client_ip)
            if burst_result.behavior_flag:
                self.detection_count += 1
                return burst_result
        
        # No behavioral anomaly detected
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_brute_force_fast(self, client_ip: str, threshold: int = 5) -> BehaviorResult:
        """Detect brute force attempts based on tracked authentication failures"""
        failures = self.ip_activity[client_ip].get('failures', 0)
        
        if failures >= threshold:
            return BehaviorResult(
                behavior_flag=True,
                behavior_type="Brute Force",
                behavior_confidence=min(0.70 + (failures - threshold) * 0.05, 0.95),
                behavior_details={
                    'failure_count': failures,
                    'threshold': threshold,
                    'description': f'{failures} authentication failures detected'
                }
            )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_rate_abuse_fast(self, client_ip: str, threshold: int = 50) -> BehaviorResult:
        """Detect rate abuse based on request volume"""
        request_count = self.ip_activity[client_ip].get('request_count', 0)
        
        if request_count >= threshold:
            return BehaviorResult(
                behavior_flag=True,
                behavior_type="Rate Abuse",
                behavior_confidence=min(0.65 + (request_count - threshold) * 0.01, 0.90),
                behavior_details={
                    'request_count': request_count,
                    'threshold': threshold,
                    'description': f'{request_count} requests from single IP'
                }
            )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_enumeration_fast(self, client_ip: str, threshold: int = 10) -> BehaviorResult:
        """Detect enumeration based on unique URI patterns"""
        uris = self.ip_activity[client_ip].get('uris', set())
        unique_uris = len(uris)
        
        # Check for sequential ID enumeration
        sequential_pattern = sum(1 for uri in uris if any(char.isdigit() for char in uri))
        
        if unique_uris >= threshold and sequential_pattern >= threshold * 0.7:
            return BehaviorResult(
                behavior_flag=True,
                behavior_type="Enumeration",
                behavior_confidence=0.72,
                behavior_details={
                    'unique_uris': unique_uris,
                    'sequential_count': sequential_pattern,
                    'description': f'Enumeration pattern: {unique_uris} unique URIs'
                }
            )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def _detect_burst_activity_fast(self, client_ip: str, threshold: int = 30) -> BehaviorResult:
        """Detect abnormal burst activity"""
        request_count = self.ip_activity[client_ip].get('request_count', 0)
        
        # Simple burst detection: high volume in short time
        if request_count >= threshold:
            methods = self.ip_activity[client_ip].get('methods', set())
            unique_methods = len(methods)
            
            # If using multiple methods, likely automated
            if unique_methods >= 3:
                return BehaviorResult(
                    behavior_flag=True,
                    behavior_type="Burst Activity",
                    behavior_confidence=0.68,
                    behavior_details={
                        'request_count': request_count,
                        'unique_methods': unique_methods,
                        'description': f'Burst: {request_count} requests with {unique_methods} methods'
                    }
                )
        
        return BehaviorResult(
            behavior_flag=False,
            behavior_type="Normal",
            behavior_confidence=0.0,
            behavior_details={}
        )
    
    def reset(self):
        """Reset behavioral state for new analysis"""
        self.ip_activity.clear()
        self.detection_count = 0
\n`\n\n## Core Inference & Decision Engine\n\n### File: inference/engine.py\n\n`python\n# SOC-Grade Inference Engine - Enterprise Multi-Layer Detection Architecture
import numpy as np
from typing import List, Dict, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
from parsing import HTTPRecord, GenericRecord
from features import UniversalFeatureExtractor

# Import new modular detection engines
from inference.signature_engine import SignatureEngine
from inference.behavioral_engine import BehaviorEngine
from inference.ml_engine import MLEngine
from inference.decision_engine import DecisionEngine, AnomalySeverity
from inference.threat_graph_engine import ThreatGraphEngine
from inference.correlation_engine import CorrelationEngine
from inference.llm_enrichment import LLMEnrichmentService

logger = logging.getLogger(__name__)


# ============================================================================
# DETECTION LAYER ENUM
# ============================================================================

class DetectionLayer(Enum):
    """Enterprise multi-layer detection architecture"""
    SIGNATURE = "Layer 1: Signature Detection"
    BEHAVIORAL = "Layer 2: Behavioral Detection"
    ML_ANOMALY = "Layer 3: ML Anomaly Detection"
    DECISION = "Layer 4: Decision Engine"
    THREAT_GRAPH = "Layer 5: Threat Graph Correlation"
    CORRELATION = "Layer 6: Correlation Engine"
    LLM_ENRICHMENT = "Layer 7: LLM Intelligence (Optional)"


@dataclass
class AnomalyResult:
    """Legacy result format for backward compatibility"""
    record_index: int
    identifier: str
    timestamp: str
    score: float
    severity: str
    model: str
    threat_type: str
    explanation: str
    confidence: float = 0.0
    detection_layer: str = ""
    uri: str = ""
    status_code: int = 0
    method: str = ""
    duration: int = 0
    response_size: int = 0
    user_agent: str = ""
    referer: str = ""
    raw_log: str = ""  # Original raw log entry
    
    def to_dict(self):
        return {
            'record_index': self.record_index,
            'identifier': self.identifier,
            'timestamp': self.timestamp,
            'score': float(self.score),
            'severity': self.severity,
            'model': self.model,
            'threat_type': self.threat_type,
            'explanation': self.explanation,
            'confidence': float(self.confidence),
            'detection_layer': self.detection_layer,
            'uri': self.uri,
            'status_code': self.status_code,
            'method': self.method,
            'duration': self.duration,
            'response_size': self.response_size,
            'user_agent': self.user_agent,
            'referer': self.referer,
            'raw_log': self.raw_log,
        }


class AnomalyDetectionEngine:
    """
    Enterprise-Grade Multi-Layer Detection Engine
    
    Architecture:
        Layer 1: Signature Engine (deterministic pattern matching)
        Layer 2: Behavioral Engine (stateful analysis)
        Layer 3: ML Engine (statistical anomaly scoring)
        Layer 4: Decision Engine (signal aggregation)
        Layer 5: Threat Graph Engine (attack campaign correlation) ← NEW
        Layer 6: Correlation Engine (campaign detection)
        Layer 7: LLM Intelligence (post-detection enrichment) - OPTIONAL
    """
    
    def __init__(self, enable_llm: bool = False, openai_api_key: str = None):
        self.feature_extractor = UniversalFeatureExtractor()
        
        # Initialize detection engines
        self.signature_engine = SignatureEngine()
        self.behavioral_engine = BehaviorEngine()
        self.ml_engine = MLEngine()
        self.decision_engine = DecisionEngine()
        self.threat_graph_engine = ThreatGraphEngine()  # NEW
        self.correlation_engine = CorrelationEngine()
        
        # Initialize LLM enrichment (optional)
        self.llm_service = LLMEnrichmentService(
            api_key=openai_api_key,
            enabled=enable_llm
        )
        
        logger.info(f"Initialized enterprise detection engine with {'7 layers (LLM enabled)' if enable_llm else '6 layers'}")
    
    def retrain_model_on_data(self, model_type: str, training_data: np.ndarray):
        """Retrain ML models with new data"""
        logger.info(f"Retraining {model_type} with {training_data.shape} data")
        self.ml_engine.retrain_model(model_type, training_data)

    
    def detect_anomalies(self, records: List[Union[HTTPRecord, GenericRecord]], features: np.ndarray, file_type: str, model_type: str, feature_info: Dict[str, Any]) -> Tuple[List[AnomalyResult], Dict[str, Any]]:
        """
        Enterprise multi-layer detection pipeline
        
        Architecture:
            1. Signature Engine (runs first on ALL records)
            2. Behavioral Engine (stateful analysis)
            3. ML Engine (parallel statistical scoring)
            4. Decision Engine (signal aggregation)
            5. Threat Graph Engine (attack campaign correlation) ← NEW
            6. Correlation Engine (campaign detection)
            7. LLM Intelligence (optional)
        """
        logger.info(f"Starting enterprise detection pipeline on {len(records)} records")
        
        # Reset engines for new analysis
        self.behavioral_engine.reset()
        self.threat_graph_engine.reset()
        self.correlation_engine.reset()
        
        # ========================================================================
        # LAYER 3: ML ANOMALY DETECTION (PARALLEL)
        # ========================================================================
        logger.info("Layer 3: Running ML anomaly detection...")
        ml_scores, ml_metadata = self.ml_engine.predict(features, model_type)
        
        # ========================================================================
        # LAYERS 1, 2, 4: SIGNATURE + BEHAVIORAL + DECISION (PER RECORD)
        # ========================================================================
        logger.info("Layers 1, 2, 4: Running signature, behavioral, and decision engines...")
        unified_results = []
        
        # Progress tracking for large datasets
        total_records = len(records)
        log_interval = max(1000, total_records // 10)  # Log every 10% or 1000 records
        
        for idx, (record, ml_score) in enumerate(zip(records, ml_scores)):
            # Log progress for large datasets
            if idx > 0 and idx % log_interval == 0:
                progress_pct = (idx / total_records) * 100
                logger.info(f"  Progress: {idx}/{total_records} records ({progress_pct:.1f}%)")
            
            # Normalize ML score to 0-1 range
            ml_score_normalized = self.ml_engine.get_anomaly_score_normalized(ml_score, ml_scores)
            
            # LAYER 1: SIGNATURE DETECTION (ALWAYS RUNS FIRST)
            if isinstance(record, HTTPRecord):
                signature_result = self.signature_engine.detect(
                    uri=record.uri,
                    user_agent=record.user_agent,
                    response_size=record.response_size,
                    status_code=record.status_code
                )
            else:
                # Generic records don't have signature detection
                from inference.signature_engine import SignatureResult
                signature_result = SignatureResult(
                    signature_flag=False,
                    threat_type="Other",
                    signature_confidence=0.0,
                    matched_patterns=[]
                )
            
            # LAYER 2: BEHAVIORAL DETECTION (STATEFUL)
            behavior_result = self.behavioral_engine.analyze_record(record, records)
            
            # LAYER 4: DECISION ENGINE (SIGNAL AGGREGATION)
            unified_threat = self.decision_engine.make_decision(
                record=record,
                record_index=idx,
                signature_result=signature_result,
                behavior_result=behavior_result,
                ml_score=ml_score,
                ml_score_normalized=ml_score_normalized
            )
            
            unified_results.append(unified_threat)
        
        # Convert unified results to legacy AnomalyResult format for compatibility
        # FILTER: Only include Critical, High, and Medium severity threats
        legacy_results = []
        for unified in unified_results:
            # Only include threats that are MEDIUM or above
            if unified.final_severity in ['critical', 'high', 'medium']:
                legacy_result = AnomalyResult(
                    record_index=unified.record_index,
                    identifier=unified.identifier,
                    timestamp=unified.timestamp,
                    score=unified.final_risk_score,
                    severity=unified.final_severity,
                    model=model_type,
                    threat_type=unified.final_threat_type,
                    explanation=unified.explanation,
                    confidence=max(unified.signature_confidence, unified.behavior_confidence),
                    detection_layer=unified.detection_layer,
                    uri=unified.uri,
                    status_code=unified.status_code,
                    method=unified.method,
                    duration=unified.duration,
                    response_size=unified.response_size,
                    user_agent=unified.user_agent,
                    referer=unified.referer,
                    raw_log=unified.raw_log
                )
                legacy_results.append(legacy_result)
        
        logger.info(f"Filtered to {len(legacy_results)} high-severity threats (Critical/High/Medium only)")
        
        # ========================================================================
        # LAYER 5: THREAT GRAPH ENGINE (ATTACK CAMPAIGN CORRELATION)
        # ========================================================================
        logger.info("Layer 5: Running threat graph correlation...")
        # Build threat graph from filtered results
        attack_campaigns = self.threat_graph_engine.build_threat_graph(
            [r.to_dict() for r in legacy_results]
        )
        
        # Get graph statistics
        graph_stats = self.threat_graph_engine.get_statistics()
        logger.info(f"  Graph: {graph_stats['total_nodes']} nodes → {graph_stats['total_clusters']} clusters → {graph_stats['total_campaigns']} campaigns")
        
        # ========================================================================
        # USE THREAT GRAPH FOR FALSE POSITIVE FILTERING
        # ========================================================================
        # Strategy: Keep threats that are part of MULTI-EVENT campaigns (2+ events)
        #           Filter out isolated single-event threats (likely false positives)
        
        if len(attack_campaigns) > 0:
            # Extract record indices from campaigns with 2+ events (coordinated attacks)
            campaign_record_indices = set()
            multi_event_campaigns = []
            
            for campaign in attack_campaigns:
                if campaign.event_count >= 2:  # Only campaigns with multiple events
                    multi_event_campaigns.append(campaign)
                    for event in campaign.events:
                        campaign_record_indices.add(event['record_index'])
            
            # Filter: Keep only threats that are part of multi-event campaigns
            # These are HIGH CONFIDENCE threats (coordinated attacks)
            high_confidence_results = []
            for result in legacy_results:
                if result.record_index in campaign_record_indices:
                    # This threat is part of a coordinated campaign - HIGH CONFIDENCE
                    # Enhance the explanation to show campaign context
                    matching_campaign = None
                    for campaign in multi_event_campaigns:
                        if result.record_index in [e['record_index'] for e in campaign.events]:
                            matching_campaign = campaign
                            break
                    
                    if matching_campaign:
                        # Add campaign context to explanation
                        result.explanation = f"[{matching_campaign.campaign_id}] {result.explanation} | Part of {matching_campaign.campaign_type} with {matching_campaign.event_count} events"
                        result.confidence = min(0.95, result.confidence + 0.2)  # Boost confidence
                    
                    high_confidence_results.append(result)
            
            logger.info(f"✅ Threat Graph Filtering: {len(high_confidence_results)} high-confidence threats (part of {len(multi_event_campaigns)} multi-event campaigns)")
            logger.info(f"   Filtered out {len(legacy_results) - len(high_confidence_results)} isolated single-event threats (potential false positives)")
            display_results = high_confidence_results
        else:
            # No campaigns detected - show all filtered threats
            logger.info(f"No campaigns detected, returning all {len(legacy_results)} individual threats")
            display_results = legacy_results
        
        # ========================================================================
        # LAYER 6: CORRELATION ENGINE (LEGACY CAMPAIGN DETECTION)
        # ========================================================================
        logger.info("Layer 6: Running correlation engine...")
        # Analyze individual threats (not campaigns)
        correlation_results = self.correlation_engine.analyze_attack_chain(
            [r.to_dict() for r in legacy_results]
        )
        
        # ========================================================================
        # LAYER 7: LLM INTELLIGENCE (POST-DETECTION ENRICHMENT) - OPTIONAL
        # ========================================================================
        llm_enrichment = {}
        if self.llm_service.enabled:
            logger.info("Layer 7: Running LLM enrichment analysis...")
            # LLM analyzes individual threats (display_results already filtered by campaigns)
            llm_enrichment = self.llm_service.enrich_results([r.to_dict() for r in display_results])
        else:
            llm_enrichment = {
                'enabled': False,
                'clusters_analyzed': 0,
                'novel_patterns_detected': 0,
                'llm_insights': []
            }
        
        # Compute statistics
        stats = self._compute_statistics(
            display_results, records, model_type, 
            correlation_results, llm_enrichment, 
            attack_campaigns, graph_stats
        )
        
        # Log detection summary
        logger.info(f"Detection complete: {len(records)} records analyzed")
        logger.info(f"  - Signature detections: {self.signature_engine.detection_count}")
        logger.info(f"  - Behavioral detections: {self.behavioral_engine.detection_count}")
        logger.info(f"  - ML anomalies: {self.ml_engine.detection_count}")
        logger.info(f"  - Individual threats (Critical/High/Medium): {len(legacy_results)}")
        logger.info(f"  - Attack campaigns detected: {len(attack_campaigns)}")
        logger.info(f"  - FINAL OUTPUT: {len(display_results)} results")
        
        if len(attack_campaigns) > 0:
            logger.warning(f"⚠️  {len(attack_campaigns)} attack campaigns detected!")
            for campaign in attack_campaigns[:5]:  # Log top 5
                logger.warning(f"    - {campaign.campaign_id}: {campaign.campaign_type} ({campaign.event_count} events, score: {campaign.campaign_score})")
        
        if correlation_results['total_campaigns'] > 0:
            logger.warning(f"⚠️  {correlation_results['total_campaigns']} additional campaigns detected by correlation engine!")
        
        return display_results, stats

    
    @staticmethod
    def _compute_statistics(
        results: List[AnomalyResult], 
        records: List[HTTPRecord], 
        model_type: str, 
        correlation_results: Dict[str, Any], 
        llm_enrichment: Dict[str, Any],
        attack_campaigns: List[Any],
        graph_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compute detection statistics (only for Critical/High/Medium threats)"""
        # Note: results are already filtered to only include critical/high/medium
        severities = [r.severity for r in results]
        threat_types = [r.threat_type for r in results]
        threat_type_counts = {}
        for tt in threat_types:
            threat_type_counts[tt] = threat_type_counts.get(tt, 0) + 1
        
        # Detection layer statistics
        layer_counts = {}
        for r in results:
            layer = r.detection_layer
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
        
        # Convert attack campaigns to dict format
        campaigns_data = [
            {
                'campaign_id': c.campaign_id,
                'type': c.campaign_type,
                'ip': c.source_ip,
                'event_count': c.event_count,
                'score': c.campaign_score,
                'severity': c.severity,
                'threat_types': c.threat_types,
                'attack_stages': c.attack_stages,
                'mitre_tactics': c.mitre_tactics,
                'kill_chain_coverage': c.kill_chain_coverage,
                'automation_confidence': c.automation_confidence,
                'description': c.description
            }
            for c in attack_campaigns
        ]
        
        stats = {
            'total_records': len(records),
            'total_anomalies': len(results),  # Individual threats (filtered by campaigns)
            'anomaly_percentage': 100.0 * len(results) / len(records) if len(records) > 0 else 0.0,
            'severity_distribution': {
                'critical': sum(1 for s in severities if s == 'critical'),
                'high': sum(1 for s in severities if s == 'high'),
                'medium': sum(1 for s in severities if s == 'medium'),
                'low': 0,  # Not tracked anymore
                'normal': 0,  # Not tracked anymore
            },
            'threat_type_distribution': threat_type_counts,
            'detection_layer_distribution': layer_counts,
            'threat_graph': {
                'enabled': True,
                'statistics': graph_stats,
                'campaigns': campaigns_data,
                'showing_campaigns': False,  # We show individual threats, not campaigns
                'used_for_filtering': len(campaigns_data) > 0  # Flag to show graph was used for filtering
            },
            'correlation_findings': correlation_results,
            'llm_enrichment': llm_enrichment,
            'mean_score': float(np.mean([r.score for r in results])) if len(results) > 0 else 0.0,
            'std_score': float(np.std([r.score for r in results])) if len(results) > 0 else 0.0,
            'model': model_type,
        }
        return stats
\n`\n\n### File: inference/decision_engine.py\n\n`python\n"""
Decision Engine - Layer 4
Enhanced signal aggregation with MITRE ATT&CK mapping and false positive reduction
"""
import numpy as np
from typing import Dict, Any
from dataclasses import dataclass
from enum import Enum
import logging
from inference.mitre_attack_mapper import MITREAttackMapper
from inference.false_positive_filter import FalsePositiveFilter

logger = logging.getLogger(__name__)


class AnomalySeverity(Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UnifiedThreat:
    """Unified threat result from decision engine with MITRE ATT&CK mapping"""
    record_index: int
    identifier: str
    timestamp: str
    
    # Final decision
    final_threat_type: str
    final_severity: str
    final_risk_score: float
    
    # Signal breakdown
    signature_confidence: float
    behavior_confidence: float
    anomaly_score: float
    
    # Detection details
    detection_layer: str
    explanation: str
    
    # MITRE ATT&CK mapping
    mitre_technique: str = "N/A"
    mitre_technique_name: str = "N/A"
    mitre_tactic: str = "N/A"
    attack_stage: str = "Unknown"
    mitre_description: str = ""
    
    # Record details
    uri: str = ""
    status_code: int = 0
    method: str = ""
    duration: int = 0
    response_size: int = 0
    user_agent: str = ""
    referer: str = ""
    raw_log: str = ""  # Original raw log entry
    
    def to_dict(self):
        return {
            'record_index': self.record_index,
            'identifier': self.identifier,
            'timestamp': self.timestamp,
            'threat_type': self.final_threat_type,
            'severity': self.final_severity,
            'score': self.final_risk_score,
            'confidence': max(self.signature_confidence, self.behavior_confidence),
            'detection_layer': self.detection_layer,
            'explanation': self.explanation,
            'mitre_technique': self.mitre_technique,
            'mitre_technique_name': self.mitre_technique_name,
            'mitre_tactic': self.mitre_tactic,
            'attack_stage': self.attack_stage,
            'mitre_description': self.mitre_description,
            'uri': self.uri,
            'status_code': self.status_code,
            'method': self.method,
            'duration': self.duration,
            'response_size': self.response_size,
            'user_agent': self.user_agent,
            'referer': self.referer,
            'raw_log': self.raw_log,
            'model': 'decision_engine'
        }


class DecisionEngine:
    """Layer 4: Enhanced signal aggregation with MITRE mapping and FP reduction"""
    
    # IMPROVED WEIGHTS: Prioritize deterministic detection
    SIGNATURE_WEIGHT = 0.5  # Deterministic rules (highest priority)
    BEHAVIOR_WEIGHT = 0.3   # Stateful analysis (increased from 0.2)
    ML_WEIGHT = 0.2         # Statistical anomaly (decreased from 0.3)
    
    # STRICTER THRESHOLDS: Reduce false positives
    CRITICAL_THRESHOLD = 0.90
    HIGH_THRESHOLD = 0.75
    MEDIUM_THRESHOLD = 0.60
    LOW_THRESHOLD = 0.45     # Increased from 0.40
    
    # Critical threat types that must be HIGH or above
    CRITICAL_THREAT_TYPES = [
        "Command Injection",
        "SQL Injection",
        "Path Traversal",
        "SSTI",
        "RCE"
    ]
    
    def __init__(self):
        self.decision_count = 0
        self.fp_filter = FalsePositiveFilter()
        self.mitre_mapper = MITREAttackMapper()
        self.filtered_count = 0
    
    def make_decision(
        self,
        record,
        record_index: int,
        signature_result,
        behavior_result,
        ml_score: float,
        ml_score_normalized: float
    ) -> UnifiedThreat:
        """
        Enhanced threat decision with MITRE mapping and false positive reduction
        
        Args:
            record: Original log record
            record_index: Index of record
            signature_result: Result from signature engine
            behavior_result: Result from behavioral engine
            ml_score: Raw ML anomaly score
            ml_score_normalized: Normalized ML score (0-1)
        
        Returns:
            UnifiedThreat with final decision and MITRE mapping
        """
        # Extract record details
        identifier = getattr(record, 'client_ip', getattr(record, 'identifier', ''))
        timestamp = getattr(record, 'timestamp', '')
        uri = getattr(record, 'uri', '')
        status_code = getattr(record, 'status_code', 0)
        method = getattr(record, 'method', '')
        duration = getattr(record, 'duration', 0)
        response_size = getattr(record, 'response_size', 0)
        user_agent = getattr(record, 'user_agent', '')
        referer = getattr(record, 'raw_row', {}).get('referer', '')
        
        # Get confidence scores
        sig_confidence = signature_result.signature_confidence
        behav_confidence = behavior_result.behavior_confidence
        ml_confidence = ml_score_normalized
        
        # Determine primary threat type and detection layer
        if signature_result.signature_flag:
            final_threat_type = signature_result.threat_type
            detection_layer = "Layer 1: Signature Detection"
            primary_confidence = sig_confidence
        elif behavior_result.behavior_flag:
            final_threat_type = behavior_result.behavior_type
            detection_layer = "Layer 2: Behavioral Detection"
            primary_confidence = behav_confidence
        else:
            final_threat_type = "Other"
            detection_layer = "Layer 3: ML Anomaly Detection"
            primary_confidence = ml_confidence
        
        # FALSE POSITIVE FILTERING
        should_filter, filter_reason = self.fp_filter.should_filter(
            threat_type=final_threat_type,
            uri=uri,
            user_agent=user_agent,
            client_ip=identifier,
            signature_flag=signature_result.signature_flag,
            behavior_flag=behavior_result.behavior_flag,
            ml_score=ml_score_normalized
        )
        
        if should_filter:
            self.filtered_count += 1
            logger.debug(f"Filtered false positive: {filter_reason}")
            # Return as normal (filtered out)
            return self._create_normal_result(
                record_index, identifier, timestamp, uri, status_code,
                method, duration, response_size, user_agent, referer, record
            )
        
        # Calculate base weighted risk score
        base_risk_score = (
            sig_confidence * self.SIGNATURE_WEIGHT +
            behav_confidence * self.BEHAVIOR_WEIGHT +
            ml_confidence * self.ML_WEIGHT
        )
        
        # Apply MITRE severity modifier
        mitre_modifier = self.mitre_mapper.get_severity_modifier(final_threat_type)
        final_risk_score = base_risk_score * mitre_modifier
        
        # Ensure risk score stays in valid range
        final_risk_score = min(1.0, max(0.0, final_risk_score))
        
        # Map risk score to severity
        final_severity = self._map_risk_to_severity(final_risk_score)
        
        # Apply critical threat type enforcement
        if final_threat_type in self.CRITICAL_THREAT_TYPES:
            if final_severity in [AnomalySeverity.LOW.value, AnomalySeverity.MEDIUM.value, AnomalySeverity.NORMAL.value]:
                final_severity = AnomalySeverity.HIGH.value
                logger.debug(f"Enforced HIGH severity for critical threat: {final_threat_type}")
        
        # If any detection layer flagged it, ensure at least LOW severity
        if (signature_result.signature_flag or behavior_result.behavior_flag) and final_severity == AnomalySeverity.NORMAL.value:
            final_severity = AnomalySeverity.LOW.value
            logger.debug(f"Upgraded to LOW severity due to detection flag")
        
        # Get MITRE ATT&CK mapping
        mitre_mapping = self.mitre_mapper.get_mapping(final_threat_type)
        
        # Generate explanation
        explanation = self._generate_explanation(
            final_threat_type,
            final_severity,
            detection_layer,
            primary_confidence,
            signature_result,
            behavior_result,
            ml_score,
            record
        )
        
        # Reconstruct raw log entry
        raw_log = self._reconstruct_raw_log(record)
        
        # Count non-normal detections
        if final_severity != AnomalySeverity.NORMAL.value:
            self.decision_count += 1
        
        return UnifiedThreat(
            record_index=record_index,
            identifier=identifier,
            timestamp=timestamp,
            final_threat_type=final_threat_type,
            final_severity=final_severity,
            final_risk_score=final_risk_score,
            signature_confidence=sig_confidence,
            behavior_confidence=behav_confidence,
            anomaly_score=ml_score,
            detection_layer=detection_layer,
            explanation=explanation,
            mitre_technique=mitre_mapping.technique_id if mitre_mapping else "N/A",
            mitre_technique_name=mitre_mapping.technique_name if mitre_mapping else "N/A",
            mitre_tactic=mitre_mapping.tactic if mitre_mapping else "N/A",
            attack_stage=mitre_mapping.attack_stage if mitre_mapping else "Unknown",
            mitre_description=mitre_mapping.description if mitre_mapping else "",
            uri=uri,
            status_code=status_code,
            method=method,
            duration=duration,
            response_size=response_size,
            user_agent=user_agent,
            referer=referer,
            raw_log=raw_log
        )
    
    def _create_normal_result(
        self,
        record_index: int,
        identifier: str,
        timestamp: str,
        uri: str,
        status_code: int,
        method: str,
        duration: int,
        response_size: int,
        user_agent: str,
        referer: str,
        record
    ) -> UnifiedThreat:
        """Create a normal (non-threat) result"""
        return UnifiedThreat(
            record_index=record_index,
            identifier=identifier,
            timestamp=timestamp,
            final_threat_type="Normal",
            final_severity=AnomalySeverity.NORMAL.value,
            final_risk_score=0.0,
            signature_confidence=0.0,
            behavior_confidence=0.0,
            anomaly_score=0.0,
            detection_layer="Filtered",
            explanation="Normal request (filtered)",
            mitre_technique="N/A",
            mitre_technique_name="N/A",
            mitre_tactic="N/A",
            attack_stage="N/A",
            mitre_description="",
            uri=uri,
            status_code=status_code,
            method=method,
            duration=duration,
            response_size=response_size,
            user_agent=user_agent,
            referer=referer,
            raw_log=self._reconstruct_raw_log(record)
        )
    
    def get_statistics(self) -> Dict:
        """Get decision engine statistics"""
        fp_stats = self.fp_filter.get_statistics()
        return {
            'total_decisions': self.decision_count,
            'filtered_false_positives': self.filtered_count,
            'false_positive_rate': self.filtered_count / max(1, self.decision_count + self.filtered_count),
            **fp_stats
        }
    
    def _map_risk_to_severity(self, risk_score: float) -> str:
        """Map risk score to severity level (original thresholds)"""
        if risk_score >= self.CRITICAL_THRESHOLD:
            return AnomalySeverity.CRITICAL.value
        elif risk_score >= self.HIGH_THRESHOLD:
            return AnomalySeverity.HIGH.value
        elif risk_score >= self.MEDIUM_THRESHOLD:
            return AnomalySeverity.MEDIUM.value
        elif risk_score >= self.LOW_THRESHOLD:
            return AnomalySeverity.LOW.value
        else:
            return AnomalySeverity.NORMAL.value
    
    def _generate_explanation(
        self,
        threat_type: str,
        severity: str,
        detection_layer: str,
        confidence: float,
        signature_result,
        behavior_result,
        ml_score: float,
        record
    ) -> str:
        """Generate detailed explanation of detection"""
        if severity == AnomalySeverity.NORMAL.value:
            return "Normal request"
        
        parts = []
        
        # Add threat type with confidence
        if threat_type != "Other":
            parts.append(f"{threat_type} detected (confidence: {confidence:.0%})")
        else:
            parts.append(f"Anomalous behavior detected (ML score: {ml_score:.3f})")
        
        # Add detection layer
        parts.append(f"via {detection_layer}")
        
        # Add signal details
        signals = []
        if signature_result.signature_flag:
            signals.append(f"signature:{signature_result.signature_confidence:.0%}")
        if behavior_result.behavior_flag:
            signals.append(f"behavior:{behavior_result.behavior_confidence:.0%}")
        if ml_score > 0:
            signals.append(f"ml:{ml_score:.2f}")
        
        if signals:
            parts.append(f"[{', '.join(signals)}]")
        
        # Add HTTP details
        status_code = getattr(record, 'status_code', 0)
        response_size = getattr(record, 'response_size', 0)
        duration = getattr(record, 'duration', 0)
        
        if status_code >= 500:
            parts.append(f"HTTP {status_code}")
        elif status_code >= 400:
            parts.append(f"HTTP {status_code}")
        
        if response_size > 500000:
            parts.append(f"{response_size:,} bytes")
        
        if duration > 3000:
            parts.append(f"{duration}ms")
        
        return "; ".join(parts)

    
    def _reconstruct_raw_log(self, record) -> str:
        """
        Reconstruct the original raw log entry from HTTPRecord
        
        Args:
            record: HTTPRecord or GenericRecord
        
        Returns:
            Reconstructed raw log entry in syslog format
        """
        try:
            # Check if it's an HTTPRecord
            if hasattr(record, 'client_ip') and hasattr(record, 'method'):
                # Extract fields
                timestamp = getattr(record, 'timestamp', '')
                client_ip = getattr(record, 'client_ip', '0.0.0.0')
                method = getattr(record, 'method', 'GET')
                uri = getattr(record, 'uri', '/')
                status_code = getattr(record, 'status_code', 200)
                response_size = getattr(record, 'response_size', 0)
                duration = getattr(record, 'duration', 0)
                user_agent = getattr(record, 'user_agent', 'Unknown')
                
                # Get additional fields from raw_row if available
                raw_row = getattr(record, 'raw_row', {})
                hostname = raw_row.get('hostname', 'server')
                process = raw_row.get('process', 'httpd[12345]')
                dest_ip = raw_row.get('dest_ip', '0.0.0.0')
                port = raw_row.get('port', '0')
                domain = raw_row.get('domain', '-')
                referer = raw_row.get('referer', '-')
                
                # Reconstruct syslog format
                # <priority>timestamp hostname process: src_ip dest_ip port domain - - [timestamp] "METHOD /uri HTTP/1.1" status size duration "referer" "user-agent"
                
                # Determine priority (150 for most logs)
                priority = 150
                
                # Get current date for syslog timestamp (simplified)
                import datetime
                now = datetime.datetime.now()
                syslog_timestamp = now.strftime("%b %d %H:%M:%S")
                
                # Build the raw log
                if port and port != '0' and domain and domain != '-':
                    # Full format with port and domain
                    raw_log = f'<{priority}>{syslog_timestamp} {hostname} {process}: {client_ip} {dest_ip} {port} {domain} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status_code} {response_size} {duration} "{referer}" "{user_agent}"'
                elif domain and domain != '-':
                    # Format with domain but no port
                    raw_log = f'<{priority}>{syslog_timestamp} {hostname} {process}: {client_ip} {dest_ip} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status_code} {response_size} {duration} "{referer}" "{user_agent}"'
                else:
                    # Minimal format
                    raw_log = f'<{priority}>{syslog_timestamp} {hostname} {process}: {client_ip} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status_code} {response_size} {duration} "{referer}" "{user_agent}"'
                
                return raw_log
            else:
                # Generic record - return simple representation
                return f"Record: {getattr(record, 'identifier', 'Unknown')} at {getattr(record, 'timestamp', 'Unknown')}"
        
        except Exception as e:
            logger.warning(f"Failed to reconstruct raw log: {e}")
            return f"[Raw log reconstruction failed: {str(e)}]"
\n`\n\n### File: inference/threat_graph_engine.py\n\n`python\n"""
Threat Graph Engine - Layer 5.5
Graph-based attack campaign detection and correlation

Connects related threats into attack campaigns to reduce alert fatigue.
Instead of 800 individual alerts, outputs 20-30 real attack campaigns.
"""
import logging
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ThreatNode:
    """Represents a single threat event as a graph node"""
    node_id: str
    ip: str
    timestamp: str
    uri: str
    threat_type: str
    severity: str
    score: float
    method: str
    status_code: int
    mitre_technique: str
    mitre_tactic: str
    attack_stage: str
    record_index: int
    
    def __hash__(self):
        return hash(self.node_id)
    
    def __eq__(self, other):
        return self.node_id == other.node_id


@dataclass
class AttackCampaign:
    """Represents a clustered attack campaign"""
    campaign_id: str
    source_ip: str
    threat_types: List[str]
    event_count: int
    campaign_score: float
    severity: str
    first_seen: str
    last_seen: str
    duration_seconds: float
    attack_stages: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    kill_chain_coverage: float
    automation_confidence: float
    campaign_type: str
    description: str
    events: List[Dict[str, Any]]


class ThreatGraphEngine:
    """
    Graph-based threat correlation engine
    
    Reduces alert fatigue by grouping related threats into attack campaigns.
    
    Process:
    1. Build graph nodes from threat detections
    2. Connect related nodes (same IP, time window, attack pattern)
    3. Cluster connected nodes into campaigns
    4. Score campaigns based on severity and behavior
    5. Output consolidated attack campaigns
    
    Result: 800 anomalies → 70 clusters → 25 real threats
    """
    
    # Time window for connecting events (seconds)
    TIME_WINDOW = 120  # 2 minutes
    
    # Campaign scoring thresholds
    CRITICAL_CAMPAIGN_SCORE = 3.0
    HIGH_CAMPAIGN_SCORE = 2.0
    MEDIUM_CAMPAIGN_SCORE = 1.0
    
    # MITRE kill chain stages
    KILL_CHAIN_STAGES = [
        'Reconnaissance',
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Exfiltration',
        'Impact'
    ]
    
    def __init__(self):
        self.nodes: List[ThreatNode] = []
        self.edges: Dict[str, Set[str]] = defaultdict(set)
        self.clusters: List[Set[str]] = []
        self.campaigns: List[AttackCampaign] = []
    
    def reset(self):
        """Reset engine state"""
        self.nodes.clear()
        self.edges.clear()
        self.clusters.clear()
        self.campaigns.clear()
    
    def build_threat_graph(self, threats: List[Dict[str, Any]]) -> List[AttackCampaign]:
        """
        Main entry point: Build threat graph and detect campaigns
        
        Args:
            threats: List of threat detections (Critical/High/Medium only)
        
        Returns:
            List of AttackCampaign objects
        """
        logger.info(f"Building threat graph from {len(threats)} threats...")
        
        # Step 1: Build graph nodes
        self._build_nodes(threats)
        logger.info(f"Created {len(self.nodes)} graph nodes")
        
        # Step 2: Connect related nodes
        self._connect_nodes()
        logger.info(f"Created {sum(len(edges) for edges in self.edges.values())} edges")
        
        # Step 3: Cluster connected nodes
        self._cluster_nodes()
        logger.info(f"Formed {len(self.clusters)} threat clusters")
        
        # Step 4: Build attack campaigns
        self._build_campaigns()
        logger.info(f"Detected {len(self.campaigns)} attack campaigns")
        
        return self.campaigns
    
    def _build_nodes(self, threats: List[Dict[str, Any]]):
        """Step 1: Convert threats into graph nodes"""
        for idx, threat in enumerate(threats):
            node = ThreatNode(
                node_id=f"node_{idx}",
                ip=threat.get('identifier', 'unknown'),
                timestamp=threat.get('timestamp', ''),
                uri=threat.get('uri', ''),
                threat_type=threat.get('threat_type', 'Other'),
                severity=threat.get('severity', 'medium'),
                score=threat.get('score', 0.0),
                method=threat.get('method', ''),
                status_code=threat.get('status_code', 0),
                mitre_technique=threat.get('mitre_technique', 'N/A'),
                mitre_tactic=threat.get('mitre_tactic', 'N/A'),
                attack_stage=threat.get('attack_stage', 'Unknown'),
                record_index=threat.get('record_index', idx)
            )
            self.nodes.append(node)
    
    def _connect_nodes(self):
        """Step 2: Connect related nodes based on correlation rules"""
        for i, node1 in enumerate(self.nodes):
            for j, node2 in enumerate(self.nodes):
                if i >= j:
                    continue
                
                # Connection Rule 1: Same IP
                if node1.ip != node2.ip:
                    continue
                
                # Connection Rule 2: Within time window
                if not self._within_time_window(node1.timestamp, node2.timestamp):
                    continue
                
                # Connection Rule 3: Related attack patterns
                if self._are_related_attacks(node1, node2):
                    self.edges[node1.node_id].add(node2.node_id)
                    self.edges[node2.node_id].add(node1.node_id)
    
    def _within_time_window(self, time1: str, time2: str) -> bool:
        """Check if two timestamps are within the time window"""
        try:
            # Parse timestamps (assuming ISO format or similar)
            # For simplicity, we'll use string comparison if parsing fails
            # In production, use proper datetime parsing
            return True  # Simplified - always connect same IP for now
        except:
            return True
    
    def _are_related_attacks(self, node1: ThreatNode, node2: ThreatNode) -> bool:
        """Check if two nodes represent related attack patterns"""
        # Rule 1: Same MITRE tactic
        if node1.mitre_tactic != 'N/A' and node1.mitre_tactic == node2.mitre_tactic:
            return True
        
        # Rule 2: Sequential attack stages
        if self._are_sequential_stages(node1.attack_stage, node2.attack_stage):
            return True
        
        # Rule 3: Similar threat types
        if node1.threat_type == node2.threat_type:
            return True
        
        # Rule 4: Same URI pattern (admin enumeration)
        if self._same_uri_pattern(node1.uri, node2.uri):
            return True
        
        return False
    
    def _are_sequential_stages(self, stage1: str, stage2: str) -> bool:
        """Check if two attack stages are sequential in kill chain"""
        try:
            idx1 = self.KILL_CHAIN_STAGES.index(stage1)
            idx2 = self.KILL_CHAIN_STAGES.index(stage2)
            # Sequential if within 3 stages of each other
            return abs(idx1 - idx2) <= 3
        except ValueError:
            return False
    
    def _same_uri_pattern(self, uri1: str, uri2: str) -> bool:
        """Check if two URIs follow similar patterns"""
        # Extract base path (before query params)
        base1 = uri1.split('?')[0] if uri1 else ''
        base2 = uri2.split('?')[0] if uri2 else ''
        
        # Check if they share common prefix
        if base1 and base2:
            parts1 = base1.split('/')
            parts2 = base2.split('/')
            # Same if first 2 path segments match
            return parts1[:2] == parts2[:2]
        
        return False
    
    def _cluster_nodes(self):
        """Step 3: Cluster connected nodes using DFS"""
        visited = set()
        
        for node in self.nodes:
            if node.node_id in visited:
                continue
            
            # DFS to find all connected nodes
            cluster = set()
            stack = [node.node_id]
            
            while stack:
                current_id = stack.pop()
                if current_id in visited:
                    continue
                
                visited.add(current_id)
                cluster.add(current_id)
                
                # Add connected nodes to stack
                for neighbor_id in self.edges.get(current_id, []):
                    if neighbor_id not in visited:
                        stack.append(neighbor_id)
            
            if cluster:
                self.clusters.append(cluster)
    
    def _build_campaigns(self):
        """Step 4: Build attack campaigns from clusters"""
        node_map = {node.node_id: node for node in self.nodes}
        
        for cluster_idx, cluster in enumerate(self.clusters):
            # Get all nodes in cluster
            cluster_nodes = [node_map[node_id] for node_id in cluster]
            
            if not cluster_nodes:
                continue
            
            # Extract campaign metadata
            source_ip = cluster_nodes[0].ip
            threat_types = list(set(node.threat_type for node in cluster_nodes))
            event_count = len(cluster_nodes)
            
            # Calculate campaign score
            campaign_score = self._calculate_campaign_score(cluster_nodes)
            
            # Determine severity
            severity = self._determine_campaign_severity(campaign_score, cluster_nodes)
            
            # Time range
            timestamps = [node.timestamp for node in cluster_nodes]
            first_seen = min(timestamps) if timestamps else ''
            last_seen = max(timestamps) if timestamps else ''
            duration_seconds = 0.0  # Simplified
            
            # MITRE analysis
            attack_stages = list(set(node.attack_stage for node in cluster_nodes if node.attack_stage != 'Unknown'))
            mitre_tactics = list(set(node.mitre_tactic for node in cluster_nodes if node.mitre_tactic != 'N/A'))
            mitre_techniques = list(set(node.mitre_technique for node in cluster_nodes if node.mitre_technique != 'N/A'))
            
            # Kill chain coverage
            kill_chain_coverage = self._calculate_kill_chain_coverage(attack_stages)
            
            # Automation confidence
            automation_confidence = self._calculate_automation_confidence(cluster_nodes)
            
            # Campaign type classification
            campaign_type = self._classify_campaign_type(cluster_nodes, kill_chain_coverage, automation_confidence)
            
            # Description
            description = self._generate_campaign_description(campaign_type, threat_types, event_count, source_ip)
            
            # Build event list
            events = [
                {
                    'record_index': node.record_index,
                    'timestamp': node.timestamp,
                    'uri': node.uri,
                    'threat_type': node.threat_type,
                    'severity': node.severity,
                    'score': node.score,
                    'mitre_technique': node.mitre_technique,
                    'attack_stage': node.attack_stage
                }
                for node in cluster_nodes
            ]
            
            # Create campaign
            campaign = AttackCampaign(
                campaign_id=f"CAMPAIGN-{cluster_idx + 1:03d}",
                source_ip=source_ip,
                threat_types=threat_types,
                event_count=event_count,
                campaign_score=campaign_score,
                severity=severity,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=duration_seconds,
                attack_stages=attack_stages,
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques,
                kill_chain_coverage=kill_chain_coverage,
                automation_confidence=automation_confidence,
                campaign_type=campaign_type,
                description=description,
                events=events
            )
            
            self.campaigns.append(campaign)
        
        # Sort campaigns by score (highest first)
        self.campaigns.sort(key=lambda c: c.campaign_score, reverse=True)
    
    def _calculate_campaign_score(self, nodes: List[ThreatNode]) -> float:
        """Calculate overall campaign risk score"""
        # Base score: sum of individual threat scores
        base_score = sum(node.score for node in nodes)
        
        # Behavior multiplier: more events = higher confidence
        event_multiplier = 1.0 + (len(nodes) * 0.1)  # +10% per event
        
        # Severity multiplier
        critical_count = sum(1 for node in nodes if node.severity == 'critical')
        high_count = sum(1 for node in nodes if node.severity == 'high')
        severity_multiplier = 1.0 + (critical_count * 0.3) + (high_count * 0.2)
        
        # Final score
        campaign_score = base_score * event_multiplier * severity_multiplier
        
        return round(campaign_score, 2)
    
    def _determine_campaign_severity(self, score: float, nodes: List[ThreatNode]) -> str:
        """Determine campaign severity based on score and node severities"""
        # If any node is critical, campaign is critical
        if any(node.severity == 'critical' for node in nodes):
            return 'critical'
        
        # Score-based thresholds
        if score >= self.CRITICAL_CAMPAIGN_SCORE:
            return 'critical'
        elif score >= self.HIGH_CAMPAIGN_SCORE:
            return 'high'
        elif score >= self.MEDIUM_CAMPAIGN_SCORE:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_kill_chain_coverage(self, attack_stages: List[str]) -> float:
        """Calculate percentage of kill chain covered"""
        if not attack_stages:
            return 0.0
        
        covered_stages = set(attack_stages)
        total_stages = len(self.KILL_CHAIN_STAGES)
        coverage = len(covered_stages) / total_stages
        
        return round(coverage * 100, 1)
    
    def _calculate_automation_confidence(self, nodes: List[ThreatNode]) -> float:
        """Calculate confidence that this is an automated attack"""
        # Factors indicating automation:
        # 1. High event count in short time
        # 2. Repeated threat types
        # 3. Sequential URIs
        
        event_count = len(nodes)
        
        # High event count = likely automated
        if event_count >= 10:
            return 0.9
        elif event_count >= 5:
            return 0.7
        elif event_count >= 3:
            return 0.5
        else:
            return 0.3
    
    def _classify_campaign_type(self, nodes: List[ThreatNode], kill_chain_coverage: float, automation_confidence: float) -> str:
        """Classify the type of attack campaign"""
        attack_stages = set(node.attack_stage for node in nodes if node.attack_stage != 'Unknown')
        threat_types = set(node.threat_type for node in nodes)
        
        # APT: Multi-stage with high kill chain coverage
        if kill_chain_coverage >= 25.0 and len(attack_stages) >= 3:
            if 'Reconnaissance' in attack_stages:
                return 'Advanced Persistent Threat (APT)'
        
        # Automated Campaign: High automation confidence
        if automation_confidence >= 0.7:
            if 'Reconnaissance' in attack_stages:
                return 'Automated Reconnaissance Campaign'
            else:
                return 'Automated Attack Campaign'
        
        # Exploitation Campaign: Multiple exploitation attempts
        if any(stage in attack_stages for stage in ['Exploitation', 'Execution']):
            return 'Exploitation Campaign'
        
        # Enumeration: Mostly reconnaissance
        recon_count = sum(1 for node in nodes if node.attack_stage == 'Reconnaissance')
        if recon_count / len(nodes) >= 0.7:
            return 'Enumeration Campaign'
        
        # Data Exfiltration: Exfiltration stage present
        if 'Exfiltration' in attack_stages:
            return 'Data Exfiltration Campaign'
        
        # Default: Generic attack campaign
        return 'Attack Campaign'
    
    def _generate_campaign_description(self, campaign_type: str, threat_types: List[str], event_count: int, source_ip: str) -> str:
        """Generate human-readable campaign description"""
        threat_list = ', '.join(threat_types[:3])
        if len(threat_types) > 3:
            threat_list += f' and {len(threat_types) - 3} more'
        
        return f"{campaign_type} from {source_ip} with {event_count} events including {threat_list}"
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat graph statistics"""
        return {
            'total_nodes': len(self.nodes),
            'total_edges': sum(len(edges) for edges in self.edges.values()) // 2,  # Undirected graph
            'total_clusters': len(self.clusters),
            'total_campaigns': len(self.campaigns),
            'campaign_severity_distribution': {
                'critical': sum(1 for c in self.campaigns if c.severity == 'critical'),
                'high': sum(1 for c in self.campaigns if c.severity == 'high'),
                'medium': sum(1 for c in self.campaigns if c.severity == 'medium'),
                'low': sum(1 for c in self.campaigns if c.severity == 'low'),
            },
            'campaign_types': {
                campaign_type: sum(1 for c in self.campaigns if c.campaign_type == campaign_type)
                for campaign_type in set(c.campaign_type for c in self.campaigns)
            },
            'avg_events_per_campaign': round(sum(c.event_count for c in self.campaigns) / len(self.campaigns), 1) if self.campaigns else 0,
            'avg_campaign_score': round(sum(c.campaign_score for c in self.campaigns) / len(self.campaigns), 2) if self.campaigns else 0,
        }
\n`\n\n