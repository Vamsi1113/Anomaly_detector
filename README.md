# Enterprise Log Anomaly Detection System

AI-powered threat detection system using multi-layer detection architecture with ML models and LLM intelligence.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the application
python app.py
```

Open http://localhost:5000 in your browser.

## Features

- **6-Layer Detection Architecture**
  - Layer 1: Signature Detection (deterministic rules)
  - Layer 2: Behavioral Detection (stateful analysis)
  - Layer 3: ML Anomaly Detection (Isolation Forest/Autoencoder)
  - Layer 4: Decision Engine (signal aggregation)
  - Layer 5: Correlation Engine (campaign detection)
  - Layer 6: LLM Intelligence (behavioral analysis)

- **ML Models**
  - Isolation Forest (statistical anomaly detection)
  - Autoencoder (deep learning reconstruction error)
  - Trained on 100,000 real log entries

- **Threat Detection**
  - 14+ threat types (SQL Injection, XSS, Path Traversal, etc.)
  - Real-time behavioral analysis
  - Attack campaign correlation
  - LLM-powered threat intelligence

## Configuration

### LLM Intelligence (Optional)

Edit `.env` file:
```env
ENABLE_LLM=true
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=your_endpoint_url
```

## Model Retraining

To retrain models with new data:

```bash
# Replace logs_dataset.csv with your training data
python retrain_models.py
```

## Project Structure

```
├── app.py                  # Main Flask application
├── retrain_models.py       # Model retraining script
├── logs_dataset.csv        # Training data (100K records)
├── config/                 # Configuration files
├── inference/              # Detection engines
├── models/                 # ML model definitions
├── parsing/                # Log parsers
├── features/               # Feature extraction
├── storage/                # Session management
├── ui/                     # Web interface
├── data/models/            # Trained models
└── uploads/                # Uploaded log files
```

## Supported Log Formats

- Syslog format (HTTP logs)
- CSV files with HTTP fields
- Generic CSV files (auto-detected)

## Usage

1. Upload a log file (.log, .csv, .txt)
2. Select detection model (Isolation Forest or Autoencoder)
3. Run detection
4. View results with severity filtering
5. Analyze LLM intelligence reports (if enabled)

## Requirements

- Python 3.8+
- TensorFlow 2.x
- scikit-learn
- Flask
- OpenAI SDK (for LLM features)

See `requirements.txt` for complete list.

## License

Enterprise Log Anomaly Detection System
