# Model Retraining Guide

## Production-Grade SOC Architecture

Your system now implements enterprise-level threat detection:

```
Layer 1: Signature Detection (Rules)
  ↓ XSS, SQLi, SSRF, RCE, IDOR, SSTI, etc.
  
Layer 2: Behavioral Detection
  ↓ Brute force, rate limiting
  
Layer 3: ML Anomaly Detection
  ↓ Isolation Forest / Autoencoder
  
Layer 4: Hybrid Classification
  ↓ ML scores + Rule-based threat types
```

## Retraining Steps

### Step 1: Generate Advanced Synthetic Logs

```bash
python generate_advanced_logs.py
```

This creates `advanced_synthetic_logs.log` with:
- 1000 records total
- 75% clean traffic (normal behavior)
- 25% attack traffic (all threat types)

**Attack Types Included:**
- XSS
- SQL Injection
- Path Traversal / LFI
- SSRF
- Command Injection / RCE
- IDOR
- SSTI
- Open Redirect
- Sensitive File Disclosure
- Privilege Escalation
- Data Exfiltration
- Reconnaissance

### Step 2: Delete Old Models

```bash
# Windows
rmdir /s /q data\models

# Linux/Mac
rm -rf data/models
```

### Step 3: Retrain Models

```bash
python retrain_models.py
```

This will:
1. Parse `advanced_synthetic_logs.log`
2. Extract 19 security features
3. Train Isolation Forest (~5 seconds)
4. Train Autoencoder (~30 seconds)
5. Save models to `data/models/`

### Step 4: Start Application

```bash
python app.py
```

Navigate to: http://localhost:5000

### Step 5: Test Detection

Upload test files with attacks:
- `orglog1.csv` (real enterprise logs with attacks)
- `advanced_synthetic_logs.log` (generated test data)

## How It Works

### ML Training Strategy

**CRITICAL:** Models are trained on CLEAN traffic only (75% of synthetic data)

Why?
- ML learns: "This is normal behavior"
- Attacks become anomalous (high scores)
- No contamination from attack patterns

### Detection Flow

```
1. Upload file
   ↓
2. Extract 19 features per record
   ↓
3. ML Anomaly Detection
   - Isolation Forest: Statistical outliers
   - Autoencoder: Reconstruction errors
   ↓
4. Percentile-Based Severity
   - P99 → CRITICAL
   - P95 → HIGH
   - P90 → MEDIUM
   - P80 → LOW
   ↓
5. Rule-Based Threat Classification
   - ALWAYS runs (not just on anomalies)
   - Detects 14+ attack types
   - Deterministic patterns
   ↓
6. Hybrid Result
   - If threat detected BUT ML says normal → Upgrade to LOW
   - Combines ML confidence + Rule certainty
```

### Features Extracted (19 total)

**Numeric (6):**
- uri_length
- response_size
- duration
- status_code
- request_rate_per_ip
- unique_uri_count_per_ip

**Binary Security (7):**
- has_path_traversal
- has_sql_injection
- has_xss
- has_command_injection
- has_privilege_escalation
- has_data_exfiltration
- has_suspicious_agent

**Statistical (3):**
- is_client_error
- is_server_error
- is_post_method

**Z-scores (3):**
- uri_length_zscore
- response_size_zscore
- duration_zscore

## When to Retrain

Retrain models when:
1. **Feature count changes** (automatic)
2. **New attack patterns emerge** (manual)
3. **False positive rate too high** (manual)
4. **Baseline traffic changes** (quarterly)

## Troubleshooting

### Issue: Feature mismatch error
**Solution:** Delete `data/models/` and retrain

### Issue: TensorFlow not available
**Solution:** System works with Isolation Forest only (autoencoder optional)

### Issue: All threats show as "Other"
**Solution:** Check threat_detectors.py patterns match your data

### Issue: Too many false positives
**Solution:** Retrain on larger clean dataset

## Files Removed

Cleaned up unnecessary files:
- ❌ `synthetic_data.py` (old generator)
- ❌ `generate_samples.py` (old generator)
- ❌ `train_models.py` (old training)
- ❌ `train_models_fresh.py` (old training)

## Production Recommendations

1. **Training Data:** Use 10,000+ clean records
2. **Retraining:** Monthly or when baseline changes
3. **Monitoring:** Track false positive rate
4. **Tuning:** Adjust percentile thresholds per environment
5. **Correlation:** Add multi-stage attack detection (future)

## Architecture Benefits

✅ Hybrid ML + Rules (best of both worlds)
✅ Adaptive percentile thresholds
✅ 14+ attack types detected
✅ No hardcoded thresholds
✅ SOC-grade deterministic classification
✅ Catches known attacks even if in training data
