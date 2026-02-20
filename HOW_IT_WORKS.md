# Enterprise-Grade Multi-Layer Threat Detection System

## Architecture Overview

Your system now implements a **4-layer detection architecture** similar to enterprise SOC platforms (Splunk, Elastic Security, Microsoft Sentinel):

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: SIGNATURE DETECTION (Deterministic Rules)        │
│  - Pattern matching for known attacks                       │
│  - XSS, SQLi, Path Traversal, Command Injection, etc.      │
│  - High confidence (85-95%)                                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: BEHAVIORAL DETECTION                              │
│  - Brute force detection                                    │
│  - Rate limiting violations                                 │
│  - Suspicious user agents                                   │
│  - Medium confidence (65-75%)                               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: ML ANOMALY DETECTION                              │
│  - Isolation Forest / Autoencoder                           │
│  - Detects unusual patterns                                 │
│  - Percentile-based severity (P99=Critical, P95=High, etc.) │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: CORRELATION ENGINE                                │
│  - Multi-stage attack detection                             │
│  - Attack campaign identification                           │
│  - APT (Advanced Persistent Threat) detection               │
└─────────────────────────────────────────────────────────────┘
```

---

## How Detection Works

### Step 1: File Upload & Parsing
- User uploads CSV/log file
- Parser detects format (syslog/HTTP/generic)
- Extracts structured records (HTTPRecord objects)

### Step 2: Feature Engineering (19 Features)

**Numeric Features (6):**
- `uri_length` - Length of URI
- `response_size` - Response size in bytes
- `duration` - Request duration in ms
- `status_code` - HTTP status code
- `request_rate_per_ip` - Requests from same IP
- `unique_uri_count_per_ip` - Unique URIs per IP

**Binary Security Features (7):**
- `has_path_traversal` - Detects `../`, `/etc/passwd`
- `has_sql_injection` - Detects `sqlmap`, `UNION SELECT`
- `has_xss` - Detects `<script>`, `javascript:`
- `has_command_injection` - Detects `rm -rf`, `whoami`
- `has_privilege_escalation` - Detects `/admin`, `sudo`
- `has_data_exfiltration` - Detects `/export`, large files
- `has_suspicious_agent` - Detects `sqlmap`, `nikto`, `nmap`

**Statistical Features (3):**
- `is_client_error` - 4xx status codes
- `is_server_error` - 5xx status codes
- `is_post_method` - POST requests

**Z-score Features (3):**
- `uri_length_zscore` - Normalized URI length
- `response_size_zscore` - Normalized response size
- `duration_zscore` - Normalized duration

> **Important:** These features inform ML about patterns but DON'T classify threats. Classification is done by rules.

### Step 3: Layer 3 - ML Anomaly Detection

**Isolation Forest:**
- Detects rare patterns
- Produces higher anomaly counts
- Fast, good for statistical outliers

**Autoencoder:**
- Detects reconstruction deviations
- Produces fewer, high-confidence anomalies
- Better for complex patterns

**Output:** Anomaly score (0-1) for each record

### Step 4: Percentile-Based Severity Classification

Thresholds calculated from current data:
- **P99** (top 1%) → CRITICAL
- **P95** (top 5%) → HIGH
- **P90** (top 10%) → MEDIUM
- **P80** (top 20%) → LOW
- **Below P80** → NORMAL

**Why Percentiles?**
- Adaptive to each dataset
- No hardcoded thresholds
- Different models have different score distributions

### Step 5: Layer 1 & 2 - Signature + Behavioral Detection

For **EVERY** HTTP record (not just anomalies):

**Priority 1: Code Execution (Critical)**
1. Command Injection → 95% confidence
2. SSTI → 95% confidence

**Priority 2: Injection Attacks**
3. SQL Injection → 90% confidence
4. XSS → 90% confidence

**Priority 3: File Access**
5. Path Traversal → 92% confidence
6. Sensitive File Disclosure → 88% confidence

**Priority 4: Network Attacks**
7. SSRF → 85% confidence

**Priority 5: Authorization**
8. IDOR → 75% confidence
9. Privilege Escalation → 80% confidence

**Priority 6: Data Attacks**
10. Data Exfiltration → 78% confidence

**Priority 7: Redirect**
11. Open Redirect → 82% confidence

**Priority 8: Behavioral**
12. Brute Force → 70% confidence
13. Reconnaissance → 65% confidence

**Severity Boosting:**
- If threat is **Command Injection, SQL Injection, Path Traversal, SSTI, or RCE**
- AND severity is LOW or MEDIUM
- → Upgrade to **HIGH**

**Minimum Severity Rule:**
- If threat detected BUT ML says "normal"
- → Upgrade severity to at least **LOW**

### Step 6: Layer 4 - Correlation Engine

Analyzes all results to detect:

**Pattern 1: Advanced Persistent Threat (APT)**
- Reconnaissance → Exploitation → Exfiltration
- Example: Same IP does: Recon → SQLi → Data Exfiltration
- Severity: **CRITICAL**

**Pattern 2: Automated Attack Campaign**
- Same attack type repeated 3+ times from same IP
- Example: 5 SQL injection attempts from 10.1.2.3
- Severity: **HIGH**

### Step 7: Generate Explanation

Combines:
- Threat type
- Confidence score
- Detection layer
- HTTP details (status, size, duration)

**Example outputs:**
- `"SQL Injection detected (confidence: 90%) via Layer 1: Signature Detection; HTTP 200"`
- `"Path Traversal detected (confidence: 92%) via Layer 1: Signature Detection; HTTP 404; 2202 bytes"`
- `"Anomalous behavior detected (ML score: 0.856) via Layer 3: ML Anomaly Detection"`

### Step 8: Display Results

Frontend shows:
- Threat type in brackets: `[SQL Injection]`
- Explanation with confidence and detection layer
- All log fields (IP, URI, status, size, duration, user agent, referer)
- Severity badge (color-coded)
- Threat type distribution chart
- Detection layer distribution
- **Attack campaigns** (if detected)

---

## Key Improvements Over Previous Version

### 1. ✅ Confidence Scoring
- Each threat has confidence level (65-95%)
- Higher confidence = more certain detection
- Helps prioritize response

### 2. ✅ Detection Layer Tracking
- Know which layer detected each threat
- Layer 1 (Signature) = Known attack patterns
- Layer 2 (Behavioral) = Suspicious behavior
- Layer 3 (ML) = Anomalous patterns
- Layer 4 (Correlation) = Multi-stage attacks

### 3. ✅ Severity Boosting
- Critical threats automatically upgraded
- Command Injection, SQLi, Path Traversal → HIGH minimum
- Prevents false negatives

### 4. ✅ Correlation Engine
- Detects attack campaigns
- Identifies APT patterns
- Groups related threats by IP

### 5. ✅ Enhanced Explanations
- Shows confidence percentage
- Shows detection layer
- More detailed context

---

## Training Strategy

### ❌ WRONG: Train on Mixed Data
```python
ANOMALY_RATIO = 0.25  # 25% attacks
# ML learns: "Attacks are normal (25% of traffic)"
# Result: Attacks not detected as anomalies
```

### ✅ CORRECT: Train on Clean Data Only
```python
ANOMALY_RATIO = 0.0  # 0% attacks
# ML learns: "This is normal behavior"
# Result: Any attack becomes anomalous
```

**Steps:**
1. Set `ANOMALY_RATIO = 0.0` in `generate_advanced_logs.py`
2. Run: `python generate_advanced_logs.py`
3. Delete old models: `rmdir /s /q data\models` (Windows)
4. Run: `python retrain_models.py`
5. Test with mixed traffic (set `ANOMALY_RATIO = 0.25`)

---

## Why This Architecture Works

### ML Alone is NOT Enough
- ML detects: "Unusual behavior compared to training"
- ML does NOT detect: "This is XSS because it's XSS"
- If training data contains `/etc/passwd`, ML considers it normal

### Rules Alone are NOT Enough
- Rules miss: Zero-day attacks, novel patterns
- Rules miss: Behavioral anomalies (unusual request rates)
- Rules require: Constant updates for new attack patterns

### Hybrid Approach = Best of Both Worlds
- **Rules** catch known attacks with high confidence
- **ML** catches unknown/novel attacks
- **Behavioral** catches brute force, scanning
- **Correlation** catches sophisticated campaigns

---

## System Behavior

### Training
- **Does NOT retrain** on every upload
- **Retrains ONCE** if feature count mismatch
- **Uses existing models** for subsequent uploads
- **Manual retrain:** Run `python retrain_models.py`

### Detection
- **Always runs** on all records
- **Layer 1-2** run first (signature + behavioral)
- **Layer 3** provides ML anomaly score
- **Layer 4** correlates results
- **Same input** → Same output (deterministic)

### Severity Assignment
1. ML calculates percentile-based severity
2. Rules classify threat type with confidence
3. Severity boosting for critical threats
4. Minimum severity if threat detected

---

## Comparison to Enterprise SOC Platforms

| Feature | Your System | Splunk | Elastic | Sentinel |
|---------|-------------|--------|---------|----------|
| Signature Detection | ✅ | ✅ | ✅ | ✅ |
| Behavioral Detection | ✅ | ✅ | ✅ | ✅ |
| ML Anomaly Detection | ✅ | ✅ | ✅ | ✅ |
| Correlation Engine | ✅ | ✅ | ✅ | ✅ |
| Confidence Scoring | ✅ | ✅ | ✅ | ✅ |
| Multi-Layer Architecture | ✅ | ✅ | ✅ | ✅ |

Your system now implements the same core architecture as enterprise SOC platforms!

---

## Next Steps

1. **Generate clean training data:**
   ```bash
   # Edit generate_advanced_logs.py: Set ANOMALY_RATIO = 0.0
   python generate_advanced_logs.py
   ```

2. **Retrain models:**
   ```bash
   rmdir /s /q data\models  # Windows
   python retrain_models.py
   ```

3. **Generate test data with attacks:**
   ```bash
   # Edit generate_advanced_logs.py: Set ANOMALY_RATIO = 0.25
   python generate_advanced_logs.py
   ```

4. **Test detection:**
   ```bash
   python app.py
   # Upload advanced_synthetic_logs.log
   ```

5. **Verify results:**
   - Check confidence scores
   - Check detection layers
   - Check for attack campaigns
   - Verify threat types are accurate
