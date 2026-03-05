# Integration Guide - System Improvements

## Quick Start

The core improvements are implemented. Follow these steps to complete integration:

---

## Step 1: Verify New Files Created

✅ Check these files exist:
```
inference/mitre_attack_mapper.py       # MITRE ATT&CK mappings
inference/false_positive_filter.py     # FP reduction filters
```

✅ Check these files were updated:
```
inference/decision_engine.py           # Enhanced with MITRE + FP filtering
inference/correlation_engine.py        # Enhanced with MITRE context
```

---

## Step 2: Test the System

### Run Detection:
```bash
python app.py
```

### Upload Test File:
- Use `logs_dataset.csv` (100K records)
- Select either Isolation Forest or Autoencoder
- Run detection

### Expected Results:
- **Before**: ~6,000 anomalies (Isolation Forest) or ~330 (Autoencoder)
- **After**: ~30-100 threats (90-95% reduction)
- All threats should have MITRE technique fields
- Check console logs for "Filtered false positive" messages

---

## Step 3: Verify MITRE Mappings

### Check Detection Results:
Each threat should now include:
```json
{
  "threat_type": "SQL Injection",
  "mitre_technique": "T1190",
  "mitre_technique_name": "Exploit Public-Facing Application",
  "mitre_tactic": "Initial Access",
  "attack_stage": "Exploitation",
  "mitre_description": "SQL injection to exploit database vulnerabilities"
}
```

### Verify in Dashboard:
- Threats should display MITRE technique IDs
- Attack stages should be visible
- Tactics should be categorized

---

## Step 4: Monitor False Positive Filtering

### Check Console Logs:
```
Filtered false positive: ML-only detection (no signature or behavioral match)
Filtered false positive: Whitelisted safe endpoint
Filtered false positive: Safe file extension
```

### Check Statistics:
The decision engine now tracks:
- Total decisions made
- False positives filtered
- False positive rate
- Unique IPs/URIs tracked

---

## Step 5: Test Correlation Engine

### Upload File with Multiple Threats:
Use a file with varied attack types from same IP

### Expected Campaigns:
```
⚠️  Advanced Persistent Threat (APT) detected
    - Multi-stage attack progression
    - Kill chain coverage: 45%
    - Stages: Reconnaissance → Exploitation → Exfiltration

⚠️  Automated Attack Campaign detected
    - Repeated attacks: 15 threats
    - Automation confidence: 85%
```

---

## Step 6: Update Dashboard (Optional)

### Add MITRE Fields to Results Table:

Edit `ui/templates/dashboard.html`:

```html
<!-- Add MITRE column to table header -->
<th>MITRE Technique</th>
<th>Attack Stage</th>

<!-- Add MITRE data to table rows -->
<td>
  <span class="mitre-badge">{{ result['mitre_technique'] }}</span>
  <div class="mitre-name">{{ result['mitre_technique_name'] }}</div>
</td>
<td>
  <span class="stage-badge">{{ result['attack_stage'] }}</span>
</td>
```

### Add CSS Styling:

Edit `ui/static/style.css`:

```css
.mitre-badge {
    background: #2196F3;
    color: white;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
}

.mitre-name {
    font-size: 9px;
    color: #666;
    margin-top: 2px;
}

.stage-badge {
    background: #ff9800;
    color: white;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10px;
}
```

---

## Step 7: Tune Thresholds (If Needed)

### If Too Many False Positives:

Edit `inference/decision_engine.py`:
```python
# Increase ML weight reduction
ML_WEIGHT = 0.15  # Down from 0.2

# Raise LOW threshold
LOW_THRESHOLD = 0.50  # Up from 0.45
```

### If Missing Real Threats:

```python
# Increase ML weight
ML_WEIGHT = 0.25  # Up from 0.2

# Lower thresholds
LOW_THRESHOLD = 0.40  # Down from 0.45
```

---

## Step 8: Add Custom Whitelists

### Edit `inference/false_positive_filter.py`:

```python
# Add your safe endpoints
SAFE_ENDPOINTS.add('/your-health-endpoint')
SAFE_ENDPOINTS.add('/your-monitoring-path')

# Add your monitoring tools
SAFE_USER_AGENTS.add('your-uptime-monitor')
SAFE_USER_AGENTS.add('your-load-balancer')

# Add your safe query parameters
SAFE_QUERY_PARAMS.add('your-tracking-param')
```

---

## Step 9: Test LLM Integration (Optional)

### Verify LLM Receives MITRE Context:

The LLM enrichment should now receive:
```python
{
    'threat_type': 'SQL Injection',
    'mitre_technique': 'T1190',
    'mitre_tactic': 'Initial Access',
    'attack_stage': 'Exploitation',
    'cluster_info': {...},
    'behavioral_indicators': {...}
}
```

### LLM Should Generate:
- Threat explanation using MITRE context
- Attack narrative with kill chain stages
- MITRE technique explanation
- Recommended response actions

---

## Step 10: Performance Testing

### Test with Large Dataset:
```bash
# 100K records
python app.py
# Upload logs_dataset.csv
```

### Monitor:
- Processing time (should be <5% slower)
- Memory usage (should be minimal increase)
- False positive rate (aim for <10%)
- Detection accuracy (aim for >90%)

---

## Troubleshooting

### Issue: Too Many False Positives

**Solution 1**: Check if ML-only filtering is working
```python
# In decision_engine.py, verify this code exists:
if not signature_flag and not behavior_flag:
    return True, "ML-only detection"
```

**Solution 2**: Add more whitelists
```python
# Add your legitimate endpoints to SAFE_ENDPOINTS
```

**Solution 3**: Increase LOW_THRESHOLD
```python
LOW_THRESHOLD = 0.50  # More conservative
```

### Issue: Missing MITRE Fields

**Solution**: Check imports in decision_engine.py
```python
from inference.mitre_attack_mapper import MITREAttackMapper
from inference.false_positive_filter import FalsePositiveFilter
```

### Issue: Correlation Not Working

**Solution**: Verify threats have MITRE fields
```python
# Each threat must have:
threat['mitre_technique']
threat['mitre_tactic']
threat['attack_stage']
```

---

## Validation Checklist

- [ ] New files created (mitre_attack_mapper.py, false_positive_filter.py)
- [ ] Decision engine updated with MITRE + FP filtering
- [ ] Correlation engine updated with MITRE context
- [ ] System runs without errors
- [ ] False positives reduced by 90%+
- [ ] All threats have MITRE technique fields
- [ ] Correlation detects multi-stage attacks
- [ ] Dashboard displays MITRE information
- [ ] LLM uses MITRE context (if enabled)
- [ ] Performance acceptable (<5% overhead)

---

## Quick Test Script

Create `test_improvements.py`:

```python
"""Quick test of system improvements"""
from inference.mitre_attack_mapper import MITREAttackMapper
from inference.false_positive_filter import FalsePositiveFilter
from inference.decision_engine import DecisionEngine

# Test MITRE mapper
mapper = MITREAttackMapper()
mapping = mapper.get_mapping("SQL Injection")
print(f"✓ MITRE Mapper: {mapping.technique_id} - {mapping.technique_name}")

# Test FP filter
fp_filter = FalsePositiveFilter()
should_filter, reason = fp_filter.should_filter(
    threat_type="Other",
    uri="/health",
    user_agent="",
    client_ip="1.2.3.4",
    signature_flag=False,
    behavior_flag=False,
    ml_score=0.8
)
print(f"✓ FP Filter: Filtered={should_filter}, Reason={reason}")

# Test decision engine
engine = DecisionEngine()
print(f"✓ Decision Engine: Initialized with FP filter and MITRE mapper")

print("\n✅ All components working!")
```

Run:
```bash
python test_improvements.py
```

---

## Success Criteria

### Before Improvements:
- 100K logs → 6,000 anomalies (6% detection rate)
- 95%+ false positive rate
- No MITRE context
- Overwhelming for analysts

### After Improvements:
- 100K logs → 30-100 threats (0.03-0.1% detection rate)
- <10% false positive rate
- All threats have MITRE ATT&CK mapping
- Actionable intelligence for analysts

---

## Support

If you encounter issues:

1. Check console logs for error messages
2. Verify all imports are correct
3. Ensure new files are in `inference/` directory
4. Test individual components with test script
5. Review `SYSTEM_IMPROVEMENTS_SUMMARY.md` for details

---

**Status**: Ready for Integration Testing
**Next**: Run `python app.py` and test with real data
