# LLM Intelligence Layer - Configuration Guide

## Overview

The LLM Intelligence Layer is an **optional** post-detection enrichment service that provides behavioral analysis and threat intelligence for high-severity threats.

## Architecture

```
Detection Phase (Always Runs)
├── Layer 1: Signature Detection
├── Layer 2: Behavioral Detection  
├── Layer 3: ML Anomaly Detection
├── Layer 4: Decision Engine
└── Layer 5: Correlation Engine

Enrichment Phase (Optional - LLM)
└── Layer 6: LLM Intelligence
    ├── Filter: Only Critical/High/Medium
    ├── Cluster: Group similar threats
    ├── Analyze: Behavioral patterns
    └── Discover: Novel threat patterns
```

## What LLM Does

✅ **LLM DOES:**
- Analyze behavioral patterns in threat clusters
- Identify multi-stage attack patterns
- Detect automated vs manual attacks
- Suggest attacker objectives
- Discover novel threat patterns
- Generate SOC-ready summaries

❌ **LLM DOES NOT:**
- Assign severity levels
- Override detection logic
- Replace deterministic rules
- Replace ML models
- Act as primary detector

## Configuration

### Step 1: Install OpenAI SDK

```bash
pip install openai
```

### Step 2: Set Environment Variables

**Option A: Using .env file (Recommended)**

Create a `.env` file in your project root:

```bash
ENABLE_LLM=true
OPENAI_API_KEY=sk-your-api-key-here
```

**Option B: Using system environment variables**

Windows (CMD):
```cmd
set ENABLE_LLM=true
set OPENAI_API_KEY=sk-your-api-key-here
```

Windows (PowerShell):
```powershell
$env:ENABLE_LLM="true"
$env:OPENAI_API_KEY="sk-your-api-key-here"
```

Linux/Mac:
```bash
export ENABLE_LLM=true
export OPENAI_API_KEY=sk-your-api-key-here
```

### Step 3: Run the Application

```bash
python app.py
```

The system will automatically detect the configuration and enable LLM enrichment if configured.

## Cost Control

The LLM service includes built-in cost controls:

- **Max Clusters per File**: 10 (only top 10 most severe clusters analyzed)
- **Max Tokens per Request**: 500 (limits response length)
- **Model**: GPT-3.5-Turbo (cost-effective)
- **Filtering**: Only Critical/High/Medium threats
- **Clustering**: Groups similar threats to reduce API calls

### Estimated Costs

- **Small file (100 threats)**: ~$0.01 - $0.02
- **Medium file (1,000 threats)**: ~$0.05 - $0.10
- **Large file (10,000 threats)**: ~$0.10 - $0.20

*Costs are approximate and depend on threat clustering efficiency*

## Output Format

### LLM Enrichment Results

The system adds a new `llm_enrichment` section to the statistics:

```json
{
  "llm_enrichment": {
    "enabled": true,
    "clusters_analyzed": 5,
    "novel_patterns_detected": 2,
    "llm_insights": [
      {
        "cluster_ip": "192.168.1.100",
        "threat_types": ["SQL Injection", "Path Traversal"],
        "request_count": 42,
        "llm_analysis": "This cluster shows automated SQL injection attempts followed by path traversal, indicating reconnaissance for database access. The attacker is likely using an automated tool (sqlmap) to enumerate database structure. Objective appears to be data exfiltration. Pattern is consistent with known attack frameworks.",
        "llm_model": "gpt-3.5-turbo",
        "analyzed_at": "2026-02-25T10:30:00"
      }
    ],
    "novel_patterns": [
      {
        "uri": "/api/unusual-endpoint",
        "ip": "10.20.30.40",
        "anomaly_score": 0.95,
        "timestamp": "2026-02-25 10:25:00"
      }
    ]
  }
}
```

## Disabling LLM Enrichment

To disable LLM enrichment:

1. Remove or set `ENABLE_LLM=false` in environment
2. Or simply don't set `OPENAI_API_KEY`

The system will run normally with 5 detection layers (without LLM).

## Best Practices

### 1. Use for High-Value Analysis

Enable LLM for:
- Production incident analysis
- Security audits
- Threat hunting
- SOC reporting

### 2. Disable for Testing

Disable LLM for:
- Development testing
- Performance testing
- Cost-sensitive environments

### 3. Review LLM Suggestions

**IMPORTANT**: LLM suggestions should be:
- Reviewed by security analysts
- Validated before adding to rule engine
- Used as intelligence, not automatic rules

### 4. Monitor Costs

- Check OpenAI usage dashboard regularly
- Set billing alerts in OpenAI account
- Adjust `max_clusters_per_file` if needed

## Customization

### Adjust Cost Controls

Edit `inference/llm_enrichment.py`:

```python
class LLMEnrichmentService:
    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        self.max_clusters_per_file = 10  # Increase/decrease
        self.max_tokens = 500  # Increase for more detailed analysis
```

### Change LLM Model

```python
response = self.client.chat.completions.create(
    model="gpt-4",  # More powerful but more expensive
    # or
    model="gpt-3.5-turbo",  # Cost-effective (default)
    ...
)
```

### Adjust Clustering

```python
# In cluster_threats() method
if total_threats >= 3:  # Change minimum threshold
```

## Troubleshooting

### LLM Not Running

**Check logs for:**
```
LLM Enrichment Service disabled (no API key or SDK not available)
```

**Solutions:**
1. Verify `ENABLE_LLM=true` is set
2. Verify `OPENAI_API_KEY` is set correctly
3. Verify OpenAI SDK is installed: `pip install openai`

### API Key Errors

**Error:** `Invalid API key`

**Solutions:**
1. Check API key format (starts with `sk-`)
2. Verify key is active in OpenAI dashboard
3. Check billing is enabled

### No Clusters Analyzed

**Log:** `Filtered 0 high-severity threats for LLM analysis`

**Reason:** No Critical/High/Medium threats detected

**This is normal** - LLM only runs when high-severity threats exist

## Security Considerations

1. **API Key Security**
   - Never commit API keys to git
   - Use environment variables
   - Add `.env` to `.gitignore`

2. **Data Privacy**
   - Log data is sent to OpenAI API
   - Review OpenAI's data usage policy
   - Consider data sensitivity before enabling

3. **Rate Limiting**
   - OpenAI has rate limits
   - System handles errors gracefully
   - Failed LLM calls don't affect detection

## Example Usage

### Scenario: Analyzing Attack Campaign

1. Upload log file with 1000 entries
2. System detects 50 Critical/High/Medium threats
3. LLM clusters them into 5 groups by IP and pattern
4. LLM analyzes each cluster:
   - "Automated SQLi campaign from 192.168.1.50"
   - "Manual reconnaissance from 10.20.30.40"
   - "Multi-stage APT pattern from 172.16.0.100"
5. Results displayed in dashboard with insights

### Scenario: Novel Threat Discovery

1. ML detects high anomaly score (0.95)
2. No signature match (threat_type = "Other")
3. LLM analyzes the pattern
4. LLM suggests: "Possible SSRF variant using encoded metadata URL"
5. Analyst reviews and adds new signature rule

## Support

For issues or questions:
1. Check logs in console output
2. Verify configuration settings
3. Test with small file first
4. Review OpenAI API status

---

**Remember**: LLM is an analyst assistant, not a detector. It enriches your existing detection with behavioral intelligence.
