# LLM Intelligence Layer - Quick Setup Guide

## Overview
The LLM Intelligence Layer (Layer 6) is now integrated into your threat detection system. It provides post-detection enrichment for high-severity threats.

## Quick Setup (3 Steps)

### Step 1: Install Dependencies
```bash
pip install openai python-dotenv
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

### Step 2: Configure API Key
Edit the `.env` file and add your OpenAI API key:

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-your-actual-api-key-here
```

Get your API key from: https://platform.openai.com/api-keys

### Step 3: Restart Application
```bash
python app.py
```

## What LLM Does

The LLM Intelligence Layer analyzes **only Critical, High, and Medium severity threats** and provides:

1. **Behavioral Pattern Analysis** - Identifies attack progression patterns
2. **Multi-Stage Attack Detection** - Detects coordinated attack campaigns
3. **Automated vs Manual Classification** - Determines attacker behavior
4. **Attacker Objective Assessment** - Suggests likely goals
5. **Novel Threat Discovery** - Identifies unknown attack patterns
6. **SOC-Ready Summaries** - Generates analyst-friendly reports

## What LLM Does NOT Do

- ❌ Assign severity (Decision Engine does this)
- ❌ Override detection logic (Rules are deterministic)
- ❌ Replace signature detection (Layer 1 always runs first)
- ❌ Replace ML anomaly detection (Layer 3 provides statistical scores)

## Cost Controls

Built-in cost controls:
- Maximum 10 clusters analyzed per file
- Maximum 500 tokens per LLM request
- Uses GPT-3.5-Turbo (cost-effective model)
- Smart clustering reduces API calls

## Verification

After setup, check the console logs when running detection:
```
INFO - LLM Enrichment Service initialized with OpenAI
INFO - Layer 6: Running LLM enrichment analysis...
INFO - LLM enrichment complete: X clusters analyzed, Y novel patterns detected
```

## Disable LLM

To disable LLM enrichment, edit `.env`:
```env
ENABLE_LLM=false
```

The system will continue to work normally with Layers 1-5 (deterministic detection).

## Troubleshooting

**Issue**: "OpenAI SDK not installed"
- **Solution**: Run `pip install openai`

**Issue**: "LLM Enrichment Service disabled (no API key)"
- **Solution**: Add valid `OPENAI_API_KEY` to `.env` file

**Issue**: API rate limit errors
- **Solution**: Reduce `max_clusters_per_file` in `inference/llm_enrichment.py`

## Architecture

```
Detection Phase (Always Runs - Deterministic)
├── Layer 1: Signature Detection
├── Layer 2: Behavioral Detection  
├── Layer 3: ML Anomaly Detection
├── Layer 4: Decision Engine
└── Layer 5: Correlation Engine

Enrichment Phase (Optional - LLM)
└── Layer 6: LLM Intelligence
    ├── Filter: Only Critical/High/Medium
    ├── Cluster: Group by IP/threat type
    ├── Analyze: Behavioral patterns
    └── Discover: Novel threats
```

## Next Steps

1. Test with sample data to verify LLM integration
2. Review LLM insights in detection results
3. Adjust cost controls if needed
4. Monitor API usage on OpenAI dashboard

For detailed information, see `LLM_ENRICHMENT_GUIDE.md`
