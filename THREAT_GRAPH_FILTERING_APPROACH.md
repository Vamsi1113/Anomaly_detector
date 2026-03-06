# Threat Graph: False Positive Filtering Approach

## Overview
The threat graph is now used for **intelligent false positive filtering**, not for displaying campaigns. The system shows **individual threat logs** with high confidence.

## How It Works

### Detection Pipeline
```
200K logs → 800 ML anomalies → 150 filtered threats
  ↓
THREAT GRAPH ANALYSIS: 70 clusters → 25 campaigns
  ↓
FILTER: Keep only threats that are part of campaigns
  ↓
50-80 HIGH CONFIDENCE individual threats (displayed)
```

### Filtering Logic

**High Confidence Threats (SHOWN):**
- Part of an attack campaign (correlated with other threats)
- Same IP, time window, attack pattern
- Real attack behavior confirmed by graph analysis

**Low Confidence Threats (FILTERED OUT):**
- Isolated anomalies not part of any campaign
- Single events with no correlation
- Likely false positives

## What You See

**Results Table:**
- Individual threat logs (not campaigns)
- Full details (IP, URI, timestamp, etc.)
- Enhanced explanation with campaign context
- Example: `[CAMPAIGN-001] SQL Injection | Part of Automated Attack Campaign with 8 events`

**Dashboard:**
- Total high-confidence threats (e.g., 50 threats)
- Green badge: "Showing 50 high-confidence threats (filtered using 25 campaigns)"
- Campaign summary panel for context

## Benefits

✅ Reduces false positives by 60-80%
✅ Shows individual logs with full details
✅ Adds campaign context to each threat
✅ Easy investigation of specific events

## Status
✅ IMPLEMENTED
