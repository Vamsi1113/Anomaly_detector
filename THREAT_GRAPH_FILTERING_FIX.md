# Threat Graph Filtering Fix

## Problem Identified

The threat graph was NOT actually filtering anything because of circular logic:

1. **Input**: All Critical/High/Medium threats (e.g., 12 threats)
2. **Threat Graph**: Groups these 12 threats into clusters/campaigns
3. **Old Filtering Logic**: Keep threats that are in campaigns
4. **Result**: ALL 12 threats are kept (because they were all used to build the campaigns!)

This is why you saw the same count before and after threat graph filtering.

## Root Cause

The threat graph engine creates a campaign for EVERY cluster, including:
- **Multi-event clusters**: 2+ threats from same IP with related patterns (REAL ATTACKS)
- **Single-event clusters**: 1 isolated threat (POTENTIAL FALSE POSITIVES)

The old filtering logic kept ALL campaigns, so nothing was filtered.

## Solution Implemented

### Changed Filtering Logic in `inference/engine.py`

**OLD LOGIC** (lines 244-265):
```python
# Keep ALL threats that are in ANY campaign
for campaign in attack_campaigns:
    for event in campaign.events:
        campaign_record_indices.add(event['record_index'])
```

**NEW LOGIC**:
```python
# Keep ONLY threats in multi-event campaigns (2+ events)
for campaign in attack_campaigns:
    if campaign.event_count >= 2:  # ← KEY CHANGE
        multi_event_campaigns.append(campaign)
        for event in campaign.events:
            campaign_record_indices.add(event['record_index'])
```

## How It Works Now

### Example Scenario

**Input**: 12 Critical/High/Medium threats detected

**Threat Graph Analysis**:
- Threat #1: Isolated SQL injection from IP 1.2.3.4 → Single-event cluster
- Threats #2-5: 4 path traversal attempts from IP 5.6.7.8 → Multi-event cluster (CAMPAIGN-001)
- Threats #6-8: 3 XSS attempts from IP 9.10.11.12 → Multi-event cluster (CAMPAIGN-002)
- Threat #9: Isolated admin access from IP 13.14.15.16 → Single-event cluster
- Threats #10-12: 3 brute force attempts from IP 17.18.19.20 → Multi-event cluster (CAMPAIGN-003)

**Filtering Result**:
- ✅ **Keep**: Threats #2-5, #6-8, #10-12 (10 threats in 3 multi-event campaigns)
- ❌ **Filter out**: Threats #1, #9 (2 isolated single-event threats)
- **Final Output**: 10 threats (83% reduction from 12)

## Expected Behavior

### Before Threat Graph
- 200K logs → 800 ML anomalies → 150 Critical/High/Medium threats

### After Threat Graph Filtering
- 150 threats → 70 clusters → 25 multi-event campaigns → **50-80 individual threats displayed**
- **Filtered out**: 70-100 isolated single-event threats (potential false positives)
- **Reduction**: 33-53% fewer threats shown

## Key Points

1. **Multi-event campaigns = HIGH CONFIDENCE**: When multiple threats from the same IP follow attack patterns, it's a real attack
2. **Single-event threats = LOWER CONFIDENCE**: Isolated threats might be false positives or noise
3. **Threat graph shows individual threats, NOT campaigns**: You still see each threat log with full details
4. **Campaign context added**: Each threat's explanation shows which campaign it belongs to

## Verification

To verify this is working, check the logs:

```
✅ Threat Graph Filtering: X high-confidence threats (part of Y multi-event campaigns)
   Filtered out Z isolated single-event threats (potential false positives)
```

Where:
- X = threats kept (in multi-event campaigns)
- Y = number of campaigns with 2+ events
- Z = threats filtered out (isolated single-event)
- X + Z should equal the original threat count

## Files Modified

1. `inference/engine.py` - Fixed filtering logic (lines 244-270)
2. `ui/templates/dashboard.html` - Removed campaign display limit (show all campaigns)
