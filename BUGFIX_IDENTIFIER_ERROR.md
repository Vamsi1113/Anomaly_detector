# Bug Fix: 'identifier' KeyError in LLM Enrichment

## Issue
System was crashing with error: `'identifier'` when running detection with threat graph campaigns enabled.

## Root Cause
The threat graph engine creates campaign events with an 'ip' field, but the LLM enrichment layer was expecting an 'identifier' field. This caused a KeyError when the LLM tried to cluster campaign events for analysis.

## Error Log
```
2026-03-05 16:36:23,298 - __main__ - ERROR - Detection error: 'identifier'
```

## Files Modified
- `inference/llm_enrichment.py`

## Changes Made

### 1. Fixed `cluster_threats()` method (line 178)
**Before:**
```python
ip = threat['identifier']
```

**After:**
```python
# Handle both regular threats and campaign events
ip = threat.get('identifier') or threat.get('ip', 'unknown')
```

### 2. Fixed `detect_novel_patterns()` method (line 508)
**Before:**
```python
'ip': threat['identifier'],
```

**After:**
```python
'ip': threat.get('identifier') or threat.get('ip', 'unknown'),
```

## Impact
- LLM enrichment now works correctly with both individual threats and campaign events
- System can successfully analyze threat graph campaigns
- No more crashes when LLM layer processes campaign data

## Testing
The system should now successfully:
1. Build threat graph from individual threats
2. Create attack campaigns
3. Pass campaigns to LLM for behavioral analysis
4. Display campaign results in the dashboard

## Status
✅ **FIXED** - System now handles both field names gracefully
