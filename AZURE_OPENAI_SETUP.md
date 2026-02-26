# Azure OpenAI Setup Guide

## Critical Configuration Checklist

### ✅ What I Fixed

1. **Import Statement**: Changed from `OpenAI` to `AzureOpenAI`
2. **API Version**: Updated to `2024-08-01-preview` (latest stable)
3. **Better Error Logging**: Added detailed error messages
4. **Test Script**: Created `test_azure_openai.py` for diagnostics

### 🔧 Configuration Steps

#### 1. Verify Your Azure OpenAI Details

Go to Azure Portal → Your OpenAI Resource and note:

- **Endpoint**: Should be `https://rhea-mm1vfuyh-eastus2.cognitiveservices.azure.com/`
- **API Key**: Found under "Keys and Endpoint" section
- **Deployment Name**: Found under "Deployments" tab (e.g., `gpt-4o-mini`)

#### 2. Update .env File

```env
ENABLE_LLM=true
OPENAI_API_KEY=your-azure-api-key-here
```

**CRITICAL**: Use the API key from Azure Portal → Your OpenAI Resource → Keys and Endpoint

#### 3. Verify Deployment Name

The deployment name in the code is set to `gpt-4o-mini`. If your Azure deployment has a different name:

1. Check Azure Portal → Your OpenAI Resource → Deployments
2. Copy the exact deployment name
3. Edit `inference/llm_enrichment.py` line ~217:
   ```python
   deployment_name = "your-actual-deployment-name"
   ```

### 🧪 Test Your Configuration

Run the diagnostic script:

```bash
python test_azure_openai.py
```

This will:
- ✅ Check environment variables
- ✅ Verify OpenAI SDK installation
- ✅ Test Azure OpenAI connection
- ✅ Make a test API call
- ✅ Provide specific troubleshooting if it fails

### 🔍 Common Issues & Solutions

#### Issue 1: 401 Unauthorized / Permission Denied

**Causes:**
- Wrong API key
- Using regular OpenAI key instead of Azure key
- Expired or inactive subscription

**Solutions:**
1. Go to Azure Portal → Your OpenAI Resource → Keys and Endpoint
2. Copy KEY 1 or KEY 2 (not the endpoint)
3. Paste into `.env` file as `OPENAI_API_KEY`
4. Restart the application

#### Issue 2: 404 Deployment Not Found

**Causes:**
- Deployment name mismatch
- Deployment doesn't exist

**Solutions:**
1. Go to Azure Portal → Your OpenAI Resource → Deployments
2. Check the exact deployment name (case-sensitive)
3. Update `deployment_name` in `inference/llm_enrichment.py`
4. Common names: `gpt-4o-mini`, `gpt-4o-mini-deployment`, `gpt4omini`

#### Issue 3: Wrong API Endpoint

**Causes:**
- Incorrect endpoint URL
- Resource moved or deleted

**Solutions:**
1. Verify endpoint in Azure Portal
2. Update `endpoint` in `inference/llm_enrichment.py` line ~107

### 📊 Verify It's Working

After running `python app.py` and uploading a file, check console logs for:

```
INFO - LLM Enrichment Service initialized with Azure OpenAI
INFO - Azure Endpoint: https://rhea-mm1vfuyh-eastus2.cognitiveservices.azure.com/
INFO - Layer 6: Running LLM enrichment analysis...
INFO - Calling Azure OpenAI with deployment: gpt-4o-mini
INFO - LLM enrichment complete: X clusters analyzed
```

### 🎯 Dashboard Display

LLM insights appear in a blue section:
- **🧠 LLM Intelligence Analysis (Layer 6)**
- Behavioral insights for each threat cluster
- Novel threat patterns discovered

### 💰 Cost Tracking

Azure OpenAI charges appear in your Azure subscription billing, not OpenAI credits.

Monitor usage: Azure Portal → Your OpenAI Resource → Metrics

### 🆘 Still Not Working?

Run the diagnostic script and share the output:
```bash
python test_azure_openai.py
```

The script will pinpoint the exact issue.
