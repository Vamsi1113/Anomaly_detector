"""
Azure OpenAI Configuration Test Script
Run this to verify your Azure OpenAI setup
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_azure_openai():
    """Test Azure OpenAI configuration"""
    print("=" * 70)
    print("Azure OpenAI Configuration Test")
    print("=" * 70)
    
    # Step 1: Check environment variables
    print("\n1. Environment Variables:")
    
    # Force reload .env file
    load_dotenv(override=True)
    
    enable_llm = os.getenv('ENABLE_LLM', 'false')
    api_key = os.getenv('OPENAI_API_KEY', None)
    
    print(f"   ENABLE_LLM: {enable_llm}")
    
    if api_key:
        print(f"   OPENAI_API_KEY: Set ({api_key[:10]}...{api_key[-10:]})")
        print(f"   Key Length: {len(api_key)} characters")
        
        # Check if it's the wrong key type
        if api_key.startswith('sk-proj-') or api_key.startswith('sk-'):
            print(f"\n   ❌ ERROR: This is a REGULAR OpenAI key, not Azure!")
            print(f"   Regular OpenAI keys start with 'sk-' or 'sk-proj-'")
            print(f"   Azure OpenAI keys are 32-64 character random strings")
            print(f"\n   Get your Azure key from:")
            print(f"   Azure Portal → Your OpenAI Resource → Keys and Endpoint → KEY 1")
            return
    else:
        print(f"   OPENAI_API_KEY: Not set")
    
    if not api_key:
        print("\n   ❌ ERROR: OPENAI_API_KEY not set in .env file")
        print("   → Add your Azure OpenAI API key to .env file")
        return
    
    # Step 2: Check OpenAI SDK
    print("\n2. OpenAI SDK:")
    try:
        from openai import OpenAI
        import openai
        print(f"   ✓ OpenAI SDK installed (version: {openai.__version__})")
    except ImportError as e:
        print(f"   ❌ OpenAI SDK not installed: {e}")
        print("   → Run: pip install openai")
        return
    
    # Step 3: Test Azure OpenAI connection
    print("\n3. Azure OpenAI Connection Test:")
    endpoint = "https://rhea-mm1vfuyh-eastus2.cognitiveservices.azure.com/openai/v1/"
    
    print(f"   Endpoint: {endpoint}")
    
    try:
        client = OpenAI(
            base_url=endpoint,
            api_key=api_key
        )
        print("   ✓ Azure OpenAI client initialized successfully")
    except Exception as e:
        print(f"   ❌ Failed to initialize client: {e}")
        return
    
    # Step 4: Test API call with deployment name
    print("\n4. Testing API Call:")
    deployment_name = "gpt-4o-mini"  # Your deployment name
    print(f"   Deployment Name: {deployment_name}")
    print("   Sending test request...")
    
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say 'Azure OpenAI is working!' in one sentence."}
            ],
            max_tokens=50,
            temperature=0.3
        )
        
        result = response.choices[0].message.content
        print(f"   ✓ API call successful!")
        print(f"   Response: {result}")
        
    except Exception as e:
        print(f"   ❌ API call failed: {e}")
        print(f"   Error type: {type(e).__name__}")
        
        # Provide specific troubleshooting
        error_str = str(e)
        if "401" in error_str or "Unauthorized" in error_str:
            print("\n   TROUBLESHOOTING:")
            print("   → Check your API key is correct")
            print("   → Verify the key is from Azure OpenAI (not regular OpenAI)")
            print("   → Check your Azure subscription is active")
        elif "404" in error_str or "DeploymentNotFound" in error_str:
            print("\n   TROUBLESHOOTING:")
            print("   → Your deployment name might be wrong")
            print("   → Check Azure Portal → Your OpenAI Resource → Deployments")
            print("   → Update deployment_name in this script and in inference/llm_enrichment.py")
        elif "ResourceNotFound" in error_str:
            print("\n   TROUBLESHOOTING:")
            print("   → Check your endpoint URL is correct")
            print("   → Verify the resource exists in Azure Portal")
        else:
            print("\n   TROUBLESHOOTING:")
            print("   → Check Azure Portal for service status")
            print("   → Verify your subscription has access to the resource")
        
        return
    
    # Step 5: Summary
    print("\n" + "=" * 70)
    print("✓ Azure OpenAI Configuration: WORKING")
    print("\nYour Azure OpenAI is configured correctly!")
    print("\nNext steps:")
    print("  1. Run: python app.py")
    print("  2. Upload a log file for detection")
    print("  3. Check dashboard for LLM insights in blue section")
    print("=" * 70)

if __name__ == '__main__':
    test_azure_openai()
