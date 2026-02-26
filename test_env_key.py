"""
Quick test to verify .env file is loading correctly
"""
import os
from dotenv import load_dotenv

# Force reload of .env
load_dotenv(override=True)

api_key = os.getenv('OPENAI_API_KEY', None)

print("=" * 70)
print("Environment Variable Test")
print("=" * 70)

if api_key:
    print(f"\n✓ API Key Found")
    print(f"  Length: {len(api_key)} characters")
    print(f"  First 10 chars: {api_key[:10]}")
    print(f"  Last 10 chars: {api_key[-10:]}")
    
    # Check key type
    if api_key.startswith('sk-proj-') or api_key.startswith('sk-'):
        print(f"\n❌ ERROR: This is a regular OpenAI key!")
        print(f"  Regular OpenAI keys start with 'sk-' or 'sk-proj-'")
        print(f"  Azure OpenAI keys are 32-64 character random strings")
        print(f"\n  You need to get your Azure OpenAI key from:")
        print(f"  Azure Portal → Your OpenAI Resource → Keys and Endpoint → KEY 1")
    else:
        print(f"\n✓ This looks like an Azure OpenAI key!")
        print(f"  Azure keys are random alphanumeric strings")
else:
    print(f"\n❌ No API key found in environment")
    print(f"  Check your .env file")

print("=" * 70)
