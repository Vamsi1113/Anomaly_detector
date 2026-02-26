"""
Quick test script to verify LLM integration setup
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_llm_setup():
    """Test LLM configuration"""
    print("=" * 60)
    print("LLM Integration Setup Test")
    print("=" * 60)
    
    # Check environment variables
    enable_llm = os.getenv('ENABLE_LLM', 'false').lower() == 'true'
    api_key = os.getenv('OPENAI_API_KEY', None)
    
    print(f"\n1. Environment Variables:")
    print(f"   ENABLE_LLM: {os.getenv('ENABLE_LLM', 'false')}")
    print(f"   OPENAI_API_KEY: {'Set' if api_key else 'Not set'}")
    
    # Check OpenAI SDK
    print(f"\n2. OpenAI SDK:")
    try:
        import openai
        print(f"   ✓ OpenAI SDK installed (version: {openai.__version__})")
    except ImportError:
        print(f"   ✗ OpenAI SDK not installed")
        print(f"   → Run: pip install openai")
    
    # Check python-dotenv
    print(f"\n3. Python-dotenv:")
    try:
        import dotenv
        print(f"   ✓ python-dotenv installed")
    except ImportError:
        print(f"   ✗ python-dotenv not installed")
        print(f"   → Run: pip install python-dotenv")
    
    # Test LLM service initialization
    print(f"\n4. LLM Service Initialization:")
    try:
        from inference.llm_enrichment import LLMEnrichmentService
        service = LLMEnrichmentService(api_key=api_key, enabled=enable_llm)
        
        if service.enabled:
            print(f"   ✓ LLM Service enabled and initialized")
            print(f"   → Ready to analyze threats")
        else:
            if not enable_llm:
                print(f"   ⚠ LLM Service disabled (ENABLE_LLM=false)")
                print(f"   → Set ENABLE_LLM=true in .env to enable")
            elif not api_key:
                print(f"   ⚠ LLM Service disabled (no API key)")
                print(f"   → Add OPENAI_API_KEY to .env file")
            else:
                print(f"   ⚠ LLM Service disabled (unknown reason)")
    except Exception as e:
        print(f"   ✗ Failed to initialize LLM service: {e}")
    
    # Summary
    print(f"\n" + "=" * 60)
    if enable_llm and api_key:
        print("✓ LLM Integration: READY")
        print("\nNext steps:")
        print("  1. Run: python app.py")
        print("  2. Upload a log file for detection")
        print("  3. Check console for LLM enrichment logs")
    else:
        print("⚠ LLM Integration: NOT CONFIGURED")
        print("\nTo enable LLM enrichment:")
        print("  1. Edit .env file")
        print("  2. Set ENABLE_LLM=true")
        print("  3. Add your OpenAI API key")
        print("  4. Run: python app.py")
    print("=" * 60)

if __name__ == '__main__':
    test_llm_setup()
