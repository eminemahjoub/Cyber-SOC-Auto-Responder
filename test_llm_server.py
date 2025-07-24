#!/usr/bin/env python3
"""
Test script to check if local LLM server is running and accessible.
"""

import requests
import json
import sys

def test_llm_server():
    """Test if the local LLM server is running and responding."""
    url = "http://localhost:5000/api/v1/generate"
    headers = {"Content-Type": "application/json"}
    payload = {
        "prompt": "What is the capital of France?",
        "max_new_tokens": 50,
        "temperature": 0.1
    }
    
    print("🔍 Testing LLM server connection...")
    print(f"URL: {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    print("-" * 50)
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        
        print("✅ SUCCESS: LLM server is running!")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        # Try to parse the response
        data = response.json()
        if "results" in data:
            text = data.get("results", [{}])[0].get("text", "")
            print(f"Extracted Text: {text}")
        
        return True
        
    except requests.ConnectionError:
        print("❌ CONNECTION ERROR: LLM server is not running or not accessible")
        print("\n📝 To start your LLM server:")
        print("1. If using text-generation-webui:")
        print("   python server.py --model mistral-7b-instruct --listen --port 5000")
        print("2. If using LM Studio:")
        print("   - Open LM Studio")
        print("   - Load Mistral 7B model")
        print("   - Enable API on port 5000")
        print("3. If using Ollama:")
        print("   ollama run mistral")
        print("   (Note: Ollama uses port 11434 by default)")
        return False
        
    except requests.RequestException as e:
        print(f"❌ REQUEST ERROR: {e}")
        return False
        
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")
        return False

def test_alternative_endpoints():
    """Test alternative LLM server endpoints."""
    alternative_urls = [
        "http://localhost:5000/v1/completions",  # LM Studio format
        "http://localhost:11434/api/generate",   # Ollama format
        "http://localhost:8080/api/v1/generate", # Alternative port
    ]
    
    print("\n🔍 Testing alternative endpoints...")
    
    for url in alternative_urls:
        print(f"\nTrying: {url}")
        try:
            response = requests.get(url, timeout=5)
            print(f"✅ {url} is accessible (Status: {response.status_code})")
        except requests.ConnectionError:
            print(f"❌ {url} is not accessible")
        except Exception as e:
            print(f"⚠️ {url} error: {e}")

if __name__ == "__main__":
    print("🚀 Local LLM Server Test")
    print("=" * 50)
    
    success = test_llm_server()
    
    if not success:
        test_alternative_endpoints()
        print("\n💡 Tips:")
        print("- Make sure your LLM server is running")
        print("- Check the port number (default is 5000)")
        print("- Verify the endpoint URL format")
        print("- Check firewall settings")
    
    sys.exit(0 if success else 1) 