#!/usr/bin/env python3
"""
Mock LLM Server for Testing
Simulates a local LLM API for development and testing.
"""

from flask import Flask, request, jsonify
import json
import random

app = Flask(__name__)

def generate_mock_response(prompt):
    """Generate a mock AI response based on the prompt."""
    if "capital of France" in prompt.lower():
        return "The capital of France is Paris."
    
    if "security" in prompt.lower() or "alert" in prompt.lower():
        # Mock security triage response
        severity = random.uniform(3.0, 9.0)
        patterns = ["system_intrusion", "social_engineering", "malware", "web_application_attacks"]
        pattern = random.choice(patterns)
        
        response = {
            "severity_score": round(severity, 1),
            "threat_pattern": pattern,
            "response_suggestion": f"Investigate {pattern} indicators and escalate if severity > 7.0"
        }
        return json.dumps(response)
    
    return "I'm a mock LLM server. Please provide a security-related prompt for analysis."

@app.route('/api/generate', methods=['POST'])
def ollama_endpoint():
    """Ollama-style endpoint."""
    data = request.json
    prompt = data.get('prompt', '')
    response_text = generate_mock_response(prompt)
    
    return jsonify({
        "model": "mistral",
        "response": response_text,
        "done": True
    })

@app.route('/api/v1/generate', methods=['POST'])
def webui_endpoint():
    """Text-generation-webui style endpoint."""
    data = request.json
    prompt = data.get('prompt', '')
    response_text = generate_mock_response(prompt)
    
    return jsonify({
        "results": [{"text": response_text}]
    })

@app.route('/v1/completions', methods=['POST'])
def openai_endpoint():
    """OpenAI-style endpoint for LM Studio."""
    data = request.json
    prompt = data.get('prompt', '')
    response_text = generate_mock_response(prompt)
    
    return jsonify({
        "choices": [{"text": response_text}]
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "message": "Mock LLM server is running"})

if __name__ == '__main__':
    print("🤖 Starting Mock LLM Server...")
    print("📍 Ollama endpoint: http://localhost:11434/api/generate")
    print("📍 WebUI endpoint: http://localhost:5000/api/v1/generate") 
    print("📍 Health check: http://localhost:11434/health")
    print("💡 This is a MOCK server for testing purposes only!")
    
    # Run on port 11434 to simulate Ollama
    app.run(host='0.0.0.0', port=11434, debug=False) 