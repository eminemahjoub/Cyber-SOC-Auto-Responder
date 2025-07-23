#!/usr/bin/env python3
"""
Activate AI Agents - Enable GPT-4 Powered Intelligence

This script activates the real AI agents instead of the simplified rule-based ones.
"""

import os
import asyncio
from typing import Dict, Any
from datetime import datetime

# Import the REAL AI agents
from agents.triage_agent import TriageAgent
from agents.scanner_agent import ScannerAgent
from config.dbir_patterns import DBIRPatterns

class AIEnabledSOCOrchestrator:
    """SOC Orchestrator with REAL AI agents enabled."""
    
    def __init__(self):
        """Initialize with AI-powered agents."""
        
        # AI Agent configurations
        agent_config = {
            "model": "gpt-4-turbo-preview",
            "temperature": 0.1,
            "max_tokens": 2000
        }
        
        # Initialize REAL AI agents
        self.triage_agent = TriageAgent(agent_config)
        self.scanner_agent = ScannerAgent(agent_config)
        self.dbir_patterns = DBIRPatterns()
        
        print("🤖 AI Agents Activated!")
        print(f"   🧠 Triage Agent: {self.triage_agent.model}")
        print(f"   🔍 Scanner Agent: {self.scanner_agent.model}")
        print("   📊 DBIR Patterns: Loaded")
    
    async def analyze_alert_with_ai(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert using REAL AI instead of simple rules."""
        
        print(f"\n🤖 AI Analysis Starting...")
        print(f"🔍 Alert: {alert.get('title', 'Unknown')}")
        
        # Step 1: AI-Powered Triage Analysis
        print("🧠 Running AI Triage Analysis...")
        ai_result = await self.triage_agent.analyze_alert(alert, self.dbir_patterns)
        
        print(f"   🎯 AI Severity Score: {ai_result.get('severity_score', 'N/A')}/10")
        print(f"   🔬 DBIR Pattern: {ai_result.get('pattern', 'N/A')}")
        print(f"   🧠 AI Confidence: {ai_result.get('confidence', 'N/A')}")
        
        return ai_result

async def demo_ai_vs_simple():
    """Demonstrate AI agents vs simple rule-based analysis."""
    
    print("🚀 Cyber-SOC AI Agent Activation Demo")
    print("=" * 60)
    
    # Sample alert for testing
    test_alert = {
        "id": "test_001",
        "title": "Suspicious PowerShell Execution",
        "description": "Encoded PowerShell command detected with potential malware payload",
        "source": "wazuh",
        "severity": "high",
        "rule_level": 12,
        "agent_name": "workstation-01",
        "user": "admin",
        "process": "powershell.exe",
        "command": "powershell.exe -enc <base64_encoded_command>",
        "indicators": ["suspicious_powershell", "base64_encoding", "admin_context"],
        "timestamp": datetime.now().isoformat()
    }
    
    # Initialize AI orchestrator
    ai_orchestrator = AIEnabledSOCOrchestrator()
    
    print(f"\n📨 Test Alert: {test_alert['title']}")
    print(f"📊 Rule Level: {test_alert['rule_level']}")
    
    # Check if OpenAI key is configured
    openai_key = os.getenv('OPENAI_API_KEY')
    
    if not openai_key:
        print("\n⚠️  OpenAI API Key Required!")
        print("🔑 Set OPENAI_API_KEY environment variable to enable AI analysis")
        print("💡 Get API key from: https://platform.openai.com/api-keys")
        return
    
    try:
        # Perform AI analysis
        ai_result = await ai_orchestrator.analyze_alert_with_ai(test_alert)
        
        print(f"\n✅ AI Analysis Complete!")
        print(f"🎯 Final Assessment: {ai_result.get('analysis_summary', 'N/A')}")
        
    except Exception as e:
        print(f"\n❌ AI Analysis Failed: {str(e)}")
        print("💡 Ensure OpenAI API key is valid and has credits")

def show_ai_agent_status():
    """Show current AI agent capabilities."""
    
    print("\n🤖 AI AGENT CAPABILITIES:")
    print("=" * 40)
    
    print("🧠 TriageAgent (GPT-4):")
    print("   • Advanced threat classification")
    print("   • DBIR pattern matching")
    print("   • Context-aware severity scoring")
    print("   • Natural language analysis")
    
    print("\n🔍 ScannerAgent (GPT-4):")
    print("   • Intelligent file analysis")
    print("   • IOC correlation")
    print("   • Malware behavior prediction")
    print("   • Risk assessment")
    
    print(f"\n📊 Current Status:")
    print(f"   ✅ AI Agents Available: agents/triage_agent.py (28KB)")
    print(f"   ✅ AI Agents Available: agents/scanner_agent.py (16KB)")
    print(f"   ❌ Currently Using: Simple rule-based analysis")
    print(f"   🔑 Requires: OPENAI_API_KEY environment variable")

if __name__ == "__main__":
    show_ai_agent_status()
    
    print(f"\n🚀 Run AI Demo:")
    print(f"python activate_ai_agents.py")
    
    # Run the demo
    asyncio.run(demo_ai_vs_simple()) 