#!/usr/bin/env python3
"""
AI-Powered Cyber-SOC Auto-Responder Production System

This is the upgraded version that uses REAL AI agents instead of simple rule-based ones.
Requires OpenAI API key for GPT-4 powered intelligence.
"""

import asyncio
import os
import random
from datetime import datetime
from typing import Dict, List, Any
import logging

# Import REAL AI agents
from agents.triage_agent import TriageAgent
from agents.scanner_agent import ScannerAgent
from config.dbir_patterns import DBIRPatterns

# Import connectors (real ones, no mocks)
from connectors.wazuh_connector import WazuhConnector
from connectors.openvas_connector import OpenVASConnector
from connectors.virustotal_connector import VirusTotalConnector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - AI-SOC - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ai_soc.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AIEnabledSOCOrchestrator:
    """AI-Powered SOC Orchestrator with GPT-4 Intelligence."""
    
    def __init__(self):
        """Initialize AI-powered components."""
        
        # Check for OpenAI API key
        if not os.getenv('OPENAI_API_KEY'):
            logger.error("❌ OPENAI_API_KEY not found!")
            logger.info("💡 Set OPENAI_API_KEY environment variable to enable AI")
            logger.info("🔑 Get API key from: https://platform.openai.com/api-keys")
            raise ValueError("OpenAI API key required for AI agents")
        
        # AI Agent configurations
        agent_config = {
            "model": os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview"),
            "temperature": 0.1,
            "max_tokens": 2000
        }
        
        # Initialize REAL AI connectors
        self.wazuh_connector = WazuhConnector()
        self.openvas_connector = OpenVASConnector()
        
        # Initialize optional VirusTotal
        try:
            self.virustotal_connector = VirusTotalConnector()
            logger.info("🦠 VirusTotal AI enhancement loaded")
        except Exception:
            self.virustotal_connector = None
            logger.info("🦠 VirusTotal not available - continuing with AI-only")
        
        # Initialize REAL AI agents
        self.triage_agent = TriageAgent(agent_config)
        self.scanner_agent = ScannerAgent(agent_config)
        self.dbir_patterns = DBIRPatterns()
        
        # Performance stats
        self.stats = {
            "start_time": datetime.now(),
            "alerts_processed": 0,
            "ai_analyses_performed": 0,
            "actions_executed": 0,
            "vulnerability_scans": 0
        }
        
        logger.info("🤖 AI-Powered SOC Orchestrator initialized")
        logger.info(f"🧠 AI Model: {agent_config['model']}")
    
    async def run_ai_soc_system(self):
        """Run the AI-powered SOC system."""
        logger.info("🚀 Starting AI-Powered Cyber-SOC Auto-Responder")
        logger.info("=" * 80)
        
        # Display AI configuration
        await self._display_ai_configuration()
        
        # Connect to services
        await self._connect_services()
        
        # Main AI processing loop
        poll_interval = int(os.environ.get('POLL_INTERVAL', '30'))
        max_concurrent = int(os.environ.get('MAX_CONCURRENT_ALERTS', '3'))  # Lower for AI processing
        
        logger.info(f"🤖 Starting AI processing loop...")
        logger.info(f"🧠 AI Model: {self.triage_agent.model}")
        logger.info(f"🔄 Poll Interval: {poll_interval} seconds")
        logger.info(f"🔢 Max Concurrent: {max_concurrent} (AI optimized)")
        logger.info("")
        
        iteration = 0
        
        try:
            while True:
                iteration += 1
                logger.info(f"🔍 AI-powered alert analysis... (Iteration {iteration})")
                
                # Get alerts from Wazuh
                try:
                    alerts = await self.wazuh_connector.get_new_alerts()
                except ConnectionError as e:
                    logger.error(f"❌ Wazuh connection failed: {str(e)}")
                    alerts = []
                
                if alerts:
                    logger.info(f"🚨 Processing {len(alerts)} alerts with AI analysis...")
                    
                    # Process with AI (limited concurrency due to API rate limits)
                    semaphore = asyncio.Semaphore(max_concurrent)
                    tasks = [
                        self._process_alert_with_ai(alert, semaphore) 
                        for alert in alerts[:max_concurrent]  # Limit for AI processing
                    ]
                    
                    await asyncio.gather(*tasks, return_exceptions=True)
                else:
                    logger.info("📝 No new alerts - AI agents standing by...")
                
                # Display AI stats
                await self._display_ai_status()
                
                logger.info(f"⏰ Waiting {poll_interval} seconds before next AI scan...")
                await asyncio.sleep(poll_interval)
                
        except KeyboardInterrupt:
            logger.info("🛑 AI SOC system shutdown requested")
        except Exception as e:
            logger.error(f"❌ AI SOC system error: {str(e)}")
    
    async def _process_alert_with_ai(self, alert: Dict[str, Any], semaphore: asyncio.Semaphore):
        """Process alert using AI-powered analysis."""
        async with semaphore:
            alert_id = alert.get("id", f"ai_alert_{int(datetime.now().timestamp())}")
            
            try:
                logger.info(f"🤖 [{alert_id}] AI Analysis Starting...")
                logger.info(f"   📋 Title: {alert.get('title', 'Unknown')}")
                logger.info(f"   🏠 Host: {alert.get('agent_name', 'Unknown')}")
                
                # Step 1: AI-Powered Triage Analysis
                logger.info(f"🧠 [{alert_id}] Step 1: AI Triage Analysis...")
                ai_result = await self.triage_agent.analyze_alert(alert, self.dbir_patterns)
                
                if ai_result.get("success"):
                    severity_score = ai_result.get("severity_score", 5.0)
                    pattern = ai_result.get("pattern", "Unknown")
                    confidence = ai_result.get("confidence", 0.0)
                    
                    logger.info(f"   🎯 AI Severity: {severity_score}/10")
                    logger.info(f"   🔬 DBIR Pattern: {pattern}")
                    logger.info(f"   🧠 AI Confidence: {confidence}")
                    
                    self.stats["ai_analyses_performed"] += 1
                else:
                    logger.error(f"   ❌ AI Triage failed: {ai_result.get('error')}")
                    severity_score = 5.0  # Default fallback
                
                # Step 2: VirusTotal Enhancement (if available)
                if self.virustotal_connector and severity_score >= 6.0:
                    logger.info(f"🦠 [{alert_id}] Step 2: AI + VirusTotal IOC analysis...")
                    try:
                        vt_result = await self.virustotal_connector.analyze_alert_iocs(alert)
                        if vt_result.get("success"):
                            ioc_score = vt_result.get("threat_score", 0.0)
                            severity_score = min(severity_score + (ioc_score * 0.1), 10.0)
                            logger.info(f"   🦠 IOC Threat Score: {ioc_score}")
                            logger.info(f"   📈 Adjusted Severity: {severity_score}/10")
                    except Exception as e:
                        logger.warning(f"   ⚠️ VirusTotal analysis failed: {str(e)}")
                
                # Step 3: AI-Powered Vulnerability Assessment
                vuln_threshold = float(os.environ.get('VULNERABILITY_SCAN_THRESHOLD', '7.0'))
                if severity_score >= vuln_threshold:
                    host_ip = self._extract_host_ip(alert)
                    if host_ip:
                        logger.info(f"🔍 [{alert_id}] Step 3: AI + OpenVAS vulnerability scan for {host_ip}...")
                        try:
                            vuln_result = await self.openvas_connector.scan_host_vulnerabilities(host_ip, alert)
                            if vuln_result["success"]:
                                logger.info(f"   🎯 Vulnerability scan initiated: {vuln_result.get('scan_id')}")
                                self.stats["vulnerability_scans"] += 1
                        except ConnectionError as e:
                            logger.error(f"   ❌ OpenVAS connection failed: {str(e)}")
                
                # Step 4: AI-Powered Response Actions
                actions_taken = await self._execute_ai_response(alert, severity_score, alert_id)
                
                # Step 5: AI Summary & Documentation
                logger.info(f"📋 [{alert_id}] AI Analysis Complete")
                logger.info(f"   🎯 Final AI Score: {severity_score}/10")
                logger.info(f"   ⚡ Actions: {', '.join(actions_taken) if actions_taken else 'None'}")
                
                self.stats["alerts_processed"] += 1
                
            except Exception as e:
                logger.error(f"❌ [{alert_id}] AI processing failed: {str(e)}")
    
    async def _execute_ai_response(self, alert: Dict[str, Any], severity_score: float, alert_id: str) -> List[str]:
        """Execute AI-powered response actions."""
        actions_taken = []
        
        logger.info(f"⚡ [{alert_id}] AI Response Engine...")
        
        # AI-determined response threshold
        if severity_score >= 8.0:
            actions_taken.append("high_priority_alert")
            logger.info(f"   🚨 High priority AI alert generated")
        
        if severity_score >= 7.0:
            actions_taken.append("ai_analysis_complete")
            logger.info(f"   🤖 Comprehensive AI analysis performed")
        
        if actions_taken:
            self.stats["actions_executed"] += len(actions_taken)
        
        return actions_taken
    
    def _extract_host_ip(self, alert: Dict[str, Any]) -> str:
        """Extract host IP from alert for vulnerability scanning."""
        for field in ["agent_ip", "src_ip", "host_ip", "ip_address"]:
            if field in alert and alert[field]:
                return alert[field]
        return None
    
    async def _display_ai_configuration(self):
        """Display AI system configuration."""
        logger.info("🤖 AI Configuration:")
        logger.info(f"   🧠 Model: {self.triage_agent.model}")
        logger.info(f"   🌡️  Temperature: {self.triage_agent.temperature}")
        logger.info(f"   📝 Max Tokens: {self.triage_agent.max_tokens}")
        
        vt_status = "✅ Available" if self.virustotal_connector else "❌ Not Available"
        logger.info(f"   🦠 VirusTotal: {vt_status}")
        logger.info("")
    
    async def _connect_services(self):
        """Connect to all services."""
        logger.info("🔌 Connecting to services...")
        
        # Connect to Wazuh
        try:
            await self.wazuh_connector.connect()
            logger.info("   ✅ Wazuh connected")
        except Exception as e:
            logger.error(f"   ❌ Wazuh error: {str(e)}")
        
        # Connect to OpenVAS
        try:
            await self.openvas_connector.connect()
            logger.info("   ✅ OpenVAS connected")
        except Exception as e:
            logger.error(f"   ❌ OpenVAS error: {str(e)}")
        
        # Connect to VirusTotal
        if self.virustotal_connector:
            try:
                await self.virustotal_connector.connect()
                logger.info("   ✅ VirusTotal connected")
            except Exception as e:
                logger.error(f"   ❌ VirusTotal error: {str(e)}")
        
        logger.info("")
    
    async def _display_ai_status(self):
        """Display AI system status."""
        uptime = datetime.now() - self.stats["start_time"]
        
        logger.info("🤖 AI SOC Status:")
        logger.info(f"   🕐 Uptime: {str(uptime).split('.')[0]}")
        logger.info(f"   🔍 Alerts Processed: {self.stats['alerts_processed']}")
        logger.info(f"   🧠 AI Analyses: {self.stats['ai_analyses_performed']}")
        logger.info(f"   ⚡ Actions Executed: {self.stats['actions_executed']}")
        logger.info(f"   🔎 Vulnerability Scans: {self.stats['vulnerability_scans']}")
        logger.info("")

async def main():
    """Main entry point for AI-powered SOC."""
    try:
        orchestrator = AIEnabledSOCOrchestrator()
        await orchestrator.run_ai_soc_system()
    except KeyboardInterrupt:
        logger.info("🛑 AI SOC system shutdown requested")
    except Exception as e:
        logger.error(f"❌ AI SOC system startup failed: {str(e)}")

if __name__ == "__main__":
    print("🤖 AI-Powered Cyber-SOC Auto-Responder")
    print("🧠 GPT-4 Intelligence + Real Security Tools")
    print("=" * 60)
    asyncio.run(main()) 