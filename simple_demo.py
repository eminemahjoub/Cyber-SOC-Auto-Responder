#!/usr/bin/env python3
"""
Cyber-SOC Auto-Responder Simple Demo

A simplified demonstration of the core functionality without external dependencies.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class SimpleDemo:
    """Simplified demo that showcases the core logic without external dependencies."""
    
    def __init__(self):
        self.processed_alerts = 0
        self.actions_taken = []
        
        # Sample alerts for demonstration
        self.demo_alerts = [
            {
                "id": "DEMO_001",
                "title": "🦠 Ransomware Detection",
                "description": "File encryption activity detected on finance workstation",
                "severity": "critical",
                "host": "FIN-WS-01",
                "user": "admin",
                "file_hash": "malicious_hash_123",
                "indicators": ["cryptolocker.exe", "encrypted_files"],
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": "DEMO_002", 
                "title": "🔍 Suspicious PowerShell Activity",
                "description": "Base64 encoded PowerShell command executed",
                "severity": "high",
                "host": "WEB-SRV-01",
                "user": "service_account",
                "process": "powershell.exe",
                "command_line": "powershell -enc <encoded_payload>",
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": "DEMO_003",
                "title": "🌐 Malicious Network Connection",
                "description": "Connection to known malicious domain detected",
                "severity": "medium", 
                "host": "HR-WS-05",
                "user": "jane.smith",
                "dest_ip": "malicious.evil.com",
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": "DEMO_004",
                "title": "🔐 Failed Authentication Attempts",
                "description": "Multiple failed login attempts from internal IP",
                "severity": "low",
                "host": "DC-01",
                "user": "admin",
                "src_ip": "192.168.1.100",
                "timestamp": datetime.now().isoformat()
            }
        ]
    
    def calculate_severity_score(self, alert: Dict[str, Any]) -> float:
        """Calculate severity score using simplified DBIR-inspired logic."""
        score = 5.0  # Base score
        
        # Severity-based scoring
        severity_map = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5
        }
        score = severity_map.get(alert.get("severity", "medium"), 5.0)
        
        # Adjust based on indicators
        indicators = alert.get("indicators", [])
        if "ransomware" in str(indicators).lower() or "cryptolocker" in str(indicators).lower():
            score += 2.0
        
        if "powershell" in alert.get("process", "").lower():
            score += 1.0
        
        if alert.get("user") == "admin":
            score += 1.5
        
        # Network-based adjustments
        if alert.get("dest_ip") and "malicious" in alert.get("dest_ip", ""):
            score += 1.0
        
        return min(score, 10.0)
    
    def determine_actions(self, alert: Dict[str, Any], severity_score: float) -> List[str]:
        """Determine appropriate response actions based on alert and severity."""
        actions = []
        
        # Always perform basic triage
        actions.append("Alert triaged and analyzed")
        
        # Severity-based actions
        if severity_score >= 8.5:
            actions.extend([
                "🚨 CRITICAL: Incident response team notified",
                "🔒 Host isolation initiated immediately", 
                "📋 Emergency case created in TheHive",
                "📧 Executive leadership notified"
            ])
        elif severity_score >= 7.0:
            actions.extend([
                "⚠️  HIGH: Security analyst assigned",
                "🔒 Host isolation scheduled",
                "📋 Priority case created",
                "🔍 Enhanced monitoring enabled"
            ])
        elif severity_score >= 5.0:
            actions.extend([
                "📋 Standard case created",
                "🔍 Investigation queued",
                "📊 Threat hunting initiated"
            ])
        else:
            actions.append("📝 Alert logged for review")
        
        # Content-specific actions
        if "ransomware" in alert.get("title", "").lower():
            actions.append("🦠 Malware signature updated")
            actions.append("💾 File quarantine initiated")
        
        if "powershell" in alert.get("process", "").lower():
            actions.append("🔍 PowerShell execution analysis")
        
        if alert.get("dest_ip"):
            actions.append("🚫 Malicious IP blocked at firewall")
        
        return actions
    
    async def process_alert(self, alert: Dict[str, Any], alert_num: int) -> None:
        """Process a single alert through the complete workflow."""
        logger.info("=" * 80)
        logger.info(f"📨 PROCESSING ALERT #{alert_num}: {alert['title']}")
        logger.info(f"   Alert ID: {alert['id']}")
        logger.info(f"   Host: {alert.get('host', 'Unknown')}")
        logger.info(f"   User: {alert.get('user', 'Unknown')}")
        logger.info(f"   Time: {alert['timestamp']}")
        
        # Step 1: Severity Analysis
        logger.info("🔍 STEP 1: Analyzing threat severity...")
        await asyncio.sleep(0.5)  # Simulate processing time
        
        severity_score = self.calculate_severity_score(alert)
        severity_level = self.get_severity_level(severity_score)
        
        logger.info(f"   📊 Severity Score: {severity_score:.1f}/10.0")
        logger.info(f"   📈 Severity Level: {severity_level.upper()}")
        logger.info(f"   🎯 DBIR Pattern: {self.identify_pattern(alert)}")
        
        # Step 2: IOC Analysis 
        logger.info("🔎 STEP 2: Scanning for indicators of compromise...")
        await asyncio.sleep(0.3)
        
        ioc_count = len(alert.get("indicators", []))
        logger.info(f"   🚨 IOCs Detected: {ioc_count}")
        
        if alert.get("file_hash"):
            logger.info("   🦠 File hash analysis: MALICIOUS DETECTED")
        
        # Step 3: Response Actions
        logger.info("⚡ STEP 3: Executing automated response actions...")
        await asyncio.sleep(0.5)
        
        actions = self.determine_actions(alert, severity_score)
        for i, action in enumerate(actions, 1):
            logger.info(f"   {i}. {action}")
            await asyncio.sleep(0.2)  # Simulate action execution time
        
        # Step 4: Case Management
        if severity_score >= 5.0:
            logger.info("📋 STEP 4: Creating incident case...")
            await asyncio.sleep(0.3)
            case_id = f"CASE-2024-{self.processed_alerts + 1:04d}"
            logger.info(f"   ✅ Case created: {case_id}")
            logger.info(f"   🔗 Case URL: https://thehive.company.com/case/{case_id}")
        
        # Track metrics
        self.processed_alerts += 1
        self.actions_taken.extend(actions)
        
        logger.info(f"✅ ALERT PROCESSING COMPLETE")
        logger.info("")
    
    def get_severity_level(self, score: float) -> str:
        """Convert numeric score to severity level."""
        if score >= 8.5:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 5.0:
            return "medium"
        else:
            return "low"
    
    def identify_pattern(self, alert: Dict[str, Any]) -> str:
        """Identify DBIR incident pattern."""
        title_lower = alert.get("title", "").lower()
        
        if "ransomware" in title_lower or "malware" in title_lower:
            return "System Intrusion (Malware)"
        elif "powershell" in title_lower or "script" in title_lower:
            return "System Intrusion (Command & Control)"
        elif "network" in title_lower or "connection" in title_lower:
            return "System Intrusion (Network)"
        elif "auth" in title_lower or "login" in title_lower:
            return "Credential Compromise"
        else:
            return "Everything Else"
    
    async def display_summary(self):
        """Display demo summary statistics."""
        logger.info("🎯" * 30)
        logger.info("📊 CYBER-SOC AUTO-RESPONDER DEMO SUMMARY")
        logger.info("🎯" * 30)
        logger.info(f"✅ Total Alerts Processed: {self.processed_alerts}")
        logger.info(f"⚡ Total Actions Executed: {len(self.actions_taken)}")
        logger.info(f"🔒 Critical Alerts (Auto-Isolated): {sum(1 for alert in self.demo_alerts if self.calculate_severity_score(alert) >= 8.5)}")
        logger.info(f"📋 Cases Created: {sum(1 for alert in self.demo_alerts if self.calculate_severity_score(alert) >= 5.0)}")
        logger.info("")
        logger.info("🎉 DEMONSTRATION COMPLETE!")
        logger.info("")
        logger.info("💡 This demo showcased how the Cyber-SOC Auto-Responder:")
        logger.info("   • Automatically triages security alerts using DBIR patterns")
        logger.info("   • Calculates threat severity scores intelligently")
        logger.info("   • Executes appropriate response actions based on severity")
        logger.info("   • Creates incident cases for investigation tracking")
        logger.info("   • Significantly reduces Mean Time to Response (MTTR)")
        logger.info("")
        logger.info("🚀 Ready for production deployment with your SIEM/EDR/SOAR integrations!")
    
    async def run_demo(self):
        """Run the complete demonstration."""
        logger.info("🚀 CYBER-SOC AUTO-RESPONDER - LIVE DEMONSTRATION")
        logger.info("⚡ Automated Security Orchestration, Response & Triage")
        logger.info("")
        logger.info("🎯 This demo processes 4 realistic security alerts:")
        logger.info("   1. Critical ransomware detection")
        logger.info("   2. High-severity PowerShell abuse")
        logger.info("   3. Medium-severity malicious network traffic")
        logger.info("   4. Low-severity authentication failures")
        logger.info("")
        logger.info("⏱️  Processing alerts in real-time simulation...")
        logger.info("")
        
        # Process each demo alert
        for i, alert in enumerate(self.demo_alerts, 1):
            await self.process_alert(alert, i)
            await asyncio.sleep(1)  # Pause between alerts
        
        # Show summary
        await self.display_summary()

async def main():
    """Main demo entry point."""
    try:
        demo = SimpleDemo()
        await demo.run_demo()
    except KeyboardInterrupt:
        logger.info("🛑 Demo interrupted by user")
    except Exception as e:
        logger.error(f"❌ Demo failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main()) 