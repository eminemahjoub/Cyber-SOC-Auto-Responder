#!/usr/bin/env python3
"""
Open-Source Cyber-SOC Auto-Responder - Demo
Shows the capabilities of the pure open-source security stack.
"""

import asyncio
import random
from datetime import datetime

class OpenSourceSOCDemo:
    """Demo of open-source SOC capabilities."""
    
    def __init__(self):
        self.stats = {
            "wazuh_alerts": 0,
            "openvas_scans": 0,
            "thehive_cases": 0,
            "high_priority_responses": 0
        }
    
    async def run_demo(self):
        """Run the open-source SOC demo."""
        print("🌟 Open-Source Cyber-SOC Auto-Responder - Live Demo")
        print("=" * 60)
        print("🔧 100% Open-Source Stack:")
        print("   🔍 Wazuh SIEM/XDR")
        print("   🔎 OpenVAS Vulnerability Scanner") 
        print("   📋 TheHive SOAR Platform")
        print()
        
        # Demo the open-source workflow
        await self._demo_wazuh_alerting()
        await self._demo_threat_analysis()
        await self._demo_openvas_scanning()
        await self._demo_thehive_response()
        await self._demo_automated_workflow()
        
        # Summary
        print("📊 OPEN-SOURCE SOC DEMO RESULTS:")
        print("=" * 45)
        print(f"🔍 Wazuh Alerts Processed: {self.stats['wazuh_alerts']}")
        print(f"🔎 OpenVAS Scans Performed: {self.stats['openvas_scans']}")
        print(f"📋 TheHive Cases Created: {self.stats['thehive_cases']}")
        print(f"🚨 High Priority Responses: {self.stats['high_priority_responses']}")
        print()
        print("🎉 OPEN-SOURCE SOC CAPABILITIES DEMONSTRATED!")
        print("✅ 100% Free & Open-Source Security Automation!")
        print("💰 $0 licensing costs - Enterprise-grade security for everyone!")
    
    async def _demo_wazuh_alerting(self):
        """Demo Wazuh SIEM capabilities."""
        print("🔍 WAZUH SIEM - ALERT COLLECTION & ANALYSIS")
        print("-" * 50)
        
        wazuh_alerts = [
            ("SSH Brute Force Attack", 12, "Critical"),
            ("File Integrity Violation", 10, "High"),
            ("Web Attack Detected", 9, "High"),
            ("Suspicious Process Execution", 8, "Medium-High")
        ]
        
        for alert_name, rule_level, severity in wazuh_alerts:
            await asyncio.sleep(0.4)
            print(f"📨 Rule {rule_level}: {alert_name} ({severity})")
            self.stats["wazuh_alerts"] += 1
        
        print(f"✅ {len(wazuh_alerts)} alerts collected from Wazuh SIEM")
        print("🎯 Wazuh Features: Agent-based monitoring, Log analysis, File integrity")
        print()
    
    async def _demo_threat_analysis(self):
        """Demo threat analysis capabilities."""
        print("🧠 OPEN-SOURCE THREAT ANALYSIS")
        print("-" * 40)
        
        analysis_steps = [
            "🔍 Wazuh rule-level severity mapping",
            "📊 Multi-factor scoring algorithm",
            "🎯 DBIR pattern classification",
            "🚨 Risk assessment calculation"
        ]
        
        for step in analysis_steps:
            await asyncio.sleep(0.3)
            print(f"   {step}")
        
        threat_score = random.uniform(7.8, 9.5)
        print(f"📊 Open-Source Threat Score: {threat_score:.1f}/10 (HIGH RISK)")
        print("💡 Analysis: Multi-stage attack with privilege escalation")
        print()
    
    async def _demo_openvas_scanning(self):
        """Demo OpenVAS vulnerability scanning."""
        print("🔎 OPENVAS - VULNERABILITY ASSESSMENT")
        print("-" * 45)
        
        target_hosts = ["192.168.1.150", "192.168.1.151"]
        
        for host in target_hosts:
            print(f"🎯 Initiating OpenVAS scan for {host}")
            await asyncio.sleep(0.8)
            
            print(f"   🔍 Creating scan target...")
            await asyncio.sleep(0.3)
            print(f"   📋 Configuring scan profile (Full and fast)...")
            await asyncio.sleep(0.3)
            print(f"   🚀 Starting vulnerability assessment...")
            await asyncio.sleep(0.5)
            
            scan_id = f"OV_{int(datetime.now().timestamp()) + random.randint(1, 100)}"
            print(f"   ✅ Scan initiated: {scan_id}")
            
            # Simulate vulnerability results
            vulns = [
                ("CVE-2023-1234", "9.8", "Remote Code Execution"),
                ("CVE-2023-5678", "7.5", "SQL Injection"),
                ("CVE-2023-9012", "6.1", "Cross-Site Scripting")
            ]
            
            print(f"   📋 Vulnerabilities found:")
            for cve, score, desc in vulns:
                severity_icon = "🚨" if float(score) >= 9.0 else "⚠️" if float(score) >= 7.0 else "💡"
                print(f"      {severity_icon} {cve} (CVSS: {score}) - {desc}")
            
            self.stats["openvas_scans"] += 1
        
        print("🎯 OpenVAS Features: CVE detection, CVSS scoring, Comprehensive scanning")
        print()
    
    async def _demo_thehive_response(self):
        """Demo TheHive SOAR capabilities."""
        print("📋 THEHIVE - SECURITY ORCHESTRATION & RESPONSE")
        print("-" * 50)
        
        case_actions = [
            ("📋 Creating incident case", "CASE-OS-001"),
            ("🔍 Adding observables (IPs, domains, hashes)", "5 observables"),
            ("📊 Assigning severity and TLP marking", "TLP:AMBER"),
            ("👥 Notifying security team", "SOC analysts"),
            ("📈 Creating investigation tasks", "4 tasks"),
            ("🔗 Linking related alerts", "3 related alerts")
        ]
        
        for action, detail in case_actions:
            await asyncio.sleep(0.5)
            print(f"   {action}: {detail}")
        
        case_id = "CASE-OS-001"
        print(f"✅ TheHive case created: {case_id}")
        print(f"🔗 Case URL: http://localhost:9000/index.html#!/case/{case_id}")
        
        self.stats["thehive_cases"] += 1
        print("🎯 TheHive Features: Case management, Observables, Task tracking")
        print()
    
    async def _demo_automated_workflow(self):
        """Demo complete automated workflow."""
        print("⚡ AUTOMATED OPEN-SOURCE WORKFLOW")
        print("-" * 45)
        
        workflow_steps = [
            ("🔍 Wazuh detects SSH brute force (Rule 5712)", True),
            ("🧠 AI analysis calculates severity: 8.5/10", True),
            ("🔎 OpenVAS scans affected host for vulnerabilities", True),
            ("📊 Critical CVE found - severity adjusted to 9.2/10", True),
            ("🚨 High priority response triggered", True),
            ("📋 TheHive case auto-created with all evidence", True),
            ("👥 SOC team notified via TheHive", True),
            ("📈 Investigation tasks automatically generated", True)
        ]
        
        for step, success in workflow_steps:
            await asyncio.sleep(0.6)
            status = "✅ SUCCESS" if success else "❌ FAILED"
            print(f"   {step} → {status}")
            
            if "High priority" in step and success:
                self.stats["high_priority_responses"] += 1
        
        print("🎯 End-to-end automation in under 60 seconds!")
        print("💡 Zero licensing costs - pure open-source automation!")
        print()

async def main():
    """Run the open-source SOC demo."""
    demo = OpenSourceSOCDemo()
    await demo.run_demo()

if __name__ == "__main__":
    asyncio.run(main()) 