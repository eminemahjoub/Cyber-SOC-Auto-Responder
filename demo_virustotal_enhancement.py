#!/usr/bin/env python3
"""
VirusTotal Enhancement Demo for Open-Source Cyber-SOC
Shows how VirusTotal threat intelligence enhances the open-source stack.
"""

import asyncio
import random
from datetime import datetime

class VirusTotalEnhancementDemo:
    """Demo of VirusTotal enhancement capabilities."""
    
    def __init__(self):
        self.stats = {
            "alerts_analyzed": 0,
            "iocs_scanned": 0,
            "malicious_detected": 0,
            "severity_adjustments": 0
        }
    
    async def run_demo(self):
        """Run the VirusTotal enhancement demo."""
        print("🦠 VirusTotal Enhancement Demo")
        print("=" * 50)
        print("🎯 Showing how VirusTotal enhances open-source security automation")
        print("🔧 Core: Wazuh + OpenVAS + TheHive")
        print("🚀 Enhancement: VirusTotal Threat Intelligence")
        print()
        
        # Demo scenarios
        await self._demo_baseline_alert()
        await self._demo_enhanced_alert()
        await self._demo_ioc_analysis()
        await self._demo_severity_adjustment()
        await self._demo_threat_intelligence()
        
        # Summary
        print("📊 VIRUSTOTAL ENHANCEMENT RESULTS:")
        print("=" * 40)
        print(f"🔍 Alerts Enhanced: {self.stats['alerts_analyzed']}")
        print(f"🦠 IOCs Analyzed: {self.stats['iocs_scanned']}")
        print(f"🚨 Malicious IOCs Detected: {self.stats['malicious_detected']}")
        print(f"📈 Severity Adjustments: {self.stats['severity_adjustments']}")
        print()
        print("🎉 ENHANCEMENT VALUE DEMONSTRATED!")
        print("💡 Open-source core + commercial threat intelligence = Best of both worlds!")
    
    async def _demo_baseline_alert(self):
        """Demo baseline open-source processing."""
        print("📋 BASELINE: Open-Source Only Processing")
        print("-" * 45)
        
        print("🔍 Wazuh detects suspicious file execution")
        print("   📄 File: malware.exe")
        print("   🎯 Rule Level: 10 (High)")
        print("   📊 Base Severity: 7.2/10")
        
        await asyncio.sleep(0.5)
        print("🔎 OpenVAS scans host for vulnerabilities")
        print("   ✅ 3 vulnerabilities found")
        
        await asyncio.sleep(0.5)
        print("📋 TheHive case created")
        print("   🎫 Case ID: CASE-BASELINE-001")
        
        print("💡 Result: Good detection, but limited threat context")
        print()
    
    async def _demo_enhanced_alert(self):
        """Demo enhanced processing with VirusTotal."""
        print("🦠 ENHANCED: With VirusTotal Intelligence")
        print("-" * 45)
        
        print("🔍 Wazuh detects suspicious file execution")
        print("   📄 File: malware.exe")
        print("   🎯 Rule Level: 10 (High)")
        print("   📊 Base Severity: 7.2/10")
        
        await asyncio.sleep(0.5)
        print("🦠 VirusTotal analyzes file hash...")
        await asyncio.sleep(1)
        print("   🚨 MALICIOUS: 45/70 engines detect malware")
        print("   📝 Threat Names: Win32.Trojan.Agent, Malware.Generic")
        print("   📈 Severity adjusted: 7.2 → 9.1/10 (+VirusTotal)")
        
        self.stats["alerts_analyzed"] += 1
        self.stats["severity_adjustments"] += 1
        
        await asyncio.sleep(0.5)
        print("🔎 OpenVAS scans host for vulnerabilities")
        print("   ✅ 3 vulnerabilities found")
        
        await asyncio.sleep(0.5)
        print("📋 TheHive case created with enhanced context")
        print("   🎫 Case ID: CASE-ENHANCED-001")
        print("   🦠 IOC Analysis: MALICIOUS file confirmed")
        print("   📊 Threat Intelligence: Global detection data")
        
        print("🎯 Result: Enhanced detection with global threat intelligence!")
        print()
    
    async def _demo_ioc_analysis(self):
        """Demo comprehensive IOC analysis."""
        print("🔍 IOC ANALYSIS WITH VIRUSTOTAL")
        print("-" * 40)
        
        iocs = [
            ("IP Address", "185.220.101.32", "Malicious", "C&C Server"),
            ("Domain", "malware-host.com", "Malicious", "Phishing"),
            ("File Hash", "a4b7c9d2e1f8...", "Clean", "Legitimate"),
            ("URL", "http://phish.evil.com", "Suspicious", "Phishing Kit")
        ]
        
        malicious_count = 0
        
        for ioc_type, ioc_value, result, category in iocs:
            await asyncio.sleep(0.4)
            
            if result == "Malicious":
                icon = "🚨"
                malicious_count += 1
            elif result == "Suspicious":
                icon = "⚠️"
            else:
                icon = "✅"
            
            print(f"   {icon} {ioc_type}: {ioc_value}")
            print(f"      → VirusTotal: {result} ({category})")
            self.stats["iocs_scanned"] += 1
        
        self.stats["malicious_detected"] = malicious_count
        
        print(f"📊 Analysis Complete: {malicious_count} malicious IOCs confirmed")
        print("💡 Enhanced context enables better decision making")
        print()
    
    async def _demo_severity_adjustment(self):
        """Demo intelligent severity adjustment."""
        print("📈 INTELLIGENT SEVERITY ADJUSTMENT")
        print("-" * 40)
        
        scenarios = [
            ("Clean IOCs", 6.5, 0, 6.5, "No adjustment needed"),
            ("1 Malicious IOC", 6.0, 1, 6.5, "Slight increase"),
            ("3 Malicious IOCs", 7.0, 3, 8.5, "Significant increase"),
            ("5 Malicious IOCs", 6.8, 5, 9.3, "Critical escalation")
        ]
        
        for scenario, base_score, malicious_iocs, adjusted_score, description in scenarios:
            await asyncio.sleep(0.5)
            
            adjustment = adjusted_score - base_score
            arrow = "📈" if adjustment > 0 else "➡️"
            
            print(f"   📊 {scenario}:")
            print(f"      Base Severity: {base_score}/10")
            print(f"      Malicious IOCs: {malicious_iocs}")
            print(f"      {arrow} Adjusted: {adjusted_score}/10 ({description})")
        
        print("🎯 Smart scoring prevents false positives and catches real threats")
        print()
    
    async def _demo_threat_intelligence(self):
        """Demo threat intelligence context."""
        print("🧠 THREAT INTELLIGENCE CONTEXT")
        print("-" * 40)
        
        print("🦠 VirusTotal provides rich threat context:")
        await asyncio.sleep(0.3)
        
        intelligence_data = [
            "🌍 Global detection: 45/70 security vendors",
            "📅 First seen: 2024-01-15 (recent campaign)",
            "🏷️  Malware families: Trojan.Agent, Backdoor.Generic",
            "🎯 Attack vectors: Email attachment, Drive-by download",
            "🔗 Related IOCs: 15 associated domains",
            "📊 Prevalence: High (1000+ submissions)",
            "🚨 Threat level: Critical infrastructure target"
        ]
        
        for intel in intelligence_data:
            await asyncio.sleep(0.4)
            print(f"   {intel}")
        
        print()
        print("💡 This intelligence transforms alert handling:")
        print("   • Faster triage decisions")
        print("   • Better threat attribution")
        print("   • Improved incident response")
        print("   • Enhanced threat hunting")
        print()

async def main():
    """Run the VirusTotal enhancement demo."""
    demo = VirusTotalEnhancementDemo()
    await demo.run_demo()

if __name__ == "__main__":
    asyncio.run(main()) 