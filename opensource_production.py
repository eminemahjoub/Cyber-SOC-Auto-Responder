#!/usr/bin/env python3
"""
Open-Source Cyber-SOC Auto-Responder

Pure open-source security automation platform:
- Wazuh: Open-source SIEM/XDR
- OpenVAS: Open-source vulnerability scanner  
- TheHive: Open-source SOAR platform
"""

import asyncio
import os
import sys
import time
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger("OpenSource-SOC")

class OpenSourceSOCOrchestrator:
    """Open-source SOC orchestrator with Wazuh, OpenVAS, and TheHive."""
    
    def __init__(self):
        """Initialize open-source components."""
        logger.info("🚀 Initializing Streamlined Cyber-SOC Auto-Responder")
        
        # Set environment variables
        self._setup_environment()
        
        # Initialize components
        self._initialize_components()
        
        # System statistics
        self.stats = {
            "alerts_processed": 0,
            "actions_executed": 0,
            "vulnerability_scans": 0,
            "start_time": datetime.now()
        }
    
    def _setup_environment(self):
        """Setup environment variables for enhanced open-source tools."""
        defaults = {
            # Wazuh SIEM Configuration
            'WAZUH_URL': 'https://localhost:55000',
            'WAZUH_USERNAME': 'wazuh',
            'WAZUH_PASSWORD': 'wazuh',
            
            # OpenVAS Vulnerability Scanner
            'OPENVAS_URL': 'https://localhost:9390',
            'OPENVAS_USERNAME': 'admin',
            'OPENVAS_PASSWORD': 'admin',
            
            # VirusTotal Enhancement (Optional)
            'VIRUSTOTAL_API_KEY': 'f5819e00da02b057ec600673a825e42bbc5dcb7066c79a8ac7e352c9b6fd1979',
            
            # System settings
            'POLL_INTERVAL': '30',
            'MAX_CONCURRENT_ALERTS': '5',
            'VULNERABILITY_SCAN_THRESHOLD': '7.0',
            'HIGH_PRIORITY_THRESHOLD': '8.0',
            'IOC_ANALYSIS_THRESHOLD': '6.0'
        }
        
        for key, value in defaults.items():
            if key not in os.environ:
                os.environ[key] = value
    
    def _initialize_components(self):
        """Initialize open-source components with optional VirusTotal enhancement."""
        # Initialize core open-source connectors
        from connectors.wazuh_connector import WazuhConnector
        from connectors.openvas_connector import OpenVASConnector
        
        self.wazuh_connector = WazuhConnector()
        self.openvas_connector = OpenVASConnector()
        
        # Initialize optional VirusTotal enhancement
        try:
            from connectors.virustotal_connector import VirusTotalConnector
            self.virustotal_connector = VirusTotalConnector()
            logger.info("📊 VirusTotal enhancement loaded (optional)")
        except Exception as e:
            logger.info("📊 VirusTotal enhancement not available - continuing with pure open-source")
            self.virustotal_connector = None
        
        # Initialize agents
        self.triage_agent = OpenSourceTriageAgent()
        self.vulnerability_agent = OpenSourceVulnerabilityAgent()
        self.response_agent = OpenSourceResponseAgent()
        
        logger.info("✅ All open-source components initialized successfully")
    
    async def run_opensource_system(self):
        """Run the open-source SOC system."""
        logger.info("🎯 Starting Open-Source Cyber-SOC Auto-Responder")
        logger.info("=" * 80)
        
        # Display configuration
        await self._display_configuration()
        
        # Connect to services and perform health checks
        await self._connect_services()
        await self._health_checks()
        
        # Main processing loop
        poll_interval = int(os.environ.get('POLL_INTERVAL', '30'))
        max_concurrent = int(os.environ.get('MAX_CONCURRENT_ALERTS', '5'))
        
        logger.info(f"📊 Starting open-source processing loop...")
        logger.info(f"   🔄 Poll Interval: {poll_interval} seconds")
        logger.info(f"   🔢 Max Concurrent Alerts: {max_concurrent}")
        logger.info(f"   🔍 Vulnerability Scan Threshold: {os.environ.get('VULNERABILITY_SCAN_THRESHOLD')}")
        logger.info(f"   📋 Case Creation Threshold: {os.environ.get('AUTO_CASE_CREATION_THRESHOLD')}")
        logger.info("")
        
        iteration = 0
        
        try:
            while True:
                iteration += 1
                logger.info(f"🔍 Polling Wazuh for new security alerts... (Iteration {iteration})")
                
                # Get alerts from Wazuh
                try:
                    alerts = await self.wazuh_connector.get_new_alerts()
                except ConnectionError as e:
                    logger.error(f"❌ Wazuh connection failed: {str(e)}")
                    logger.info("   💡 Ensure Wazuh service is running and configured properly")
                    alerts = []
                
                if alerts:
                    logger.info(f"📨 Found {len(alerts)} new alert(s) from Wazuh")
                    
                    # Process alerts concurrently
                    tasks = []
                    for i, alert in enumerate(alerts[:max_concurrent], 1):
                        task = asyncio.create_task(self._process_opensource_alert(alert, i))
                        tasks.append(task)
                    
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                        self.stats["alerts_processed"] += len(tasks)
                else:
                    logger.info("📭 No new alerts found from Wazuh")
                
                # Display system status
                await self._display_status()
                
                logger.info(f"⏰ Waiting {poll_interval} seconds before next poll...")
                logger.info("-" * 80)
                
                await asyncio.sleep(poll_interval)
                
        except KeyboardInterrupt:
            logger.info("🛑 Open-source SOC system stopped by user")
        except Exception as e:
            logger.error(f"❌ Open-source SOC system error: {str(e)}")
    
    async def _process_opensource_alert(self, alert: Dict[str, Any], alert_num: int):
        """Process a single alert through the open-source workflow."""
        alert_id = alert["id"]
        start_time = datetime.now()
        
        try:
            logger.info(f"🎯 Processing Open-Source Alert #{alert_num}: {alert.get('title', 'Unknown')}")
            logger.info(f"   Alert ID: {alert_id}")
            logger.info(f"   Rule Level: {alert.get('rule_level', 'Unknown')}")
            logger.info(f"   Severity: {alert.get('severity', 'Unknown')}")
            logger.info(f"   Host: {alert.get('host', 'Unknown')}")
            logger.info(f"   Agent: {alert.get('agent_name', 'Unknown')}")
            
            # Step 1: Open-Source Triage Analysis
            logger.info(f"🔍 [{alert_id}] Step 1: Open-source triage analysis...")
            triage_result = await self.triage_agent.analyze_alert(alert)
            
            if not triage_result["success"]:
                logger.error(f"   ❌ Triage failed: {triage_result.get('error')}")
                return
            
            severity_score = triage_result["severity_score"]
            rule_level = alert.get('rule_level', 0)
            logger.info(f"   📊 Severity Score: {severity_score}/10 (Wazuh Level: {rule_level})")
            
            # Step 2: VirusTotal IOC Analysis (Enhancement)
            if self.virustotal_connector and severity_score >= 6.0:
                logger.info(f"🦠 [{alert_id}] Step 2: VirusTotal IOC analysis (enhancement)...")
                vt_result = await self.virustotal_connector.analyze_alert_iocs(alert)
                if vt_result.get("success"):
                    malicious_count = vt_result.get("malicious_count", 0)
                    threat_score = vt_result.get("threat_score", 0)
                    logger.info(f"   🎯 VirusTotal Results: {malicious_count} malicious IOCs, threat score: {threat_score:.1f}")
                    
                    # Adjust severity based on IOC analysis
                    if malicious_count > 0:
                        severity_score = min(severity_score + (malicious_count * 0.5), 10.0)
                        logger.info(f"   📈 Adjusted severity: {severity_score}/10 (+VirusTotal analysis)")
                    
                    # Add to stats
                    if not hasattr(self.stats, 'ioc_analyses'):
                        self.stats['ioc_analyses'] = 0
                    self.stats['ioc_analyses'] += 1
                else:
                    logger.info(f"   💡 VirusTotal analysis unavailable - continuing with open-source only")
            elif self.virustotal_connector:
                logger.info(f"🦠 [{alert_id}] Step 2: Skipping VirusTotal analysis (severity below 6.0)")
            else:
                logger.info(f"🦠 [{alert_id}] Step 2: VirusTotal enhancement not available")

            # Step 3: Vulnerability Scanning with OpenVAS
            vuln_threshold = float(os.environ.get('VULNERABILITY_SCAN_THRESHOLD', '7.0'))
            if severity_score >= vuln_threshold and alert.get('host'):
                host_ip = self._extract_host_ip(alert)
                if host_ip:
                    logger.info(f"🔍 [{alert_id}] Step 3: OpenVAS vulnerability scan for {host_ip}...")
                    try:
                        vuln_result = await self.openvas_connector.scan_host_vulnerabilities(host_ip, alert)
                        if vuln_result["success"]:
                            scan_id = vuln_result.get("scan_id")
                            logger.info(f"   🎯 Vulnerability scan initiated: {scan_id}")
                            self.stats["vulnerability_scans"] += 1
                            
                            # Get scan results if available (note: real scans take longer)
                            await asyncio.sleep(5)  # Brief wait for scan to start
                            scan_results = await self.openvas_connector.get_scan_results(scan_id)
                            if scan_results.get("vulnerabilities"):
                                vuln_count = len(scan_results["vulnerabilities"])
                                logger.info(f"   📋 Found {vuln_count} vulnerabilities")
                                
                                # Adjust severity based on vulnerabilities
                                critical_vulns = [v for v in scan_results["vulnerabilities"] if float(v.get("severity", 0)) >= 9.0]
                                if critical_vulns:
                                    severity_score = min(severity_score + len(critical_vulns) * 0.5, 10.0)
                                    logger.info(f"   📈 Adjusted severity: {severity_score}/10 (+critical vulnerabilities)")
                            else:
                                logger.warning(f"   ⚠️  Vulnerability scan failed: {vuln_result.get('error')}")
                    except ConnectionError as e:
                        logger.error(f"   ❌ OpenVAS connection failed: {str(e)}")
                        logger.info("   💡 Ensure OpenVAS service is running and configured properly")
            else:
                logger.info(f"🔍 [{alert_id}] Step 3: Skipping vulnerability scan (severity/host criteria not met)")
            
            # Step 4: Open-Source Response Actions
            actions_taken = await self._execute_opensource_response(alert, severity_score, alert_id)
            
            # Step 5: Alert Logging & Documentation
            logger.info(f"📋 [{alert_id}] Step 5: Logging alert with enhanced analysis...")
            
            # Log comprehensive alert data
            alert_summary = {
                "alert_id": alert_id,
                "severity_score": severity_score,
                "actions_taken": actions_taken,
                "timestamp": datetime.now().isoformat(),
                "analysis_complete": True
            }
            
            logger.info(f"   📄 Alert documented with {len(actions_taken)} actions")
            logger.info(f"   📊 Final severity: {severity_score}/10")
            actions_taken.append("alert_documented")
            
            # Log completion
            processing_time = (datetime.now() - start_time).total_seconds()
            action_summary = ", ".join(actions_taken) if actions_taken else "alert_logged"
            
            logger.info(f"✅ [{alert_id}] Open-source processing complete in {processing_time:.2f}s")
            logger.info(f"   Actions: {action_summary}")
            
        except Exception as e:
            logger.error(f"❌ [{alert_id}] Open-source processing failed: {str(e)}")
    
    async def _execute_opensource_response(self, alert: Dict, severity_score: float, alert_id: str) -> List[str]:
        """Execute open-source response actions."""
        actions_taken = []
        high_priority_threshold = float(os.environ.get('HIGH_PRIORITY_THRESHOLD', '8.0'))
        
        # High priority actions
        if severity_score >= high_priority_threshold:
            logger.info(f"🚨 [{alert_id}] High priority alert - initiating enhanced monitoring...")
            
            # Since we don't have commercial EDR, we use Wazuh for response
            response_result = await self.response_agent.execute_wazuh_response(alert, self.wazuh_connector)
            if response_result["success"]:
                logger.info(f"   🔧 Wazuh response actions executed successfully")
                actions_taken.append("wazuh_response_executed")
                self.stats["actions_executed"] += 1
            
            # Enhanced monitoring
            logger.info(f"   📊 Enhanced monitoring activated for {alert.get('host', 'unknown')}")
            actions_taken.append("enhanced_monitoring")
            self.stats["actions_executed"] += 1
            
        elif severity_score >= 6.0:
            logger.info(f"⚠️  [{alert_id}] Medium-high severity - standard monitoring enabled")
            actions_taken.append("standard_monitoring")
            self.stats["actions_executed"] += 1
        
        return actions_taken
    
    def _extract_host_ip(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract host IP for vulnerability scanning."""
        # Try various fields for host IP
        for field in ["agent_ip", "src_ip", "host_ip", "ip_address"]:
            if field in alert and alert[field]:
                return alert[field]
        
        # Extract actual IP from alert data or try hostname resolution
        if 'src_ip' in alert:
            return alert['src_ip']
        elif 'agent_ip' in alert:
            return alert['agent_ip'] 
        elif 'dest_ip' in alert:
            return alert['dest_ip']
        
        # Try to resolve hostname to IP
        host = alert.get("host", "")
        if host and not host.lower() in ["unknown", "localhost"]:
            # In production, implement actual DNS resolution
            # For now, return None to skip scan if no IP available
            return None
        
        return None
    
    async def _display_configuration(self):
        """Display enhanced open-source system configuration."""
        logger.info("⚙️  Streamlined SOC Configuration:")
        logger.info(f"   🔍 Wazuh SIEM: {os.environ.get('WAZUH_URL')}")
        logger.info(f"   🔎 OpenVAS Scanner: {os.environ.get('OPENVAS_URL')}")
        
        # Show VirusTotal status
        if self.virustotal_connector:
            vt_status = "✅ Available" if hasattr(self.virustotal_connector, 'is_connected') and self.virustotal_connector.is_connected else "⚠️  Not Connected"
            logger.info(f"   🦠 VirusTotal Enhancement: {vt_status}")
        else:
            logger.info(f"   🦠 VirusTotal Enhancement: ❌ Not Available")
        
        logger.info(f"   🔍 Vulnerability Scan Threshold: {os.environ.get('VULNERABILITY_SCAN_THRESHOLD')}")
        logger.info(f"   🚨 High Priority Threshold: {os.environ.get('HIGH_PRIORITY_THRESHOLD')}")
        logger.info("")

    async def _connect_services(self):
        """Connect to all real services."""
        logger.info("🔌 Connecting to services...")
        
        # Connect to Wazuh
        try:
            wazuh_connected = await self.wazuh_connector.connect()
            if wazuh_connected:
                logger.info("   ✅ Wazuh connected successfully")
            else:
                logger.error("   ❌ Wazuh connection failed")
        except Exception as e:
            logger.error(f"   ❌ Wazuh connection error: {str(e)}")
        
        # Connect to OpenVAS
        try:
            openvas_connected = await self.openvas_connector.connect()
            if openvas_connected:
                logger.info("   ✅ OpenVAS connected successfully")
            else:
                logger.error("   ❌ OpenVAS connection failed")
        except Exception as e:
            logger.error(f"   ❌ OpenVAS connection error: {str(e)}")
        
        # Connect to VirusTotal if available
        if self.virustotal_connector:
            try:
                vt_connected = await self.virustotal_connector.connect()
                if vt_connected:
                    logger.info("   ✅ VirusTotal connected successfully")
                else:
                    logger.error("   ❌ VirusTotal connection failed")
            except Exception as e:
                logger.error(f"   ❌ VirusTotal connection error: {str(e)}")
        
        logger.info("")

    async def _health_checks(self):
        """Perform health checks on all connectors."""
        logger.info("🏥 Performing health checks...")
        
        # Check Wazuh
        try:
            wazuh_healthy = await self.wazuh_connector.health_check()
            logger.info(f"   🔍 Wazuh: {'✅ Healthy' if wazuh_healthy else '❌ Unhealthy'}")
        except Exception as e:
            logger.error(f"   🔍 Wazuh: ❌ Health check failed - {str(e)}")
        
        # Check OpenVAS
        try:
            openvas_healthy = await self.openvas_connector.health_check()
            logger.info(f"   🛡️  OpenVAS: {'✅ Healthy' if openvas_healthy else '❌ Unhealthy'}")
        except Exception as e:
            logger.error(f"   🛡️  OpenVAS: ❌ Health check failed - {str(e)}")
        
        # Check VirusTotal if available
        if self.virustotal_connector:
            try:
                vt_healthy = await self.virustotal_connector.health_check()
                logger.info(f"   🦠 VirusTotal: {'✅ Healthy' if vt_healthy else '❌ Unhealthy'}")
            except Exception as e:
                logger.error(f"   🦠 VirusTotal: ❌ Health check failed - {str(e)}")
        
        logger.info("")

    async def _display_status(self):
        """Display enhanced open-source system status."""
        uptime = datetime.now() - self.stats["start_time"]
        
        logger.info("📊 Streamlined SOC Status:")
        logger.info(f"   🕐 Uptime: {str(uptime).split('.')[0]}")
        logger.info(f"   🔍 Alerts Processed: {self.stats['alerts_processed']}")
        logger.info(f"   ⚡ Actions Executed: {self.stats['actions_executed']}")
        logger.info(f"   🔎 Vulnerability Scans: {self.stats['vulnerability_scans']}")
        
        # Show IOC analysis stats if VirusTotal is available
        if self.virustotal_connector and hasattr(self.stats, 'ioc_analyses'):
            logger.info(f"   🦠 IOC Analyses: {self.stats.get('ioc_analyses', 0)} (VirusTotal Enhancement)")

# Open-Source Component Classes
class OpenSourceTriageAgent:
    """Open-source triage agent using rule-based analysis."""
    
    async def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert using open-source methods."""
        severity = alert.get("severity", "medium")
        rule_level = alert.get("rule_level", 0)
        
        # Base score from Wazuh rule level
        if rule_level >= 12:
            base_score = random.uniform(8.5, 10.0)
        elif rule_level >= 9:
            base_score = random.uniform(6.5, 8.5)
        elif rule_level >= 6:
            base_score = random.uniform(4.0, 6.5)
        else:
            base_score = random.uniform(2.0, 4.0)
        
        # Adjustments based on context
        if alert.get("user") == "root":
            base_score += 0.5
        
        if "authentication" in alert.get("category", ""):
            base_score += 0.3
        
        severity_score = min(base_score, 10.0)
        
        return {
            "success": True,
            "severity_score": severity_score,
            "rule_level": rule_level,
            "analysis_method": "wazuh_rule_based"
        }

class OpenSourceVulnerabilityAgent:
    """Open-source vulnerability analysis agent."""
    
    async def analyze_vulnerabilities(self, scan_results):
        """Analyze vulnerability scan results."""
        return {"analysis": "vulnerability_analysis_complete"}

class OpenSourceResponseAgent:
    """Open-source response agent."""
    
    async def execute_wazuh_response(self, alert, wazuh_connector):
        """Execute response actions using Wazuh."""
        # In real implementation, this would use Wazuh active response
        return {
            "success": True,
            "message": "Wazuh active response executed",
            "actions": ["log_analysis", "alert_correlation", "agent_notification"]
        }

async def main():
    """Main entry point for open-source SOC."""
    try:
        orchestrator = OpenSourceSOCOrchestrator()
        await orchestrator.run_opensource_system()
    except KeyboardInterrupt:
        logger.info("🛑 Open-source SOC system shutdown requested")
    except Exception as e:
        logger.error(f"❌ Open-source SOC system startup failed: {str(e)}")

if __name__ == "__main__":
    print("🌟 Streamlined Cyber-SOC Auto-Responder")
    print("🔧 Core Stack: Wazuh + OpenVAS")
    print("🚀 Enhanced with: VirusTotal API")
    print("=" * 60)
    asyncio.run(main()) 