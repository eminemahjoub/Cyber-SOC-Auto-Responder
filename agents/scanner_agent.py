"""
Cyber-SOC Auto-Responder Scanner Agent

This module contains the AI-powered scanner agent that coordinates
file analysis, malware detection, and IOC scanning operations.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path

from config.logger_config import get_logger, log_security_event
from scanners.yara_scanner import YaraScanner
from scanners.file_analyzer import FileAnalyzer
from scanners.ioc_scanner import IOCScanner

logger = get_logger(__name__)

class ScannerAgent:
    """
    AI-powered scanner agent for coordinating security scanning operations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = config.get("model", "gpt-4-turbo-preview")
        self.temperature = config.get("temperature", 0.0)
        self.max_tokens = config.get("max_tokens", 1500)
        
        # Initialize scanners
        self.file_analyzer = FileAnalyzer()
        self.ioc_scanner = IOCScanner()
        
        # Scan statistics
        self.stats = {
            "scans_performed": 0,
            "malware_detected": 0,
            "iocs_found": 0,
            "files_quarantined": 0,
            "last_scan_time": None
        }
    
    async def scan_file(
        self, 
        file_path: Union[str, Path], 
        yara_scanner: YaraScanner
    ) -> Dict[str, Any]:
        """
        Perform comprehensive file scanning including YARA and file analysis.
        
        Args:
            file_path: Path to the file to scan
            yara_scanner: YARA scanner instance
            
        Returns:
            Dictionary containing scan results
        """
        try:
            start_time = time.time()
            file_path = Path(file_path)
            
            logger.info("Starting file scan", file_path=str(file_path))
            
            # Step 1: File analysis
            file_analysis = self.file_analyzer.analyze_file(file_path)
            
            # Step 2: YARA scanning
            yara_results = yara_scanner.scan_file(file_path)
            
            # Step 3: IOC extraction from file path and metadata
            ioc_results = self._extract_file_iocs(file_analysis)
            
            # Step 4: Consolidate results and determine threat level
            scan_result = self._consolidate_scan_results(
                file_analysis, yara_results, ioc_results
            )
            
            # Step 5: Generate recommendations
            recommendations = self._generate_scan_recommendations(scan_result)
            
            # Compile final results
            final_result = {
                "success": True,
                "file_path": str(file_path),
                "scan_time": datetime.now().isoformat(),
                "malware_detected": scan_result["malware_detected"],
                "threat_score": scan_result["threat_score"],
                "threat_level": scan_result["threat_level"],
                "file_analysis": file_analysis,
                "yara_results": yara_results,
                "ioc_results": ioc_results,
                "recommendations": recommendations,
                "quarantine_recommended": scan_result["quarantine_recommended"],
                "duration_ms": int((time.time() - start_time) * 1000)
            }
            
            # Update statistics
            self._update_scan_statistics(final_result)
            
            # Log security events if malware detected
            if scan_result["malware_detected"]:
                log_security_event(
                    logger, "malware_detected_file_scan",
                    f"Malware detected in file: {file_path}",
                    indicators=[str(file_path)]
                )
            
            logger.info("File scan completed",
                       file_path=str(file_path),
                       malware_detected=scan_result["malware_detected"],
                       threat_score=scan_result["threat_score"],
                       duration_ms=final_result["duration_ms"])
            
            return final_result
            
        except Exception as e:
            logger.error("File scan failed", 
                        file_path=str(file_path), error=str(e))
            return {
                "success": False,
                "error": str(e),
                "file_path": str(file_path),
                "scan_time": datetime.now().isoformat()
            }
    
    async def scan_alert_for_iocs(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan an alert for indicators of compromise.
        
        Args:
            alert_data: Alert data to scan
            
        Returns:
            Dictionary containing IOC scan results
        """
        try:
            start_time = time.time()
            alert_id = alert_data.get("id", "unknown")
            
            logger.info("Starting alert IOC scan", alert_id=alert_id)
            
            # Perform IOC scanning
            ioc_results = self.ioc_scanner.scan_alert(alert_data)
            
            # Analyze results and generate insights
            insights = self._analyze_ioc_results(ioc_results, alert_data)
            
            result = {
                "success": True,
                "alert_id": alert_id,
                "scan_time": datetime.now().isoformat(),
                "ioc_results": ioc_results,
                "insights": insights,
                "duration_ms": int((time.time() - start_time) * 1000)
            }
            
            # Update statistics
            if ioc_results.get("malicious_matches"):
                self.stats["iocs_found"] += len(ioc_results["malicious_matches"])
            
            logger.info("Alert IOC scan completed",
                       alert_id=alert_id,
                       iocs_found=len(ioc_results.get("malicious_matches", [])),
                       duration_ms=result["duration_ms"])
            
            return result
            
        except Exception as e:
            logger.error("Alert IOC scan failed", 
                        alert_id=alert_data.get("id"), error=str(e))
            return {
                "success": False,
                "error": str(e),
                "alert_id": alert_data.get("id"),
                "scan_time": datetime.now().isoformat()
            }
    
    def _extract_file_iocs(self, file_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs from file analysis results"""
        if not file_analysis.get("success"):
            return {"success": False, "error": "File analysis failed"}
        
        # Extract file hashes as IOCs
        hashes = file_analysis.get("hashes", {})
        file_path = file_analysis.get("file_path", "")
        
        # Create text representation for IOC scanning
        ioc_text = f"File: {file_path}"
        
        if hashes:
            ioc_text += f" MD5: {hashes.get('md5', '')} SHA256: {hashes.get('sha256', '')}"
        
        # Scan for IOCs
        return self.ioc_scanner.scan_text(ioc_text, f"file_analysis_{Path(file_path).name}")
    
    def _consolidate_scan_results(
        self,
        file_analysis: Dict[str, Any],
        yara_results: Dict[str, Any],
        ioc_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Consolidate results from different scanners"""
        malware_detected = False
        threat_score = 0.0
        threat_indicators = []
        
        # Check YARA results
        if yara_results.get("malware_detected"):
            malware_detected = True
            threat_score = max(threat_score, yara_results.get("threat_score", 0))
            threat_indicators.extend(yara_results.get("rule_matches", []))
        
        # Check file analysis security flags
        security_analysis = file_analysis.get("security", {})
        if security_analysis.get("is_suspicious"):
            threat_score = max(threat_score, security_analysis.get("risk_score", 0))
            threat_indicators.extend(security_analysis.get("security_flags", []))
        
        # Check IOC results
        if ioc_results.get("malicious_matches"):
            malware_detected = True
            threat_score = max(threat_score, ioc_results.get("threat_score", 0))
            threat_indicators.extend([
                match["value"] for match in ioc_results.get("malicious_matches", [])
            ])
        
        # Determine threat level
        if threat_score >= 8.0:
            threat_level = "critical"
        elif threat_score >= 6.0:
            threat_level = "high"
        elif threat_score >= 4.0:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        # Determine if quarantine is recommended
        quarantine_recommended = (
            malware_detected or 
            threat_score >= 7.0 or
            any(flag in security_analysis.get("security_flags", []) 
                for flag in ["type_mismatch", "suspicious_extension"])
        )
        
        return {
            "malware_detected": malware_detected,
            "threat_score": round(threat_score, 1),
            "threat_level": threat_level,
            "threat_indicators": threat_indicators,
            "quarantine_recommended": quarantine_recommended
        }
    
    def _generate_scan_recommendations(self, scan_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on scan results"""
        recommendations = []
        
        if scan_result["malware_detected"]:
            recommendations.extend([
                "Immediately quarantine the file",
                "Scan all systems for similar files",
                "Update antivirus signatures",
                "Investigate file origin and distribution"
            ])
        
        if scan_result["quarantine_recommended"]:
            recommendations.append("Consider quarantining file pending further analysis")
        
        threat_level = scan_result["threat_level"]
        
        if threat_level == "critical":
            recommendations.extend([
                "Initiate emergency incident response",
                "Isolate affected systems immediately",
                "Notify security leadership"
            ])
        elif threat_level == "high":
            recommendations.extend([
                "Escalate to senior security analyst",
                "Perform detailed forensic analysis",
                "Check for lateral movement"
            ])
        elif threat_level == "medium":
            recommendations.extend([
                "Queue for security analyst review",
                "Monitor for additional suspicious activity"
            ])
        
        if scan_result["threat_indicators"]:
            recommendations.append("Block identified IOCs at security controls")
        
        return recommendations
    
    def _analyze_ioc_results(
        self, 
        ioc_results: Dict[str, Any], 
        alert_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze IOC results and generate insights"""
        insights = {
            "risk_assessment": "low",
            "key_findings": [],
            "correlation_opportunities": [],
            "next_steps": []
        }
        
        malicious_matches = ioc_results.get("malicious_matches", [])
        threat_score = ioc_results.get("threat_score", 0)
        
        if not malicious_matches:
            insights["key_findings"].append("No known malicious IOCs detected")
            insights["next_steps"].append("Continue with standard analysis procedures")
            return insights
        
        # Risk assessment
        if threat_score >= 8.0:
            insights["risk_assessment"] = "critical"
        elif threat_score >= 6.0:
            insights["risk_assessment"] = "high"
        elif threat_score >= 4.0:
            insights["risk_assessment"] = "medium"
        
        # Key findings
        ioc_types = set(match["type"] for match in malicious_matches)
        insights["key_findings"].append(
            f"Detected {len(malicious_matches)} malicious IOCs of types: {', '.join(ioc_types)}"
        )
        
        # High-confidence IOCs
        high_confidence_iocs = [
            match for match in malicious_matches 
            if match.get("confidence", 0) > 0.8
        ]
        
        if high_confidence_iocs:
            insights["key_findings"].append(
                f"{len(high_confidence_iocs)} high-confidence malicious indicators found"
            )
        
        # Correlation opportunities
        if "ip_address" in ioc_types:
            insights["correlation_opportunities"].append("Search network logs for IP communications")
        
        if "file_hash" in ioc_types:
            insights["correlation_opportunities"].append("Search for files with matching hashes")
        
        if "domain" in ioc_types:
            insights["correlation_opportunities"].append("Search DNS logs for domain queries")
        
        # Next steps
        if insights["risk_assessment"] in ["critical", "high"]:
            insights["next_steps"].extend([
                "Initiate threat hunting procedures",
                "Block malicious IOCs at security controls",
                "Search for additional indicators"
            ])
        else:
            insights["next_steps"].extend([
                "Monitor for additional IOC activity",
                "Consider blocking lower-confidence IOCs"
            ])
        
        return insights
    
    def _update_scan_statistics(self, scan_result: Dict[str, Any]) -> None:
        """Update scanner agent statistics"""
        self.stats["scans_performed"] += 1
        self.stats["last_scan_time"] = datetime.now().isoformat()
        
        if scan_result.get("malware_detected"):
            self.stats["malware_detected"] += 1
        
        if scan_result.get("quarantine_recommended"):
            self.stats["files_quarantined"] += 1
    
    async def quarantine_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Quarantine a file by moving it to the quarantine directory.
        
        Args:
            file_path: Path to the file to quarantine
            
        Returns:
            Result dictionary
        """
        try:
            import shutil
            
            file_path = Path(file_path)
            quarantine_dir = Path("./quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            
            # Create unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{file_path.name}"
            quarantine_path = quarantine_dir / quarantine_filename
            
            # Move file to quarantine
            shutil.move(str(file_path), str(quarantine_path))
            
            logger.info("File quarantined successfully",
                       original_path=str(file_path),
                       quarantine_path=str(quarantine_path))
            
            return {
                "success": True,
                "original_path": str(file_path),
                "quarantine_path": str(quarantine_path),
                "timestamp": timestamp
            }
            
        except Exception as e:
            logger.error("File quarantine failed", 
                        file_path=str(file_path), error=str(e))
            return {
                "success": False,
                "error": str(e),
                "file_path": str(file_path)
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner agent statistics"""
        # Combine stats from all scanners
        stats = dict(self.stats)
        stats["file_analyzer_stats"] = self.file_analyzer.get_stats()
        stats["ioc_scanner_stats"] = self.ioc_scanner.get_ioc_stats()
        
        return stats 