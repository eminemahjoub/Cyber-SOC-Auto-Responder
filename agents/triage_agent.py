"""
Cyber-SOC Auto-Responder Triage Agent

This module contains the AI-powered triage agent that analyzes security alerts,
assigns severity scores, and determines appropriate response actions based on
DBIR patterns and threat intelligence.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from config.logger_config import get_logger, log_alert_processing
from config.dbir_patterns import DBIRPatterns, IncidentPattern, ThreatActorType

logger = get_logger(__name__)

class TriageAgent:
    """
    AI-powered triage agent for security alert analysis and severity scoring.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = config.get("model", "gpt-4-turbo-preview")
        self.temperature = config.get("temperature", 0.1)
        self.max_tokens = config.get("max_tokens", 2000)
        
        # Analysis statistics
        self.stats = {
            "alerts_analyzed": 0,
            "patterns_detected": {},
            "severity_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "last_analysis_time": None
        }
    
    async def analyze_alert(
        self, 
        alert_data: Dict[str, Any], 
        dbir_patterns: DBIRPatterns
    ) -> Dict[str, Any]:
        """
        Perform comprehensive triage analysis of a security alert.
        
        Args:
            alert_data: The alert data to analyze
            dbir_patterns: DBIR patterns for threat intelligence
            
        Returns:
            Dictionary containing triage analysis results
        """
        try:
            start_time = time.time()
            alert_id = alert_data.get("id", "unknown")
            
            logger.info("Starting alert triage analysis", alert_id=alert_id)
            
            # Step 1: Extract and normalize alert features
            features = self._extract_alert_features(alert_data)
            
            # Step 2: Identify DBIR incident pattern
            pattern_analysis = self._identify_incident_pattern(features, dbir_patterns)
            
            # Step 3: Calculate base severity score
            base_score = self._calculate_base_severity(features, pattern_analysis)
            
            # Step 4: Apply contextual adjustments
            adjusted_score = self._apply_contextual_adjustments(
                base_score, features, pattern_analysis, dbir_patterns
            )
            
            # Step 5: Determine threat actor likelihood
            threat_actors = self._analyze_threat_actors(pattern_analysis, dbir_patterns)
            
            # Step 6: Generate risk factors and recommendations
            risk_factors = self._identify_risk_factors(features, pattern_analysis)
            recommendations = self._generate_recommendations(
                adjusted_score, pattern_analysis, risk_factors
            )
            
            # Step 7: Determine urgency and priority
            urgency = self._calculate_urgency(adjusted_score, features)
            priority = self._calculate_priority(adjusted_score, features, pattern_analysis)
            
            # Compile analysis results
            triage_result = {
                "success": True,
                "alert_id": alert_id,
                "analysis_time": datetime.now().isoformat(),
                "severity_score": round(adjusted_score, 1),
                "severity_level": self._score_to_severity_level(adjusted_score),
                "pattern": pattern_analysis.get("primary_pattern"),
                "pattern_confidence": pattern_analysis.get("confidence", 0.0),
                "threat_actors": threat_actors,
                "risk_factors": risk_factors,
                "recommendations": recommendations,
                "urgency": urgency,
                "priority": priority,
                "features": features,
                "raw_scores": {
                    "base_score": round(base_score, 1),
                    "adjusted_score": round(adjusted_score, 1)
                },
                "duration_ms": int((time.time() - start_time) * 1000)
            }
            
            # Update statistics
            self._update_statistics(triage_result)
            
            # Log analysis completion
            log_alert_processing(
                logger, alert_id, alert_data.get("source", "unknown"),
                triage_result["severity_level"], "triaged",
                triage_result["duration_ms"]
            )
            
            logger.info("Alert triage analysis completed",
                       alert_id=alert_id,
                       severity_score=adjusted_score,
                       pattern=pattern_analysis.get("primary_pattern"),
                       duration_ms=triage_result["duration_ms"])
            
            return triage_result
            
        except Exception as e:
            logger.error("Alert triage analysis failed", 
                        alert_id=alert_data.get("id"), error=str(e))
            return {
                "success": False,
                "error": str(e),
                "alert_id": alert_data.get("id"),
                "analysis_time": datetime.now().isoformat()
            }
    
    def _extract_alert_features(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize features from alert data"""
        features = {
            # Basic alert properties
            "title": alert_data.get("title", ""),
            "description": alert_data.get("description", ""),
            "category": alert_data.get("category", "").lower(),
            "source": alert_data.get("source", ""),
            "timestamp": alert_data.get("timestamp", ""),
            
            # Network indicators
            "has_network_activity": bool(
                alert_data.get("src_ip") or alert_data.get("dest_ip")
            ),
            "external_ip_present": self._has_external_ip(alert_data),
            "suspicious_ports": self._check_suspicious_ports(alert_data),
            
            # Host indicators
            "has_host_info": bool(alert_data.get("host")),
            "has_user_info": bool(alert_data.get("user")),
            "privileged_user": self._is_privileged_user(alert_data.get("user", "")),
            
            # File indicators
            "has_file_info": bool(
                alert_data.get("file_path") or alert_data.get("file_hash")
            ),
            "suspicious_file_extension": self._has_suspicious_file_extension(alert_data),
            "system_file_modification": self._is_system_file_modification(alert_data),
            
            # Process indicators
            "has_process_info": bool(alert_data.get("process_name")),
            "suspicious_process": self._is_suspicious_process(alert_data),
            "command_line_suspicious": self._has_suspicious_command_line(alert_data),
            
            # Temporal indicators
            "off_hours": self._is_off_hours(alert_data.get("timestamp")),
            "weekend": self._is_weekend(alert_data.get("timestamp")),
            
            # Content analysis
            "keywords": self._extract_security_keywords(alert_data),
            "mitre_tactics": alert_data.get("mitre_tactics", []),
            "indicators": alert_data.get("indicators", [])
        }
        
        return features
    
    def _identify_incident_pattern(
        self, 
        features: Dict[str, Any], 
        dbir_patterns: DBIRPatterns
    ) -> Dict[str, Any]:
        """Identify the most likely DBIR incident pattern"""
        pattern_scores = {}
        
        # Analyze features against each DBIR pattern
        for pattern in IncidentPattern:
            score = 0.0
            matching_indicators = []
            
            pattern_indicators = dbir_patterns.get_pattern_indicators(pattern)
            
            # Check for keyword matches
            for indicator in pattern_indicators:
                if self._feature_matches_indicator(features, indicator):
                    score += 1.0
                    matching_indicators.append(indicator)
            
            # Pattern-specific scoring logic
            if pattern == IncidentPattern.SYSTEM_INTRUSION:
                if features["has_network_activity"]:
                    score += 2.0
                if features["external_ip_present"]:
                    score += 1.5
                if features["has_process_info"]:
                    score += 1.0
                if "lateral_movement" in features["keywords"]:
                    score += 2.0
            
            elif pattern == IncidentPattern.SOCIAL_ENGINEERING:
                if "phishing" in features["keywords"]:
                    score += 3.0
                if "email" in features["keywords"]:
                    score += 1.5
                if features["has_user_info"]:
                    score += 1.0
                if "credential" in features["keywords"]:
                    score += 2.0
            
            elif pattern == IncidentPattern.WEB_APPLICATION_ATTACKS:
                if "sql" in features["keywords"] or "xss" in features["keywords"]:
                    score += 3.0
                if features["suspicious_ports"]:
                    score += 1.0
                if "web" in features["category"]:
                    score += 2.0
            
            elif pattern == IncidentPattern.PRIVILEGE_MISUSE:
                if features["privileged_user"]:
                    score += 3.0
                if features["has_user_info"]:
                    score += 1.0
                if "unauthorized" in features["keywords"]:
                    score += 2.0
            
            elif pattern == IncidentPattern.MISCELLANEOUS_ERRORS:
                if "error" in features["keywords"]:
                    score += 2.0
                if "misconfiguration" in features["keywords"]:
                    score += 3.0
                if not features["has_network_activity"]:
                    score += 1.0
            
            # Normalize score by number of pattern indicators
            if pattern_indicators:
                normalized_score = score / len(pattern_indicators)
                pattern_scores[pattern] = normalized_score
        
        # Find the best matching pattern
        if pattern_scores:
            best_pattern = max(pattern_scores, key=pattern_scores.get)
            confidence = pattern_scores[best_pattern]
            
            # Only return pattern if confidence is reasonable
            if confidence >= 0.3:
                return {
                    "primary_pattern": best_pattern.value,
                    "confidence": confidence,
                    "all_scores": {p.value: s for p, s in pattern_scores.items()}
                }
        
        return {
            "primary_pattern": IncidentPattern.EVERYTHING_ELSE.value,
            "confidence": 0.5,
            "all_scores": {}
        }
    
    def _calculate_base_severity(
        self, 
        features: Dict[str, Any], 
        pattern_analysis: Dict[str, Any]
    ) -> float:
        """Calculate base severity score"""
        score = 5.0  # Start with medium severity
        
        # Pattern-based scoring
        pattern = pattern_analysis.get("primary_pattern")
        pattern_confidence = pattern_analysis.get("confidence", 0.5)
        
        pattern_base_scores = {
            "system_intrusion": 7.5,
            "social_engineering": 6.8,
            "web_application_attacks": 6.2,
            "denial_of_service": 5.5,
            "privilege_misuse": 6.0,
            "lost_stolen_assets": 4.8,
            "miscellaneous_errors": 3.2,
            "everything_else": 5.0
        }
        
        if pattern in pattern_base_scores:
            pattern_score = pattern_base_scores[pattern] * pattern_confidence
            score = max(score, pattern_score)
        
        # Feature-based adjustments
        if features["external_ip_present"]:
            score += 1.5
        
        if features["privileged_user"]:
            score += 2.0
        
        if features["suspicious_process"]:
            score += 1.5
        
        if features["system_file_modification"]:
            score += 2.5
        
        if features["command_line_suspicious"]:
            score += 1.0
        
        if features["suspicious_file_extension"]:
            score += 1.0
        
        if features["suspicious_ports"]:
            score += 1.0
        
        # Keyword-based scoring
        high_risk_keywords = [
            "malware", "ransomware", "trojan", "backdoor", "rootkit",
            "exploit", "vulnerability", "compromise", "breach"
        ]
        
        for keyword in high_risk_keywords:
            if keyword in features["keywords"]:
                score += 1.5
        
        # MITRE tactics boost
        if features["mitre_tactics"]:
            score += min(len(features["mitre_tactics"]) * 0.5, 2.0)
        
        return min(score, 10.0)  # Cap at 10.0
    
    def _apply_contextual_adjustments(
        self,
        base_score: float,
        features: Dict[str, Any],
        pattern_analysis: Dict[str, Any],
        dbir_patterns: DBIRPatterns
    ) -> float:
        """Apply contextual adjustments to the base score"""
        adjusted_score = base_score
        
        # Time-based adjustments
        if features["off_hours"]:
            adjusted_score *= 1.2
        
        if features["weekend"]:
            adjusted_score *= 1.1
        
        # Asset criticality (simplified - would normally come from CMDB)
        # For now, assume server/admin systems are critical
        if features["privileged_user"] or "server" in features.get("title", "").lower():
            adjusted_score *= 1.3
        
        # Pattern-specific adjustments using DBIR data
        pattern = pattern_analysis.get("primary_pattern")
        if pattern:
            try:
                pattern_enum = IncidentPattern(pattern)
                
                # Apply industry and temporal risk factors
                adjusted_score = dbir_patterns.calculate_risk_score(
                    adjusted_score,
                    time_factor="after_hours" if features["off_hours"] else "business_hours"
                )
                
            except ValueError:
                pass  # Unknown pattern
        
        return min(adjusted_score, 10.0)
    
    def _analyze_threat_actors(
        self, 
        pattern_analysis: Dict[str, Any], 
        dbir_patterns: DBIRPatterns
    ) -> Dict[str, float]:
        """Analyze likely threat actors based on pattern"""
        pattern = pattern_analysis.get("primary_pattern")
        
        if pattern:
            try:
                pattern_enum = IncidentPattern(pattern)
                return dbir_patterns.get_threat_actor_likelihood(pattern_enum)
            except ValueError:
                pass
        
        # Default distribution
        return {
            "organized_crime": 0.25,
            "nation_state": 0.25,
            "activist": 0.25,
            "malicious_insider": 0.25
        }
    
    def _identify_risk_factors(
        self, 
        features: Dict[str, Any], 
        pattern_analysis: Dict[str, Any]
    ) -> List[str]:
        """Identify key risk factors for the alert"""
        risk_factors = []
        
        if features["external_ip_present"]:
            risk_factors.append("External IP communication")
        
        if features["privileged_user"]:
            risk_factors.append("Privileged user account involved")
        
        if features["system_file_modification"]:
            risk_factors.append("System file modification detected")
        
        if features["off_hours"]:
            risk_factors.append("Activity outside business hours")
        
        if features["suspicious_process"]:
            risk_factors.append("Suspicious process execution")
        
        if features["command_line_suspicious"]:
            risk_factors.append("Suspicious command line activity")
        
        if len(features["indicators"]) > 0:
            risk_factors.append(f"Multiple IOCs present ({len(features['indicators'])})")
        
        pattern_confidence = pattern_analysis.get("confidence", 0.0)
        if pattern_confidence > 0.7:
            pattern = pattern_analysis.get("primary_pattern", "").replace("_", " ").title()
            risk_factors.append(f"High confidence {pattern} pattern match")
        
        return risk_factors
    
    def _generate_recommendations(
        self,
        severity_score: float,
        pattern_analysis: Dict[str, Any],
        risk_factors: List[str]
    ) -> List[str]:
        """Generate specific recommendations based on analysis"""
        recommendations = []
        
        # Score-based recommendations
        if severity_score >= 8.5:
            recommendations.extend([
                "Initiate emergency incident response",
                "Consider network isolation of affected systems",
                "Notify CISO and executive leadership"
            ])
        elif severity_score >= 7.0:
            recommendations.extend([
                "Escalate to senior security analyst",
                "Begin detailed investigation",
                "Monitor for lateral movement"
            ])
        elif severity_score >= 5.0:
            recommendations.extend([
                "Assign to security analyst for investigation",
                "Collect additional forensic data"
            ])
        else:
            recommendations.append("Queue for routine investigation")
        
        # Pattern-specific recommendations
        pattern = pattern_analysis.get("primary_pattern")
        
        if pattern == "system_intrusion":
            recommendations.extend([
                "Check for indicators of compromise",
                "Review authentication logs",
                "Scan for malware presence"
            ])
        elif pattern == "social_engineering":
            recommendations.extend([
                "Verify with affected user",
                "Check email security logs",
                "Review user training records"
            ])
        elif pattern == "web_application_attacks":
            recommendations.extend([
                "Review web server logs",
                "Check application security controls",
                "Validate input sanitization"
            ])
        elif pattern == "privilege_misuse":
            recommendations.extend([
                "Review user access permissions",
                "Check data access logs",
                "Interview affected user"
            ])
        
        # Risk factor specific recommendations
        if "External IP communication" in risk_factors:
            recommendations.append("Block suspicious external IPs")
        
        if "Privileged user account involved" in risk_factors:
            recommendations.append("Review privileged account activity")
        
        if "System file modification detected" in risk_factors:
            recommendations.append("Perform system integrity check")
        
        return recommendations
    
    def _calculate_urgency(self, severity_score: float, features: Dict[str, Any]) -> str:
        """Calculate urgency level"""
        if severity_score >= 8.5:
            return "critical"
        elif severity_score >= 7.0:
            return "high"
        elif severity_score >= 5.0:
            return "medium"
        else:
            return "low"
    
    def _calculate_priority(
        self, 
        severity_score: float, 
        features: Dict[str, Any],
        pattern_analysis: Dict[str, Any]
    ) -> str:
        """Calculate priority level considering business impact"""
        base_priority = self._calculate_urgency(severity_score, features)
        
        # Adjust based on business factors
        if features["privileged_user"]:
            if base_priority == "medium":
                base_priority = "high"
            elif base_priority == "low":
                base_priority = "medium"
        
        if features["off_hours"] and base_priority in ["medium", "low"]:
            # Lower priority for after-hours non-critical events
            return "low" if base_priority == "medium" else base_priority
        
        return base_priority
    
    # Helper methods for feature extraction
    def _has_external_ip(self, alert_data: Dict[str, Any]) -> bool:
        """Check if alert involves external IP addresses"""
        try:
            import ipaddress
            
            for ip_field in ["src_ip", "dest_ip"]:
                ip_str = alert_data.get(ip_field)
                if ip_str:
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if not (ip.is_private or ip.is_loopback or ip.is_reserved):
                            return True
                    except ValueError:
                        continue
        except ImportError:
            pass
        
        return False
    
    def _check_suspicious_ports(self, alert_data: Dict[str, Any]) -> bool:
        """Check for suspicious port numbers"""
        suspicious_ports = {22, 23, 135, 139, 445, 3389, 5985, 5986}
        
        for port_field in ["src_port", "dest_port"]:
            port = alert_data.get(port_field)
            if port and int(port) in suspicious_ports:
                return True
        
        return False
    
    def _is_privileged_user(self, user: str) -> bool:
        """Check if user appears to be privileged"""
        if not user:
            return False
        
        privileged_indicators = [
            "admin", "root", "administrator", "service", "system",
            "sa", "svc", "adm", "sudo"
        ]
        
        user_lower = user.lower()
        return any(indicator in user_lower for indicator in privileged_indicators)
    
    def _has_suspicious_file_extension(self, alert_data: Dict[str, Any]) -> bool:
        """Check for suspicious file extensions"""
        file_path = alert_data.get("file_path", "")
        if not file_path:
            return False
        
        suspicious_extensions = {
            ".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
            ".js", ".jse", ".vbs", ".vbe", ".ps1", ".wsf"
        }
        
        return any(file_path.lower().endswith(ext) for ext in suspicious_extensions)
    
    def _is_system_file_modification(self, alert_data: Dict[str, Any]) -> bool:
        """Check if system files were modified"""
        file_path = alert_data.get("file_path", "")
        if not file_path:
            return False
        
        system_paths = [
            "\\windows\\system32\\", "\\windows\\syswow64\\",
            "/usr/bin/", "/usr/sbin/", "/etc/"
        ]
        
        file_path_lower = file_path.lower()
        return any(path in file_path_lower for path in system_paths)
    
    def _is_suspicious_process(self, alert_data: Dict[str, Any]) -> bool:
        """Check for suspicious process names"""
        process_name = alert_data.get("process_name", "")
        if not process_name:
            return False
        
        suspicious_processes = [
            "powershell", "cmd", "wscript", "cscript", "rundll32",
            "regsvr32", "mshta", "certutil", "bitsadmin"
        ]
        
        process_lower = process_name.lower()
        return any(proc in process_lower for proc in suspicious_processes)
    
    def _has_suspicious_command_line(self, alert_data: Dict[str, Any]) -> bool:
        """Check for suspicious command line indicators"""
        command_line = alert_data.get("command_line", "")
        if not command_line:
            return False
        
        suspicious_patterns = [
            "powershell", "base64", "encoded", "bypass", "hidden",
            "download", "invoke", "iex", "wget", "curl"
        ]
        
        command_lower = command_line.lower()
        return any(pattern in command_lower for pattern in suspicious_patterns)
    
    def _is_off_hours(self, timestamp: str) -> bool:
        """Check if timestamp is outside business hours"""
        if not timestamp:
            return False
        
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            return hour < 7 or hour > 19  # Outside 7 AM - 7 PM
        except:
            return False
    
    def _is_weekend(self, timestamp: str) -> bool:
        """Check if timestamp is on weekend"""
        if not timestamp:
            return False
        
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.weekday() >= 5  # Saturday = 5, Sunday = 6
        except:
            return False
    
    def _extract_security_keywords(self, alert_data: Dict[str, Any]) -> List[str]:
        """Extract security-related keywords from alert"""
        keywords = []
        
        text_fields = [
            alert_data.get("title", ""),
            alert_data.get("description", ""),
            alert_data.get("category", "")
        ]
        
        security_keywords = [
            "malware", "virus", "trojan", "ransomware", "phishing",
            "exploit", "vulnerability", "attack", "breach", "compromise",
            "lateral_movement", "privilege_escalation", "credential",
            "injection", "xss", "sql", "buffer_overflow"
        ]
        
        combined_text = " ".join(text_fields).lower()
        
        for keyword in security_keywords:
            if keyword in combined_text:
                keywords.append(keyword)
        
        return keywords
    
    def _feature_matches_indicator(self, features: Dict[str, Any], indicator: str) -> bool:
        """Check if extracted features match a DBIR pattern indicator"""
        indicator_lower = indicator.lower()
        
        # Check against keywords
        if indicator_lower in features.get("keywords", []):
            return True
        
        # Check against text fields
        text_content = " ".join([
            features.get("title", ""),
            features.get("description", ""),
            features.get("category", "")
        ]).lower()
        
        return indicator_lower in text_content
    
    def _score_to_severity_level(self, score: float) -> str:
        """Convert numeric score to severity level"""
        if score >= 8.5:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 5.0:
            return "medium"
        else:
            return "low"
    
    def _update_statistics(self, triage_result: Dict[str, Any]) -> None:
        """Update agent statistics"""
        self.stats["alerts_analyzed"] += 1
        self.stats["last_analysis_time"] = datetime.now().isoformat()
        
        # Update severity distribution
        severity = triage_result["severity_level"]
        if severity in self.stats["severity_distribution"]:
            self.stats["severity_distribution"][severity] += 1
        
        # Update pattern detection stats
        pattern = triage_result.get("pattern")
        if pattern:
            if pattern not in self.stats["patterns_detected"]:
                self.stats["patterns_detected"][pattern] = 0
            self.stats["patterns_detected"][pattern] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return dict(self.stats) 