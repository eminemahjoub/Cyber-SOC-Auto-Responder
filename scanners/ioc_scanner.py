"""
Cyber-SOC Auto-Responder IOC Scanner

This module provides Indicators of Compromise (IOC) detection and analysis
for identifying known malicious artifacts in alerts and files.
"""

import re
import hashlib
import ipaddress
import time
from typing import Dict, List, Optional, Any, Set, Union
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from config.logger_config import get_logger, log_security_event

logger = get_logger(__name__)

class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"

@dataclass
class IOC:
    """Indicator of Compromise data structure"""
    value: str
    ioc_type: IOCType
    threat_level: str  # low, medium, high, critical
    description: str
    source: str
    first_seen: str
    last_seen: str
    tags: List[str]
    confidence: float  # 0.0 to 1.0

class IOCScanner:
    """
    IOC scanner for detecting known malicious indicators in security data.
    """
    
    def __init__(self):
        # IOC database
        self.iocs: Dict[IOCType, Set[str]] = {ioc_type: set() for ioc_type in IOCType}
        self.ioc_details: Dict[str, IOC] = {}
        
        # Regex patterns for IOC extraction
        self.patterns = {
            IOCType.IP_ADDRESS: re.compile(
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ),
            IOCType.DOMAIN: re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            ),
            IOCType.URL: re.compile(
                r'https?://(?:[-\w.])+(?::[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
            ),
            IOCType.EMAIL: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            IOCType.FILE_HASH: re.compile(
                r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
            ),
            IOCType.REGISTRY_KEY: re.compile(
                r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\\]+(?:\\[^\\]+)*',
                re.IGNORECASE
            ),
            IOCType.FILE_PATH: re.compile(
                r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
            ),
            IOCType.MUTEX: re.compile(
                r'(?:Global\\|Local\\)?[A-Za-z0-9_\-\{\}]+',
                re.IGNORECASE
            )
        }
        
        # Scan statistics
        self.stats = {
            "scans_performed": 0,
            "iocs_detected": 0,
            "unique_iocs": 0,
            "last_scan_time": None,
            "last_update_time": None
        }
        
        # Load default IOCs
        self._load_default_iocs()
    
    def scan_text(self, text: str, source: str = "unknown") -> Dict[str, Any]:
        """
        Scan text for IOCs and match against known malicious indicators.
        
        Args:
            text: Text content to scan
            source: Source identifier for the scan
            
        Returns:
            Dictionary containing scan results
        """
        try:
            start_time = time.time()
            
            # Extract all potential IOCs from text
            extracted_iocs = self._extract_iocs(text)
            
            # Match against known malicious IOCs
            matches = self._match_against_database(extracted_iocs)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(matches)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(matches, threat_score)
            
            result = {
                "success": True,
                "source": source,
                "scan_time": datetime.now().isoformat(),
                "extracted_iocs": extracted_iocs,
                "malicious_matches": matches,
                "threat_score": threat_score,
                "recommendations": recommendations,
                "duration_ms": int((time.time() - start_time) * 1000)
            }
            
            # Update statistics
            self.stats["scans_performed"] += 1
            self.stats["last_scan_time"] = datetime.now().isoformat()
            
            if matches:
                self.stats["iocs_detected"] += len(matches)
                
                # Log security event
                log_security_event(
                    logger, "malicious_iocs_detected",
                    f"Malicious IOCs detected in {source}",
                    indicators=[match["value"] for match in matches]
                )
            
            logger.info("IOC scan completed",
                       source=source,
                       extracted_count=len(extracted_iocs),
                       malicious_matches=len(matches),
                       threat_score=threat_score)
            
            return result
            
        except Exception as e:
            logger.error("IOC scan failed", source=source, error=str(e))
            return {
                "success": False,
                "error": str(e),
                "source": source,
                "scan_time": datetime.now().isoformat()
            }
    
    def scan_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan an alert for IOCs.
        
        Args:
            alert_data: Alert dictionary to scan
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Combine relevant alert fields into text
            text_fields = []
            
            # Add common text fields
            for field in ["title", "description", "message", "raw_event"]:
                if field in alert_data and alert_data[field]:
                    text_fields.append(str(alert_data[field]))
            
            # Add specific IOC fields if they exist
            ioc_fields = ["src_ip", "dest_ip", "file_path", "file_hash", 
                         "command_line", "process_name", "user"]
            
            for field in ioc_fields:
                if field in alert_data and alert_data[field]:
                    text_fields.append(str(alert_data[field]))
            
            # Combine all text
            combined_text = " ".join(text_fields)
            
            # Perform scan
            result = self.scan_text(combined_text, f"alert_{alert_data.get('id', 'unknown')}")
            
            # Add alert-specific metadata
            result["alert_id"] = alert_data.get("id")
            result["alert_source"] = alert_data.get("source")
            
            return result
            
        except Exception as e:
            logger.error("Alert IOC scan failed", 
                        alert_id=alert_data.get("id"), error=str(e))
            return {
                "success": False,
                "error": str(e),
                "alert_id": alert_data.get("id")
            }
    
    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns"""
        extracted = {}
        
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            
            # Filter and validate matches
            validated_matches = []
            for match in matches:
                if self._validate_ioc(match, ioc_type):
                    validated_matches.append(match)
            
            if validated_matches:
                extracted[ioc_type.value] = list(set(validated_matches))  # Remove duplicates
        
        return extracted
    
    def _validate_ioc(self, value: str, ioc_type: IOCType) -> bool:
        """Validate extracted IOC based on type"""
        try:
            if ioc_type == IOCType.IP_ADDRESS:
                # Validate IP address and filter out private/reserved ranges
                ip = ipaddress.ip_address(value)
                return not (ip.is_private or ip.is_loopback or ip.is_reserved or 
                           ip.is_multicast or ip.is_link_local)
            
            elif ioc_type == IOCType.DOMAIN:
                # Basic domain validation
                if len(value) < 4 or len(value) > 253:
                    return False
                
                # Filter out common non-malicious domains
                common_domains = {
                    'microsoft.com', 'google.com', 'amazon.com', 'apple.com',
                    'facebook.com', 'github.com', 'stackoverflow.com',
                    'localhost', 'example.com', 'test.com'
                }
                
                return value.lower() not in common_domains
            
            elif ioc_type == IOCType.FILE_HASH:
                # Validate hash format
                if len(value) == 32:  # MD5
                    return True
                elif len(value) == 40:  # SHA1
                    return True
                elif len(value) == 64:  # SHA256
                    return True
                return False
            
            elif ioc_type == IOCType.EMAIL:
                # Additional email validation
                return '@' in value and '.' in value.split('@')[1]
            
            elif ioc_type == IOCType.FILE_PATH:
                # Filter out common system paths
                system_paths = {
                    'C:\\Windows\\System32', 'C:\\Program Files',
                    'C:\\Users\\Public', '/usr/bin', '/etc'
                }
                
                return not any(value.startswith(path) for path in system_paths)
            
            return True
            
        except Exception:
            return False
    
    def _match_against_database(self, extracted_iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Match extracted IOCs against known malicious indicators"""
        matches = []
        
        for ioc_type_str, values in extracted_iocs.items():
            try:
                ioc_type = IOCType(ioc_type_str)
                
                for value in values:
                    if value in self.iocs[ioc_type]:
                        ioc_details = self.ioc_details.get(value)
                        if ioc_details:
                            matches.append({
                                "value": value,
                                "type": ioc_type.value,
                                "threat_level": ioc_details.threat_level,
                                "description": ioc_details.description,
                                "source": ioc_details.source,
                                "confidence": ioc_details.confidence,
                                "tags": ioc_details.tags,
                                "first_seen": ioc_details.first_seen,
                                "last_seen": ioc_details.last_seen
                            })
                        else:
                            # Fallback for IOCs without detailed info
                            matches.append({
                                "value": value,
                                "type": ioc_type.value,
                                "threat_level": "medium",
                                "description": f"Known malicious {ioc_type.value}",
                                "source": "internal_database",
                                "confidence": 0.8,
                                "tags": ["malicious"],
                                "first_seen": "unknown",
                                "last_seen": "unknown"
                            })
            
            except ValueError:
                # Unknown IOC type
                continue
        
        return matches
    
    def _calculate_threat_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate overall threat score based on matches"""
        if not matches:
            return 0.0
        
        # Base scoring system
        threat_level_scores = {
            "low": 2.0,
            "medium": 5.0,
            "high": 7.5,
            "critical": 9.0
        }
        
        total_score = 0.0
        for match in matches:
            base_score = threat_level_scores.get(match["threat_level"], 5.0)
            confidence = match.get("confidence", 0.8)
            
            # Adjust score by confidence
            adjusted_score = base_score * confidence
            total_score += adjusted_score
        
        # Apply diminishing returns for multiple matches
        if len(matches) > 1:
            multiplier = min(1.0 + (len(matches) - 1) * 0.2, 2.0)
            total_score *= multiplier
        
        # Cap at 10.0
        return min(total_score, 10.0)
    
    def _generate_recommendations(self, matches: List[Dict[str, Any]], threat_score: float) -> List[str]:
        """Generate recommendations based on IOC matches"""
        recommendations = []
        
        if not matches:
            recommendations.append("No malicious IOCs detected")
            return recommendations
        
        # General recommendations
        recommendations.append("Investigate the source of malicious indicators")
        
        # Specific recommendations based on IOC types
        ioc_types = set(match["type"] for match in matches)
        
        if "ip_address" in ioc_types:
            recommendations.extend([
                "Block malicious IP addresses at firewall",
                "Review network logs for connections to malicious IPs"
            ])
        
        if "domain" in ioc_types:
            recommendations.extend([
                "Block malicious domains via DNS filtering",
                "Check for DNS queries to malicious domains"
            ])
        
        if "file_hash" in ioc_types:
            recommendations.extend([
                "Quarantine files with malicious hashes",
                "Perform full system scan for similar files"
            ])
        
        if "email" in ioc_types:
            recommendations.extend([
                "Block sender addresses",
                "Review email security policies"
            ])
        
        # Threat level specific recommendations
        if threat_score >= 8.0:
            recommendations.extend([
                "Initiate incident response procedures",
                "Consider network isolation for affected systems"
            ])
        elif threat_score >= 6.0:
            recommendations.extend([
                "Escalate to security team",
                "Perform enhanced monitoring"
            ])
        
        return recommendations
    
    def add_ioc(self, ioc: IOC) -> bool:
        """
        Add an IOC to the database.
        
        Args:
            ioc: IOC object to add
            
        Returns:
            True if added successfully
        """
        try:
            self.iocs[ioc.ioc_type].add(ioc.value)
            self.ioc_details[ioc.value] = ioc
            
            self.stats["unique_iocs"] = sum(len(ioc_set) for ioc_set in self.iocs.values())
            
            logger.debug("IOC added to database", 
                        value=ioc.value, type=ioc.ioc_type.value)
            
            return True
            
        except Exception as e:
            logger.error("Failed to add IOC", value=ioc.value, error=str(e))
            return False
    
    def remove_ioc(self, value: str, ioc_type: IOCType) -> bool:
        """
        Remove an IOC from the database.
        
        Args:
            value: IOC value to remove
            ioc_type: Type of IOC
            
        Returns:
            True if removed successfully
        """
        try:
            self.iocs[ioc_type].discard(value)
            self.ioc_details.pop(value, None)
            
            self.stats["unique_iocs"] = sum(len(ioc_set) for ioc_set in self.iocs.values())
            
            logger.debug("IOC removed from database", 
                        value=value, type=ioc_type.value)
            
            return True
            
        except Exception as e:
            logger.error("Failed to remove IOC", value=value, error=str(e))
            return False
    
    def _load_default_iocs(self) -> None:
        """Load default malicious IOCs"""
        # Sample malicious indicators for demonstration
        default_iocs = [
            IOC(
                value="192.168.1.100",  # Example IP (normally would be real malicious IP)
                ioc_type=IOCType.IP_ADDRESS,
                threat_level="high",
                description="Known C2 server",
                source="threat_intel",
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-15T00:00:00Z",
                tags=["c2", "malware"],
                confidence=0.9
            ),
            IOC(
                value="evil.com",
                ioc_type=IOCType.DOMAIN,
                threat_level="critical",
                description="Malware distribution domain",
                source="threat_intel",
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-15T00:00:00Z",
                tags=["malware", "phishing"],
                confidence=0.95
            ),
            IOC(
                value="44d88612fea8a8f36de82e1278abb02f",  # Example MD5
                ioc_type=IOCType.FILE_HASH,
                threat_level="high",
                description="Known malware hash",
                source="sandbox_analysis",
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-15T00:00:00Z",
                tags=["malware", "trojan"],
                confidence=0.9
            ),
            IOC(
                value="malware@evil.com",
                ioc_type=IOCType.EMAIL,
                threat_level="medium",
                description="Phishing email sender",
                source="email_security",
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-15T00:00:00Z",
                tags=["phishing", "email"],
                confidence=0.8
            )
        ]
        
        for ioc in default_iocs:
            self.add_ioc(ioc)
        
        self.stats["last_update_time"] = datetime.now().isoformat()
        
        logger.info("Default IOCs loaded", count=len(default_iocs))
    
    def update_iocs_from_feed(self, feed_data: List[Dict[str, Any]]) -> int:
        """
        Update IOCs from threat intelligence feed.
        
        Args:
            feed_data: List of IOC dictionaries from feed
            
        Returns:
            Number of IOCs added
        """
        added_count = 0
        
        for ioc_data in feed_data:
            try:
                ioc = IOC(
                    value=ioc_data["value"],
                    ioc_type=IOCType(ioc_data["type"]),
                    threat_level=ioc_data.get("threat_level", "medium"),
                    description=ioc_data.get("description", ""),
                    source=ioc_data.get("source", "feed"),
                    first_seen=ioc_data.get("first_seen", datetime.now().isoformat()),
                    last_seen=ioc_data.get("last_seen", datetime.now().isoformat()),
                    tags=ioc_data.get("tags", []),
                    confidence=ioc_data.get("confidence", 0.8)
                )
                
                if self.add_ioc(ioc):
                    added_count += 1
                    
            except Exception as e:
                logger.warning("Failed to add IOC from feed", 
                             ioc_data=ioc_data, error=str(e))
        
        self.stats["last_update_time"] = datetime.now().isoformat()
        
        logger.info("IOCs updated from feed", added=added_count, total=len(feed_data))
        
        return added_count
    
    def get_ioc_stats(self) -> Dict[str, Any]:
        """Get IOC database statistics"""
        stats = dict(self.stats)
        
        # Add per-type counts
        stats["ioc_counts_by_type"] = {
            ioc_type.value: len(ioc_set)
            for ioc_type, ioc_set in self.iocs.items()
        }
        
        return stats
    
    def search_iocs(self, query: str, ioc_type: Optional[IOCType] = None) -> List[Dict[str, Any]]:
        """
        Search for IOCs in the database.
        
        Args:
            query: Search query
            ioc_type: Optional IOC type filter
            
        Returns:
            List of matching IOCs
        """
        results = []
        
        search_types = [ioc_type] if ioc_type else list(IOCType)
        
        for search_type in search_types:
            for value in self.iocs[search_type]:
                if query.lower() in value.lower():
                    ioc_details = self.ioc_details.get(value)
                    if ioc_details:
                        results.append({
                            "value": value,
                            "type": search_type.value,
                            "threat_level": ioc_details.threat_level,
                            "description": ioc_details.description,
                            "source": ioc_details.source,
                            "tags": ioc_details.tags
                        })
        
        return results 