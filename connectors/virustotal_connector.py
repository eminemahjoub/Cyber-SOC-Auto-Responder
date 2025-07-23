"""
VirusTotal Connector for Enhanced Open-Source SOC
Provides threat intelligence enhancement to the open-source stack.
"""

import asyncio
import json
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import aiohttp

logger = logging.getLogger(__name__)

class VirusTotalConnector:
    """VirusTotal connector for enhanced threat intelligence."""
    
    def __init__(self, config=None):
        """Initialize VirusTotal connector."""
        self.config = config or {}
        self.api_key = getattr(config, 'virustotal_api_key', 'f5819e00da02b057ec600673a825e42bbc5dcb7066c79a8ac7e352c9b6fd1979')
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.base_url_v3 = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15  # seconds between requests for free API
        self.session = None
        self.is_connected = False
        
        logger.info("VirusTotal connector initialized for open-source enhancement")
    
    async def connect(self) -> bool:
        """Initialize VirusTotal connection."""
        try:
            self.session = aiohttp.ClientSession(
                headers={
                    'x-apikey': self.api_key,
                    'User-Agent': 'OpenSource-CyberSOC/1.0'
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            # Test API key validity
            test_result = await self._test_api_key()
            if test_result:
                self.is_connected = True
                logger.info("✅ Successfully connected to VirusTotal API")
                return True
            else:
                logger.warning("⚠️  VirusTotal API key test failed - continuing without VT enhancement")
                self.is_connected = False
                return False
            
        except Exception as e:
            logger.error(f"VirusTotal connection failed: {str(e)}")
            self.is_connected = False
            return False
    
    async def analyze_alert_iocs(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze all IOCs from an alert."""
        if not self.is_connected:
            await self.connect()
        
        if not self.is_connected:
            return {
                "success": False,
                "error": "VirusTotal not available",
                "enhancement_available": False
            }
        
        results = {
            "success": True,
            "alert_id": alert.get("id", "unknown"),
            "enhancement_source": "virustotal",
            "ioc_results": {
                "files": [],
                "ips": [],
                "urls": [],
                "domains": []
            },
            "threat_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0
        }
        
        try:
            # Extract IOCs from alert
            iocs = self._extract_iocs_from_alert(alert)
            
            logger.info(f"🦠 Analyzing {sum(len(v) for v in iocs.values())} IOCs with VirusTotal")
            
            # Scan file hashes
            for file_hash in iocs.get("file_hashes", []):
                result = await self.scan_file_hash(file_hash)
                results["ioc_results"]["files"].append(result)
                if result.get("malicious", False):
                    results["malicious_count"] += 1
                elif result.get("suspicious", False):
                    results["suspicious_count"] += 1
            
            # Scan IP addresses
            for ip in iocs.get("ip_addresses", []):
                result = await self.scan_ip_reputation(ip)
                results["ioc_results"]["ips"].append(result)
                if result.get("malicious", False):
                    results["malicious_count"] += 1
                elif result.get("suspicious", False):
                    results["suspicious_count"] += 1
            
            # Scan URLs
            for url in iocs.get("urls", []):
                result = await self.scan_url_reputation(url)
                results["ioc_results"]["urls"].append(result)
                if result.get("malicious", False):
                    results["malicious_count"] += 1
                elif result.get("suspicious", False):
                    results["suspicious_count"] += 1
            
            # Scan domains
            for domain in iocs.get("domains", []):
                result = await self.scan_domain_reputation(domain)
                results["ioc_results"]["domains"].append(result)
                if result.get("malicious", False):
                    results["malicious_count"] += 1
                elif result.get("suspicious", False):
                    results["suspicious_count"] += 1
            
            # Calculate threat score
            total_iocs = sum(len(v) for v in iocs.values())
            if total_iocs > 0:
                malicious_ratio = results["malicious_count"] / total_iocs
                suspicious_ratio = results["suspicious_count"] / total_iocs
                results["threat_score"] = (malicious_ratio * 10) + (suspicious_ratio * 5)
            
            logger.info(f"🎯 VirusTotal Results: {results['malicious_count']} malicious, {results['suspicious_count']} suspicious")
            
            return results
            
        except Exception as e:
            logger.error(f"VirusTotal IOC analysis failed: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            return results
    
    async def scan_file_hash(self, file_hash: str, hash_type: str = "sha256") -> Dict[str, Any]:
        """Scan file hash for malware detection."""
        try:
            if not self.session:
                return {"success": False, "error": "Not connected"}
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
            # Use v3 API for better results
            url = f"{self.base_url_v3}/files/{file_hash}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._parse_file_report(data, file_hash)
                elif response.status == 404:
                    return {
                        "success": True,
                        "file_hash": file_hash,
                        "found": False,
                        "message": "File not found in VirusTotal database"
                    }
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return {"success": False, "error": f"API error: {response.status}"}
            
        except Exception as e:
            logger.error(f"File hash scan failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def scan_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address reputation."""
        try:
            if not self.session:
                return {"success": False, "error": "Not connected"}
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
            url = f"{self.base_url_v3}/ip_addresses/{ip_address}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._parse_ip_report(data, ip_address)
                else:
                    logger.error(f"VirusTotal IP scan error: {response.status}")
                    return {"success": False, "error": f"API error: {response.status}"}
            
        except Exception as e:
            logger.error(f"IP reputation check failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def scan_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation."""
        try:
            if not self.session:
                return {"success": False, "error": "Not connected"}
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
            # URL needs to be base64 encoded for v3 API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"{self.base_url_v3}/urls/{url_id}"
            
            async with self.session.get(api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._parse_url_report(data, url)
                elif response.status == 404:
                    # URL not found, submit for scanning
                    return await self._submit_url_for_scanning(url)
                else:
                    logger.error(f"VirusTotal URL scan error: {response.status}")
                    return {"success": False, "error": f"API error: {response.status}"}
            
        except Exception as e:
            logger.error(f"URL reputation check failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def scan_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation."""
        try:
            if not self.session:
                return {"success": False, "error": "Not connected"}
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
            url = f"{self.base_url_v3}/domains/{domain}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._parse_domain_report(data, domain)
                else:
                    logger.error(f"VirusTotal domain scan error: {response.status}")
                    return {"success": False, "error": f"API error: {response.status}"}
            
        except Exception as e:
            logger.error(f"Domain reputation check failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _extract_iocs_from_alert(self, alert: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from alert data."""
        iocs = {
            "file_hashes": [],
            "ip_addresses": [],
            "urls": [],
            "domains": []
        }
        
        # Extract from common alert fields
        for field in ["file_hash", "md5", "sha1", "sha256"]:
            if field in alert and alert[field]:
                iocs["file_hashes"].append(alert[field])
        
        for field in ["src_ip", "dest_ip", "source_ip", "destination_ip", "agent_ip"]:
            if field in alert and alert[field]:
                iocs["ip_addresses"].append(alert[field])
        
        for field in ["url", "request_url", "referer"]:
            if field in alert and alert[field]:
                iocs["urls"].append(alert[field])
        
        for field in ["domain", "hostname", "dns_query"]:
            if field in alert and alert[field]:
                iocs["domains"].append(alert[field])
        
        # Extract from indicators list
        indicators = alert.get("indicators", [])
        for indicator in indicators:
            if isinstance(indicator, str):
                # Try to classify the indicator
                if self._is_ip_address(indicator):
                    iocs["ip_addresses"].append(indicator)
                elif self._is_domain(indicator):
                    iocs["domains"].append(indicator)
                elif self._is_hash(indicator):
                    iocs["file_hashes"].append(indicator)
                elif indicator.startswith(("http://", "https://")):
                    iocs["urls"].append(indicator)
        
        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(iocs[key]))
        
        return iocs
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain name."""
        import re
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        return re.match(domain_pattern, value) is not None
    
    def _is_hash(self, value: str) -> bool:
        """Check if value is a file hash."""
        if len(value) in [32, 40, 64, 128]:  # MD5, SHA1, SHA256, SHA512
            return all(c in '0123456789abcdefABCDEF' for c in value)
        return False
    
    async def _test_api_key(self) -> bool:
        """Test VirusTotal API key validity."""
        try:
            url = f"{self.base_url_v3}/users/current"
            async with self.session.get(url) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def _parse_file_report(self, data: Dict, file_hash: str) -> Dict[str, Any]:
        """Parse VirusTotal file report."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        
        return {
            "success": True,
            "file_hash": file_hash,
            "found": True,
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "detection_ratio": f"{malicious + suspicious}/{total_engines}",
            "scan_date": attributes.get("last_analysis_date", ""),
            "threat_names": list(attributes.get("last_analysis_results", {}).keys())[:5],
            "reputation_score": max(malicious * 2, suspicious) if total_engines > 0 else 0
        }
    
    async def _parse_ip_report(self, data: Dict, ip_address: str) -> Dict[str, Any]:
        """Parse VirusTotal IP report."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        return {
            "success": True,
            "ip_address": ip_address,
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "country": attributes.get("country", ""),
            "asn": attributes.get("asn", ""),
            "reputation_score": max(malicious * 2, suspicious),
            "categories": attributes.get("categories", [])
        }
    
    async def _parse_url_report(self, data: Dict, url: str) -> Dict[str, Any]:
        """Parse VirusTotal URL report."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        return {
            "success": True,
            "url": url,
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "reputation_score": max(malicious * 2, suspicious),
            "categories": attributes.get("categories", [])
        }
    
    async def _parse_domain_report(self, data: Dict, domain: str) -> Dict[str, Any]:
        """Parse VirusTotal domain report."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        return {
            "success": True,
            "domain": domain,
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "reputation_score": max(malicious * 2, suspicious),
            "categories": attributes.get("categories", [])
        }
    
    async def _submit_url_for_scanning(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning."""
        try:
            submit_url = f"{self.base_url_v3}/urls"
            data = {"url": url}
            
            async with self.session.post(submit_url, data=data) as response:
                if response.status == 200:
                    return {
                        "success": True,
                        "url": url,
                        "submitted": True,
                        "message": "URL submitted for analysis"
                    }
        except Exception as e:
            logger.error(f"URL submission failed: {str(e)}")
        
        return {"success": False, "error": "URL submission failed"}
    
    async def health_check(self) -> bool:
        """Check VirusTotal connection health."""
        try:
            if not self.is_connected:
                await self.connect()
            
            if self.session and self.is_connected:
                # Test with a simple request
                test_result = await self._test_api_key()
                if test_result:
                    logger.info("VirusTotal health check passed")
                    return True
            
            logger.info("VirusTotal not available - continuing with open-source only")
            return False
            
        except Exception as e:
            logger.warning(f"VirusTotal health check failed: {str(e)} - continuing with open-source only")
            return False
    
    async def disconnect(self):
        """Disconnect from VirusTotal."""
        if self.session:
            await self.session.close()
            self.session = None
            self.is_connected = False
            logger.info("Disconnected from VirusTotal")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics."""
        return {
            "connected": self.is_connected,
            "api_configured": bool(self.api_key),
            "enhancement_available": self.is_connected,
            "rate_limit_delay": self.rate_limit_delay,
            "last_connection_attempt": datetime.now().isoformat()
        } 