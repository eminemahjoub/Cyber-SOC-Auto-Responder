"""
Cyber-SOC Auto-Responder YARA Scanner

This module provides YARA-based malware detection and file analysis
capabilities for automated threat scanning.
"""

import os
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

import yara

from config.logger_config import get_logger, log_security_event
from config.settings import YaraSettings

logger = get_logger(__name__)

class YaraScanner:
    """
    YARA-based malware scanner for file analysis and threat detection.
    """
    
    def __init__(self, settings: YaraSettings):
        self.settings = settings
        self.rules = None
        self.rules_loaded_at = None
        self.rules_path = Path(settings.rules_path)
        
        # Ensure rules directory exists
        self.rules_path.mkdir(parents=True, exist_ok=True)
        
        # Scan statistics
        self.scan_stats = {
            "total_scans": 0,
            "malware_detected": 0,
            "false_positives": 0,
            "last_scan_time": None
        }
        
    def load_rules(self) -> None:
        """Load YARA rules from the rules directory"""
        try:
            start_time = time.time()
            
            # Find all .yar and .yara files
            rule_files = []
            for pattern in ["*.yar", "*.yara"]:
                rule_files.extend(self.rules_path.glob(pattern))
            
            if not rule_files:
                # Create some basic rules if none exist
                self._create_default_rules()
                rule_files = list(self.rules_path.glob("*.yar"))
            
            # Compile rules
            rule_dict = {}
            for rule_file in rule_files:
                try:
                    rule_name = rule_file.stem
                    rule_dict[rule_name] = str(rule_file)
                    logger.debug("Loading YARA rule", rule_file=str(rule_file))
                except Exception as e:
                    logger.warning("Failed to load YARA rule", 
                                 rule_file=str(rule_file), error=str(e))
            
            if rule_dict:
                self.rules = yara.compile(filepaths=rule_dict)
                self.rules_loaded_at = datetime.now()
                
                duration_ms = int((time.time() - start_time) * 1000)
                logger.info("YARA rules loaded successfully",
                           rule_count=len(rule_dict),
                           duration_ms=duration_ms)
            else:
                raise Exception("No valid YARA rules found")
                
        except Exception as e:
            logger.error("Failed to load YARA rules", error=str(e))
            raise
    
    def _create_default_rules(self) -> None:
        """Create default YARA rules for basic malware detection"""
        default_rules = {
            "common_malware.yar": '''
rule Suspicious_PE_Features
{
    meta:
        description = "Detects suspicious PE file features"
        author = "Cyber-SOC Auto-Responder"
        category = "malware"
        
    strings:
        $packer1 = "UPX" ascii
        $packer2 = "FSG" ascii
        $packer3 = "PECompact" ascii
        $debug1 = "Microsoft Visual C++" ascii
        $debug2 = "Borland" ascii
        
    condition:
        uint16(0) == 0x5A4D and (any of ($packer*) and not any of ($debug*))
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects suspicious network-related strings"
        author = "Cyber-SOC Auto-Responder"
        category = "network"
        
    strings:
        $url1 = "http://" ascii
        $url2 = "https://" ascii
        $ip_regex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
        $suspicious1 = "cmd.exe" ascii nocase
        $suspicious2 = "powershell" ascii nocase
        $suspicious3 = "wget" ascii nocase
        $suspicious4 = "curl" ascii nocase
        
    condition:
        (any of ($url*) or $ip_regex) and any of ($suspicious*)
}

rule Ransomware_Indicators
{
    meta:
        description = "Detects common ransomware indicators"
        author = "Cyber-SOC Auto-Responder"
        category = "ransomware"
        severity = "high"
        
    strings:
        $encrypt1 = "encrypt" ascii nocase
        $encrypt2 = "decrypt" ascii nocase
        $encrypt3 = "crypto" ascii nocase
        $ransom1 = "bitcoin" ascii nocase
        $ransom2 = "payment" ascii nocase
        $ransom3 = "unlock" ascii nocase
        $file_ext1 = ".encrypted" ascii
        $file_ext2 = ".locked" ascii
        $file_ext3 = ".crypto" ascii
        
    condition:
        (any of ($encrypt*) and any of ($ransom*)) or any of ($file_ext*)
}

rule Keylogger_Indicators
{
    meta:
        description = "Detects keylogger-related functionality"
        author = "Cyber-SOC Auto-Responder"
        category = "keylogger"
        
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetKeyboardState" ascii
        $log1 = "keylog" ascii nocase
        $log2 = "keystroke" ascii nocase
        
    condition:
        any of ($api*) or any of ($log*)
}
''',
            
            "credential_theft.yar": '''
rule Password_Dumping_Tools
{
    meta:
        description = "Detects password dumping tool indicators"
        author = "Cyber-SOC Auto-Responder"
        category = "credential_theft"
        severity = "high"
        
    strings:
        $tool1 = "mimikatz" ascii nocase
        $tool2 = "pwdump" ascii nocase
        $tool3 = "gsecdump" ascii nocase
        $tool4 = "wce.exe" ascii nocase
        $lsass1 = "lsass.exe" ascii nocase
        $lsass2 = "sekurlsa" ascii nocase
        $sam1 = "SAM" ascii
        $sam2 = "SYSTEM" ascii
        
    condition:
        any of ($tool*) or (any of ($lsass*) and any of ($sam*))
}

rule Browser_Credential_Theft
{
    meta:
        description = "Detects browser credential theft attempts"
        author = "Cyber-SOC Auto-Responder"
        category = "credential_theft"
        
    strings:
        $chrome1 = "Chrome/User Data" ascii
        $chrome2 = "Login Data" ascii
        $firefox1 = "Firefox/Profiles" ascii
        $firefox2 = "logins.json" ascii
        $ie1 = "Internet Explorer" ascii
        $ie2 = "Vault" ascii
        $decrypt1 = "CryptUnprotectData" ascii
        
    condition:
        (any of ($chrome*) or any of ($firefox*) or any of ($ie*)) and $decrypt1
}
''',
            
            "persistence_mechanisms.yar": '''
rule Registry_Persistence
{
    meta:
        description = "Detects registry-based persistence mechanisms"
        author = "Cyber-SOC Auto-Responder"
        category = "persistence"
        
    strings:
        $reg1 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii nocase
        $reg2 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce" ascii nocase
        $reg3 = "SYSTEM\\\\CurrentControlSet\\\\Services" ascii nocase
        $reg4 = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon" ascii nocase
        $api1 = "RegCreateKey" ascii
        $api2 = "RegSetValue" ascii
        
    condition:
        any of ($reg*) and any of ($api*)
}

rule Scheduled_Task_Persistence
{
    meta:
        description = "Detects scheduled task persistence"
        author = "Cyber-SOC Auto-Responder"
        category = "persistence"
        
    strings:
        $task1 = "schtasks" ascii nocase
        $task2 = "at.exe" ascii nocase
        $task3 = "TaskScheduler" ascii
        $create1 = "/create" ascii
        $create2 = "/sc" ascii
        
    condition:
        any of ($task*) and any of ($create*)
}
'''
        }
        
        # Write default rules to files
        for filename, content in default_rules.items():
            rule_file = self.rules_path / filename
            with open(rule_file, 'w') as f:
                f.write(content.strip())
        
        logger.info("Created default YARA rules", 
                   count=len(default_rules), 
                   location=str(self.rules_path))
    
    def scan_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Scan a file for malware using YARA rules.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary containing scan results
        """
        try:
            start_time = time.time()
            file_path = Path(file_path)
            
            # Check if rules need to be loaded/reloaded
            self._check_rules_update()
            
            if not self.rules:
                raise Exception("YARA rules not loaded")
            
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get file information
            file_info = self._get_file_info(file_path)
            
            # Perform YARA scan
            matches = self.rules.match(str(file_path))
            
            # Process matches
            scan_result = self._process_matches(matches, file_info)
            
            # Update statistics
            self.scan_stats["total_scans"] += 1
            self.scan_stats["last_scan_time"] = datetime.now().isoformat()
            
            if scan_result["malware_detected"]:
                self.scan_stats["malware_detected"] += 1
                
                # Log security event
                log_security_event(
                    logger, "malware_detected",
                    f"Malware detected in file: {file_path}",
                    indicators=[str(file_path)] + scan_result["rule_matches"]
                )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            logger.info("File scan completed",
                       file_path=str(file_path),
                       malware_detected=scan_result["malware_detected"],
                       rule_matches=len(scan_result["rule_matches"]),
                       duration_ms=duration_ms)
            
            return scan_result
            
        except Exception as e:
            logger.error("File scan failed", 
                        file_path=str(file_path), error=str(e))
            return {
                "success": False,
                "malware_detected": False,
                "error": str(e),
                "file_path": str(file_path),
                "scan_time": datetime.now().isoformat()
            }
    
    def scan_data(self, data: bytes, identifier: str = "memory_data") -> Dict[str, Any]:
        """
        Scan raw data for malware.
        
        Args:
            data: Raw bytes to scan
            identifier: Identifier for the data being scanned
            
        Returns:
            Dictionary containing scan results
        """
        try:
            start_time = time.time()
            
            # Check if rules need to be loaded/reloaded
            self._check_rules_update()
            
            if not self.rules:
                raise Exception("YARA rules not loaded")
            
            # Perform YARA scan on data
            matches = self.rules.match(data=data)
            
            # Create basic file info
            file_info = {
                "name": identifier,
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "type": "data"
            }
            
            # Process matches
            scan_result = self._process_matches(matches, file_info)
            
            # Update statistics
            self.scan_stats["total_scans"] += 1
            self.scan_stats["last_scan_time"] = datetime.now().isoformat()
            
            if scan_result["malware_detected"]:
                self.scan_stats["malware_detected"] += 1
                
                # Log security event
                log_security_event(
                    logger, "malware_detected",
                    f"Malware detected in data: {identifier}",
                    indicators=[identifier] + scan_result["rule_matches"]
                )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            logger.info("Data scan completed",
                       identifier=identifier,
                       data_size=len(data),
                       malware_detected=scan_result["malware_detected"],
                       rule_matches=len(scan_result["rule_matches"]),
                       duration_ms=duration_ms)
            
            return scan_result
            
        except Exception as e:
            logger.error("Data scan failed", 
                        identifier=identifier, error=str(e))
            return {
                "success": False,
                "malware_detected": False,
                "error": str(e),
                "identifier": identifier,
                "scan_time": datetime.now().isoformat()
            }
    
    def _check_rules_update(self) -> None:
        """Check if rules need to be updated"""
        if not self.rules or not self.rules_loaded_at:
            self.load_rules()
            return
        
        # Check if update interval has passed
        if self.settings.update_interval > 0:
            time_since_load = (datetime.now() - self.rules_loaded_at).seconds
            if time_since_load > self.settings.update_interval:
                logger.info("Reloading YARA rules due to update interval")
                self.load_rules()
    
    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            stat = file_path.stat()
            
            # Calculate file hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
            
            return {
                "name": file_path.name,
                "path": str(file_path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "md5": md5_hash,
                "sha256": sha256_hash,
                "type": self._detect_file_type(file_path, content)
            }
            
        except Exception as e:
            logger.error("Failed to get file info", 
                        file_path=str(file_path), error=str(e))
            return {
                "name": file_path.name,
                "path": str(file_path),
                "size": 0,
                "error": str(e)
            }
    
    def _detect_file_type(self, file_path: Path, content: bytes) -> str:
        """Detect file type based on magic bytes and extension"""
        # Check magic bytes
        if content.startswith(b'MZ'):
            return "pe_executable"
        elif content.startswith(b'\x7fELF'):
            return "elf_executable"
        elif content.startswith(b'%PDF'):
            return "pdf"
        elif content.startswith(b'PK'):
            return "zip_archive"
        elif content.startswith(b'\x50\x4b\x03\x04'):
            return "office_document"
        
        # Check file extension
        extension = file_path.suffix.lower()
        extension_map = {
            '.exe': 'pe_executable',
            '.dll': 'pe_library',
            '.bat': 'batch_script',
            '.ps1': 'powershell_script',
            '.vbs': 'vbscript',
            '.js': 'javascript',
            '.jar': 'java_archive',
            '.pdf': 'pdf',
            '.doc': 'office_document',
            '.docx': 'office_document',
            '.xls': 'office_document',
            '.xlsx': 'office_document'
        }
        
        return extension_map.get(extension, "unknown")
    
    def _process_matches(self, matches: List[yara.Match], file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process YARA rule matches into scan result"""
        rule_matches = []
        severity_scores = []
        categories = set()
        
        for match in matches:
            rule_info = {
                "rule_name": match.rule,
                "namespace": match.namespace,
                "meta": dict(match.meta),
                "strings": []
            }
            
            # Process matched strings
            for string_match in match.strings:
                rule_info["strings"].append({
                    "identifier": string_match.identifier,
                    "instances": [
                        {
                            "offset": instance.offset,
                            "matched_data": instance.matched_data[:100]  # Limit to first 100 bytes
                        }
                        for instance in string_match.instances
                    ]
                })
            
            rule_matches.append(rule_info)
            
            # Extract severity and category from meta
            meta = dict(match.meta)
            category = meta.get("category", "unknown")
            categories.add(category)
            
            # Calculate severity score
            severity = meta.get("severity", "medium")
            severity_score = {
                "low": 3.0,
                "medium": 5.0,
                "high": 7.0,
                "critical": 9.0
            }.get(severity, 5.0)
            severity_scores.append(severity_score)
        
        # Calculate overall threat score
        if severity_scores:
            threat_score = max(severity_scores)  # Use highest severity
            if len(severity_scores) > 1:
                threat_score += min(1.0, len(severity_scores) * 0.2)  # Bonus for multiple matches
        else:
            threat_score = 0.0
        
        return {
            "success": True,
            "malware_detected": len(matches) > 0,
            "rule_matches": [match.rule for match in matches],
            "detailed_matches": rule_matches,
            "threat_score": round(threat_score, 1),
            "categories": list(categories),
            "file_info": file_info,
            "scan_time": datetime.now().isoformat(),
            "scanner_version": "yara-python",
            "rules_loaded_at": self.rules_loaded_at.isoformat() if self.rules_loaded_at else None
        }
    
    def update_rules(self, rules_source: Optional[str] = None) -> bool:
        """
        Update YARA rules from external source.
        
        Args:
            rules_source: Optional source URL or path for rules
            
        Returns:
            True if update was successful
        """
        try:
            logger.info("Updating YARA rules", source=rules_source)
            
            # For now, just reload existing rules
            # In production, you might want to download from a rules repository
            self.load_rules()
            
            logger.info("YARA rules updated successfully")
            return True
            
        except Exception as e:
            logger.error("Failed to update YARA rules", error=str(e))
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return {
            **self.scan_stats,
            "rules_loaded": self.rules is not None,
            "rules_loaded_at": self.rules_loaded_at.isoformat() if self.rules_loaded_at else None,
            "rules_path": str(self.rules_path)
        }
    
    def health_check(self) -> bool:
        """Check scanner health"""
        try:
            return self.rules is not None
        except Exception:
            return False 