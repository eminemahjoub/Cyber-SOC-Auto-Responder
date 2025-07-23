"""
Cyber-SOC Auto-Responder File Analyzer

This module provides file analysis capabilities including metadata extraction,
hash calculation, and file type detection for security analysis.
"""

import os
import hashlib
import mimetypes
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import json

from config.logger_config import get_logger

logger = get_logger(__name__)

class FileAnalyzer:
    """
    File analyzer for extracting metadata, calculating hashes, and analyzing file properties.
    """
    
    def __init__(self):
        # Known malicious file extensions
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.jar', '.js', '.jse',
            '.vbs', '.vbe', '.ps1', '.ps2', '.wsf', '.wsh', '.msi', '.reg'
        }
        
        # Archive extensions that might contain malware
        self.archive_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'
        }
        
        # Office document extensions
        self.office_extensions = {
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf'
        }
        
        # Analysis statistics
        self.stats = {
            "files_analyzed": 0,
            "suspicious_files": 0,
            "malware_hashes": set(),
            "last_analysis_time": None
        }
    
    def analyze_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Perform comprehensive file analysis.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            start_time = time.time()
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Basic file information
            basic_info = self._get_basic_info(file_path)
            
            # File hashes
            hashes = self._calculate_hashes(file_path)
            
            # Magic bytes and file type detection
            file_type_info = self._analyze_file_type(file_path)
            
            # Metadata extraction
            metadata = self._extract_metadata(file_path)
            
            # Security analysis
            security_analysis = self._security_analysis(file_path, basic_info, file_type_info)
            
            # Combine all analysis results
            analysis_result = {
                "success": True,
                "file_path": str(file_path),
                "analysis_time": datetime.now().isoformat(),
                "basic_info": basic_info,
                "hashes": hashes,
                "file_type": file_type_info,
                "metadata": metadata,
                "security": security_analysis,
                "duration_ms": int((time.time() - start_time) * 1000)
            }
            
            # Update statistics
            self.stats["files_analyzed"] += 1
            self.stats["last_analysis_time"] = datetime.now().isoformat()
            
            if security_analysis.get("is_suspicious"):
                self.stats["suspicious_files"] += 1
            
            logger.info("File analysis completed",
                       file_path=str(file_path),
                       is_suspicious=security_analysis.get("is_suspicious", False),
                       duration_ms=analysis_result["duration_ms"])
            
            return analysis_result
            
        except Exception as e:
            logger.error("File analysis failed", 
                        file_path=str(file_path), error=str(e))
            return {
                "success": False,
                "error": str(e),
                "file_path": str(file_path),
                "analysis_time": datetime.now().isoformat()
            }
    
    def _get_basic_info(self, file_path: Path) -> Dict[str, Any]:
        """Extract basic file information"""
        try:
            stat = file_path.stat()
            
            return {
                "name": file_path.name,
                "extension": file_path.suffix.lower(),
                "size_bytes": stat.st_size,
                "size_human": self._format_size(stat.st_size),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:],
                "is_hidden": file_path.name.startswith('.'),
                "parent_directory": str(file_path.parent)
            }
            
        except Exception as e:
            logger.error("Failed to get basic file info", error=str(e))
            return {"error": str(e)}
    
    def _calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate multiple hash types for the file"""
        try:
            hashes = {
                "md5": hashlib.md5(),
                "sha1": hashlib.sha1(), 
                "sha256": hashlib.sha256()
            }
            
            # Read file in chunks to handle large files
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {
                name: hash_obj.hexdigest() 
                for name, hash_obj in hashes.items()
            }
            
        except Exception as e:
            logger.error("Failed to calculate file hashes", error=str(e))
            return {"error": str(e)}
    
    def _analyze_file_type(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file type using multiple methods"""
        try:
            result = {
                "extension_based": None,
                "mime_type": None,
                "magic_bytes": None,
                "detected_type": None,
                "type_mismatch": False
            }
            
            # Extension-based detection
            extension = file_path.suffix.lower()
            result["extension_based"] = self._get_type_from_extension(extension)
            
            # MIME type detection
            mime_type, _ = mimetypes.guess_type(str(file_path))
            result["mime_type"] = mime_type
            
            # Magic bytes analysis
            with open(file_path, 'rb') as f:
                header = f.read(64)  # Read first 64 bytes
                result["magic_bytes"] = header.hex()
                result["detected_type"] = self._get_type_from_magic_bytes(header)
            
            # Determine actual file type
            if result["detected_type"]:
                result["actual_type"] = result["detected_type"]
            elif result["mime_type"]:
                result["actual_type"] = result["mime_type"]
            else:
                result["actual_type"] = result["extension_based"]
            
            # Check for type mismatch (possible evasion attempt)
            if (result["extension_based"] and result["detected_type"] and 
                result["extension_based"] != result["detected_type"]):
                result["type_mismatch"] = True
            
            return result
            
        except Exception as e:
            logger.error("Failed to analyze file type", error=str(e))
            return {"error": str(e)}
    
    def _get_type_from_extension(self, extension: str) -> Optional[str]:
        """Get file type based on extension"""
        extension_map = {
            '.exe': 'pe_executable',
            '.dll': 'pe_library',
            '.sys': 'system_driver',
            '.bat': 'batch_script',
            '.cmd': 'batch_script',
            '.ps1': 'powershell_script',
            '.vbs': 'vbscript',
            '.js': 'javascript',
            '.jar': 'java_archive',
            '.pdf': 'pdf_document',
            '.doc': 'word_document',
            '.docx': 'word_document',
            '.xls': 'excel_document',
            '.xlsx': 'excel_document',
            '.zip': 'zip_archive',
            '.rar': 'rar_archive',
            '.7z': '7zip_archive'
        }
        return extension_map.get(extension)
    
    def _get_type_from_magic_bytes(self, header: bytes) -> Optional[str]:
        """Detect file type from magic bytes"""
        if header.startswith(b'MZ'):
            return 'pe_executable'
        elif header.startswith(b'\x7fELF'):
            return 'elf_executable'
        elif header.startswith(b'%PDF'):
            return 'pdf_document'
        elif header.startswith(b'PK\x03\x04'):
            return 'zip_archive'
        elif header.startswith(b'Rar!'):
            return 'rar_archive'
        elif header.startswith(b'\x37\x7a\xbc\xaf\x27\x1c'):
            return '7zip_archive'
        elif header.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
            return 'ole_document'  # MS Office old format
        elif header.startswith(b'\x50\x4b\x03\x04') and b'word/' in header[:1024]:
            return 'word_document'
        elif header.startswith(b'\x50\x4b\x03\x04') and b'xl/' in header[:1024]:
            return 'excel_document'
        elif header.startswith(b'\xff\xd8\xff'):
            return 'jpeg_image'
        elif header.startswith(b'\x89PNG'):
            return 'png_image'
        
        return None
    
    def _extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract file metadata based on file type"""
        try:
            metadata = {}
            
            # Try to extract PE metadata for executables
            if file_path.suffix.lower() in ['.exe', '.dll']:
                metadata.update(self._extract_pe_metadata(file_path))
            
            # Try to extract archive metadata
            elif file_path.suffix.lower() in self.archive_extensions:
                metadata.update(self._extract_archive_metadata(file_path))
            
            return metadata
            
        except Exception as e:
            logger.error("Failed to extract metadata", error=str(e))
            return {"error": str(e)}
    
    def _extract_pe_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract PE (Portable Executable) metadata"""
        try:
            metadata = {}
            
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return metadata
                
                # Get PE header offset
                pe_offset = int.from_bytes(dos_header[60:64], 'little')
                f.seek(pe_offset)
                
                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return metadata
                
                # Read COFF header
                coff_header = f.read(20)
                if len(coff_header) < 20:
                    return metadata
                
                machine = int.from_bytes(coff_header[0:2], 'little')
                sections = int.from_bytes(coff_header[2:4], 'little')
                timestamp = int.from_bytes(coff_header[4:8], 'little')
                
                metadata.update({
                    "pe_format": True,
                    "machine_type": self._get_machine_type(machine),
                    "section_count": sections,
                    "compile_timestamp": datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None,
                    "architecture": "x64" if machine == 0x8664 else "x86"
                })
            
            return metadata
            
        except Exception as e:
            logger.debug("Failed to extract PE metadata", error=str(e))
            return {}
    
    def _get_machine_type(self, machine: int) -> str:
        """Convert machine type to human-readable string"""
        machine_types = {
            0x014c: "i386",
            0x0200: "ia64", 
            0x8664: "amd64",
            0x01c4: "arm",
            0xaa64: "arm64"
        }
        return machine_types.get(machine, f"unknown_{machine:04x}")
    
    def _extract_archive_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract archive metadata"""
        try:
            metadata = {"is_archive": True}
            
            # This is a simplified implementation
            # In production, you might want to use libraries like zipfile, rarfile, etc.
            
            return metadata
            
        except Exception as e:
            logger.debug("Failed to extract archive metadata", error=str(e))
            return {}
    
    def _security_analysis(self, file_path: Path, basic_info: Dict[str, Any], file_type_info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security-focused analysis"""
        try:
            security_flags = []
            risk_score = 0.0
            
            # Check for suspicious extensions
            extension = basic_info.get("extension", "").lower()
            if extension in self.suspicious_extensions:
                security_flags.append("suspicious_extension")
                risk_score += 3.0
            
            # Check for hidden files
            if basic_info.get("is_hidden"):
                security_flags.append("hidden_file")
                risk_score += 1.0
            
            # Check for type mismatch
            if file_type_info.get("type_mismatch"):
                security_flags.append("type_mismatch")
                risk_score += 4.0
            
            # Check file size (very small or very large files can be suspicious)
            size = basic_info.get("size_bytes", 0)
            if size < 1024:  # Very small executable
                if extension in ['.exe', '.dll']:
                    security_flags.append("unusually_small_executable")
                    risk_score += 2.0
            elif size > 100 * 1024 * 1024:  # Very large file (>100MB)
                security_flags.append("unusually_large_file")
                risk_score += 1.0
            
            # Check for double extensions
            filename = basic_info.get("name", "")
            if filename.count('.') > 1:
                parts = filename.split('.')
                if len(parts) >= 3 and parts[-2] in ['txt', 'pdf', 'doc', 'jpg']:
                    security_flags.append("double_extension")
                    risk_score += 3.0
            
            # Check for suspicious names
            suspicious_names = [
                'svchost', 'csrss', 'winlogon', 'explorer', 'system32',
                'temp', 'tmp', 'cache', 'update', 'patch'
            ]
            
            if any(name in filename.lower() for name in suspicious_names):
                security_flags.append("suspicious_filename")
                risk_score += 2.0
            
            # Determine overall suspicion level
            is_suspicious = risk_score >= 3.0 or len(security_flags) >= 2
            
            return {
                "is_suspicious": is_suspicious,
                "risk_score": round(risk_score, 1),
                "security_flags": security_flags,
                "recommendations": self._generate_recommendations(security_flags, risk_score)
            }
            
        except Exception as e:
            logger.error("Failed to perform security analysis", error=str(e))
            return {"error": str(e)}
    
    def _generate_recommendations(self, security_flags: List[str], risk_score: float) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if "suspicious_extension" in security_flags:
            recommendations.append("Verify file legitimacy before execution")
        
        if "type_mismatch" in security_flags:
            recommendations.append("Investigate potential file masquerading")
        
        if "double_extension" in security_flags:
            recommendations.append("Check for social engineering attempts")
        
        if "hidden_file" in security_flags:
            recommendations.append("Review file hiding techniques")
        
        if risk_score >= 5.0:
            recommendations.append("Perform detailed malware analysis")
            recommendations.append("Consider sandboxed execution")
        
        if risk_score >= 7.0:
            recommendations.append("Block file execution")
            recommendations.append("Quarantine immediately")
        
        return recommendations
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def batch_analyze(self, file_paths: List[Union[str, Path]]) -> List[Dict[str, Any]]:
        """Analyze multiple files in batch"""
        results = []
        
        for file_path in file_paths:
            try:
                result = self.analyze_file(file_path)
                results.append(result)
            except Exception as e:
                results.append({
                    "success": False,
                    "error": str(e),
                    "file_path": str(file_path)
                })
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            **self.stats,
            "malware_hashes_count": len(self.stats["malware_hashes"])
        }
    
    def add_malware_hash(self, hash_value: str) -> None:
        """Add a known malware hash to the database"""
        self.stats["malware_hashes"].add(hash_value)
    
    def is_known_malware(self, hash_value: str) -> bool:
        """Check if a hash is known malware"""
        return hash_value in self.stats["malware_hashes"] 