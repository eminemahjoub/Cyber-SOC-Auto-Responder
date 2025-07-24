"""
Cyber-SOC Auto-Responder Agents Package

This package contains AI agents for different aspects of incident response:
- Triage Agent: Alert analysis and severity scoring
- Scanner Agent: File and malware analysis coordination  
"""

from .triage_agent import TriageAgent
from .scanner_agent import ScannerAgent

__all__ = [
    "TriageAgent",
    "ScannerAgent", 
] 