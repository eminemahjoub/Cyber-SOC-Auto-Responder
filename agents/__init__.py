"""
Cyber-SOC Auto-Responder Agents Package

This package contains AI agents for different aspects of incident response:
- Triage Agent: Alert analysis and severity scoring
- Scanner Agent: File and malware analysis coordination  
- Response Agent: Host isolation and remediation actions
- Case Agent: Incident ticket management
"""

from .triage_agent import TriageAgent
from .scanner_agent import ScannerAgent
from .response_agent import ResponseAgent
from .case_agent import CaseAgent

__all__ = [
    "TriageAgent",
    "ScannerAgent", 
    "ResponseAgent",
    "CaseAgent"
] 