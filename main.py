"""
Main Production Orchestrator (DEPRECATED - Use opensource_production.py instead)

This file is kept for reference but the active system is now opensource_production.py
which uses WazuhConnector, OpenVASConnector, and VirusTotalConnector only.
"""

# Deprecated - Use opensource_production.py instead
# class SOCOrchestrator:
#     """Main orchestrator for the SOC automation system."""
#     def __init__(self, settings: Settings):
#         # These connectors have been removed - use opensource_production.py
#         pass

# The main entry point now uses opensource_production.py
from opensource_production import main

if __name__ == "__main__":
    # Redirect to the open-source production system
    print("🔄 Redirecting to Open-Source Production System...")
    print("📌 Use: python opensource_production.py")
    import asyncio
    asyncio.run(main()) 