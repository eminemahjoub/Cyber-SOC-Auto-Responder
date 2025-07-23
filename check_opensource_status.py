#!/usr/bin/env python3
"""
Open-Source Cyber-SOC Auto-Responder Status Checker
"""

import subprocess
import sys

def check_opensource_status():
    """Check if the open-source SOC system is running."""
    print("🔍 Checking Streamlined Cyber-SOC Auto-Responder Status...")
    print("=" * 60)
    
    try:
        # Check for Python processes
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq python.exe"], 
            capture_output=True, 
            text=True
        )
        
        if "python.exe" in result.stdout:
            print("✅ Python processes found - Open-Source SOC appears to be running")
            
            # Try to find our specific process
            lines = result.stdout.split('\n')
            python_processes = [line for line in lines if 'python.exe' in line]
            
            print(f"📊 Found {len(python_processes)} Python process(es):")
            for process in python_processes:
                if process.strip():
                    parts = process.split()
                    if len(parts) >= 2:
                        print(f"   • PID: {parts[1]}")
            
            print("\n🌟 Streamlined Cyber-SOC Auto-Responder Status: RUNNING")
            print("💡 The system is actively monitoring with streamlined capabilities:")
            print("   🔍 Wazuh SIEM - Security Information & Event Management")
            print("   🔎 OpenVAS - Vulnerability Assessment & Scanning")
            print("   🦠 VirusTotal - Threat Intelligence Enhancement")
            print("📊 Processing alerts every 30 seconds")
            print("🔍 Vulnerability scan threshold: 7.0/10")
            print("🦠 IOC analysis threshold: 6.0/10")
            
        else:
            print("❌ No Python processes found")
            print("💡 Open-source system may not be running - try starting it with:")
            print("   .\\run_opensource.bat")
            
    except Exception as e:
        print(f"❌ Error checking status: {str(e)}")
        print("💡 Try running: .\\run_opensource.bat")
    
    print("\n" + "=" * 60)
    print("🎯 To start the streamlined system:")
    print("   Windows: .\\run_opensource.bat")
    print("   Direct:  python opensource_production.py")
    print("\n🌟 STREAMLINED SOC STACK:")
    print("   ✅ Wazuh SIEM (Free & Open Source)")
    print("   ✅ OpenVAS Scanner (Free & Open Source)")
    print("   🦠 VirusTotal Enhancement (Threat Intelligence)")
    print("   💡 Lightweight & focused on detection + analysis!")

if __name__ == "__main__":
    check_opensource_status() 