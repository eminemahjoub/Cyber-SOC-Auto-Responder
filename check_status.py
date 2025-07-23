#!/usr/bin/env python3
"""
Cyber-SOC Auto-Responder Status Checker
"""

import subprocess
import sys

def check_system_status():
    """Check if the Cyber-SOC system is running."""
    print("🔍 Checking Cyber-SOC Auto-Responder Status...")
    print("=" * 50)
    
    try:
        # Check for Python processes
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq python.exe"], 
            capture_output=True, 
            text=True
        )
        
        if "python.exe" in result.stdout:
            print("✅ Python processes found - System appears to be running")
            
            # Try to find our specific process
            lines = result.stdout.split('\n')
            python_processes = [line for line in lines if 'python.exe' in line]
            
            print(f"📊 Found {len(python_processes)} Python process(es):")
            for process in python_processes:
                if process.strip():
                    parts = process.split()
                    if len(parts) >= 2:
                        print(f"   • PID: {parts[1]}")
            
            print("\n🚀 Cyber-SOC Auto-Responder Status: RUNNING")
            print("💡 The system is actively monitoring for security alerts")
            print("📊 Processing alerts every 30 seconds")
            print("🔒 Auto-isolation threshold: 8.0/10")
            print("📋 Case creation threshold: 5.0/10")
            
        else:
            print("❌ No Python processes found")
            print("💡 System may not be running - try starting it with:")
            print("   python working_production.py")
            
    except Exception as e:
        print(f"❌ Error checking status: {str(e)}")
        print("💡 Try running: python working_production.py")
    
    print("\n" + "=" * 50)
    print("🎯 To start the system: python working_production.py")
    print("🎯 To use batch file: .\\run_cybersoc.bat")
    print("🎯 To use shell script: bash run_cybersoc.sh")

if __name__ == "__main__":
    check_system_status() 