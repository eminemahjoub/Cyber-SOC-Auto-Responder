# 🛠️ Cyber-SOC Auto-Responder Setup Guide

## 📋 **What You Need Now**

Your system is **running** but using **real connectors** that require actual services. Here's how to set up everything:

## 🔧 **1. Install Required Services**

### **🔍 Wazuh SIEM (Free & Open Source)**

**Option A: Docker (Easiest)**
```bash
# Download Wazuh Docker Compose
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node

# Start Wazuh
docker-compose up -d

# Access: https://localhost:443
# Default: admin/SecretPassword
```

**Option B: Manual Installation**
```bash
# Ubuntu/Debian
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# CentOS/RHEL
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

### **🔎 OpenVAS Scanner (Free & Open Source)**

**Option A: Docker (Recommended)**
```bash
# Download and run OpenVAS
docker run -d -p 9392:9392 --name openvas mikesplain/openvas

# Wait 10-15 minutes for initial setup
# Access: https://localhost:9392
# Default: admin/admin
```

**Option B: Greenbone Community Edition**
```bash
# Install GVM/OpenVAS
sudo apt update
sudo apt install gvm
sudo gvm-setup
sudo gvm-start

# Access: https://localhost:9392
```

## ⚙️ **2. Configure Your Services**

### **🔍 Configure Wazuh**
1. **Access Wazuh Dashboard**: https://localhost:443
2. **Create API User**: 
   - Go to Security → Users → Create User
   - Username: `cybersoc-api`
   - Password: `YourSecurePassword123`
3. **Update .env file**:
   ```env
   WAZUH_URL=https://localhost:55000
   WAZUH_USERNAME=cybersoc-api
   WAZUH_PASSWORD=YourSecurePassword123
   ```

### **🔎 Configure OpenVAS**
1. **Access OpenVAS**: https://localhost:9392
2. **Login**: admin/admin (change password)
3. **Create Scan Config**:
   - Go to Configuration → Scan Configs → Clone "Full and fast"
   - Name: "CyberSOC-Scan"
4. **Update .env file**:
   ```env
   OPENVAS_URL=https://localhost:9390
   OPENVAS_USERNAME=admin
   OPENVAS_PASSWORD=YourNewPassword
   ```

### **🦠 VirusTotal (Already Configured)**
✅ Your API key is already set: `f5819e00da02b057ec600673a825e42bbc5dcb7066c79a8ac7e352c9b6fd1979`

## 🚀 **3. Quick Start Options**

### **Option A: Full Production Setup**
```bash
# 1. Install services (Docker recommended)
# 2. Configure authentication
# 3. Update .env with real credentials
# 4. Restart system
python opensource_production.py
```

### **Option B: Development/Testing**
```bash
# Use local VM or cloud instances
# - Wazuh: AWS/Azure marketplace
# - OpenVAS: DigitalOcean droplet
# - Update .env with remote URLs
```

### **Option C: Hybrid Approach**
```bash
# Use cloud Wazuh + local OpenVAS
# Or vice versa
# Update URLs in .env accordingly
```

## 📊 **4. Verification Steps**

After setup, verify everything works:

```bash
# Check system status
python check_opensource_status.py

# Test connections
python -c "
import asyncio
from connectors.wazuh_connector import WazuhConnector
from connectors.openvas_connector import OpenVASConnector
from connectors.virustotal_connector import VirusTotalConnector

async def test():
    w = WazuhConnector()
    o = OpenVASConnector()
    v = VirusTotalConnector()
    
    print('Wazuh:', await w.connect())
    print('OpenVAS:', await o.connect())
    print('VirusTotal:', await v.connect())

asyncio.run(test())
"
```

## 🔧 **5. Common Issues & Solutions**

### **Connection Refused**
- Services not started: `docker-compose up -d`
- Wrong ports: Check firewall/port forwarding
- SSL issues: Use `VERIFY_SSL=false` for testing

### **Authentication Failed**  
- Wrong credentials in .env
- User doesn't have API permissions
- Check service logs

### **Timeouts**
- Services starting up (wait 5-10 minutes)
- Network connectivity issues
- Resource constraints (increase RAM/CPU)

## 🎯 **Your Current Status**
- ✅ **System Running**: 8 Python processes active
- ✅ **VirusTotal**: Connected with your API key
- ⚠️ **Wazuh**: Needs real service installation
- ⚠️ **OpenVAS**: Needs real service installation

## 💡 **Next Steps**
1. **Choose installation option** (Docker recommended)
2. **Set up Wazuh** (15-20 minutes)
3. **Set up OpenVAS** (20-30 minutes) 
4. **Update .env** with real credentials
5. **Restart system** and verify connections

Your system will then be **100% operational** with real threat detection! 🛡️ 