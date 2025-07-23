# 🛡️ Cyber-SOC Auto-Responder

[![GitHub](https://img.shields.io/github/license/eminemahjoub/Cyber-SOC-Auto-Responder)](https://github.com/eminemahjoub/Cyber-SOC-Auto-Responder)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AI Powered](https://img.shields.io/badge/AI-GPT--4%20Powered-brightgreen)](https://openai.com/)

> **Advanced AI-Powered Security Operations Center (SOC) automation platform that combines real-time threat detection, intelligent analysis, and automated response capabilities.**

## 🚀 Features

### 🤖 **AI-Powered Intelligence**
- **GPT-4 Turbo** powered threat analysis
- **Advanced pattern recognition** using DBIR frameworks
- **Context-aware severity scoring** with natural language processing
- **Intelligent IOC correlation** and risk assessment

### 🔗 **Enterprise Integrations**
- **🔍 Wazuh SIEM** - Real-time security event monitoring
- **🔎 OpenVAS** - Automated vulnerability assessment
- **🦠 VirusTotal** - Global threat intelligence platform
- **⚡ Streamlined workflow** - No case management overhead

### 🛡️ **Security Capabilities**
- **Real-time threat detection** (30-second cycles)
- **Automated vulnerability scanning** (7.0+ severity threshold)
- **IOC analysis & validation** (6.0+ severity threshold)
- **Intelligent response actions** (8.0+ critical threshold)
- **Cross-platform support** (Windows, Linux, macOS)

## 📋 Quick Start

### 1. **Clone Repository**
```bash
git clone https://github.com/eminemahjoub/Cyber-SOC-Auto-Responder.git
cd Cyber-SOC-Auto-Responder
```

### 2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

### 3. **Configuration**
```bash
# Copy template and configure
cp config_template.env .env
# Edit .env with your API keys and service URLs
```

### 4. **Run System**
```bash
# Streamlined production system (recommended)
python opensource_production.py

# AI-powered system (requires OpenAI API key)
python upgrade_to_ai_production.py

# Demo mode
python demo_streamlined.py
```

## ⚙️ Configuration

### **Required Services**
| Service | Purpose | Status |
|---------|---------|--------|
| **Wazuh** | SIEM & Log Analysis | Free & Open Source |
| **OpenVAS** | Vulnerability Scanning | Free & Open Source |
| **VirusTotal** | Threat Intelligence | Freemium API |

### **Environment Variables**
```env
# Core Security Services
WAZUH_URL=https://localhost:55000
WAZUH_USERNAME=your_username
WAZUH_PASSWORD=your_password

OPENVAS_URL=https://localhost:9390
OPENVAS_USERNAME=admin
OPENVAS_PASSWORD=your_password

VIRUSTOTAL_API_KEY=your_api_key

# AI Enhancement (Optional)
OPENAI_API_KEY=your_openai_key

# System Configuration
POLL_INTERVAL=30
VULNERABILITY_SCAN_THRESHOLD=7.0
IOC_ANALYSIS_THRESHOLD=6.0
```

### **Quick Setup (Docker)**
```bash
# Install Wazuh
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker-compose up -d

# Install OpenVAS
docker run -d -p 9392:9392 --name openvas mikesplain/openvas
```

## 🏗️ Architecture

```mermaid
graph TB
    A[Wazuh SIEM] --> D[SOC Orchestrator]
    B[OpenVAS Scanner] --> D
    C[VirusTotal API] --> D
    
    D --> E[AI Triage Agent]
    D --> F[Vulnerability Agent]
    D --> G[Response Agent]
    
    E --> H[Threat Analysis]
    F --> I[Risk Assessment]
    G --> J[Automated Actions]
    
    H --> K[Security Dashboard]
    I --> K
    J --> K
```

## 🤖 AI Agents

### **🧠 Triage Agent** (27.8KB)
- **GPT-4 powered** threat classification
- **DBIR pattern matching** for attack identification
- **Context-aware severity scoring** (1-10 scale)
- **Natural language analysis** of security events

### **🔍 Scanner Agent** (16.1KB)
- **Intelligent file analysis** with behavioral detection
- **IOC correlation** across multiple threat feeds
- **Malware behavior prediction** using AI models
- **Risk assessment** with confidence scoring

### **⚡ Response Agent**
- **Automated containment** actions
- **Intelligent escalation** based on threat severity
- **Evidence preservation** and documentation
- **Integration with security tools**

## 📊 Usage Examples

### **Basic Operation**
```python
from opensource_production import OpenSourceSOCOrchestrator

# Initialize and run
orchestrator = OpenSourceSOCOrchestrator()
await orchestrator.run_opensource_system()
```

### **AI-Enhanced Analysis**
```python
from upgrade_to_ai_production import AIEnabledSOCOrchestrator

# Requires OPENAI_API_KEY
orchestrator = AIEnabledSOCOrchestrator()
await orchestrator.run_ai_soc_system()
```

### **Custom Alert Processing**
```python
# Process specific alert with AI
ai_result = await triage_agent.analyze_alert(alert, dbir_patterns)
severity = ai_result.get("severity_score", 5.0)
pattern = ai_result.get("pattern", "Unknown")
```

## 🎯 Performance Metrics

| Metric | Streamlined | AI-Enhanced |
|--------|-------------|-------------|
| **Detection Speed** | 30 seconds | 30 seconds |
| **Analysis Depth** | Rule-based | GPT-4 powered |
| **False Positives** | ~15% | ~5% |
| **Threat Coverage** | DBIR patterns | Advanced AI + DBIR |
| **Cost per Alert** | Free | ~$0.01-0.03 |

## 🛠️ Development

### **Project Structure**
```
cybersoc-auto-responder/
├── agents/                 # AI-powered analysis agents
│   ├── triage_agent.py    # GPT-4 threat triage (27.8KB)
│   ├── scanner_agent.py   # Intelligent file scanning (16.1KB)
│   └── response_agent.py  # Automated response actions
├── connectors/            # Security tool integrations
│   ├── wazuh_connector.py # SIEM integration
│   ├── openvas_connector.py # Vulnerability scanner
│   └── virustotal_connector.py # Threat intelligence
├── config/               # Configuration management
├── scanners/            # File and IOC scanners
├── opensource_production.py # Main production system
├── upgrade_to_ai_production.py # AI-enhanced system
└── SETUP_GUIDE.md       # Detailed setup instructions
```

### **Adding New Connectors**
```python
class CustomConnector:
    async def connect(self) -> bool:
        # Implementation
        pass
    
    async def health_check(self) -> bool:
        # Health verification
        pass
```

## 🔒 Security Features

- **🔐 Zero hardcoded credentials** - All sensitive data in environment variables
- **🛡️ Real connector validation** - No mock/simulation modes in production
- **📊 Comprehensive logging** - Full audit trail of all actions
- **🔍 Input validation** - Sanitized inputs prevent injection attacks
- **⚡ Rate limiting** - API call throttling for stability

## 📈 Monitoring & Alerting

### **System Health Checks**
```bash
# Check system status
python check_opensource_status.py

# Verify connections
python -c "
from connectors.wazuh_connector import WazuhConnector
connector = WazuhConnector()
print('Wazuh:', await connector.connect())
"
```

### **Performance Metrics**
- **📊 Real-time dashboards** with system status
- **📈 Trend analysis** of threat patterns
- **⚡ Response time tracking** for optimization
- **🎯 Accuracy metrics** for AI model performance

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### **Development Setup**
```bash
# Fork and clone
git clone https://github.com/your-username/Cyber-SOC-Auto-Responder.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Wazuh Team** - Open-source SIEM platform
- **Greenbone Networks** - OpenVAS vulnerability scanner
- **VirusTotal** - Threat intelligence platform
- **OpenAI** - GPT-4 AI capabilities
- **SANS Institute** - DBIR threat patterns

## 📞 Support

- **📖 Documentation**: [Setup Guide](SETUP_GUIDE.md)
- **🐛 Issues**: [GitHub Issues](https://github.com/eminemahjoub/Cyber-SOC-Auto-Responder/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/eminemahjoub/Cyber-SOC-Auto-Responder/discussions)

---

⭐ **Star this repository if you find it helpful!**

**Built with ❤️ for the cybersecurity community**