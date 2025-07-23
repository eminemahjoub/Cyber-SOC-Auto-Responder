# 🚀 Cyber-SOC Auto-Responder

An intelligent, multi-agent AI-powered security orchestration, automation, and response (SOAR) platform designed to revolutionize security operations centers (SOCs) by automating alert triage, threat analysis, and incident response.

## ✨ Key Features

### 🧠 Intelligent Alert Triage
- **DBIR Pattern Recognition**: Leverages 2024 Verizon Data Breach Investigations Report patterns for accurate threat classification
- **Dynamic Severity Scoring**: AI-powered scoring algorithm that considers multiple threat indicators
- **Contextual Analysis**: Considers user privileges, network zones, and historical patterns

### ⚡ Automated Response Actions
- **Host Isolation**: Automatic endpoint containment via CrowdStrike Falcon API
- **Threat Intelligence**: Real-time IOC scanning and malware analysis
- **Case Management**: Automated incident case creation in TheHive
- **Escalation Workflows**: Intelligent escalation based on severity thresholds

### 🔍 Advanced Scanning Capabilities
- **YARA Malware Detection**: File analysis using custom and community YARA rules
- **IOC Extraction**: Automated indicator extraction from alerts and files
- **Threat Intelligence Enrichment**: Real-time threat intelligence correlation

### 📊 Enterprise Integration
- **Splunk Integration**: Native SIEM alert ingestion and searching
- **CrowdStrike Falcon**: EDR integration for endpoint protection
- **TheHive Integration**: Case management and incident tracking
- **Extensible Architecture**: Easy integration with additional security tools

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Splunk      │    │   CrowdStrike   │    │    TheHive      │
│   (SIEM Data)   │    │   (EDR Actions) │    │ (Case Mgmt)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AI Agent Orchestrator                        │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│  Triage Agent   │  Scanner Agent  │ Response Agent  │Case Agent │
│                 │                 │                 │           │
│ • DBIR Analysis │ • YARA Scanning │ • Host Isolation│• Case     │
│ • Severity      │ • IOC Extraction│ • Quarantine    │  Creation │
│   Scoring       │ • File Analysis │ • Notifications │• Updates  │
│ • Pattern Recog │ • Threat Intel  │ • Blocking      │• Tracking │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
```

## 📁 Project Structure

```
cybersoc-auto-responder/
├── agents/                    # AI Agents
│   ├── triage_agent.py       # Alert analysis and severity scoring
│   ├── scanner_agent.py      # File and IOC scanning coordination
│   ├── response_agent.py     # Automated response actions
│   └── case_agent.py         # Incident case management
├── connectors/                # External System Integrations
│   ├── splunk_connector.py   # Splunk SIEM integration
│   ├── crowdstrike_connector.py # CrowdStrike Falcon EDR
│   └── thehive_connector.py  # TheHive case management
├── scanners/                  # Analysis Components
│   ├── yara_scanner.py       # YARA-based malware detection
│   ├── file_analyzer.py      # File metadata and analysis
│   ├── ioc_scanner.py        # IOC extraction and validation
│   └── yara_rules/           # YARA rule repository
├── config/                    # Configuration Management
│   ├── settings.py           # Application settings
│   ├── logger_config.py      # Logging configuration
│   └── dbir_patterns.py      # DBIR incident patterns
├── logs/                      # Application logs
├── quarantine/               # Quarantined files
├── main.py                   # Production orchestrator
├── simple_demo.py            # Simplified demonstration
├── requirements.txt          # Python dependencies
└── .env                      # Environment configuration
```

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-org/cybersoc-auto-responder.git
cd cybersoc-auto-responder

# Install dependencies
pip install -r requirements.txt

# Install additional packages for full functionality
pip install pydantic-settings pytest pytest-asyncio
```

### 2. Configuration

Create or update the `.env` file with your system credentials:

```bash
# Splunk Configuration
SPLUNK_HOST=your-splunk-host.com
SPLUNK_PORT=8089
SPLUNK_USERNAME=your-username
SPLUNK_PASSWORD=your-password
SPLUNK_SCHEME=https

# CrowdStrike Configuration  
CROWDSTRIKE_CLIENT_ID=your-client-id
CROWDSTRIKE_CLIENT_SECRET=your-client-secret
CROWDSTRIKE_BASE_URL=https://api.crowdstrike.com

# TheHive Configuration
THEHIVE_URL=https://your-thehive-instance.com
THEHIVE_API_KEY=your-api-key
THEHIVE_ORGANIZATION=your-organization

# System Settings
DEBUG=false
LOG_LEVEL=INFO
POLL_INTERVAL=30
MAX_CONCURRENT_ALERTS=10
```

### 3. Run Demo Mode

Experience the system capabilities with simulated data:

```bash
# Run the simplified demo (no dependencies required)
python simple_demo.py
```

### 4. Production Deployment

```bash
# Run the production system
python main.py
```

## 💡 Usage Examples

### Automatic Alert Processing

The system automatically:

1. **Ingests alerts** from Splunk every 30 seconds
2. **Analyzes threats** using DBIR patterns and AI
3. **Calculates severity** based on multiple factors
4. **Executes responses** based on configurable thresholds
5. **Creates cases** for investigation tracking
6. **Logs all actions** for audit trails

### Manual Investigation

```python
from agents.triage_agent import TriageAgent
from config.dbir_patterns import DBIRPatterns

# Initialize components
triage_agent = TriageAgent(config)
dbir_patterns = DBIRPatterns()

# Analyze a specific alert
alert = {
    "title": "Suspicious file execution",
    "host": "workstation-01",
    "user": "admin",
    "file_hash": "suspicious_hash"
}

result = await triage_agent.analyze_alert(alert, dbir_patterns)
print(f"Severity: {result['severity_score']}/10")
```

## 🔍 Monitoring

The system provides comprehensive logging and monitoring capabilities through the production launcher and status checking scripts.

## 📋 DBIR Pattern Integration

The system implements the 2024 Verizon DBIR incident patterns:

- **System Intrusion**: Malware, command & control, network-based attacks
- **Social Engineering**: Phishing, pretexting, and social attacks  
- **Basic Web Application Attacks**: SQL injection, XSS, web exploits
- **Denial of Service**: DDoS and resource exhaustion attacks
- **Lost and Stolen Assets**: Physical device compromise
- **Privilege Misuse**: Insider threats and privilege abuse
- **Cyber-Espionage**: APT and nation-state activities
- **Point of Sale**: Payment card industry attacks
- **Everything Else**: Misconfiguration and other incidents

## ⚙️ Configuration Options

### Automation Thresholds

```bash
# Auto-isolation threshold (8.0+ triggers immediate isolation)
AUTO_ISOLATION_THRESHOLD=8.0

# Auto-scanning threshold (6.0+ triggers enhanced scanning)  
AUTO_SCANNING_THRESHOLD=6.0

# Case creation threshold (5.0+ creates incident case)
AUTO_CASE_CREATION_THRESHOLD=5.0
```

### Agent Configuration

```bash
# AI Model Settings
TRIAGE_MODEL=gpt-4-turbo-preview
TRIAGE_TEMPERATURE=0.1
TRIAGE_MAX_TOKENS=2000

SCANNER_MODEL=gpt-4-turbo-preview  
SCANNER_TEMPERATURE=0.0
SCANNER_MAX_TOKENS=1500
```

## 🔧 Customization

### Adding New Connectors

1. Create connector class in `connectors/`
2. Implement required methods: `connect()`, `health_check()`, custom methods
3. Add configuration to `config/settings.py`
4. Update orchestrator to use new connector

### Custom YARA Rules

1. Add `.yar` files to `scanners/yara_rules/`
2. Rules are automatically loaded on startup
3. Supports both custom and community rules

### Custom DBIR Patterns

Modify `config/dbir_patterns.py` to add organization-specific threat patterns.

## 📊 Monitoring & Metrics

The system provides comprehensive metrics:

- **Alert Processing Times**: Average time per alert
- **Action Success Rates**: Response action effectiveness  
- **Severity Distribution**: Alert severity trends
- **False Positive Rates**: Model accuracy metrics
- **System Health**: Connector and component status

## 🛡️ Security Considerations

- **Credential Management**: Use environment variables for all secrets
- **Network Security**: Implement proper firewall rules
- **Access Control**: Restrict API access to authorized systems
- **Audit Logging**: All actions are logged for compliance
- **Data Encryption**: Encrypt sensitive data in transit and at rest

## 🔄 Maintenance

### Log Rotation
Logs are stored in `logs/` directory with automatic rotation.

### YARA Rule Updates
Rules can be updated by replacing files in `scanners/yara_rules/`.

### Performance Tuning
Adjust `MAX_CONCURRENT_ALERTS` and `POLL_INTERVAL` based on environment.

## 🐛 Troubleshooting

### Common Issues

**Configuration Errors**
```bash
# Check environment file
cat .env

# Test configuration loading
python -c "from config import Settings; print('Config OK')"
```

**Connection Issues**
```bash
# Test individual connectors
python -c "from connectors.splunk_connector import SplunkConnector; # test code"
```

**Performance Issues**
- Reduce `MAX_CONCURRENT_ALERTS`
- Increase `POLL_INTERVAL`
- Check system resources

## 📈 Roadmap

- [ ] Machine Learning threat scoring
- [ ] Custom playbook automation
- [ ] Advanced threat hunting
- [ ] Multi-tenant support
- [ ] REST API interface
- [ ] Web dashboard interface
- [ ] Mobile notifications

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Verizon DBIR Team** for incident pattern research
- **YARA Project** for malware detection capabilities
- **Security Community** for threat intelligence contributions
- **Open Source Contributors** for foundational libraries

## 📞 Support

For support and questions:
- 📧 Email: security-team@company.com
- 💬 Slack: #cybersoc-auto-responder
- 📋 Issues: GitHub Issues page
- 📖 Documentation: [Wiki Pages](https://github.com/your-org/cybersoc-auto-responder/wiki)

---

**⚡ Dramatically reduce Mean Time to Response (MTTR) with intelligent automation**

Built with ❤️ for the cybersecurity community #   C y b e r - S O C - A u t o - R e s p o n d e r  
 