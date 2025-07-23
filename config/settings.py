"""
Cyber-SOC Auto-Responder Settings Configuration

This module handles loading and managing all configuration settings
from environment variables and YAML files.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class SplunkSettings(BaseSettings):
    """Splunk configuration settings"""
    host: str = Field(..., env="SPLUNK_HOST")
    port: int = Field(8089, env="SPLUNK_PORT")
    username: str = Field(..., env="SPLUNK_USERNAME")
    password: str = Field(..., env="SPLUNK_PASSWORD")
    scheme: str = Field("https", env="SPLUNK_SCHEME")
    index: str = Field("main", env="SPLUNK_INDEX")
    search_query: str = Field("search index=security earliest=-1h", env="SPLUNK_SEARCH_QUERY")

class CrowdStrikeSettings(BaseSettings):
    """CrowdStrike Falcon configuration settings"""
    client_id: str = Field(..., env="CROWDSTRIKE_CLIENT_ID")
    client_secret: str = Field(..., env="CROWDSTRIKE_CLIENT_SECRET")
    base_url: str = Field("https://api.crowdstrike.com", env="CROWDSTRIKE_BASE_URL")

class TheHiveSettings(BaseSettings):
    """TheHive configuration settings"""
    url: str = Field(..., env="THEHIVE_URL")
    api_key: str = Field(..., env="THEHIVE_API_KEY")
    organization: str = Field(..., env="THEHIVE_ORGANIZATION")

class OpenAISettings(BaseSettings):
    """OpenAI configuration settings"""
    api_key: str = Field(..., env="OPENAI_API_KEY")
    model: str = Field("gpt-4-turbo-preview", env="OPENAI_MODEL")

class YaraSettings(BaseSettings):
    """YARA configuration settings"""
    rules_path: Path = Field(Path("./scanners/yara_rules/"), env="YARA_RULES_PATH")
    update_interval: int = Field(3600, env="YARA_UPDATE_INTERVAL")

class LoggingSettings(BaseSettings):
    """Logging configuration settings"""
    level: str = Field("INFO", env="LOG_LEVEL")
    file_path: Path = Field(Path("./logs/cybersoc.log"), env="LOG_FILE_PATH")
    max_size: int = Field(10485760, env="LOG_MAX_SIZE")  # 10MB
    backup_count: int = Field(5, env="LOG_BACKUP_COUNT")

class AlertSettings(BaseSettings):
    """Alert processing configuration settings"""
    poll_interval: int = Field(60, env="POLL_INTERVAL")
    max_concurrent: int = Field(10, env="MAX_CONCURRENT_ALERTS")
    retention_days: int = Field(30, env="ALERT_RETENTION_DAYS")

class SecuritySettings(BaseSettings):
    """Security configuration settings"""
    encryption_key: str = Field(..., env="ENCRYPTION_KEY")
    api_rate_limit: int = Field(100, env="API_RATE_LIMIT")
    request_timeout: int = Field(30, env="REQUEST_TIMEOUT")

class Settings:
    """Main settings class that loads and manages all configuration"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            config_dir = Path(__file__).parent
        
        self.config_dir = config_dir
        self.yaml_config = self._load_yaml_config()
        
        # Initialize all settings
        self.splunk = SplunkSettings()
        self.crowdstrike = CrowdStrikeSettings()
        self.thehive = TheHiveSettings()
        self.openai = OpenAISettings()
        self.yara = YaraSettings()
        self.logging = LoggingSettings()
        self.alerts = AlertSettings()
        self.security = SecuritySettings()
    
    def _load_yaml_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_file = self.config_dir / "settings.yaml"
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    
    def get_scoring_config(self) -> Dict[str, Any]:
        """Get scoring configuration from YAML"""
        return self.yaml_config.get("scoring", {})
    
    def get_automation_config(self) -> Dict[str, Any]:
        """Get automation configuration from YAML"""
        return self.yaml_config.get("automation", {})
    
    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """Get specific agent configuration"""
        agents_config = self.yaml_config.get("agents", {})
        return agents_config.get(agent_name, {})
    
    def get_timeouts_config(self) -> Dict[str, Any]:
        """Get timeout configuration"""
        return self.yaml_config.get("timeouts", {})
    
    def get_rate_limits_config(self) -> Dict[str, Any]:
        """Get rate limiting configuration"""
        return self.yaml_config.get("rate_limits", {})
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return self.yaml_config.get("monitoring", {})
    
    def get_retention_config(self) -> Dict[str, Any]:
        """Get data retention configuration"""
        return self.yaml_config.get("retention", {})
    
    def validate_config(self) -> bool:
        """Validate that all required configuration is present"""
        try:
            # Test that all required settings can be loaded
            required_settings = [
                self.splunk,
                self.crowdstrike, 
                self.thehive,
                self.openai,
                self.security
            ]
            
            for setting in required_settings:
                # This will raise validation errors if required fields are missing
                setting.dict()
            
            return True
            
        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False

# Global settings instance
settings = Settings() 