"""
Wazuh Connector for SIEM Integration
Integrates with Wazuh API for alert ingestion and analysis.
"""

import asyncio
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import aiohttp

logger = logging.getLogger(__name__)

class WazuhConnector:
    """Wazuh connector for SIEM integration."""
    
    def __init__(self, config=None):
        """Initialize Wazuh connector."""
        self.config = config or {}
        self.base_url = getattr(config, 'wazuh_url', 'https://localhost:55000')
        self.username = getattr(config, 'wazuh_username', 'wazuh')
        self.password = getattr(config, 'wazuh_password', 'wazuh')
        self.auth_token = None
        self.session = None
        self.is_connected = False
        
        # Default search parameters
        self.default_index = "wazuh-alerts-*"
        self.max_alerts_per_request = 500
        
        logger.info(f"Wazuh connector initialized for {self.base_url}")
    
    async def connect(self) -> bool:
        """Connect to Wazuh and authenticate."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False)  # Disable SSL verification for local installs
            )
            
            # Authenticate with Wazuh API
            auth_url = f"{self.base_url}/security/user/authenticate"
            
            # Create basic auth header
            credentials = f"{self.username}:{self.password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.post(auth_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data.get('data', {}).get('token')
                    if self.auth_token:
                        self.is_connected = True
                        logger.info("Successfully connected to Wazuh API")
                        return True
            
            logger.error("Failed to authenticate with Wazuh API")
            await self.session.close()
            self.session = None
            return False
            
        except Exception as e:
            logger.error(f"Wazuh connection failed: {str(e)}")
            if self.session:
                await self.session.close()
                self.session = None
            return False
    
    async def get_new_alerts(self, lookback_minutes: int = 5) -> List[Dict[str, Any]]:
        """Get new alerts from Wazuh."""
        if not self.is_connected or not self.auth_token:
            raise ConnectionError("Wazuh connector not connected. Please ensure Wazuh service is running and configured properly.")
        
        try:
            # Calculate time range
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=lookback_minutes)
            
            # Query Wazuh alerts
            alerts_url = f"{self.base_url}/alerts"
            
            headers = {
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            }
            
            params = {
                'rule.level': '7..15',  # High severity rules only
                'timestamp': f'{start_time.isoformat()}..{end_time.isoformat()}',
                'limit': self.max_alerts_per_request,
                'sort': '-timestamp'
            }
            
            async with self.session.get(alerts_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    raw_alerts = data.get('data', {}).get('affected_items', [])
                    
                    # Convert to standard format
                    formatted_alerts = []
                    for alert in raw_alerts:
                        formatted_alert = await self._format_alert(alert)
                        if formatted_alert:
                            formatted_alerts.append(formatted_alert)
                    
                    logger.info(f"Retrieved {len(formatted_alerts)} alerts from Wazuh")
                    return formatted_alerts
                else:
                    logger.error(f"Failed to get alerts: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting Wazuh alerts: {str(e)}")
            raise ConnectionError(f"Failed to retrieve alerts from Wazuh: {str(e)}")
    
    async def search_alerts(self, query: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """Search for alerts matching specific criteria."""
        if not self.is_connected or not self.auth_token:
            raise ConnectionError("Wazuh connector not connected. Please ensure Wazuh service is running and configured properly.")
        
        try:
            search_url = f"{self.base_url}/alerts"
            
            headers = {
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            }
            
            params = {
                'q': query,
                'limit': max_results,
                'sort': '-timestamp'
            }
            
            async with self.session.get(search_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    raw_alerts = data.get('data', {}).get('affected_items', [])
                    
                    formatted_alerts = []
                    for alert in raw_alerts:
                        formatted_alert = await self._format_alert(alert)
                        if formatted_alert:
                            formatted_alerts.append(formatted_alert)
                    
                    return formatted_alerts
                else:
                    logger.error(f"Search failed: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error searching Wazuh alerts: {str(e)}")
            raise ConnectionError(f"Failed to search alerts in Wazuh: {str(e)}")
    
    async def _format_alert(self, raw_alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Format raw Wazuh alert to standard format."""
        try:
            alert_id = raw_alert.get('id', f"wazuh_{int(datetime.now().timestamp())}")
            
            # Extract rule information
            rule = raw_alert.get('rule', {})
            agent = raw_alert.get('agent', {})
            
            # Determine severity based on rule level
            rule_level = rule.get('level', 0)
            if rule_level >= 12:
                severity = "critical"
            elif rule_level >= 9:
                severity = "high"
            elif rule_level >= 6:
                severity = "medium"
            else:
                severity = "low"
            
            # Extract indicators (IPs, domains, hashes)
            indicators = []
            if 'srcip' in raw_alert:
                indicators.append(raw_alert['srcip'])
            if 'dstip' in raw_alert:
                indicators.append(raw_alert['dstip'])
            
            formatted_alert = {
                "id": alert_id,
                "title": rule.get('description', 'Wazuh Alert'),
                "description": raw_alert.get('full_log', rule.get('description', '')),
                "timestamp": raw_alert.get('timestamp', datetime.now().isoformat()),
                "source": "wazuh",
                "severity": severity,
                "category": self._categorize_alert(rule),
                "rule_id": rule.get('id'),
                "rule_level": rule_level,
                "rule_groups": rule.get('groups', []),
                "agent_name": agent.get('name'),
                "agent_ip": agent.get('ip'),
                "src_ip": raw_alert.get('srcip'),
                "dest_ip": raw_alert.get('dstip'),
                "dest_port": raw_alert.get('dstport'),
                "user": raw_alert.get('user'),
                "process": raw_alert.get('process'),
                "file_path": raw_alert.get('syscheck', {}).get('path'),
                "indicators": indicators,
                "tags": rule.get('groups', []),
                "raw_data": raw_alert
            }
            
            return formatted_alert
            
        except Exception as e:
            logger.error(f"Error formatting alert: {str(e)}")
            return None
    
    def _categorize_alert(self, rule: Dict[str, Any]) -> str:
        """Categorize alert based on rule groups."""
        groups = rule.get('groups', [])
        
        if any(group in groups for group in ['authentication_failed', 'authentication_success']):
            return 'authentication'
        elif any(group in groups for group in ['web', 'attack']):
            return 'web'
        elif any(group in groups for group in ['syscheck', 'file_changed']):
            return 'file_integrity'
        elif any(group in groups for group in ['malware', 'rootkit']):
            return 'malware'
        elif any(group in groups for group in ['firewall', 'ids']):
            return 'network'
        else:
            return 'general'
    
    async def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific Wazuh agent."""
        if not self.is_connected or not self.auth_token:
            raise ConnectionError("Wazuh connector not connected")
        
        try:
            agent_url = f"{self.base_url}/agents/{agent_id}"
            
            headers = {
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.get(agent_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get('affected_items', [{}])[0]
                else:
                    logger.error(f"Failed to get agent info: HTTP {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting agent info: {str(e)}")
            return None
    
    async def get_rules_info(self, rule_ids: List[str]) -> List[Dict[str, Any]]:
        """Get information about specific Wazuh rules."""
        if not self.is_connected or not self.auth_token:
            raise ConnectionError("Wazuh connector not connected")
        
        try:
            rules_url = f"{self.base_url}/rules"
            
            headers = {
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            }
            
            params = {
                'rule_ids': ','.join(rule_ids)
            }
            
            async with self.session.get(rules_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get('affected_items', [])
                else:
                    logger.error(f"Failed to get rules info: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting rules info: {str(e)}")
            return []
    
    async def health_check(self) -> bool:
        """Check Wazuh connection health."""
        try:
            if not self.is_connected or not self.auth_token:
                return False
            
            # Try to get manager info
            manager_url = f"{self.base_url}/manager/info"
            headers = {
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.get(manager_url, headers=headers) as response:
                if response.status == 200:
                    logger.info("Wazuh health check passed")
                    return True
                else:
                    logger.error(f"Wazuh health check failed: HTTP {response.status}")
                    return False
        
        except Exception as e:
            logger.error(f"Wazuh health check failed: {str(e)}")
            return False
    
    async def disconnect(self):
        """Disconnect from Wazuh."""
        if self.session:
            await self.session.close()
            self.session = None
            self.is_connected = False
            self.auth_token = None
            logger.info("Disconnected from Wazuh")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics."""
        return {
            "connected": self.is_connected,
            "base_url": self.base_url,
            "authenticated": bool(self.auth_token),
            "last_connection_attempt": datetime.now().isoformat()
        } 