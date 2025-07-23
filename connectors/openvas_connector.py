"""
OpenVAS Connector for Vulnerability Scanning
Integrates with OpenVAS/GVM for automated vulnerability assessments.
"""

import asyncio
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import requests
from xml.sax.saxutils import escape

logger = logging.getLogger(__name__)

class OpenVASConnector:
    """OpenVAS connector for vulnerability management."""
    
    def __init__(self, config=None):
        """Initialize OpenVAS connector."""
        self.config = config or {}
        self.base_url = getattr(config, 'openvas_url', 'https://localhost:9390')
        self.username = getattr(config, 'openvas_username', 'admin')
        self.password = getattr(config, 'openvas_password', 'admin')
        self.session_token = None
        self.is_connected = False
        
        # Default scan configuration
        self.default_scan_config = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
        
        logger.info(f"OpenVAS connector initialized for {self.base_url}")
    
    async def connect(self) -> bool:
        """Connect to OpenVAS and authenticate."""
        try:
            # Authenticate with OpenVAS
            auth_data = {
                'cmd': 'authenticate',
                'login': self.username,
                'password': self.password
            }
            
            response = requests.post(
                f"{self.base_url}/omp",
                data=auth_data,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                # Parse response for session token
                root = ET.fromstring(response.text)
                if root.get('status') == '200':
                    self.session_token = root.get('token')
                    self.is_connected = True
                    logger.info("Successfully connected to OpenVAS")
                    return True
            
            logger.error("Failed to authenticate with OpenVAS")
            return False
            
        except Exception as e:
            logger.error(f"OpenVAS connection failed: {str(e)}")
            return False
    
    async def scan_host_vulnerabilities(self, target_ip: str, alert_context: Dict = None) -> Dict[str, Any]:
        """Scan a host for vulnerabilities."""
        if not self.is_connected or not self.session_token:
            raise ConnectionError("OpenVAS connector not connected. Please ensure OpenVAS service is running and configured properly.")
        
        try:
            # Create target
            target_id = await self._create_target(target_ip)
            if not target_id:
                return {"success": False, "error": "Failed to create scan target"}
            
            # Create and start scan task
            task_id = await self._create_scan_task(target_id, target_ip)
            if not task_id:
                return {"success": False, "error": "Failed to create scan task"}
            
            # Start the scan
            scan_started = await self._start_scan(task_id)
            if not scan_started:
                return {"success": False, "error": "Failed to start vulnerability scan"}
            
            logger.info(f"Vulnerability scan started for {target_ip} (Task: {task_id})")
            
            return {
                "success": True,
                "scan_id": task_id,
                "target_ip": target_ip,
                "scan_status": "running",
                "message": f"Vulnerability scan initiated for {target_ip}"
            }
            
        except Exception as e:
            logger.error(f"Error scanning vulnerabilities for {target_ip}: {str(e)}")
            raise ConnectionError(f"Failed to start vulnerability scan: {str(e)}")
    
    async def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get results of a vulnerability scan."""
        if not self.is_connected or not self.session_token:
            raise ConnectionError("OpenVAS connector not connected")
        
        try:
            # Get task status
            task_status = await self._get_task_status(scan_id)
            if not task_status:
                return {"success": False, "error": "Failed to get scan status"}
            
            status = task_status.get('status', 'Unknown')
            progress = task_status.get('progress', 0)
            
            result = {
                "success": True,
                "scan_id": scan_id,
                "status": status,
                "progress": progress
            }
            
            # If scan is complete, get the report
            if status.lower() == "done":
                vulnerabilities = await self._get_scan_report(scan_id)
                result["vulnerabilities"] = vulnerabilities
                result["vulnerability_count"] = len(vulnerabilities)
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting scan results for {scan_id}: {str(e)}")
            raise ConnectionError(f"Failed to get scan results: {str(e)}")
    
    async def _create_target(self, target_ip: str) -> Optional[str]:
        """Create a scan target in OpenVAS."""
        try:
            create_target_xml = f"""
            <create_target>
                <name>Scan_Target_{target_ip}_{int(datetime.now().timestamp())}</name>
                <hosts>{target_ip}</hosts>
            </create_target>
            """
            
            response = await self._send_omp_command(create_target_xml)
            if response and response.get('status') == '201':
                return response.get('id')
            
            logger.error("Failed to create scan target")
            return None
            
        except Exception as e:
            logger.error(f"Error creating target: {str(e)}")
            return None
    
    async def _create_scan_task(self, target_id: str, target_ip: str) -> Optional[str]:
        """Create a scan task in OpenVAS."""
        try:
            create_task_xml = f"""
            <create_task>
                <name>Vulnerability_Scan_{target_ip}_{int(datetime.now().timestamp())}</name>
                <config id="{self.default_scan_config}"/>
                <target id="{target_id}"/>
            </create_task>
            """
            
            response = await self._send_omp_command(create_task_xml)
            if response and response.get('status') == '201':
                return response.get('id')
            
            logger.error("Failed to create scan task")
            return None
            
        except Exception as e:
            logger.error(f"Error creating scan task: {str(e)}")
            return None
    
    async def _start_scan(self, task_id: str) -> bool:
        """Start a vulnerability scan."""
        try:
            start_task_xml = f"""
            <start_task task_id="{task_id}"/>
            """
            
            response = await self._send_omp_command(start_task_xml)
            return response and response.get('status') == '202'
            
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return False
    
    async def _get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a scan task."""
        try:
            get_tasks_xml = f"""
            <get_tasks task_id="{task_id}"/>
            """
            
            response = await self._send_omp_command(get_tasks_xml)
            if response and response.get('status') == '200':
                tasks = response.get('tasks', [])
                if tasks:
                    task = tasks[0]
                    return {
                        "status": task.get('status'),
                        "progress": int(task.get('progress', 0))
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting task status: {str(e)}")
            return None
    
    async def _get_scan_report(self, task_id: str) -> List[Dict[str, Any]]:
        """Get the scan report and extract vulnerabilities."""
        try:
            # Get reports for the task
            get_reports_xml = f"""
            <get_reports task_id="{task_id}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>
            """
            
            response = await self._send_omp_command(get_reports_xml)
            if not response or response.get('status') != '200':
                return []
            
            reports = response.get('reports', [])
            if not reports:
                return []
            
            # Parse vulnerabilities from the report
            vulnerabilities = []
            for report in reports:
                report_vulnerabilities = await self._parse_vulnerabilities(report)
                vulnerabilities.extend(report_vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting scan report: {str(e)}")
            return []
    
    async def _parse_vulnerabilities(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from scan report."""
        vulnerabilities = []
        
        try:
            results = report.get('results', [])
            
            for result in results:
                if result.get('threat', '').lower() in ['high', 'medium', 'low']:
                    vuln = {
                        "id": result.get('nvt', {}).get('oid'),
                        "name": result.get('nvt', {}).get('name'),
                        "severity": result.get('severity'),
                        "threat": result.get('threat'),
                        "host": result.get('host', {}).get('hostname'),
                        "port": result.get('port'),
                        "description": result.get('description'),
                        "solution": result.get('nvt', {}).get('solution', {}).get('text'),
                        "references": result.get('nvt', {}).get('refs', []),
                        "cvss_score": result.get('nvt', {}).get('cvss_base'),
                        "family": result.get('nvt', {}).get('family')
                    }
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Failed to parse vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    async def _send_omp_command(self, xml_command: str) -> Optional[Dict[str, Any]]:
        """Send OMP command to OpenVAS and parse response."""
        try:
            if not self.session_token:
                return None
            
            # Prepare the full OMP request
            full_command = f"""<?xml version="1.0"?>
            <omp>
                <authenticate>
                    <credentials>
                        <username>{self.username}</username>
                        <password>{self.password}</password>
                    </credentials>
                </authenticate>
                {xml_command}
            </omp>"""
            
            response = requests.post(
                f"{self.base_url}/omp",
                data=full_command,
                headers={'Content-Type': 'text/xml'},
                verify=False,
                timeout=60
            )
            
            if response.status_code == 200:
                # Parse XML response
                root = ET.fromstring(response.text)
                return self._parse_omp_response(root)
            else:
                logger.error(f"OMP command failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error sending OMP command: {str(e)}")
            return None
    
    def _parse_omp_response(self, root: ET.Element) -> Dict[str, Any]:
        """Parse OMP XML response."""
        try:
            response_data = {
                'status': root.get('status'),
                'status_text': root.get('status_text')
            }
            
            # Extract ID if present (for create operations)
            if root.get('id'):
                response_data['id'] = root.get('id')
            
            # Parse tasks if present
            tasks = []
            for task in root.findall('.//task'):
                task_data = {
                    'id': task.get('id'),
                    'status': task.find('status').text if task.find('status') is not None else 'Unknown',
                    'progress': task.find('progress').text if task.find('progress') is not None else '0'
                }
                tasks.append(task_data)
            
            if tasks:
                response_data['tasks'] = tasks
            
            # Parse reports if present
            reports = []
            for report in root.findall('.//report'):
                report_data = {'id': report.get('id')}
                
                # Parse results
                results = []
                for result in report.findall('.//result'):
                    result_data = {
                        'id': result.get('id'),
                        'threat': result.find('threat').text if result.find('threat') is not None else '',
                        'severity': result.find('severity').text if result.find('severity') is not None else '0',
                        'description': result.find('description').text if result.find('description') is not None else '',
                        'port': result.find('port').text if result.find('port') is not None else '',
                        'host': {'hostname': result.find('host').text if result.find('host') is not None else ''},
                        'nvt': {}
                    }
                    
                    # Parse NVT information
                    nvt = result.find('nvt')
                    if nvt is not None:
                        result_data['nvt'] = {
                            'oid': nvt.get('oid'),
                            'name': nvt.find('name').text if nvt.find('name') is not None else '',
                            'family': nvt.find('family').text if nvt.find('family') is not None else '',
                            'cvss_base': nvt.find('cvss_base').text if nvt.find('cvss_base') is not None else '0',
                            'solution': {'text': nvt.find('solution').text if nvt.find('solution') is not None else ''},
                            'refs': [ref.text for ref in nvt.findall('refs/ref')]
                        }
                    
                    results.append(result_data)
                
                report_data['results'] = results
                reports.append(report_data)
            
            if reports:
                response_data['reports'] = reports
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error parsing OMP response: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    async def health_check(self) -> bool:
        """Check OpenVAS connection health."""
        try:
            if not self.is_connected or not self.session_token:
                return False
            
            # Try to get version info
            get_version_xml = "<get_version/>"
            response = await self._send_omp_command(get_version_xml)
            
            if response and response.get('status') == '200':
                logger.info("OpenVAS health check passed")
                return True
            else:
                logger.error("OpenVAS health check failed: Invalid response")
                return False
        
        except Exception as e:
            logger.error(f"OpenVAS health check failed: {str(e)}")
            return False
    
    async def disconnect(self):
        """Disconnect from OpenVAS."""
        self.session_token = None
        self.is_connected = False
        logger.info("Disconnected from OpenVAS")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics."""
        return {
            "connected": self.is_connected,
            "base_url": self.base_url,
            "authenticated": bool(self.session_token),
            "last_connection_attempt": datetime.now().isoformat()
        } 