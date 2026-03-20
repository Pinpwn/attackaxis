from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
from .models import LogEntry, SimulationConfig, ToolType
import json

class LogGenerator:
    # High-fidelity TTP to Port Mapping
    TTP_PORT_MAPPING = {
        "T1021.001": 3389, # RDP
        "T1021.002": 445,  # SMB/Windows Admin Shares
        "T1021.004": 22,   # SSH
        "T1071.001": [80, 443], # Web Protocols
        "T1071.002": 21,   # File Transfer Protocols (FTP)
        "T1071.003": 25,   # Mail Protocols (SMTP)
        "T1071.004": 53,   # DNS
        "T1105": [80, 443, 8080], # Ingress Tool Transfer
        "T1567": [80, 443], # Exfiltration to Cloud Repository
        "T1048": [21, 53, 443], # Exfiltration Over Alternative Protocol
        "T1133": [1194, 1723, 443], # External Remote Services (VPN)
        "T1210": [445, 135, 139], # Exploitation of Remote Services
        "T1573": [443, 8080, 8443], # Encrypted Channel
    }

    def __init__(self, simulation_events: List[Dict[str, Any]], config: SimulationConfig):
        self.events = simulation_events
        self.config = config

    def _get_severity(self, technique_id: str, tool_type: ToolType) -> str:
        """Determines severity based on technique and tool."""
        # High impact techniques (simplified mapping)
        critical_prefixes = ["T1567", "T1020", "T1041", "T1485", "T1486"] # Exfiltration, Impact
        high_prefixes = ["T1003", "T1555", "T1078"] # Credential Access, Valid Accounts
        
        if any(technique_id.startswith(p) for p in critical_prefixes):
            return "Critical"
        if any(technique_id.startswith(p) for p in high_prefixes):
            return "High"
        
        if tool_type in [ToolType.EDR, ToolType.WAF]:
            return "Medium"
        
        return "Low"

    def generate_logs(self) -> List[Dict[str, Any]]:
        """Generates the final list of log entries spread across duration."""
        logs = []
        if not self.events:
            return []
            
        total_seconds = self.config.duration_days * 24 * 3600
        start_time = datetime.now() - timedelta(days=self.config.duration_days)
        
        # Generate random sorted offsets for events
        offsets = sorted([random.randint(0, total_seconds) for _ in range(len(self.events))])
        
        for i, event in enumerate(self.events):
            # Attack time
            attack_time = start_time + timedelta(seconds=offsets[i])
            # Simulation of detection latency
            latency = random.expovariate(1.0 / self.config.detection_latency_min) if self.config.detection_latency_min > 0 else 0
            detection_time = attack_time + timedelta(minutes=latency)
            
            tech = event['technique']
            asset = event['asset']
            tool = event['tool']
            is_benign = event.get('is_benign', False)
            
            message = f"Detected {tech['name']} activity on {asset.hostname}" if not is_benign else f"System check: {tech['name']}"
            
            dst_ip = None
            src_port = None
            dst_port = None
            
            is_network_tool = tool.type in [ToolType.NDR, ToolType.FW, ToolType.IDS, ToolType.IPS, ToolType.WAF, ToolType.PROXY]
            is_internal = event.get('is_internal', False)
            dest_asset = event.get('destination_asset')
            
            if not is_benign:
                # 1. Determine Port Realism based on TTP
                ttp_id = tech['id']
                mapped_port = self.TTP_PORT_MAPPING.get(ttp_id)
                
                if mapped_port:
                    if isinstance(mapped_port, list):
                        dst_port = random.choice(mapped_port)
                    else:
                        dst_port = mapped_port
                
                # 2. Assign ports/IPs for network tools
                if is_network_tool:
                    if not dst_port:
                        dst_port = random.choice([80, 443, 445, 22, 3389])
                    src_port = random.randint(49152, 65535)
                    
                    if is_internal and dest_asset:
                        dst_ip = dest_asset.ip
                    else:
                        dst_ip = ".".join([str(random.randint(1, 255)) for _ in range(4)])
            else:
                # Benign noise ports
                if random.random() < 0.2:
                    src_port = random.randint(49152, 65535)
                    dst_port = random.choice([80, 443, 123, 53])
                    dst_ip = ".".join([str(random.randint(1, 255)) for _ in range(4)])
            
            log_entry = {
                "time": detection_time.isoformat(),
                "attack_time": attack_time.isoformat(),
                "srcip": asset.ip,
                "dstip": dst_ip,
                "srcport": src_port,
                "dstport": dst_port,
                "ttp": tech['id'] if not is_benign else "N/A",
                "tactics": tech.get('tactics', []),
                "devicename": asset.hostname,
                "devicetype": asset.device_type.value,
                "severity": "Low" if is_benign else self._get_severity(tech['id'], tool.type),
                "message": message,
                "tool_name": tool.name,
                "tool_type": tool.type.value,
                "is_benign": is_benign
            }
            
            # Include all essential fields unmapped for backend processing
            logs.append(log_entry)
            
        # Re-sort logs by detection time
        logs.sort(key=lambda x: x.get("time", ""))
        return logs

    def get_asset_mapping(self, assets: List[Any]) -> List[Dict[str, str]]:
        """Returns a mapping of IP to mac to device type and some description."""
        mapping = []
        for asset in assets:
            mapping.append({
                "ip": asset.ip,
                "mac": asset.mac,
                "device_type": asset.device_type.value,
                "hostname": asset.hostname,
                "description": asset.description
            })
        return mapping
