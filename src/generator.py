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
        
        # Track temporal state for stateful attack chains
        track_times = {}
        # Simulate Attacker working hours (e.g., 08:00 - 18:00 UTC)
        attacker_start_hour = random.randint(5, 12)
        attacker_end_hour = attacker_start_hour + 10
        
        for event in self.events:
            is_benign = event.get('is_benign', False)
            track_name = event.get('track')
            identity = event.get('identity')
            
            if is_benign:
                # Noise happens randomly throughout the entire simulation window
                offset = random.randint(0, total_seconds)
                attack_time = start_time + timedelta(seconds=offset)
            else:
                # Attack tracks are stateful and progress over time
                if track_name not in track_times:
                    # Start the track randomly within the first 80% of the window
                    track_start_offset = random.randint(0, int(total_seconds * 0.8))
                    track_times[track_name] = start_time + timedelta(seconds=track_start_offset)
                
                attack_time = track_times[track_name]
                
                # Advance time, pushing interactive tasks into "working hours"
                if attack_time.hour < attacker_start_hour or attack_time.hour > attacker_end_hour:
                    # Fast forward to next shift if this is an interactive tactic
                    if any(t in event['technique'].get('tactics', []) for t in ["discovery", "lateral-movement", "execution"]):
                        hours_to_add = (24 - attack_time.hour + attacker_start_hour) % 24
                        if hours_to_add == 0: hours_to_add = 24
                        attack_time += timedelta(hours=hours_to_add, minutes=random.randint(10, 60))
                
                max_gap = max(3600, int((total_seconds * 0.2) / 10)) # Spread steps over remaining time
                track_times[track_name] = attack_time + timedelta(seconds=random.randint(600, max_gap))

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
            
            # Forensic payload generation
            process_name = None
            command_line = None
            if tool.type == ToolType.EDR:
                if "PowerShell" in tech['name']:
                    process_name = "powershell.exe"
                    command_line = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz..."
                elif "Service" in tech['name']:
                    process_name = "services.exe"
                    command_line = f"sc create updater binPath= \"C:\\Windows\\Temp\\{random.randint(1000,9999)}.exe\" start= auto"
                elif "Process" in tech['name']:
                    process_name = random.choice(["cmd.exe", "svchost.exe", "wmic.exe", "rundll32.exe"])
                    command_line = f"{process_name} /c echo \"Init\""
                else:
                    process_name = "unknown.exe"
            
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
                "username": identity if identity else (f"CORP\\{random.choice(['sys', 'local', 'network'])}" if not is_benign else None),
                "process_name": process_name,
                "command_line": command_line,
                "severity": "Low" if is_benign else self._get_severity(tech['id'], tool.type),
                "message": message,
                "tool_name": tool.name,
                "tool_type": tool.type.value,
                "track": track_name,
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
