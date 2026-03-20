import random
import ipaddress
from typing import List, Dict, Any, Optional
from .models import Organization, Asset, DeviceType, ToolType, SecurityTool, SimulationConfig
import uuid

class OrgSimulator:
    def __init__(self, size: int, security_coverage: float, tools: List[ToolType]):
        self.size = size
        self.security_coverage = security_coverage
        self.tools = [SecurityTool(name=f"Org-{t}", type=t, coverage_score=security_coverage) for t in tools]
        self.assets: List[Asset] = []
        self._generate_assets()

    def _generate_assets(self):
        """Generates mock assets for the organization."""
        base_ip = ipaddress.IPv4Address("192.168.1.1")
        for i in range(self.size):
            ip = str(base_ip + i)
            mac = ":".join(["{:02x}".format(random.randint(0, 255)) for _ in range(6)])
            dt_rand = random.random()
            if dt_rand < 0.7:
                device_type = DeviceType.WORKSTATION
                hostname = f"WKSTN-{i:03d}"
                description = "Employee workstation"
            elif dt_rand < 0.9:
                device_type = DeviceType.SERVER
                hostname = f"SRV-{i:03d}"
                description = "Internal server"
            else:
                infra_rand = random.random()
                if infra_rand < 0.3:
                    device_type = DeviceType.FIREWALL
                    hostname = f"FW-{i:03d}"
                    description = "Network security appliance"
                elif infra_rand < 0.6:
                    device_type = DeviceType.ROUTER
                    hostname = f"RTR-{i:03d}"
                    description = "Core router"
                else:
                    device_type = DeviceType.IOT
                    hostname = f"IOT-{i:03d}"
                    description = "Office IoT device"
            self.assets.append(Asset(ip=ip, mac=mac, device_type=device_type, hostname=hostname, description=description))

    def get_organization(self) -> Organization:
        return Organization(name="SimulatedCorp", size=self.size, deployed_tools=self.tools, security_coverage=self.security_coverage, assets=self.assets)

class AttackSimulator:
    DATA_SOURCE_MAPPING = {
        "Process": [ToolType.EDR, ToolType.AV, ToolType.HIDS],
        "Command": [ToolType.EDR, ToolType.SIEM],
        "File": [ToolType.EDR, ToolType.AV, ToolType.HIDS],
        "Windows Registry": [ToolType.EDR],
        "Kernel": [ToolType.EDR],
        "Service": [ToolType.EDR, ToolType.SIEM],
        "User Account": [ToolType.SIEM, ToolType.EDR],
        "Group": [ToolType.SIEM],
        "Scheduled Job": [ToolType.EDR, ToolType.HIDS],
        "Module": [ToolType.EDR],
        "Drive": [ToolType.EDR, ToolType.AV],
        "Cloud Storage": [ToolType.SIEM, ToolType.PROXY],
        "Instance": [ToolType.SIEM],
        "Active Directory": [ToolType.SIEM],
        "Network Traffic": [ToolType.NDR, ToolType.FW, ToolType.IDS, ToolType.IPS],
        "Network Boundary": [ToolType.FW, ToolType.IPS],
        "Logon Session": [ToolType.SIEM, ToolType.EDR],
        "HTTP Request": [ToolType.WAF, ToolType.PROXY, ToolType.NDR],
        "Domain Name": [ToolType.NDR, ToolType.PROXY],
        "Application Log": [ToolType.SIEM, ToolType.WAF],
        "Certificate": [ToolType.NDR, ToolType.PROXY],
        "Packet": [ToolType.NDR, ToolType.IDS]
    }

    BENIGN_SCENARIOS = {
        ToolType.EDR: [
            {"id": "T1059.001", "name": "PowerShell Script Execution (Admin Update)", "tactics": ["execution"], "data_sources": ["Command"]},
            {"id": "T1543.003", "name": "Windows Service Creation (Software Install)", "tactics": ["persistence"], "data_sources": ["Service"]},
            {"id": "T1057", "name": "Process Discovery (Monitoring Agent)", "tactics": ["discovery"], "data_sources": ["Process"]},
            {"id": "T1112", "name": "Registry Modification (System Settings)", "tactics": ["defense-evasion"], "data_sources": ["Windows Registry"]},
            {"id": "T1083", "name": "File and Directory Discovery (Backup Agent)", "tactics": ["discovery"], "data_sources": ["File"]},
            {"id": "T1055", "name": "Process Injection (Security Software)", "tactics": ["defense-evasion", "privilege-escalation"], "data_sources": ["Process"]},
            {"id": "T1218", "name": "Signed Binary Proxy Execution (System)", "tactics": ["defense-evasion"], "data_sources": ["Process"]},
            {"id": "T1070.004", "name": "File Deletion (Temp Cleanup)", "tactics": ["defense-evasion"], "data_sources": ["File"]},
            {"id": "T1106", "name": "Native API Execution (Diagnostic Tool)", "tactics": ["execution"], "data_sources": ["Process"]},
            {"id": "T1053.005", "name": "Scheduled Task (Daily Defrag)", "tactics": ["persistence"], "data_sources": ["Scheduled Job"]}
        ],
        ToolType.FW: [
            {"id": "T1071.001", "name": "Web Protocol Traffic (Update Check)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1071.004", "name": "DNS Traffic (Recursive Query)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1105", "name": "Ingress Tool Transfer (Driver Download)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1133", "name": "External Remote Services (Authorized VPN)", "tactics": ["persistence"], "data_sources": ["Network Boundary"]},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol (Large Upload)", "tactics": ["exfiltration"], "data_sources": ["Network Traffic"]},
            {"id": "T1571", "name": "Non-Standard Port Traffic (Legacy App)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1090", "name": "Proxy Traffic (Gateway Access)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1573", "name": "Encrypted Channel (Standard HTTPS)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1071.003", "name": "Mail Protocol (Legitimate SMTP)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel (Database Sync)", "tactics": ["exfiltration"], "data_sources": ["Network Traffic"]}
        ],
        ToolType.NDR: [
            {"id": "T1046", "name": "Network Service Discovery (Inventory Scan)", "tactics": ["discovery"], "data_sources": ["Network Traffic"]},
            {"id": "T1021.002", "name": "SMB/Windows Admin Shares (Internal Copy)", "tactics": ["lateral-movement"], "data_sources": ["Network Traffic"]},
            {"id": "T1021.001", "name": "Remote Desktop Protocol (IT Maintenance)", "tactics": ["lateral-movement"], "data_sources": ["Network Traffic"]},
            {"id": "T1018", "name": "Remote System Discovery (AD Sync)", "tactics": ["discovery"], "data_sources": ["Network Traffic"]},
            {"id": "T1087.002", "name": "Domain Account Discovery (Query)", "tactics": ["discovery"], "data_sources": ["Network Traffic"]},
            {"id": "T1550.002", "name": "Pass the Hash (Admin Script)", "tactics": ["lateral-movement"], "data_sources": ["Logon Session"]},
            {"id": "T1021.004", "name": "SSH (Management Access)", "tactics": ["lateral-movement"], "data_sources": ["Network Traffic"]},
            {"id": "T1039", "name": "Data from Network Shared Drive (Search)", "tactics": ["collection"], "data_sources": ["Network Traffic"]},
            {"id": "T1071.002", "name": "File Transfer Protocols (Internal FTP)", "tactics": ["command-and-control"], "data_sources": ["Network Traffic"]},
            {"id": "T1016", "name": "System Network Configuration Discovery", "tactics": ["discovery"], "data_sources": ["Network Traffic"]}
        ],
        ToolType.WAF: [
            {"id": "T1190", "name": "Exploit Public-Facing Application (False Hit)", "tactics": ["initial-access"], "data_sources": ["HTTP Request"]},
            {"id": "T1505.003", "name": "Web Shell (Authorized Web Console)", "tactics": ["persistence"], "data_sources": ["Application Log"]},
            {"id": "T1071.001", "name": "Web Protocols (API Request)", "tactics": ["command-and-control"], "data_sources": ["HTTP Request"]},
            {"id": "T1567", "name": "Exfiltration to Cloud Repository (File Upload)", "tactics": ["exfiltration"], "data_sources": ["HTTP Request"]},
            {"id": "T1566", "name": "Phishing (Legitimate Email Link)", "tactics": ["initial-access"], "data_sources": ["HTTP Request"]},
            {"id": "T1213", "name": "Data from Information Repositories (Wiki)", "tactics": ["collection"], "data_sources": ["HTTP Request"]},
            {"id": "T1059.007", "name": "JavaScript (Legacy Site)", "tactics": ["execution"], "data_sources": ["HTTP Request"]},
            {"id": "T1102", "name": "Web Service (Third-party Integration)", "tactics": ["command-and-control"], "data_sources": ["HTTP Request"]},
            {"id": "T1568", "name": "Dynamic Resolution (Content Delivery)", "tactics": ["command-and-control"], "data_sources": ["HTTP Request"]},
            {"id": "T1595", "name": "Active Scanning (Authorized Audit)", "tactics": ["reconnaissance"], "data_sources": ["HTTP Request"]}
        ],
        ToolType.SIEM: [
            {"id": "T1078.002", "name": "Domain Accounts (Standard Admin Logon)", "tactics": ["initial-access"], "data_sources": ["Logon Session"]},
            {"id": "T1484.001", "name": "Domain Policy Modification (Authorized GPO)", "tactics": ["defense-evasion", "privilege-escalation"], "data_sources": ["Active Directory"]},
            {"id": "T1098", "name": "Account Manipulation (Password Reset)", "tactics": ["persistence"], "data_sources": ["User Account"]},
            {"id": "T1531", "name": "Account Access Removal (Disabled User)", "tactics": ["impact"], "data_sources": ["User Account"]},
            {"id": "T1078.003", "name": "Cloud Accounts (Azure AD Sync)", "tactics": ["initial-access"], "data_sources": ["Logon Session"]},
            {"id": "T1003", "name": "OS Credential Dumping (False Positive)", "tactics": ["credential-access"], "data_sources": ["Active Directory"]},
            {"id": "T1553.002", "name": "Subvert Trust Controls (Cert Auto-enroll)", "tactics": ["defense-evasion"], "data_sources": ["Certificate"]},
            {"id": "T1078.001", "name": "Default Accounts (Local System)", "tactics": ["initial-access"], "data_sources": ["Logon Session"]},
            {"id": "T1070.001", "name": "Clear Windows Event Logs (Maintenance)", "tactics": ["defense-evasion"], "data_sources": ["Application Log"]},
            {"id": "T1548.002", "name": "Bypass User Account Control (Admin Tool)", "tactics": ["privilege-escalation", "defense-evasion"], "data_sources": ["Process"]}
        ]
    }

    def __init__(self, techniques: List[Dict[str, Any]], organization: Organization, segmentation: float = 0.5, deviation: float = 0.2):
        self.techniques = techniques
        self.org = organization
        self.segmentation = segmentation
        self.deviation = deviation
        self.tactic_order = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
        self.critical_tactics = ["initial-access", "lateral-movement", "exfiltration", "impact"]
        self._group_techniques()

    def _group_techniques(self):
        self.tech_by_tactic = {t: [] for t in self.tactic_order}
        for tech in self.techniques:
            for tactic in tech.get('tactics', []):
                if tactic in self.tech_by_tactic:
                    self.tech_by_tactic[tactic].append(tech)

    def _get_tools_for_technique(self, tech: Dict[str, Any]) -> List[SecurityTool]:
        data_sources = tech.get('data_sources', [])
        required_tool_types = set()
        for ds in data_sources:
            if not isinstance(ds, str): continue
            for ds_key, tool_types in self.DATA_SOURCE_MAPPING.items():
                if ds_key.lower() in ds.lower():
                    required_tool_types.update(tool_types)
        if not required_tool_types:
            required_tool_types = {ToolType.EDR, ToolType.SIEM}
        return [t for t in self.org.deployed_tools if t.type in required_tool_types]

    def simulate_attack_path(self) -> List[Dict[str, Any]]:
        all_events = []
        num_tracks = random.randint(1, 3)
        for track_id in range(num_tracks):
            all_events.extend(self._simulate_track(f"track_{track_id}"))
        return all_events

    def _simulate_track(self, track_name: str) -> List[Dict[str, Any]]:
        events = []
        potential_entry_points = [a for a in self.org.assets if a.device_type in [DeviceType.WORKSTATION, DeviceType.SERVER]]
        if not potential_entry_points: return []
        current_host = random.choice(potential_entry_points)
        for tactic in self.tactic_order:
            if tactic not in self.critical_tactics and random.random() < self.deviation:
                continue 
            possible_techs = list(self.tech_by_tactic.get(tactic, []))
            if not possible_techs or random.random() < (self.deviation * 0.5):
                all_generic = []
                for tool_noise in self.BENIGN_SCENARIOS.values():
                    all_generic.extend([s for s in tool_noise if tactic in s.get('tactics', [])])
                if all_generic: possible_techs = [random.choice(all_generic)]
                elif not possible_techs: continue
            num_to_exec = random.randint(1, 3)
            techs_to_exec = random.sample(possible_techs, min(num_to_exec, len(possible_techs)))
            for tech in techs_to_exec:
                is_lateral = (tactic == "lateral-movement")
                if is_lateral and random.random() < self.segmentation: continue
                capable_tools = self._get_tools_for_technique(tech)
                if not capable_tools: continue
                if random.random() > self.org.security_coverage: continue
                tool = random.choice(capable_tools)
                dest_asset = None
                if is_lateral or tactic == "discovery":
                    dest_asset = random.choice([a for a in self.org.assets if a.ip != current_host.ip])
                events.append({"technique": tech, "asset": current_host, "destination_asset": dest_asset, "tool": tool, "is_benign": False, "is_internal": (is_lateral or tactic == "discovery"), "track": track_name})
                if is_lateral and dest_asset: current_host = dest_asset
        return events

    def generate_noise(self, activity_level: float, duration_days: int) -> List[Dict[str, Any]]:
        noise_events = []
        num_logs = int(activity_level * 150 * duration_days)
        for _ in range(num_logs):
            asset = random.choice(self.org.assets)
            possible_tool_types = [t.type for t in self.org.deployed_tools if t.type in self.BENIGN_SCENARIOS]
            if not possible_tool_types: continue
            tool_type = random.choice(possible_tool_types)
            tool = random.choice([t for t in self.org.deployed_tools if t.type == tool_type])
            scenario = random.choice(self.BENIGN_SCENARIOS[tool_type])
            is_internal = random.random() < 0.2
            dest_asset = None
            if is_internal:
                dest_asset = random.choice([a for a in self.org.assets if a.ip != asset.ip])
            noise_events.append({"technique": scenario, "asset": asset, "destination_asset": dest_asset, "tool": tool, "is_benign": True, "is_internal": is_internal})
        return noise_events
