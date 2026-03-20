from pydantic import BaseModel, Field, IPvAnyAddress
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime

class ToolType(str, Enum):
    EDR = "EDR"
    FW = "FW"
    NDR = "NDR"
    WAF = "WAF"
    SIEM = "SIEM"
    AV = "AV"
    IDS = "IDS"
    IPS = "IPS"
    PROXY = "PROXY"
    HIDS = "HIDS"
    NIDS = "NIDS"

class DeviceType(str, Enum):
    WORKSTATION = "Workstation"
    SERVER = "Server"
    FIREWALL = "Firewall"
    ROUTER = "Router"
    SWITCH = "Switch"
    MOBILE = "Mobile"
    IOT = "IoT"

class Asset(BaseModel):
    ip: str
    mac: str
    device_type: DeviceType
    hostname: str
    description: str

class SecurityTool(BaseModel):
    name: str
    type: ToolType
    coverage_score: float = Field(0.0, ge=0.0, le=1.0) # 0 to 1

class Organization(BaseModel):
    name: str
    size: int # Number of assets
    deployed_tools: List[SecurityTool]
    security_coverage: float = Field(..., ge=0, le=0.9) # Max 90% as per requirements
    assets: List[Asset] = []

class LogEntry(BaseModel):
    time: datetime
    srcip: Optional[str] = None
    dstip: Optional[str] = None
    srcport: Optional[int] = None
    dstport: Optional[int] = None
    ttp: Optional[str] = None # MITRE Technique ID
    devicename: str
    devicetype: str
    severity: str # Low, Medium, High, Critical
    message: str
    additional_fields: Dict[str, Any] = {}

class IndustryType(str, Enum):
    FINANCIAL = "Financial"
    HEALTHCARE = "Healthcare"
    TECHNOLOGY = "Technology"
    GOVERNMENT = "Government"
    ENERGY = "Energy"
    EDUCATION = "Education"
    OTHER = "Other"

class SimulationConfig(BaseModel):
    session_name: str = Field(..., min_length=1)
    target_apt: str # Name of APT/Campaign/Software
    org_size: int = Field(100, ge=1)
    industry: IndustryType = IndustryType.OTHER
    network_segmentation: float = Field(0.5, ge=0.0, le=1.0) # 0.0: flat, 1.0: highly segmented
    user_activity_level: float = Field(0.5, ge=0.0, le=1.0) # 0.0: low noise, 1.0: high noise
    simulation_deviation: float = Field(0.2, ge=0.0, le=1.0) # 0.0: strict APT path, 1.0: highly random
    detection_latency_min: int = Field(15, ge=0, le=1440) # Mean minutes to detection
    tools: List[ToolType]
    security_coverage: float
    duration_days: int = Field(1, ge=1, le=365)
    output_fields: List[str]
    field_mapping: Dict[str, str] = {}
