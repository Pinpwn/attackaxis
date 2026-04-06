# AttackAxis

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange.svg)](https://attack.mitre.org/)

## Introduction

AttackAxis is a sophisticated adversarial simulation platform designed to generate high-fidelity security telemetry. Unlike static log generators, AttackAxis models the complex, stateful behaviors of real-world threat actors within a simulated organizational environment. It is engineered for security operations center (SOC) training, SIEM validation, and the development of robust detection engineering pipelines.

## Purpose

The primary objective of AttackAxis is to bridge the gap between abstract threat intelligence and practical defensive operations. By simulating cohesive "Attack Chains" rather than isolated events, the platform provides analysts with a realistic environment to:
- **Validate Detection Logic**: Test SIEM rules and XDR capabilities against multi-hop breach tracks.
- **Train SOC Analysts**: Provide a "blackbox" triage experience where malicious signals are buried within realistic background noise.
- **Forensic Research**: Analyze the correlation between host-based process telemetry and network-based traffic anomalies.

## Architectural Overview

AttackAxis is built on a modular Python-based engine with a modern decoupled frontend. The architecture follows a data-driven approach, leveraging the MITRE ATT&CK® framework via STIX integration.

### Core Components

1.  **Threat Ingestor (`src/ingestor.py`)**: Automatically retrieves and parses the latest MITRE Enterprise ATT&CK dataset. it maps techniques to their required data sources, enabling logical tool attribution.
2.  **Simulation Engine (`src/simulator.py`)**: 
    - **Topology Module**: Generates a hierarchical network layout (Core, Distribution, Access) based on standard network engineering principles.
    - **Breach Engine**: Orchestrates stateful attack tracks. It maintains session state, handles lateral movement pivots, and simulates defensive evasion (e.g., EDR impairment).
    - **Noise Generator**: Injects realistic false positives based on actual administrative and user behaviors mapped to MITRE TTPs.
3.  **Log Constructor (`src/generator.py`)**: Transforms simulated events into high-fidelity logs. It implements intelligent port mapping, forensic artifact generation (process paths, command lines), and human-centric temporal clustering (operating hours).
4.  **Backend API (`src/api.py`)**: A FastAPI-powered REST interface that serves as the bridge between the simulation engine and external interfaces.
5.  **Command Dashboard (`web/`)**: A React-based XDR interface that emulates a modern SOC triage environment, featuring incident correlation, threat hunting tools, and network topology visualization.

---

## Key Capabilities

### Stateful Multi-Hop Simulation
AttackAxis simulates the logical progression of an adversary. Tracks begin with infiltration, followed by local consolidation and discovery, before attempting lateral movement to deeper network tiers.

### Hierarchical Network Modeling
The simulation environment is structured into a three-tier hierarchical model. Analysts can visualize the network topology and trace the path of an intrusion from the edge firewall down to internal workstations.

### Professional Telemetry Export
The platform supports a wide array of industry-standard log formats, including **CEF, LEEF, Syslog, JSONL, and CSV**. Analysts can customize schema mappings and time formatting during the export process to ensure compatibility with any SIEM or data lake.

---

## Installation

### Prerequisites
- Python 3.10 or higher

### Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/attackaxis.git
   cd attackaxis
   ```

2. **Initialize Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

---

## Usage

### Web Interface (Operational)
To launch the XDR Command Interface:
```bash
python3 -m src.api
```
Navigate to `http://localhost:1337` to begin a mission.

1.  **Mission Setup**: Configure the target adversary, network density, and defensive posture.
2.  **Analysis**: Use the **Triage Queue** to investigate correlated incidents or the **Threat Hunting** tab for granular log analysis.
3.  **Export**: Deploy the generated dataset using the integrated Export Engine.

### CLI Mode (Automated)
For scripted or headless simulations:
```bash
python3 -m src.main
```

---

## Community and Contributions

We welcome contributions from the security community. Please review `CONTRIBUTING.md` for technical guidelines and our development workflow.

## License

AttackAxis is released under the **Apache License 2.0**. See the `LICENSE` file for full details.

## Disclaimer

AttackAxis is intended for **authorized security research and defensive validation only**. The logs and scenarios generated are simulations and do not represent actual system compromises.
