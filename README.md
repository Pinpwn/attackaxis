# 🛡️ AttackAxis: Elite SOC Simulation Platform

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange.svg)](https://attack.mitre.org/)

**AttackAxis** is a high-fidelity adversarial simulation engine designed to generate realistic security telemetry for SOC training, SIEM validation, and detection engineering. It bridges the gap between static threat intelligence and actionable logs by simulating complex "Attack Chains" across a virtual organizational landscape.

---

## 🚀 Key Features

### 1. **Stateful Attack Chain Engine**
Unlike random log generators, AttackAxis simulates cohesive **Breach Tracks**. Adversaries infiltrate an entry point, perform discovery, and move laterally across internal assets, creating a traceable and logical sequence of alerts.

### 2. **Context-Aware Telemetry**
- **Tool Attribution**: Alerts are intelligently mapped to logically capable tools (EDR, NDR, FW, SIEM, WAF) based on MITRE STIX data sources.
- **Network Realism**: Includes `srcport` and `dstport` logic based on specific TTPs (e.g., RDP on 3389, SMB on 445).
- **East-West Simulation**: Realistically models internal lateral movement and discovery traffic.

### 3. **High-Fidelity Noise Floor**
Simulates "The Needle in the Haystack" by injecting **50+ False Positive Scenarios**. Normal administrative and user activities (e.g., authorized PowerShell scripts, Windows Updates) trigger legitimate MITRE TTPs, challenging analysts to distinguish noise from true threats.

### 4. **Professional Command Interface**
A sleek, high-tech terminal dashboard optimized for elite analyst UX:
- **Global Risk Index**: Real-time organizational health monitoring.
- **Signal-to-Noise Ratio**: Metric-driven complexity assessment.
- **Tactic Heatmap**: Visualizes the attack progression across the MITRE framework.
- **Entity Dossier**: Deep-dive into adversarial intelligence and aliases.

### 5. **Elite Export Suite**
Export high-fidelity datasets in multiple professional formats:
- **Formats**: CSV, JSON, JSONL, Syslog, CEF (Common Event Format), LEEF.
- **Custom Mapping**: Surgically select columns and apply schema aliases (e.g., `srcip` → `deviceAddress`) during the export workflow.
- **Time Formatting**: Support for ISO 8601, Unix Epoch, and custom Python date strings.

---

## 🛠️ Installation

### Prerequisites
- Python 3.10 or higher

### Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/attackaxis.git
   cd attackaxis
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🕹️ Usage

### Engaging the Mission (Web UI)
Launch the professional command interface on elite port **1337**:
```bash
python3 -m src.api
```
Navigate to **`http://localhost:1337`** to begin.

1.  **Mission Setup**: Define your target APT, organization vertical, and defense posture.
2.  **Simulation Deviation**: Adjust the slider to introduce unpredictability into the attack path.
3.  **Command Center**: Analyze the generated logs, visualize risk trends, and deep-dive into threat intel.
4.  **Telemetry Deployment**: Use the **EXPORT** suite to generate datasets for your SIEM or training platform.

### CLI Mode (Legacy)
For a quick terminal-based simulation:
```bash
python3 -m src.main
```

---

## 🏗️ Architecture

- **`src/ingestor.py`**: Automated MITRE Enterprise ATT&CK parser via STIX.
- **`src/simulator.py`**: The stateful breach track and noise generation engine.
- **`src/generator.py`**: High-fidelity log constructor with intelligent port mapping.
- **`src/api.py`**: FastAPI backend serving simulation logic and telemetry.
- **`web/`**: Modern React-based frontend with a hi-tech terminal aesthetic.

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to improve the simulation engine or dashboard.

---

## 📜 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

AttackAxis is intended for **authorized security research, training, and defensive validation only**. The logs generated are simulations and do not represent actual system compromises. Use responsibly.
