# Contributing to AttackAxis

First off, thank you for considering contributing to AttackAxis! It's people like you that make this a great tool for the cybersecurity community.

## 🌈 How Can I Contribute?

### Reporting Bugs
- Use the GitHub Issue Tracker.
- Describe the exact steps to reproduce the behavior.
- Include details about your environment (OS, Python version).

### Suggesting Enhancements
- Explain why the enhancement would be useful.
- Provide examples of how it would work.
- If it's a new TTP or Noise Scenario, provide the MITRE ID if possible.

### Pull Requests
1. **Fork the repo** and create your branch from `main`.
2. **Install dependencies** including development tools.
3. **If you've added code**, add tests or verify with a sample simulation.
4. **Ensure your code follows the style** of the existing project.
5. **Issue that pull request!**

## 🛠️ Technical Guidelines

### Simulation Engine (`src/simulator.py`)
- When adding new noise scenarios, ensure they map to realistic TTPs and logically capable tools.
- Maintain the stateful logic of the `BreachTrack` engine.

### Telemetry & Ports (`src/generator.py`)
- If adding port mappings, use industry-standard assignments for the given TTP.

### Frontend (`web/`)
- Maintain the "Elite Terminal" aesthetic.
- Keep the UI responsive and high-density.

## 📜 Code of Conduct
Please be respectful and professional in all interactions within this project.

## 💎 License
By contributing, you agree that your contributions will be licensed under its Apache License 2.0.
