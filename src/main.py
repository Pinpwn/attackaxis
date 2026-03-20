import argparse
import sys
import json
import os
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, FloatPrompt, Confirm
from rich.panel import Panel
from rich.progress import Progress
from datetime import datetime

from .ingestor import MITREIngestor
from .simulator import OrgSimulator, AttackSimulator
from .generator import LogGenerator
from .models import SimulationConfig, ToolType

console = Console()
SESSIONS_DIR = "sessions"

def save_session(config: SimulationConfig):
    """Saves the simulation config to a session file."""
    if not os.path.exists(SESSIONS_DIR):
        os.makedirs(SESSIONS_DIR)
    
    file_path = os.path.join(SESSIONS_DIR, f"{config.session_name}.json")
    with open(file_path, 'w') as f:
        f.write(config.model_dump_json(indent=2))
    console.print(f"[bold green]Session '{config.session_name}' saved to {file_path}[/bold green]")

def load_session(session_name: str) -> Optional[SimulationConfig]:
    """Loads a simulation config from a session file."""
    file_path = os.path.join(SESSIONS_DIR, f"{session_name}.json")
    if not os.path.exists(file_path):
        console.print(f"[bold red]Session '{session_name}' not found.[/bold red]")
        return None
    
    with open(file_path, 'r') as f:
        data = json.load(f)
        return SimulationConfig(**data)

def list_sessions() -> List[str]:
    """Lists all saved session names."""
    if not os.path.exists(SESSIONS_DIR):
        return []
    return [f.replace(".json", "") for f in os.listdir(SESSIONS_DIR) if f.endswith(".json")]

def get_config_interactively(ingestor: MITREIngestor) -> SimulationConfig:
    console.print(Panel("[bold cyan]AttackAxis: Advanced Log Simulation Tool[/bold cyan]"))
    
    # Check for existing sessions
    existing_sessions = list_sessions()
    if existing_sessions:
        if Confirm.ask(f"Found {len(existing_sessions)} existing sessions. Load one?"):
            session_name = Prompt.ask("Select session to load", choices=existing_sessions)
            config = load_session(session_name)
            if config:
                if Confirm.ask(f"Loaded '{session_name}'. Use this config?"):
                    return config

    # 1. Session Name
    session_name = Prompt.ask("Enter a name for this session", default=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    # 2. Select Target APT/Campaign/Software
    with console.status("Fetching available MITRE objects..."):
        available = ingestor.list_available_objects()
    
    console.print("\n[bold]Select object type to simulate:[/bold]")
    console.print("1. APT/Groups")
    console.print("2. Campaigns")
    console.print("3. Software (Malware/Tools)")
    
    choice = Prompt.ask("Enter choice", choices=["1", "2", "3"], default="1")
    
    if choice == "1":
        object_list = available["groups"]
        type_label = "Group"
    elif choice == "2":
        object_list = available["campaigns"]
        type_label = "Campaign"
    else:
        object_list = available["software"]
        type_label = "Software"

    target_obj = Prompt.ask(f"Select {type_label} to simulate", choices=object_list)
    
    # 3. Configure Organization
    org_size = IntPrompt.ask("Enter organization size (number of assets)", default=100)
    
    console.print("\n[bold]Select security tools deployed:[/bold]")
    available_tools = [t.value for t in ToolType]
    console.print(f"Available tools: {', '.join(available_tools)}")
    
    selected_tools_str = Prompt.ask("Enter tools (comma separated)", default="EDR,FW,NDR")
    selected_tools = [ToolType(t.strip().upper()) for t in selected_tools_str.split(",") if t.strip().upper() in available_tools]
    
    security_coverage = FloatPrompt.ask("Enter security coverage percentage (0.0 to 0.9)", default=0.7)
    if security_coverage > 0.9:
        console.print("[yellow]Warning: Coverage maxed at 0.9 as per guidelines.[/yellow]")
        security_coverage = 0.9

    # 4. Attack Duration
    duration_days = IntPrompt.ask("Enter attack duration (in days)", default=7)
    
    # 5. Configure Output
    console.print("\n[bold]Configure Output Fields:[/bold]")
    all_possible_fields = ["time", "srcip", "dstip", "ttp", "devicename", "devicetype", "severity", "message", "tool_name", "tool_type"]
    console.print(f"Available fields: {', '.join(all_possible_fields)}")
    
    selected_fields_str = Prompt.ask("Enter fields to include (comma separated)", default="time,srcip,ttp,devicename,severity")
    selected_fields = [f.strip() for f in selected_fields_str.split(",") if f.strip() in all_possible_fields]
    
    # 6. Field Mapping
    field_mapping = {}
    if Confirm.ask("Do you want to provide custom keynames (mapping)?"):
        for field in selected_fields:
            mapping = Prompt.ask(f"Map '{field}' to (press enter to keep original)", default=field)
            if mapping != field:
                field_mapping[field] = mapping
    
    config = SimulationConfig(
        session_name=session_name,
        target_apt=target_obj,
        org_size=org_size,
        tools=selected_tools,
        security_coverage=security_coverage,
        duration_days=duration_days,
        output_fields=selected_fields,
        field_mapping=field_mapping
    )
    
    if Confirm.ask("Save this session for future use?"):
        save_session(config)
        
    return config

def run_simulation(config: SimulationConfig, ingestor: MITREIngestor):
    # Step 1: Ingest Data
    with console.status(f"[bold green]Fetching techniques for {config.target_apt}..."):
        techniques = ingestor.get_techniques_for_object(config.target_apt)
    
    if not techniques:
        console.print(f"[bold red]No techniques found for {config.target_apt}. Aborting.[/bold red]")
        return

    # Step 2: Simulate Organization
    with console.status("[bold green]Simulating organization assets..."):
        org_sim = OrgSimulator(config.org_size, config.security_coverage, config.tools)
        org = org_sim.get_organization()

    # Step 3: Simulate Attack Path
    with console.status(f"[bold green]Simulating attack path over {config.duration_days} days..."):
        attack_sim = AttackSimulator(techniques, org)
        events = attack_sim.simulate_attack_path()

    # Step 4: Generate Logs
    log_gen = LogGenerator(events, config)
    logs = log_gen.generate_logs()
    asset_mapping = log_gen.get_asset_mapping(org.assets)

    # Step 5: Display Results
    console.print(Panel(f"[bold cyan]Simulation Results: {config.session_name}[/bold cyan]\n[italic]Simulating {config.target_apt} over {config.duration_days} days[/italic]"))
    
    # Display Asset Mapping (partial)
    asset_table = Table(title="Asset Inventory (First 5)")
    asset_table.add_column("IP")
    asset_table.add_column("MAC")
    asset_table.add_column("Type")
    asset_table.add_column("Hostname")
    for asset in asset_mapping[:5]:
        asset_table.add_row(asset['ip'], asset['mac'], asset['device_type'], asset['hostname'])
    console.print(asset_table)

    # Display Logs (Top and Bottom to show duration spread)
    if logs:
        log_table = Table(title=f"Generated Logs ({len(logs)} entries)")
        for field in config.output_fields:
            header = config.field_mapping.get(field, field)
            log_table.add_column(header)
        
        # Show first 5 and last 5 if many logs
        display_logs = logs if len(logs) <= 15 else logs[:7] + [{"...": "..."}] + logs[-7:]
        
        for log in display_logs:
            if "..." in log:
                log_table.add_row(*(["..."] * len(config.output_fields)))
                continue
            row = [str(log.get(config.field_mapping.get(f, f), "")) for f in config.output_fields]
            log_table.add_row(*row)
        
        console.print(log_table)
    else:
        console.print("[yellow]No logs generated for this simulation (check security coverage).[/yellow]")
    
    # Option to save results
    if logs and Confirm.ask("Save logs to file?"):
        default_name = f"{config.session_name}_logs.json"
        filename = Prompt.ask("Enter filename", default=default_name)
        with open(filename, 'w') as f:
            json.dump(logs, f, indent=2)
        console.print(f"[bold green]Logs saved to {filename}[/bold green]")
        
        mapping_file = f"{config.session_name}_assets.json"
        with open(mapping_file, 'w') as f:
            json.dump(asset_mapping, f, indent=2)
        console.print(f"[bold green]Asset mapping saved to {mapping_file}[/bold green]")

def main():
    ingestor = MITREIngestor()
    try:
        config = get_config_interactively(ingestor)
        run_simulation(config, ingestor)
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]An error occurred: {e}[/bold red]")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
