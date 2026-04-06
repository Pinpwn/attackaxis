from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import os
import json

from .models import SimulationConfig, ToolType, Asset
from .ingestor import MITREIngestor
from .simulator import OrgSimulator, AttackSimulator
from .generator import LogGenerator

app = FastAPI(title="AttackAxis API")

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SESSIONS_DIR = "sessions"
ingestor = MITREIngestor()

from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import os

app.mount("/static", StaticFiles(directory="web"), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_index():
    with open("web/index.html", "r") as f:
        return f.read()

@app.get("/api/mitre/objects")
async def get_mitre_objects():
    return ingestor.list_available_objects()

@app.post("/api/simulate")
async def simulate(config: SimulationConfig):
    techniques = ingestor.get_techniques_for_object(config.target_apt)
    if not techniques:
        raise HTTPException(status_code=404, detail=f"No techniques found for {config.target_apt}")

    intel = ingestor.get_object_details(config.target_apt)

    org_sim = OrgSimulator(config.org_size, config.security_coverage, config.tools)
    org = org_sim.get_organization()

    attack_sim = AttackSimulator(techniques, org, segmentation=config.network_segmentation, deviation=config.simulation_deviation)
    attack_events = attack_sim.simulate_attack_path()
    noise_events = attack_sim.generate_noise(config.user_activity_level, config.duration_days)

    all_events = attack_events + noise_events
    
    log_gen = LogGenerator(all_events, config)
    logs = log_gen.generate_logs()
    asset_mapping = log_gen.get_asset_mapping(org.assets)

    # Metrics
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    tactic_counts = {}
    tool_performance = {} # tool_type -> {detected: X, missed: Y}
    asset_risk = {}
    
    attack_logs = [l for l in logs if not l.get('is_benign', False)]
    
    for log in logs:
        is_attack = not log.get('is_benign', False)
        sev = log.get('severity', 'Low')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Tactic Distribution
        tactics = log.get('tactics', [])
        for t in tactics:
            t_name = t.replace("-", " ").title()
            tactic_counts[t_name] = tactic_counts.get(t_name, 0) + 1
        
        if is_attack:
            host = log.get('devicename', 'unknown')
            weight = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}.get(sev, 1)
            asset_risk[host] = asset_risk.get(host, 0) + weight
            
            t_type = log.get('tool_type', 'Unknown')
            if t_type not in tool_performance: tool_performance[t_type] = 0
            tool_performance[t_type] += 1

    risky_assets = sorted([{"host": k, "score": v} for k, v in asset_risk.items()], key=lambda x: x['score'], reverse=True)[:5]
    
    asset_types = {}
    for asset in asset_mapping:
        asset_types[asset['device_type']] = asset_types.get(asset['device_type'], 0) + 1

    # Weighted Risk Score
    base_risk = (severity_counts["Critical"] * 25 + severity_counts["High"] * 12 + severity_counts["Medium"] * 6)
    coverage_factor = (1.0 - config.security_coverage)
    segmentation_benefit = (1.0 - config.network_segmentation * 0.5)
    final_risk_score = min(100, int(base_risk * coverage_factor * segmentation_benefit / (config.org_size / 50)))

    return {
        "logs": logs,
        "assets": asset_mapping,
        "network_edges": org.network_edges,
        "config": config,
        "intel": intel,
        "metrics": {
            "severity_counts": severity_counts,
            "tactic_counts": tactic_counts,
            "tool_performance": tool_performance,
            "risky_assets": risky_assets,
            "asset_types": asset_types,
            "risk_score": final_risk_score,
            "total_alerts": len(logs),
            "attack_alerts": len(attack_logs)
        }
    }

@app.get("/api/sessions")
async def list_sessions():
    if not os.path.exists(SESSIONS_DIR):
        return []
    return [f.replace(".json", "") for f in os.listdir(SESSIONS_DIR) if f.endswith(".json")]

@app.get("/api/sessions/{name}")
async def load_session(name: str):
    file_path = os.path.join(SESSIONS_DIR, f"{name}.json")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Session not found")
    
    with open(file_path, 'r') as f:
        return json.load(f)

@app.delete("/api/sessions/{name}")
async def delete_session(name: str):
    file_path = os.path.join(SESSIONS_DIR, f"{name}.json")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        os.remove(file_path)
        return {"status": "success", "message": f"Session {name} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sessions")
async def save_session(config: SimulationConfig):
    if not os.path.exists(SESSIONS_DIR):
        os.makedirs(SESSIONS_DIR)
    
    file_path = os.path.join(SESSIONS_DIR, f"{config.session_name}.json")
    with open(file_path, 'w') as f:
        f.write(config.model_dump_json(indent=2))
    return {"status": "success", "message": f"Session {config.session_name} saved"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=1337)
