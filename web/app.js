const { useState, useEffect, useRef } = React;

const EXPORT_FORMATS = ['CSV', 'JSON', 'JSONL', 'SYSLOG', 'CEF', 'LEEF'];
const ALL_FIELDS = ['time', 'srcip', 'srcport', 'dstip', 'dstport', 'ttp', 'devicename', 'username', 'process_name', 'command_line', 'severity', 'tool_name', 'tool_type'];
const TOOL_OPTIONS = ['EDR', 'FW', 'NDR', 'SIEM', 'WAF', 'AV', 'IPS', 'PROXY'];
const TOOL_ICONS = {
    'EDR': '🛡️',
    'FW': '🧱',
    'NDR': '🕸️',
    'SIEM': '👁️',
    'WAF': '🌐',
    'AV': '🦠',
    'IPS': '🛑',
    'PROXY': '🚪'
};

function ExportModal({ logs, onClose }) {
    const [selectedFields, setSelectedFields] = useState([...ALL_FIELDS]);
    const [mappings, setMappings] = useState({});
    const [format, setFormat] = useState('CSV');
    const [timeFormat, setTimeFormat] = useState('ISO');
    const [customTimeFormat, setCustomTimeFormat] = useState('%Y-%m-%d %H:%M:%S');

    const formatTime = (timeStr) => {
        const date = new Date(timeStr);
        if (timeFormat === 'EPOCH') return Math.floor(date.getTime() / 1000);
        if (timeFormat === 'CUSTOM') {
            let fmt = customTimeFormat;
            fmt = fmt.replace('%Y', date.getFullYear());
            fmt = fmt.replace('%m', String(date.getMonth() + 1).padStart(2, '0'));
            fmt = fmt.replace('%d', String(date.getDate()).padStart(2, '0'));
            fmt = fmt.replace('%H', String(date.getHours()).padStart(2, '0'));
            fmt = fmt.replace('%M', String(date.getMinutes()).padStart(2, '0'));
            fmt = fmt.replace('%S', String(date.getSeconds()).padStart(2, '0'));
            return fmt;
        }
        return timeStr;
    };

    const handleExport = () => {
        const exportedData = logs.map(l => {
            const row = {};
            selectedFields.forEach(f => {
                const key = mappings[f] || f;
                let val = l[f] !== undefined ? l[f] : '';
                if (f === 'time') val = formatTime(val);
                row[key] = val;
            });
            return row;
        });

        let blob, filename = `attackaxis_export.${format.toLowerCase()}`;
        if (format === 'JSON') {
            blob = new Blob([JSON.stringify(exportedData, null, 2)], { type: 'application/json' });
        } else if (format === 'JSONL') {
            const content = exportedData.map(r => JSON.stringify(r)).join('\n');
            blob = new Blob([content], { type: 'application/x-jsonlines' });
        } else if (format === 'CSV') {
            const headers = selectedFields.map(f => mappings[f] || f).join(',');
            const content = exportedData.map(r => Object.values(r).map(v => `"${v}"`).join(',')).join('\n');
            blob = new Blob([headers + '\n' + content], { type: 'text/csv' });
        } else {
            let content = '';
            if (format === 'SYSLOG') {
                content = exportedData.map(r => `<13> ${r.time || new Date().toISOString()} ${r.devicename || 'sensor'} AttackAxis: ${JSON.stringify(r)}`).join('\n');
            } else if (format === 'CEF') {
                content = exportedData.map(r => `CEF:0|AttackAxis|Simulator|1.0|${r.ttp || '0'}|${r.message || 'Alert'}|${r.severity || 'Low'}|${Object.entries(r).map(([k,v])=>`${k}=${v}`).join(' ')}`).join('\n');
            } else if (format === 'LEEF') {
                content = exportedData.map(r => `LEEF:1.0|AttackAxis|Simulator|1.0|${r.ttp || '0'}|${Object.entries(r).map(([k,v])=>`${k}=${v}`).join('\t')}`).join('\n');
            }
            blob = new Blob([content], { type: 'text/plain' });
        }

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename; a.click();
        onClose();
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
                <h2 className="mono accent">EXPORT_TELEMETRY_ENGINE</h2>
                <div className="form-group">
                    <label>EXPORT_FORMAT</label>
                    <select value={format} onChange={e => setFormat(e.target.value)}>
                        {EXPORT_FORMATS.map(f => <option key={f} value={f}>{f}</option>)}
                    </select>
                </div>
                <div className="form-group">
                    <label>TIME_FORMATTING</label>
                    <select value={timeFormat} onChange={e => setTimeFormat(e.target.value)}>
                        <option value="ISO">ISO 8601 (DEFAULT)</option>
                        <option value="EPOCH">UNIX EPOCH</option>
                        <option value="CUSTOM">PYTHON_CUSTOM_FORMAT</option>
                    </select>
                    {timeFormat === 'CUSTOM' && (
                        <input style={{marginTop: 5}} placeholder="%Y-%m-%d %H:%M:%S" value={customTimeFormat} onChange={e => setCustomTimeFormat(e.target.value)} />
                    )}
                </div>
                <label>SELECT_COLUMNS</label>
                <div className="field-grid">
                    {ALL_FIELDS.map(f => (
                        <div key={f} className="field-item">
                            <input type="checkbox" checked={selectedFields.includes(f)} onChange={e => {
                                setSelectedFields(e.target.checked ? [...selectedFields, f] : selectedFields.filter(x => x !== f));
                            }} />
                            <span style={{fontSize:11}}>{f}</span>
                        </div>
                    ))}
                </div>
                <label>KEY_MAPPING (ALIAS)</label>
                <div className="map-grid" style={{maxHeight:200, overflowY:'auto'}}>
                    {selectedFields.map(f => (
                        <div key={f} className="field-item">
                            <span className="mono" style={{fontSize:10, width:80}}>{f}:</span>
                            <input placeholder="New Key Name" value={mappings[f] || ''} onChange={e => setMappings({...mappings, [f]: e.target.value})} style={{fontSize:10, padding:4}} />
                        </div>
                    ))}
                </div>
                <div style={{display:'flex', gap:10, marginTop:20}}>
                    <button className="btn btn-primary" style={{flex:1}} onClick={handleExport}>GENERATE_EXPORT</button>
                    <button className="btn" style={{flex:1}} onClick={onClose}>ABORT</button>
                </div>
            </div>
        </div>
    );
}

function AssetGraphView({ assets, logs, network_edges }) {
    const containerRef = useRef(null);
    const networkInstance = useRef(null);

    useEffect(() => {
        if (!containerRef.current) return;

        const compromisedIPs = new Set();
        logs.forEach(l => {
            if (!l.is_benign && l.tactics && (l.tactics.includes("lateral-movement") || l.tactics.includes("execution") || l.tactics.includes("initial-access"))) {
                if (l.srcip) compromisedIPs.add(l.srcip);
                if (l.dstip) compromisedIPs.add(l.dstip);
            }
        });

        const nodes = new vis.DataSet(assets.map(a => {
            const isCompromised = compromisedIPs.has(a.ip);
            let shape = 'dot';
            let color = { background: '#1c2128', border: '#8b949e' };
            let size = 15;
            
            if (a.device_type === 'Firewall') { shape = 'triangle'; size = 25; color.border = '#00f2ff'; color.background = 'rgba(0, 242, 255, 0.1)'; }
            else if (a.device_type === 'Router') { shape = 'diamond'; size = 20; color.border = '#c9d1d9'; }
            else if (a.device_type === 'Server') { shape = 'square'; size = 18; color.border = '#58a6ff'; }
            
            if (isCompromised) {
                color.border = '#ff3e3e';
                color.background = 'rgba(255, 62, 62, 0.3)';
                size += 5;
            }

            return {
                id: a.ip,
                label: a.hostname + '\n' + a.ip,
                title: `${a.ip}\n${a.device_type}\n${a.description}`,
                shape: shape,
                size: size,
                color: color,
                level: a.level, // Crucial for hierarchical layout
                font: { color: isCompromised ? '#ff3e3e' : '#c9d1d9', size: 10, face: 'JetBrains Mono' }
            };
        }));

        const edgesArray = (network_edges || []).map((e, i) => ({
            id: `edge_${i}`,
            from: e.source,
            to: e.target,
            color: { color: '#8b949e', opacity: 0.8 },
            smooth: { type: 'continuous' }
        }));
        
        logs.forEach(l => {
            if (!l.is_benign && l.tactics && l.tactics.includes("lateral-movement") && l.srcip && l.dstip) {
                const edgeId = `lat_${l.srcip}_${l.dstip}`;
                edgesArray.push({
                    id: edgeId,
                    from: l.srcip,
                    to: l.dstip,
                    color: { color: '#ff3e3e', opacity: 1.0 },
                    arrows: 'to',
                    dashes: true,
                    width: 2
                });
            }
        });

        const edges = new vis.DataSet(edgesArray);
        const graphData = { nodes: nodes, edges: edges };
        const options = {
            layout: {
                hierarchical: {
                    direction: 'UD',
                    sortMethod: 'directed',
                    nodeSpacing: 150,
                    levelSeparation: 150,
                    parentCentralization: true
                }
            },
            physics: {
                hierarchicalRepulsion: {
                    nodeDistance: 150
                }
            },
            interaction: { hover: true, tooltipDelay: 200 }
        };

        try {
            if (networkInstance.current) {
                networkInstance.current.destroy();
            }
            networkInstance.current = new vis.Network(containerRef.current, graphData, options);
        } catch (err) {
            console.error("VIS_NETWORK_CRASH", err);
        }

        
        return () => {
            if (networkInstance.current) {
                networkInstance.current.destroy();
                networkInstance.current = null;
            }
        };
    }, [assets, logs, network_edges]);
    
    return <div ref={containerRef} style={{height: 600, width: '100%', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-base)'}}></div>;
}

function WarRoomModal({ incident, onClose }) {
    if (!incident) return null;
    return (
        <div className="modal-overlay" style={{zIndex: 4000}} onClick={onClose}>
            <div className="modal-content" style={{width: '80%', maxWidth: '1000px'}} onClick={e => e.stopPropagation()}>
                <h2 className="mono accent">WAR_ROOM // {incident.id}</h2>
                <div style={{maxHeight: '60vh', overflowY: 'auto'}}>
                    {incident.logs.map((l, i) => (
                        <div key={i} className="event-inspector" style={{borderLeft: '2px solid var(--accent-red)'}}>
                            {JSON.stringify(l, null, 2)}
                        </div>
                    ))}
                </div>
                <button className="btn" style={{marginTop: 20}} onClick={onClose}>CLOSE</button>
            </div>
        </div>
    );
}

function App() {
    const [view, setView] = useState('setup');
    const [mitreObjects, setMitreObjects] = useState({ groups: [], campaigns: [], software: [] });
    const [sessions, setSessions] = useState([]);
    const [loading, setLoading] = useState(false);
    const [data, setData] = useState(null);
    const [activeTab, setActiveTab] = useState('xdr');
    const [showExport, setShowExport] = useState(false);
    const [selectedIncident, setSelectedIncident] = useState(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [expandedLogId, setExpandedLogId] = useState(null);

    const [config, setConfig] = useState({
        session_name: `mission_${new Date().getTime().toString().slice(-6)}`,
        target_apt: '', org_size: 250, industry: 'Financial', network_segmentation: 0.5,
        user_activity_level: 0.3, simulation_deviation: 0.2, detection_latency_min: 30, tools: ['EDR', 'FW', 'NDR', 'SIEM'],
        security_coverage: 0.7, duration_days: 7, output_fields: [...ALL_FIELDS], field_mapping: {}
    });

    const chartRefs = { trend: useRef(null), tactics: useRef(null) };

    useEffect(() => {
        const init = async () => {
            try {
                const [mRes, sRes] = await Promise.all([fetch('/api/mitre/objects'), fetch('/api/sessions')]);
                const mData = await mRes.json();
                setMitreObjects(mData);
                setSessions(await sRes.json());
                if (mData.groups?.length) setConfig(c => ({...c, target_apt: mData.groups[0]}));
            } catch (e) { console.error("INIT_ERR", e); }
        };
        init();
    }, []);

    useEffect(() => {
        if (data && view === 'dashboard' && activeTab === 'xdr') {
            const t = setTimeout(renderXdrCharts, 100);
            return () => clearTimeout(t);
        }
    }, [data, view, activeTab]);

    const renderXdrCharts = () => {
        Object.values(chartRefs).forEach(r => r.current?.destroy());
        const attackData = {};
        const noiseData = {};
        data.logs.forEach(l => { 
            const d = l.time.split('T')[0]; 
            if (l.is_benign) noiseData[d] = (noiseData[d] || 0) + 1;
            else attackData[d] = (attackData[d] || 0) + 1;
        });
        const days = Array.from(new Set([...Object.keys(attackData), ...Object.keys(noiseData)])).sort();
        
        chartRefs.trend.current = new Chart(document.getElementById('chartTrend'), {
            type: 'line',
            data: { 
                labels: days, 
                datasets: [
                    { label: 'Malicious Alerts', data: days.map(d => attackData[d] || 0), backgroundColor: 'rgba(239, 68, 68, 0.2)', borderColor: '#ef4444', fill: true, tension: 0.4 },
                    { label: 'Benign Noise', data: days.map(d => noiseData[d] || 0), backgroundColor: 'rgba(148, 163, 184, 0.1)', borderColor: '#94a3b8', fill: true, tension: 0.4 }
                ]
            },
            options: { maintainAspectRatio: false, scales: { x: { grid: { color: '#1e293b' } }, y: { grid: { color: '#1e293b' } } }, plugins: { legend: { position: 'bottom' } } }
        });

        const tactics = data.metrics.tactic_counts;
        chartRefs.tactics.current = new Chart(document.getElementById('chartTactics'), {
            type: 'bar',
            data: { labels: Object.keys(tactics), datasets: [{ data: Object.values(tactics), backgroundColor: '#00f2ff' }]},
            options: { indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#161b22' } }, y: { grid: { color: '#161b22' } } } }
        });
    };

    const runSimulation = async () => {
        setLoading(true);
        try {
            const res = await fetch('/api/simulate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) });
            const result = await res.json();
            if (res.ok) { setData(result); setView('dashboard'); setActiveTab('xdr'); }
            else { alert(`SIM_ERR: ${result.detail || 'Unknown Error'}`); }
        } catch (e) { alert(`NET_ERR: ${e.message}`); }
        finally { setLoading(false); }
    };

    const loadSession = async (name) => {
        setLoading(true);
        try {
            const res = await fetch(`/api/sessions/${name}`);
            setConfig(await res.json());
        } catch(e) {}
        finally { setLoading(false); }
    };

    const saveSession = async () => {
        try {
            await fetch('/api/sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) });
            alert("MISSION_SAVED");
            const res = await fetch('/api/sessions');
            setSessions(await res.json());
        } catch(e) { alert("SAVE_ERROR"); }
    };

    const deleteSession = async (name) => {
        if (!confirm(`Are you sure you want to delete session '${name}'?`)) return;
        try {
            await fetch(`/api/sessions/${name}`, { method: 'DELETE' });
            const res = await fetch('/api/sessions');
            setSessions(await res.json());
            if (config.session_name === name) {
                setConfig({...config, session_name: `mission_${new Date().getTime().toString().slice(-6)}`});
            }
        } catch(e) { alert("DELETE_ERROR"); }
    };

    const getIncidents = () => {
        if (!data) return [];
        const incidentsMap = {};
        data.logs.forEach(l => {
            if (l.is_benign) return;
            const track = l.track || 'UNKNOWN';
            if (!incidentsMap[track]) {
                incidentsMap[track] = { id: `INC-${track.toUpperCase()}`, logs: [], maxSev: 'Low', target: l.devicename, tactics: new Set() };
            }
            incidentsMap[track].logs.push(l);
            incidentsMap[track].tactics.add(...(l.tactics || []));
            if (l.severity === 'Critical') incidentsMap[track].maxSev = 'Critical';
            else if (l.severity === 'High' && incidentsMap[track].maxSev !== 'Critical') incidentsMap[track].maxSev = 'High';
            else if (l.severity === 'Medium' && !['Critical', 'High'].includes(incidentsMap[track].maxSev)) incidentsMap[track].maxSev = 'Medium';
        });
        return Object.values(incidentsMap).sort((a,b) => b.logs.length - a.logs.length);
    };

    const filteredLogs = data ? data.logs.filter(l => {
        if (!searchQuery) return true;
        const q = searchQuery.toLowerCase();
        return Object.values(l).some(v => String(v).toLowerCase().includes(q));
    }) : [];

    return (
        <div style={{height:'100vh', display:'flex', flexDirection:'column'}}>
            <header>
                <div className="header-title">ATTACKAXIS // COMMAND_INTERFACE</div>
                <div className="mono" style={{fontSize:10, color:'var(--text-secondary)'}}>STATUS: <span style={{color:'var(--accent-green)'}}>READY</span></div>
            </header>
            <div className="main-container">
                {loading && <div className="loading-overlay"><div className="mono accent" style={{fontSize:24, letterSpacing:4}}>EXECUTING_SIMULATION...</div></div>}
                {showExport && <ExportModal logs={data.logs} onClose={() => setShowExport(false)} />}
                {selectedIncident && <WarRoomModal incident={selectedIncident} onClose={() => setSelectedIncident(null)} />}
                
                {view === 'setup' ? (
                    <div className="setup-view">
                        <h2 className="mono accent">MISSION_CONFIGURATION</h2>
                        <div className="setup-grid">
                            <div className="setup-section col-6">
                                <span className="section-label">01 // TARGETING</span>
                                <div className="form-group"><label title="Select the threat actor or malware to simulate based on MITRE ATT&CK profiles.">ADVERSARY</label>
                                    <select value={config.target_apt} onChange={e => setConfig({...config, target_apt: e.target.value})}>
                                        <optgroup label="Groups">{mitreObjects.groups.map(g => <option key={g} value={g}>{g}</option>)}</optgroup>
                                        <optgroup label="Software">{mitreObjects.software.map(s => <option key={s} value={s}>{s}</option>)}</optgroup>
                                    </select>
                                </div>
                                <div className="form-group"><label title="Total length of the campaign. Higher values spread events out for 'Low and Slow' realism.">DURATION ({config.duration_days} DAYS)</label><input type="range" min="1" max="365" step="1" value={config.duration_days} onChange={e => setConfig({...config, duration_days: parseInt(e.target.value)})} /></div>
                                <div className="form-group"><label title="Unique identifier for saving and recalling this simulation configuration.">MISSION_ID</label>
                                    <div style={{display:'flex', gap: 10}}>
                                        <input type="text" value={config.session_name} onChange={e => setConfig({...config, session_name: e.target.value})} style={{flex: 1}}/>
                                        <button className="btn" onClick={saveSession}>SAVE</button>
                                    </div>
                                </div>
                                <div className="session-list"><label title="Previously saved mission configurations.">ARCHIVES</label>
                                    {sessions.map(s => (
                                        <div key={s} className="session-item" style={{display:'flex', justifyContent:'space-between'}}>
                                            <span onClick={() => loadSession(s)} style={{flex:1}}>{s}</span>
                                            <span onClick={(e) => { e.stopPropagation(); deleteSession(s); }} style={{color:'var(--accent-red)', fontWeight:'bold', cursor:'pointer'}}>X</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                            <div className="setup-section col-6">
                                <span className="section-label">02 // ENVIRONMENT</span>
                                <div className="form-group"><label title="Industry context can influence the probability of specific initial access vectors.">INDUSTRY</label>
                                    <select value={config.industry} onChange={e => setConfig({...config, industry: e.target.value})}>
                                        <option value="Financial">Financial Services</option><option value="Healthcare">Healthcare</option><option value="Technology">Technology</option><option value="Government">Government</option>
                                    </select>
                                </div>
                                <div className="form-group"><label title="Total number of simulated endpoints, routers, and servers in the network.">NODES</label><input type="number" value={config.org_size} onChange={e => setConfig({...config, org_size: parseInt(e.target.value)})} /></div>
                                <div className="form-group"><label title="Higher segmentation decreases the probability of successful lateral movement.">SEGMENTATION ({Math.round(config.network_segmentation*100)}%)</label><input type="range" min="0" max="1" step="0.1" value={config.network_segmentation} onChange={e => setConfig({...config, network_segmentation: Math.round(parseFloat(e.target.value)*100)/100})} /></div>
                                <div className="form-group"><label title="Determines how closely the attacker follows the standard MITRE profile vs substituting generic techniques.">SIMULATION_DEVIATION ({Math.round(config.simulation_deviation*100)}%)</label><input type="range" min="0" max="1" step="0.1" value={config.simulation_deviation} onChange={e => setConfig({...config, simulation_deviation: Math.round(parseFloat(e.target.value)*100)/100})} /></div>
                                <div className="form-group"><label title="Global probability that an active security tool will successfully detect and log a technique.">COVERAGE ({Math.round(config.security_coverage*100)}%)</label><input type="range" min="0" max="0.9" step="0.05" value={config.security_coverage} onChange={e => setConfig({...config, security_coverage: Math.round(parseFloat(e.target.value)*100)/100})} /></div>
                                <div className="form-group"><label title="Volume of legitimate background events (false positives) generated per day to mask malicious activity.">NOISE_LEVEL ({Math.round(config.user_activity_level*100)}%)</label><input type="range" min="0" max="1" step="0.1" value={config.user_activity_level} onChange={e => setConfig({...config, user_activity_level: Math.round(parseFloat(e.target.value)*100)/100})} /></div>
                                <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:10}}>
                                    {TOOL_OPTIONS.map(t => (
                                        <label key={t} style={{fontSize:11, display:'flex', alignItems:'center'}} title={`Toggle ${t} telemetry collection.`}>
                                            <input type="checkbox" checked={config.tools.includes(t)} onChange={e => {
                                                const ts = e.target.checked ? [...config.tools, t] : config.tools.filter(x => x !== t);
                                                setConfig({...config, tools: ts});
                                            }} style={{width:'auto', marginRight:5}} /> {TOOL_ICONS[t]} {t}
                                        </label>
                                    ))}
                                </div>
                            </div>
                        </div>
                        <button className="btn-engage mono" onClick={runSimulation}>ENGAGE_SIMULATION</button>
                    </div>
                ) : (
                    <div className="dashboard-view">
                        <div className="dash-header">
                            <div style={{display:'flex', gap:20, alignItems:'center'}}>
                                <button className="btn" onClick={() => setView('setup')}>⟵ MISSION_CTRL</button>
                                <div className="mono" style={{fontSize:11}}>MISSION: <span className="accent">{config.session_name}</span></div>
                                <div className="mono" style={{fontSize:11}}>ADVERSARY: <span className="accent">{data.intel.name}</span></div>
                            </div>
                            <button className="btn btn-primary" onClick={() => setShowExport(true)}>EXPORT_DATA</button>
                        </div>
                        <div className="dash-content">
                            <div className="widget col-3"><div className="widget-title">XDR_RISK_SCORE</div><div className="stat-val">{data.metrics.risk_score}%</div><div className="risk-meter"><div className="risk-fill" style={{width:`${data.metrics.risk_score}%`, background: data.metrics.risk_score > 60 ? 'var(--accent-red)' : 'var(--accent-cyan)'}}></div></div></div>
                            <div className="widget col-3"><div className="widget-title">ACTIVE_INCIDENTS</div><div className="stat-val">{getIncidents().length}</div><div className="stat-label">Correlated attack chains</div></div>
                            <div className="widget col-3"><div className="widget-title">RAW_ALERTS</div><div className="stat-val">{data.metrics.total_alerts}</div><div className="stat-label">Malicious + Benign signals</div></div>
                            <div className="widget col-3"><div className="widget-title">ASSETS_AT_RISK</div><div className="stat-val">{data.metrics.risky_assets.length}</div><div className="stat-label">Compromised endpoints</div></div>
                            <div className="col-12"><div className="tabs">
                                <div className={`tab ${activeTab === 'xdr' ? 'active' : ''}`} onClick={() => setActiveTab('xdr')}>XDR_TRIAGE_DASHBOARD</div>
                                <div className={`tab ${activeTab === 'hunting' ? 'active' : ''}`} onClick={() => setActiveTab('hunting')}>THREAT_HUNTING</div>
                                <div className={`tab ${activeTab === 'assets' ? 'active' : ''}`} onClick={() => setActiveTab('assets')}>ASSET_GRAPH</div>
                            </div></div>
                            {activeTab === 'xdr' && (
                                <React.Fragment>
                                    <div className="col-8" style={{display:'flex', flexDirection:'column', gap:'1.5rem'}}>
                                        <div className="widget">
                                            <div className="widget-title">SIGNAL_VOLUME_ANALYSIS</div>
                                            <div style={{height:220}}><canvas id="chartTrend"></canvas></div>
                                        </div>
                                        <div className="widget">
                                            <div className="widget-title">MITRE_ATT&CK_MATRIX_COVERAGE</div>
                                            <div style={{height:220}}><canvas id="chartTactics"></canvas></div>
                                        </div>
                                    </div>
                                    <div className="col-4" style={{display:'flex', flexDirection:'column', gap:'1.5rem'}}>
                                        <div className="widget" style={{flex:1, display:'flex', flexDirection:'column'}}>
                                            <div className="widget-title">INCIDENT_TRIAGE_QUEUE</div>
                                            <div style={{overflowY:'auto', flex:1, paddingRight:10}}>
                                                {getIncidents().map(inc => (
                                                    <div key={inc.id} className={`incident-card ${inc.maxSev.toLowerCase()}`} onClick={() => setSelectedIncident(inc)}>
                                                        <div className="incident-header">
                                                            <span className="incident-id">{inc.id}</span>
                                                            <span className={`badge bg-${inc.maxSev.toLowerCase()}`}>{inc.maxSev}</span>
                                                        </div>
                                                        <div className="incident-body">
                                                            <div><strong>LEAD_ASSET:</strong> <span className="mono">{inc.target}</span></div>
                                                            <div><strong>SIGNALS:</strong> <span className="mono">{inc.logs.length}</span></div>
                                                        </div>
                                                        <div style={{fontSize:10, marginTop:10, color:'var(--text-secondary)'}}>
                                                            TACTICS: {Array.from(inc.tactics).join(', ')}
                                                        </div>
                                                    </div>
                                                ))}
                                                {getIncidents().length === 0 && <div style={{color:'var(--text-secondary)'}}>NO_ACTIVE_INCIDENTS</div>}
                                            </div>
                                        </div>
                                    </div>
                                </React.Fragment>
                            )}
                            {activeTab === 'hunting' && (
                                <div className="widget col-12" style={{display:'flex', flexDirection:'column'}}>
                                    <div style={{marginBottom:15}}>
                                        <input className="search-bar" placeholder="> SEARCH_LOGSTREAM (e.g., 192.168.1.5, T1059, PowerShell)..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
                                    </div>
                                    <div style={{overflowY:'auto', flex:1}}>
                                        <table>
                                            <thead>
                                                <tr><th>TIME</th><th>HOST</th><th>USER</th><th>TTP</th><th>SRC_IP</th><th>PROCESS</th><th>SEV</th><th>TOOL</th></tr>
                                            </thead>
                                            <tbody>
                                                {filteredLogs.map((l, i) => (
                                                    <React.Fragment key={i}>
                                                        <tr className="clickable-row" onClick={() => setExpandedLogId(expandedLogId === i ? null : i)}>
                                                            <td className="mono" style={{color:'var(--text-secondary)'}}>{l.time.slice(11,19)}</td>
                                                            <td><strong>{l.devicename}</strong></td>
                                                            <td className="mono" style={{color:'var(--accent-orange)'}}>{l.username || '-'}</td>
                                                            <td className="mono">{l.ttp}</td>
                                                            <td className="mono">{l.srcip}</td>
                                                            <td className="mono" style={{maxWidth:150, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{l.process_name || '-'}</td>
                                                            <td><span className={`badge bg-${l.severity.toLowerCase()}`}>{l.severity}</span></td>
                                                            <td className="accent">{l.tool_name}</td>
                                                        </tr>
                                                        {expandedLogId === i && (
                                                            <tr><td colSpan="8" style={{padding:0, border:0}}><div className="event-inspector">{JSON.stringify(l, null, 2)}</div></td></tr>
                                                        )}
                                                    </React.Fragment>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}
                            {activeTab === 'assets' && (
                                <div className="widget col-12">
                                    <div className="widget-title">NETWORK_ASSET_INVENTORY</div>
                                    <AssetGraphView assets={data.assets} logs={data.logs} network_edges={data.network_edges} />
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
