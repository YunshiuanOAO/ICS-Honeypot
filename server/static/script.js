const API_BASE = '/api';

// Navigation
function showSection(sectionId) {
    document.querySelectorAll('.content-section').forEach(el => el.classList.add('hidden'));
    document.getElementById(sectionId).classList.remove('hidden');

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    event.target.classList.add('active');

    if (sectionId === 'agents') loadAgents();
    if (sectionId === 'dashboard') refreshData();
}

// Data Fetching
async function refreshData() {
    const btn = document.querySelector('button[onclick="refreshData()"]');
    if (btn) btn.innerText = 'Refreshing...';

    await loadStats();
    await loadRecentLogs();

    if (btn) setTimeout(() => btn.innerText = 'Refresh', 500);
}

async function loadStats() {
    const agents = await fetch(`${API_BASE}/agents`).then(r => r.json());
    const uniqueAgents = agents.filter(a => a.status === 'Online').length;
    document.getElementById('active-agents-count').innerText = uniqueAgents;

    // We don't have a total logs count endpoint yet, but maybe use recent logs length as placeholder
    // or fetch it if available. For now, leave as -- or update with logs length
}

async function loadRecentLogs() {
    const logs = await fetch(`${API_BASE}/recent_logs`).then(r => r.json());
    document.getElementById('total-logs-count').innerText = logs.length + (logs.length >= 50 ? '+' : '');
    const tbody = document.getElementById('dashboard-logs-body');
    tbody.innerHTML = '';

    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
            <td>${log.node_id}</td>
            <td><span class="badge ${log.protocol}">${log.protocol}</span></td>
            <td>${log.attacker_ip}</td>
            <td>${formatActivity(log)}</td>
        `;
        tbody.appendChild(row);
    });
}

function formatActivity(log) {
    // Attempt to describe activity from metadata
    try {
        const meta = JSON.parse(log.metadata);
        if (log.protocol === 'modbus') {
            return `${meta['modbus.func_name'] || 'Func ' + meta['modbus.func_code']} (Unit ${meta['modbus.unit_id']})`;
        } else if (log.protocol === 's7comm') {
            let desc = meta['s7.pdu_type'] || 'S7 Communication';
            if (meta['s7.function_code']) {
                desc += ` (Func 0x${meta['s7.function_code'].toString(16).toUpperCase()})`;
            }
            return desc;
        }
    } catch (e) { }
    return "Interaction";
}

async function loadAgents() {
    const agents = await fetch(`${API_BASE}/agents`).then(r => r.json());
    const grid = document.getElementById('agents-grid');
    grid.innerHTML = '';

    agents.forEach(agent => {
        const card = document.createElement('div');
        card.className = 'agent-card';
        card.innerHTML = `
            <div class="agent-status ${agent.status.toLowerCase()}"></div>
            <h3>${agent.name}</h3>
            <div class="agent-meta">
                <div>ID: ${agent.node_id}</div>
                <div>IP: ${agent.ip}</div>
                <div>Last Seen: ${new Date(agent.last_heartbeat).toLocaleString()}</div>
                <div style="margin-top:0.5rem; display:flex; align-items:center; gap:0.5rem">
                    <span>Active:</span>
                    <label class="switch">
                        <input type="checkbox" ${agent.is_active ? 'checked' : ''} onchange="toggleAgent('${agent.node_id}', this.checked)">
                        <span class="slider"></span>
                    </label>
                </div>
            </div>
            <div class="agent-actions">
                <button class="btn btn-secondary" onclick="editConfig('${agent.node_id}')">Config</button>
                <button class="btn btn-secondary" onclick="deleteAgent('${agent.node_id}')" style="color:var(--danger)">Delete</button>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Config Editor
async function editConfig(nodeId) {
    const config = await fetch(`${API_BASE}/config/${nodeId}`).then(r => r.json());
    document.getElementById('config-node-id').value = nodeId;
    document.getElementById('config-json').value = JSON.stringify(config, null, 4);

    document.getElementById('config-modal').classList.remove('hidden');
}

async function saveConfig() {
    const nodeId = document.getElementById('config-node-id').value;
    const configStr = document.getElementById('config-json').value;

    try {
        const config = JSON.parse(configStr);
        await fetch(`${API_BASE}/update_agent_config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ node_id: nodeId, config: config })
        });
        closeModal();
        alert('Configuration updated. Agent will pick it up on next heartbeat.');
    } catch (e) {
        alert('Failed to save config! Please check your JSON syntax.\nError: ' + e);
    }
}

async function deleteAgent(nodeId) {
    if (!confirm('Are you sure?')) return;
    await fetch(`${API_BASE}/agents/${nodeId}`, { method: 'DELETE' });
    loadAgents();
}

// Add Agent Logic
function showAddAgentModal() {
    document.getElementById('add-agent-modal').classList.remove('hidden');
}

function closeAddAgentModal() {
    document.getElementById('add-agent-modal').classList.add('hidden');
}

async function saveNewAgent() {
    const id = document.getElementById('new-agent-id').value;
    const name = document.getElementById('new-agent-name').value;
    const ip = document.getElementById('new-agent-ip').value;
    const config = document.getElementById('new-agent-config').value;

    if (!id) { alert('Node ID is required'); return; }

    const formData = new FormData();
    formData.append('node_id', id);
    formData.append('name', name);
    formData.append('ip', ip || '0.0.0.0');
    formData.append('config_json', config || '');

    await fetch(`${API_BASE}/agents`, {
        method: 'POST',
        body: formData
    });

    closeAddAgentModal();
    loadAgents();
    alert('Agent added!');
}

async function toggleAgent(nodeId, isActive) {
    try {
        await fetch(`${API_BASE}/agents/${nodeId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_active: isActive })
        });
    } catch (e) {
        alert('Failed to toggle agent: ' + e);
        loadAgents(); // Revert UI
    }
}


function closeModal() {
    document.getElementById('config-modal').classList.add('hidden');
}

// Initial Load
document.addEventListener('DOMContentLoaded', () => {
    refreshData();
    // Auto refresh every 5s
    setInterval(refreshData, 5000);
});
