/**
 * APS Honeypot Dashboard - Frontend JavaScript
 * =============================================
 * Modern, clean implementation with improved UX
 */

const API_BASE = '/api';

// State Management
// ========================================
let PROFILES_LIST = [];
let editPlcConfigs = [];
let isLogPaused = false;
let previousLogs = [];

// ========================================
// Toast Notification System
// ========================================
const Toast = {
    container: null,

    init() {
        this.container = document.getElementById('toast-container');
    },

    show(message, type = 'info', duration = 4000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: 'check-circle',
            error: 'alert-circle',
            warning: 'alert-triangle',
            info: 'info'
        };

        toast.innerHTML = `
            <i data-lucide="${icons[type]}" class="toast-icon"></i>
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="Toast.dismiss(this.parentElement)">
                <i data-lucide="x"></i>
            </button>
        `;

        this.container.appendChild(toast);
        lucide.createIcons();

        // Auto dismiss
        setTimeout(() => this.dismiss(toast), duration);
    },

    dismiss(toast) {
        if (!toast || !toast.parentElement) return;
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    },

    success(message) { this.show(message, 'success'); },
    error(message) { this.show(message, 'error', 6000); },
    warning(message) { this.show(message, 'warning'); },
    info(message) { this.show(message, 'info'); }
};

// ========================================
// Profiles Management
// ========================================
async function loadProfilesList() {
    try {
        const res = await fetch(`${API_BASE}/profiles`);
        PROFILES_LIST = await res.json();
    } catch (e) {
        console.error("Failed to load profiles", e);
    }
}

function renderProfileOptions(selected) {
    return PROFILES_LIST.map(s =>
        `<option value="${s.name}" ${selected === s.name ? 'selected' : ''}>${s.description} (${s.name})</option>`
    ).join('');
}

// ========================================
// Navigation
// ========================================
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(el => el.classList.add('hidden'));

    // Show target section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.remove('hidden');
    }

    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.querySelector(`.nav-item[data-section="${sectionId}"]`)?.classList.add('active');

    // Load section-specific data
    if (sectionId === 'agents') loadAgents();
    if (sectionId === 'dashboard') refreshData();
    if (sectionId === 'logs') initLogStream();

    // Re-initialize icons
    lucide.createIcons();
}

// ========================================
// Dashboard Data
// ========================================
async function refreshData() {
    const btn = document.querySelector('button[onclick="refreshData()"]');
    if (btn) {
        const icon = btn.querySelector('i');
        if (icon) icon.style.animation = 'spin 1s linear infinite';
    }

    try {
        await Promise.all([loadStats(), loadRecentLogs()]);
    } catch (e) {
        Toast.error('Failed to refresh data');
    }

    if (btn) {
        const icon = btn.querySelector('i');
        if (icon) icon.style.animation = '';
    }
}

async function loadStats() {
    try {
        const agents = await fetch(`${API_BASE}/agents`).then(r => r.json());
        const onlineCount = agents.filter(a => a.status === 'Online').length;

        animateNumber('active-agents-count', onlineCount);
    } catch (e) {
        console.error('Failed to load stats', e);
    }
}

async function loadRecentLogs() {
    try {
        const logs = await fetch(`${API_BASE}/recent_logs`).then(r => r.json());

        const totalLogsEl = document.getElementById('total-logs-count');
        const alertsEl = document.getElementById('alerts-count');
        const tbody = document.getElementById('dashboard-logs-body');
        const emptyState = document.getElementById('table-empty');

        if (totalLogsEl) {
            animateNumber('total-logs-count', logs.length, logs.length >= 50 ? '+' : '');
        }

        // Count alerts (write operations are typically more interesting)
        const alertCount = logs.filter(l => {
            try {
                const meta = JSON.parse(l.metadata);
                return meta['modbus.func_code'] >= 5 || meta['s7.function_code'];
            } catch { return false; }
        }).length;
        if (alertsEl) animateNumber('alerts-count', alertCount);

        if (logs.length === 0) {
            tbody.innerHTML = '';
            emptyState?.classList.remove('hidden');
            return;
        }

        emptyState?.classList.add('hidden');
        tbody.innerHTML = '';

        logs.forEach((log, index) => {
            const row = document.createElement('tr');
            row.style.animation = `fadeIn 0.3s ease ${index * 0.03}s both`;
            row.innerHTML = `
                <td>${formatTime(log.timestamp)}</td>
                <td><code>${log.node_id}</code></td>
                <td><span class="badge ${log.protocol}">${log.protocol}</span></td>
                <td><code>${log.attacker_ip}</code></td>
                <td>${formatActivity(log)}</td>
            `;
            tbody.appendChild(row);
        });

        lucide.createIcons();
    } catch (e) {
        console.error('Failed to load logs', e);
    }
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function formatActivity(log) {
    try {
        const meta = JSON.parse(log.metadata);
        if (log.protocol === 'modbus') {
            const funcName = meta['modbus.func_name'] || `Func ${meta['modbus.func_code']}`;
            const unitId = meta['modbus.unit_id'] || '?';
            return `${funcName} <span class="text-muted">(Unit ${unitId})</span>`;
        } else if (log.protocol === 's7comm') {
            let desc = meta['s7.pdu_type'] || 'S7 Communication';
            if (meta['s7.function_code']) {
                desc += ` <span class="text-muted">(0x${meta['s7.function_code'].toString(16).toUpperCase()})</span>`;
            }
            return desc;
        }
    } catch (e) { }
    return '<span class="text-muted">Interaction</span>';
}

function animateNumber(elementId, targetValue, suffix = '') {
    const el = document.getElementById(elementId);
    if (!el) return;

    const currentValue = parseInt(el.textContent) || 0;
    const diff = targetValue - currentValue;
    const duration = 500;
    const steps = 20;
    const increment = diff / steps;
    let current = currentValue;
    let step = 0;

    const timer = setInterval(() => {
        step++;
        current += increment;
        el.textContent = Math.round(current) + suffix;

        if (step >= steps) {
            clearInterval(timer);
            el.textContent = targetValue + suffix;
        }
    }, duration / steps);
}

// ========================================
// Agents Management
// ========================================
async function loadAgents() {
    try {
        const agents = await fetch(`${API_BASE}/agents`).then(r => r.json());
        const grid = document.getElementById('agents-grid');
        grid.innerHTML = '';

        if (agents.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <i data-lucide="cpu"></i>
                    <p>No agents registered yet.</p>
                    <p class="text-muted">Agents will appear here when they connect to the server.</p>
                </div>
            `;
            lucide.createIcons();
            return;
        }

        agents.forEach((agent, index) => {
            const card = document.createElement('div');
            card.className = 'agent-card';
            card.style.animation = `fadeIn 0.4s ease ${index * 0.1}s both`;

            const lastSeen = new Date(agent.last_heartbeat);
            const isOnline = agent.status === 'Online';

            card.innerHTML = `
                <div class="agent-status ${isOnline ? 'online' : 'offline'}"></div>
                <h3>${escapeHtml(agent.name)}</h3>
                <div class="agent-meta">
                    <div>
                        <span class="text-muted">Node ID</span>
                        <code>${escapeHtml(agent.node_id)}</code>
                    </div>
                    <div>
                        <span class="text-muted">IP Address</span>
                        <code>${escapeHtml(agent.ip)}</code>
                    </div>
                    <div>
                        <span class="text-muted">Last Seen</span>
                        <span>${formatRelativeTime(lastSeen)}</span>
                    </div>
                    <div style="margin-top: 0.5rem; display: flex; align-items: center; justify-content: space-between;">
                        <span class="text-muted">Active</span>
                        <label class="switch">
                            <input type="checkbox" ${agent.is_active ? 'checked' : ''} 
                                   onchange="toggleAgent('${agent.node_id}', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="agent-actions">
                    <button class="btn btn-secondary btn-sm" onclick="editConfig('${agent.node_id}')">
                        <i data-lucide="settings"></i>
                        Config
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="deleteAgent('${agent.node_id}')">
                        <i data-lucide="trash-2"></i>
                        Delete
                    </button>
                </div>
            `;
            grid.appendChild(card);
        });

        lucide.createIcons();
    } catch (e) {
        Toast.error('Failed to load agents');
    }
}

function formatRelativeTime(date) {
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
}

async function toggleAgent(nodeId, isActive) {
    try {
        await fetch(`${API_BASE}/agents/${nodeId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_active: isActive })
        });
        Toast.success(`Agent ${isActive ? 'activated' : 'deactivated'}`);
    } catch (e) {
        Toast.error('Failed to toggle agent');
        loadAgents();
    }
}

async function deleteAgent(nodeId) {
    if (!confirm(`Are you sure you want to delete agent "${nodeId}"?\n\nThis action cannot be undone.`)) return;

    try {
        await fetch(`${API_BASE}/agents/${nodeId}`, { method: 'DELETE' });
        Toast.success('Agent deleted successfully');
        loadAgents();
    } catch (e) {
        Toast.error('Failed to delete agent');
    }
}

// ========================================
// Log Console
// ========================================
function initLogStream() {
    // Log streaming is done via periodic refresh
    // Could be enhanced with WebSocket for real-time
}

function toggleLogPause() {
    isLogPaused = !isLogPaused;
    const btn = document.getElementById('log-pause-btn');
    const statusEl = document.getElementById('console-status');

    if (btn) {
        btn.innerHTML = isLogPaused
            ? '<i data-lucide="play"></i><span>Resume</span>'
            : '<i data-lucide="pause"></i><span>Pause</span>';
    }

    if (statusEl) {
        statusEl.innerHTML = isLogPaused
            ? '<span class="status-dot paused"></span>Paused'
            : '<span class="status-dot streaming"></span>Streaming';
    }

    lucide.createIcons();
}

function clearLogConsole() {
    const console = document.getElementById('log-console');
    if (console) {
        console.innerHTML = `
            <div class="log-entry info">
                <span class="log-time">[System]</span>
                <span class="log-message">Console cleared</span>
            </div>
        `;
    }
    Toast.info('Console cleared');
}

function addLogEntry(time, message, type = 'info') {
    if (isLogPaused) return;

    const console = document.getElementById('log-console');
    if (!console) return;

    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerHTML = `
        <span class="log-time">[${time}]</span>
        <span class="log-message">${escapeHtml(message)}</span>
    `;

    console.appendChild(entry);
    console.scrollTop = console.scrollHeight;

    // Keep only last 500 entries
    while (console.children.length > 500) {
        console.removeChild(console.firstChild);
    }
}

// ========================================
// Configuration Modal
// ========================================
async function editConfig(nodeId) {
    try {
        const config = await fetch(`${API_BASE}/config/${nodeId}`).then(r => r.json());

        document.getElementById('config-node-id-original').value = nodeId;
        document.getElementById('edit-node-id').value = nodeId;
        document.getElementById('edit-agent-name').value = config.name || '';
        document.getElementById('edit-server-url').value = config.server_url || 'http://localhost:8000';
        document.getElementById('config-json').value = JSON.stringify(config, null, 4);

        // Parse PLC configs for form view
        editPlcConfigs = (config.plcs || []).map((plc, index) => {
            const simulation = plc.simulation || {};
            const customConfig = plc.type === 'modbus' ? {
                holding_registers: simulation.holding_registers || [],
                coils: simulation.coils || [],
                input_registers: simulation.input_registers || [],
                discrete_inputs: simulation.discrete_inputs || []
            } : {
                db: simulation.db || {},
                m: simulation.m || {},
                i: simulation.i || {},
                q: simulation.q || {}
            };

            const profileName = simulation.profile || simulation.scenario || ''; // Fallback for old configs
            const mode = profileName ? 'template' : 'custom';

            let desc = '';
            if (mode === 'template') {
                const meta = PROFILES_LIST.find(s => s.name === profileName);
                if (meta) desc = meta.description;
            }

            return {
                id: plc.id || crypto.randomUUID(), // Ensure distinct ID for UI tracking
                type: plc.type || 'modbus',
                enabled: plc.enabled !== false,
                port: plc.port || 5020,
                model: plc.model || '',
                profile: profileName,
                mode: mode,
                profileDesc: desc,
                vendor: plc.vendor,
                revision: plc.revision,
                customConfig: customConfig
            };
        });

        renderEditPlcConfigs();
        showConfigTab('form');
        openModal('config-modal');
    } catch (e) {
        Toast.error('Failed to load configuration');
    }
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.remove('hidden');
    requestAnimationFrame(() => {
        modal.classList.add('visible');
    });
    lucide.createIcons();
}

function closeModal() {
    const modal = document.getElementById('config-modal');
    modal.classList.remove('visible');
    setTimeout(() => modal.classList.add('hidden'), 300);
}

function showConfigTab(tab) {
    document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.config-view').forEach(v => v.classList.add('hidden'));

    const tabs = document.querySelectorAll('.config-tab');

    if (tab === 'form') {
        tabs[0]?.classList.add('active');
        document.getElementById('config-form-view')?.classList.remove('hidden');
    } else {
        tabs[1]?.classList.add('active');
        document.getElementById('config-json-view')?.classList.remove('hidden');
        syncFormToJson();
    }
}

// ========================================
// PLC Configuration
// ========================================
function addEditPlcConfig() {
    try {
        const id = Date.now();
        const index = editPlcConfigs.length;

        editPlcConfigs.push({
            id: id,
            type: 'modbus',
            enabled: true,
            port: index === 0 ? 5020 : (index === 1 ? 1020 : 5020 + index),
            model: '',
            profile: '',
            mode: 'template',
            profileDesc: '',
            customConfig: {
                holding_registers: [],
                coils: [],
                input_registers: [],
                discrete_inputs: []
            }
        });

        renderEditPlcConfigs();
        Toast.success("Added new PLC");
    } catch (e) {
        console.error(e);
        Toast.error("Error adding PLC: " + e.message);
    }
}

function removeEditPlcConfig(id) {
    editPlcConfigs = editPlcConfigs.filter(p => p.id !== id);
    renderEditPlcConfigs();
}

function renderEditPlcConfigs() {
    try {
        const container = document.getElementById('edit-plc-config-list');

        if (editPlcConfigs.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="padding: 2rem;">
                    <i data-lucide="cpu"></i>
                    <p>No PLC devices configured.</p>
                    <button class="btn btn-secondary btn-sm mt-2" onclick="addEditPlcConfig()">
                        <i data-lucide="plus"></i>
                        Add First PLC
                    </button>
                </div>
            `;
            lucide.createIcons();
            return;
        }

        container.innerHTML = editPlcConfigs.map((plc, index) => `
            <div class="plc-config-card" data-id="${plc.id}">
                <div class="card-header">
                    <span class="card-title">
                        <i data-lucide="cpu" style="width:16px;height:16px;margin-right:6px;"></i>
                        PLC #${index + 1}
                    </span>
                    <button class="btn-remove" onclick="removeEditPlcConfig(${plc.id})" title="Remove">
                        <i data-lucide="x"></i>
                    </button>
                </div>

                <!-- Mode Selection -->
                <div class="mode-selection-panel">
                    <label style="font-weight: 600; color: var(--text-primary);">Mode:</label>
                    <label class="radio-label">
                        <input type="radio" name="edit_mode_${plc.id}" value="template" 
                            ${plc.mode !== 'custom' ? 'checked' : ''} 
                            onchange="updateEditPlcConfig(${plc.id}, 'mode', 'template')"> 
                        Template
                    </label>
                    <label class="radio-label">
                        <input type="radio" name="edit_mode_${plc.id}" value="custom" 
                            ${plc.mode === 'custom' ? 'checked' : ''} 
                            onchange="updateEditPlcConfig(${plc.id}, 'mode', 'custom')"> 
                        Custom
                    </label>
                </div>

                <div style="padding: 0 1.25rem 1rem;">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Protocol Type</label>
                            <select onchange="updateEditPlcConfig(${plc.id}, 'type', this.value)" ${plc.mode !== 'custom' ? 'disabled' : ''}>
                                <option value="modbus" ${plc.type === 'modbus' ? 'selected' : ''}>Modbus TCP</option>
                                <option value="s7comm" ${plc.type === 's7comm' ? 'selected' : ''}>S7Comm</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Enabled</label>
                            <select onchange="updateEditPlcConfig(${plc.id}, 'enabled', this.value === 'true')">
                                <option value="true" ${plc.enabled ? 'selected' : ''}>Yes</option>
                                <option value="false" ${!plc.enabled ? 'selected' : ''}>No</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Port</label>
                            <input type="number" value="${plc.port}" onchange="updateEditPlcConfig(${plc.id}, 'port', parseInt(this.value))">
                        </div>
                        <div class="form-group">
                            <label>Model Name</label>
                            <input type="text" value="${escapeHtml(plc.model)}" 
                                placeholder="${plc.type === 'modbus' ? 'e.g. Schneider M340' : 'e.g. S7-300'}" 
                                onchange="updateEditPlcConfig(${plc.id}, 'model', this.value)">
                        </div>
                    </div>
                </div>

                <!-- Template Selector -->
                ${plc.mode !== 'custom' ? `
                <div class="simulation-section">
                    <h4>Select Device Template</h4>
                    <div class="form-group" style="margin-bottom: 0;">
                        <select onchange="applyEditProfileTemplate(${plc.id}, this.value)">
                            <option value="">-- Select Template --</option>
                            ${renderProfileOptions(plc.profile)}
                        </select>
                        ${plc.profileDesc ? `
                        <div class="scenario-desc">${escapeHtml(plc.profileDesc)}</div>
                        ` : ''}
                    </div>
                </div>
                ` : `
                <div class="simulation-section">
                    <p style="color: var(--text-muted); font-size: 0.9rem; margin: 0;">
                        In Custom mode, configure registers manually below.
                    </p>
                </div>
                `}

                <div class="advanced-section">
                    <div class="advanced-header">
                        <h4>${plc.mode !== 'custom' ? 'Fine-tune Configuration' : 'Register Configuration'}</h4>
                        <button class="btn btn-secondary btn-sm" onclick="toggleEditAdvancedConfig(${plc.id}, event)">
                            <i data-lucide="${plc.isAdvancedOpen ? 'chevron-up' : 'chevron-down'}"></i>
                            ${plc.isAdvancedOpen ? 'Hide' : 'Show'}
                        </button>
                    </div>
                    <div id="edit-advanced-config-${plc.id}" class="advanced-content ${plc.isAdvancedOpen ? '' : 'hidden'}">
                        ${renderEditAdvancedConfig(plc)}
                    </div>
                </div>
            </div>
        `).join('');

        lucide.createIcons();
    } catch (e) {
        console.error(e);
        Toast.error("Error rendering PLC list: " + e.message);
    }
}

function updateEditPlcConfig(id, field, value) {
    const plc = editPlcConfigs.find(p => p.id === id);
    if (plc) {
        plc[field] = value;
        if (field === 'type') {
            if (plc.type === 'modbus') {
                plc.customConfig = {
                    holding_registers: [],
                    coils: [],
                    input_registers: [],
                    discrete_inputs: []
                };
            } else {
                plc.customConfig = {
                    db: {},
                    m: {},
                    i: {},
                    q: {}
                };
            }
            renderEditPlcConfigs();
        }
        if (field === 'mode') {
            renderEditPlcConfigs();
        }
    }
}

function toggleEditAdvancedConfig(plcId, event) {
    event.preventDefault();
    const plc = editPlcConfigs.find(p => p.id === plcId);
    if (plc) {
        plc.isAdvancedOpen = !plc.isAdvancedOpen;
        renderEditPlcConfigs();
    }
}

function renderEditAdvancedConfig(plc) {
    if (plc.type === 'modbus') {
        return `
            <div class="custom-config-section">
                <div class="custom-config-header">
                    <h5>Holding Registers</h5>
                    <button class="btn btn-secondary btn-xs" onclick="addEditCustomItem(${plc.id}, 'holding_registers', event)">
                        <i data-lucide="plus" style="width:12px;height:12px;"></i> Add
                    </button>
                </div>
                <div id="edit_holding_registers_${plc.id}">
                    ${(plc.customConfig.holding_registers || []).map((item, idx) =>
            renderEditModbusRegisterItem(plc.id, 'holding_registers', item, idx, plc.mode)).join('')}
                </div>
            </div>
            
            <div class="custom-config-section">
                <div class="custom-config-header">
                    <h5>Coils</h5>
                    <button class="btn btn-secondary btn-xs" onclick="addEditCustomItem(${plc.id}, 'coils', event)">
                        <i data-lucide="plus" style="width:12px;height:12px;"></i> Add
                    </button>
                </div>
                <div id="edit_coils_${plc.id}">
                    ${(plc.customConfig.coils || []).map((item, idx) =>
                renderEditModbusCoilItem(plc.id, 'coils', item, idx, plc.mode)).join('')}
                </div>
            </div>
            
            <div class="custom-config-section">
                <div class="custom-config-header">
                    <h5>Input Registers</h5>
                    <button class="btn btn-secondary btn-xs" onclick="addEditCustomItem(${plc.id}, 'input_registers', event)">
                        <i data-lucide="plus" style="width:12px;height:12px;"></i> Add
                    </button>
                </div>
                <div id="edit_input_registers_${plc.id}">
                    ${(plc.customConfig.input_registers || []).map((item, idx) =>
                    renderEditModbusRegisterItem(plc.id, 'input_registers', item, idx, plc.mode)).join('')}
                </div>
            </div>
            
            <div class="custom-config-section">
                <div class="custom-config-header">
                    <h5>Discrete Inputs</h5>
                    <button class="btn btn-secondary btn-xs" onclick="addEditCustomItem(${plc.id}, 'discrete_inputs', event)">
                        <i data-lucide="plus" style="width:12px;height:12px;"></i> Add
                    </button>
                </div>
                <div id="edit_discrete_inputs_${plc.id}">
                    ${(plc.customConfig.discrete_inputs || []).map((item, idx) =>
                        renderEditModbusCoilItem(plc.id, 'discrete_inputs', item, idx, plc.mode)).join('')}
                </div>
            </div>
        `;
    } else {
        return `
            <div class="custom-config-section">
                <p style="color: var(--text-muted); font-size: 0.9rem;">
                    S7 advanced configuration coming soon. Use JSON view for direct editing.
                </p>
            </div>
        `;
    }
}

// ========================================
// Modbus Register/Coil Rendering
// ========================================
function renderModbusRegisterItem(plcId, type, item, index, mode = 'custom') {
    return `
    <div class="custom-item">
        <div class="custom-item-row">
            <button class="btn-remove-item" onclick="removeEditCustomItem(${plcId}, '${type}', ${index}, event)">×</button>
            
            <div class="form-group-mini">
                <label>Addr</label>
                <input type="number" value="${item.addr || ''}" 
                    onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'addr', parseInt(this.value))"
                    class="input-mini">
            </div>

            <div class="form-group-mini" style="flex:1">
                <label>Wave Type</label>
                <select onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'wave', this.value)" class="input-mini">
                    <option value="">Fixed Value</option>
                    <option value="random" ${item.wave === 'random' ? 'selected' : ''}>Random</option>
                    <option value="sine" ${item.wave === 'sine' ? 'selected' : ''}>Sine Wave</option>
                    <option value="sawtooth" ${item.wave === 'sawtooth' ? 'selected' : ''}>Sawtooth</option>
                    <option value="static" ${item.wave === 'static' ? 'selected' : ''}>Static</option>
                </select>
            </div>
        </div>
        
        <div class="custom-item-params">
            ${renderWaveParams(plcId, type, index, item.wave, item)}
        </div>
    </div>
    `;
}

function renderModbusCoilItem(plcId, type, item, index, mode = 'custom') {
    return `
    <div class="custom-item">
        <div class="custom-item-row">
            <button class="btn-remove-item" onclick="removeEditCustomItem(${plcId}, '${type}', ${index}, event)">×</button>
            <div class="form-group-mini">
                <label>Addr</label>
                <input type="number" value="${item.addr || ''}" 
                    onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'addr', parseInt(this.value))"
                    class="input-mini">
            </div>
            
            <div class="form-group-mini" style="flex:1">
                <label>Behavior</label>
                <select onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'wave', this.value)" class="input-mini">
                    <option value="">Static (ON/OFF)</option>
                    <option value="random" ${item.wave === 'random' ? 'selected' : ''}>Random Flip</option>
                    <option value="pulse" ${item.wave === 'pulse' ? 'selected' : ''}>Pulse</option>
                </select>
            </div>
        </div>
        <div class="custom-item-params">
            ${renderWaveParams(plcId, type, index, item.wave, item)}
        </div>
    </div>
    `;
}

function renderEditModbusRegisterItem(plcId, type, item, index, mode) {
    return renderModbusRegisterItem(plcId, type, item, index, mode);
}

function renderEditModbusCoilItem(plcId, type, item, index, mode) {
    return renderModbusCoilItem(plcId, type, item, index, mode);
}

function renderWaveParams(plcId, type, index, wave, item) {
    if (!wave || wave === 'fixed' || wave === 'static') {
        return `
        <div class="form-group-mini">
            <label>Value</label>
            <input type="number" placeholder="Value" value="${item.value !== undefined ? item.value : 0}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'value', parseFloat(this.value))" class="input-mini">
        </div>`;
    }

    if (wave === 'random') {
        return `
        <div class="form-group-mini">
            <label>Min</label>
            <input type="number" value="${item.min || 0}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'min', parseFloat(this.value))" class="input-mini">
        </div>
        <div class="form-group-mini">
            <label>Max</label>
            <input type="number" value="${item.max || 100}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'max', parseFloat(this.value))" class="input-mini">
        </div>`;
    }

    if (wave === 'sine' || wave === 'sawtooth') {
        return `
        <div class="form-group-mini">
            <label>Min</label>
            <input type="number" value="${item.min || 0}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'min', parseFloat(this.value))" class="input-mini">
        </div>
        <div class="form-group-mini">
            <label>Max</label>
            <input type="number" value="${item.max || 100}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'max', parseFloat(this.value))" class="input-mini">
        </div>
        <div class="form-group-mini">
            <label>Period(s)</label>
            <input type="number" value="${item.period || 60}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'period', parseFloat(this.value))" class="input-mini">
        </div>`;
    }

    if (wave === 'pulse') {
        return `
        <div class="form-group-mini">
            <label>Interval(s)</label>
            <input type="number" value="${item.period || 5}" 
                onchange="updateEditCustomItem(${plcId}, '${type}', ${index}, 'period', parseFloat(this.value))" class="input-mini">
        </div>`;
    }

    return '';
}

function addEditCustomItem(plcId, type, event) {
    event.preventDefault();
    const plc = editPlcConfigs.find(p => p.id === plcId);
    if (!plc) return;

    if (!plc.customConfig[type]) {
        plc.customConfig[type] = [];
    }

    plc.customConfig[type].push({ addr: 0, wave: '' });
    renderEditPlcConfigs();
}

function removeEditCustomItem(plcId, type, index, event) {
    event.preventDefault();
    const plc = editPlcConfigs.find(p => p.id === plcId);
    if (!plc) return;

    plc.customConfig[type].splice(index, 1);
    renderEditPlcConfigs();
}

function updateEditCustomItem(plcId, type, index, field, value) {
    const plc = editPlcConfigs.find(p => p.id === plcId);
    if (!plc || !plc.customConfig[type][index]) return;

    plc.customConfig[type][index][field] = value;

    if (field === 'wave') {
        renderEditPlcConfigs();
    }
}

// ========================================
// Template Application
// ========================================
async function applyEditProfileTemplate(plcId, profileName) {
    const plc = editPlcConfigs.find(p => p.id === plcId);
    if (!plc) return;

    plc.profile = profileName;

    if (!profileName) {
        plc.profileDesc = '';
        renderEditPlcConfigs();
        return;
    }

    try {
        const meta = PROFILES_LIST.find(s => s.name === profileName);
        if (meta) plc.profileDesc = meta.description;

        const res = await fetch(`${API_BASE}/profiles/${profileName}`);
        const data = await res.json();

        let templateType = 'modbus';
        if (data.s7) templateType = 's7comm';

        plc.type = templateType;
        plc.model = data.product_code || data.name || profileName;
        plc.vendor = data.vendor;
        plc.revision = data.revision;

        if (templateType === 'modbus') {
            const m = data.modbus || {};
            plc.customConfig = {
                holding_registers: m.registers || [],
                coils: m.coils || [],
                input_registers: m.input_registers || [],
                discrete_inputs: m.discrete_inputs || []
            };
        } else {
            const s = data.s7 || {};
            plc.customConfig = {
                db: s.db || {},
                m: s.m || {},
                i: s.i || {},
                q: s.q || {}
            };
        }

        renderEditPlcConfigs();
        Toast.success(`Template "${profileName}" applied`);
    } catch (e) {
        Toast.error("Failed to load template");
    }
}

// ========================================
// Configuration Save
// ========================================
function syncFormToJson() {
    const originalNodeId = document.getElementById('config-node-id-original').value;
    const newNodeId = document.getElementById('edit-node-id').value.trim();
    const serverUrl = document.getElementById('edit-server-url').value.trim();

    const config = {
        node_id: newNodeId || originalNodeId,
        server_url: serverUrl,
        plcs: editPlcConfigs.map(plc => {
            const plcConfig = {
                type: plc.type,
                enabled: plc.enabled,
                port: plc.port,
                model: plc.model || (plc.type === 'modbus' ? 'Simulated Modbus Device' : 'S7-300'),
                vendor: plc.vendor,
                revision: plc.revision
            };

            const simulation = {};

            if (plc.profile) {
                simulation.profile = plc.profile;
            }

            if (plc.type === 'modbus') {
                if (plc.customConfig.holding_registers?.length > 0) {
                    simulation.holding_registers = plc.customConfig.holding_registers.filter(item => item.addr !== undefined && item.wave);
                }
                if (plc.customConfig.coils?.length > 0) {
                    simulation.coils = plc.customConfig.coils.filter(item => item.addr !== undefined && item.wave);
                }
                if (plc.customConfig.input_registers?.length > 0) {
                    simulation.input_registers = plc.customConfig.input_registers.filter(item => item.addr !== undefined && item.wave);
                }
                if (plc.customConfig.discrete_inputs?.length > 0) {
                    simulation.discrete_inputs = plc.customConfig.discrete_inputs.filter(item => item.addr !== undefined && item.wave);
                }
            } else if (plc.type === 's7comm') {
                // For S7, you'd add custom config logic here if UI supported it
                // Currently we just pass 'profile'
            }

            if (Object.keys(simulation).length > 0) {
                plcConfig.simulation = simulation;
            }

            return plcConfig;
        })
    };

    document.getElementById('config-json').value = JSON.stringify(config, null, 4);
}

async function saveConfig() {
    const originalNodeId = document.getElementById('config-node-id-original').value;
    const newNodeId = document.getElementById('edit-node-id').value.trim();
    const newName = document.getElementById('edit-agent-name').value.trim();

    const isJsonView = !document.getElementById('config-json-view').classList.contains('hidden');

    let config;

    if (isJsonView) {
        const configStr = document.getElementById('config-json').value;
        try {
            config = JSON.parse(configStr);
        } catch (e) {
            Toast.error('Invalid JSON syntax: ' + e.message);
            return;
        }
    } else {
        syncFormToJson();
        config = JSON.parse(document.getElementById('config-json').value);
    }

    try {
        await fetch(`${API_BASE}/update_agent_config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                node_id: originalNodeId,
                new_node_id: newNodeId,
                name: newName,
                config: config
            })
        });
        closeModal();
        loadAgents();
        Toast.success('Configuration updated successfully');
    } catch (e) {
        Toast.error('Failed to save configuration');
    }
}

// ========================================
// Utility Functions
// ========================================
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========================================
// CSS Animations (injected)
// ========================================
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
`;
document.head.appendChild(styleSheet);

// ========================================
// Initialization
// ========================================
document.addEventListener('DOMContentLoaded', () => {
    Toast.init();
    loadProfilesList();
    refreshData();

    // Auto-refresh every 5 seconds
    setInterval(() => {
        const dashboardVisible = !document.getElementById('dashboard').classList.contains('hidden');
        if (dashboardVisible) {
            loadRecentLogs();
        }
    }, 5000);

    // Initialize icons
    lucide.createIcons();
});
