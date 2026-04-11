/**
 * APS Honeypot — Attack Map Module
 * Renders a world map with animated attack arcs from attacker → honeypot.
 */

// ─── GeoIP Cache ───────────────────────────────────────────────────────────
const geoCache = new Map();
const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/;

// Default location for private/unresolvable IPs (center of map)
const DEFAULT_LOCATION = { lat: 0, lon: 0, country: "Private Network", city: "Local" };

async function resolveGeoIP(ip) {
    if (!ip || PRIVATE_IP_REGEX.test(ip)) {
        return { ...DEFAULT_LOCATION, ip };
    }
    if (geoCache.has(ip)) return geoCache.get(ip);

    // Proxy through our own server. ip-api.com's free tier is HTTP-only, so
    // calling it directly from an HTTPS dashboard gets blocked as mixed
    // content and silently drops the lookup to (0, 0).
    try {
        const resp = await fetch(`/api/geoip/${encodeURIComponent(ip)}`);
        if (resp.ok) {
            const data = await resp.json();
            if (data.status === "success") {
                const result = {
                    ip,
                    lat: Number(data.lat) || 0,
                    lon: Number(data.lon) || 0,
                    country: data.country || "",
                    city: data.city || "",
                };
                geoCache.set(ip, result);
                return result;
            }
        }
    } catch (_e) { /* ignore */ }

    const fallback = { ...DEFAULT_LOCATION, ip };
    geoCache.set(ip, fallback);
    return fallback;
}

// ─── Map Projection Helpers ────────────────────────────────────
function latLonToXY(lat, lon, attackMap) {
    if (attackMap && attackMap.projection) {
        const [x, y] = attackMap.projection([lon, lat]);
        return { x, y };
    }
    // Fallback if projection isn't ready
    const x = (lon + 180) * (attackMap.width / 360);
    const y = (90 - lat) * (attackMap.height / 180);
    return { x, y };
}

// ─── AttackMap Class ───────────────────────────────────────────────────────
class AttackMap {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) return;

        this.canvas = null;
        this.ctx = null;
        this.animationId = null;
        this.attacks = []; 
        this.honeypots = []; 
        this.seenLogIds = new Set();
        this.pollTimer = null;
        this.agentsCache = [];
        this.feedEl = null;
        this.feedCount = 0;
        this.totalAttacks = 0;
        this.width = 0;
        this.height = 0;
        this.land = null; // D3 land feature

        this._buildDOM();
        this._loadMapData();
    }

    async _loadMapData() {
        try {
            // Load world map TopoJSON
            const topoData = await d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json");
            this.land = topojson.feature(topoData, topoData.objects.land);
            this._resize(); // Trigger redraw
        } catch (e) {
            console.error("Failed to load map data", e);
        }
    }

    _buildDOM() {
        this.container.innerHTML = `
            <div class="attackmap-layout">
                <div class="attackmap-map-wrap">
                    <canvas id="attackmap-canvas"></canvas>
                    <div class="attackmap-tooltip" id="attackmap-tooltip"></div>
                    <div class="attackmap-stats-bar">
                        <div class="attackmap-stat">
                            <span class="attackmap-stat-label">Total Attacks</span>
                            <span class="attackmap-stat-value" id="attackmap-total">0</span>
                        </div>
                        <div class="attackmap-stat">
                            <span class="attackmap-stat-label">Active Honeypots</span>
                            <span class="attackmap-stat-value" id="attackmap-honeypots">0</span>
                        </div>
                        <div class="attackmap-stat">
                            <span class="attackmap-stat-label">Unique Attackers</span>
                            <span class="attackmap-stat-value" id="attackmap-unique">0</span>
                        </div>
                    </div>
                </div>
                <div class="attack-feed" id="attack-feed">
                    <div class="attack-feed-header">
                        <i data-lucide="zap"></i>
                        <span>Live Attack Feed</span>
                        <span class="live-indicator"><span class="live-dot"></span>Live</span>
                    </div>
                    <div class="attack-feed-list" id="attack-feed-list"></div>
                </div>
            </div>
        `;

        this.canvas = document.getElementById("attackmap-canvas");
        this.ctx = this.canvas.getContext("2d");
        this.feedEl = document.getElementById("attack-feed-list");
        this.tooltip = document.getElementById("attackmap-tooltip");

        // Tooltip events
        this.canvas.addEventListener("mousemove", (e) => this._onMouseMove(e));
        this.canvas.addEventListener("mouseleave", () => this._hideTooltip());

        if (typeof lucide !== "undefined") lucide.createIcons();

        this._resize();
        window.addEventListener("resize", () => this._resize());
    }

    _resize() {
        const wrap = this.container.querySelector(".attackmap-map-wrap");
        if (!wrap) return;
        const rect = wrap.getBoundingClientRect();
        this.width = rect.width;
        this.height = rect.height;
        this.canvas.width = this.width * devicePixelRatio;
        this.canvas.height = this.height * devicePixelRatio;
        this.canvas.style.width = this.width + "px";
        this.canvas.style.height = this.height + "px";
        this.ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);

        // Map projection
        this.projection = d3.geoEquirectangular().fitSize([this.width, this.height], {type: "Sphere"});
        this.pathGenerator = d3.geoPath().projection(this.projection).context(this.ctx);

        // Recompute honeypot positions
        this.honeypots.forEach(hp => {
            const pos = latLonToXY(hp.lat, hp.lon, this);
            hp.x = pos.x;
            hp.y = pos.y;
        });
    }

    // ─── Tooltip Logic ─────────────────────────────────────────────────────
    _onMouseMove(e) {
        const rect = this.canvas.getBoundingClientRect();
        // Mouse coordinates relative to canvas drawn size
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        let hovered = null;
        for (const hp of this.honeypots) {
            const dx = hp.x - mouseX;
            const dy = hp.y - mouseY;
            if (Math.hypot(dx, dy) < 18) { // Hover radius
                hovered = hp;
                break;
            }
        }

        if (hovered) {
            this.canvas.style.cursor = "pointer";
            this._showTooltip(hovered, mouseX, mouseY);
        } else {
            this.canvas.style.cursor = "crosshair";
            this._hideTooltip();
        }
    }

    _showTooltip(hp, x, y) {
        if (!this.tooltip) return;
        
        // Agent meta
        let content = `
            <div class="tooltip-title">
                <i data-lucide="cpu" style="width:16px;height:16px;margin-right:6px"></i>
                ${escapeHtml(hp.name)}
            </div>
            <div class="tooltip-row">
                <span class="tooltip-label">Node ID</span>
                <code>${escapeHtml(hp.agent.node_id)}</code>
            </div>
            <div class="tooltip-row">
                <span class="tooltip-label">IP Address</span>
                <code>${escapeHtml(hp.ip)}</code>
            </div>
            <div class="tooltip-row">
                <span class="tooltip-label">Location</span>
                <span>${(hp.lat||0).toFixed(2)}, ${(hp.lon||0).toFixed(2)}</span>
            </div>
        `;
        
        if (hp.agent && hp.agent.runtime_status) {
            const activeDeployments = Object.keys(hp.agent.runtime_status).filter(k => hp.agent.runtime_status[k].state === "running").length;
            const styleClass = activeDeployments > 0 ? "text-success" : "text-danger";
            content += `
                <div class="tooltip-row" style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.05)">
                    <span class="tooltip-label">Honeypots Hosted</span>
                    <span class="${styleClass}">${activeDeployments} Active</span>
                </div>
            `;
        }

        this.tooltip.innerHTML = content;
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons({ root: this.tooltip });
        }

        this.tooltip.style.display = "block";
        this.tooltip.style.left = `${x}px`;
        this.tooltip.style.top = `${y - 12}px`;
    }

    _hideTooltip() {
        if (this.tooltip) {
            this.tooltip.style.display = "none";
        }
    }

    // ─── Map Rendering ─────────────────────────────────────────────────────
    _drawMapBackground() {
        const ctx = this.ctx;
        const w = this.width;
        const h = this.height;

        const isLight = document.documentElement.getAttribute('data-theme') === 'light';

        ctx.fillStyle = isLight ? "#f0f4f8" : "#080c14";
        ctx.fillRect(0, 0, w, h);

        if (!this.pathGenerator) return;

        // Draw Graticule (Grid lines)
        const graticule = d3.geoGraticule();
        ctx.beginPath();
        this.pathGenerator(graticule());
        ctx.strokeStyle = isLight ? "rgba(6, 182, 212, 0.15)" : "rgba(6, 182, 212, 0.05)";
        ctx.lineWidth = 0.5;
        ctx.stroke();

        // Draw Map Landmass
        if (this.land) {
            ctx.beginPath();
            this.pathGenerator(this.land);
            
            // Fill
            ctx.fillStyle = isLight ? "rgba(226, 232, 240, 0.8)" : "rgba(10, 20, 30, 0.6)"; 
            ctx.fill();
            
            // Stroke shadow for a glowing edge effect
            ctx.shadowColor = isLight ? "rgba(6, 182, 212, 0.1)" : "rgba(6, 182, 212, 0.3)";
            ctx.shadowBlur = 8;
            ctx.strokeStyle = isLight ? "rgba(6, 182, 212, 0.6)" : "rgba(6, 182, 212, 0.4)";
            ctx.lineWidth = 1;
            ctx.stroke();

            // Clear shadow for next items
            ctx.shadowBlur = 0;
            ctx.shadowColor = "transparent";
        }
    }

    // ─── Honeypot Markers ──────────────────────────────────────────────────
    _drawHoneypots(time) {
        const ctx = this.ctx;
        for (const hp of this.honeypots) {
            const pulse = Math.sin(time * 0.003 + hp.pulsePhase) * 0.5 + 0.5;

            // Outer glow
            const gradient = ctx.createRadialGradient(hp.x, hp.y, 2, hp.x, hp.y, 14 + pulse * 6);
            gradient.addColorStop(0, "rgba(16, 185, 129, 0.8)");
            gradient.addColorStop(1, "rgba(16, 185, 129, 0)");
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.arc(hp.x, hp.y, 14 + pulse * 6, 0, Math.PI * 2);
            ctx.fill();

            // Core dot
            ctx.fillStyle = "#10b981";
            ctx.beginPath();
            ctx.arc(hp.x, hp.y, 4, 0, Math.PI * 2);
            ctx.fill();

            // Inner dark dot (high tech look)
            ctx.fillStyle = "#000";
            ctx.beginPath();
            ctx.arc(hp.x, hp.y, 1.5, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    // ─── Attack Arc Animation ──────────────────────────────────────────────
    addAttack(srcGeo, dstGeo, protocol, log) {
        const src = latLonToXY(srcGeo.lat, srcGeo.lon, this);
        const dst = latLonToXY(dstGeo.lat, dstGeo.lon, this);

        // Determine color by protocol
        let color;
        switch (protocol) {
            case "http": color = { r: 59, g: 130, b: 246 }; break;   // Blue
            case "mqtt": color = { r: 168, g: 85, b: 247 }; break;   // Purple
            case "ssh": color = { r: 239, g: 68, b: 68 }; break;     // Red
            case "modbus": color = { r: 14, g: 165, b: 233 }; break;  // Cyan
            default: color = { r: 245, g: 158, b: 11 }; break;       // Orange
        }

        this.attacks.push({
            sx: src.x, sy: src.y,
            dx: dst.x, dy: dst.y,
            progress: 0,
            color,
            protocol,
            trail: [],
            startTime: performance.now(),
            duration: 1800 + Math.random() * 600, // randomized speed
            impacted: false,
        });

        this.totalAttacks++;
        const totalEl = document.getElementById("attackmap-total");
        if (totalEl) totalEl.textContent = this.totalAttacks;

        const uniqueEl = document.getElementById("attackmap-unique");
        if (uniqueEl) uniqueEl.textContent = geoCache.size;

        this._addFeedEntry(srcGeo, dstGeo, protocol, log);
    }

    _drawAttacks(time) {
        const ctx = this.ctx;
        const toRemove = [];

        for (let i = 0; i < this.attacks.length; i++) {
            const atk = this.attacks[i];
            const elapsed = time - atk.startTime;
            atk.progress = Math.min(elapsed / atk.duration, 1);

            if (atk.progress >= 1) {
                // Impact flash
                if (!atk.impacted) {
                    atk.impacted = true;
                    this._drawImpact(ctx, atk.dx, atk.dy, atk.color);
                }
                // Keep impact visible briefly
                if (elapsed > atk.duration + 500) {
                    toRemove.push(i);
                }
                continue;
            }

            const t = atk.progress;
            // Quadratic Bezier control point (arc upward)
            const midX = (atk.sx + atk.dx) / 2;
            const midY = (atk.sy + atk.dy) / 2;
            const dist = Math.hypot(atk.dx - atk.sx, atk.dy - atk.sy);
            const cpX = midX;
            const cpY = midY - dist * 0.35; // arc height

            // Current position on curve
            const curX = (1 - t) * (1 - t) * atk.sx + 2 * (1 - t) * t * cpX + t * t * atk.dx;
            const curY = (1 - t) * (1 - t) * atk.sy + 2 * (1 - t) * t * cpY + t * t * atk.dy;

            // Trail
            atk.trail.push({ x: curX, y: curY, birth: time });

            // Draw trail
            const { r, g, b } = atk.color;
            if (atk.trail.length > 1) {
                ctx.lineCap = "round";
                ctx.lineJoin = "round";
                for (let j = 1; j < atk.trail.length; j++) {
                    const age = (time - atk.trail[j].birth) / 600;
                    const alpha = Math.max(0, 0.7 - age);
                    if (alpha <= 0) continue;
                    ctx.strokeStyle = `rgba(${r},${g},${b},${alpha})`;
                    ctx.lineWidth = 2 - age;
                    ctx.beginPath();
                    ctx.moveTo(atk.trail[j - 1].x, atk.trail[j - 1].y);
                    ctx.lineTo(atk.trail[j].x, atk.trail[j].y);
                    ctx.stroke();
                }
            }

            // Glow head
            const headGrad = ctx.createRadialGradient(curX, curY, 0, curX, curY, 10);
            headGrad.addColorStop(0, `rgba(${r},${g},${b},0.9)`);
            headGrad.addColorStop(1, `rgba(${r},${g},${b},0)`);
            ctx.fillStyle = headGrad;
            ctx.beginPath();
            ctx.arc(curX, curY, 10, 0, Math.PI * 2);
            ctx.fill();

            // Core particle
            ctx.fillStyle = `rgba(255,255,255,1)`;
            ctx.beginPath();
            ctx.arc(curX, curY, 2.5, 0, Math.PI * 2);
            ctx.fill();

            // Clean old trail points
            atk.trail = atk.trail.filter(pt => time - pt.birth < 600);
        }

        // Remove finished attacks
        for (let i = toRemove.length - 1; i >= 0; i--) {
            this.attacks.splice(toRemove[i], 1);
        }
    }

    _drawImpact(ctx, x, y, color) {
        const { r, g, b } = color;
        // Flash ring
        for (let radius = 5; radius < 30; radius += 6) {
            const alpha = 0.5 - (radius / 30) * 0.5;
            ctx.strokeStyle = `rgba(${r},${g},${b},${alpha})`;
            ctx.lineWidth = 2.5;
            ctx.beginPath();
            ctx.arc(x, y, radius, 0, Math.PI * 2);
            ctx.stroke();
        }
    }

    // ─── Attack Feed Panel ─────────────────────────────────────────────────
    _addFeedEntry(srcGeo, dstGeo, protocol, log) {
        if (!this.feedEl) return;
        this.feedCount++;

        const now = new Date();
        const timeStr = now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

        const protocolColors = {
            http: "#3b82f6", mqtt: "#a855f7", ssh: "#ef4444",
            modbus: "#0ea5e9", default: "#f59e0b"
        };
        const pColor = protocolColors[protocol] || protocolColors.default;

        const entry = document.createElement("div");
        entry.className = "feed-entry feed-entry-new";
        entry.innerHTML = `
            <div class="feed-entry-header">
                <span class="feed-protocol" style="background:${pColor}20;color:${pColor};border:1px solid ${pColor}40">${escapeHtml(protocol || "unknown").toUpperCase()}</span>
                <span class="feed-time">${timeStr}</span>
            </div>
            <div class="feed-detail">
                <span class="feed-ip">${escapeHtml(srcGeo.ip || "?")}</span>
                <span class="feed-arrow">→</span>
                <span class="feed-target">${escapeHtml(dstGeo.city || dstGeo.country || "Honeypot")}</span>
            </div>
            <div class="feed-location">${escapeHtml(srcGeo.city ? srcGeo.city + ", " : "")}${escapeHtml(srcGeo.country || "Unknown")}</div>
        `;

        this.feedEl.prepend(entry);

        // Remove "new" animation class after it plays
        setTimeout(() => entry.classList.remove("feed-entry-new"), 500);

        // Cap feed length
        while (this.feedEl.children.length > 50) {
            this.feedEl.lastChild.remove();
        }
    }

    // ─── Main Animation Loop ───────────────────────────────────────────────
    start() {
        this._animate = (time) => {
            this._drawMapBackground();
            this._drawHoneypots(time);
            this._drawAttacks(time);
            this.animationId = requestAnimationFrame(this._animate);
        };
        this.animationId = requestAnimationFrame(this._animate);

        // Start polling for logs
        this._pollLogs();
        this.pollTimer = setInterval(() => this._pollLogs(), 3000);

        // Load agents to place honeypot markers
        this._loadHoneypotMarkers();
    }

    stop() {
        if (this.animationId) {
            cancelAnimationFrame(this.animationId);
            this.animationId = null;
        }
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    async _loadHoneypotMarkers() {
        try {
            const agents = await fetch("/api/agents").then(r => r.json());
            this.agentsCache = agents;
            this.honeypots = [];

            const locationCounts = new Map();

            for (const agent of agents) {
                if (agent.status !== "Online") continue;
                const geo = await resolveGeoIP(agent.ip);
                
                let lat = geo.lat;
                let lon = geo.lon;

                // Add a small jitter if multiple agents share the same location
                const locKey = `${lat.toFixed(3)},${lon.toFixed(3)}`;
                const count = locationCounts.get(locKey) || 0;
                locationCounts.set(locKey, count + 1);

                if (count > 0) {
                    // Spiral offset: move each subsequent agent slightly further away in a circle
                    const angle = count * 0.8; // radians
                    const radius = 1.2 * Math.sqrt(count); // degrees (approx 130km at equator per 1.2deg)
                    lat += radius * Math.sin(angle);
                    lon += radius * Math.cos(angle);
                }

                const pos = latLonToXY(lat, lon, this);
                this.honeypots.push({
                    x: pos.x, y: pos.y,
                    lat: lat, lon: lon,
                    name: agent.name || agent.node_id,
                    ip: agent.ip,
                    agent: agent, // store full agent for tooltip
                    pulsePhase: Math.random() * Math.PI * 2,
                });
            }

            const hpEl = document.getElementById("attackmap-honeypots");
            if (hpEl) hpEl.textContent = this.honeypots.length;
        } catch (_e) { /* ignore */ }
    }

    async _pollLogs() {
        try {
            const logs = await fetch("/api/recent_logs").then(r => r.json());
            for (const log of logs) {
                const logId = log.id;
                if (this.seenLogIds.has(logId)) continue;
                this.seenLogIds.add(logId);

                // Resolve attacker geo
                const srcGeo = await resolveGeoIP(log.attacker_ip);

                // Find the honeypot target
                let dstGeo = null;
                
                // Try to find the specific honeypot marker (which might have a jittered position)
                const hp = this.honeypots.find(h => h.agent.node_id === log.node_id);
                if (hp) {
                    dstGeo = { lat: hp.lat, lon: hp.lon, ip: hp.ip, country: "", city: hp.name };
                } else {
                    // Fallback to resolving by IP if agent not in current markers
                    const agent = this.agentsCache.find(a => a.node_id === log.node_id);
                    if (agent) {
                        const resolved = await resolveGeoIP(agent.ip);
                        dstGeo = { ...resolved, city: agent.name || agent.node_id };
                    }
                }

                if (!dstGeo) {
                    if (this.honeypots.length > 0) {
                        const hp = this.honeypots[0];
                        dstGeo = { lat: hp.lat, lon: hp.lon, ip: hp.ip, country: "", city: hp.name };
                    } else {
                        dstGeo = DEFAULT_LOCATION;
                    }
                }

                this.addAttack(srcGeo, dstGeo, log.protocol, log);
            }

            if (this.seenLogIds.size > 500) {
                const arr = Array.from(this.seenLogIds);
                this.seenLogIds = new Set(arr.slice(arr.length - 300));
            }
        } catch (_e) { /* ignore */ }
    }
}

// ─── Exports ───────────────────────────────────────────────────────────────
window.AttackMap = AttackMap;
