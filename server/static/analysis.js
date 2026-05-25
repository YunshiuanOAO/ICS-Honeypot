/**
 * APS Honeypot — IP-grouped Log Analysis
 *
 * Powers the panel below the Attack Map: pulls /api/ip_analysis,
 * renders one card per attacker IP, and opens a detail modal with
 * Suricata-style alerts + raw packets when a card is clicked.
 */
(function () {
    "use strict";

    let ipAnalysisRefreshTimer = null;
    let lastFetchedRows = [];
    let inFlightController = null;
    let consecutiveFailures = 0;

    // Suricata severity: 1=high, 2=medium, 3=low, 0=none
    const SEVERITY_LABEL = { 0: "None", 1: "High", 2: "Medium", 3: "Low" };
    const SEVERITY_CLASS = { 0: "sev-none", 1: "sev-high", 2: "sev-med", 3: "sev-low" };

    const PROTOCOL_CLASS = {
        http: "proto-http",
        mqtt: "proto-mqtt",
        modbus: "proto-modbus",
        ssh: "proto-ssh",
        tcp: "proto-tcp",
    };

    function escapeHtml(text) {
        if (text === null || text === undefined) return "";
        const div = document.createElement("div");
        div.textContent = String(text);
        return div.innerHTML;
    }

    function formatTime(ts) {
        if (!ts) return "—";
        const d = new Date(ts);
        if (Number.isNaN(d.getTime())) return ts;
        return d.toLocaleString("en-US", { hour12: false });
    }

    function formatRelative(ts) {
        if (!ts) return "—";
        const d = new Date(ts);
        if (Number.isNaN(d.getTime())) return ts;
        const diff = Math.floor((Date.now() - d.getTime()) / 1000);
        if (diff < 60) return "just now";
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }

    function parseMaybeJson(s) {
        if (s === null || s === undefined) return null;
        if (typeof s === "object") return s;
        try { return JSON.parse(s); } catch (_e) { return null; }
    }

    function isPrivateIp(ip) {
        return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip || "");
    }

    async function fetchGeo(ip) {
        if (!ip || isPrivateIp(ip)) return null;
        try {
            const resp = await fetch(`/api/geoip/${encodeURIComponent(ip)}`);
            if (!resp.ok) return null;
            const data = await resp.json();
            if (data.status !== "success") return null;
            return data;
        } catch (_e) {
            return null;
        }
    }

    // ─── Fetch + render ─────────────────────────────────────────────

    function localDatetimeToIso(value) {
        // <input type="datetime-local"> returns "2026-05-13T08:30" (no TZ).
        // Treat it as local time and produce an ISO string so the server
        // compares against the local-time strings already stored in `logs`.
        if (!value) return "";
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) return "";
        const pad = n => String(n).padStart(2, "0");
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
               `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }

    function buildAnalysisQuery() {
        const windowSel = document.getElementById("ip-analysis-window");
        const value = windowSel ? windowSel.value : "";
        const params = ["limit=200"];

        if (value === "custom") {
            const fromIso = localDatetimeToIso(document.getElementById("ip-analysis-from")?.value || "");
            const toIso = localDatetimeToIso(document.getElementById("ip-analysis-to")?.value || "");
            if (fromIso) params.push(`from_ts=${encodeURIComponent(fromIso)}`);
            if (toIso) params.push(`to_ts=${encodeURIComponent(toIso)}`);
        } else if (value) {
            params.push(`hours=${encodeURIComponent(value)}`);
        }
        return `/api/ip_analysis?${params.join("&")}`;
    }

    function updateCustomVisibility() {
        const windowSel = document.getElementById("ip-analysis-window");
        const customBox = document.getElementById("ip-analysis-custom");
        if (!customBox) return;
        const isCustom = windowSel?.value === "custom";
        customBox.hidden = !isCustom;
    }

    // Map alert source -> display label + CSS class.
    const ALERT_SOURCE_LABELS = {
        "elastalert": { label: "ElastAlert", cls: "alert-source-elastalert" },
    };

    function renderAlertSourceTag(source) {
        const info = ALERT_SOURCE_LABELS[source] || { label: source || "Unknown", cls: "" };
        return `<span class="alert-source-tag ${info.cls}">${escapeHtml(info.label)}</span>`;
    }

    function setStaleBanner(visible, reason) {
        const panel = document.querySelector(".ip-analysis-panel");
        if (!panel) return;
        let banner = panel.querySelector(".ip-analysis-stale");
        if (!visible) {
            if (banner) banner.remove();
            return;
        }
        if (!banner) {
            banner = document.createElement("div");
            banner.className = "ip-analysis-stale";
            panel.insertBefore(banner, panel.querySelector(".ip-analysis-grid"));
        }
        banner.innerHTML = `
            <i data-lucide="alert-triangle"></i>
            <span>${reason || "Couldn't refresh — showing last known data"}</span>
            <button type="button" class="ip-analysis-stale-retry" onclick="refreshIpAnalysis()">Retry</button>
        `;
        if (typeof lucide !== "undefined") lucide.createIcons({ root: banner });
    }

    async function refreshIpAnalysis() {
        const grid = document.getElementById("ip-analysis-grid");
        if (!grid) {
            console.warn("[analysis] grid element not found");
            return;
        }

        // First-load loading hint so user can tell the fetch was triggered.
        if (!lastFetchedRows.length && grid.querySelector("#ip-analysis-empty")) {
            grid.innerHTML = `<div class="table-empty-state"><i data-lucide="loader"></i><p>Loading IP analysis…</p></div>`;
            if (typeof lucide !== "undefined") lucide.createIcons();
        }

        // Cancel any prior in-flight request — only one refresh at a time.
        if (inFlightController) inFlightController.abort();
        inFlightController = new AbortController();
        const controller = inFlightController;

        const url = buildAnalysisQuery();
        console.debug("[analysis] fetching", url);

        try {
            const resp = await fetch(url, { signal: controller.signal });
            if (controller.signal.aborted) {
                console.debug("[analysis] aborted before response");
                return;
            }
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

            const ct = resp.headers.get("content-type") || "";
            if (!ct.includes("application/json")) {
                // 401 redirect-to-login etc. produces HTML; the global fetch
                // wrapper handles 401, so just bail silently here.
                throw new Error(`Unexpected response (${ct.split(";")[0] || "non-JSON"})`);
            }

            const rows = await resp.json();
            console.debug("[analysis] got", rows.length, "rows");
            lastFetchedRows = Array.isArray(rows) ? rows : [];
            consecutiveFailures = 0;
            setStaleBanner(false);
            renderIpAnalysisRows(applySearchFilter(lastFetchedRows));
        } catch (e) {
            if (e.name === "AbortError") return;
            consecutiveFailures++;
            console.warn(`ip_analysis fetch failed (#${consecutiveFailures}):`, e.message || e);

            // First/second failure: keep showing the last good data, just
            // hint that the latest refresh missed. Third+ failure: replace
            // the empty placeholder with a clearer error, but only if we
            // never managed to load anything.
            if (lastFetchedRows.length) {
                setStaleBanner(true, `Couldn't refresh (${e.message || "error"}) — showing last good data`);
            } else if (consecutiveFailures >= 3) {
                grid.innerHTML = `
                    <div class="table-empty-state">
                        <i data-lucide="alert-circle"></i>
                        <p>Failed to load IP analysis</p>
                        <button class="btn btn-secondary btn-sm" onclick="refreshIpAnalysis()">
                            <i data-lucide="refresh-cw"></i><span>Retry</span>
                        </button>
                    </div>`;
                if (typeof lucide !== "undefined") lucide.createIcons();
            }
        } finally {
            if (controller === inFlightController) inFlightController = null;
        }
    }

    function applySearchFilter(rows) {
        const search = document.getElementById("ip-analysis-search");
        const term = (search?.value || "").trim().toLowerCase();
        if (!term) return rows;
        return rows.filter(r => (r.ip || "").toLowerCase().includes(term));
    }

    function renderIpAnalysisRows(rows) {
        const grid = document.getElementById("ip-analysis-grid");
        if (!grid) return;

        if (!rows.length) {
            grid.innerHTML = `<div class="table-empty-state"><i data-lucide="search"></i><p>No attacker activity matches the current filter</p></div>`;
            if (typeof lucide !== "undefined") lucide.createIcons();
            return;
        }

        const html = rows.map(row => {
            const sev = Number(row.max_severity || 0);
            const sevClass = SEVERITY_CLASS[sev] || SEVERITY_CLASS[0];
            const sevLabel = SEVERITY_LABEL[sev] || "None";

            const protos = (row.protocols || []).filter(Boolean);
            const protoBadges = protos.map(p => {
                const cls = PROTOCOL_CLASS[p?.toLowerCase()] || "proto-default";
                return `<span class="proto-badge ${cls}">${escapeHtml((p || "").toUpperCase())}</span>`;
            }).join("");

            const nodes = (row.node_ids || []).filter(Boolean);
            const nodeText = nodes.length ? nodes.join(", ") : "—";

            const alertBadge = row.alert_count > 0
                ? `<div class="ip-card-alert ${sevClass}">
                       <i data-lucide="shield-alert"></i>
                       <span>${row.alert_count} alert${row.alert_count === 1 ? "" : "s"}</span>
                       <span class="ip-card-sev-pill">${sevLabel}</span>
                   </div>`
                : `<div class="ip-card-alert sev-none">
                       <i data-lucide="shield-check"></i>
                       <span>No alerts</span>
                   </div>`;

            return `
                <div class="ip-card" data-ip="${escapeHtml(row.ip || "")}" onclick="openIpModal('${escapeHtml(row.ip || "")}')">
                    <div class="ip-card-head">
                        <div class="ip-card-ip">
                            <i data-lucide="globe-2"></i>
                            <span>${escapeHtml(row.ip || "—")}</span>
                            ${isPrivateIp(row.ip) ? '<span class="ip-card-tag">Private</span>' : ""}
                        </div>
                        ${alertBadge}
                    </div>
                    <div class="ip-card-body">
                        <div class="ip-card-stat">
                            <span class="ip-card-stat-label">Packets</span>
                            <span class="ip-card-stat-value">${row.total_packets || 0}</span>
                        </div>
                        <div class="ip-card-stat">
                            <span class="ip-card-stat-label">Protocols</span>
                            <span class="ip-card-stat-value ip-card-protos">${protoBadges || "—"}</span>
                        </div>
                        <div class="ip-card-stat">
                            <span class="ip-card-stat-label">Agents</span>
                            <span class="ip-card-stat-value ip-card-nodes" title="${escapeHtml(nodeText)}">${escapeHtml(nodeText)}</span>
                        </div>
                        <div class="ip-card-stat">
                            <span class="ip-card-stat-label">Last seen</span>
                            <span class="ip-card-stat-value" title="${escapeHtml(formatTime(row.last_seen))}">${escapeHtml(formatRelative(row.last_seen))}</span>
                        </div>
                    </div>
                </div>`;
        }).join("");

        grid.innerHTML = html;
        if (typeof lucide !== "undefined") lucide.createIcons();
    }

    // ─── IP detail modal ────────────────────────────────────────────

    async function openIpModal(ip) {
        if (!ip) return;
        const backdrop = document.getElementById("ip-modal-backdrop");
        const title = document.getElementById("ip-modal-title");
        const subtitle = document.getElementById("ip-modal-subtitle");
        if (!backdrop) return;

        title.textContent = ip;
        subtitle.textContent = "Loading…";
        backdrop.classList.add("visible");
        switchIpTab("overview");

        document.getElementById("ip-modal-overview").innerHTML = `<div class="ip-modal-loading">Loading details…</div>`;
        document.getElementById("ip-modal-alerts").innerHTML = "";
        document.getElementById("ip-modal-packets").innerHTML = "";
        document.getElementById("ip-modal-alerts-badge").textContent = "0";
        document.getElementById("ip-modal-packets-badge").textContent = "0";

        try {
            const [details, geo] = await Promise.all([
                fetch(`/api/ip_details/${encodeURIComponent(ip)}?limit=300`).then(r => r.json()),
                fetchGeo(ip),
            ]);

            const logs = details.logs || [];
            const alerts = details.alerts || [];

            renderModalOverview(ip, logs, alerts, geo);
            renderModalAlerts(alerts);
            renderModalPackets(logs);

            const protos = new Set(logs.map(l => l.protocol).filter(Boolean));
            subtitle.textContent = geo
                ? `${geo.city ? geo.city + ", " : ""}${geo.country || "Unknown"} · ${protos.size} protocol${protos.size === 1 ? "" : "s"}`
                : `${protos.size} protocol${protos.size === 1 ? "" : "s"}`;
        } catch (e) {
            console.error("ip_details fetch failed", e);
            document.getElementById("ip-modal-overview").innerHTML = `<div class="ip-modal-error">Failed to load details.</div>`;
            subtitle.textContent = "Error";
        }
    }

    function closeIpModal(event) {
        if (event && event.target && event.target.id !== "ip-modal-backdrop") return;
        document.getElementById("ip-modal-backdrop")?.classList.remove("visible");
    }

    function switchIpTab(tabName) {
        document.querySelectorAll(".ip-modal-tab").forEach(btn => {
            btn.classList.toggle("active", btn.dataset.tab === tabName);
        });
        document.querySelectorAll(".ip-modal-tab-panel").forEach(p => {
            p.classList.toggle("active", p.dataset.tabPanel === tabName);
        });
    }

    function renderModalOverview(ip, logs, alerts, geo) {
        const protos = {};
        const ports = new Set();
        let firstSeen = null, lastSeen = null;
        logs.forEach(l => {
            const p = l.protocol || "unknown";
            protos[p] = (protos[p] || 0) + 1;
            const meta = parseMaybeJson(l.metadata) || {};
            if (meta.dst_port) ports.add(meta.dst_port);
            if (!firstSeen || l.timestamp < firstSeen) firstSeen = l.timestamp;
            if (!lastSeen || l.timestamp > lastSeen) lastSeen = l.timestamp;
        });

        const sevCounts = { 1: 0, 2: 0, 3: 0 };
        alerts.forEach(a => {
            const s = Number(a.severity) || 3;
            if (sevCounts[s] !== undefined) sevCounts[s]++;
        });

        const protoRows = Object.entries(protos)
            .sort((a, b) => b[1] - a[1])
            .map(([p, c]) => {
                const cls = PROTOCOL_CLASS[p.toLowerCase()] || "proto-default";
                return `<div class="ip-overview-row">
                    <span class="proto-badge ${cls}">${escapeHtml(p.toUpperCase())}</span>
                    <span>${c} packet${c === 1 ? "" : "s"}</span>
                </div>`;
            }).join("") || `<div class="ip-overview-row">No packets recorded</div>`;

        const portList = ports.size
            ? Array.from(ports).sort((a, b) => a - b).map(p => `<code>${escapeHtml(p)}</code>`).join(" ")
            : "—";

        const geoBlock = geo
            ? `<div class="ip-overview-card">
                    <h4><i data-lucide="map-pin"></i> GeoIP</h4>
                    <div class="ip-overview-kv"><span>Country</span><strong>${escapeHtml(geo.country || "—")}</strong></div>
                    <div class="ip-overview-kv"><span>City</span><strong>${escapeHtml(geo.city || "—")}</strong></div>
                    <div class="ip-overview-kv"><span>Coords</span><strong>${(geo.lat || 0).toFixed(2)}, ${(geo.lon || 0).toFixed(2)}</strong></div>
               </div>`
            : `<div class="ip-overview-card">
                    <h4><i data-lucide="map-pin"></i> GeoIP</h4>
                    <div class="ip-overview-kv"><span>Status</span><strong>${isPrivateIp(ip) ? "Private Network" : "Unknown"}</strong></div>
               </div>`;

        document.getElementById("ip-modal-overview").innerHTML = `
            <div class="ip-overview-grid">
                <div class="ip-overview-card">
                    <h4><i data-lucide="activity"></i> Activity</h4>
                    <div class="ip-overview-kv"><span>Total Packets</span><strong>${logs.length}</strong></div>
                    <div class="ip-overview-kv"><span>First Seen</span><strong>${escapeHtml(formatTime(firstSeen))}</strong></div>
                    <div class="ip-overview-kv"><span>Last Seen</span><strong>${escapeHtml(formatTime(lastSeen))}</strong></div>
                    <div class="ip-overview-kv"><span>Ports Touched</span><strong>${portList}</strong></div>
                </div>
                <div class="ip-overview-card">
                    <h4><i data-lucide="shield-alert"></i> Detection Alerts</h4>
                    <div class="ip-overview-kv"><span>Total</span><strong>${alerts.length}</strong></div>
                    <div class="ip-overview-kv"><span class="sev-pill sev-high">High</span><strong>${sevCounts[1]}</strong></div>
                    <div class="ip-overview-kv"><span class="sev-pill sev-med">Medium</span><strong>${sevCounts[2]}</strong></div>
                    <div class="ip-overview-kv"><span class="sev-pill sev-low">Low</span><strong>${sevCounts[3]}</strong></div>
                </div>
                ${geoBlock}
                <div class="ip-overview-card ip-overview-card-wide">
                    <h4><i data-lucide="layers"></i> Protocol Breakdown</h4>
                    ${protoRows}
                </div>
            </div>
        `;
        if (typeof lucide !== "undefined") lucide.createIcons();
    }

    function renderModalAlerts(alerts) {
        const container = document.getElementById("ip-modal-alerts");
        document.getElementById("ip-modal-alerts-badge").textContent = alerts.length;

        if (!alerts.length) {
            container.innerHTML = `<div class="ip-modal-empty"><i data-lucide="shield-check"></i><p>No alerts for this IP</p></div>`;
            if (typeof lucide !== "undefined") lucide.createIcons();
            return;
        }

        const html = alerts.map(a => {
            const sev = Number(a.severity) || 3;
            const sevClass = SEVERITY_CLASS[sev] || SEVERITY_CLASS[3];
            const sevLabel = SEVERITY_LABEL[sev] || "Low";
            const meta = parseMaybeJson(a.metadata) || {};
            const metaText = Object.keys(meta).length
                ? `<pre class="alert-meta">${escapeHtml(JSON.stringify(meta, null, 2))}</pre>`
                : "";
            const sourceTag = renderAlertSourceTag(a.source);

            return `
                <div class="alert-row ${sevClass}">
                    <div class="alert-row-head">
                        <span class="alert-sev-pill ${sevClass}">${sevLabel}</span>
                        <span class="alert-sig">${escapeHtml(a.signature || "Unknown signature")}</span>
                        <span class="alert-time">${escapeHtml(formatTime(a.timestamp))}</span>
                    </div>
                    <div class="alert-row-meta">
                        <span><strong>SID</strong> ${escapeHtml(a.signature_id ?? "—")}</span>
                        <span><strong>Category</strong> ${escapeHtml(a.category || "—")}</span>
                        <span><strong>Proto</strong> ${escapeHtml((a.protocol || "—").toUpperCase())}</span>
                        <span><strong>Dest</strong> ${escapeHtml(a.dst_ip || "—")}:${escapeHtml(a.dst_port || "—")}</span>
                        <span><strong>Node</strong> ${escapeHtml(a.node_id || "—")}</span>
                        ${sourceTag}
                    </div>
                    ${metaText}
                </div>`;
        }).join("");

        container.innerHTML = html;
    }

    function renderModalPackets(logs) {
        const container = document.getElementById("ip-modal-packets");
        document.getElementById("ip-modal-packets-badge").textContent = logs.length;

        if (!logs.length) {
            container.innerHTML = `<div class="ip-modal-empty"><i data-lucide="inbox"></i><p>No packets recorded</p></div>`;
            if (typeof lucide !== "undefined") lucide.createIcons();
            return;
        }

        const html = logs.map(l => {
            const meta = parseMaybeJson(l.metadata) || {};
            const protoCls = PROTOCOL_CLASS[(l.protocol || "").toLowerCase()] || "proto-default";
            const summary = meta["log.message"] || meta["log_message"] || meta["mqtt_packet_type_name"] || meta["http_method"] || meta["modbus_function_name"] || "";
            const req = l.request_data || "";
            const resp = l.response_data || "";

            return `
                <details class="packet-row">
                    <summary>
                        <span class="proto-badge ${protoCls}">${escapeHtml((l.protocol || "?").toUpperCase())}</span>
                        <span class="packet-time">${escapeHtml(formatTime(l.timestamp))}</span>
                        <span class="packet-summary">${escapeHtml(summary || "packet")}</span>
                        <span class="packet-port">${escapeHtml((meta.src_port ?? "") + "→" + (meta.dst_port ?? ""))}</span>
                    </summary>
                    <div class="packet-body">
                        <div class="packet-kv"><span>Node</span><code>${escapeHtml(l.node_id || "—")}</code></div>
                        <div class="packet-kv"><span>Request</span><code class="packet-data">${escapeHtml(req || "—")}</code></div>
                        <div class="packet-kv"><span>Response</span><code class="packet-data">${escapeHtml(resp || "—")}</code></div>
                        <details class="packet-meta-toggle">
                            <summary>Metadata</summary>
                            <pre>${escapeHtml(JSON.stringify(meta, null, 2))}</pre>
                        </details>
                    </div>
                </details>`;
        }).join("");

        container.innerHTML = html;
    }

    // ─── Wire up auto-refresh + filters ─────────────────────────────

    function startIpAnalysisAutoRefresh() {
        if (ipAnalysisRefreshTimer) return;
        refreshIpAnalysis();
        ipAnalysisRefreshTimer = setInterval(refreshIpAnalysis, 30000);
    }

    function stopIpAnalysisAutoRefresh() {
        if (ipAnalysisRefreshTimer) {
            clearInterval(ipAnalysisRefreshTimer);
            ipAnalysisRefreshTimer = null;
        }
    }

    // Hook into the existing showSection() flow without modifying script.js
    const _originalShowSection = window.showSection;
    if (typeof _originalShowSection === "function") {
        window.showSection = function (sectionId) {
            _originalShowSection(sectionId);
            if (sectionId === "attackmap") {
                startIpAnalysisAutoRefresh();
            } else {
                stopIpAnalysisAutoRefresh();
            }
        };
    }

    document.addEventListener("DOMContentLoaded", () => {
        const search = document.getElementById("ip-analysis-search");
        if (search) {
            search.addEventListener("input", () => {
                renderIpAnalysisRows(applySearchFilter(lastFetchedRows));
            });
        }
        const windowSel = document.getElementById("ip-analysis-window");
        if (windowSel) {
            windowSel.addEventListener("change", () => {
                updateCustomVisibility();
                refreshIpAnalysis();
            });
            updateCustomVisibility();
        }

        // Custom range — debounce so dragging the picker doesn't spam the API
        let customRefreshTimer = null;
        const scheduleCustomRefresh = () => {
            clearTimeout(customRefreshTimer);
            customRefreshTimer = setTimeout(refreshIpAnalysis, 350);
        };
        ["ip-analysis-from", "ip-analysis-to"].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener("change", scheduleCustomRefresh);
        });

        const clearBtn = document.getElementById("ip-analysis-clear-custom");
        if (clearBtn) {
            clearBtn.addEventListener("click", () => {
                const from = document.getElementById("ip-analysis-from");
                const to = document.getElementById("ip-analysis-to");
                if (from) from.value = "";
                if (to) to.value = "";
                refreshIpAnalysis();
            });
        }

        // ESC closes the modal
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") closeIpModal();
        });

        const attackMapVisible = !document.getElementById("attackmap")?.classList.contains("hidden");
        if (attackMapVisible) startIpAnalysisAutoRefresh();
    });

    // Expose for inline onclick handlers
    window.refreshIpAnalysis = refreshIpAnalysis;
    window.openIpModal = openIpModal;
    window.closeIpModal = closeIpModal;
    window.switchIpTab = switchIpTab;
})();
