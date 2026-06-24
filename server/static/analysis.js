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
    let progressTimer = null;
    let progressStartedAt = 0;
    let currentPage = 1;
    let currentTotal = 0;
    const pageSize = 100;

    // Suricata severity: 1=high, 2=medium, 3=low, 0=none
    const SEVERITY_LABEL = { 0: "None", 1: "High", 2: "Medium", 3: "Low" };
    const SEVERITY_CLASS = { 0: "sev-none", 1: "sev-high", 2: "sev-med", 3: "sev-low" };

    const PROTOCOL_CLASS = {
        http: "proto-http",
        https: "proto-https",
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

    function normalizeHexString(value) {
        const raw = String(value || "").trim();
        if (!raw) return "";
        let hex = raw;
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.slice(2);
        hex = hex.replace(/[\s:_-]+/g, "");
        if (hex.length < 4 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return "";
        return hex;
    }

    function decodeHexToText(value) {
        const hex = normalizeHexString(value);
        if (!hex) return null;
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.slice(i, i + 2), 16));
        }
        try {
            return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
        } catch (_e) {
            return String.fromCharCode(...bytes);
        }
    }

    function isReadableDecodedText(text) {
        if (!text) return false;
        let printable = 0;
        let control = 0;
        for (const ch of text) {
            const code = ch.charCodeAt(0);
            if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) printable++;
            else control++;
        }
        return printable > 0 && control / Math.max(printable + control, 1) < 0.2;
    }

    function formatPacketData(value, protocol = "") {
        const raw = String(value || "");
        if (!raw) return "—";
        const decoded = decodeHexToText(raw);
        const shouldDecode = decoded && isReadableDecodedText(decoded);
        if (!shouldDecode) {
            return `<code class="packet-data">${escapeHtml(raw)}</code>`;
        }

        const normalizedRaw = normalizeHexString(raw);
        const normalizedDecoded = normalizeHexString(decoded);
        if (normalizedDecoded && normalizedDecoded.toLowerCase() === normalizedRaw.toLowerCase()) {
            return `<code class="packet-data">${escapeHtml(raw)}</code>`;
        }

        return `
            <div class="packet-data-decoded">
                <pre class="packet-data-text">${escapeHtml(decoded)}</pre>
                <details class="packet-raw-toggle">
                    <summary>Raw hex</summary>
                    <code class="packet-data packet-data-raw">${escapeHtml(raw)}</code>
                </details>
            </div>`;
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
        const search = (document.getElementById("ip-analysis-search")?.value || "").trim();
        const hideAgentIps = document.getElementById("ip-analysis-agent-filter")?.checked !== false;
        const hidePrivateIps = document.getElementById("ip-analysis-private-filter")?.checked !== false;
        const params = [`page=${currentPage}`, `page_size=${pageSize}`];
        if (search) params.push(`search=${encodeURIComponent(search)}`);
        if (hideAgentIps) params.push("hide_agent_ips=true");
        if (hidePrivateIps) params.push("hide_private_ips=true");

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

    function describeAnalysisWindow() {
        const windowSel = document.getElementById("ip-analysis-window");
        const value = windowSel ? windowSel.value : "";
        if (value === "custom") {
            const fromVal = document.getElementById("ip-analysis-from")?.value || "";
            const toVal = document.getElementById("ip-analysis-to")?.value || "";
            if (fromVal && toVal) return `Custom range: ${fromVal} to ${toVal}`;
            if (fromVal) return `Custom range from ${fromVal}`;
            if (toVal) return `Custom range until ${toVal}`;
            return "Custom range";
        }
        if (value === "1") return "Last hour";
        if (value === "24") return "Last 24 hours";
        if (value === "168") return "Last 7 days";
        return "All time";
    }

    function setAnalysisProgress(visible, text) {
        const progress = document.getElementById("ip-analysis-progress");
        const label = document.getElementById("ip-analysis-progress-text");
        const elapsed = document.getElementById("ip-analysis-progress-elapsed");
        if (!progress) return;

        if (!visible) {
            progress.hidden = true;
            if (progressTimer) {
                clearInterval(progressTimer);
                progressTimer = null;
            }
            return;
        }

        progress.hidden = false;
        progressStartedAt = Date.now();
        if (label) label.textContent = text || `Loading IP analysis (${describeAnalysisWindow()})…`;
        if (elapsed) elapsed.textContent = "0s";
        if (progressTimer) clearInterval(progressTimer);
        progressTimer = setInterval(() => {
            if (!elapsed) return;
            elapsed.textContent = `${Math.max(0, Math.floor((Date.now() - progressStartedAt) / 1000))}s`;
        }, 250);
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

        // Only one refresh at a time. Aborting a browser request does not
        // reliably cancel the PostgreSQL query, so skip overlapping refreshes.
        if (inFlightController) {
            console.debug("[analysis] refresh already in flight");
            return;
        }
        inFlightController = new AbortController();
        const controller = inFlightController;
        const timeoutId = setTimeout(() => controller.abort("timeout"), 60000);

        const url = buildAnalysisQuery();
        setAnalysisProgress(true, `Loading IP analysis (${describeAnalysisWindow()})…`);
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

            const payload = await resp.json();
            const rows = Array.isArray(payload) ? payload : (payload.rows || []);
            currentTotal = Array.isArray(payload) ? rows.length : Number(payload.total || 0);
            currentPage = Array.isArray(payload) ? 1 : Number(payload.page || currentPage);
            console.debug("[analysis] got", rows.length, "rows of", currentTotal);
            lastFetchedRows = Array.isArray(rows) ? rows : [];
            consecutiveFailures = 0;
            setStaleBanner(false);
            renderIpAnalysisRows(lastFetchedRows);
        } catch (e) {
            if (e.name === "AbortError" && controller === inFlightController) {
                e = new Error("Request timed out");
            } else if (e.name === "AbortError") {
                return;
            }
            consecutiveFailures++;
            console.warn(`ip_analysis fetch failed (#${consecutiveFailures}):`, e.message || e);

            // First/second failure: keep showing the last good data, just
            // hint that the latest refresh missed. Third+ failure: replace
            // the empty placeholder with a clearer error, but only if we
            // never managed to load anything.
            if (lastFetchedRows.length) {
                setStaleBanner(true, `Couldn't refresh (${e.message || "error"}) — showing last good data`);
            } else {
                grid.innerHTML = `
                    <div class="table-empty-state">
                        <i data-lucide="alert-circle"></i>
                        <p>Failed to load IP analysis${e.message ? `: ${escapeHtml(e.message)}` : ""}</p>
                        <button class="btn btn-secondary btn-sm" onclick="refreshIpAnalysis()">
                            <i data-lucide="refresh-cw"></i><span>Retry</span>
                        </button>
                    </div>`;
                if (typeof lucide !== "undefined") lucide.createIcons();
            }
        } finally {
            clearTimeout(timeoutId);
            if (controller === inFlightController) {
                inFlightController = null;
                setAnalysisProgress(false);
            }
        }
    }

    function renderIpAnalysisRows(rows) {
        const grid = document.getElementById("ip-analysis-grid");
        if (!grid) return;

        if (!rows.length) {
            grid.innerHTML = `<div class="table-empty-state"><i data-lucide="search"></i><p>No attacker activity matches the current filter</p></div>`;
            if (typeof lucide !== "undefined") lucide.createIcons();
            return;
        }

        const totalPages = Math.max(1, Math.ceil(currentTotal / pageSize));
        const from = currentTotal ? ((currentPage - 1) * pageSize) + 1 : 0;
        const to = Math.min(currentPage * pageSize, currentTotal);

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
            const packets = Number(row.total_packets || 0);
            const alertText = row.alert_count > 0 ? `${row.alert_count} ${sevLabel}` : "None";

            return `
                <tr class="ip-analysis-row ${sevClass}" data-ip="${escapeHtml(row.ip || "")}" onclick="openIpModal('${escapeHtml(row.ip || "")}')">
                    <td>
                        <div class="ip-analysis-ip-cell">
                            <i data-lucide="globe-2"></i>
                            <code>${escapeHtml(row.ip || "—")}</code>
                            ${isPrivateIp(row.ip) ? '<span class="ip-card-tag">Private</span>' : ""}
                        </div>
                    </td>
                    <td class="ip-analysis-number">${packets.toLocaleString()}</td>
                    <td><div class="ip-card-protos">${protoBadges || "—"}</div></td>
                    <td class="ip-analysis-node-cell" title="${escapeHtml(nodeText)}">${escapeHtml(nodeText)}</td>
                    <td>
                        <div class="ip-analysis-alert-cell ${sevClass}">
                            <i data-lucide="${row.alert_count > 0 ? "shield-alert" : "shield-check"}"></i>
                            <span>${escapeHtml(alertText)}</span>
                        </div>
                    </td>
                    <td title="${escapeHtml(formatTime(row.first_seen))}">${escapeHtml(formatTime(row.first_seen))}</td>
                    <td title="${escapeHtml(formatTime(row.last_seen))}">
                        <span class="ip-analysis-last-seen">${escapeHtml(formatRelative(row.last_seen))}</span>
                    </td>
                </tr>`;
        }).join("");

        grid.innerHTML = `
            <div class="ip-analysis-results">
                <div class="ip-analysis-summarybar">
                    <div class="ip-analysis-summaryitem">
                        <strong>${currentTotal.toLocaleString()}</strong>
                        <span>Attacker IPs</span>
                    </div>
                    <div class="ip-analysis-summaryitem">
                        <strong>${from.toLocaleString()}-${to.toLocaleString()}</strong>
                        <span>Current page</span>
                    </div>
                    <div class="ip-analysis-summaryitem">
                        <strong>${currentPage.toLocaleString()} / ${totalPages.toLocaleString()}</strong>
                        <span>Pages</span>
                    </div>
                </div>
                <div class="ip-analysis-table-wrap">
                    <table class="ip-analysis-table">
                        <thead>
                            <tr>
                                <th>Attacker IP</th>
                                <th>Packets</th>
                                <th>Protocols</th>
                                <th>Agents</th>
                                <th>Alerts</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>${html}</tbody>
                    </table>
                </div>
                <div class="ip-analysis-pagination">
                    <button type="button" class="btn btn-secondary btn-sm" ${currentPage <= 1 ? "disabled" : ""} onclick="changeIpAnalysisPage(-1)">
                        <i data-lucide="chevron-left"></i><span>Previous</span>
                    </button>
                    <span class="ip-analysis-page-status">Showing ${from.toLocaleString()}-${to.toLocaleString()} of ${currentTotal.toLocaleString()}</span>
                    <button type="button" class="btn btn-secondary btn-sm" ${currentPage >= totalPages ? "disabled" : ""} onclick="changeIpAnalysisPage(1)">
                        <span>Next</span><i data-lucide="chevron-right"></i>
                    </button>
                </div>
            </div>
        `;
        if (typeof lucide !== "undefined") lucide.createIcons();
    }

    function changeIpAnalysisPage(delta) {
        const totalPages = Math.max(1, Math.ceil(currentTotal / pageSize));
        currentPage = Math.max(1, Math.min(totalPages, currentPage + delta));
        refreshIpAnalysis();
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
            renderModalPackets(logs, alerts);

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
        if (typeof lucide !== "undefined") lucide.createIcons({ root: container });
    }

    function toTimeMs(ts) {
        if (!ts) return NaN;
        const ms = Date.parse(ts);
        return Number.isNaN(ms) ? NaN : ms;
    }

    function getLogNetwork(meta) {
        const unifiedNetwork = meta?._unified_entry?.network || {};
        return {
            src_port: unifiedNetwork.src_port ?? meta.src_port,
            dst_port: unifiedNetwork.dst_port ?? meta.dst_port,
            src_ip: unifiedNetwork.src_ip ?? meta.src_ip,
            dst_ip: unifiedNetwork.dst_ip ?? meta.dst_ip,
        };
    }

    function buildPacketAlertMatches(logs, alerts) {
        const elastAlerts = (alerts || []).filter(a => (a.source || "").toLowerCase() === "elastalert");
        const matches = new Map();
        if (!elastAlerts.length) return matches;

        logs.forEach(log => {
            const logMeta = parseMaybeJson(log.metadata) || {};
            const logNetwork = getLogNetwork(logMeta);
            const logTime = toTimeMs(log.timestamp);
            const hitAlerts = elastAlerts.filter(alert => {
                if (alert.log_id && log.id && Number(alert.log_id) === Number(log.id)) return true;
                const alertMeta = parseMaybeJson(alert.metadata) || {};
                const alertTime = toTimeMs(alert.timestamp || alertMeta.timestamp);
                if (!Number.isNaN(logTime) && !Number.isNaN(alertTime) && Math.abs(logTime - alertTime) > 3000) {
                    return false;
                }
                if (alert.node_id && log.node_id && alert.node_id !== log.node_id) return false;
                if (alert.protocol && log.protocol && alert.protocol !== log.protocol) return false;

                const srcPort = alert.src_port || alertMeta.src_port;
                const dstPort = alert.dst_port || alertMeta.dst_port;
                if (srcPort && logNetwork.src_port && Number(srcPort) !== Number(logNetwork.src_port)) return false;
                if (dstPort && logNetwork.dst_port && Number(dstPort) !== Number(logNetwork.dst_port)) return false;

                return true;
            });
            if (hitAlerts.length) matches.set(log.id, hitAlerts);
        });
        return matches;
    }

    function renderPacketAlertMarkers(alerts) {
        if (!alerts?.length) return "";
        const maxSev = Math.min(...alerts.map(a => Number(a.severity) || 3));
        const sevClass = SEVERITY_CLASS[maxSev] || SEVERITY_CLASS[3];
        const sevLabel = SEVERITY_LABEL[maxSev] || "Low";
        return `
            <span class="packet-alert-tag packet-alert-source">
                <i data-lucide="bell-ring"></i> ElastAlert
            </span>
            <span class="packet-alert-tag ${sevClass}">${escapeHtml(sevLabel)}</span>
            ${alerts.length > 1 ? `<span class="packet-alert-tag">+${alerts.length - 1}</span>` : ""}`;
    }

    function renderPacketAlertDetails(alerts) {
        if (!alerts?.length) return "";
        const rows = alerts.map(alert => {
            const sev = Number(alert.severity) || 3;
            const sevClass = SEVERITY_CLASS[sev] || SEVERITY_CLASS[3];
            const sevLabel = SEVERITY_LABEL[sev] || "Low";
            return `
                <div class="packet-alert-detail ${sevClass}">
                    <span class="alert-sev-pill ${sevClass}">${escapeHtml(sevLabel)}</span>
                    <strong>${escapeHtml(alert.signature || "ElastAlert match")}</strong>
                    <span>${escapeHtml(formatTime(alert.timestamp))}</span>
                </div>`;
        }).join("");
        return `<div class="packet-alert-details">${rows}</div>`;
    }

    function renderModalPackets(logs, alerts = []) {
        const container = document.getElementById("ip-modal-packets");
        document.getElementById("ip-modal-packets-badge").textContent = logs.length;

        if (!logs.length) {
            container.innerHTML = `<div class="ip-modal-empty"><i data-lucide="inbox"></i><p>No packets recorded</p></div>`;
            if (typeof lucide !== "undefined") lucide.createIcons();
            return;
        }

        const alertMatches = buildPacketAlertMatches(logs, alerts);
        const html = logs.map(l => {
            const meta = parseMaybeJson(l.metadata) || {};
            const network = getLogNetwork(meta);
            const protoCls = PROTOCOL_CLASS[(l.protocol || "").toLowerCase()] || "proto-default";
            const summary = meta["log.message"] || meta["log_message"] || meta["mqtt_packet_type_name"] || meta["http_method"] || meta["modbus_function_name"] || "";
            const req = l.request_data || "";
            const resp = l.response_data || "";
            const matchedAlerts = alertMatches.get(l.id) || [];
            const maxSev = matchedAlerts.length ? Math.min(...matchedAlerts.map(a => Number(a.severity) || 3)) : 0;
            const matchClass = matchedAlerts.length ? `packet-elastalert-match ${SEVERITY_CLASS[maxSev] || "sev-low"}` : "";

            return `
                <details class="packet-row ${matchClass}">
                    <summary>
                        <span class="proto-badge ${protoCls}">${escapeHtml((l.protocol || "?").toUpperCase())}</span>
                        <span class="packet-time">${escapeHtml(formatTime(l.timestamp))}</span>
                        <span class="packet-summary">${escapeHtml(summary || "packet")}</span>
                        ${renderPacketAlertMarkers(matchedAlerts)}
                        <span class="packet-port">${escapeHtml((network.src_port ?? "") + "→" + (network.dst_port ?? ""))}</span>
                    </summary>
                    <div class="packet-body">
                        ${renderPacketAlertDetails(matchedAlerts)}
                        <div class="packet-kv"><span>Node</span><code>${escapeHtml(l.node_id || "—")}</code></div>
                        <div class="packet-kv"><span>Request</span>${formatPacketData(req, l.protocol)}</div>
                        <div class="packet-kv"><span>Response</span>${formatPacketData(resp, l.protocol)}</div>
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
            let searchTimer = null;
            search.addEventListener("input", () => {
                clearTimeout(searchTimer);
                searchTimer = setTimeout(() => {
                    currentPage = 1;
                    refreshIpAnalysis();
                }, 300);
            });
        }
        const windowSel = document.getElementById("ip-analysis-window");
        if (windowSel) {
            windowSel.addEventListener("change", () => {
                updateCustomVisibility();
                currentPage = 1;
                refreshIpAnalysis();
            });
            updateCustomVisibility();
        }
        const agentFilter = document.getElementById("ip-analysis-agent-filter");
        if (agentFilter) {
            agentFilter.addEventListener("change", () => {
                currentPage = 1;
                refreshIpAnalysis();
            });
        }
        const privateFilter = document.getElementById("ip-analysis-private-filter");
        if (privateFilter) {
            privateFilter.addEventListener("change", () => {
                currentPage = 1;
                refreshIpAnalysis();
            });
        }

        // Custom range — debounce so dragging the picker doesn't spam the API
        let customRefreshTimer = null;
        const scheduleCustomRefresh = () => {
            clearTimeout(customRefreshTimer);
            customRefreshTimer = setTimeout(() => {
                currentPage = 1;
                refreshIpAnalysis();
            }, 350);
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
                currentPage = 1;
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
    window.changeIpAnalysisPage = changeIpAnalysisPage;
    window.openIpModal = openIpModal;
    window.closeIpModal = closeIpModal;
    window.switchIpTab = switchIpTab;
})();
