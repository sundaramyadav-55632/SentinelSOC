const API_BASE = "http://127.0.0.1:8000";

let incidents = [];
let statistics = {};
let summary = {};
let events = [];
let alerts = [];

document.addEventListener("DOMContentLoaded", () => {
    buildDashboard();
    loadDashboard();
});


/* =========================================================
   MAIN DASHBOARD UI
   ========================================================= */

function buildDashboard() {

    document.body.innerHTML = `
        <div class="soc-app">

            <aside class="sidebar">

                <div class="brand">
                    <div class="brand-icon">S</div>

                    <div>
                        <h2>SentinelSOC</h2>
                        <span>Security Operations Center</span>
                    </div>
                </div>

                <nav class="navigation">

                    <button class="nav-item active" data-section="dashboard">
                        <span>▦</span>
                        Dashboard
                    </button>

                    <button class="nav-item" data-section="incidents">
                        <span>△</span>
                        Incidents
                    </button>

                    <button class="nav-item" data-section="events">
                        <span>○</span>
                        Events
                    </button>

                    <button class="nav-item" data-section="alerts">
                        <span>!</span>
                        Alerts
                    </button>

                </nav>

                <div class="api-status-card">

                    <div class="status-indicator" id="apiIndicator"></div>

                    <div>
                        <strong>API Status</strong>
                        <span id="apiStatus">Checking...</span>
                    </div>

                </div>

                <div class="sidebar-version">
                    SentinelSOC v1.0.0
                </div>

            </aside>


            <main class="main-content">

                <header class="topbar">

                    <div>
                        <h1>Security Operations Dashboard</h1>

                        <p>
                            Real-time security monitoring,
                            detection and incident management
                        </p>
                    </div>

                    <div class="topbar-actions">

                        <div class="last-updated">
                            Last updated
                            <strong id="lastUpdated">--</strong>
                        </div>

                        <button
                            class="refresh-button"
                            onclick="loadDashboard()"
                        >
                            ↻ Refresh
                        </button>

                    </div>

                </header>


                <section id="dashboardSection">

                    <div class="stats-grid">

                        <div class="stat-card">
                            <div class="stat-icon blue">◉</div>

                            <div>
                                <span>Total Events</span>
                                <strong id="totalEvents">0</strong>
                            </div>
                        </div>


                        <div class="stat-card">
                            <div class="stat-icon orange">!</div>

                            <div>
                                <span>Total Alerts</span>
                                <strong id="totalAlerts">0</strong>
                            </div>
                        </div>


                        <div class="stat-card">
                            <div class="stat-icon red">△</div>

                            <div>
                                <span>Total Incidents</span>
                                <strong id="totalIncidents">0</strong>
                            </div>
                        </div>


                        <div class="stat-card">
                            <div class="stat-icon green">◌</div>

                            <div>
                                <span>Open Incidents</span>
                                <strong id="openIncidents">0</strong>
                            </div>
                        </div>

                    </div>


                    <div class="content-grid">

                        <section class="panel">

                            <div class="panel-header">

                                <div>
                                    <h2>Incident Severity</h2>
                                    <p>Current incident distribution</p>
                                </div>

                            </div>

                            <div id="severityChart"></div>

                        </section>


                        <section class="panel">

                            <div class="panel-header">

                                <div>
                                    <h2>Attack Types</h2>
                                    <p>Detected incident categories</p>
                                </div>

                            </div>

                            <div id="attackTypes"></div>

                        </section>

                    </div>


                    <section class="panel">

                        <div class="panel-header">

                            <div>
                                <h2>Recent Incidents</h2>
                                <p>Latest security incidents detected</p>
                            </div>

                            <button
                                class="small-button"
                                onclick="showSection('incidents')"
                            >
                                View All
                            </button>

                        </div>

                        <div id="recentIncidents"></div>

                    </section>

                </section>


                <section
                    id="incidentsSection"
                    class="hidden-section"
                >

                    <div class="section-title">

                        <div>
                            <h2>Security Incidents</h2>
                            <p>Investigate and manage detected incidents</p>
                        </div>

                    </div>

                    <div id="allIncidents"></div>

                </section>


                <section
                    id="eventsSection"
                    class="hidden-section"
                >

                    <div class="section-title">

                        <div>
                            <h2>Security Events</h2>
                            <p>Normalized security telemetry</p>
                        </div>

                    </div>

                    <div class="table-wrapper">

                        <table>

                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Timestamp</th>
                                    <th>Source</th>
                                    <th>Event Type</th>
                                    <th>Severity</th>
                                    <th>Source IP</th>
                                    <th>Destination</th>
                                </tr>
                            </thead>

                            <tbody id="eventsTable"></tbody>

                        </table>

                    </div>

                </section>


                <section
                    id="alertsSection"
                    class="hidden-section"
                >

                    <div class="section-title">

                        <div>
                            <h2>Detection Alerts</h2>
                            <p>Alerts generated by detection engines</p>
                        </div>

                    </div>

                    <div id="alertsContainer"></div>

                </section>

            </main>

        </div>


        <div
            id="incidentModal"
            class="modal hidden"
        >

            <div class="modal-content">

                <div class="modal-header">

                    <div>
                        <span class="modal-label">
                            SECURITY INCIDENT
                        </span>

                        <h2 id="modalTitle">
                            Incident
                        </h2>
                    </div>

                    <button
                        class="close-button"
                        onclick="closeIncidentModal()"
                    >
                        ×
                    </button>

                </div>

                <div id="incidentDetails"></div>

            </div>

        </div>
    `;


    addDashboardStyles();


    document.querySelectorAll(".nav-item").forEach(button => {

        button.addEventListener("click", () => {

            const section = button.dataset.section;

            showSection(section);

        });

    });
}


/* =========================================================
   LOAD ALL DATA
   ========================================================= */

async function loadDashboard() {

    setApiStatus("checking");

    try {

        const results = await Promise.all([

            fetchJSON("/api/health"),

            fetchJSON("/api/statistics"),

            fetchJSON("/api/incidents"),

            fetchJSON("/api/events?limit=50"),

            fetchJSON("/api/alerts?limit=50"),

            fetchJSON("/api/summary")

        ]);


        const health = results[0];

        statistics = results[1] || {};

        incidents = results[2]?.incidents || [];

        events = results[3]?.events || [];

        alerts = results[4]?.alerts || [];

        summary = results[5] || {};


        if (
            health &&
            (
                health.status === "healthy" ||
                health.status === "online"
            )
        ) {

            setApiStatus("online");

        } else {

            setApiStatus("offline");

        }


        renderStatistics();

        renderSeverity();

        renderAttackTypes();

        renderRecentIncidents();

        renderAllIncidents();

        renderEvents();

        renderAlerts();


        document.getElementById(
            "lastUpdated"
        ).textContent = new Date().toLocaleTimeString();


    } catch (error) {

        console.error(
            "Dashboard API error:",
            error
        );

        setApiStatus("offline");

    }

}


/* =========================================================
   API
   ========================================================= */

async function fetchJSON(endpoint) {

    const response = await fetch(
        API_BASE + endpoint
    );

    if (!response.ok) {

        throw new Error(
            `API request failed: ${response.status}`
        );

    }

    return await response.json();

}


/* =========================================================
   API STATUS
   ========================================================= */

function setApiStatus(status) {

    const indicator =
        document.getElementById("apiIndicator");

    const text =
        document.getElementById("apiStatus");

    if (!indicator || !text) {
        return;
    }


    if (status === "online") {

        indicator.className =
            "status-indicator online";

        text.textContent =
            "Online";

    } else if (status === "checking") {

        indicator.className =
            "status-indicator checking";

        text.textContent =
            "Checking...";

    } else {

        indicator.className =
            "status-indicator offline";

        text.textContent =
            "Offline";

    }

}


/* =========================================================
   STATISTICS
   ========================================================= */

function renderStatistics() {

    document.getElementById(
        "totalEvents"
    ).textContent =
        statistics.total_events ?? events.length;


    document.getElementById(
        "totalAlerts"
    ).textContent =
        statistics.total_alerts ?? alerts.length;


    document.getElementById(
        "totalIncidents"
    ).textContent =
        statistics.total_incidents ??
        incidents.length;


    document.getElementById(
        "openIncidents"
    ).textContent =
        statistics.open_incidents ??
        incidents.filter(
            incident =>
                (incident.status || "open") === "open"
        ).length;

}


/* =========================================================
   SEVERITY
   ========================================================= */

function renderSeverity() {

    const severity =
        statistics.severity || {};


    const values = {

        critical:
            severity.critical ?? 0,

        high:
            severity.high ?? 0,

        medium:
            severity.medium ?? 0,

        low:
            severity.low ?? 0

    };


    const total =
        Object.values(values)
            .reduce(
                (sum, value) =>
                    sum + value,
                0
            );


    const container =
        document.getElementById(
            "severityChart"
        );


    container.innerHTML = Object.entries(
        values
    ).map(
        ([name, count]) => {

            const percentage =
                total > 0
                    ? (count / total) * 100
                    : 0;


            return `

                <div class="severity-row">

                    <div class="severity-info">

                        <span class="severity-dot ${name}">
                        </span>

                        <span>
                            ${capitalize(name)}
                        </span>

                        <strong>
                            ${count}
                        </strong>

                    </div>

                    <div class="severity-bar">

                        <div
                            class="severity-fill ${name}"
                            style="width:${percentage}%"
                        ></div>

                    </div>

                </div>

            `;

        }
    ).join("");

}


/* =========================================================
   ATTACK TYPES
   ========================================================= */

function renderAttackTypes() {

    const container =
        document.getElementById(
            "attackTypes"
        );


    let attackTypes =
        summary.incident_types || {};


    if (
        Object.keys(attackTypes).length === 0 &&
        incidents.length > 0
    ) {

        attackTypes = {};

        incidents.forEach(
            incident => {

                const type =
                    incident.incident_type ||
                    "unknown";

                attackTypes[type] =
                    (
                        attackTypes[type] || 0
                    ) + 1;

            }
        );

    }


    if (
        Object.keys(attackTypes).length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">
                No attack categories detected.
            </div>
        `;

        return;

    }


    container.innerHTML =
        Object.entries(
            attackTypes
        ).map(
            ([type, count]) => `

                <div class="attack-row">

                    <div>

                        <span class="attack-icon">
                            ${getAttackIcon(type)}
                        </span>

                        <strong>
                            ${formatIncidentType(type)}
                        </strong>

                    </div>

                    <span class="attack-count">
                        ${count}
                    </span>

                </div>

            `
        ).join("");

}


/* =========================================================
   RECENT INCIDENTS
   ========================================================= */

function renderRecentIncidents() {

    const container =
        document.getElementById(
            "recentIncidents"
        );


    const recent =
        [...incidents]
            .sort(
                (a, b) =>
                    (
                        Number(
                            b.incident_id ||
                            b.id ||
                            0
                        )
                    ) -
                    (
                        Number(
                            a.incident_id ||
                            a.id ||
                            0
                        )
                    )
            )
            .slice(0, 5);


    if (recent.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                No incidents detected.
            </div>
        `;

        return;

    }


    container.innerHTML =
        recent.map(
            incident =>
                createIncidentCard(
                    incident
                )
        ).join("");

}


/* =========================================================
   ALL INCIDENTS
   ========================================================= */

function renderAllIncidents() {

    const container =
        document.getElementById(
            "allIncidents"
        );


    if (incidents.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                No security incidents found.
            </div>
        `;

        return;

    }


    container.innerHTML =
        [...incidents]
            .sort(
                (a, b) =>
                    Number(
                        b.incident_id ||
                        b.id ||
                        0
                    ) -
                    Number(
                        a.incident_id ||
                        a.id ||
                        0
                    )
            )
            .map(
                incident =>
                    createIncidentCard(
                        incident
                    )
            )
            .join("");

}


/* =========================================================
   INCIDENT CARD
   ========================================================= */

function createIncidentCard(
    incident
) {

    const id =
        incident.incident_id ||
        incident.id ||
        "N/A";


    const type =
        incident.incident_type ||
        incident.alert_type ||
        "unknown";


    const severity =
        (
            incident.severity ||
            "low"
        ).toLowerCase();


    const status =
        (
            incident.status ||
            "open"
        ).toLowerCase();


    const risk =
        incident.risk_score ??
        0;


    const confidence =
        incident.confidence ??
        0;


    const sourceIP =
        incident.source_ip ||
        "N/A";


    const mitre =
        incident.mitre ||
        {};


    return `

        <article
            class="incident-card"
            onclick='openIncident(${JSON.stringify(
                incident
            ).replace(/'/g, "&#39;")})'
        >

            <div class="incident-card-top">

                <div>

                    <span class="incident-id">
                        #${id}
                    </span>

                    <h3>
                        ${formatIncidentType(type)}
                    </h3>

                </div>

                <div class="incident-badges">

                    <span
                        class="severity-badge ${severity}"
                    >
                        ${severity.toUpperCase()}
                    </span>

                    <span
                        class="status-badge ${status}"
                    >
                        ${formatStatus(status)}
                    </span>

                </div>

            </div>


            <div class="incident-card-middle">

                <div>
                    <span>Source IP</span>
                    <strong>${sourceIP}</strong>
                </div>

                <div>
                    <span>Risk</span>
                    <strong>${risk}/100</strong>
                </div>

                <div>
                    <span>Confidence</span>
                    <strong>${confidence}%</strong>
                </div>

                <div>
                    <span>MITRE</span>
                    <strong>
                        ${mitre.technique_id || "—"}
                    </strong>
                </div>

            </div>


            <div class="incident-card-bottom">

                <span>
                    ${
                        incident.description ||
                        "Security incident detected."
                    }
                </span>

                <button
                    class="investigate-button"
                    onclick="event.stopPropagation(); openIncidentById(${id})"
                >
                    Investigate →
                </button>

            </div>

        </article>

    `;

}


/* =========================================================
   OPEN INCIDENT
   ========================================================= */

async function openIncidentById(
    incidentId
) {

    const localIncident =
        incidents.find(
            incident =>
                Number(
                    incident.incident_id ||
                    incident.id
                ) === Number(incidentId)
        );


    if (localIncident) {

        openIncident(
            localIncident
        );

        return;

    }


    try {

        const incident =
            await fetchJSON(
                `/api/incidents/${incidentId}`
            );

        openIncident(
            incident
        );

    } catch (error) {

        console.error(error);

    }

}


/* =========================================================
   INCIDENT MODAL
   ========================================================= */

function openIncident(
    incident
) {

    const modal =
        document.getElementById(
            "incidentModal"
        );


    const id =
        incident.incident_id ||
        incident.id ||
        "N/A";


    const type =
        incident.incident_type ||
        incident.alert_type ||
        "unknown";


    const severity =
        (
            incident.severity ||
            "low"
        ).toLowerCase();


    const status =
        (
            incident.status ||
            "open"
        ).toLowerCase();


    const mitre =
        incident.mitre ||
        {};


    const evidence =
        incident.evidence ||
        [];


    const reasons =
        incident.reasons ||
        [];


    let response =
        incident.recommended_response ||
        [];


    if (
        response &&
        !Array.isArray(response)
    ) {

        response =
            response.recommended_actions ||
            [];

    }


    document.getElementById(
        "modalTitle"
    ).textContent =
        `Incident #${id} — ${formatIncidentType(type)}`;


    document.getElementById(
        "incidentDetails"
    ).innerHTML = `

        <div class="detail-grid">

            <div class="detail-box">
                <span>Incident Type</span>
                <strong>
                    ${formatIncidentType(type)}
                </strong>
            </div>

            <div class="detail-box">
                <span>Risk Score</span>
                <strong>
                    ${incident.risk_score ?? 0}/100
                </strong>
            </div>

            <div class="detail-box">
                <span>Severity</span>
                <strong class="text-${severity}">
                    ${severity.toUpperCase()}
                </strong>
            </div>

            <div class="detail-box">
                <span>Confidence</span>
                <strong>
                    ${incident.confidence ?? 0}%
                </strong>
            </div>

            <div class="detail-box">
                <span>Source IP</span>
                <strong>
                    ${incident.source_ip || "N/A"}
                </strong>
            </div>

            <div class="detail-box">
                <span>Username</span>
                <strong>
                    ${incident.username || "N/A"}
                </strong>
            </div>

            <div class="detail-box">
                <span>Failed Attempts</span>
                <strong>
                    ${incident.failed_attempts ?? 0}
                </strong>
            </div>

            <div class="detail-box">
                <span>Unique Ports</span>
                <strong>
                    ${incident.unique_ports ?? 0}
                </strong>
            </div>

        </div>


        <section class="detail-section">

            <h3>Incident Status</h3>

            <div class="status-control">

                <select
                    id="incidentStatusSelect"
                    onchange="updateIncidentStatus(${id}, this.value)"
                >

                    ${statusOption("open", status)}

                    ${statusOption(
                        "investigating",
                        status
                    )}

                    ${statusOption(
                        "contained",
                        status
                    )}

                    ${statusOption(
                        "resolved",
                        status
                    )}

                    ${statusOption(
                        "false_positive",
                        status
                    )}

                </select>

                <span>
                    Current:
                    <strong>
                        ${formatStatus(status)}
                    </strong>
                </span>

            </div>

        </section>


        <section class="detail-section mitre-section">

            <h3>MITRE ATT&CK</h3>

            ${
                mitre.technique_id
                    ? `
                        <div class="mitre-card">

                            <div class="mitre-id">
                                ${mitre.technique_id}
                            </div>

                            <div>

                                <strong>
                                    ${mitre.technique_name || "Unknown"}
                                </strong>

                                <span>
                                    Tactic:
                                    ${mitre.tactic || "Unknown"}
                                </span>

                            </div>

                        </div>
                    `
                    : `
                        <div class="empty-state">
                            No MITRE ATT&CK mapping available.
                        </div>
                    `
            }

        </section>


        <section class="detail-section">

            <h3>Description</h3>

            <p class="description">
                ${
                    incident.description ||
                    "No description available."
                }
            </p>

        </section>


        <section class="detail-section">

            <h3>Detection Reasons</h3>

            ${
                reasons.length
                    ? `
                        <ul class="evidence-list">

                            ${reasons.map(
                                reason =>
                                    `<li>${reason}</li>`
                            ).join("")}

                        </ul>
                    `
                    : `
                        <div class="empty-state">
                            No detection reasons recorded.
                        </div>
                    `
            }

        </section>


        <section class="detail-section">

            <h3>Evidence</h3>

            ${
                evidence.length
                    ? `
                        <ul class="evidence-list">

                            ${evidence.map(
                                item =>
                                    `<li>${item}</li>`
                            ).join("")}

                        </ul>
                    `
                    : `
                        <div class="empty-state">
                            No evidence recorded.
                        </div>
                    `
            }

        </section>


        <section class="detail-section response-section">

            <h3>Recommended Response</h3>

            ${
                response.length
                    ? `
                        <ol class="response-list">

                            ${response.map(
                                action =>
                                    `<li>${action}</li>`
                            ).join("")}

                        </ol>
                    `
                    : `
                        <div class="empty-state">
                            No response recommendations available.
                        </div>
                    `
            }

        </section>

    `;


    modal.classList.remove(
        "hidden"
    );

}


function statusOption(
    value,
    current
) {

    return `
        <option
            value="${value}"
            ${value === current ? "selected" : ""}
        >
            ${formatStatus(value)}
        </option>
    `;

}


/* =========================================================
   UPDATE INCIDENT STATUS
   ========================================================= */

async function updateIncidentStatus(
    incidentId,
    status
) {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/incidents/${incidentId}/status`,
                {
                    method: "PATCH",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        status: status
                    })
                }
            );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                errorText ||
                `HTTP ${response.status}`
            );

        }


        const incident =
            incidents.find(
                item =>
                    Number(
                        item.incident_id ||
                        item.id
                    ) === Number(incidentId)
            );


        if (incident) {

            incident.status =
                status;

        }


        renderStatistics();

        renderRecentIncidents();

        renderAllIncidents();


        const select =
            document.getElementById(
                "incidentStatusSelect"
            );


        if (select) {

            select.value =
                status;

        }


        alert(
            `Incident #${incidentId} status updated to ${formatStatus(status)}`
        );


    } catch (error) {

        console.error(
            "Status update failed:",
            error
        );


        alert(
            "Failed to update incident status. Check the API server."
        );

    }

}


/* =========================================================
   EVENTS
   ========================================================= */

function renderEvents() {

    const table =
        document.getElementById(
            "eventsTable"
        );


    if (events.length === 0) {

        table.innerHTML = `
            <tr>
                <td colspan="7">
                    No events found.
                </td>
            </tr>
        `;

        return;

    }


    table.innerHTML =
        events.map(
            event => `

                <tr>

                    <td>
                        ${event.id ?? "—"}
                    </td>

                    <td>
                        ${event.timestamp || "—"}
                    </td>

                    <td>
                        ${event.source || "—"}
                    </td>

                    <td>
                        ${event.event_type || "—"}
                    </td>

                    <td>
                        <span class="severity-badge ${
                            (
                                event.severity ||
                                "low"
                            ).toLowerCase()
                        }">
                            ${(
                                event.severity ||
                                "low"
                            ).toUpperCase()}
                        </span>
                    </td>

                    <td>
                        ${event.source_ip || "—"}
                    </td>

                    <td>
                        ${
                            event.destination_ip
                                ? `${event.destination_ip}:${event.destination_port || ""}`
                                : "—"
                        }
                    </td>

                </tr>

            `
        ).join("");

}


/* =========================================================
   ALERTS
   ========================================================= */

function renderAlerts() {

    const container =
        document.getElementById(
            "alertsContainer"
        );


    if (alerts.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                No detection alerts found.
            </div>
        `;

        return;

    }


    container.innerHTML =
        alerts.map(
            alert => `

                <div class="alert-card">

                    <div class="alert-header">

                        <strong>
                            ${
                                formatIncidentType(
                                    alert.incident_type ||
                                    alert.alert_type ||
                                    alert.event_type ||
                                    "Security Alert"
                                )
                            }
                        </strong>

                        <span class="severity-badge ${
                            (
                                alert.severity ||
                                "low"
                            ).toLowerCase()
                        }">
                            ${(
                                alert.severity ||
                                "low"
                            ).toUpperCase()}
                        </span>

                    </div>

                    <div class="alert-details">

                        <span>
                            Source:
                            ${alert.source_ip || "N/A"}
                        </span>

                        <span>
                            User:
                            ${alert.username || "N/A"}
                        </span>

                    </div>

                    <p>
                        ${
                            alert.message ||
                            alert.description ||
                            "Detection alert generated."
                        }
                    </p>

                </div>

            `
        ).join("");

}


/* =========================================================
   NAVIGATION
   ========================================================= */

function showSection(
    section
) {

    const sections = {

        dashboard:
            document.getElementById(
                "dashboardSection"
            ),

        incidents:
            document.getElementById(
                "incidentsSection"
            ),

        events:
            document.getElementById(
                "eventsSection"
            ),

        alerts:
            document.getElementById(
                "alertsSection"
            )

    };


    Object.values(
        sections
    ).forEach(
        element => {

            if (element) {

                element.classList.add(
                    "hidden-section"
                );

            }

        }
    );


    if (sections[section]) {

        sections[section].classList.remove(
            "hidden-section"
        );

    }


    document.querySelectorAll(
        ".nav-item"
    ).forEach(
        button => {

            button.classList.toggle(
                "active",
                button.dataset.section === section
            );

        }
    );

}


/* =========================================================
   MODAL
   ========================================================= */

function closeIncidentModal() {

    const modal =
        document.getElementById(
            "incidentModal"
        );

    modal.classList.add(
        "hidden"
    );

}


document.addEventListener(
    "click",
    event => {

        const modal =
            document.getElementById(
                "incidentModal"
            );

        if (
            event.target === modal
        ) {

            closeIncidentModal();

        }

    }
);


/* =========================================================
   HELPERS
   ========================================================= */

function formatIncidentType(
    value
) {

    return String(
        value || "Unknown"
    )
        .replaceAll(
            "_",
            " "
        )
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );

}


function formatStatus(
    value
) {

    return String(
        value || "open"
    )
        .replaceAll(
            "_",
            " "
        )
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );

}


function capitalize(
    value
) {

    return (
        value.charAt(0).toUpperCase() +
        value.slice(1)
    );

}


function getAttackIcon(
    type
) {

    const icons = {

        brute_force: "🔐",

        password_spray: "🎯",

        port_scan: "🔎",

        connection_burst: "⚡",

        suspicious_activity: "⚠️"

    };

    return icons[type] || "🛡️";

}


/* =========================================================
   DASHBOARD STYLES
   ========================================================= */

function addDashboardStyles() {

    const style =
        document.createElement(
            "style"
        );


    style.textContent = `

        * {
            box-sizing: border-box;
        }


        body {
            margin: 0;
            font-family:
                Inter,
                Segoe UI,
                Arial,
                sans-serif;

            background: #07111f;
            color: #e7eef8;
        }


        button,
        select {
            font-family: inherit;
        }


        .soc-app {
            min-height: 100vh;
            display: flex;
        }


        .sidebar {
            width: 290px;
            min-height: 100vh;
            background: #06101d;
            border-right: 1px solid #1d3047;
            padding: 28px 16px;
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            display: flex;
            flex-direction: column;
        }


        .brand {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 10px 13px 30px;
        }


        .brand-icon {
            width: 52px;
            height: 52px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #0c2b45;
            border: 1px solid #17537d;
            color: #35b8ff;
            font-size: 29px;
            font-weight: 800;
        }


        .brand h2 {
            margin: 0 0 5px;
            font-size: 21px;
        }


        .brand span {
            color: #71849a;
            font-size: 12px;
        }


        .navigation {
            display: flex;
            flex-direction: column;
            gap: 7px;
        }


        .nav-item {
            border: 0;
            background: transparent;
            color: #8da0b7;
            padding: 15px 17px;
            border-radius: 11px;
            text-align: left;
            font-size: 16px;
            cursor: pointer;
            display: flex;
            gap: 15px;
            align-items: center;
        }


        .nav-item:hover {
            background: #0c1d31;
            color: #dbe9f7;
        }


        .nav-item.active {
            background: #102841;
            color: white;
            border-left: 3px solid #28b7ff;
        }


        .nav-item span {
            width: 18px;
            text-align: center;
        }


        .api-status-card {
            margin-top: auto;
            border: 1px solid #203851;
            background: #0b1929;
            border-radius: 11px;
            padding: 16px;
            display: flex;
            gap: 12px;
            align-items: center;
        }


        .api-status-card strong,
        .api-status-card span {
            display: block;
        }


        .api-status-card strong {
            font-size: 14px;
        }


        .api-status-card span {
            color: #7d91a7;
            font-size: 12px;
            margin-top: 5px;
        }


        .status-indicator {
            width: 11px;
            height: 11px;
            border-radius: 50%;
        }


        .status-indicator.online {
            background: #36d399;
            box-shadow: 0 0 14px #36d399;
        }


        .status-indicator.offline {
            background: #ff526d;
        }


        .status-indicator.checking {
            background: #f5b942;
        }


        .sidebar-version {
            color: #536980;
            font-size: 11px;
            padding: 22px 5px 0;
        }


        .main-content {
            margin-left: 290px;
            width: calc(100% - 290px);
            padding: 42px;
            max-width: 1600px;
        }


        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 32px;
        }


        .topbar h1 {
            margin: 0;
            font-size: 34px;
            letter-spacing: -0.8px;
        }


        .topbar p {
            color: #778ba3;
            margin: 9px 0 0;
            font-size: 14px;
        }


        .topbar-actions {
            display: flex;
            align-items: center;
            gap: 22px;
        }


        .last-updated {
            color: #72869d;
            font-size: 12px;
        }


        .last-updated strong {
            display: block;
            color: #d8e5f2;
            margin-top: 4px;
        }


        .refresh-button,
        .small-button {
            border: 1px solid #24628c;
            background: #0d2941;
            color: #8ed9ff;
            border-radius: 9px;
            padding: 11px 17px;
            cursor: pointer;
        }


        .refresh-button:hover,
        .small-button:hover {
            background: #123853;
        }


        .stats-grid {
            display: grid;
            grid-template-columns:
                repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }


        .stat-card {
            background: #0c1929;
            border: 1px solid #1d334b;
            border-radius: 13px;
            padding: 26px;
            display: flex;
            align-items: center;
            gap: 17px;
        }


        .stat-icon {
            width: 54px;
            height: 54px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 23px;
        }


        .stat-icon.blue {
            background: #0d304b;
            color: #38b8ff;
        }


        .stat-icon.orange {
            background: #3b2b0c;
            color: #ffbd43;
        }


        .stat-icon.red {
            background: #3c1722;
            color: #ff536e;
        }


        .stat-icon.green {
            background: #10362b;
            color: #45dca8;
        }


        .stat-card span {
            display: block;
            color: #788ba0;
            font-size: 12px;
            margin-bottom: 7px;
        }


        .stat-card strong {
            font-size: 30px;
        }


        .content-grid {
            display: grid;
            grid-template-columns:
                repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }


        .panel {
            background: #0c1929;
            border: 1px solid #1d334b;
            border-radius: 13px;
            padding: 25px;
            margin-bottom: 20px;
        }


        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }


        .panel-header h2 {
            margin: 0;
            font-size: 18px;
        }


        .panel-header p {
            color: #70859d;
            font-size: 12px;
            margin: 7px 0 0;
        }


        .severity-row {
            margin-bottom: 18px;
        }


        .severity-info {
            display: grid;
            grid-template-columns:
                12px 1fr 30px;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
            font-size: 13px;
        }


        .severity-info strong {
            text-align: right;
        }


        .severity-dot {
            width: 9px;
            height: 9px;
            border-radius: 50%;
        }


        .severity-dot.critical {
            background: #ff4563;
        }


        .severity-dot.high {
            background: #ff8c42;
        }


        .severity-dot.medium {
            background: #ffc247;
        }


        .severity-dot.low {
            background: #42d5a0;
        }


        .severity-bar {
            height: 8px;
            background: #15263a;
            border-radius: 8px;
            overflow: hidden;
        }


        .severity-fill {
            height: 100%;
            border-radius: 8px;
        }


        .severity-fill.critical {
            background: #ff4563;
        }


        .severity-fill.high {
            background: #ff8c42;
        }


        .severity-fill.medium {
            background: #ffc247;
        }


        .severity-fill.low {
            background: #42d5a0;
        }


        .attack-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 13px 0;
            border-bottom: 1px solid #182b40;
        }


        .attack-row:last-child {
            border-bottom: 0;
        }


        .attack-row > div {
            display: flex;
            align-items: center;
            gap: 11px;
        }


        .attack-icon {
            width: 31px;
            text-align: center;
        }


        .attack-count {
            font-weight: 700;
            color: #9cc9e6;
        }


        .incident-card {
            background: #0b1828;
            border: 1px solid #1b344c;
            border-radius: 11px;
            padding: 20px;
            margin-bottom: 13px;
            cursor: pointer;
            transition:
                border-color 0.15s,
                transform 0.15s;
        }


        .incident-card:hover {
            border-color: #2d6b95;
            transform: translateY(-1px);
        }


        .incident-card-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }


        .incident-id {
            color: #617991;
            font-size: 11px;
        }


        .incident-card h3 {
            margin: 5px 0 0;
            font-size: 18px;
        }


        .incident-badges {
            display: flex;
            gap: 7px;
        }


        .severity-badge,
        .status-badge {
            display: inline-block;
            border-radius: 6px;
            padding: 5px 8px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.4px;
        }


        .severity-badge.critical {
            background: #481827;
            color: #ff5571;
        }


        .severity-badge.high {
            background: #482817;
            color: #ff984d;
        }


        .severity-badge.medium {
            background: #493a16;
            color: #ffc94d;
        }


        .severity-badge.low {
            background: #12372b;
            color: #4bd8a4;
        }


        .status-badge.open {
            background: #162d43;
            color: #74c8f3;
        }


        .status-badge.investigating {
            background: #312d15;
            color: #f4ca55;
        }


        .status-badge.contained {
            background: #2f1e36;
            color: #d68aff;
        }


        .status-badge.resolved {
            background: #12372b;
            color: #4bd8a4;
        }


        .status-badge.false_positive {
            background: #26303a;
            color: #9caab8;
        }


        .incident-card-middle {
            display: grid;
            grid-template-columns:
                repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
            padding: 16px 0;
            border-top: 1px solid #182b40;
            border-bottom: 1px solid #182b40;
        }


        .incident-card-middle span {
            display: block;
            color: #647b92;
            font-size: 10px;
            margin-bottom: 6px;
            text-transform: uppercase;
        }


        .incident-card-middle strong {
            font-size: 13px;
        }


        .incident-card-bottom {
            display: flex;
            justify-content: space-between;
            gap: 15px;
            align-items: center;
            color: #8497aa;
            font-size: 12px;
        }


        .investigate-button {
            border: 0;
            background: transparent;
            color: #50bfff;
            cursor: pointer;
            white-space: nowrap;
        }


        .section-title {
            margin-bottom: 25px;
        }


        .section-title h2 {
            margin: 0;
            font-size: 26px;
        }


        .section-title p {
            color: #7489a0;
            font-size: 13px;
        }


        .hidden-section {
            display: none !important;
        }


        .empty-state {
            padding: 30px;
            text-align: center;
            color: #657b92;
            border: 1px dashed #243b53;
            border-radius: 9px;
        }


        .table-wrapper {
            background: #0c1929;
            border: 1px solid #1d334b;
            border-radius: 13px;
            overflow: auto;
        }


        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 850px;
        }


        th,
        td {
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid #172b40;
            font-size: 12px;
        }


        th {
            color: #70869e;
            background: #0a1625;
            text-transform: uppercase;
            font-size: 10px;
        }


        td {
            color: #bdcddd;
        }


        .alert-card {
            background: #0c1929;
            border: 1px solid #1d334b;
            border-radius: 11px;
            padding: 18px;
            margin-bottom: 12px;
        }


        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }


        .alert-details {
            display: flex;
            gap: 25px;
            margin-top: 11px;
            color: #73879e;
            font-size: 11px;
        }


        .alert-card p {
            color: #a9b9c9;
            font-size: 12px;
            line-height: 1.5;
        }


        .modal {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.72);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 30px;
            z-index: 1000;
        }


        .modal.hidden {
            display: none;
        }


        .modal-content {
            width: min(900px, 95vw);
            max-height: 90vh;
            overflow-y: auto;
            background: #091727;
            border: 1px solid #29435e;
            border-radius: 15px;
            padding: 28px;
            box-shadow:
                0 25px 80px rgba(0, 0, 0, 0.5);
        }


        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 25px;
        }


        .modal-label {
            color: #46bfff;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 1px;
        }


        .modal-header h2 {
            margin: 7px 0 0;
        }


        .close-button {
            border: 0;
            background: transparent;
            color: #8ba0b5;
            font-size: 30px;
            cursor: pointer;
        }


        .detail-grid {
            display: grid;
            grid-template-columns:
                repeat(4, 1fr);
            gap: 11px;
        }


        .detail-box {
            background: #0d1d2f;
            border: 1px solid #1d354c;
            border-radius: 9px;
            padding: 14px;
        }


        .detail-box span {
            display: block;
            color: #688099;
            font-size: 10px;
            margin-bottom: 7px;
            text-transform: uppercase;
        }


        .detail-box strong {
            font-size: 13px;
            word-break: break-word;
        }


        .detail-section {
            margin-top: 27px;
        }


        .detail-section h3 {
            font-size: 15px;
            margin-bottom: 12px;
        }


        .description {
            color: #aab9c8;
            line-height: 1.6;
            background: #0d1d2f;
            border-radius: 9px;
            padding: 15px;
        }


        .mitre-card {
            display: flex;
            gap: 18px;
            align-items: center;
            background: #10243a;
            border: 1px solid #285473;
            border-radius: 10px;
            padding: 18px;
        }


        .mitre-id {
            font-size: 23px;
            font-weight: 800;
            color: #54c6ff;
        }


        .mitre-card strong,
        .mitre-card span {
            display: block;
        }


        .mitre-card span {
            color: #8499ae;
            margin-top: 5px;
            font-size: 12px;
        }


        .evidence-list,
        .response-list {
            margin: 0;
            padding-left: 22px;
            color: #aebdca;
            line-height: 1.7;
        }


        .evidence-list li,
        .response-list li {
            margin-bottom: 6px;
        }


        .response-section {
            padding-bottom: 10px;
        }


        .status-control {
            display: flex;
            align-items: center;
            gap: 15px;
        }


        .status-control select {
            background: #0d1d2f;
            color: #d9e6f1;
            border: 1px solid #29435e;
            border-radius: 8px;
            padding: 10px 13px;
            cursor: pointer;
        }


        .status-control span {
            color: #6f849b;
            font-size: 12px;
        }


        .text-critical {
            color: #ff5571;
        }


        .text-high {
            color: #ff984d;
        }


        .text-medium {
            color: #ffc94d;
        }


        .text-low {
            color: #4bd8a4;
        }


        @media (
            max-width: 1100px
        ) {

            .stats-grid {
                grid-template-columns:
                    repeat(2, 1fr);
            }

            .detail-grid {
                grid-template-columns:
                    repeat(2, 1fr);
            }

        }


        @media (
            max-width: 800px
        ) {

            .sidebar {
                width: 220px;
            }

            .main-content {
                margin-left: 220px;
                width: calc(100% - 220px);
                padding: 25px;
            }

            .content-grid {
                grid-template-columns: 1fr;
            }

            .topbar {
                flex-direction: column;
                gap: 20px;
            }

            .incident-card-middle {
                grid-template-columns:
                    repeat(2, 1fr);
            }

        }


        @media (
            max-width: 600px
        ) {

            .sidebar {
                position: relative;
                width: 100%;
                min-height: auto;
            }

            .soc-app {
                flex-direction: column;
            }

            .main-content {
                margin-left: 0;
                width: 100%;
                padding: 20px;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

        }

    `;


    document.head.appendChild(
        style
    );

}