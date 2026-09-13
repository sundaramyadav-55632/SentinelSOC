const API_BASE = "http://127.0.0.1:8000";


async function apiRequest(endpoint) {

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


/* --------------------------------------------------
   API HEALTH
-------------------------------------------------- */

async function checkHealth() {

    const dot =
        document.getElementById("statusDot");

    const status =
        document.getElementById("apiStatus");

    try {

        const data =
            await apiRequest("/api/health");

        if (data.status === "healthy") {

            dot.className =
                "status-dot online";

            status.textContent =
                "Online";
        }

    } catch (error) {

        dot.className =
            "status-dot offline";

        status.textContent =
            "Offline";
    }
}


/* --------------------------------------------------
   STATISTICS
-------------------------------------------------- */

async function loadStatistics() {

    try {

        const data =
            await apiRequest(
                "/api/statistics"
            );

        document.getElementById(
            "totalEvents"
        ).textContent =
            data.total_events;

        document.getElementById(
            "totalAlerts"
        ).textContent =
            data.total_alerts;

        document.getElementById(
            "totalIncidents"
        ).textContent =
            data.total_incidents;

        document.getElementById(
            "openIncidents"
        ).textContent =
            data.open_incidents;


        const severity =
            data.severity || {};

        const critical =
            severity.critical || 0;

        const high =
            severity.high || 0;

        const medium =
            severity.medium || 0;

        const low =
            severity.low || 0;


        document.getElementById(
            "criticalCount"
        ).textContent = critical;

        document.getElementById(
            "highCount"
        ).textContent = high;

        document.getElementById(
            "mediumCount"
        ).textContent = medium;

        document.getElementById(
            "lowCount"
        ).textContent = low;


        const max =
            Math.max(
                critical,
                high,
                medium,
                low,
                1
            );


        document.getElementById(
            "criticalBar"
        ).style.width =
            `${(critical / max) * 100}%`;

        document.getElementById(
            "highBar"
        ).style.width =
            `${(high / max) * 100}%`;

        document.getElementById(
            "mediumBar"
        ).style.width =
            `${(medium / max) * 100}%`;

        document.getElementById(
            "lowBar"
        ).style.width =
            `${(low / max) * 100}%`;

    } catch (error) {

        console.error(
            "Statistics error:",
            error
        );
    }
}


/* --------------------------------------------------
   INCIDENTS
-------------------------------------------------- */

async function loadIncidents() {

    const table =
        document.getElementById(
            "incidentTable"
        );

    try {

        const data =
            await apiRequest(
                "/api/incidents"
            );

        if (
            !data.incidents ||
            data.incidents.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td
                        colspan="8"
                        class="empty"
                    >
                        No incidents found
                    </td>
                </tr>
            `;

            return;
        }


        table.innerHTML =
            data.incidents.map(
                incident => `

                <tr
                    onclick="showIncident(${incident.id})"
                    style="cursor:pointer"
                >

                    <td>
                        #${incident.id}
                    </td>

                    <td>
                        ${formatType(
                            incident.incident_type
                        )}
                    </td>

                    <td>
                        ${severityBadge(
                            incident.severity
                        )}
                    </td>

                    <td>
                        <span class="risk">
                            ${incident.risk_score}/100
                        </span>
                    </td>

                    <td>
                        ${incident.source_ip || "-"}
                    </td>

                    <td>
                        ${incident.username || "-"}
                    </td>

                    <td>
                        ${statusBadge(
                            incident.status
                        )}
                    </td>

                    <td>
                        ${formatDate(
                            incident.created_at
                        )}
                    </td>

                </tr>

            `
            ).join("");

    } catch (error) {

        table.innerHTML = `
            <tr>
                <td
                    colspan="8"
                    class="empty"
                >
                    Failed to load incidents
                </td>
            </tr>
        `;

        console.error(
            "Incident error:",
            error
        );
    }
}


/* --------------------------------------------------
   EVENTS
-------------------------------------------------- */

async function loadEvents() {

    const table =
        document.getElementById(
            "eventTable"
        );

    try {

        const data =
            await apiRequest(
                "/api/events?limit=20"
            );

        if (
            !data.events ||
            data.events.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td
                        colspan="8"
                        class="empty"
                    >
                        No events found
                    </td>
                </tr>
            `;

            return;
        }


        table.innerHTML =
            data.events.map(
                event => `

                <tr>

                    <td>
                        #${event.id}
                    </td>

                    <td>
                        ${formatDate(
                            event.timestamp
                        )}
                    </td>

                    <td>
                        ${event.source || "-"}
                    </td>

                    <td>
                        ${formatType(
                            event.event_type
                        )}
                    </td>

                    <td>
                        ${severityBadge(
                            event.severity
                        )}
                    </td>

                    <td>
                        ${event.source_ip || "-"}
                    </td>

                    <td>
                        ${
                            event.destination_ip
                                ? event.destination_ip
                                + (
                                    event.destination_port
                                        ? ":" +
                                        event.destination_port
                                        : ""
                                )
                                : "-"
                        }
                    </td>

                    <td>
                        ${event.protocol || "-"}
                    </td>

                </tr>

            `
            ).join("");

    } catch (error) {

        table.innerHTML = `
            <tr>
                <td
                    colspan="8"
                    class="empty"
                >
                    Failed to load events
                </td>
            </tr>
        `;
    }
}


/* --------------------------------------------------
   ALERTS
-------------------------------------------------- */

async function loadAlerts() {

    const table =
        document.getElementById(
            "alertTable"
        );

    try {

        const data =
            await apiRequest(
                "/api/alerts?limit=20"
            );

        if (
            !data.alerts ||
            data.alerts.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td
                        colspan="7"
                        class="empty"
                    >
                        No alerts found
                    </td>
                </tr>
            `;

            return;
        }


        table.innerHTML =
            data.alerts.map(
                alert => `

                <tr>

                    <td>
                        #${alert.id}
                    </td>

                    <td>
                        ${formatType(
                            alert.alert_type
                        )}
                    </td>

                    <td>
                        ${severityBadge(
                            alert.severity
                        )}
                    </td>

                    <td>
                        ${alert.source_ip || "-"}
                    </td>

                    <td>
                        ${alert.username || "-"}
                    </td>

                    <td>
                        ${alert.description || "-"}
                    </td>

                    <td>
                        ${formatDate(
                            alert.created_at
                        )}
                    </td>

                </tr>

            `
            ).join("");

    } catch (error) {

        table.innerHTML = `
            <tr>
                <td
                    colspan="7"
                    class="empty"
                >
                    Failed to load alerts
                </td>
            </tr>
        `;
    }
}


/* --------------------------------------------------
   ATTACK TYPES
-------------------------------------------------- */

async function loadAttackTypes() {

    const container =
        document.getElementById(
            "attackTypes"
        );

    try {

        const data =
            await apiRequest(
                "/api/summary"
            );

        const types =
            data.incident_types || {};

        const entries =
            Object.entries(types);

        if (entries.length === 0) {

            container.innerHTML = `
                <div class="empty">
                    No incidents available
                </div>
            `;

            return;
        }


        container.innerHTML =
            entries.map(
                ([type, count]) => `

                <div class="attack-type">

                    <span>
                        ${formatType(type)}
                    </span>

                    <strong>
                        ${count}
                    </strong>

                </div>

            `
            ).join("");

    } catch (error) {

        container.innerHTML = `
            <div class="empty">
                Failed to load summary
            </div>
        `;
    }
}


/* --------------------------------------------------
   INCIDENT DETAILS
-------------------------------------------------- */

async function showIncident(id) {

    try {

        const incident =
            await apiRequest(
                `/api/incidents/${id}`
            );

        const details =
            document.getElementById(
                "incidentDetails"
            );


        details.innerHTML = `

            <div class="detail-grid">

                <div class="detail-item">
                    <span>Incident ID</span>
                    <strong>
                        #${incident.id}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Type</span>
                    <strong>
                        ${formatType(
                            incident.incident_type
                        )}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Severity</span>
                    <strong>
                        ${severityBadge(
                            incident.severity
                        )}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Risk Score</span>
                    <strong>
                        ${incident.risk_score}/100
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Source IP</span>
                    <strong>
                        ${incident.source_ip || "-"}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Username</span>
                    <strong>
                        ${incident.username || "-"}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Failed Attempts</span>
                    <strong>
                        ${incident.failed_attempts || 0}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Unique Users</span>
                    <strong>
                        ${incident.unique_users || 0}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Unique Ports</span>
                    <strong>
                        ${incident.unique_ports || 0}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>Status</span>
                    <strong>
                        ${statusBadge(
                            incident.status
                        )}
                    </strong>
                </div>

            </div>

            <div style="margin-top:18px">

                <label
                    style="
                        display:block;
                        color:#8494a8;
                        font-size:11px;
                        margin-bottom:8px;
                    "
                >
                    Update Status
                </label>

                <select
                    id="statusSelect"
                    style="
                        background:#101e30;
                        color:#e7edf5;
                        border:1px solid #29415c;
                        padding:10px;
                        border-radius:7px;
                        width:100%;
                    "
                >

                    <option value="open">
                        Open
                    </option>

                    <option value="investigating">
                        Investigating
                    </option>

                    <option value="contained">
                        Contained
                    </option>

                    <option value="resolved">
                        Resolved
                    </option>

                    <option value="false_positive">
                        False Positive
                    </option>

                </select>

                <button
                    onclick="updateIncidentStatus(${incident.id})"
                    class="refresh-btn"
                    style="margin-top:10px"
                >
                    Update Incident
                </button>

            </div>

            <div style="margin-top:18px">

                <div class="detail-item">

                    <span>Description</span>

                    <strong>
                        ${incident.description || "-"}
                    </strong>

                </div>

            </div>
        `;


        document.getElementById(
            "statusSelect"
        ).value =
            incident.status;


        document.getElementById(
            "incidentModal"
        ).classList.remove(
            "hidden"
        );

    } catch (error) {

        console.error(
            "Incident detail error:",
            error
        );
    }
}


async function updateIncidentStatus(id) {

    const status =
        document.getElementById(
            "statusSelect"
        ).value;

    try {

        await fetch(
            `${API_BASE}/api/incidents/${id}/status`,
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


        closeModal();

        await loadDashboard();

    } catch (error) {

        alert(
            "Failed to update incident"
        );
    }
}


function closeModal() {

    document.getElementById(
        "incidentModal"
    ).classList.add(
        "hidden"
    );
}


/* --------------------------------------------------
   HELPERS
-------------------------------------------------- */

function formatType(value) {

    if (!value) {
        return "-";
    }

    return value
        .replaceAll("_", " ")
        .replace(
            /\b\w/g,
            letter =>
                letter.toUpperCase()
        );
}


function severityBadge(value) {

    const severity =
        String(
            value || "low"
        ).toLowerCase();

    return `
        <span class="badge badge-${severity}">
            ${severity}
        </span>
    `;
}


function statusBadge(value) {

    const status =
        String(
            value || "open"
        ).toLowerCase();

    return `
        <span class="badge badge-${status}">
            ${formatType(status)}
        </span>
    `;
}


function formatDate(value) {

    if (!value) {
        return "-";
    }

    try {

        return new Date(
            value
        ).toLocaleString();

    } catch {

        return value;
    }
}


/* --------------------------------------------------
   LOAD EVERYTHING
-------------------------------------------------- */

async function loadDashboard() {

    await Promise.all([
        checkHealth(),
        loadStatistics(),
        loadIncidents(),
        loadEvents(),
        loadAlerts(),
        loadAttackTypes()
    ]);

    document.getElementById(
        "lastUpdated"
    ).textContent =
        "Last updated: " +
        new Date().toLocaleTimeString();
}


/* --------------------------------------------------
   AUTO REFRESH
-------------------------------------------------- */

setInterval(
    loadDashboard,
    30000
);


/* --------------------------------------------------
   START
-------------------------------------------------- */

loadDashboard();