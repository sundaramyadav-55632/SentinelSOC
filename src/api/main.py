from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.database.database import Database
from src.database.incident_store import IncidentStore


app = FastAPI(
    title="SentinelSOC API",
    description="Security Operations Center REST API",
    version="1.0.0"
)


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

database = Database()
store = IncidentStore(database)


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class IncidentStatusUpdate(BaseModel):

    status: str


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "application": "SentinelSOC",
        "status": "online",
        "version": "1.0.0",
        "message": "Security Operations Center API"
    }


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/api/health")
def health():

    return {
        "status": "healthy",
        "service": "SentinelSOC API"
    }


# --------------------------------------------------
# INCIDENTS
# --------------------------------------------------

@app.get("/api/incidents")
def get_incidents(
    status: Optional[str] = Query(
        default=None
    ),
    severity: Optional[str] = Query(
        default=None
    )
):

    incidents = store.get_incidents()

    if status:

        incidents = [
            incident
            for incident in incidents
            if incident.get("status") == status
        ]

    if severity:

        incidents = [
            incident
            for incident in incidents
            if incident.get("severity") == severity
        ]

    return {
        "count": len(incidents),
        "incidents": incidents
    }


# --------------------------------------------------
# SINGLE INCIDENT
# --------------------------------------------------

@app.get("/api/incidents/{incident_id}")
def get_incident(
    incident_id: int
):

    incident = store.get_incident(
        incident_id
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident


# --------------------------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------------------------

@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate
):

    incident = store.get_incident(
        incident_id
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    try:

        updated = store.update_incident_status(
            incident_id,
            update.status
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    if updated == 0:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "message": "Incident status updated",
        "incident_id": incident_id,
        "status": update.status
    }


# --------------------------------------------------
# EVENTS
# --------------------------------------------------

@app.get("/api/events")
def get_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=1000
    )
):

    cursor = database.connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    events = [
        dict(row)
        for row in cursor.fetchall()
    ]

    return {
        "count": len(events),
        "events": events
    }


# --------------------------------------------------
# ALERTS
# --------------------------------------------------

@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(
        default=100,
        ge=1,
        le=1000
    )
):

    cursor = database.connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    alerts = [
        dict(row)
        for row in cursor.fetchall()
    ]

    return {
        "count": len(alerts),
        "alerts": alerts
    }


# --------------------------------------------------
# STATISTICS
# --------------------------------------------------

@app.get("/api/statistics")
def get_statistics():

    cursor = database.connection.cursor()

    total_events = cursor.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    total_alerts = cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    total_incidents = cursor.execute(
        "SELECT COUNT(*) FROM incidents"
    ).fetchone()[0]

    open_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'open'
        """
    ).fetchone()[0]

    critical_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity = 'critical'
        """
    ).fetchone()[0]

    high_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity = 'high'
        """
    ).fetchone()[0]

    medium_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity = 'medium'
        """
    ).fetchone()[0]

    low_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity = 'low'
        """
    ).fetchone()[0]

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "severity": {
            "critical": critical_incidents,
            "high": high_incidents,
            "medium": medium_incidents,
            "low": low_incidents
        }
    }


# --------------------------------------------------
# INCIDENT SUMMARY
# --------------------------------------------------

@app.get("/api/summary")
def get_summary():

    cursor = database.connection.cursor()

    rows = cursor.execute(
        """
        SELECT
            incident_type,
            COUNT(*) AS count
        FROM incidents
        GROUP BY incident_type
        ORDER BY count DESC
        """
    ).fetchall()

    incident_types = {
        row["incident_type"]: row["count"]
        for row in rows
    }

    return {
        "incident_types": incident_types
    }


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "src.api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )