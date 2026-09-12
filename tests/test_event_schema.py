from src.utils.event_schema import SecurityEvent


event = SecurityEvent(
    timestamp="2026-09-12T17:30:00",
    source="linux",
    event_type="authentication_failure",
    severity="medium",
    username="admin",
    source_ip="192.168.1.50",
    destination_port=22,
    message="Failed password for admin"
)

print(event.to_json())