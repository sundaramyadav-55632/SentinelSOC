from dataclasses import dataclass, asdict
from typing import Optional
import json


@dataclass
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    message: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict())