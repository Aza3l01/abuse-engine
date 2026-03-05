from dataclasses import dataclass, field
from typing import Optional, Dict


@dataclass
class CanonicalEvent:
    timestamp: str              # When the request happened (ISO format)
    ip: str                     # IP address of the requester
    user_id: Optional[str]      # Who made the request (can be null)
    endpoint: str               # API path hit, e.g. /api/users/123
    method: str                 # HTTP method: GET, POST, PUT, DELETE
    status_code: int            # Response code: 200, 401, 404, etc.
    user_agent: str             # Browser/tool string
    response_time: Optional[float] = None  # How long the server took (ms)
    request_params: Dict = field(default_factory=dict)  # Query params or body