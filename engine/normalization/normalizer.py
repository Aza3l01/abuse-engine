from schemas.event_schema import CanonicalEvent
from typing import List, Dict


def normalize(raw_logs: List[Dict]) -> List[CanonicalEvent]:
    """
    Takes a list of raw log dictionaries (from JSON)
    and converts each one into a CanonicalEvent.

    This ensures every downstream component (sessionizer, agents)
    receives data in the same consistent format.
    """
    events = []
    for log in raw_logs:
        event = CanonicalEvent(
            timestamp=log.get("timestamp", ""),
            ip=log.get("ip", ""),
            user_id=log.get("user_id", None),
            endpoint=log.get("endpoint", ""),
            method=log.get("method", "GET"),
            status_code=log.get("status_code", 200),
            user_agent=log.get("user_agent", ""),
            response_time=log.get("response_time", None),
            request_params=log.get("request_params", {}),
        )
        events.append(event)
    return events