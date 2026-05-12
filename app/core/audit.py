import json
import os
from datetime import datetime
from typing import Optional

LOG_FILE = "logs/audit.log"
os.makedirs("logs", exist_ok=True)

def log_event(event: str, user_id: str, details: dict = {}):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event,
        "user_id": user_id,
        "details": details
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

def read_logs(
    event_filter: Optional[str] = None,
    user_filter: Optional[str] = None,
    limit: int = 100
) -> list[dict]:
    """Read and optionally filter audit logs."""
    if not os.path.exists(LOG_FILE):
        return []
    logs = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if event_filter and entry.get("event") != event_filter:
                    continue
                if user_filter and entry.get("user_id") != user_filter:
                    continue
                logs.append(entry)
            except json.JSONDecodeError:
                continue
    return logs[-limit:]  # Return most recent N entries

def get_log_stats() -> dict:
    """Compute summary statistics from audit log."""
    logs = read_logs(limit=10000)
    stats = {
        "total_events": len(logs),
        "events_by_type": {},
        "recent_failures": 0,
        "unique_users": set()
    }
    for entry in logs:
        event = entry.get("event", "UNKNOWN")
        stats["events_by_type"][event] = stats["events_by_type"].get(event, 0) + 1
        stats["unique_users"].add(entry.get("user_id"))
        if "FAILED" in event or "BLOCKED" in event:
            stats["recent_failures"] += 1

    stats["unique_users"] = len(stats["unique_users"])
    return stats