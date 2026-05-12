from datetime import datetime, timedelta
from collections import defaultdict
from app.core.audit import read_logs

# Thresholds
FAILED_LOGIN_THRESHOLD = 5      # 5 failed logins in 10 minutes = brute force
DOWNLOAD_THRESHOLD = 20         # 20 downloads in 5 minutes = bulk exfil
UPLOAD_THRESHOLD = 15           # 15 uploads in 5 minutes = suspicious
BLOCKED_UPLOAD_THRESHOLD = 3    # 3 blocked uploads = attacker probing

def detect_anomalies() -> list[dict]:
    """
    Scan audit logs for suspicious patterns.
    Returns list of anomaly alerts.
    """
    logs = read_logs(limit=10000)
    alerts = []
    now = datetime.utcnow()

    # ── Rule 1: Brute Force Detection ─────────────────────────────────────────
    # 5+ LOGIN_FAILED events from same user within 10 minutes
    window = now - timedelta(minutes=10)
    failed_logins = defaultdict(list)

    for entry in logs:
        if entry["event"] == "LOGIN_FAILED":
            ts = datetime.fromisoformat(entry["timestamp"])
            if ts > window:
                username = entry["details"].get("username", "unknown")
                failed_logins[username].append(ts)

    for username, times in failed_logins.items():
        if len(times) >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "type": "BRUTE_FORCE_DETECTED",
                "message": f"User '{username}' had {len(times)} failed logins in the last 10 minutes",
                "count": len(times),
                "detected_at": now.isoformat()
            })

    # ── Rule 2: Bulk Download (Data Exfiltration) ─────────────────────────────
    # 20+ FILE_DOWNLOADED events from same user within 5 minutes
    window = now - timedelta(minutes=5)
    downloads = defaultdict(list)

    for entry in logs:
        if entry["event"] in ("FILE_DOWNLOADED", "SHARED_FILE_DOWNLOADED"):
            ts = datetime.fromisoformat(entry["timestamp"])
            if ts > window:
                downloads[entry["user_id"]].append(ts)

    for user_id, times in downloads.items():
        if len(times) >= DOWNLOAD_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "type": "BULK_DOWNLOAD_DETECTED",
                "message": f"User '{user_id[:8]}...' downloaded {len(times)} files in 5 minutes — possible data exfiltration",
                "count": len(times),
                "detected_at": now.isoformat()
            })

    # ── Rule 3: Malware Upload Probing ────────────────────────────────────────
    # 3+ UPLOAD_BLOCKED events from same user = attacker testing filters
    window = now - timedelta(minutes=30)
    blocked = defaultdict(int)

    for entry in logs:
        if entry["event"] in ("UPLOAD_BLOCKED_MIME", "UPLOAD_BLOCKED_MALWARE"):
            ts = datetime.fromisoformat(entry["timestamp"])
            if ts > window:
                blocked[entry["user_id"]] += 1

    for user_id, count in blocked.items():
        if count >= BLOCKED_UPLOAD_THRESHOLD:
            alerts.append({
                "severity": "MEDIUM",
                "type": "MALWARE_PROBE_DETECTED",
                "message": f"User '{user_id[:8]}...' had {count} blocked uploads in 30 minutes — probing security filters",
                "count": count,
                "detected_at": now.isoformat()
            })

    # ── Rule 4: Integrity Failure ─────────────────────────────────────────────
    # ANY integrity failure = immediate critical alert
    for entry in logs:
        if entry["event"] == "INTEGRITY_FAILURE":
            ts = datetime.fromisoformat(entry["timestamp"])
            if ts > now - timedelta(hours=24):
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "FILE_TAMPERING_DETECTED",
                    "message": f"File integrity check failed for file '{entry['details'].get('file_id', 'unknown')}' — possible storage tampering",
                    "count": 1,
                    "detected_at": entry["timestamp"]
                })

    # ── Rule 5: MFA Bypass Attempts ───────────────────────────────────────────
    # 5+ MFA_FAILED events within 10 minutes
    window = now - timedelta(minutes=10)
    mfa_failures = defaultdict(int)

    for entry in logs:
        if entry["event"] == "MFA_FAILED":
            ts = datetime.fromisoformat(entry["timestamp"])
            if ts > window:
                mfa_failures[entry["user_id"]] += 1

    for user_id, count in mfa_failures.items():
        if count >= 5:
            alerts.append({
                "severity": "HIGH",
                "type": "MFA_BYPASS_ATTEMPT",
                "message": f"User '{user_id[:8]}...' failed MFA {count} times in 10 minutes — possible bypass attempt",
                "count": count,
                "detected_at": now.isoformat()
            })

    return sorted(alerts, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x["severity"]])