from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from typing import Optional
from app.core.audit import read_logs, get_log_stats
from app.core.anomaly import detect_anomalies
from app.models.user import User
from app.routers.files import get_current_user

router = APIRouter(prefix="/audit", tags=["Audit & Monitoring"])


# ── GET /audit/logs ───────────────────────────────────────────────────────────
@router.get("/logs")
def get_logs(
    event: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, le=500),
    current_user: User = Depends(get_current_user)
):
    """Retrieve audit logs with optional filtering."""
    return {
        "logs": read_logs(event_filter=event, limit=limit),
        "count": limit
    }


# ── GET /audit/stats ──────────────────────────────────────────────────────────
@router.get("/stats")
def get_stats(current_user: User = Depends(get_current_user)):
    """Get summary statistics of all audit events."""
    return get_log_stats()


# ── GET /audit/anomalies ──────────────────────────────────────────────────────
@router.get("/anomalies")
def get_anomalies(current_user: User = Depends(get_current_user)):
    """Run anomaly detection and return active alerts."""
    alerts = detect_anomalies()
    return {
        "alert_count": len(alerts),
        "alerts": alerts
    }


# ── GET /audit/dashboard ──────────────────────────────────────────────────────
@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(current_user: User = Depends(get_current_user)):
    """Live HTML audit dashboard."""
    stats = get_log_stats()
    alerts = detect_anomalies()
    logs = read_logs(limit=20)

    severity_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#00cc44"}

    alerts_html = ""
    if alerts:
        for a in alerts:
            color = severity_colors.get(a["severity"], "#888")
            alerts_html += f"""
            <div class="alert-card" style="border-left: 4px solid {color}">
                <span class="badge" style="background:{color}">{a['severity']}</span>
                <strong>{a['type']}</strong>
                <p>{a['message']}</p>
                <small>🕐 {a['detected_at']}</small>
            </div>"""
    else:
        alerts_html = '<div class="no-alerts">✅ No anomalies detected</div>'

    logs_html = ""
    event_colors = {
        "LOGIN_FAILED": "#ff4444", "LOGIN_SUCCESS": "#00cc44",
        "FILE_UPLOADED": "#4488ff", "FILE_DOWNLOADED": "#aa44ff",
        "MFA_ENABLED": "#00cc44", "UPLOAD_BLOCKED_MIME": "#ff8800",
        "UPLOAD_BLOCKED_MALWARE": "#ff4444", "INTEGRITY_FAILURE": "#ff4444",
        "SHARE_LINK_CREATED": "#4488ff", "FILE_DELETED": "#ff8800"
    }
    for log in reversed(logs):
        color = event_colors.get(log["event"], "#888888")
        logs_html += f"""
        <tr>
            <td><code style="color:#aaa">{log['timestamp'][:19]}</code></td>
            <td><span class="event-badge" style="background:{color}22;color:{color};border:1px solid {color}44">{log['event']}</span></td>
            <td><code>{log['user_id'][:8]}...</code></td>
            <td><code>{str(log.get('details',''))[:60]}</code></td>
        </tr>"""

    events_by_type = stats.get("events_by_type", {})
    chart_labels = list(events_by_type.keys())
    chart_values = list(events_by_type.values())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureVault — Audit Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }}
        header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }}
        header h1 {{ font-size: 1.25rem; color: #58a6ff; }}
        .status-dot {{ width: 10px; height: 10px; background: #3fb950; border-radius: 50%; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%,100% {{ opacity:1 }} 50% {{ opacity:0.4 }} }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .kpi-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.25rem; text-align: center; }}
        .kpi-card .value {{ font-size: 2rem; font-weight: bold; color: #58a6ff; }}
        .kpi-card .label {{ font-size: 0.8rem; color: #8b949e; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; }}
        .card h2 {{ font-size: 0.9rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 1rem; }}
        .alert-card {{ background: #0d1117; border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem; }}
        .badge {{ font-size: 0.7rem; font-weight: bold; padding: 2px 8px; border-radius: 4px; color: #000; margin-right: 0.5rem; }}
        .alert-card strong {{ color: #c9d1d9; font-size: 0.9rem; }}
        .alert-card p {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.25rem; }}
        .alert-card small {{ color: #6e7681; font-size: 0.75rem; }}
        .no-alerts {{ color: #3fb950; text-align: center; padding: 2rem; font-size: 0.9rem; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{ color: #8b949e; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; padding: 0.5rem; border-bottom: 1px solid #30363d; text-align: left; }}
        td {{ padding: 0.6rem 0.5rem; border-bottom: 1px solid #21262d; vertical-align: middle; }}
        .event-badge {{ font-size: 0.72rem; padding: 2px 8px; border-radius: 4px; font-weight: 500; white-space: nowrap; }}
        .refresh-btn {{ background: #238636; color: #fff; border: none; padding: 0.4rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; margin-left: auto; }}
        .refresh-btn:hover {{ background: #2ea043; }}
        .section-header {{ display: flex; align-items: center; margin-bottom: 1.5rem; }}
        .section-header h2 {{ font-size: 1rem; color: #c9d1d9; }}
        code {{ font-family: 'Courier New', monospace; font-size: 0.82rem; }}
    </style>
</head>
<body>
    <header>
        <div class="status-dot"></div>
        <h1>🔐 SecureVault — Audit Dashboard</h1>
        <button class="refresh-btn" onclick="location.reload()">↻ Refresh</button>
    </header>
    <div class="container">

        <!-- KPI Cards -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="value">{stats.get('total_events', 0)}</div>
                <div class="label">Total Events</div>
            </div>
            <div class="kpi-card">
                <div class="value" style="color:#3fb950">{stats.get('unique_users', 0)}</div>
                <div class="label">Unique Users</div>
            </div>
            <div class="kpi-card">
                <div class="value" style="color:#ff4444">{stats.get('recent_failures', 0)}</div>
                <div class="label">Failures & Blocks</div>
            </div>
            <div class="kpi-card">
                <div class="value" style="color:{'#ff4444' if alerts else '#3fb950'}">{len(alerts)}</div>
                <div class="label">Active Alerts</div>
            </div>
        </div>

        <!-- Alerts + Chart -->
        <div class="grid-2">
            <div class="card">
                <h2>🚨 Anomaly Alerts</h2>
                {alerts_html}
            </div>
            <div class="card">
                <h2>📊 Events by Type</h2>
                <canvas id="eventChart" height="220"></canvas>
            </div>
        </div>

        <!-- Audit Log Table -->
        <div class="card">
            <div class="section-header">
                <h2>📋 Recent Audit Events (last 20)</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event</th>
                        <th>User ID</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>{logs_html}</tbody>
            </table>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('eventChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: {chart_labels},
                datasets: [{{
                    data: {chart_values},
                    backgroundColor: ['#58a6ff','#3fb950','#ff8800','#ff4444','#aa44ff','#00ccbb','#ffcc00','#ff6688'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'right', labels: {{ color: '#8b949e', font: {{ size: 11 }} }} }}
                }}
            }}
        }});

        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>"""