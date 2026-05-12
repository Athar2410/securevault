import requests
import hashlib
import time
from app.config import settings

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"

def scan_file(data: bytes) -> dict:
    """
    Scan file with VirusTotal.
    Returns {"is_malicious": bool, "detections": int, "total_engines": int}
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return {"is_malicious": False, "detections": 0, "total_engines": 0, "skipped": True}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    # Step 1: Upload file for scanning
    files = {"file": ("upload", data)}
    response = requests.post(
        f"{VIRUSTOTAL_URL}/files",
        headers=headers,
        files=files,
        timeout=30
    )
    if response.status_code != 200:
        return {"is_malicious": False, "error": "VT upload failed"}

    analysis_id = response.json()["data"]["id"]

    # Step 2: Poll for results (max 30 seconds)
    for _ in range(6):
        time.sleep(5)
        result = requests.get(
            f"{VIRUSTOTAL_URL}/analyses/{analysis_id}",
            headers=headers,
            timeout=15
        )
        if result.status_code == 200:
            stats = result.json()["data"]["attributes"].get("stats", {})
            status = result.json()["data"]["attributes"].get("status")
            if status == "completed":
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                return {
                    "is_malicious": (malicious + suspicious) > 0,
                    "detections": malicious + suspicious,
                    "total_engines": total
                }

    return {"is_malicious": False, "error": "VT timeout"}