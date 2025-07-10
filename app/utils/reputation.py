# app/utils/reputation.py

import os
import requests
import base64
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def is_ip(ioc: str) -> bool:
    try:
        parts = ioc.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except:
        return False

def is_url(ioc: str) -> bool:
    try:
        result = urlparse(ioc)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_domain(ioc: str) -> bool:
    return "." in ioc and not is_ip(ioc) and not is_url(ioc)

def check_ip_abuseipdb(ip: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": ip,
            "abuse_confidence": data.get("abuseConfidenceScore", "N/A"),
            "reports": data.get("totalReports", "N/A"),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A")
        }
    return {"ip": ip, "error": f"AbuseIPDB error: {response.status_code}"}

def check_virustotal(ioc: str) -> dict:
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    if is_ip(ioc):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif is_url(ioc):
        url = f"https://www.virustotal.com/api/v3/urls/{_url_id(ioc)}"
    elif is_domain(ioc):
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:
        return {"ioc": ioc, "error": "Invalid IOC format"}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {})
        return {
            "ioc": ioc,
            "malicious_votes": data.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_votes": data.get("last_analysis_stats", {}).get("suspicious", 0)
        }
    return {"ioc": ioc, "error": f"VirusTotal error: {response.status_code}"}

def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_reputation(iocs: list) -> list:
    results = []
    for ioc in iocs:
        if is_ip(ioc):
            results.append(check_ip_abuseipdb(ioc))
            results.append(check_virustotal(ioc))
        elif is_url(ioc):
            results.append(check_virustotal(ioc))
        elif is_domain(ioc):
            results.append(check_virustotal(ioc))
        else:
            results.append({"ioc": ioc, "error": "Unsupported IOC type"})
    return results
