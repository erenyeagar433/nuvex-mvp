# app/utils/reputation.py
import requests
import os

def check_ip_abuseipdb(ip: str) -> dict:
    try:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return {"ip": ip, "abuse_confidence": 0, "reports": 0, "country": "N/A", "isp": "N/A"}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {"Key": api_key, "Accept": "application/json"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A")
        }
    except requests.RequestException:
        return {"ip": ip, "abuse_confidence": 0, "reports": 0, "country": "N/A", "isp": "N/A"}

def check_virustotal(ioc: str) -> dict:
    try:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {"ioc": ioc, "malicious_votes": 0, "suspicious_votes": 0}
        url = f"https://www.virustotal.com/api/v3/urls" if "http" in ioc else f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        return {
            "ioc": ioc,
            "malicious_votes": data.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_votes": data.get("last_analysis_stats", {}).get("suspicious", 0)
        }
    except requests.RequestException:
        return {"ioc": ioc, "malicious_votes": 0, "suspicious_votes": 0}
