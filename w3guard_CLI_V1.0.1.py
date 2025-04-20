import requests
import re
import json
import socket
import whois
import datetime
from urllib.parse import urlparse
from prettytable import PrettyTable
from colorama import Fore, Style

# Constants
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"
]

# Grade Color Map
GRADE_COLOR = {
    "A+": Fore.GREEN,
    "A": Fore.GREEN,
    "B": Fore.YELLOW,
    "C": Fore.MAGENTA,
    "E": Fore.RED
}

# Load API keys from the config.json file
def load_api_keys():
    with open('config.json', 'r') as f:
        config = json.load(f)
    return config

# Helper: Extract domain
def extract_domain(url):
    return urlparse(url).netloc

# Helper: Check domain age
def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days
        return age
    except:
        return -1

# Security Header Check
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        result = {}
        for h in SECURITY_HEADERS:
            result[h] = h in headers
        return result
    except:
        return {}

# Header Grade Calculation
def grade_headers(header_dict):
    total = len(SECURITY_HEADERS)
    enabled = sum(header_dict.values())
    percent = (enabled / total) * 100
    if percent == 100:
        return "A+"
    elif percent >= 85:
        return "A"
    elif percent >= 65:
        return "B"
    elif percent >= 40:
        return "C"
    else:
        return "E"

# API Scans

# VirusTotal API Lookup
def virustotal_scan(url, api_key):
    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# AbuseIPDB API Lookup
def abuseipdb_scan(ip, api_key):
    headers = {"Key": api_key}
    response = requests.get(f"https://api.abuseipdb.com/api/v2/check", headers=headers, params={"ipAddress": ip})
    if response.status_code == 200:
        return response.json()
    return None

# IPQualityScore Lookup
'''def ipqualityscore_scan(ip, api_key):
    params = {"ip": ip, "apikey": api_key}
    response = requests.get("https://ipqualityscore.com/api/json/ip/" + api_key, params=params)
    if response.status_code == 200:
        return response.json()
    return None'''

# Shodan API Lookup
def shodan_scan(ip, api_key):
    headers = {"Authorization": "APIKEY " + api_key}
    response = requests.get(f"https://api.shodan.io/shodan/host/{ip}", headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

'''# HaveIBeenPwned API Lookup
def hibp_scan(email, api_key):
    response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                            headers={"hibp-api-key": api_key})
    if response.status_code == 200:
        return response.json()
    return None'''

# Simple Phishing Detection (heuristics)
def is_suspicious_url(url):
    domain = extract_domain(url)
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        return True
    if len(domain) > 30:
        return True
    if any(c in domain for c in ['@', '-', '_']):
        return True
    return False

# Main Scanner Function
def scan_url(url, api_keys):
    print(f"\nScanning: {url}\n")

    domain = extract_domain(url)
    age = get_domain_age(domain)
    print(f"Domain Age: {age} days")

    # Header Scan
    headers_result = check_security_headers(url)
    grade = grade_headers(headers_result)
    print(f"\nSecurity Headers Grade: {GRADE_COLOR[grade]}{grade}{Style.RESET_ALL}")

    table = PrettyTable()
    table.field_names = ["Header", "Enabled"]
    for h, status in headers_result.items():
        table.add_row([h, "Yes" if status else "No"])
    print(table)

    # Phishing heuristic
    if is_suspicious_url(url):
        print(f"{Fore.RED}⚠️ Suspicious URL pattern detected!{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}URL pattern looks normal.{Style.RESET_ALL}")

    # Additional API scans
    ip = socket.gethostbyname(domain)

    # AbuseIPDB Check
    abuse_result = abuseipdb_scan(ip, api_keys['abuseipdb_api_key'])
    print("\nAbuseIPDB Check:")
    if abuse_result:
        print(json.dumps(abuse_result, indent=4))
    
    # IPQualityScore Check
    '''ipqs_result = ipqualityscore_scan(ip, api_keys['ipqualityscore_api_key'])
    print("\nIPQualityScore Check:")
    if ipqs_result:
        print(json.dumps(ipqs_result, indent=4))'''

    # Shodan Check
    shodan_result = shodan_scan(ip, api_keys['shodan_api_key'])
    print("\nShodan Check:")
    if shodan_result:
        print(json.dumps(shodan_result, indent=4))

    # VirusTotal Scan
    virustotal_result = virustotal_scan(url, api_keys['virustotal_api_key'])
    print("\nVirusTotal Scan:")
    if virustotal_result:
        print(json.dumps(virustotal_result, indent=4))

    # HaveIBeenPwned Check (for emails)
    #print("\n[Optional] Integrate HaveIBeenPwned scan for email addresses here.")
    
    # Final Verdict
    print("\nFinal Verdict:")
    if grade in ["A+", "A"] and not is_suspicious_url(url):
        print(f"{Fore.GREEN}✅ Likely Safe{Style.RESET_ALL}")
    elif grade in ["B", "C"]:
        print(f"{Fore.YELLOW}⚠️ Medium Risk — Caution advised{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ High Risk — Possibly malicious{Style.RESET_ALL}")

# Entry point
if __name__ == "__main__":
    # Load API keys from the config file
    api_keys = load_api_keys()

    target_url = input("Enter the URL to scan: ")
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    scan_url(target_url, api_keys)
