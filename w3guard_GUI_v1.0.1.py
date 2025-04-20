from flask import Flask, request, jsonify, render_template, Response
import requests
import re
import socket
import whois
from datetime import datetime
import json
import base64

app = Flask(__name__)

# Load API keys from config.json
with open("config.json") as f:
    api_keys = json.load(f)


def extract_domain(url):
    match = re.search(r"https?://([^/]+)", url)
    return match.group(1) if match else url


def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        return age
    except:
        return -1


def check_security_headers(url):
    try:
        r = requests.get(url, timeout=10)
        headers = r.headers
        header_list = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection"
        ]
        return {header: header in headers for header in header_list}
    except:
        return {header: False for header in header_list}


def abuseipdb_scan(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {
            "Key": api_keys['abuseipdb_api_key'],
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("data", {})
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {str(e)}"}
    except ValueError:
        return {"error": "Invalid JSON response from AbuseIPDB"}


def shodan_scan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_keys['shodan_api_key']}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Shodan request failed: {str(e)}"}
    except ValueError:
        return {"error": "Invalid JSON response from Shodan"}


def virustotal_scan(url):
    try:
        headers = {"x-apikey": api_keys['virustotal_api_key']}
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(report_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {str(e)}"}
    except ValueError:
        return {"error": "Invalid JSON response from VirusTotal"}


def is_suspicious_url(url):
    domain = extract_domain(url)
    return (
        bool(re.search(r"\d+\.\d+\.\d+\.\d+", domain)) or
        len(domain) > 30 or
        any(c in domain for c in ['@', '-', '_'])
    )


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/scan')
def scan():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    domain = extract_domain(url)
    age = get_domain_age(domain)
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unavailable"

    headers = check_security_headers(url)
    heuristics = {
        "IP in URL": bool(re.search(r"\d+\.\d+\.\d+\.\d+", domain)),
        "Domain Length > 30": len(domain) > 30,
        "Special Characters (@, -, _)": any(c in domain for c in ['@', '-', '_'])
    }

    abuse_data = abuseipdb_scan(ip) if ip != "Unavailable" else {"error": "IP unavailable"}
    shodan_data = shodan_scan(ip) if ip != "Unavailable" else {"error": "IP unavailable"}
    vt_stats = virustotal_scan(url)

    response_data = {
        "domain": domain,
        "ip": ip,
        "age": age,
        "headers": headers,
        "heuristics": heuristics,
        "abuseipdb": abuse_data,
        "shodan": shodan_data,
        "virustotal": vt_stats
    }

    return jsonify(response_data)


@app.route('/download')
def download():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided for download"}), 400

    domain = extract_domain(url)
    age = get_domain_age(domain)
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unavailable"

    headers = check_security_headers(url)
    heuristics = {
        "IP in URL": bool(re.search(r"\d+\.\d+\.\d+\.\d+", domain)),
        "Domain Length > 30": len(domain) > 30,
        "Special Characters (@, -, _)": any(c in domain for c in ['@', '-', '_'])
    }

    abuse_data = abuseipdb_scan(ip) if ip != "Unavailable" else {"error": "IP unavailable"}
    shodan_data = shodan_scan(ip) if ip != "Unavailable" else {"error": "IP unavailable"}
    vt_stats = virustotal_scan(url)

    result_txt = f"""
Scan Results for: {url}

Domain Information:
- Domain: {domain}
- IP Address: {ip}
- Domain Age: {age} days

Security Headers:
{json.dumps(headers, indent=4)}

Heuristics:
{json.dumps(heuristics, indent=4)}

AbuseIPDB Data:
{json.dumps(abuse_data, indent=4)}

Shodan Data:
{json.dumps(shodan_data, indent=4)}

VirusTotal Scan Summary:
{json.dumps(vt_stats, indent=4)}
"""

    response = Response(result_txt, mimetype='text/plain')
    response.headers['Content-Disposition'] = 'attachment; filename=scan_result.txt'
    return response


if __name__ == '__main__':
    app.run(debug=True)