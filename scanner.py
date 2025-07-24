# scanner.py

import subprocess
import re
import socket
import ssl
import requests

def run_command(command, timeout=20):
    try:
        return subprocess.check_output(command, shell=True, timeout=timeout, stderr=subprocess.STDOUT).decode()
    except subprocess.TimeoutExpired:
        return f"⏱️ Command timed out: {command}\n"
    except subprocess.CalledProcessError as e:
        return f"❌ Error: {e.output.decode()}\n"
    except Exception as ex:
        return f"❌ Unexpected error: {str(ex)}\n"

def rate_website(whatweb_output):
    score = 8
    lower = whatweb_output.lower()
    if "outdated" in lower or "vulnerable" in lower:
        score -= 3
    if "unknown" in lower or "no server" in lower:
        score -= 2
    if "wordpress" in lower:
        score -= 1
    if "apache" in lower or "nginx" in lower:
        score += 1
    return max(1, min(score, 10))

def check_ssl(host):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return "✅ Valid SSL Certificate"
    except Exception:
        return "❌ Not Found"

def check_headers(url):
    headers = run_command(f"curl -sI {url}", timeout=10)
    required = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY or SAMEORIGIN",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self';"
    }
    missing = [key for key in required if key not in headers]
    if missing:
        suggestion_text = "\n💡 Suggestion: Add the following headers to your server configuration:\n"
        for h in missing:
            suggestion_text += f"   - {h}: {required[h]}\n"
        return f"⚠️ Missing: {', '.join(missing)}{suggestion_text}"
    return "✅ Present"

def get_whois_info(domain):
    whois_data = run_command(f"whois {domain}", timeout=10)
    owner = "Not available"
    country = "Unknown"
    for line in whois_data.splitlines():
        line_lower = line.lower()
        if any(key in line_lower for key in ["registrant name", "registrant organization", "orgname", "organization"]):
            owner = line.strip()
        if "country:" in line_lower and country == "Unknown":
            match = re.search(r"country:\s*(\w+)", line_lower)
            if match:
                country = match.group(1).upper()
    return owner, country

def generate_report(clean_url, http_url, https_url):
    report = f"🌐 Website Security Report for: `{clean_url}`\n"
    report += "-" * 60 + "\n\n"

    # WHOIS Info
    owner, country = get_whois_info(clean_url)
    report += f"👤 Website Owner: {owner}\n"
    report += f"🌍 Hosting Country: {country}\n\n"

    # WhatWeb (Tech Detection)
    whatweb_data = run_command(f"whatweb {http_url}", timeout=10)
    if "not found" in whatweb_data.lower() or "error" in whatweb_data.lower():
        tech_summary = "⚠️ Skipped (WhatWeb not available on this system)"
    else:
        tech_summary = whatweb_data.split("] ")[-1].replace(",", ", ")
    report += f"🔧 Technology Stack: {tech_summary}\n"

    # Safety Score
    score = rate_website(whatweb_data)
    level = "✅ Safe" if score >= 8 else "⚠️ Moderate" if score >= 5 else "❌ Risky"
    report += f"🔐 Security Rating: {score}/10 → {level}\n"

    # SSL Check
    ssl_status = check_ssl(clean_url)
    report += f"🔒 SSL Certificate: {ssl_status}\n"

    # Security Headers
    header_status = check_headers(https_url)
    report += f"🛡️ HTTP Security Headers: {header_status}\n"

    # WAF Detection
    waf = run_command(f"wafw00f {http_url}", timeout=15)
    if 'is behind' in waf:
        waf_result = "✅ Detected"
    else:
        waf_result = "⚠️ Not detected (may be hidden behind CDN or blocked)"
    report += f"🧱 Firewall (WAF): {waf_result}\n"

    # Open Ports
    nmap_data = run_command(f"nmap --top-ports 100 {clean_url}", timeout=20)
    open_ports = [line for line in nmap_data.splitlines() if "/tcp" in line and "open" in line]
    report += f"📡 Open Ports Detected: {len(open_ports)} port(s)\n"
    if len(open_ports) == 0:
        report += "💡 Note: Some websites block scans or only allow HTTPS on port 443.\n"

    # Summary
    report += "\n📊 Summary:\n"
    if score >= 8:
        report += "✅ This website appears to be generally **safe**.\n"
    elif score >= 5:
        report += "⚠️ This website may have **moderate** security concerns.\n"
    else:
        report += "❌ This website may be **risky**. Avoid sensitive interactions.\n"

    report += "\n📘 Note: This is a public scan using open-source tools. Always verify results with professional security testing."

    return report
