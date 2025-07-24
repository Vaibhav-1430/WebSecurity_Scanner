from flask import Flask, request, render_template
import subprocess
import re

app = Flask(__name__)

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return "❌ Please enter a valid website."

    clean_url = url.replace('https://', '').replace('http://', '').split('/')[0]
    http_url = "http://" + clean_url
    https_url = "https://" + clean_url

    report = f"🌐 Website Security Report for: `{clean_url}`\n"
    report += "-" * 60 + "\n\n"

    # WHOIS Info
    whois_data = run_command(f"whois {clean_url}", timeout=10)
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

    report += f"👤 Website Owner: {owner}\n"
    report += f"🌍 Hosting Country: {country}\n\n"

    # WhatWeb Output
    whatweb_data = run_command(f"whatweb {http_url}", timeout=10)
    tech_summary = whatweb_data.split("] ")[-1].replace(",", ", ")
    report += f"🔧 Technology Stack: {tech_summary}\n"

    # Safety Score
    score = rate_website(whatweb_data)
    level = "✅ Safe" if score >= 8 else "⚠️ Moderate" if score >= 5 else "❌ Risky"
    report += f"🔐 Security Rating: {score}/10 → {level}\n"

    # SSL Check
    sslscan_data = run_command(f"sslscan {clean_url}", timeout=15)
    ssl_status = "✅ Active & Detected" if "SSL" in sslscan_data or "TLS" in sslscan_data else "❌ Not Found"
    report += f"🔒 SSL Certificate: {ssl_status}\n"

    # Security Headers
    headers = run_command(f"curl -I {https_url}", timeout=10)
    headers_good = "X-Content-Type-Options" in headers and "X-Frame-Options" in headers
    report += f"🛡️ HTTP Security Headers: {'✅ Present' if headers_good else '⚠️ Missing'}\n"

    # WAF Detection
    waf = run_command(f"wafw00f {http_url}", timeout=15)
    report += f"🧱 Firewall (WAF): {'✅ Detected' if 'is behind' in waf else '❌ Not Found'}\n"

    # Open Ports
    nmap_data = run_command(f"nmap --top-ports 100 {clean_url}", timeout=20)
    open_ports = [line for line in nmap_data.splitlines() if "/tcp" in line and "open" in line]
    report += f"📡 Open Ports Detected: {len(open_ports)} port(s)\n"

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

if __name__ == '__main__':
    app.run(debug=True)
