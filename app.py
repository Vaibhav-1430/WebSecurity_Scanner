from flask import Flask, request, render_template
import subprocess
import re
import os
import subprocess
import re
import os
import requests
import ssl, socket
from datetime import datetime

app = Flask(__name__)

# 🔧 Helper: Run shell commands
def run_command(command, timeout=20):
    try:
        return subprocess.check_output(command, shell=True, timeout=timeout, stderr=subprocess.STDOUT).decode()
    except subprocess.TimeoutExpired:
        return f"⏱️ Command timed out: {command}\n"
    except subprocess.CalledProcessError as e:
        return f"❌ Error: {e.output.decode()}\n"
    except Exception as ex:
        return f"❌ Unexpected error: {str(ex)}\n"

# 🔧 BuiltWith tech stack via API
def get_tech_stack_with_builtwith(domain):
    api_key = "19954cde-cbc6-49d5-ba23-a77339c067b9"  # Your API key
    try:
        response = requests.get(f"https://api.builtwith.com/free1/api.json?KEY={api_key}&LOOKUP={domain}")
        if response.status_code == 200:
            data = response.json()
            if "Results" in data and data["Results"]:
                techs = []
                for tech in data["Results"][0].get("Result", []):
                    techs.append(tech.get("Name"))
                return ', '.join(techs) if techs else "⚠️ No technologies found."
            return "⚠️ No technologies found."
        else:
            return f"❌ API error ({response.status_code})"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# 🔐 SSL Check (Python-based)
def check_ssl_cert(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expires - datetime.utcnow()).days
                return f"✅ Valid SSL Certificate (expires in {days_left} days)"
    except Exception as e:
        return f"❌ Not Found"

# 🔐 Rate site based on tech keywords
def rate_website(tech_string):
    score = 8
    lower = tech_string.lower()
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

    # Technology Stack (via BuiltWith)
    tech_summary = get_tech_stack_with_builtwith(clean_url)
    report += f"🔧 Technology Stack: {tech_summary}\n"

    # Safety Score
    score = rate_website(tech_summary)
    level = "✅ Safe" if score >= 8 else "⚠️ Moderate" if score >= 5 else "❌ Risky"
    report += f"🔐 Security Rating: {score}/10 → {level}\n"

    # SSL Certificate Check
    ssl_status = check_ssl_cert(clean_url)
    report += f"🔒 SSL Certificate: {ssl_status}\n"

    # HTTP Headers Check
    headers = run_command(f"curl -I {https_url}", timeout=10)
    missing_headers = []
    if "X-Content-Type-Options" not in headers:
        missing_headers.append("X-Content-Type-Options")
    if "Strict-Transport-Security" not in headers:
        missing_headers.append("Strict-Transport-Security")
    if missing_headers:
        report += f"🛡️ HTTP Security Headers: ⚠️ Missing: {', '.join(missing_headers)}\n"
        report += "💡 Suggestion: Add the following headers to your server configuration:\n"
        if "X-Content-Type-Options" in missing_headers:
            report += "   - X-Content-Type-Options: nosniff\n"
        if "Strict-Transport-Security" in missing_headers:
            report += "   - Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
    else:
        report += "🛡️ HTTP Security Headers: ✅ Present\n"

    # WAF Detection
    waf = run_command(f"wafw00f {http_url}", timeout=15)
    report += f"🧱 Firewall (WAF): {'✅ Detected' if 'is behind' in waf else '⚠️ Not detected (may be hidden behind CDN or blocked)'}\n"

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

# 🌐 Flask entry point
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)


app = Flask(__name__)

# BuiltWith Tech Stack Detection
def get_tech_stack_with_builtwith(target_url):
    api_key = "19954cde-cbc6-49d5-ba23-a77339c067b9"  # 🔐 Your API key

    try:
        response = requests.get(
            f"https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP={target_url}"
        )
        data = response.json()

        techs = []
        for result in data.get("Results", []):
            for tech in result.get("Result", {}).get("Paths", {}).get("*", []):
                techs.append(tech.get("Technology", {}).get("Name"))

        if not techs:
            return "⚠️ No technologies found."
        return "🕵️ " + ", ".join(sorted(set(techs)))

    except Exception as e:
        return f"❌ BuiltWith API Error: {e}"

# Command Runner
def run_command(command, timeout=20):
    try:
        return subprocess.check_output(command, shell=True, timeout=timeout, stderr=subprocess.STDOUT).decode()
    except subprocess.TimeoutExpired:
        return f"⏱️ Command timed out: {command}\n"
    except subprocess.CalledProcessError as e:
        return f"❌ Error: {e.output.decode()}\n"
    except Exception as ex:
        return f"❌ Unexpected error: {str(ex)}\n"

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

    # 🔧 Tech Stack Detection using BuiltWith
    tech_summary = get_tech_stack_with_builtwith(http_url)
    report += f"🔧 Technology Stack: {tech_summary}\n"

    # 🔐 Safety Score (basic scoring)
    score = 8
    level = "✅ Safe" if score >= 8 else "⚠️ Moderate" if score >= 5 else "❌ Risky"
    report += f"🔐 Security Rating: {score}/10 → {level}\n"

    # 🔒 SSL Check
    sslscan_data = run_command(f"sslscan {clean_url}", timeout=15)
    ssl_status = "✅ Valid SSL Certificate" if "SSL" in sslscan_data or "TLS" in sslscan_data else "❌ Not Found"
    report += f"🔒 SSL Certificate: {ssl_status}\n"

    # 🛡️ HTTP Security Headers
    headers = run_command(f"curl -I {https_url}", timeout=10)
    missing_headers = []
    if "X-Content-Type-Options" not in headers:
        missing_headers.append("X-Content-Type-Options")
    if "Strict-Transport-Security" not in headers:
        missing_headers.append("Strict-Transport-Security")
    
    if not missing_headers:
        report += "🛡️ HTTP Security Headers: ✅ Present\n"
    else:
        report += f"🛡️ HTTP Security Headers: ⚠️ Missing: {', '.join(missing_headers)}\n"
        report += "💡 Suggestion: Add the following headers to your server configuration:\n"
        for h in missing_headers:
            if h == "X-Content-Type-Options":
                report += "   - X-Content-Type-Options: nosniff\n"
            if h == "Strict-Transport-Security":
                report += "   - Strict-Transport-Security: max-age=31536000; includeSubDomains\n"

    # 🧱 WAF Detection
    waf = run_command(f"wafw00f {http_url}", timeout=15)
    report += f"🧱 Firewall (WAF): {'✅ Detected' if 'is behind' in waf else '⚠️ Not detected (may be hidden behind CDN or blocked)'}\n"

    # 📡 Open Ports
    nmap_data = run_command(f"nmap --top-ports 100 {clean_url}", timeout=20)
    open_ports = [line for line in nmap_data.splitlines() if "/tcp" in line and "open" in line]
    report += f"📡 Open Ports Detected: {len(open_ports)} port(s)\n"
    if len(open_ports) == 0:
        report += "💡 Note: Some websites block scans or only allow HTTPS on port 443.\n"

    # 📊 Summary
    report += "\n📊 Summary:\n"
    if score >= 8:
        report += "✅ This website appears to be generally **safe**.\n"
    elif score >= 5:
        report += "⚠️ This website may have **moderate** security concerns.\n"
    else:
        report += "❌ This website may be **risky**. Avoid sensitive interactions.\n"

    report += "\n📘 Note: This is a public scan using open-source tools. Always verify results with professional security testing."

    return report

# Run on Render or localhost
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
