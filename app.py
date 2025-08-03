from flask import Flask, request, render_template
import subprocess as sp
import re, os, ssl, socket, requests
from datetime import datetime as dt
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')


app = Flask(__name__)

def do_cmd(cmd, timeout=15):
    try:
        out = sp.check_output(cmd, shell=True, timeout=timeout, stderr=sp.STDOUT)
        return out.decode('utf-8')
    except sp.TimeoutExpired:
        return f"timeout on: {cmd}\n"
    except sp.CalledProcessError as ce:
        return f"fail: {ce.output.decode()}\n"
    except Exception as e:
        return f"err: {str(e)}\n"

def fetch_tech(domain):
    k = "19954cde-cbc6-49d5-ba23-a77339c067b9"
    try:
        r = requests.get(f"https://api.builtwith.com/free1/api.json?KEY={k}&LOOKUP={domain}")
        if r.status_code == 200:
            j = r.json()
            res = j.get("Results", [])
            if res:
                ts = [i.get("Name") for i in res[0].get("Result", []) if i.get("Name")]
                return ', '.join(ts) if ts else "none"
            return "none"
        return f"api err {r.status_code}"
    except Exception as e:
        return f"err: {e}"

def check_ssl(host):
    try:
        c = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                end = dt.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                left = (end - dt.utcnow()).days
                return f"valid ({left}d)"
    except:
        return "bad"

def rate(t):
    score = 8
    t = t.lower()
    if "outdated" in t or "vulnerable" in t:
        score -= 3
    if "unknown" in t or "no server" in t:
        score -= 2
    if "wordpress" in t:
        score -= 1
    if "apache" in t or "nginx" in t:
        score += 1
    return max(1, min(score, 10))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scanner():
    info = request.get_json()
    url = info.get('url')
    if not url:
        return "bad input"

    url = url.replace("http://", "").replace("https://", "").split("/")[0]
    hurl = "http://" + url
    surl = "https://" + url

    rep = f"Scan: {url}\n" + ("-"*55) + "\n\n"

    who = do_cmd(f"whois {url}", timeout=10)
    name = "n/a"
    ctry = "n/a"
    for l in who.splitlines():
        l = l.lower()
        if any(tag in l for tag in ["registrant name", "registrant organization", "orgname", "organization"]):
            name = l.strip()
        if "country:" in l and ctry == "n/a":
            found = re.search(r"country:\s*(\w+)", l)
            if found:
                ctry = found.group(1).upper()

    rep += f"Owner: {name}\n"
    rep += f"Country: {ctry}\n\n"

    tech = fetch_tech(url)
    rep += f"Stack: {tech}\n"

    scr = rate(tech)
    lvl = "OK" if scr >= 8 else ("Warn" if scr >= 5 else "Fail")
    rep += f"Rating: {scr}/10 [{lvl}]\n"

    cert = check_ssl(url)
    rep += f"SSL: {cert}\n"

    heads = do_cmd(f"curl -I {surl}", timeout=10)
    missing = []
    if "X-Content-Type-Options" not in heads:
        missing.append("X-Content-Type-Options")
    if "Strict-Transport-Security" not in heads:
        missing.append("Strict-Transport-Security")

    if missing:
        rep += f"Missing Headers: {', '.join(missing)}\n"
        for m in missing:
            if m == "X-Content-Type-Options":
                rep += "  - Add: nosniff\n"
            elif m == "Strict-Transport-Security":
                rep += "  - Add: max-age=31536000; includeSubDomains\n"
    else:
        rep += "Headers OK\n"

    waf = do_cmd(f"wafw00f {hurl}", timeout=15)
    rep += f"WAF: {'yes' if 'is behind' in waf else 'no'}\n"

    scan_ports = do_cmd(f"nmap --top-ports 100 {url}", timeout=20)
    open_p = [x for x in scan_ports.splitlines() if "/tcp" in x and "open" in x]
    rep += f"Ports: {len(open_p)}\n"
    if not open_p:
        rep += "Note: ports closed or filtered\n"

    rep += "\n-- Summary --\n"
    if scr >= 8:
        rep += "✓ Site looks OK\n"
    elif scr >= 5:
        rep += "~ Site has issues\n"
    else:
        rep += "✗ Site not secure\n"

    rep += "\n* This is a basic check. Confirm wwsl"
    "ith proper tools."
    return rep

if __name__ == '__main__':
    p = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=p)
