import subprocess
from pathlib import Path
from datetime import datetime as date
import sqlite3
import sys
import argparse
import yaml
import re
import json

# Assigning timestamp a variable
timestamp = date.now().strftime("%Y-%m-%d_%H-%M-%S")

                                                    #Bootstrapping the script

# Creating directories
base = Path.home() / "recon_orchestrator"
(base / "runs").mkdir(parents=True, exist_ok=True)

# Creating database file or connecting to it
conn = sqlite3.connect(f"{base}/recon.db") 
c = conn.cursor() # Connecting cursor

# Creating tables
c.execute('''
    CREATE TABLE IF NOT EXISTS runs (
          run_id INTEGER PRIMARY KEY AUTOINCREMENT,
          target TEXT NOT NULL,
          timestamp DATETIME NOT NULL
          )
''')
c.execute('''
    CREATE TABLE IF NOT EXISTS scans (
          scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id INTEGER NOT NULL,
          tool TEXT NOT NULL,
          target TEXT NOT NULL,
          timestamp DATETIME NOT NULL,
          FOREIGN KEY (run_id) REFERENCES runs(run_id)
          )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id INTEGER NOT NULL,
          run_id INTEGER NOT NULL,
          tool TEXT NOT NULL,
          type TEXT NOT NULL,
          item TEXT NOT NULL,
          value TEXT NOT NULL,
          extra TEXT,
          FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
          FOREIGN KEY (run_id) REFERENCES runs(run_id)
     )    
''')
conn.commit()

if not (base / "config.yaml").is_file():
    with open(f"{base}/config.yaml", "w") as file:
        file.write('''tools:
    nmap:
        enabled: true
        binary: nmap
        mode: regular  # stealth | regular | aggressive | udp | custom
        presets:
            stealth: "-sS -T2 -Pn"
            regular: "-sV -Pn"
            aggressive: "-sV -sC -T4" # this mode yields more information but it's loud and easily detectable
            udp: "-sU --top-ports 100"
            custom: "" # Add your custom command between the quotation marks if you wish to use it
    gobuster:
        enabled: true
        binary: gobuster
        mode: dir  # dir | dns | custom
        follow_redirect: true
        threads: 40  # Changing this will affect the speed/accuracy of the scan. 10-20 = slow but safe, 30-50 = regular, 50+ fast but can drop accuracy
        presets:
            dir:
                args: "dir -x php,txt,html"
                wordlist: "/usr/share/wordlists/dirb/common.txt"
            dns:
                args: "dns"
                wordlist: "/usr/share/wordlists/dnsmap.txt"
            custom:
                args: ""   # Include wordlist and target
    enum4linux:
        enabled: true
        binary: enum4linux-ng
        mode: full  # full | custom
        force_run: false  # Run even if SMB is not detected during Nmap scan
        presets:
            full: "-A"
            custom: ""
''')
        print("[*] Bootstrapping the script for first time use......")
        print(f"[+] The script has been initialized, the working directory of the script is: {base}")
        print("[!] Navigate to the directory and locate the config.yaml file")
        print("[!] Modify the config.yaml file to suit your needs, then re-run the script to begin scanning.")
        print("No scans have been run yet")
        sys.exit(0)

# CLI arguments
parser = argparse.ArgumentParser(description="Automated Recon Orchestration", usage=" [-h] | [python3 orc.py --target <ip_or_host>] | [python3 orc.py --report <run_id>]")
parser.add_argument("--target", help="Target IP address or hostname (URL only required if Nmap is disabled)")
parser.add_argument("--report", type=int, help="Generate report for an existing run_id without running new scans")
args = parser.parse_args()
target = args.target
report_id = args.report

if target and " " in target:
    print("Error: You can only scan 1 target at a time")
    sys.exit(1)

if report_id is None and not target:
    print("Error: --target is required unless you are using --report")
    sys.exit(1)

if report_id is not None and target:
    print("Error: Use either --target or --report, not both")
    sys.exit(1)

# YAML Config parsing
with open(f"{base}/config.yaml") as f:
    config = yaml.safe_load(f)

nmap_cfg = config["tools"]["nmap"]
gobuster_cfg = config["tools"]["gobuster"]
enum4linux_cfg = config["tools"]["enum4linux"]

# Nmap scan function
def nmap_run(target, run_id):
    # Checking config file for Nmap settings
    if not nmap_cfg["enabled"]:
        print("[!] Nmap will be skipped during this scan as it's disabled!")
        return None, None
    if nmap_cfg["enabled"] and not target.startswith("http"):
        binary = nmap_cfg["binary"]
        mode = nmap_cfg["mode"]

        if mode == "custom":
            arguments = nmap_cfg["presets"]["custom"]
            command = [binary] + arguments.split() + [target]
            print("[!] Custom Nmap command executed. Output captured but excluded from automated parsing.")

            result = subprocess.run(command, capture_output=True, text=True) # Capturing the result of the ran command in a variable

            c.execute(
                "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
                (run_id, "nmap", target, date.now().isoformat())
            )
            conn.commit()
            scan_id = c.lastrowid

            with open(f"{base}/runs/run_{run_id}/nmap_scan_{scan_id}.txt", "w") as file:
                file.write(result.stdout)

            print(result.stdout)
            return None, scan_id  # Skip Parsing

        # Normal Modes
        arguments = nmap_cfg["presets"][mode]
        command = [binary] + arguments.split() + [target]

        result = subprocess.run(command, capture_output=True, text=True)

        # Storing scan info in database
        c.execute(
            "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
            (run_id, "nmap", target, date.now().isoformat())
        )
        conn.commit()
        scan_id = c.lastrowid

        # Storing the raw output of the Nmap scan in a file
        with open (f"{base}/runs/run_{run_id}/nmap_scan_{scan_id}.txt", "w") as file:
            file.write(f"{result.stdout}")

        # Returning output
        print (result.stdout)
        return result.stdout, scan_id

    if target.startswith("http"):
        print("[!] Nmap will be skipped during this scan as an URL was detected in the target argument.")
        return None, None

# Parsing the output of the Nmap scan
def parse_nmap(output, scan_id, run_id):
    if nmap_cfg["enabled"] and target.startswith("http") == False:
        http_ports = []
        smb = False

        if output is None:
            return [], False
        for line in output.splitlines():
            if line and line[0].isdigit():
                parsed_lines = line.split()
                port = parsed_lines[0]
                state = parsed_lines[1]
                service = parsed_lines[2]
                version = " ".join(parsed_lines[3:]) if len(parsed_lines) > 3 else None
                # DB inserts
                c.execute(
                    "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, run_id, "nmap", "port", port, state, None)
                )
                c.execute(
                    "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, run_id, "nmap", "service", port, service, version)
                )

                # Extracting gobuster targets
                if service == "http" or service == "https":
                    http_ports.append({"port": str(port), "service": service})
                # Identifying SMB for Enum4linux targets
                if port.startswith("139") or port.startswith("445"):
                    smb = True

        conn.commit()
        return http_ports, smb
    return [], False

def gobuster_run(target, http_ports, run_id):
    if not gobuster_cfg["enabled"]:
        print("[!] Gobuster will be skipped during this scan as it's disabled!")
        return None
    if gobuster_cfg["enabled"]:
        if not http_ports and not target.startswith("http") and gobuster_cfg["mode"] != "dns":
            print("[!] No HTTP targets detected and no URL provided in target argument — skipping Gobuster...")
            return None
        # Config parsing
        binary = gobuster_cfg["binary"]
        mode = gobuster_cfg["mode"]
        arguments = gobuster_cfg["presets"][mode]["args"]
        if not mode == "custom":
            wordlist = gobuster_cfg["presets"][mode]["wordlist"]
        threads = str(gobuster_cfg["threads"])
        redirect = []
        results = []
        if gobuster_cfg["follow_redirect"]:
            redirect = ["-r"]
        # Using ports discovered from Nmap in a dir / custom scan
        if http_ports and not mode == "dns":
            for entry in http_ports:
                port = entry["port"].split("/")
                service = entry["service"]
                url = (f"{service}://{target}:{port[0]}")
                if mode == "dir":
                    command = [binary] + arguments.split() + redirect + ["-w"] + [wordlist] + ["-t"] + [threads] + ["-u"] + [url] + ["--no-color"]
                elif mode == "custom":
                    command = [binary] + arguments.split() + ["--no-color"]
                    print("[!] Custom Gobuster command executed. Output captured but excluded from automated parsing and correlation.")

                print("\n[+] HTTP/S detected, running Gobuster against targets....")
                result = subprocess.run(command, capture_output=True, text=True)

                # Storing scan info in the database
                c.execute(
                    "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
                    (run_id, "gobuster", url, date.now().isoformat())
                )
                scan_id = c.lastrowid

                results.append({"scan_id": scan_id, "output": result.stdout})
                
                print(result.stdout)
                with open (f"{base}/runs/run_{run_id}/gobuster_scan_{scan_id}.txt", "w") as file:
                    file.write(result.stdout)

            conn.commit()
        
        # Scans where the target is already a URL so Nmap isn't needed
        elif target.startswith("http") and not mode == "dns":
                if mode == "dir":
                    command = [binary] + arguments.split() + redirect + ["-w"] + [wordlist] + ["-t"] + [threads] + ["-u"] + [target] + ["--no-color"]
                elif mode == "custom":
                    command = [binary] + arguments.split() + ["--no-color"]
                    print("[!] Custom Gobuster command executed. Output captured but excluded from automated parsing and correlation.")
                
                result = subprocess.run(command, capture_output=True, text=True)

                c.execute(
                    "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
                    (run_id, "gobuster", target, date.now().isoformat())
                )
                scan_id = c.lastrowid

                results.append({"scan_id": scan_id, "output": result.stdout})

                with open (f"{base}/runs/run_{run_id}/gobuster_scan_{scan_id}.txt", "w") as file:
                    file.write(result.stdout)
                print(result.stdout)
        
        elif mode == "custom":
            command = [binary] + arguments.split() + ["--no-color"]
            print("[!] Custom Gobuster command executed. Output captured but excluded from automated parsing and correlation.")
            result = subprocess.run(command, capture_output=True, text=True)
            c.execute(
                "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
                (run_id, "gobuster", target, date.now().isoformat())
            )
            scan_id = c.lastrowid

            with open (f"{base}/runs/run_{run_id}/gobuster_scan_{scan_id}.txt", "w") as file:
                file.write(result.stdout)
            print(result.stdout)
            print(result.stderr)

        # DNS scans
        if mode == "dns":
            if target.startswith("http"):
                print("[!] DNS mode is set and for such scan you must provide a domain not an URL. -- Gobuster skipped...")
                return None

            command = [binary] + [arguments] + ["-w"] + [wordlist] + ["-d"] + [target] + ["-t"] + [threads] + ["--no-color"]
            result = subprocess.run(command, capture_output=True, text=True)

            # Storing scan info in the database
            c.execute(
                "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
                (run_id, "gobuster", target, date.now().isoformat())
            )
            scan_id = c.lastrowid

            results.append({"scan_id": scan_id, "output": result.stdout})
                
            print(result.stdout)
            with open (f"{base}/runs/run_{run_id}/gobuster_scan_{scan_id}.txt", "w") as file:
                file.write(result.stdout)
        
        
        conn.commit()

    if mode == "custom":
        return []
    else:
        return results

def parse_gobuster(output, run_id):
    if gobuster_cfg["enabled"] and output:
        ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
        for scan in output:
            scan_id = scan["scan_id"]
            raw_output = scan["output"]
            for line in raw_output.splitlines():
                clean_line = ANSI_ESCAPE.sub("", line).strip()
                if clean_line.startswith("/"):
                    parsed_lines = clean_line.split()
#                    print (parsed_lines)
                    item = parsed_lines[0]
                    value = " ".join(parsed_lines[1:3])
                    extra = " ".join(parsed_lines[3:])

                    c.execute(
                        "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (scan_id, run_id, "gobuster", "path", item, value, extra)
                    )
                elif clean_line.startswith("Found"):
                    parsed_lines = clean_line.split()
#                    print (parsed_lines)
                    value = parsed_lines[1]

                    c.execute(
                        "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (scan_id, run_id, "gobuster", "dns_subdomain", target, value, None)
                    )
            conn.commit()

def run_enum4linux(target, smb, run_id):
    if not enum4linux_cfg["enabled"]:
        print("[!] Enum4Linux will be skipped during this scan as it's disabled!")
        return None, None, None

    binary = enum4linux_cfg["binary"]
    mode = enum4linux_cfg["mode"]
    arguments = enum4linux_cfg["presets"][mode]
    force_run = enum4linux_cfg["force_run"]

    if nmap_cfg["enabled"] and not (smb or force_run):
        print("[!] No SMB services detected — skipping Enum4linux...")
        print("[*] Note: In rare cases, SMB services may not be detected if not exposed on standard ports (139/445).")
        print("[*] Note: Enable 'force_run' in the configuration file to override this.")
        return None, None, None

    c.execute(
        "INSERT INTO scans (run_id, tool, target, timestamp) VALUES (?, ?, ?, ?)",
        (run_id, "enum4linux-ng", target, date.now().isoformat())
    )
    scan_id = c.lastrowid

    command = [binary] + arguments.split() + [target] + ["-oJ", f"{base}/runs/run_{run_id}/enum4linux_scan_{scan_id}"]

    print("\n[+] SMB detected (or force run toggled on), running Enum4linux-ng against targets....")
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)

    with open(f"{base}/runs/run_{run_id}/enum4linux_scan_{scan_id}.txt", "w") as file:
        file.write(result.stdout)

    if mode == "custom":
        print("[!] Custom Enum4Linux-ng command executed. Output is captured but excluded from automated parsing and corrrelation!")
        conn.commit()
        return None, None, None

    conn.commit()
    return result.stdout, scan_id, mode

def parse_enum4linux(data, scan_id, scan_mode, run_id):
    if enum4linux_cfg["enabled"] and not scan_mode == "custom":
        # Listeners parsing
        listeners = data.get("listeners", {})
        for service_name, service_data in listeners.items():
            if service_name not in ("SMB", "SMB over NetBIOS"):
                continue
            port = service_data.get("port")
            accessible = service_data.get("accessible")
            value = "accessible" if accessible else "inaccessible"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_listener", f"port_{port}", value, service_name)
            )

        # SMB dialects
        smb_dialects = data.get("smb_dialects", {})
        if not isinstance(smb_dialects, dict):
            smb_dialects = {}

        # Supported dialects
        supported = smb_dialects.get("Supported dialects", {})
        if not isinstance(supported, dict):
            supported = {}

        for dialect, enabled in supported.items():
            value = "true" if enabled else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_dialect", dialect, value, "supported")
            )

        preferred = smb_dialects.get("Preferred dialect")
        if preferred:
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_dialect", "preferred", str(preferred), None)
            )

        smb1_only = smb_dialects.get("SMB1 only")
        if smb1_only is not None:
            value = "true" if smb1_only else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_dialect", "smb1_only", value, None)
            )

        signing = smb_dialects.get("SMB signing required")
        if signing is not None:
            value = "true" if signing else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_dialect", "smb_signing_required", value, None)
            )

        # Also record whether SMB signing is required
        signing_required = smb_dialects.get("SMB signing required")
        if signing_required is not None:
            value = "true" if signing_required else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_configuration", "smb_signing_required", value, None)
            )

        # Sessions
        sessions = data.get("sessions", {})
        # Sessions possible
        sessions_possible = sessions.get("sessions_possible")
        if sessions_possible is not None:
            value = "true" if sessions_possible else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_sessions", "sessions_possible", value, None)
            )

        # Null sessions
        null_sessions = sessions.get("null")
        if null_sessions is not None:
            value = "true" if null_sessions else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_sessions", "null_sessions", value, None)
            )

        # passwords
        passwords = sessions.get("passwords")
        if passwords is not None:
            value = "true" if passwords else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_sessions", "passwords", value, None)
            )

        # Kerberos
        kerberos = sessions.get("Kerberos")
        if kerberos is not None:
            value = "true" if kerberos else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_sessions", "kerberos", value, None)
            )

        # NTLM
        ntlm = sessions.get("NTLM")
        if ntlm is not None:
            value = "true" if ntlm else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_sessions", "ntlm", value, None)
            )

        # Guest sessions
        guest = sessions.get("guest")
        if guest is not None:
            value = "true" if guest else "false"
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_sessions", "guest", value, None)
            )

        # Users
        users = data.get("users", {})
        for rid, user_data in users.items():
            username = user_data.get("username")
            name = user_data.get("name")
            acb = user_data.get("acb")
            description = user_data.get("description")
            if not username:
                continue
            extra_parts = [f"rid={rid}"]
            if name:
                extra_parts.append(f"name={name}")
            if acb:
                extra_parts.append(f"acb={acb}")
            if description:
                extra_parts.append(f"description={description}")
            extra = ";".join(extra_parts)
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_users", "users", username, extra)
            )

        # Shares
        shares = data.get("shares", {})
        for share_name, share_data in shares.items():
            share_type = share_data.get("type")
            comment = share_data.get("comment")
            access = share_data.get("access", {})
            mapping_access = access.get("mapping")
            listing_access = access.get("listing")

            extra_parts = []
            if share_type:
                extra_parts.append(f"share_type={share_type}")
            if comment:
                extra_parts.append(f"comment={comment}")
            if mapping_access:
                extra_parts.append(f"mapping_access={mapping_access}")
            if listing_access:
                extra_parts.append(f"listing_access={listing_access}")
            extra = ";".join(extra_parts) if extra_parts else None
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_share", "name", share_name, extra)
            )

        # Policy
        policy = data.get("policy", {})
        pass_data = policy.get("Domain password information", {})
        lockout_data = policy.get("Domain lockout information", {})

        # Minimum password length
        pass_length = pass_data.get("Minimum password length")
        if pass_length is not None:
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_policy", "pass_length", str(pass_length), None)
            )

        # Password properties
        password_property_map = {
            "DOMAIN_PASSWORD_COMPLEX": "pass_complexity",
            "DOMAIN_PASSWORD_NO_ANON_CHANGE": "no_anon_change",
            "DOMAIN_PASSWORD_NO_CLEAR_CHANGE": "no_clear_change",
            "DOMAIN_PASSWORD_LOCKOUT_ADMINS": "lockout_admins",
            "DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT": "store_cleartext",
            "DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE": "refuse_password_change"
        }

        properties = pass_data.get("Password properties", [])

        for prop in properties:
            for raw_key, raw_value in prop.items():
                item = password_property_map.get(raw_key)
                if item is None:
                    continue

                value = "true" if raw_value else "false"
                c.execute(
                    "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, run_id, "enum4linux-ng", "smb_policy", item, value, raw_key)
                )

        # Lockout observation window
        lockout_observation_window = lockout_data.get("Lockout observation window")
        if lockout_observation_window is not None:
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_policy", "lockout_observation_window", str(lockout_observation_window), None)
            )

        # Lockout duration
        lockout_duration = lockout_data.get("Lockout duration")
        if lockout_duration is not None:
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_policy", "lockout_duration", str(lockout_duration), None)
            )

        # Lockout threshold
        lockout_threshold = lockout_data.get("Lockout threshold")
        if lockout_threshold is not None:
            c.execute(
                "INSERT INTO findings (scan_id, run_id, tool, type, item, value, extra) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, run_id, "enum4linux-ng", "smb_policy", "lockout_threshold", str(lockout_threshold), None)
            )

        conn.commit()
        
TEST_run_id = 10

# Generate report function
def generate_report(run_id):
    # Make a list to put together the report
    sections = []

    sections.append("\n=== RECON REPORT ===")
    sections.append(f"Run ID: {run_id}")
    sections.append(f"Generated: {date.now().isoformat()}")
    sections.append("")

    # Retrieve data from the database
    c.execute(
        "SELECT type, item, value, extra FROM findings WHERE run_id = ? AND tool = 'nmap'",
        (run_id,)
    )
    nmap_data = c.fetchall()
    c.execute(
        "SELECT type, item, value, extra FROM findings WHERE run_id= ? AND tool = 'gobuster'",
        (run_id,)
    )
    gobuster_data = c.fetchall()
    c.execute(
        "SELECT type, item, value, extra FROM findings WHERE run_id = ? AND tool = 'enum4linux-ng'",
        (run_id,)
    )
    enum4linux_data = c.fetchall()

    # Generate Nmap section
    ports = build_nmap_structure(nmap_data)
    sections.append(format_nmap_section(ports))

    # Generate Gobuster section
    results = build_gobuster_structure(gobuster_data)
    sections.append(format_gobuster_section(results))

    # Generate Enum4Linux section
    enum_data = build_enum4linux_structure(enum4linux_data)
    sections.append(format_enum4linux_section(enum_data))

    # Generate Notable Issues section
    issues = build_notable_issues(nmap_data, gobuster_data, enum4linux_data)
    sections.append(format_notable_issues_section(issues))

    return "\n".join(sections)

# Function to structure the Nmap data and put it together
def build_nmap_structure(nmap_data):
    ports = {}

    for entry in nmap_data:
        finding_type, item, value, extra = entry

        if finding_type == "port":
            ports[item] = {"state": value, "service": None, "version": None}

        elif finding_type == "service":
            if item not in ports:
                ports[item]: {}

            ports[item]["service"] = value
            ports[item]["version"] = extra

    return ports

# Function to format the Nmap data and add it to a list for re-usability
def format_nmap_section(nmap_data):
    lines = []
    lines.append("=== NMAP RESULTS ===")
    lines.append("")

    open_ports = []
    open_filtered_ports = []

    for port, data in nmap_data.items():
        state = data.get("state")
        service = data.get("service")
        version = data.get("version")

        line = f"- {port}"
        if service:
            line += f" → {service}"
        if version:
            line += f" ({version})"

        if state == "open":
            open_ports.append(line)
        elif state == "open|filtered":
            open_filtered_ports.append(line)

    if open_ports:
        lines.append("[+] Open Ports & Services")
        lines.extend(open_ports)
        lines.append("")

    if open_filtered_ports:
        lines.append("[+] Open|Filtered Ports & Services")
        lines.extend(open_filtered_ports)
        lines.append("")

    if not open_ports and not open_filtered_ports:
        lines.append("[!] No open or open|filtered ports identified.")
        lines.append("")

    return "\n".join(lines)

# Function to structure the Gobuster data and put it together
def build_gobuster_structure(gobuster_data):
    results = {"200": [], "301": [], "302": [], "403": [], "other": []}
    for entry in gobuster_data:
        finding_type, item, value, extra = entry

        if finding_type != "path":
            continue
        
        path = item

        # Extract status code
        status = value.replace("(Status:", "").replace(")", "").strip()
        if status in results:
            results[status].append((path, extra))
        else:
            results["other"].append((path, status, extra))

    return results

# Function to format the Gobuster data and add it to a list for re-usability
def format_gobuster_section(results):
    lines = [] # Initiliaze the list

    lines.append("=== GOBUSTER RESULTS ===")
    lines.append("")

    if not any(results.values()):
        lines.append("[!] No Gobuster findings found")
        lines.append("")
        return "\n".join(lines)

    # 200 (OK) - Most important
    if results["200"]:
        lines.append("[+] Accessible Endpoints")
        for path, extra in results["200"]:
            lines.append(f"- {path} → 200 OK {extra}")
        lines.append("")

    # 403 - Significant in pentesting
    if results["403"]:
        lines.append("[!] Restricted (403) -- interesting for bypassing/testing")
        for path, _ in results["403"]:
            lines.append(f"- {path}")
        lines.append("")

    # Redirects
    if results["301"] or results["302"]:
        lines.append("[*] Redirects")
        for code in ["301", "302"]:
            for path, extra in results[code]:
                lines.append(f"- {path} → {code} {extra}")
        lines.append("")

    return "\n".join(lines)

# Function to structure the Enum4linux data and put it together
def build_enum4linux_structure(enum4linux_data):
    data = {"smb_access": [], "auth": [], "users": [], "shares": [], "policy": []}
    for finding_type, item, value, extra in enum4linux_data:
        if finding_type in ("smb_listener", "smb_protocol", "smb_dialect", "smb_configuration"):
            data["smb_access"].append((finding_type, item, value, extra))

        elif finding_type == "smb_sessions":
            data["auth"].append((item, value, extra))
        elif finding_type == "smb_users":
            data["users"].append((item, value, extra))
        elif finding_type == "smb_share":
            data["shares"].append((item, value, extra))
        elif finding_type == "smb_policy":
            data["policy"].append((item, value, extra))

    return data

# Function to format the Enum4linux data and add it to a list for re-usability
def format_enum4linux_section(data):
    lines = [] # Initialize the list

    lines.append("=== ENUM4LINUX RESULTS ===")
    lines.append("")

    if not any(data.values()):
        lines.append("[!] No Enum4Linux findings found")
        lines.append("")
        return "\n".join(lines)
    
    if data["smb_access"]:
        lines.append("[+] SMB Access")
        for finding_type, item, value, extra in data["smb_access"]:
            lines.append(f"- {item}: {value}")
        lines.append("")

    if data["auth"]:
        lines.append("[+] Authentication")
        for item, value, _ in data["auth"]:
            lines.append(f"- {item}: {value}")
        lines.append("")

    if data["users"]:
        lines.append("[+] Users")
        for _, value, extra in data["users"]:
            lines.append(f"- {value}")
        lines.append("")

    if data["shares"]:
        lines.append("[+] Shares")
        for _, value, extra in data["shares"]:
            lines.append(f"- {value} ({extra})")
        lines.append("")

    if data["policy"]:
        lines.append("[+] Policy")
        for item, value, _ in data["policy"]:
            lines.append(f"- {item}: {value}")
        lines.append("")

    return "\n".join(lines)

# Function to structure the most important data and put it together
def build_notable_issues(nmap_data, gobuster_data, enum4linux_data):
    issues = []

    for finding_type, item, value, extra in enum4linux_data:
        if finding_type == "smb_configuration" and item == "smb_signing_required" and value == "false":
            issues.append("- SMB signing is not required")
        elif finding_type == "smb_sessions" and item == "null_sessions" and value == "true":
            issues.append("- Null session access is allowed")
        elif finding_type == "smb_sessions" and item == "guest" and value == "true":
            issues.append("- Guest access is allowed")
        elif finding_type == "smb_policy" and item == "pass_complexity" and value == "false":
            issues.append("- Password complexity is disabled")
        elif finding_type == "smb_policy" and item == "pass_length":
            try:
                if int(value) < 8:
                    issues.append(f"- Minimum password length is weak ({value})")
            except ValueError:
                pass
        elif finding_type == "smb_policy" and item == "lockout_threshold" and str(value).lower() == "none":
            issues.append("- No account lockout threshold is configured")
        elif finding_type == "smb_share" and extra:
            if "mapping_access=ok" in extra or "listing_access=ok" in extra:
                issues.append(f"- Accessible SMB share discovered: {value}")

    for finding_type, item, value, extra in gobuster_data:
        if finding_type == "path":
            if item == "/server-status":
                issues.append("- Apache server-status endpoint discovered")
            elif item in ("/.htaccess", "/.htpasswd"):
                issues.append(f"- Sensitive file path discovered: {item}")

    return issues

# Function to format the important data and add it to a list for re-usability
def format_notable_issues_section(issues):
    lines = [] # Initialize the list
    lines.append("### NOTABLE ISSUES ###")
    lines.append("")

    if not issues:
        lines.append("[!] No notable issues automatically identified")
        lines.append("")
        return "\n".join(lines)

    for issue in issues:
        lines.append(issue)

    lines.append("")
    return "\n".join(lines)

# Generate report from the --report CLI argument
if report_id is not None:
    report_text = generate_report(report_id)
    print(report_text)

    with open(f"{base}/runs/run_{report_id}/report.txt", "w") as file:
        file.write(report_text)

    conn.close()
    sys.exit(0)

# Execute scan mode if --report wasn't used
if report_id is None:
    c.execute(
        "INSERT INTO runs (target, timestamp) VALUES (?, ?)",
        (target, date.now().isoformat())
    )
    run_id = c.lastrowid
    conn.commit()

    (base / "runs" / f"run_{run_id}").mkdir(parents=True, exist_ok=True)
    print(f"Initiliazing script... run_id:{run_id}")

    output, scan_id = nmap_run(target, run_id)
    http_ports, smb = parse_nmap(output, scan_id, run_id)

    output = gobuster_run(target, http_ports, run_id)
    parse_gobuster(output, run_id)

    output, scan_id, scan_mode = run_enum4linux(target, smb, run_id)

    if scan_id is not None:
        with open(f"{base}/runs/run_{run_id}/enum4linux_scan_{scan_id}.json") as f:
            data = json.load(f)

        parse_enum4linux(data, scan_id, scan_mode, run_id)

    report_text = generate_report(run_id)
    print(report_text)

    with open(f"{base}/runs/run_{run_id}/report_{run_id}.txt", "w") as file:
        file.write(report_text)
    print (f"The report with run_id: {run_id} has been generated at: '{base}/runs/run_{run_id}/report_{run_id}.txt'")

conn.close()