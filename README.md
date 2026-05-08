# Automated Reconnaissance and Enumeration Orchestrator

A lightweight command-line reconnaissance and enumeration orchestrator built in Python for authorised penetration testing workflows.

The tool automates repetitive early-stage reconnaissance tasks by integrating Nmap, Gobuster, and Enum4linux-ng into a single workflow. It performs initial service discovery, conditionally runs relevant enumeration tools, stores structured findings in SQLite, preserves raw outputs, and generates a consolidated reconnaissance report.

## Disclaimer

This tool is intended only for authorised penetration testing, educational use, and controlled lab environments. Do not run this tool against systems, networks, or services without explicit permission.

The project does not include exploitation, privilege escalation, credential theft, persistence, malware functionality, or post-exploitation features. It is designed to support early-stage information gathering and operator-led analysis.

## Features

- Command-line target input
- Automated Nmap scanning
- Conditional workflow logic based on discovered services
- Automatic Gobuster execution when HTTP/HTTPS services are detected
- Automatic Enum4linux-ng execution when SMB services are detected
- Optional Enum4linux-ng force-run mode
- YAML-based configuration file
- Raw output preservation for manual verification
- SQLite database storage for structured findings
- Run-based result organisation
- Report generation from current or previous runs
- Support for custom tool commands, with custom outputs preserved but excluded from structured parsing

## Tools Integrated

| Tool | Purpose |
| --- | --- |
| Nmap | Port scanning and service discovery |
| Gobuster | Web directory/resource enumeration and DNS mode support |
| Enum4linux-ng | SMB/Samba enumeration |

## Project Purpose

This project was developed as a final-year university dissertation artefact. The aim was to investigate whether a lightweight orchestrator could automate parts of early-stage reconnaissance and enumeration effectively enough to be feasible, while preserving operator control and structured output.

The tool is designed to support, not replace, the penetration tester. It automates repetitive execution and reporting tasks while keeping raw outputs available for manual review.

## How It Works

1. The user provides a target IP address, hostname, or URL.
2. The orchestrator runs Nmap unless the target is already provided as a URL.
3. Nmap output is parsed for open ports and services.
4. If HTTP/HTTPS is detected, Gobuster is triggered automatically.
5. If SMB is detected, Enum4linux-ng is triggered automatically.
6. Raw tool outputs are saved to the run directory.
7. Parsed findings are stored in SQLite.
8. A consolidated report is generated for the run.

## Demos

## Demo 1: Workspace initialisation

On first execution, the orchestrator performs a bootstrapping process to prepare the working environment. The script creates a dedicated `~/recon_orchestrator/` directory, generates the default `config.yaml` file, and sets up the required folder structure for future scan results.

After initialisation, the script exits without running any scans. This allows the user to review and modify the generated configuration file before executing reconnaissance against a target. This behaviour ensures that tool settings, scan modes, wordlists, and execution preferences can be adjusted safely before the first scan is launched.

```bash
python3 orc.py
```

<img width="1902" height="960" alt="WorkspaceDemo" src="https://github.com/user-attachments/assets/48f4701b-9a0c-4223-8cb5-dbbd64b2d5b2" />

## Demo 2: Running the Orchestrator against Metasploitable 2

This demo shows the orchestrator being executed against a Metasploitable 2 virtual machine within a controlled lab environment. The tool begins by running an Nmap scan to identify open ports and services on the target. Based on the discovered services, the orchestrator then applies conditional logic to decide which enumeration tools should be executed.

When HTTP services are detected, Gobuster is automatically triggered to perform web directory enumeration. When SMB-related services are identified, Enum4linux-ng is executed to gather SMB enumeration data. The raw outputs from each tool are saved for manual verification, while relevant findings are parsed and stored in the local SQLite database.

At the end of the run, the system generates a consolidated report containing the discovered services, web enumeration results, SMB findings, and notable issues identified during the scan.

```bash
python3 orc.py --target 192.168.56.104
```

<img width="1901" height="1052" alt="Msp2RunDemo" src="https://github.com/user-attachments/assets/99cc8980-b64e-40c7-9989-f20df5a58657" />
*Automated reconnaissance and enumeration run against Metasploitable 2 in a controlled lab environment.*
<br><br>
<br><br>
<img width="1900" height="1052" alt="Msp2ReportDemo" src="https://github.com/user-attachments/assets/009ba8e6-e70c-4b13-b8ac-12f95191a997" />
*Report generated from the run against Metasploitable 2.*

## Demo 3: Running the Orchestrator against West-Wild V-0.1

This demo shows the orchestrator being executed against the West-Wild vulnerable virtual machine in a controlled lab environment. This target was useful for demonstrating the full workflow because it exposed both web and SMB-related services, allowing the system to validate Nmap scanning, Gobuster enumeration, Enum4linux-ng enumeration, conditional execution, structured parsing, database storage, and report generation in a single run.

The orchestrator begins by running an Nmap scan to identify open ports and services. Based on the detected services, it automatically triggers Gobuster for web enumeration and Enum4linux-ng for SMB enumeration. The Enum4linux-ng results are parsed from structured JSON output, allowing SMB access, authentication details, users, supported SMB dialects, SMB signing status, and related configuration information to be stored in the SQLite database and included in the final report.

At the end of the run, the system generates a consolidated report that summarises the findings from all executed tools while preserving the raw outputs for manual verification.

<img width="1900" height="1052" alt="WestWildRunDemo" src="https://github.com/user-attachments/assets/d7ff5a2d-97f8-407d-b16d-09c1c9917cd5" />
*Full automated reconnaissance and enumeration workflow against the West-Wild vulnerable VM.*

## Demo 4: Changing the Nmap Scan Mode

This demo shows how the orchestrator can be configured without modifying the source code. The system uses a YAML configuration file that allows the user to change tool behaviour, including the scan mode used by Nmap.

In this example, the Nmap mode is changed in the configuration file before running the orchestrator against the West-Wild vulnerable virtual machine. This demonstrates the configurability of the system and shows how different scanning presets can be selected depending on the testing scenario. For example, a user may choose a regular scan for standard service detection, a stealth scan for slower and less aggressive scanning, or an aggressive scan when more detailed service and script information is required.

After the configuration is updated, the orchestrator runs using the selected Nmap mode while keeping the rest of the workflow unchanged. This allows the user to adapt the initial reconnaissance stage while still benefiting from automated conditional execution, output parsing, database storage, and report generation.

<img width="1900" height="1052" alt="ConfigEditDemo" src="https://github.com/user-attachments/assets/17d37141-815b-4ec4-bff5-ce92faf0f4c9" />
*Changing the Nmap scan mode through the YAML configuration file before running the orchestrator against West-Wild.*

## Demo 5: Reviewing Stored Workspace and Database Results

This demo shows how the orchestrator stores scan artefacts after execution. Each run is organised inside the `~/recon_orchestrator/runs/` directory using a unique run identifier, allowing raw outputs, JSON files, and generated reports to be kept together for later review.

In addition to saving raw tool outputs, the orchestrator stores parsed findings inside a local SQLite database. This allows results from Nmap, Gobuster, and Enum4linux-ng to be linked to the same run and reviewed after the scan has completed. The database supports traceability by preserving relationships between runs, individual tool executions, and extracted findings.

This demonstrates that the system does not only automate tool execution, but also preserves evidence and structured results for later analysis, verification, and report regeneration.

Note: Raw tool outputs are currently saved exactly as returned by the terminal, including ANSI escape codes. This may cause some raw scan files to appear visually inconsistent when viewed as plain text.

<img width="1900" height="1052" alt="StoredDataDemo" src="https://github.com/user-attachments/assets/a181591c-bcbc-4884-8277-60b737511463" />
*Reviewing the generated run folder containing raw tool outputs, JSON output, and the consolidated report.*
<br><br>
<br><br>
<img width="1900" height="1052" alt="DatabaseDemo" src="https://github.com/user-attachments/assets/aa87abdb-afe9-45e3-be4d-2443ad156a71" />
*Reviewing structured findings stored in the SQLite database after a completed run.*

## Demo 6: Generating a Report from a Previous Run

This demo shows how the orchestrator can regenerate a consolidated report from a previous scan using the stored run ID. Instead of re-running Nmap, Gobuster, or Enum4linux-ng, the tool retrieves the existing structured findings from the SQLite database and formats them into a readable report.

This demonstrates the benefit of storing results persistently: previous reconnaissance data can be reviewed, reused, and converted into a report without repeating the scan or generating additional network traffic.

<img width="1900" height="1052" alt="ReportDemo" src="https://github.com/user-attachments/assets/8751c64f-f4cd-4b85-841c-01059ecda452" />
*Regenerating consolidated reports from stored database findings using a previous run IDs.*

## Installation

This tool is intended to run on Kali Linux or another Linux environment with the required reconnaissance and enumeration tools installed.

### Requirements

- Python 3
- Nmap
- Gobuster
- Enum4linux-ng
- PyYAML

Install the Python dependency:

```bash
pip3 install pyyaml
```

Install the required tools:

```bash
sudo apt update
sudo apt install nmap gobuster enum4linux-ng
```

Run the orchestrator once to initialise the workspace:

```bash
python3 orc.py
```

## Usage

Run the orchestrator against an IP address or hostname:

```bash
python3 orc.py --target <ip_or_hostname>
```

Example:

```bash
python3 orc.py --target 192.168.56.104
```

Run the orchestrator against a URL for web-focused enumeration:

```bash
python3 orc.py --target http://example.local
```

Generate a report from a previous run using the stored run ID:

```bash
python3 orc.py --report <run_id>
```

Example:

```bash
python3 orc.py --report 12
```

When running a new scan, the orchestrator performs service discovery, applies conditional logic, executes relevant enumeration tools, stores parsed findings in the SQLite database, preserves raw outputs, and generates a consolidated report for the run.

## First Run Behaviour

On first execution, the orchestrator creates a working directory in the user's home folder:

```text
~/recon_orchestrator/
```

This directory contains the files and folders required for future scans:

```text
config.yaml
recon.db
runs/
```

The first run generates the default configuration file and exits before running any scans. This allows the user to review or modify the configuration before executing the orchestrator against a target.

The configuration file controls tool settings such as enabled tools, Nmap scan modes, Gobuster options, Enum4linux-ng options, wordlists, thread counts, and custom command presets.

## Configuration

The orchestrator uses a YAML configuration file located at:

```text
~/recon_orchestrator/config.yaml
```

The configuration file allows the user to modify tool behaviour without changing the source code. It can be used to:

- enable or disable tools
- select Nmap scan modes
- configure Gobuster mode, wordlist, redirects, and threads
- configure Enum4linux-ng mode
- enable Enum4linux-ng force-run mode
- define custom command presets

Example configuration excerpt:

```yaml
tools:
  nmap:
    enabled: true
    binary: nmap
    mode: regular
    presets:
      regular: "-sV -Pn"
      stealth: "-sS -T2 -Pn"
      aggressive: "-sV -sC -T4"
      udp: "-sU --top-ports 100"

  gobuster:
    enabled: true
    binary: gobuster
    mode: dir
    follow_redirect: true
    threads: 40

  enum4linux:
    enabled: true
    binary: enum4linux-ng
    mode: full
    force_run: false
```

## Output Structure

Each scan is organised by run ID inside the workspace directory:

```text
~/recon_orchestrator/runs/run_<run_id>/
```

Example run folder structure:

```text
run_12/
├── nmap_scan_<scan_id>.txt
├── gobuster_scan_<scan_id>.txt
├── enum4linux_scan_<scan_id>.txt
├── enum4linux_scan_<scan_id>.json
└── report_<run_id>.txt
```

Raw tool outputs are preserved for manual verification, while parsed findings are stored separately in the SQLite database. This allows the user to review the original scan evidence while also benefiting from structured reporting and database-backed result organisation.

## Database

Structured findings are stored in a local SQLite database:

```text
~/recon_orchestrator/recon.db
```

The database is used to organise results across multiple executions of the orchestrator. It contains three main tables:

| Table | Purpose |
| --- | --- |
| runs | Stores each execution of the orchestrator |
| scans | Stores individual tool executions linked to a run |
| findings | Stores parsed findings extracted from tool outputs |

This structure allows findings from Nmap, Gobuster, and Enum4linux-ng to be linked back to the same scan run. It also supports report regeneration, as previous results can be retrieved from the database without re-running the reconnaissance workflow.

## Evaluation Summary

The orchestrator was evaluated in a controlled virtual lab environment using vulnerable virtual machines. The evaluation compared a manual reconnaissance workflow against the automated orchestration process.

Key findings:

- Manual average execution time: approximately 2.71 minutes
- Automated average execution time: approximately 0.72 minutes
- Approximate reduction in execution time: 73.5%
- Automated workflow completed the same process nearly 3.7 times faster
- Conditional tool execution behaved consistently across repeated TCP-based tests
- Structured reporting improved readability and traceability of findings

The evaluation showed that the orchestrator can reduce repetitive manual effort while preserving raw outputs and maintaining operator control over interpretation.

## Limitations

- The tool depends on the accuracy and behaviour of Nmap, Gobuster, and Enum4linux-ng.
- Service detection is based primarily on scan output and may miss unusual configurations, filtered services, or services running on non-standard ports.
- Custom command outputs are preserved as raw files but are not automatically parsed into the SQLite database.
- The current report highlights selected notable issues but does not perform advanced severity ranking or contextual risk scoring.
- The SQLite database is not currently encrypted, so stored scan results should be handled carefully.
- Testing was conducted in controlled lab environments and may not represent the full complexity of real-world networks.

These limitations are important because the orchestrator is designed to support reconnaissance and enumeration, not replace human judgement or full penetration testing methodology.

## Future Work

Planned or possible improvements include:

- Encrypting stored scan results
- Adding password-based access control using secure salted hashing
- Integrating additional tools such as Nikto and Searchsploit
- Improving service detection and custom trigger logic
- Adding severity ranking, confidence levels, and clearer prioritisation to reports
- Supporting user-defined parsing rules for custom commands
- Considering a lightweight GUI or dashboard for easier result navigation
- Testing across a wider range of target environments

Future development would focus on improving security, flexibility, and analytical value while keeping the tool lightweight and operator-controlled.

## Author

Alexandru Constantin

Final Year Project — Automated Reconnaissance and Enumeration Orchestrator
