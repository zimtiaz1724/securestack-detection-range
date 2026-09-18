# securestack-detection-range

securestack-detection-range

This project serves as a hands-on lab for Detection and Response engineering. It maps observed activity to MITRE ATT&CK techniques by associating events captured in the lab with technique IDs. The project is implemented on AWS, and the brain of the lab is the SIEM (Elastic Stack) with Elastic Agents configured on Windows and Ubuntu victim hosts.

Windows and Linux store log events natively, but they are not granular enough for detection work. Sysmon (Windows) and auditd (Linux) write rich, detection-ready events into their own channels. Those events are forwarded to the SIEM, where they are normalized into one schema (ECS) and become queryable within seconds. The current state of the lab is telemetry coverage — the data that could reveal attacker techniques is collected and verified. Detection rules that alert on that data are the next phase (see Roadmap).

Communication between the Elastic Agents and the SIEM happens on two channels:

Control channel (port 8220) — agents check in with Fleet Server for policy updates.
Data channel (port 9200) — agents ship collected events directly to Elasticsearch over TLS.
Architecture
SIEM host
sg-victims
policy check-in :8220
policy check-in :8220
events :9200 TLS
events :9200 TLS
isolated
win-victim-01Sysmon + Elastic Agent
linux-victim-01auditd + Elastic Agent
Fleet Server :8220
Elasticsearch :9200
Kibana :5601
splunk-01BOTS practice range
Host	Role	OS	Key software
siem-01	SIEM: storage, search, fleet management	Ubuntu 24.04	Elasticsearch 9.x, Kibana, Fleet Server
win-victim-01	Windows victim / telemetry source	Windows Server 2022	Sysmon (community config), Elastic Agent
linux-victim-01	Linux victim / telemetry source	Ubuntu 24.04	auditd (custom rules), Elastic Agent
splunk-01	SPL practice range (isolated from the pipeline)	Ubuntu 24.04	Splunk Enterprise trial, BOTS v1 dataset
Telemetry sources

Windows (win-victim-01):

Sysmon with a community-maintained config — process creation (EID 1) with full command line, hashes, and parent lineage; network connections (EID 3); file creation (EID 11); registry (EID 13); DNS (EID 22)
PowerShell Operational channel — script block logging (EID 4104)
Windows Security / System / Application channels

Linux (linux-victim-01):

auditd with hand-written rules (detection.rules):
execve syscall pair (b64 and b32 — a 64-bit-only rule can be evaded by compiling a tool 32-bit)
file watches on /etc/passwd, /etc/shadow, /etc/sudoers, and cron paths, each tagged with a searchable key (proc_exec, cred_access, priv_esc, persistence)
Example events

Windows — ipconfig /all, captured as Sysmon EID 1 (trimmed):

event.code:             1
event.dataset:          windows.sysmon_operational
process.command_line:   "C:\Windows\system32\ipconfig.exe" /all
process.parent.name:    powershell.exe
user.name:              Administrator
rule.name:              technique_id=T1016,technique_name=System Network Configuration Discovery

The parent-child lineage (PowerShell spawning ipconfig) and the full command line are what make this event detection-ready. The technique tag comes from the Sysmon config and is treated as a hint, not an answer — see Design decisions.

Linux — sudo cat /etc/shadow, captured by the auditd file watch (trimmed):

auditd.log.SYSCALL:     openat
auditd.log.key:         cred_access
auditd.log.success:     true
process.name:           cat
user.effective.name:    root
user.audit.name:        ubuntu

The two identity fields tell the attribution story: sudo elevated the process to root (user.effective.name), but the audit identity (user.audit.name) still names the human who logged in. Attribution survives privilege escalation.

ATT&CK coverage (telemetry)

Method: run a benign instance of a real technique on each host, find the event in Kibana, and record command → sensor event → ATT&CK data component → technique. A technique is only marked covered if a real event proves it.

Command	Host	Sensor event	Data component	Technique
whoami	Windows	Sysmon EID 1	Process Creation, Command Execution	T1033 System Owner/User Discovery
net user	Windows	Sysmon EID 1	Process Creation, Command Execution	T1087.001 Local Account Discovery¹
ipconfig /all	Windows	Sysmon EID 1	Process Creation, Command Execution	T1016 System Network Config Discovery
powershell -Command "Get-Process..."	Windows	Sysmon EID 1 + PowerShell 4104	+ Script Execution	T1059.001 PowerShell (action: T1057)
id	Linux	auditd execve (proc_exec)	Process Creation, Command Execution	T1033 System Owner/User Discovery
cat /etc/passwd	Linux	auditd execve (proc_exec)²	Process Creation, Command Execution	T1087.001 Local Account Discovery
uname -a	Linux	auditd execve (proc_exec)	Process Creation, Command Execution	T1082 System Information Discovery
sudo cat /etc/shadow	Linux	auditd file watch (cred_access) + execve	File Access	T1003.008 /etc/passwd and /etc/shadow

¹ The Sysmon config tagged this event T1018 Remote System Discovery. That tag is wrong for this invocation — net user run bare lists local accounts. Corrected to T1087.001. Technique tags are verified, not trusted.

² No file-access record for reads of /etc/passwd — by design. The file is world-readable and read constantly; auditing its reads would be noise. It is watched for writes only.

Full coverage layer: coverage-telemetry-w1.json (ATT&CK Navigator layer — score 1 = telemetry present, no detections yet) and the rendered matrix: coverage-telemetry-w1.svg.

Known blind spot: [FILL IN — the technique you left dark and why, e.g. "T1040 Network Sniffing — no packet-capture sensor in the lab" or "cloud techniques — no CloudTrail ingestion until the cloud phase"]

Design decisions
Elasticsearch (9200) and Kibana (5601) are never internet-exposed. Services listen broadly; security groups restrict narrowly. Exposed Elasticsearch APIs are among the most-scanned and most-breached services on the internet.
Security-group referencing for the delivery path. The SIEM's group allows 8220/9200 with source = sg-victims (the group itself, not IPs) — every future victim inherits delivery rights by membership, with no IP bookkeeping.
Fleet output points at the SIEM's private IP, never localhost. Fleet settings are copied into every agent's policy, and each agent resolves "localhost" to itself — a remote agent told to deliver to localhost delivers to itself forever while reporting healthy.
Technique tags are hints, not answers. The Sysmon config pre-stamps ATT&CK IDs per rule; they break on multi-tool binaries (see the corrected net user row). Every mapping in the coverage table was verified against what the command actually did.
Audit reads only where reads are rare. /etc/shadow reads are signal (nothing but the auth stack should read it); /etc/passwd reads are noise (world-readable by design). The ruleset encodes that judgment.
No service runs as root. Splunk refused to run as root — correctly: a SIEM is a parser fed attacker-influenced input, and parser bugs execute as the service identity. All services run as dedicated users under systemd; daily Kibana work uses a named admin account, not the built-in superuser.
Splunk lives on its own instance. Two memory-hungry platforms sharing one host destabilize both, and separation lets each run (and bill) independently.
Cost controls: all instances stop when idle; AWS budget alerts at 50/80/100%.
Known limitations
The Fleet control channel (8220) runs with certificate verification disabled (--insecure) because quick-start Fleet Server self-signs. Lab-only trade-off; the data channel (9200) remains CA-verified. Production issues Fleet Server a certificate from a known CA.
Single-node Elasticsearch: cluster health is permanently yellow (replicas have no second node), and there is no redundancy. Fine for a lab, never for production.
This is telemetry coverage, not detection coverage — no rules alert on anything yet.
No network sensor (packet capture / IDS) and no cloud log ingestion yet — both are roadmap items.
Coverage decays silently as configs drift; the map is only as true as its last re-validation.
Field notes

Debugging lessons preserved from the build:

An x509: certificate signed by unknown authority error is a trust failure, not a network failure — the handshake completed and was rejected.
ELF: not found on a fresh binary means wrong CPU architecture (arm64 vs x86_64), not a corrupt download.
A credential-access alert on /etc/shadow turned out to be dpkg-preconfigure (package management) — identified by AUID=unset (no login session). The audit identity field doubles as a benign/human noise filter for future rules.
A healthy agent is not a delivering agent: control plane and data plane fail independently.
Roadmap
Detections as code — Sigma rules in this repo with CI (lint → compile → test → deploy), overlaying detection coverage (score 2) on this telemetry layer
Adversary emulation — Atomic Red Team / Caldera runs to validate detections against known-bad
Cloud telemetry — CloudTrail ingestion and cloud-native detections
Host DFIR — memory and disk forensics on the victim fleet
