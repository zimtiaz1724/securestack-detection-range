# securestack-detection-range

This project serves as the guide for Detection and Response Engineering. The prjoect employs MITRE ATT&CK vectors by associating observed intrusions tagging it to a Technique ID. The project is implemented on AWS and the brain for this project is the SIEM (ElasticStack) with elastic agents configured on a Windows and Ubuntu hosts.

Windows and Linux stores log events but they are not granular. Sysmon and authd writes rich, detection ready events in to its own channel. They are then forwarded to the SIEM where detections are fired based on the rules configured for alerting. 

The communication b/w elastic agent and SIEM happens on two channels 
1. control channel - used for policy updates and connection on port 8220
2. Data channel - forward logs.

Here is an example of a windows event and a Linux event as seen on the SIEM 
Windows -> running ipconfig /all 
"@timestamp": [
    "2026-09-18T05:49:41.878Z"
  ],
  "agent.ephemeral_id": [
    "0701f79f-cb92-4f85-a0d0-d6b2e5a28762"
  ],
  "agent.id": [
    "5d744e9d-2d88-44e6-aa58-7392bbe098f2"
  ],
  "agent.name": [
    "EC2AMAZ-B8CN7U4"
  ],
  "agent.name.text": [
    "EC2AMAZ-B8CN7U4"
  ],
  "agent.type": [
    "filebeat"
  ],
  "agent.version": [
    "9.5.4"
  ],
  "cloud.account.id": [
    "151110387185"
  ],
  "cloud.availability_zone": [
    "us-east-2c"
  ],
  "cloud.image.id": [
    "ami-0883b7ef84c11bc3e"
  ],
  "cloud.instance.id": [
    "i-065061c95b168d39e"
  ],
  "cloud.machine.type": [
    "t3.medium"
  ],
  "cloud.provider": [
    "aws"
  ],
  "cloud.region": [
    "us-east-2"
  ],
  "cloud.service.name": [
    "EC2"
  ],
  "cloud.service.name.text": [
    "EC2"
  ],
  "data_stream.dataset": [
    "windows.sysmon_operational"
  ],
  "data_stream.namespace": [
    "default"
  ],
  "data_stream.type": [
    "logs"
  ],
  "ecs.version": [
    "8.17.0"
  ],
  "elastic_agent.id": [
    "5d744e9d-2d88-44e6-aa58-7392bbe098f2"
  ],
  "elastic_agent.snapshot": [
    false
  ],
  "elastic_agent.version": [
    "9.5.4"
  ],
  "event.action": [
    "Process creation"
  ],
  "event.agent_id_status": [
    "verified"
  ],
  "event.category": [
    "process"
  ],
  "event.code": [
    "1"
  ],
  "event.created": [
    "2026-09-18T05:49:43.644Z"
  ],
  "event.dataset": [
    "windows.sysmon_operational"
  ],
  "event.ingested": [
    "2026-09-18T05:49:53.000Z"
  ],
  "event.kind": [
    "event"
  ],
  "event.module": [
    "windows"
  ],
  "event.provider": [
    "Microsoft-Windows-Sysmon"
  ],
  "event.type": [
    "start"
  ],
  "host.architecture": [
    "x86_64"
  ],
  "host.hostname": [
    "EC2AMAZ-B8CN7U4"
  ],
  "host.id": [
    "63bde38b-c492-4ab2-b45d-49d1e479721b"
  ],
  "host.ip": [
    "fe80::efd8:2ed8:de74:454d",
    "172.31.44.211"
  ],
  "host.mac": [
    "0A-FF-E7-A7-BE-B3"
  ],
  "host.name": [
    "ec2amaz-b8cn7u4"
  ],
  "host.os.build": [
    "20348.5622"
  ],
  "host.os.family": [
    "windows"
  ],
  "host.os.kernel": [
    "10.0.20348.5622 (WinBuild.160101.0800)"
  ],
  "host.os.name": [
    "Windows Server 2022 Datacenter"
  ],
  "host.os.name.text": [
    "Windows Server 2022 Datacenter"
  ],
  "host.os.platform": [
    "windows"
  ],
  "host.os.type": [
    "windows"
  ],
  "host.os.version": [
    "10.0"
  ],
  "input.type": [
    "winlog"
  ],
  "log.level": [
    "information"
  ],
  "message": [
    "Process Create:\nRuleName: technique_id=T1016,technique_name=System Network Configuration Discovery\nUtcTime: 2026-09-18 05:49:41.878\nProcessGuid: {63BDE38B-D0F5-6AAC-8101-000000009402}\nProcessId: 4884\nImage: C:\\Windows\\System32\\ipconfig.exe\nFileVersion: 10.0.20348.3451 (WinBuild.160101.0800)\nDescription: IP Configuration Utility\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: ipconfig.exe\nCommandLine: \"C:\\Windows\\system32\\ipconfig.exe\" /all\nCurrentDirectory: C:\\Users\\Administrator\\\nUser: EC2AMAZ-B8CN7U4\\Administrator\nLogonGuid: {63BDE38B-CA77-6AAC-614A-110000000000}\nLogonId: 0x114a61\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=72FE255B4D1F6F774F1A021AA8D383AB719BA874,MD5=44EF7ED749B54413795F1E7894C70D50,SHA256=1BDCC390896EF5E642CFDEB2CFAB71C386A1D58290B27EC9E3C761E8718A8A27,IMPHASH=3C4BF3CD6C64B24B9534F30802178D06\nParentProcessGuid: {63BDE38B-CAAC-6AAC-DD00-000000009402}\nParentProcessId: 6492\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \nParentUser: EC2AMAZ-B8CN7U4\\Administrator"
  ],
  "process.args": [
    "C:\\Windows\\system32\\ipconfig.exe",
    "/all"
  ],
  "process.args_count": [
    2
  ],
  "process.command_line": [
    "\"C:\\Windows\\system32\\ipconfig.exe\" /all"
  ],
  "process.command_line.text": [
    "\"C:\\Windows\\system32\\ipconfig.exe\" /all"
  ],
  "process.entity_id": [
    "{63BDE38B-D0F5-6AAC-8101-000000009402}"
  ],
  "process.executable": [
    "C:\\Windows\\System32\\ipconfig.exe"
  ],
  "process.executable.caseless": [
    "c:\\windows\\system32\\ipconfig.exe"
  ],
  "process.executable.text": [
    "C:\\Windows\\System32\\ipconfig.exe"
  ],
  "process.hash.md5": [
    "44ef7ed749b54413795f1e7894c70d50"
  ],
  "process.hash.sha1": [
    "72fe255b4d1f6f774f1a021aa8d383ab719ba874"
  ],
  "process.hash.sha256": [
    "1bdcc390896ef5e642cfdeb2cfab71c386a1d58290b27ec9e3c761e8718a8a27"
  ],
  "process.name": [
    "ipconfig.exe"
  ],
  "process.name.caseless": [
    "ipconfig.exe"
  ],
  "process.name.text": [
    "ipconfig.exe"
  ],
  "process.parent.args": [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  ],
  "process.parent.args_count": [
    1
  ],
  "process.parent.command_line": [
    "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
  ],
  "process.parent.command_line.text": [
    "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
  ],
  "process.parent.entity_id": [
    "{63BDE38B-CAAC-6AAC-DD00-000000009402}"
  ],
  "process.parent.executable": [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  ],
  "process.parent.executable.text": [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  ],
  "process.parent.name": [
    "powershell.exe"
  ],
  "process.parent.name.text": [
    "powershell.exe"
  ],
  "process.parent.pid": [
    6492
  ],
  "process.pe.company": [
    "Microsoft Corporation"
  ],
  "process.pe.description": [
    "IP Configuration Utility"
  ],
  "process.pe.file_version": [
    "10.0.20348.3451 (WinBuild.160101.0800)"
  ],
  "process.pe.imphash": [
    "3c4bf3cd6c64b24b9534f30802178d06"
  ],
  "process.pe.original_file_name": [
    "ipconfig.exe"
  ],
  "process.pe.product": [
    "Microsoft® Windows® Operating System"
  ],
  "process.pid": [
    4884
  ],
  "process.working_directory": [
    "C:\\Users\\Administrator\\"
  ],
  "process.working_directory.text": [
    "C:\\Users\\Administrator\\"
  ],
  "related.hash": [
    "1bdcc390896ef5e642cfdeb2cfab71c386a1d58290b27ec9e3c761e8718a8a27",
    "72fe255b4d1f6f774f1a021aa8d383ab719ba874",
    "44ef7ed749b54413795f1e7894c70d50",
    "3c4bf3cd6c64b24b9534f30802178d06"
  ],
  "related.user": [
    "Administrator"
  ],
  "rule.name": [
    "technique_id=T1016,technique_name=System Network Configuration Discovery"
  ],
  "user.domain": [
    "EC2AMAZ-B8CN7U4"
  ],
  "user.id": [
    "S-1-5-18"
  ],
  "user.name": [
    "Administrator"
  ],
  "user.name.text": [
    "Administrator"
  ],
  "winlog.channel": [
    "Microsoft-Windows-Sysmon/Operational"
  ],
  "winlog.computer_name": [
    "EC2AMAZ-B8CN7U4"
  ],
  "winlog.event_data.Company": [
    "Microsoft Corporation"
  ],
  "winlog.event_data.Description": [
    "IP Configuration Utility"
  ],
  "winlog.event_data.FileVersion": [
    "10.0.20348.3451 (WinBuild.160101.0800)"
  ],
  "winlog.event_data.IntegrityLevel": [
    "High"
  ],
  "winlog.event_data.LogonGuid": [
    "{63BDE38B-CA77-6AAC-614A-110000000000}"
  ],
  "winlog.event_data.LogonId": [
    "0x114a61"
  ],
  "winlog.event_data.ParentUser": [
    "EC2AMAZ-B8CN7U4\\Administrator"
  ],
  "winlog.event_data.Product": [
    "Microsoft® Windows® Operating System"
  ],
  "winlog.event_data.TerminalSessionId": [
    "2"
  ],
  "winlog.event_id": [
    "1"
  ],
  "winlog.opcode": [
    "Info"
  ],
  "winlog.process.pid": [
    2860
  ],
  "winlog.process.thread.id": [
    3812
  ],
  "winlog.provider_guid": [
    "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
  ],
  "winlog.provider_name": [
    "Microsoft-Windows-Sysmon"
  ],
  "winlog.record_id": [
    "3965"
  ],
  "winlog.task": [
    "Process Create (rule: ProcessCreate)"
  ],
  "winlog.user.domain": [
    "NT AUTHORITY"
  ],
  "winlog.user.identifier": [
    "S-1-5-18"
  ],
  "winlog.user.name": [
    "SYSTEM"
  ],
  "winlog.user.type": [
    "User"
  ],
  "winlog.version": [
    5
  ],
  "_id": "AaCzEDgS68Dc_0dugpTY",
  "_index": ".ds-logs-windows.sysmon_operational-default-2026.09.16-000001",
  "_score": null
}


Linux -> running id command
{
  "@timestamp": [
    "2026-09-18T06:17:31.022Z"
  ],
  "agent.ephemeral_id": [
    "0a347366-c7c7-43ba-9750-f18cf695f14b"
  ],
  "agent.id": [
    "eb09b693-daa6-4951-ac96-65bbb34415d2"
  ],
  "agent.name": [
    "ip-172-31-43-153"
  ],
  "agent.name.text": [
    "ip-172-31-43-153"
  ],
  "agent.type": [
    "filebeat"
  ],
  "agent.version": [
    "9.5.4"
  ],
  "auditd.log.a0": [
    "ffffff9c"
  ],
  "auditd.log.a1": [
    "7ffd6e22f7c0"
  ],
  "auditd.log.a2": [
    "0"
  ],
  "auditd.log.a3": [
    "0"
  ],
  "auditd.log.ARCH": [
    "x86_64"
  ],
  "auditd.log.AUID": [
    "ubuntu"
  ],
  "auditd.log.EGID": [
    "root"
  ],
  "auditd.log.EUID": [
    "root"
  ],
  "auditd.log.FSGID": [
    "root"
  ],
  "auditd.log.FSUID": [
    "root"
  ],
  "auditd.log.GID": [
    "root"
  ],
  "auditd.log.items": [
    "1"
  ],
  "auditd.log.key": [
    "cred_access"
  ],
  "auditd.log.record_type": [
    "SYSCALL"
  ],
  "auditd.log.sequence": [
    1300
  ],
  "auditd.log.ses": [
    "1"
  ],
  "auditd.log.SGID": [
    "root"
  ],
  "auditd.log.subj": [
    "unconfined"
  ],
  "auditd.log.success": [
    true
  ],
  "auditd.log.SUID": [
    "root"
  ],
  "auditd.log.syscall": [
    "257"
  ],
  "auditd.log.SYSCALL": [
    "openat"
  ],
  "auditd.log.tty": [
    "pts1"
  ],
  "auditd.log.UID": [
    "root"
  ],
  "cloud.account.id": [
    "151110387185"
  ],
  "cloud.availability_zone": [
    "us-east-2c"
  ],
  "cloud.image.id": [
    "ami-0ea1cddefe0c4aed5"
  ],
  "cloud.instance.id": [
    "i-0b50f39d6929e9713"
  ],
  "cloud.machine.type": [
    "t3.small"
  ],
  "cloud.provider": [
    "aws"
  ],
  "cloud.region": [
    "us-east-2"
  ],
  "cloud.service.name": [
    "EC2"
  ],
  "cloud.service.name.text": [
    "EC2"
  ],
  "data_stream.dataset": [
    "auditd.log"
  ],
  "data_stream.namespace": [
    "default"
  ],
  "data_stream.type": [
    "logs"
  ],
  "ecs.version": [
    "8.17.0"
  ],
  "elastic_agent.id": [
    "eb09b693-daa6-4951-ac96-65bbb34415d2"
  ],
  "elastic_agent.snapshot": [
    false
  ],
  "elastic_agent.version": [
    "9.5.4+build202609161310"
  ],
  "event.action": [
    "syscall"
  ],
  "event.agent_id_status": [
    "verified"
  ],
  "event.category": [
    "process"
  ],
  "event.dataset": [
    "auditd.log"
  ],
  "event.ingested": [
    "2026-09-18T06:17:41.000Z"
  ],
  "event.kind": [
    "event"
  ],
  "event.module": [
    "auditd"
  ],
  "event.type": [
    "info"
  ],
  "host.architecture": [
    "x86_64"
  ],
  "host.containerized": [
    false
  ],
  "host.hostname": [
    "ip-172-31-43-153"
  ],
  "host.id": [
    "ec26351f6a59d15947fc9ff63f080f55"
  ],
  "host.ip": [
    "172.31.43.153",
    "fe80::8ff:e7ff:fe6e:7e1"
  ],
  "host.mac": [
    "0A-FF-E7-6E-07-E1"
  ],
  "host.name": [
    "ip-172-31-43-153"
  ],
  "host.os.codename": [
    "noble"
  ],
  "host.os.family": [
    "debian"
  ],
  "host.os.kernel": [
    "6.17.0-1017-aws"
  ],
  "host.os.name": [
    "Ubuntu"
  ],
  "host.os.name.text": [
    "Ubuntu"
  ],
  "host.os.platform": [
    "ubuntu"
  ],
  "host.os.type": [
    "linux"
  ],
  "host.os.version": [
    "24.04.4 LTS (Noble Numbat)"
  ],
  "input.type": [
    "log"
  ],
  "log.file.path": [
    "/var/log/audit/audit.log"
  ],
  "log.offset": [
    1924444
  ],
  "process.executable": [
    "/usr/bin/cat"
  ],
  "process.executable.text": [
    "/usr/bin/cat"
  ],
  "process.exit_code": [
    3
  ],
  "process.name": [
    "cat"
  ],
  "process.name.text": [
    "cat"
  ],
  "process.parent.pid": [
    1618
  ],
  "process.pid": [
    1619
  ],
  "related.user": [
    "root",
    "ubuntu"
  ],
  "tags": [
    "auditd-log"
  ],
  "user.audit.id": [
    "1000"
  ],
  "user.audit.name": [
    "ubuntu"
  ],
  "user.effective.group.id": [
    "0"
  ],
  "user.effective.group.name": [
    "root"
  ],
  "user.effective.id": [
    "0"
  ],
  "user.effective.name": [
    "root"
  ],
  "user.effective.name.text": [
    "root"
  ],
  "user.filesystem.group.id": [
    "0"
  ],
  "user.filesystem.group.name": [
    "root"
  ],
  "user.filesystem.id": [
    "0"
  ],
  "user.filesystem.name": [
    "root"
  ],
  "user.group.id": [
    "0"
  ],
  "user.group.name": [
    "root"
  ],
  "user.id": [
    "0"
  ],
  "user.name": [
    "root"
  ],
  "user.name.text": [
    "root"
  ],
  "user.saved.group.id": [
    "0"
  ],
  "user.saved.group.name": [
    "root"
  ],
  "user.saved.id": [
    "0"
  ],
  "user.saved.name": [
    "root"
  ],
  "_id": "AaCzKTgS68Dc_0fhh_jB",
  "_index": ".ds-logs-auditd.log-default-2026.09.16-000001",
  "_score": null
}


5 Techniques that were implemented in the lab. 

T1059 — Command and Scripting Interpreter
The attacker runs actions through interpreters the system already has — PowerShell, cmd, bash — instead of
dropping custom binaries, because these are pre-installed, trusted, usually allowlisted, and blend into administration;
no malware file for AV to flag. Logs: process-creation telemetry (Sysmon Event ID 1 / Windows 4688) with the full
command line, where the parent-child relationship carries the signal — winword.exe spawning powershell.exe is a
story. PowerShell script-block logging (4104) exposes the actual code even when the command line is obfuscated;
flags like -enc or IEX are high-signal alone. Linux equivalent: execve syscalls in auditd; a web-server process
spawning bash is the parent-child anomaly worth alerting on.
T1078 — Valid Accounts
The attacker authenticates with legitimate credentials — phished, dumped, purchased, or from accounts never fully
decommissioned — and simply logs in. A valid login defeats most controls by definition: no exploit, no malware, full
inherited permissions; works for initial access and quiet persistence. The authentication event itself is clean, so
detection is never the event — it is context and deviation. Windows: 4624 with attention to logon type (type 3 network
vs. type 10 RDP tell different stories), runs of 4625 failures ending in a success, Kerberos 4768. Identity layer:
IdP/SAML assertion logs, AD/LDAP bind logs, RADIUS accounting. Cloud: CloudTrail ConsoleLogin and API calls
from unfamiliar IPs. Signals to engineer for: a dormant account waking, impossible travel, first-ever authentication to
a system, a service account logging in interactively.
T1071 — Application Layer Protocol
The attacker carries C2 and exfiltration inside protocols the network expects — HTTPS, DNS, sometimes mail/FTP
— exiting over ports open everywhere, because a custom protocol on an odd port is exactly what perimeters catch.
Flow data (IPs, ports, protocol) is therefore nearly useless: the point of the technique is that the flow looks normal.
Detect one layer up and one layer down. Endpoint: Sysmon Event ID 3 ties each connection to its process — an
Office app or script host speaking HTTPS to a bare IP is not user browsing. Network: C2 has rhythm — fixed-interval
beaconing with uniform payload sizes, visible in pcap timing analysis; DNS logs betray tunneling via long
high-entropy subdomains and abnormal query volume to one domain; TLS metadata adds client fingerprints and
self-signed or newly-registered-domain certificates.
T1053 — Scheduled Task/Job
The attacker creates or modifies a scheduled task, cron entry, or systemd timer so code re-executes on schedule or
at boot — persistence through a legitimate, ubiquitous OS feature, hiding among constant admin activity. Windows
telemetry: Security 4698 (task created), Sysmon Event ID 1 catching schtasks.exe with full command line, the Task
Scheduler operational log. Linux: auditd file watches on /etc/cron* and /var/spool/cron, plus new systemd timer units.
Because admins create tasks all day, the rule must encode suspicion: task action pointing at a binary in
%TEMP%/%APPDATA% or a user-writable path, unexpected parent, a SYSTEM-level task from a non-admin
session or outside a change window, names mimicking legitimate tasks. The benign-vs-malicious contrast is the
detection; the event alone is noise.
T1552 — Unsecured Credentials
The attacker searches systems already compromised for credentials lying unprotected — plaintext files and scripts,
hardcoded secrets in unattend.xml or web.config, .aws/credentials and .env files, bash history, cloud
instance-metadata secrets — because found credentials are the cheapest escalation: no cracking, no exploit, each
one unlocks the next system. Scope boundary: T1552 ends the moment the credential is obtained; the moment it is
used, that is T1078. Detect the hunt itself: command-line telemetry (Sysmon 1, auditd execve) showing findstr /si
password or recursive greps for password/key; file-access auditing on credential-bearing files read by unusual
processes, or one user's history read by another account; in cloud, bursts of GetSecretValue, enumeration across
Secrets Manager/SSM, or requests to 169.254.169.254 from a process with no business touching metadata. Cheap
to instrument and high-signal — normal software almost never greps a filesystem for passwords.
