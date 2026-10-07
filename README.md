# Windows Persistence Checker

A lightweight Windows security and DFIR-oriented tool written in **Java 21** for detecting common Windows persistence mechanisms.

The tool scans persistence locations commonly abused by malware to maintain execution across system startup, user logon, and scheduled execution.

> **Project status:** Early development / MVP

---

## Overview

Windows malware frequently uses persistence mechanisms to ensure that malicious code is executed again after reboot, user logon, or specific system events.

**Windows Persistence Checker** is designed to help security analysts, SOC analysts, and DFIR practitioners quickly identify potentially suspicious persistence entries on a Windows endpoint.

Current detection capabilities include:

* Registry Run Keys
* Startup Folder
* Scheduled Tasks
* Basic risk scoring
* Suspicious path detection
* Suspicious PowerShell command detection
* Potentially misleading system-name detection

The project is intentionally designed with a modular architecture so additional persistence mechanisms and detection rules can be added later.

---

## Features

### Current Features

| Feature                            | Status |
| ---------------------------------- | ------ |
| Registry Run Keys                  | ✅      |
| Registry RunOnce                   | ✅      |
| Startup Folder                     | ✅      |
| Scheduled Tasks                    | ✅      |
| Suspicious path detection          | ✅      |
| PowerShell detection               | ✅      |
| Encoded PowerShell detection       | ✅      |
| Hidden PowerShell detection        | ✅      |
| Suspicious filename detection      | ✅      |
| Risk scoring                       | ✅      |
| CLI output                         | ✅      |
| Windows native command integration | ✅      |
| Windows Services                   | 🚧     |
| WMI Persistence                    | 🚧     |
| SHA256 calculation                 | 🚧     |
| Digital Signature verification     | 🚧     |
| JSON output                        | 🚧     |
| MITRE ATT&CK mapping               | 🚧     |
| Baseline comparison                | 🚧     |
| ELK integration                    | 🚧     |

---

# Detection Coverage

## 1. Registry Run Keys

The tool checks commonly used Windows Registry persistence locations:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Example:

```text
WindowsUpdate = C:\Users\Public\update.exe
```

The tool extracts:

```text
Name
Path
Command
Registry Location
Risk Score
Risk Level
```

Example output:

```text
[SUSPICIOUS]

Type: REGISTRY_RUN
Name: WindowsUpdate

Path:
C:\Users\Public\update.exe

Location:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Risk Score: 40
Risk Level: MEDIUM

Reasons:
  [+] Executable in Users\Public
  [+] Potentially misleading system name
```

---

# 2. Startup Folder

The tool scans the Windows Startup directories.

### Current User

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

### All Users

```text
%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp
```

Files found in these locations are reported as persistence entries.

Examples of potentially interesting files include:

```text
update.exe
update.bat
script.ps1
payload.vbs
suspicious.lnk
```

Further analysis of `.lnk`, PowerShell, VBScript, and batch files is planned for future versions.

---

# 3. Scheduled Tasks

The tool enumerates Windows Scheduled Tasks using the native Windows:

```text
schtasks.exe
```

The current implementation collects task information and attempts to identify executable or script-based actions.

Potentially suspicious examples include tasks executing:

```text
PowerShell
cmd.exe
wscript.exe
cscript.exe
Unknown executables
Executables from user-writable directories
```

Example:

```text
[SUSPICIOUS]

Type: SCHEDULED_TASK

Name:
WindowsUpdateCheck

Path:
C:\Users\Public\update.exe

Location:
Task Scheduler

Risk Level:
HIGH
```

---

# Risk Analysis

Finding a persistence mechanism does **not** automatically mean that the system is infected.

Legitimate applications frequently use persistence mechanisms.

For example:

```text
OneDrive
Google Update
Microsoft applications
Security software
Hardware utilities
```

may legitimately create:

```text
Registry Run Keys
Scheduled Tasks
Windows Services
```

Therefore, the project uses a basic **risk scoring model** instead of treating every persistence entry as malicious.

---

## Risk Factors

Examples of currently implemented indicators:

### Suspicious locations

```text
C:\Users\Public\
C:\Users\<user>\AppData\Local\Temp\
C:\Windows\Temp\
```

These locations are interesting because malware can sometimes place executable files there.

---

### PowerShell

Commands containing:

```text
powershell
```

receive additional risk points.

---

### Encoded PowerShell

Commands containing:

```text
-EncodedCommand
```

receive a higher risk score.

Example:

```text
powershell.exe -EncodedCommand ...
```

This is a useful indicator because attackers may encode PowerShell commands to obscure their actual contents.

---

### Hidden PowerShell

Commands containing:

```text
-WindowStyle Hidden
```

are considered suspicious.

Example:

```text
powershell.exe -WindowStyle Hidden ...
```

---

### Misleading names

The tool currently checks for names that may imitate legitimate Windows components, such as:

```text
WindowsUpdate
SecurityUpdate
SystemUpdate
MicrosoftUpdate
ChromeUpdate
```

For example:

```text
WindowsUpdate
    ↓
C:\Users\Public\update.exe
```

is more suspicious than a legitimate Windows executable located in:

```text
C:\Windows\System32\
```

---

# Risk Levels

The current scoring model uses:

```text
0 - 29      LOW
30 - 59     MEDIUM
60 - 79     HIGH
80 - 100    CRITICAL
```

The score is currently capped at:

```text
100
```

Example:

```text
Executable in Public directory       +20
PowerShell                            +15
Encoded PowerShell                   +30
Hidden PowerShell                    +20
Suspicious system-like name          +10
```

The scoring system is intentionally simple in the MVP and will be expanded into a configurable rule engine.

---

# Architecture

The project uses a modular Java architecture.

```text
Windows Persistence Checker
│
├── Scanner Layer
│   ├── RegistryScanner
│   ├── StartupScanner
│   └── ScheduledTaskScanner
│
├── Model Layer
│   ├── PersistenceEntry
│   ├── PersistenceType
│   └── RiskLevel
│
├── Analysis Layer
│   └── RiskAnalyzer
│
└── Main
```

The scanner abstraction is based on:

```java
public interface PersistenceScanner {

    List<PersistenceEntry> scan();
}
```

This makes it possible to add additional scanners without changing the core application.

Future scanners can implement the same interface:

```text
ServiceScanner
WmiScanner
WinlogonScanner
IfeoScanner
BitsScanner
```

---

# Project Structure

```text
windows-persistence-checker/
│
├── .gitignore
│
├── src/
│   │
│   ├── Main.java
│   │
│   ├── analyzer/
│   │   └── RiskAnalyzer.java
│   │
│   ├── model/
│   │   ├── PersistenceEntry.java
│   │   ├── PersistenceType.java
│   │   └── RiskLevel.java
│   │
│   └── scanner/
│       ├── PersistenceScanner.java
│       ├── RegistryScanner.java
│       ├── ScheduledTaskScanner.java
│       └── StartupScanner.java
│
└── README.md
```

---

# Requirements

## Operating System

```text
Windows 10
Windows 11
```

The project currently relies on native Windows commands such as:

```text
reg.exe
schtasks.exe
```

Therefore, Windows is required.

---

## Java

Required:

```text
Java 21+
```

Check your Java version:

```powershell
java -version
```

Example:

```text
openjdk version "21"
```

---

# Running the Project

## IntelliJ IDEA

Open the project in IntelliJ IDEA.

Configure the project SDK:

```text
JDK 21
```

Then run:

```text
Main.java
```

---

## Command Line

Compile the source:

```powershell
javac -d out `
src\Main.java `
src\analyzer\*.java `
src\model\*.java `
src\scanner\*.java
```

Run:

```powershell
java -cp out Main
```

---

# Example Output

```text
==========================================
  Windows Persistence Checker
  BHNamSSD
  Version 0.1
==========================================

[*] Starting persistence scan...

[*] Running: RegistryScanner
[*] Running: StartupScanner
[*] Running: ScheduledTaskScanner

==========================================
 Persistence Findings
==========================================

[SUSPICIOUS]

Type: REGISTRY_RUN

Name: WindowsUpdate

Path:
C:\Users\Public\update.exe

Command:
C:\Users\Public\update.exe

Location:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Risk Score: 40
Risk Level: MEDIUM

Reasons:
  [+] Executable in Users\Public
  [+] Potentially misleading system name

------------------------------------------

Total persistence entries: 120
Suspicious entries: 2

[*] Scan completed.
```

---

# Security Use Cases

The project is intended for defensive security and endpoint investigation.

Potential use cases include:

### SOC Triage

Quickly inspect an endpoint after an alert.

```text
EDR Alert
    ↓
Endpoint investigation
    ↓
Persistence Checker
    ↓
Suspicious persistence
    ↓
Further investigation
```

---

### DFIR

After a suspected compromise, persistence locations can be inspected to determine whether malware attempted to survive reboot or user logon.

---

### Malware Analysis

When analyzing malware in an isolated lab, the tool can help identify persistence mechanisms created by the sample.

---

### Security Research

The project can also be used to study:

```text
Windows persistence
MITRE ATT&CK
Windows Registry
Scheduled Tasks
PowerShell
Endpoint Detection
DFIR
Detection Engineering
```

---

# MITRE ATT&CK Mapping

Future versions will map findings to MITRE ATT&CK techniques.

Planned mappings include:

| Persistence Mechanism              | MITRE ATT&CK |
| ---------------------------------- | ------------ |
| Registry Run Keys / Startup Folder | T1547.001    |
| Scheduled Task                     | T1053.005    |
| Windows Service                    | T1543.003    |
| WMI Event Subscription             | T1546.003    |

This will allow output such as:

```text
[SUSPICIOUS]

Persistence:
Scheduled Task

Technique:
T1053.005
Scheduled Task/Job: Scheduled Task

Name:
WindowsUpdateCheck

Command:
C:\Users\Public\update.exe

Risk:
HIGH
```

---

# Roadmap

## v0.1 — MVP

* [x] Registry Run Keys
* [x] Registry RunOnce
* [x] Startup Folder
* [x] Scheduled Tasks
* [x] Basic risk scoring
* [x] Suspicious path detection
* [x] PowerShell detection
* [x] CLI output

## v0.2 — Endpoint Intelligence

* [ ] Windows Services
* [ ] SHA256 calculation
* [ ] File metadata
* [ ] Digital Signature verification
* [ ] Better Scheduled Task parsing
* [ ] `.lnk` analysis
* [ ] PowerShell argument analysis

## v0.3 — Advanced Persistence

* [ ] WMI Event Subscription
* [ ] Winlogon
* [ ] Image File Execution Options
* [ ] AppInit_DLLs
* [ ] BITS Jobs
* [ ] COM Hijacking

## v0.4 — Detection Engineering

* [ ] Configurable detection rules
* [ ] External `rules.json`
* [ ] MITRE ATT&CK mapping
* [ ] Improved risk scoring
* [ ] False-positive handling

## v0.5 — Reporting

* [ ] JSON output
* [ ] CSV output
* [ ] HTML report
* [ ] Scan summary
* [ ] IOC export

## v1.0 — DFIR / SOC Tool

* [ ] Baseline creation
* [ ] Persistence comparison
* [ ] New persistence detection
* [ ] File hash intelligence
* [ ] VirusTotal integration
* [ ] ELK integration
* [ ] Automated investigation report

---

# Future Baseline Mode

One planned feature is endpoint baselining.

Initial scan:

```text
persistence-checker --baseline
```

The tool stores known persistence entries.

Later:

```text
persistence-checker --compare
```

Example:

```text
[NEW PERSISTENCE]

Type:
SCHEDULED_TASK

Name:
WindowsUpdateCheck

Command:
C:\Users\Public\update.exe

First Seen:
2026-10-07

Risk:
HIGH
```

This is useful because a newly created persistence mechanism can be more interesting to an analyst than a legitimate persistence entry that has existed for months.

---

# Planned ELK Integration

The project is also designed with future SIEM integration in mind.

Potential architecture:

```text
Windows Endpoint
       │
       ▼
Persistence Checker
       │
       ▼
JSON
       │
       ▼
Logstash
       │
       ▼
Elasticsearch
       │
       ▼
Kibana
```

Example event:

```json
{
  "host": "WIN-PC01",
  "type": "REGISTRY_RUN",
  "name": "WindowsUpdate",
  "path": "C:\\Users\\Public\\update.exe",
  "risk_score": 82,
  "risk_level": "CRITICAL"
}
```

This could eventually allow SOC analysts to search for persistence activity across multiple Windows endpoints.

---

# Limitations

The current version should be considered a **security triage tool**, not a full malware detection engine.

A `[SUSPICIOUS]` finding does not mean that the file or persistence mechanism is confirmed malicious.

Possible false positives include:

```text
Legitimate software updaters
Enterprise management software
Security products
Monitoring agents
Backup software
Vendor utilities
```

Additional investigation should be performed before declaring an endpoint compromised.

The current risk engine is heuristic-based and does not currently perform:

```text
PE analysis
Digital signature verification
Malware sandboxing
YARA scanning
Threat intelligence correlation
Behavioral analysis
```

These capabilities may be added in future versions.

---

# Security Disclaimer

This project is intended for:

* Defensive security research
* SOC investigation
* DFIR
* Malware analysis in controlled environments
* Windows security research
* Educational purposes

Do not use the tool to access or analyze systems without appropriate authorization.

---

# Technology

```text
Language: Java
Version: Java 21
Platform: Windows
Interface: CLI
Build System: None / javac
```

The project intentionally avoids external frameworks in the initial version to keep the tool lightweight and easy to compile and execute.

---

# Author

**BHNamSSD**

GitHub:

```text
https://github.com/BHNamSSD
```

Project:

```text
windows-persistence-checker
```

---

# License

License information will be added in a future release.
