# Analysis Layer Implementation

## Overview

This document describes the implemented signature-based detection system for the log analyzer tool.

## Components Implemented

### 1. Signature-Based Detector (`backend/analyzers/signature_detector.py`)

A comprehensive detection engine that matches logs against known attack patterns using:

- **Regex Pattern Matching**: Compiled regex patterns for efficient matching
- **YARA-Style Rules**: Structured signature definitions with metadata
- **Hash-Based Detection**: Matches file hashes against known malware signatures
- **Blocked IP Detection**: Checks source IPs against a blocklist
- **Protocol-Specific Signatures**: Specialized patterns for different attack types

#### Features:
- Pre-compiled regex patterns for performance
- Support for multiple field matching (raw, message, normalized fields)
- Automatic signature reloading
- Comprehensive logging and metrics

### 2. Signature Files

Created comprehensive signature databases covering:

#### Web Attacks (`config/signatures/web_attacks.yaml`)
- SQL Injection (UNION, Boolean, Time-based, Stacked queries)
- Cross-Site Scripting (XSS) - Script tags, Event handlers, JavaScript protocol
- Path Traversal & Directory traversal
- Command Injection
- Local/Remote File Inclusion (LFI/RFI)
- XML External Entity (XXE)
- Server-Side Request Forgery (SSRF)
- LDAP Injection
- Server-Side Template Injection (SSTI)

**Total: 17 signatures**

#### Authentication Attacks (`config/signatures/auth_attacks.yaml`)
- SSH/RDP/Web Brute Force
- Credential Stuffing
- Password Spraying
- Authentication Bypass (SQL/NoSQL injection)
- Session Hijacking
- Default Credentials
- Privilege Escalation (sudo, UAC bypass)
- Account Manipulation
- MFA Bypass

**Total: 15 signatures**

#### Network Attacks (`config/signatures/network_attacks.yaml`)
- Port Scanning (SYN scan, multiple ports)
- DDoS Attacks (SYN flood, UDP flood, HTTP flood)
- DNS Attacks (Tunneling, Amplification)
- Man-in-the-Middle (ARP spoofing, SSL/TLS MITM)
- Protocol Attacks (SMB EternalBlue, SMB brute force)
- Beaconing Traffic & C2 Communication
- Data Exfiltration
- Tor Network Usage
- Firewall Evasion
- Lateral Movement (PSExec, WMI)
- Reverse Shell Connections
- Covert Channels (ICMP tunneling)

**Total: 20 signatures**

#### Malware & Exploits (`config/signatures/malware.yaml`)
- Known Malware Families (WannaCry, Emotet, Cobalt Strike, Mimikatz)
- Web Shells (PHP, ASP/ASPX, JSP)
- Cryptocurrency Miners
- Rootkits
- SSH Backdoors
- Exploit Frameworks (Metasploit, Empire)
- Fileless Malware (PowerShell, WMI)
- Ransomware
- Remote Access Trojans (RATs)
- Keyloggers
- C2 Communication (HTTP, DNS)
- Living Off the Land Binaries (LOLBins - certutil, bitsadmin)

**Total: 21 signatures with 3 hash-based detections**

### 3. Blocked IPs (`config/blocked_ips.txt`)

Text file containing malicious IP addresses:
- Known C2 servers
- Botnet IPs
- Tor exit nodes
- Malicious actors

Format: One IP per line, supports comments with `#`

### 4. Analysis Orchestrator (`backend/analyzers/orchestrator.py`)

Coordinates the analysis pipeline:

#### Features:
- **Periodic Analysis**: Runs detection cycles at configurable intervals
- **Parallel Detection**: Runs all detectors concurrently using asyncio
- **Alert Aggregation**: Combines alerts from all detectors
- **Alert Prioritization**: Scores alerts based on severity
- **Alert Deduplication**: Removes duplicate alerts
- **Performance Metrics**: Tracks cycles, logs processed, alerts generated
- **Error Handling**: Continues operation even if individual detectors fail
- **Hot Reload**: Can reload signatures without restart

#### Configuration:
```yaml
orchestrator:
  analysis_interval: 60  # seconds
  batch_size: 10000
  signature_dir: config/signatures
  blocked_ips_file: config/blocked_ips.txt
```

## Testing

### Test Scripts

1. **Signature Detector Test** (`backend/tests/test_signature_detector.py`)
   - Tests pattern matching
   - Tests blocked IP detection
   - Tests hash-based detection
   - Validates all signature categories

2. **Orchestrator Test** (`backend/tests/test_orchestrator.py`)
   - Tests analysis cycle
   - Tests continuous mode
   - Tests alert storage
   - Validates metrics tracking

### Running Tests

```bash
# Activate virtual environment
cd backend
source .venv/bin/activate

# Test signature detector
python3 tests/test_signature_detector.py

# Test orchestrator
python3 tests/test_orchestrator.py
```

## Statistics

### Signature Coverage

| Category | Signatures | Hash Signatures |
|----------|-----------|-----------------|
| Web Attacks | 17 | 0 |
| Authentication | 15 | 0 |
| Network Attacks | 20 | 0 |
| Malware & Exploits | 21 | 3 |
| **Total** | **73** | **3** |

### Attack Types Covered

- **MITRE ATT&CK Tactics**:
  - Initial Access
  - Execution
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Credential Access
  - Discovery
  - Lateral Movement
  - Collection
  - Command and Control
  - Exfiltration
  - Impact

## Performance

- **Pattern Compilation**: Regex patterns are compiled once at initialization
- **Parallel Processing**: All detectors run concurrently
- **Efficient Matching**: Field-specific matching reduces unnecessary checks
- **Caching**: Compiled patterns cached in memory

## Usage Example

```python
from analyzers.orchestrator import AnalysisOrchestrator
from storage.db_manager import DuckDBManager

# Initialize
db_manager = DuckDBManager("data/duckdb/logs.db")
config = {
    'analysis_interval': 60,
    'batch_size': 10000,
    'signature_dir': 'config/signatures',
    'blocked_ips_file': 'config/blocked_ips.txt'
}

orchestrator = AnalysisOrchestrator(db_manager, config)

# Run continuous analysis
await orchestrator.start()
```

## Next Steps

To complete the analysis layer, implement:

1. **Anomaly Detector** - Statistical and ML-based anomaly detection
2. **Heuristic Analyzer** - Rule-of-thumb based detection
3. **Behavioral Analyzer** - UEBA (User and Entity Behavior Analytics)
4. **Rule Engine** - MITRE ATT&CK correlation rules
5. **Network Analyzer** - Network traffic pattern analysis
6. **Threat Intel Matcher** - IoC matching against threat feeds

## File Structure

```
backend/
├── analyzers/
│   ├── __init__.py
│   ├── signature_detector.py    # ✓ Implemented
│   ├── orchestrator.py           # ✓ Implemented
│   ├── anomaly_detector.py       # TODO
│   ├── heuristic_analyzer.py     # TODO
│   ├── behavioral_analyzer.py    # TODO
│   ├── rule_engine.py            # TODO
│   ├── network_analyzer.py       # TODO
│   └── threat_intel_matcher.py   # TODO
├── tests/
│   ├── test_signature_detector.py  # ✓ Implemented
│   └── test_orchestrator.py        # ✓ Implemented
config/
├── signatures/
│   ├── web_attacks.yaml          # ✓ Implemented
│   ├── auth_attacks.yaml         # ✓ Implemented
│   ├── network_attacks.yaml      # ✓ Implemented
│   └── malware.yaml              # ✓ Implemented
└── blocked_ips.txt               # ✓ Implemented
```

## Maintenance

### Adding New Signatures

1. Edit the appropriate YAML file in `config/signatures/`
2. Follow the signature format:
```yaml
- id: SIG-XXX-###
  name: Signature Name
  severity: critical|high|medium|low|info
  category: attack_category
  description: Description of what this detects
  patterns:
    - regex: "pattern1"
    - regex: "pattern2"
  fields:
    - raw
    - message
    - normalized.field_name
```

3. Reload signatures: `orchestrator.reload_detectors()`

### Adding Blocked IPs

1. Edit `config/blocked_ips.txt`
2. Add one IP per line
3. Reload: `detector.reload_blocked_ips()`

### Adding Hash Signatures

Add to signature YAML:
```yaml
hashes:
  - value: "hash_value_in_lowercase"
    type: md5|sha1|sha256
    description: "Description of malware"
```
