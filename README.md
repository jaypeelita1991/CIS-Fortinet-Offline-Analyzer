# FortiGate Security Analysis Toolkit

Complete suite of tools for analyzing, auditing, and securing FortiGate firewall configurations offline.

## What You Get

### 1. **General Security Analyzer** 
`fortigate_config_analyzer.py` - 60+ security checks
- Misconfigurations detection
- Best practices validation
- Security scoring
- Multiple report formats

### 2. **CIS Benchmark Scanner**
`cis_fortigate_scanner.py` - 31 CIS controls
- Official CIS compliance checking
- Automated remediation guidance
- Level 1 & Level 2 profiles
- Multiple report formats

### 3. **YAML Fixer**
`fix_fortigate_yaml.py` - YAML syntax repair
- Fixes multi-value issues
- Removes escaped quotes
- Handles tab characters
- Validates output

### 4. **Diagnostic Tools**
- `yaml_diagnostic.py` - YAML file analysis
- `system_check.py` - Environment verification

## Quick Start

### Install Dependencies
```bash
pip install pyyaml
```

### Run Security Analysis
```bash
# General security scan
python fortigate_config_analyzer.py your_config.conf html

# CIS compliance scan
python cis_fortigate_scanner.py your_config.conf html
```

### Fix YAML Issues
```bash
# If you have a .yaml file with errors
python fix_fortigate_yaml.py your_config.yaml
python fortigate_config_analyzer.py your_config_fixed.yaml html
```

## Tools Comparison

| Feature | Security Analyzer | CIS Scanner |
|---------|------------------|-------------|
| **Focus** | General security & best practices | CIS Benchmark compliance |
| **Checks** | 60+ across 11 categories | 31 CIS controls |
| **Output** | Security score 0-100 | Compliance % |
| **Use Case** | Daily security audits | Compliance reporting |
| **Reports** | Text, JSON, HTML | Text, JSON, HTML, CSV |
| **Remediation** | General recommendations | Specific CIS guidance |

**Recommendation:** Run BOTH tools for comprehensive coverage!

## Files Overview

### Core Analyzers
- **`fortigate_config_analyzer.py`** - Main security analyzer (1,000+ lines)
- **`cis_fortigate_scanner.py`** - CIS benchmark scanner (1,600+ lines)

### Utilities
- **`fix_fortigate_yaml.py`** - YAML syntax fixer
- **`yaml_diagnostic.py`** - YAML file diagnostics
- **`system_check.py`** - Environment checker

### Documentation
- **`README.md`** - This file
- **`QUICKSTART.md`** - Fast start guide
- **`CIS_SCANNER_GUIDE.md`** - CIS scanner manual
- **`FORTIGATE_YAML_STRUCTURE.md`** - YAML format guide
- **`TROUBLESHOOTING.md`** - Problem solving
- **`YAML_TROUBLESHOOTING.md`** - YAML-specific issues
- **`COMPLETE_FIX_GUIDE.md`** - Comprehensive fixes

### Samples
- **`sample_config.txt`** - CLI format example
- **`sample_config.yaml`** - YAML format example

## 🎓 Usage Workflows

### Workflow 1: New Configuration Audit

```bash
# 1. Check if file is valid
python yaml_diagnostic.py config.yaml

# 2. Fix any issues
python fix_fortigate_yaml.py config.yaml

# 3. Run security analysis
python fortigate_config_analyzer.py config_fixed.yaml html

# 4. Run CIS compliance
python cis_fortigate_scanner.py config_fixed.yaml html

# 5. Review both reports
open fortigate_analysis_report.html
open cis_compliance_report.html
```

### Workflow 2: Regular Compliance Scan

```bash
# Monthly compliance check
python cis_fortigate_scanner.py production_fw.conf html
DATE=$(date +%Y-%m)
mv cis_compliance_report.html "reports/compliance_$DATE.html"
```

### Workflow 3: Pre-Change Validation

```bash
# Before making changes
python fortigate_config_analyzer.py current.conf html
mv fortigate_analysis_report.html before_report.html

# After changes
python fortigate_config_analyzer.py updated.conf html
mv fortigate_analysis_report.html after_report.html

# Compare
diff before_report.html after_report.html
```

### Workflow 4: CI/CD Integration

```bash
#!/bin/bash
# config_validation.sh

CONFIG=$1
SECURITY_THRESHOLD=80
COMPLIANCE_THRESHOLD=75

# Run both scans
python fortigate_config_analyzer.py $CONFIG json
SEC_SCORE=$(jq -r '.security_score' fortigate_analysis_report.json)

python cis_fortigate_scanner.py $CONFIG json
CIS_SCORE=$(jq -r '.compliance_score' cis_compliance_report.json)

echo "Security Score: $SEC_SCORE%"
echo "CIS Compliance: $CIS_SCORE%"

if (( $(echo "$SEC_SCORE < $SECURITY_THRESHOLD" | bc -l) )) || \
   (( $(echo "$CIS_SCORE < $COMPLIANCE_THRESHOLD" | bc -l) )); then
    echo "❌ FAIL: Scores below threshold"
    exit 1
fi

echo "✅ PASS: Configuration meets requirements"
```

## 🔍 What Each Tool Checks

### Security Analyzer Checks

**System Configuration (6 checks)**
- Hostname settings
- Timezone configuration
- Admin timeout
- Pre-login banner

**Administrative Access (10 checks)**
- Default accounts
- Two-factor authentication
- Trusted host restrictions
- Password policies

**Firewall Policies (8 checks)**
- Overly permissive rules
- Logging configuration
- Security profiles
- NAT settings

**Interface Configuration (5 checks)**
- Management access
- Interface descriptions
- DHCP configuration

**VPN Settings (7 checks)**
- Encryption strength
- DH groups
- Dead Peer Detection
- TLS versions

**Logging & Monitoring (4 checks)**
- Remote syslog
- Disk logging
- Log retention

**SNMP Configuration (5 checks)**
- SNMPv3 usage
- Community strings
- Host restrictions

**High Availability (3 checks)**
- HA encryption
- HA passwords
- Heartbeat configuration

**Network Services (6 checks)**
- DNS configuration
- NTP synchronization
- Routing tables

### CIS Scanner Checks

**31 CIS Controls Across:**
- Initial Setup (5)
- Logging & Monitoring (4)
- Network Configuration (5)
- VPN Configuration (4)
- Firewall Policy (4)
- SNMP Configuration (3)
- High Availability (2)
- System Configuration (4)

See `CIS_SCANNER_GUIDE.md` for complete list.

## 📈 Understanding Scores

### Security Analyzer Score

| Score | Rating | Interpretation |
|-------|--------|----------------|
| 90-100 | ✅ Excellent | Minimal security issues |
| 80-89 | 🟢 Good | Few minor issues |
| 70-79 | 🟡 Fair | Several improvements needed |
| 60-69 | 🟠 Poor | Significant security gaps |
| 0-59 | 🔴 Critical | Immediate attention required |

**Calculation:**
- Start at 100
- CRITICAL: -15 points each
- HIGH: -8 points each
- MEDIUM: -3 points each
- LOW: -1 point each

### CIS Compliance Score

**Calculation:**
- Pass / (Pass + Fail) × 100
- Manual reviews excluded
- Not Applicable excluded

| Score | Status | Action |
|-------|--------|--------|
| 90-100% | Excellent | Maintain posture |
| 70-89% | Good | Fix critical findings |
| 50-69% | Fair | Significant work needed |
| <50% | Poor | Immediate remediation |

## 🛠️ Common Use Cases

### Use Case 1: Security Audit
**Tool:** `fortigate_config_analyzer.py`
**Frequency:** Weekly
**Output:** HTML report for team review

### Use Case 2: Compliance Reporting
**Tool:** `cis_fortigate_scanner.py`
**Frequency:** Monthly
**Output:** HTML for management, CSV for tracking

### Use Case 3: Configuration Changes
**Tool:** Both analyzers
**Frequency:** Before/after every change
**Output:** JSON for automated comparison

### Use Case 4: Onboarding New Firewall
**Tool:** Both analyzers + diagnostic
**Frequency:** One-time
**Output:** Full HTML reports + remediation plan

### Use Case 5: Continuous Monitoring
**Tools:** All tools
**Frequency:** Automated daily scans
**Output:** JSON to SIEM/monitoring system

## 🔧 Troubleshooting

### Problem: Configuration Won't Load

**Solution:**
```bash
# 1. Check format
head -20 your_config.yaml

# 2. Diagnose
python yaml_diagnostic.py your_config.yaml

# 3. Fix
python fix_fortigate_yaml.py your_config.yaml

# 4. Retry
python fortigate_config_analyzer.py your_config_fixed.yaml
```

### Problem: YAML Syntax Errors

**Error:** `expected <block end>, but found '<scalar>'`

**Solution:**
```bash
python fix_fortigate_yaml.py config.yaml
# Automatically fixes:
# - Multiple quoted values
# - Escaped quotes
# - Tab characters
```

### Problem: Low Scores

**Focus on:**
1. Enable 2FA (HIGH impact)
2. Remove WAN admin access (CRITICAL)
3. Apply security profiles (HIGH)
4. Enable logging (MEDIUM)
5. Fix VPN encryption (HIGH)

### Problem: Tool Dependencies

**Check:**
```bash
python system_check.py
# Verifies:
# - Python version
# - PyYAML installed
# - File permissions
# - Tool availability
```

## Documentation Index

| Document | Purpose |
|----------|---------|
| **README.md** | You are here - main overview |
| **QUICKSTART.md** | 5-minute start guide |
| **CIS_SCANNER_GUIDE.md** | Complete CIS scanner manual |
| **FORTIGATE_YAML_STRUCTURE.md** | Understanding FortiGate YAML |
| **TROUBLESHOOTING.md** | General problem solving |
| **YAML_TROUBLESHOOTING.md** | YAML-specific issues |
| **COMPLETE_FIX_GUIDE.md** | Step-by-step fixes |

## Best Practices

### Regular Scanning
- **Daily:** Automated security scans
- **Weekly:** Manual review of findings
- **Monthly:** CIS compliance reports
- **Quarterly:** Full audit with manual checks

### Version Control
```bash
# Track your configs
git add configs/fortigate_$(date +%Y%m%d).conf
git commit -m "Config snapshot $(date +%Y-%m-%d)"

# Track reports
git add reports/scan_$(date +%Y%m%d).html
git commit -m "Security scan $(date +%Y-%m-%d)"
```

### Automated Monitoring
```bash
# crontab -e
0 2 * * * /scripts/daily_scan.sh
0 9 1 * * /scripts/monthly_cis_scan.sh
```

### Documentation
- Keep scan history
- Document exceptions
- Track remediation
- Update runbooks

## Security Notes

- **No network access** - All tools run offline
- **No data transmission** - Everything stays local
- **Config confidentiality** - Remove sensitive data before sharing
- **Backup configs** - Keep original files safe
- **Review changes** - Test fixes in lab first

## Getting Help

### Self-Service
1. Check relevant guide (see Documentation Index)
2. Review troubleshooting sections
3. Try with sample_config.txt
4. Read error messages carefully

### Quick Reference
```bash
# Test with sample
python fortigate_config_analyzer.py sample_config.txt html

# Check system
python system_check.py

# Diagnose YAML
python yaml_diagnostic.py your_file.yaml

# Fix YAML
python fix_fortigate_yaml.py your_file.yaml
```

## Sample Reports

Both tools generate professional HTML reports with:
- Executive summary
- Visual dashboards
- Detailed findings
- Specific recommendations
- Remediation commands
- Compliance metrics

**Example Output:**
```
Security Score: 85/100
Compliance: 87.5%

Critical Issues: 1
- Admin access on WAN interface

High Issues: 3
- No 2FA on admin accounts
- Weak VPN encryption
- Missing IPS profiles

Medium Issues: 7
Low Issues: 4
```

## Learning Resources

- **CIS Benchmarks:** [cisecurity.org](https://www.cisecurity.org/benchmark/fortinet)
- **FortiGate Docs:** [docs.fortinet.com](https://docs.fortinet.com/)
- **NSA Security Guide:** [NSA Cybersecurity](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/)
- **Fortinet Best Practices:** [Fortinet Documentation](https://docs.fortinet.com/document/fortigate/7.4.0/best-practices)

## Advanced Usage

### Python API

```python
from fortigate_config_analyzer import FortiGateConfigAnalyzer

# Load and analyze
analyzer = FortiGateConfigAnalyzer('config.conf')
analyzer.load_config()
report = analyzer.analyze()

# Check specific findings
critical = [f for f in report.findings if f.severity.value == 'CRITICAL']
print(f"Critical issues: {len(critical)}")

# Custom logic
if report.score < 80:
    send_alert_to_team()
```

### Batch Processing

```bash
#!/bin/bash
# scan_all.sh

for fw in firewall_configs/*.conf; do
    echo "Scanning $(basename $fw)..."
    
    python fortigate_config_analyzer.py $fw json > /dev/null
    python cis_fortigate_scanner.py $fw json > /dev/null
    
    SEC_SCORE=$(jq -r '.security_score' fortigate_analysis_report.json)
    CIS_SCORE=$(jq -r '.compliance_score' cis_compliance_report.json)
    
    echo "$(basename $fw): Security=$SEC_SCORE% CIS=$CIS_SCORE%"
done
```

## Quick Checklist

Before deployment:
- [ ] Python 3.6+ installed
- [ ] PyYAML installed (`pip install pyyaml`)
- [ ] Tools tested with sample_config.txt
- [ ] Output directory writable
- [ ] Config files accessible

After first scan:
- [ ] Review both HTML reports
- [ ] Prioritize critical findings
- [ ] Document current state
- [ ] Create remediation plan
- [ ] Schedule follow-up scans

## License & Credits

These tools are provided for security auditing and compliance checking. Results should be reviewed by qualified security professionals.

Based on:
- CIS Fortinet FortiGate Benchmark v1.3.0
- FortiOS 7.x Security Best Practices
- Industry standard security frameworks

## You're Ready!

```bash
# Start here
python fortigate_config_analyzer.py your_config.conf html
python cis_fortigate_scanner.py your_config.conf html

# Open reports
open fortigate_analysis_report.html
open cis_compliance_report.html

# Review findings and improve security!
```

**Questions?** Check the documentation guides above!

---

**Complete FortiGate Security Analysis Toolkit** - Professional offline configuration auditing
