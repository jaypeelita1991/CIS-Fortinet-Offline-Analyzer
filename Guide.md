# CIS Fortinet FortiGate Benchmark Scanner - Complete Guide

## Quick Start

```bash
python cis_fortigate_scanner.py fortigate.conf html
```

Opens a beautiful HTML report showing your compliance score and all findings!

## What It Does

Automatically checks your FortiGate configuration against **31 CIS security controls**:

- Password policies & 2FA
- Admin access restrictions  
- Firewall logging
- VPN encryption strength
- UTM security profiles
- SNMP hardening
- System configuration

**Output:** Compliance score (0-100%) + detailed remediation steps

## Report Formats

| Format | Command | Best For |
|--------|---------|----------|
| HTML | `python cis_fortigate_scanner.py config.conf html` | Management reports, sharing |
| Text | `python cis_fortigate_scanner.py config.conf text` | Documentation, CLI |
| JSON | `python cis_fortigate_scanner.py config.conf json` | Automation, CI/CD |
| CSV | `python cis_fortigate_scanner.py config.conf csv` | Excel, trending |

## All 31 CIS Controls

### Authentication (5 controls)
- Password complexity & expiration
- Default admin account renamed
- Two-factor authentication
- Trusted host restrictions

### Logging (4 controls)  
- Policy logging enabled
- Remote syslog configured
- NTP synchronization
- Timezone settings

### Network Security (5 controls)
- Telnet/HTTP disabled
- HTTPS restricted
- No WAN admin access
- Session timeout

### VPN Security (4 controls)
- Strong encryption (AES256)
- Strong DH groups (14+)
- Dead Peer Detection
- TLS 1.2 minimum

### Firewall Policies (4 controls)
- Default deny rule
- UTM profiles applied
- Antivirus enabled
- IPS enabled

### SNMP (3 controls)
- SNMPv3 usage
- No default strings
- Host restrictions

### High Availability (2 controls)
- Heartbeat encryption
- HA password set

### System Config (4 controls)
- Pre-login banner
- Strong crypto
- Auto-updates
- Firmware current

## Understanding Your Score

| Score | Status | Action |
|-------|--------|--------|
| 90-100% | ✅ Excellent | Maintain |
| 70-89% | 🟡 Good | Fix critical items |
| 50-69% | 🟠 Fair | Significant work needed |
| <50% | 🔴 Poor | Immediate attention |

## Sample Results

```
Compliance Score: 72.4%

SUMMARY
  Pass:           21 controls
  Fail:            8 controls  
  Manual Review:   1 control
  Not Applicable:  1 control

TOP FAILURES
❌ [1.4] Two-factor authentication not enabled
❌ [3.4] Admin access enabled on WAN
❌ [4.1] Weak VPN encryption
❌ [5.2] No UTM profiles on policies
```

## Remediation Workflow

### 1. Run Scan
```bash
python cis_fortigate_scanner.py current.conf html
open cis_compliance_report.html
```

### 2. Fix Critical Issues First

** Critical (Fix Now):**
- Admin access on WAN
- Weak VPN encryption  
- No 2FA enabled
- Missing security profiles

** High (Fix This Week):**
- Default admin account
- Telnet/HTTP enabled
- No remote logging
- Weak SNMP

** Medium (Fix This Month):**
- Password policies
- Policy logging
- System hardening

### 3. Apply Fixes

Each failed control includes exact FortiGate CLI commands:

```bash
# Example: Enable 2FA
config system admin
    edit admin
        set two-factor fortitoken
    next
end
```

### 4. Verify

```bash
python cis_fortigate_scanner.py updated.conf html
# Check improved score!
```

## CI/CD Integration

```bash
#!/bin/bash
# compliance_gate.sh

python cis_fortigate_scanner.py $CONFIG_FILE json

SCORE=$(python -c "import json; print(json.load(open('cis_compliance_report.json'))['compliance_score'])")

if (( $(echo "$SCORE < 80" | bc -l) )); then
    echo "❌ FAIL: Score $SCORE% below threshold"
    exit 1
fi

echo "✅ PASS: Compliance $SCORE%"
```

## Best Practices

### Regular Scanning
- **Monthly**: Scan all firewalls
- **After Changes**: Before/after comparison
- **Quarterly**: Full audit with manual reviews

### Track Progress
```bash
# Monthly tracking
DATE=$(date +%Y-%m)
python cis_fortigate_scanner.py config.conf csv
mv cis_compliance_report.csv "history/scan_$DATE.csv"
```

### Automation
```bash
# Batch scan all configs
for cfg in configs/*.conf; do
    python cis_fortigate_scanner.py $cfg json
    mv cis_compliance_report.json "results/$(basename $cfg .conf).json"
done
```

## What Gets Checked vs. What Doesn't

### Checked Automatically
- Configuration settings
- Policy rules
- Feature enablement  
- Security hardening

### Requires Manual Verification
- Actual firmware version
- Certificate expiration
- User behavior
- Physical security
- Operational procedures

## Common Issues

### Low Score? Start Here:

1. **Enable 2FA** - Biggest security improvement
2. **Remove WAN admin access** - Critical vulnerability
3. **Apply UTM profiles** - Enable AV, IPS, Web Filter
4. **Fix VPN crypto** - Use AES256, DH 14+
5. **Enable logging** - Required for compliance

### Config Won't Load?

```bash
# For YAML files
python fix_fortigate_yaml.py config.yaml
python cis_fortigate_scanner.py config_fixed.yaml html

# For CLI files
python cis_fortigate_scanner.py config.conf html
```

## Quick Reference

```bash
# Basic scan
python cis_fortigate_scanner.py config.conf

# HTML report (recommended)
python cis_fortigate_scanner.py config.conf html

# Check score only
python cis_fortigate_scanner.py config.conf | grep "Compliance Score"

# Export for Excel
python cis_fortigate_scanner.py config.conf csv

# CI/CD JSON
python cis_fortigate_scanner.py config.conf json
```

## Report Sections

### HTML Report Includes:
- Compliance score with color coding
- Summary dashboard
- Failed controls with remediation
- Passed controls  
- Manual review items
- Detailed recommendations

### Each Finding Shows:
- Control ID and title
- Category and CIS level
- Current configuration
- Security risk
- Exact fix commands
- CIS recommendation

## Advanced Usage

### Compare Before/After

```bash
# Before changes
python cis_fortigate_scanner.py before.conf json
cp cis_compliance_report.json before.json

# After changes  
python cis_fortigate_scanner.py after.conf json
cp cis_compliance_report.json after.json

# Compare
diff <(jq -S . before.json) <(jq -S . after.json)
```

### Filter Results

```python
# Show only failed Level 1 controls
import json

with open('cis_compliance_report.json') as f:
    data = json.load(f)
    
failed_l1 = [
    r for r in data['results'] 
    if r['status'] == 'Fail' and r['level'] == 'Level 1'
]

for control in failed_l1:
    print(f"{control['control_id']}: {control['title']}")
```

## Compliance Tracking Dashboard

Create a simple tracker:

```bash
#!/bin/bash
# dashboard.sh

echo "CIS Compliance Dashboard"
echo "========================"
echo ""

for config in production/*.conf; do
    FW=$(basename $config .conf)
    python cis_fortigate_scanner.py $config json >/dev/null 2>&1
    
    SCORE=$(jq -r '.compliance_score' cis_compliance_report.json)
    FAILED=$(jq -r '.summary.Fail' cis_compliance_report.json)
    
    printf "%-20s Score: %5.1f%%  Failed: %2d\n" $FW $SCORE $FAILED
done
```

Output:
```
CIS Compliance Dashboard
========================

firewall_hq          Score:  87.5%  Failed:  4
firewall_branch1     Score:  76.2%  Failed:  7
firewall_dmz         Score:  91.3%  Failed:  3
```

## Integration Examples

### Ansible Playbook

```yaml
- name: CIS Compliance Scan
  hosts: fortigate_devices
  tasks:
    - name: Export config
      fortios_configuration_backup:
        output: "/tmp/{{ inventory_hostname }}.conf"
    
    - name: Run CIS scan
      command: python cis_fortigate_scanner.py /tmp/{{ inventory_hostname }}.conf json
      
    - name: Check compliance
      shell: |
        SCORE=$(jq -r '.compliance_score' cis_compliance_report.json)
        if (( $(echo "$SCORE < 80" | bc -l) )); then
          echo "FAIL"
          exit 1
        fi
```

### Slack Notifications

```bash
#!/bin/bash
# notify_compliance.sh

python cis_fortigate_scanner.py $CONFIG json

SCORE=$(jq -r '.compliance_score' cis_compliance_report.json)
FAILED=$(jq -r '.summary.Fail' cis_compliance_report.json)

if (( $(echo "$SCORE < 80" | bc -l) )); then
    curl -X POST $SLACK_WEBHOOK \
      -H 'Content-Type: application/json' \
      -d "{
        \"text\": \"⚠️ CIS Compliance Alert\",
        \"attachments\": [{
          \"color\": \"danger\",
          \"text\": \"Score: $SCORE%\nFailed Controls: $FAILED\"
        }]
      }"
fi
```

## Troubleshooting

### "Configuration not loaded"
- Check file path is correct
- Verify file is FortiGate format
- Try with sample_config.txt first

### "No controls checked"
- Config file might be empty
- Check parsing worked correctly
- Review config structure

### "All controls failed"
- May be YAML format issue
- Run fix_fortigate_yaml.py first
- Check config completeness

## Resources

- **CIS Benchmark**: [cisecurity.org](https://www.cisecurity.org/benchmark/fortinet)
- **FortiGate Docs**: [docs.fortinet.com](https://docs.fortinet.com/)
- **Security Guide**: [Fortinet Best Practices](https://docs.fortinet.com/document/fortigate/7.4.0/best-practices)

---

## Summary Card

```
WHAT: CIS Fortinet FortiGate Benchmark Scanner
CHECKS: 31 automated security controls
OUTPUT: Compliance score + remediation guide
USAGE: python cis_fortigate_scanner.py config.conf html
FORMATS: HTML, Text, JSON, CSV
TIME: ~5 seconds per scan
LEVEL: CIS Level 1 & Level 2
```

**Ready to scan?** Just run the command and open the HTML report!
