#!/usr/bin/env python3
"""
CIS Fortinet FortiGate Benchmark Scanner
Scans FortiGate configuration files against CIS Fortinet FortiGate Benchmark v1.3.0

Based on CIS Fortinet FortiGate 7.x Benchmark recommendations
https://www.cisecurity.org/benchmark/fortinet
"""

import re
import json
import yaml
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ComplianceLevel(Enum):
    """CIS Benchmark profile levels"""
    LEVEL_1 = "Level 1"
    LEVEL_2 = "Level 2"


class ComplianceStatus(Enum):
    """Compliance check result status"""
    PASS = "Pass"
    FAIL = "Fail"
    MANUAL = "Manual Review Required"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class CISControl:
    """Represents a single CIS control"""
    control_id: str
    title: str
    description: str
    level: ComplianceLevel
    automated: bool
    recommendation: str
    remediation: str
    category: str


@dataclass
class ComplianceResult:
    """Result of a compliance check"""
    control: CISControl
    status: ComplianceStatus
    finding: str = ""
    evidence: str = ""
    current_value: str = ""


@dataclass
class CISReport:
    """Complete CIS compliance report"""
    scan_date: str
    config_file: str
    results: List[ComplianceResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    compliance_score: float = 0.0


class CISFortiGateScanner:
    """Scanner for CIS Fortinet FortiGate Benchmark"""
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.report = CISReport(
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            config_file=config_file
        )
        self._init_cis_controls()
    
    def _init_cis_controls(self):
        """Initialize CIS control definitions"""
        self.cis_controls = [
            # 1. Initial Setup
            CISControl(
                "1.1",
                "Ensure administrator password complexity is enabled",
                "Strong password policies help prevent unauthorized access",
                ComplianceLevel.LEVEL_1,
                True,
                "Enable strong password requirements with minimum length, complexity rules",
                "config system password-policy\n    set status enable\n    set minimum-length 12\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-number 1\n    set min-non-alphanumeric 1\nend",
                "Authentication"
            ),
            CISControl(
                "1.2",
                "Ensure administrator password expiration is configured",
                "Regular password changes reduce the risk of compromised credentials",
                ComplianceLevel.LEVEL_1,
                True,
                "Set password expiration to 90 days or less",
                "config system password-policy\n    set expire-day 90\nend",
                "Authentication"
            ),
            CISControl(
                "1.3",
                "Ensure default administrator account is renamed",
                "Default account names are well-known and targeted by attackers",
                ComplianceLevel.LEVEL_1,
                True,
                "Rename the default 'admin' account or create a new admin and disable default",
                "config system admin\n    rename admin to <new_admin_name>\nend",
                "Authentication"
            ),
            CISControl(
                "1.4",
                "Ensure two-factor authentication is enabled for administrators",
                "2FA provides an additional layer of security beyond passwords",
                ComplianceLevel.LEVEL_1,
                True,
                "Enable two-factor authentication for all administrator accounts",
                "config system admin\n    edit <admin_name>\n        set two-factor fortitoken\n    next\nend",
                "Authentication"
            ),
            CISControl(
                "1.5",
                "Ensure trusted hosts are configured for all administrators",
                "Restricting access to specific IP addresses reduces attack surface",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure trusted host IP addresses for each administrator",
                "config system admin\n    edit <admin_name>\n        set trusthost1 <trusted_ip> <netmask>\n    next\nend",
                "Authentication"
            ),
            
            # 2. Logging and Monitoring
            CISControl(
                "2.1",
                "Ensure logging is enabled on all firewall policies",
                "Logging provides visibility into network traffic and security events",
                ComplianceLevel.LEVEL_1,
                True,
                "Enable 'Log Allowed Traffic' on all accept policies",
                "config firewall policy\n    edit <policy_id>\n        set logtraffic all\n    next\nend",
                "Logging"
            ),
            CISControl(
                "2.2",
                "Ensure FortiGate is configured to log to a remote syslog server",
                "Centralized logging prevents log tampering and provides backup",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure remote syslog server for log collection",
                "config log syslogd setting\n    set status enable\n    set server <syslog_ip>\n    set port 514\nend",
                "Logging"
            ),
            CISControl(
                "2.3",
                "Ensure NTP is configured and synchronized",
                "Accurate time is critical for logging, authentication, and certificates",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure NTP servers and verify synchronization",
                "config system ntp\n    set ntpsync enable\n    set type fortiguard\nend",
                "Logging"
            ),
            CISControl(
                "2.4",
                "Ensure timezone is configured correctly",
                "Correct timezone ensures accurate log timestamps",
                ComplianceLevel.LEVEL_1,
                True,
                "Set the appropriate timezone for your location",
                "config system global\n    set timezone <timezone_id>\nend",
                "Logging"
            ),
            
            # 3. Network Configuration
            CISControl(
                "3.1",
                "Ensure HTTPS administrative access is restricted to trusted networks",
                "Limiting admin access to trusted networks reduces unauthorized access risk",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure HTTPS access only from management networks",
                "config system interface\n    edit <interface>\n        set allowaccess ping\n    next\nend",
                "Network Security"
            ),
            CISControl(
                "3.2",
                "Ensure Telnet administrative access is disabled",
                "Telnet transmits credentials in cleartext",
                ComplianceLevel.LEVEL_1,
                True,
                "Disable Telnet on all interfaces",
                "config system interface\n    edit <interface>\n        unset allowaccess telnet\n    next\nend",
                "Network Security"
            ),
            CISControl(
                "3.3",
                "Ensure HTTP administrative access is disabled",
                "HTTP transmits data in cleartext; use HTTPS only",
                ComplianceLevel.LEVEL_1,
                True,
                "Disable HTTP admin access on all interfaces",
                "config system interface\n    edit <interface>\n        unset allowaccess http\n    next\nend",
                "Network Security"
            ),
            CISControl(
                "3.4",
                "Ensure administrative access is not enabled on WAN interfaces",
                "Management interfaces should not be exposed to the Internet",
                ComplianceLevel.LEVEL_1,
                True,
                "Remove all administrative protocols from WAN interfaces",
                "config system interface\n    edit <wan_interface>\n        set allowaccess ping\n    next\nend",
                "Network Security"
            ),
            CISControl(
                "3.5",
                "Ensure idle timeout for administrative sessions is configured",
                "Automatic logout of idle sessions prevents unauthorized access",
                ComplianceLevel.LEVEL_1,
                True,
                "Set admin idle timeout to 15 minutes or less",
                "config system global\n    set admintimeout 15\nend",
                "Network Security"
            ),
            
            # 4. VPN Configuration
            CISControl(
                "4.1",
                "Ensure IKE encryption is set to AES256 or higher",
                "Strong encryption protects VPN communications",
                ComplianceLevel.LEVEL_1,
                True,
                "Use AES256 for IKE encryption",
                "config vpn ipsec phase1-interface\n    edit <vpn_name>\n        set proposal aes256-sha256\n    next\nend",
                "VPN Security"
            ),
            CISControl(
                "4.2",
                "Ensure IPsec uses strong DH groups (14 or higher)",
                "Weak DH groups are vulnerable to cryptographic attacks",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure DH group 14, 19, 20, or 21",
                "config vpn ipsec phase1-interface\n    edit <vpn_name>\n        set dhgrp 14 19 20 21\n    next\nend",
                "VPN Security"
            ),
            CISControl(
                "4.3",
                "Ensure Dead Peer Detection (DPD) is enabled",
                "DPD detects and responds to failed VPN connections",
                ComplianceLevel.LEVEL_1,
                True,
                "Enable DPD on all IPsec tunnels",
                "config vpn ipsec phase1-interface\n    edit <vpn_name>\n        set dpd on-idle\n    next\nend",
                "VPN Security"
            ),
            CISControl(
                "4.4",
                "Ensure SSL VPN uses TLS 1.2 or higher",
                "Older TLS versions have known vulnerabilities",
                ComplianceLevel.LEVEL_1,
                True,
                "Set minimum TLS version to 1.2 or 1.3",
                "config vpn ssl settings\n    set ssl-min-proto-ver tls1-2\nend",
                "VPN Security"
            ),
            
            # 5. Firewall Policy
            CISControl(
                "5.1",
                "Ensure default deny policy exists at the end of policy list",
                "Explicit deny rule provides defense in depth",
                ComplianceLevel.LEVEL_1,
                True,
                "Create a deny-all policy as the last rule",
                "config firewall policy\n    edit <last_policy_id>\n        set name \"Deny-All\"\n        set srcintf any\n        set dstintf any\n        set srcaddr all\n        set dstaddr all\n        set action deny\n    next\nend",
                "Firewall Policy"
            ),
            CISControl(
                "5.2",
                "Ensure UTM profiles are applied to firewall policies",
                "UTM features provide additional security inspection",
                ComplianceLevel.LEVEL_1,
                True,
                "Apply AV, IPS, Web Filter, and App Control to policies",
                "config firewall policy\n    edit <policy_id>\n        set av-profile default\n        set ips-sensor default\n        set webfilter-profile default\n        set application-list default\n    next\nend",
                "Firewall Policy"
            ),
            CISControl(
                "5.3",
                "Ensure anti-virus scanning is enabled",
                "AV scanning protects against malware",
                ComplianceLevel.LEVEL_1,
                True,
                "Enable AV profiles on accept policies",
                "config firewall policy\n    edit <policy_id>\n        set av-profile default\n    next\nend",
                "Firewall Policy"
            ),
            CISControl(
                "5.4",
                "Ensure IPS is enabled on firewall policies",
                "IPS detects and blocks known attack patterns",
                ComplianceLevel.LEVEL_1,
                True,
                "Enable IPS sensors on accept policies",
                "config firewall policy\n    edit <policy_id>\n        set ips-sensor default\n    next\nend",
                "Firewall Policy"
            ),
            
            # 6. SNMP Configuration
            CISControl(
                "6.1",
                "Ensure SNMPv3 is used",
                "SNMPv3 provides authentication and encryption",
                ComplianceLevel.LEVEL_1,
                True,
                "Use SNMPv3 instead of v1/v2c",
                "config system snmp user\n    edit <user>\n        set security-level auth-priv\n    next\nend",
                "SNMP"
            ),
            CISControl(
                "6.2",
                "Ensure default SNMP community strings are changed",
                "Default community strings are widely known",
                ComplianceLevel.LEVEL_1,
                True,
                "Change 'public' and 'private' community strings",
                "config system snmp community\n    edit 1\n        set name <unique_string>\n    next\nend",
                "SNMP"
            ),
            CISControl(
                "6.3",
                "Ensure SNMP is restricted to authorized hosts",
                "Limit SNMP access to management stations only",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure host restrictions for SNMP communities",
                "config system snmp community\n    edit 1\n        config hosts\n            edit 1\n                set ip <mgmt_ip> <netmask>\n            next\n        end\n    next\nend",
                "SNMP"
            ),
            
            # 7. High Availability
            CISControl(
                "7.1",
                "Ensure HA heartbeat encryption is enabled",
                "Encrypted heartbeat prevents eavesdropping on HA traffic",
                ComplianceLevel.LEVEL_2,
                True,
                "Enable HA heartbeat encryption",
                "config system ha\n    set encryption enable\nend",
                "High Availability"
            ),
            CISControl(
                "7.2",
                "Ensure HA password is configured",
                "HA password prevents unauthorized devices from joining cluster",
                ComplianceLevel.LEVEL_1,
                True,
                "Set a strong HA password",
                "config system ha\n    set password <strong_password>\nend",
                "High Availability"
            ),
            
            # 8. System Configuration
            CISControl(
                "8.1",
                "Ensure pre-login banner is configured",
                "Legal banners inform users of monitoring and access policies",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure pre-login banner with legal notice",
                "config system global\n    set pre-login-banner enable\n    set pre-login-banner-message \"Authorized access only\"\nend",
                "System Configuration"
            ),
            CISControl(
                "8.2",
                "Ensure strong SSL/TLS cipher suites are configured",
                "Strong ciphers protect administrative access",
                ComplianceLevel.LEVEL_1,
                True,
                "Configure high-strength cipher suites only",
                "config system global\n    set strong-crypto enable\nend",
                "System Configuration"
            ),
            CISControl(
                "8.3",
                "Ensure firmware is up to date",
                "Current firmware includes security patches",
                ComplianceLevel.LEVEL_1,
                False,
                "Regularly update to the latest stable firmware version",
                "Manual: Check Fortinet support site for latest firmware",
                "System Configuration"
            ),
            CISControl(
                "8.4",
                "Ensure automatic update checking is enabled",
                "Automatic checks ensure awareness of available updates",
                ComplianceLevel.LEVEL_2,
                True,
                "Enable automatic update notifications",
                "config system autoupdate push-update\n    set status enable\nend",
                "System Configuration"
            ),
        ]
    
    def load_config(self) -> bool:
        """Load and parse FortiGate configuration"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try YAML first
            try:
                self.config = yaml.safe_load(content)
                if isinstance(self.config, dict) and self.config:
                    print("✅ Loaded as YAML format")
                    return True
            except yaml.YAMLError:
                pass
            
            # Parse FortiGate CLI format
            self.config = self._parse_fortigate_cli(content)
            if isinstance(self.config, dict) and self.config:
                print("✅ Loaded as FortiGate CLI format")
                return True
            
            print("❌ Could not parse configuration file")
            return False
            
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return False
    
    def _parse_fortigate_cli(self, content: str) -> Dict:
        """Parse FortiGate CLI configuration format"""
        config = {}
        section_stack = [config]
        path_stack = []
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('config '):
                section_path = line.split('config ', 1)[1].strip().split()
                path_stack.append(section_path)
                
                current = config
                for part in section_path:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                
                section_stack.append(current)
                
            elif line.startswith('edit '):
                edit_name = line.split('edit ', 1)[1].strip().strip('"')
                current_section = section_stack[-1]
                
                if 'entries' not in current_section:
                    current_section['entries'] = {}
                
                current_section['entries'][edit_name] = {}
                section_stack.append(current_section['entries'][edit_name])
                
            elif line.startswith('set '):
                parts = line.split(None, 2)
                current_section = section_stack[-1]
                
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2].strip('"')
                    current_section[key] = value
                elif len(parts) == 2:
                    current_section[parts[1]] = True
                    
            elif line == 'next':
                if len(section_stack) > 1:
                    section_stack.pop()
                    
            elif line == 'end':
                if len(section_stack) > 1:
                    section_stack.pop()
                if path_stack:
                    path_stack.pop()
        
        return config
    
    def scan(self) -> CISReport:
        """Perform CIS compliance scan"""
        if not self.config:
            print("❌ Configuration not loaded")
            return self.report
        
        print("\n" + "="*70)
        print("CIS Fortinet FortiGate Benchmark Scanner")
        print("="*70)
        print(f"Configuration: {self.config_file}")
        print(f"Scan Date: {self.report.scan_date}")
        print(f"Total Controls: {len(self.cis_controls)}")
        print("="*70 + "\n")
        
        # Run all checks
        for control in self.cis_controls:
            if control.automated:
                result = self._check_control(control)
                self.report.results.append(result)
        
        # Calculate summary
        self._calculate_summary()
        
        return self.report
    
    def _check_control(self, control: CISControl) -> ComplianceResult:
        """Check a specific CIS control"""
        
        # Route to specific check methods
        check_methods = {
            "1.1": self._check_password_complexity,
            "1.2": self._check_password_expiration,
            "1.3": self._check_default_admin,
            "1.4": self._check_two_factor_auth,
            "1.5": self._check_trusted_hosts,
            "2.1": self._check_policy_logging,
            "2.2": self._check_remote_syslog,
            "2.3": self._check_ntp,
            "2.4": self._check_timezone,
            "3.1": self._check_https_restricted,
            "3.2": self._check_telnet_disabled,
            "3.3": self._check_http_disabled,
            "3.4": self._check_wan_admin_access,
            "3.5": self._check_idle_timeout,
            "4.1": self._check_ike_encryption,
            "4.2": self._check_dh_groups,
            "4.3": self._check_dpd,
            "4.4": self._check_ssl_vpn_tls,
            "5.1": self._check_default_deny,
            "5.2": self._check_utm_profiles,
            "5.3": self._check_antivirus,
            "5.4": self._check_ips,
            "6.1": self._check_snmpv3,
            "6.2": self._check_snmp_community,
            "6.3": self._check_snmp_hosts,
            "7.1": self._check_ha_encryption,
            "7.2": self._check_ha_password,
            "8.1": self._check_pre_login_banner,
            "8.2": self._check_strong_crypto,
            "8.4": self._check_auto_update,
        }
        
        check_method = check_methods.get(control.control_id)
        if check_method:
            return check_method(control)
        else:
            # Manual check
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.MANUAL,
                finding="Manual verification required"
            )
    
    # Check method implementations
    
    def _check_password_complexity(self, control: CISControl) -> ComplianceResult:
        """Check 1.1: Password complexity"""
        password_policy = self.config.get('system', {}).get('password-policy', {})
        
        status = password_policy.get('status', 'disable')
        min_length = int(password_policy.get('minimum-length', 0))
        
        if status == 'enable' and min_length >= 12:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"Password policy enabled with minimum length {min_length}"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Password complexity not properly configured",
                current_value=f"status={status}, min-length={min_length}"
            )
    
    def _check_password_expiration(self, control: CISControl) -> ComplianceResult:
        """Check 1.2: Password expiration"""
        password_policy = self.config.get('system', {}).get('password-policy', {})
        expire_days = int(password_policy.get('expire-day', 0))
        
        if 0 < expire_days <= 90:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"Password expiration set to {expire_days} days"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Password expiration not configured or exceeds 90 days",
                current_value=f"expire-day={expire_days}"
            )
    
    def _check_default_admin(self, control: CISControl) -> ComplianceResult:
        """Check 1.3: Default admin account"""
        admins = self.config.get('system', {}).get('admin', {}).get('entries', {})
        
        if 'admin' in admins:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Default 'admin' account is still active",
                current_value="admin account exists"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="Default admin account not found (renamed or removed)"
            )
    
    def _check_two_factor_auth(self, control: CISControl) -> ComplianceResult:
        """Check 1.4: Two-factor authentication"""
        admins = self.config.get('system', {}).get('admin', {}).get('entries', {})
        
        admins_without_2fa = []
        for admin_name, admin_config in admins.items():
            two_factor = admin_config.get('two-factor', 'disable')
            if two_factor in ['disable', 'fortitoken', None]:
                if two_factor == 'disable' or two_factor is None:
                    admins_without_2fa.append(admin_name)
        
        if not admins_without_2fa:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All administrators have 2FA enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Administrators without 2FA: {', '.join(admins_without_2fa)}",
                current_value=f"{len(admins_without_2fa)} admins without 2FA"
            )
    
    def _check_trusted_hosts(self, control: CISControl) -> ComplianceResult:
        """Check 1.5: Trusted hosts configuration"""
        admins = self.config.get('system', {}).get('admin', {}).get('entries', {})
        
        admins_without_trusthost = []
        for admin_name, admin_config in admins.items():
            trusthost = admin_config.get('trusthost1', admin_config.get('trusthost', ''))
            if trusthost in ['0.0.0.0 0.0.0.0', '0.0.0.0/0', '']:
                admins_without_trusthost.append(admin_name)
        
        if not admins_without_trusthost:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All administrators have trusted host restrictions"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Admins without trusted host restrictions: {', '.join(admins_without_trusthost)}",
                current_value=f"{len(admins_without_trusthost)} admins unrestricted"
            )
    
    def _check_policy_logging(self, control: CISControl) -> ComplianceResult:
        """Check 2.1: Firewall policy logging"""
        policies = self.config.get('firewall', {}).get('policy', {}).get('entries', {})
        
        policies_without_logging = []
        for policy_id, policy_config in policies.items():
            action = policy_config.get('action', '')
            logtraffic = policy_config.get('logtraffic', 'disable')
            
            if action == 'accept' and logtraffic not in ['all', 'utm']:
                policies_without_logging.append(policy_id)
        
        if not policies_without_logging:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All accept policies have logging enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Policies without logging: {', '.join(policies_without_logging)}",
                current_value=f"{len(policies_without_logging)} policies"
            )
    
    def _check_remote_syslog(self, control: CISControl) -> ComplianceResult:
        """Check 2.2: Remote syslog configuration"""
        syslog = self.config.get('log', {}).get('syslogd', {}).get('setting', {})
        status = syslog.get('status', 'disable')
        
        if status == 'enable':
            server = syslog.get('server', '')
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"Remote syslog enabled to {server}"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Remote syslog not configured",
                current_value=f"status={status}"
            )
    
    def _check_ntp(self, control: CISControl) -> ComplianceResult:
        """Check 2.3: NTP configuration"""
        ntp = self.config.get('system', {}).get('ntp', {})
        ntpsync = ntp.get('ntpsync', ntp.get('type', 'disable'))
        
        if ntpsync in ['enable', 'fortiguard', 'custom']:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"NTP enabled with type: {ntpsync}"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="NTP not configured or disabled",
                current_value=f"ntpsync={ntpsync}"
            )
    
    def _check_timezone(self, control: CISControl) -> ComplianceResult:
        """Check 2.4: Timezone configuration"""
        global_config = self.config.get('system', {}).get('global', {})
        timezone = global_config.get('timezone', '')
        
        if timezone and timezone not in ['00', '']:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"Timezone configured: {timezone}"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Timezone not configured",
                current_value=f"timezone={timezone}"
            )
    
    def _check_https_restricted(self, control: CISControl) -> ComplianceResult:
        """Check 3.1: HTTPS access restricted"""
        # This is partially implemented - would need interface role detection
        return ComplianceResult(
            control=control,
            status=ComplianceStatus.MANUAL,
            finding="Manual verification required - check interface configurations"
        )
    
    def _check_telnet_disabled(self, control: CISControl) -> ComplianceResult:
        """Check 3.2: Telnet disabled"""
        interfaces = self.config.get('system', {}).get('interface', {}).get('entries', {})
        
        interfaces_with_telnet = []
        for iface_name, iface_config in interfaces.items():
            allowaccess = iface_config.get('allowaccess', '')
            if 'telnet' in allowaccess.lower():
                interfaces_with_telnet.append(iface_name)
        
        if not interfaces_with_telnet:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="Telnet disabled on all interfaces"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Interfaces with Telnet enabled: {', '.join(interfaces_with_telnet)}",
                current_value=f"{len(interfaces_with_telnet)} interfaces"
            )
    
    def _check_http_disabled(self, control: CISControl) -> ComplianceResult:
        """Check 3.3: HTTP disabled"""
        interfaces = self.config.get('system', {}).get('interface', {}).get('entries', {})
        
        interfaces_with_http = []
        for iface_name, iface_config in interfaces.items():
            allowaccess = iface_config.get('allowaccess', '')
            # Check for HTTP but not HTTPS
            if 'http' in allowaccess.lower() and 'https' not in allowaccess.lower():
                interfaces_with_http.append(iface_name)
            elif allowaccess.lower() == 'http':
                interfaces_with_http.append(iface_name)
        
        if not interfaces_with_http:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="HTTP disabled on all interfaces"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Interfaces with HTTP enabled: {', '.join(interfaces_with_http)}",
                current_value=f"{len(interfaces_with_http)} interfaces"
            )
    
    def _check_wan_admin_access(self, control: CISControl) -> ComplianceResult:
        """Check 3.4: No admin access on WAN interfaces"""
        interfaces = self.config.get('system', {}).get('interface', {}).get('entries', {})
        
        wan_with_admin = []
        for iface_name, iface_config in interfaces.items():
            role = iface_config.get('role', '')
            allowaccess = iface_config.get('allowaccess', '')
            
            if role == 'wan' and allowaccess:
                # Check for any admin protocols
                admin_protocols = ['https', 'http', 'ssh', 'telnet', 'fgfm']
                if any(proto in allowaccess.lower() for proto in admin_protocols):
                    wan_with_admin.append(iface_name)
        
        if not wan_with_admin:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="No administrative access on WAN interfaces"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"WAN interfaces with admin access: {', '.join(wan_with_admin)}",
                current_value=f"{len(wan_with_admin)} WAN interfaces"
            )
    
    def _check_idle_timeout(self, control: CISControl) -> ComplianceResult:
        """Check 3.5: Admin idle timeout"""
        global_config = self.config.get('system', {}).get('global', {})
        timeout = int(global_config.get('admintimeout', 480))
        
        if timeout <= 15:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"Admin timeout set to {timeout} minutes"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Admin timeout exceeds 15 minutes",
                current_value=f"{timeout} minutes"
            )
    
    def _check_ike_encryption(self, control: CISControl) -> ComplianceResult:
        """Check 4.1: IKE encryption strength"""
        phase1 = self.config.get('vpn', {}).get('ipsec', {}).get('phase1-interface', {}).get('entries', {})
        
        weak_vpns = []
        for vpn_name, vpn_config in phase1.items():
            proposal = vpn_config.get('proposal', '')
            # Check for weak encryption
            if any(weak in proposal.lower() for weak in ['des', '3des', 'md5', 'sha1', 'aes128']):
                weak_vpns.append(vpn_name)
        
        if not weak_vpns:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All VPNs use strong encryption (AES256)"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"VPNs with weak encryption: {', '.join(weak_vpns)}",
                current_value=f"{len(weak_vpns)} VPNs"
            )
    
    def _check_dh_groups(self, control: CISControl) -> ComplianceResult:
        """Check 4.2: DH group strength"""
        phase1 = self.config.get('vpn', {}).get('ipsec', {}).get('phase1-interface', {}).get('entries', {})
        
        weak_dh_vpns = []
        for vpn_name, vpn_config in phase1.items():
            dhgrp = vpn_config.get('dhgrp', '')
            # DH groups 1, 2, 5 are weak
            if any(weak in str(dhgrp) for weak in ['1', '2', '5']):
                weak_dh_vpns.append(vpn_name)
        
        if not weak_dh_vpns:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All VPNs use strong DH groups (14+)"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"VPNs with weak DH groups: {', '.join(weak_dh_vpns)}",
                current_value=f"{len(weak_dh_vpns)} VPNs"
            )
    
    def _check_dpd(self, control: CISControl) -> ComplianceResult:
        """Check 4.3: Dead Peer Detection"""
        phase1 = self.config.get('vpn', {}).get('ipsec', {}).get('phase1-interface', {}).get('entries', {})
        
        vpns_without_dpd = []
        for vpn_name, vpn_config in phase1.items():
            dpd = vpn_config.get('dpd', 'disable')
            if dpd == 'disable':
                vpns_without_dpd.append(vpn_name)
        
        if not vpns_without_dpd:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="DPD enabled on all VPN tunnels"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"VPNs without DPD: {', '.join(vpns_without_dpd)}",
                current_value=f"{len(vpns_without_dpd)} VPNs"
            )
    
    def _check_ssl_vpn_tls(self, control: CISControl) -> ComplianceResult:
        """Check 4.4: SSL VPN TLS version"""
        ssl_vpn = self.config.get('vpn', {}).get('ssl', {}).get('settings', {})
        ssl_min_ver = ssl_vpn.get('ssl-min-proto-ver', '')
        
        if ssl_min_ver in ['tls1-2', 'tls1-3', 'tls-1.2', 'tls-1.3']:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"SSL VPN uses {ssl_min_ver}"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="SSL VPN allows weak TLS versions",
                current_value=f"min-ver={ssl_min_ver}"
            )
    
    def _check_default_deny(self, control: CISControl) -> ComplianceResult:
        """Check 5.1: Default deny policy"""
        policies = self.config.get('firewall', {}).get('policy', {}).get('entries', {})
        
        if not policies:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="No firewall policies found"
            )
        
        # Check last policy
        last_policy_id = list(policies.keys())[-1]
        last_policy = policies[last_policy_id]
        
        action = last_policy.get('action', '')
        if action == 'deny':
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence=f"Default deny policy exists (policy {last_policy_id})"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="No explicit deny-all policy at end of policy list",
                current_value=f"Last policy action={action}"
            )
    
    def _check_utm_profiles(self, control: CISControl) -> ComplianceResult:
        """Check 5.2: UTM profiles applied"""
        policies = self.config.get('firewall', {}).get('policy', {}).get('entries', {})
        
        policies_without_utm = []
        for policy_id, policy_config in policies.items():
            action = policy_config.get('action', '')
            if action == 'accept':
                has_av = 'av-profile' in policy_config
                has_ips = 'ips-sensor' in policy_config
                has_webfilter = 'webfilter-profile' in policy_config
                has_app = 'application-list' in policy_config
                
                if not (has_av or has_ips or has_webfilter or has_app):
                    policies_without_utm.append(policy_id)
        
        if not policies_without_utm:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All accept policies have UTM profiles"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Policies without UTM: {', '.join(policies_without_utm)}",
                current_value=f"{len(policies_without_utm)} policies"
            )
    
    def _check_antivirus(self, control: CISControl) -> ComplianceResult:
        """Check 5.3: Antivirus enabled"""
        policies = self.config.get('firewall', {}).get('policy', {}).get('entries', {})
        
        policies_without_av = []
        for policy_id, policy_config in policies.items():
            action = policy_config.get('action', '')
            if action == 'accept' and 'av-profile' not in policy_config:
                policies_without_av.append(policy_id)
        
        if not policies_without_av:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All accept policies have AV profiles"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Policies without AV: {', '.join(policies_without_av)}",
                current_value=f"{len(policies_without_av)} policies"
            )
    
    def _check_ips(self, control: CISControl) -> ComplianceResult:
        """Check 5.4: IPS enabled"""
        policies = self.config.get('firewall', {}).get('policy', {}).get('entries', {})
        
        policies_without_ips = []
        for policy_id, policy_config in policies.items():
            action = policy_config.get('action', '')
            if action == 'accept' and 'ips-sensor' not in policy_config:
                policies_without_ips.append(policy_id)
        
        if not policies_without_ips:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All accept policies have IPS sensors"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Policies without IPS: {', '.join(policies_without_ips)}",
                current_value=f"{len(policies_without_ips)} policies"
            )
    
    def _check_snmpv3(self, control: CISControl) -> ComplianceResult:
        """Check 6.1: SNMPv3 usage"""
        snmp = self.config.get('system', {}).get('snmp', {})
        has_v3_user = 'user' in snmp
        has_community = 'community' in snmp
        
        if has_v3_user and not has_community:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="Using SNMPv3 exclusively"
            )
        elif has_community:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="SNMPv1/v2c community strings configured",
                current_value="Community-based SNMP enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.NOT_APPLICABLE,
                finding="SNMP not configured"
            )
    
    def _check_snmp_community(self, control: CISControl) -> ComplianceResult:
        """Check 6.2: SNMP community strings"""
        communities = self.config.get('system', {}).get('snmp', {}).get('community', {}).get('entries', {})
        
        default_communities = []
        for comm_id, comm_config in communities.items():
            name = comm_config.get('name', comm_id)
            if name.lower() in ['public', 'private']:
                default_communities.append(name)
        
        if not communities:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.NOT_APPLICABLE,
                finding="SNMP communities not configured"
            )
        elif not default_communities:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="No default SNMP community strings found"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Default communities found: {', '.join(default_communities)}",
                current_value=f"{len(default_communities)} default strings"
            )
    
    def _check_snmp_hosts(self, control: CISControl) -> ComplianceResult:
        """Check 6.3: SNMP host restrictions"""
        communities = self.config.get('system', {}).get('snmp', {}).get('community', {}).get('entries', {})
        
        unrestricted = []
        for comm_id, comm_config in communities.items():
            hosts = comm_config.get('hosts', '')
            if hosts in ['0.0.0.0 0.0.0.0', '0.0.0.0/0', '']:
                unrestricted.append(comm_id)
        
        if not communities:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.NOT_APPLICABLE,
                finding="SNMP not configured"
            )
        elif not unrestricted:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="All SNMP communities have host restrictions"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding=f"Unrestricted SNMP communities: {', '.join(unrestricted)}",
                current_value=f"{len(unrestricted)} unrestricted"
            )
    
    def _check_ha_encryption(self, control: CISControl) -> ComplianceResult:
        """Check 7.1: HA heartbeat encryption"""
        ha = self.config.get('system', {}).get('ha', {})
        
        if not ha:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.NOT_APPLICABLE,
                finding="HA not configured"
            )
        
        encryption = ha.get('encryption', ha.get('hb-encrypt', 'disable'))
        if encryption == 'enable':
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="HA heartbeat encryption enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="HA heartbeat encryption not enabled",
                current_value=f"encryption={encryption}"
            )
    
    def _check_ha_password(self, control: CISControl) -> ComplianceResult:
        """Check 7.2: HA password configured"""
        ha = self.config.get('system', {}).get('ha', {})
        
        if not ha:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.NOT_APPLICABLE,
                finding="HA not configured"
            )
        
        password = ha.get('password', '')
        if password and password != '':
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="HA password configured"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="HA password not configured",
                current_value="No password set"
            )
    
    def _check_pre_login_banner(self, control: CISControl) -> ComplianceResult:
        """Check 8.1: Pre-login banner"""
        global_config = self.config.get('system', {}).get('global', {})
        banner = global_config.get('pre-login-banner', 'disable')
        
        if banner == 'enable':
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="Pre-login banner enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Pre-login banner not enabled",
                current_value=f"pre-login-banner={banner}"
            )
    
    def _check_strong_crypto(self, control: CISControl) -> ComplianceResult:
        """Check 8.2: Strong crypto enabled"""
        global_config = self.config.get('system', {}).get('global', {})
        strong_crypto = global_config.get('strong-crypto', 'disable')
        
        if strong_crypto == 'enable':
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="Strong crypto enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Strong crypto not enabled",
                current_value=f"strong-crypto={strong_crypto}"
            )
    
    def _check_auto_update(self, control: CISControl) -> ComplianceResult:
        """Check 8.4: Auto-update checking"""
        autoupdate = self.config.get('system', {}).get('autoupdate', {}).get('push-update', {})
        status = autoupdate.get('status', 'disable')
        
        if status == 'enable':
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.PASS,
                evidence="Auto-update checking enabled"
            )
        else:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.FAIL,
                finding="Auto-update checking not enabled",
                current_value=f"status={status}"
            )
    
    def _calculate_summary(self):
        """Calculate compliance summary statistics"""
        self.report.summary = {
            'Total Controls': len(self.report.results),
            'Pass': 0,
            'Fail': 0,
            'Manual': 0,
            'Not Applicable': 0,
            'Level 1': 0,
            'Level 2': 0,
        }
        
        for result in self.report.results:
            # Map status to summary key
            status_key = result.status.value
            if status_key == 'Manual Review Required':
                status_key = 'Manual'
            elif status_key not in self.report.summary:
                # Handle any other status values
                continue
                
            self.report.summary[status_key] += 1
            self.report.summary[result.control.level.value] += 1
        
        # Calculate compliance score
        total_checked = self.report.summary['Pass'] + self.report.summary['Fail']
        if total_checked > 0:
            self.report.compliance_score = (self.report.summary['Pass'] / total_checked) * 100
        else:
            self.report.compliance_score = 0.0
    
    def generate_report(self, output_format='text') -> str:
        """Generate compliance report"""
        if output_format == 'text':
            return self._generate_text_report()
        elif output_format == 'json':
            return self._generate_json_report()
        elif output_format == 'html':
            return self._generate_html_report()
        elif output_format == 'csv':
            return self._generate_csv_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate text format report"""
        report = []
        report.append("="*80)
        report.append("CIS FORTINET FORTIGATE BENCHMARK COMPLIANCE REPORT")
        report.append("="*80)
        report.append(f"\nConfiguration File: {self.config_file}")
        report.append(f"Scan Date: {self.report.scan_date}")
        report.append(f"\nCompliance Score: {self.report.compliance_score:.1f}%")
        
        # Summary
        report.append("\n" + "-"*80)
        report.append("SUMMARY")
        report.append("-"*80)
        report.append(f"Total Controls Checked: {self.report.summary['Total Controls']}")
        report.append(f"  Pass:           {self.report.summary['Pass']}")
        report.append(f"  Fail:           {self.report.summary['Fail']}")
        report.append(f"  Manual Review:  {self.report.summary['Manual']}")
        report.append(f"  Not Applicable: {self.report.summary['Not Applicable']}")
        report.append(f"\nBy Profile Level:")
        report.append(f"  Level 1 Controls: {self.report.summary['Level 1']}")
        report.append(f"  Level 2 Controls: {self.report.summary['Level 2']}")
        
        # Failed controls
        report.append("\n" + "="*80)
        report.append("FAILED CONTROLS")
        report.append("="*80)
        
        failed = [r for r in self.report.results if r.status == ComplianceStatus.FAIL]
        if failed:
            for result in failed:
                report.append(f"\n[{result.control.control_id}] {result.control.title}")
                report.append(f"Category: {result.control.category}")
                report.append(f"Level: {result.control.level.value}")
                report.append(f"Status: FAIL")
                report.append(f"\nFinding:")
                report.append(f"  {result.finding}")
                if result.current_value:
                    report.append(f"Current Value: {result.current_value}")
                report.append(f"\nRecommendation:")
                report.append(f"  {result.control.recommendation}")
                report.append(f"\nRemediation:")
                for line in result.control.remediation.split('\n'):
                    report.append(f"  {line}")
                report.append("-"*80)
        else:
            report.append("\nNo failed controls!")
        
        # Passed controls
        report.append("\n" + "="*80)
        report.append("PASSED CONTROLS")
        report.append("="*80)
        
        passed = [r for r in self.report.results if r.status == ComplianceStatus.PASS]
        if passed:
            for result in passed:
                report.append(f"✓ [{result.control.control_id}] {result.control.title}")
                if result.evidence:
                    report.append(f"  Evidence: {result.evidence}")
        else:
            report.append("\nNo passed controls.")
        
        # Manual review required
        manual = [r for r in self.report.results if r.status == ComplianceStatus.MANUAL]
        if manual:
            report.append("\n" + "="*80)
            report.append("MANUAL REVIEW REQUIRED")
            report.append("="*80)
            for result in manual:
                report.append(f"\n[{result.control.control_id}] {result.control.title}")
                report.append(f"  {result.control.description}")
                report.append(f"  Recommendation: {result.control.recommendation}")
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate JSON format report"""
        report_data = {
            'scan_date': self.report.scan_date,
            'config_file': self.config_file,
            'compliance_score': self.report.compliance_score,
            'summary': self.report.summary,
            'results': [
                {
                    'control_id': r.control.control_id,
                    'title': r.control.title,
                    'category': r.control.category,
                    'level': r.control.level.value,
                    'status': r.status.value,
                    'finding': r.finding,
                    'evidence': r.evidence,
                    'current_value': r.current_value,
                    'recommendation': r.control.recommendation,
                    'remediation': r.control.remediation
                }
                for r in self.report.results
            ]
        }
        return json.dumps(report_data, indent=2)
    
    def _generate_csv_report(self) -> str:
        """Generate CSV format report"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['Control ID', 'Title', 'Category', 'Level', 'Status', 
                        'Finding', 'Evidence', 'Current Value', 'Recommendation'])
        
        # Data
        for result in self.report.results:
            writer.writerow([
                result.control.control_id,
                result.control.title,
                result.control.category,
                result.control.level.value,
                result.status.value,
                result.finding,
                result.evidence,
                result.current_value,
                result.control.recommendation
            ])
        
        return output.getvalue()
    
    def _generate_html_report(self) -> str:
        """Generate HTML format report"""
        
        # Color coding
        status_colors = {
            'Pass': '#28a745',
            'Fail': '#dc3545',
            'Manual Review Required': '#ffc107',
            'Not Applicable': '#6c757d'
        }
        
        # Calculate score color
        score = self.report.compliance_score
        if score >= 90:
            score_color = '#28a745'
        elif score >= 70:
            score_color = '#ffc107'
        else:
            score_color = '#dc3545'
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CIS FortiGate Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; border-left: 4px solid #007bff; padding-left: 10px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {score_color}; text-align: center; margin: 20px 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 15px; border-radius: 5px; text-align: center; color: white; }}
        .control {{ margin: 20px 0; padding: 15px; border-left: 4px solid; background-color: #f8f9fa; }}
        .control-header {{ font-weight: bold; font-size: 18px; margin-bottom: 10px; }}
        .control-meta {{ color: #666; font-size: 14px; margin: 5px 0; }}
        .finding {{ background-color: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .evidence {{ background-color: #d4edda; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .remediation {{ background-color: #e7f3ff; padding: 10px; margin: 10px 0; border-radius: 3px; font-family: monospace; white-space: pre-wrap; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007bff; color: white; }}
        .pass {{ border-left-color: #28a745; }}
        .fail {{ border-left-color: #dc3545; }}
        .manual {{ border-left-color: #ffc107; }}
        .na {{ border-left-color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CIS Fortinet FortiGate Benchmark Compliance Report</h1>
        <p><strong>Configuration File:</strong> {self.config_file}</p>
        <p><strong>Scan Date:</strong> {self.report.scan_date}</p>
        <p><strong>Benchmark Version:</strong> CIS FortiGate 7.x Benchmark v1.3.0</p>
        
        <div class="score">Compliance Score: {self.report.compliance_score:.1f}%</div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card" style="background-color: {status_colors['Pass']}">
                <div style="font-size: 32px;">{self.report.summary['Pass']}</div>
                <div>PASSED</div>
            </div>
            <div class="summary-card" style="background-color: {status_colors['Fail']}">
                <div style="font-size: 32px;">{self.report.summary['Fail']}</div>
                <div>FAILED</div>
            </div>
            <div class="summary-card" style="background-color: {status_colors['Manual Review Required']}">
                <div style="font-size: 32px;">{self.report.summary['Manual']}</div>
                <div>MANUAL REVIEW</div>
            </div>
            <div class="summary-card" style="background-color: {status_colors['Not Applicable']}">
                <div style="font-size: 32px;">{self.report.summary['Not Applicable']}</div>
                <div>NOT APPLICABLE</div>
            </div>
        </div>
        
        <h2>Failed Controls</h2>
"""
        
        failed = [r for r in self.report.results if r.status == ComplianceStatus.FAIL]
        if failed:
            for result in failed:
                html += f"""
        <div class="control fail">
            <div class="control-header">[{result.control.control_id}] {result.control.title}</div>
            <div class="control-meta">Category: {result.control.category} | Level: {result.control.level.value}</div>
            <div class="control-meta">Status: <strong style="color: {status_colors['Fail']}">FAIL</strong></div>
            <div class="finding">
                <strong>Finding:</strong> {result.finding}
"""
                if result.current_value:
                    html += f"<br><strong>Current Value:</strong> {result.current_value}"
                html += f"""
            </div>
            <div>
                <strong>Recommendation:</strong> {result.control.recommendation}
            </div>
            <div class="remediation">
                <strong>Remediation:</strong>
{result.control.remediation}
            </div>
        </div>
"""
        else:
            html += "<p>✅ No failed controls!</p>"
        
        html += """
        <h2>Passed Controls</h2>
"""
        
        passed = [r for r in self.report.results if r.status == ComplianceStatus.PASS]
        if passed:
            html += "<table><tr><th>Control ID</th><th>Title</th><th>Evidence</th></tr>"
            for result in passed:
                html += f"""
                <tr>
                    <td>{result.control.control_id}</td>
                    <td>{result.control.title}</td>
                    <td>{result.evidence}</td>
                </tr>
"""
            html += "</table>"
        else:
            html += "<p>No passed controls.</p>"
        
        # Manual review
        manual = [r for r in self.report.results if r.status == ComplianceStatus.MANUAL]
        if manual:
            html += """
        <h2>Manual Review Required</h2>
"""
            for result in manual:
                html += f"""
        <div class="control manual">
            <div class="control-header">[{result.control.control_id}] {result.control.title}</div>
            <div class="control-meta">Category: {result.control.category}</div>
            <p>{result.control.description}</p>
            <p><strong>Recommendation:</strong> {result.control.recommendation}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("CIS Fortinet FortiGate Benchmark Scanner")
        print("="*70)
        print("\nUsage:")
        print(f"  python {sys.argv[0]} <config_file> [output_format]")
        print("\nOutput formats: text (default), json, html, csv")
        print("\nExample:")
        print(f"  python {sys.argv[0]} fortigate.conf html")
        sys.exit(1)
    
    config_file = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else 'text'
    
    # Create scanner
    scanner = CISFortiGateScanner(config_file)
    
    # Load configuration
    if not scanner.load_config():
        print("\n❌ Failed to load configuration file")
        sys.exit(1)
    
    # Run scan
    report = scanner.scan()
    
    # Generate report
    report_text = scanner.generate_report(output_format)
    
    # Save to file
    ext = 'txt' if output_format == 'text' else output_format
    output_file = f"cis_compliance_report.{ext}"
    
    with open(output_file, 'w') as f:
        f.write(report_text)
    
    print(f"\n✅ Compliance scan complete!")
    print(f"📊 Compliance Score: {report.compliance_score:.1f}%")
    print(f"📄 Report saved to: {output_file}")
    
    # Print summary
    print("\n" + "="*70)
    print("QUICK SUMMARY")
    print("="*70)
    print(f"Pass:           {report.summary['Pass']}")
    print(f"Fail:           {report.summary['Fail']}")
    print(f"Manual Review:  {report.summary['Manual']}")
    print(f"Not Applicable: {report.summary['Not Applicable']}")
    print("="*70)


if __name__ == "__main__":
    main()
