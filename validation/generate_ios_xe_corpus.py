#!/usr/bin/env python3
"""Generate IOS-XE handler evaluation corpus fixtures."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "validation" / "corpus" / "config" / "cisco_ios_xe"
HOLDOUT = ROOT / "validation" / "corpus" / "holdout" / "cisco_ios_xe"

BASE = """\
version 16.12
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
hostname {hostname}
!
"""

ENTRIES: list[dict] = [
    {
        "path": "cisco_ios_xe/ios002-violation-telnet-vty.cfg",
        "expected": ["IOS-002"],
        "description": "VTY lines permit telnet transport.",
        "content": BASE.format(hostname="ios002-violation")
        + """
line vty 0 4
 exec-timeout 10 0
 logging synchronous
 transport input telnet ssh
 login local
!
ip ssh version 2
""",
    },
    {
        "path": "cisco_ios_xe/ios002-clean-ssh-only-vty.cfg",
        "expected": [],
        "description": "VTY restricted to SSH transport only.",
        "content": BASE.format(hostname="ios002-clean")
        + """
line vty 0 4
 exec-timeout 10 0
 transport input ssh
 login local
!
ip ssh version 2
""",
    },
    {
        "path": "cisco_ios_xe/ios003-violation-snmp-public.cfg",
        "expected": ["IOS-003"],
        "description": "SNMP community uses default public string.",
        "content": BASE.format(hostname="ios003-violation")
        + """
snmp-server community public RO
snmp-server location DC1-IDF3
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios003-clean-snmp-custom.cfg",
        "expected": [],
        "description": "SNMP community uses non-default read-only string.",
        "content": BASE.format(hostname="ios003-clean")
        + """
snmp-server community netops-ro-7f3a RO
snmp-server location DC1-IDF3
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios004-violation-aaa-enable.cfg",
        "expected": ["IOS-004"],
        "description": "AAA new-model without login authentication and weak enable password.",
        "content": BASE.format(hostname="ios004-violation")
        + """
aaa new-model
!
enable password 7 094F471A1A0A
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios004-clean-aaa-secret.cfg",
        "expected": [],
        "description": "AAA login authentication and enable secret configured.",
        "content": BASE.format(hostname="ios004-clean")
        + """
aaa new-model
aaa authentication login default local
!
enable secret 9 $14$k1gO$9m9m9m9m9m9m9m9m9m9m9m9m9m9m9m
!
line vty 0 4
 transport input ssh
 login authentication default
""",
    },
    {
        "path": "cisco_ios_xe/ios005-violation-http-cleartext.cfg",
        "expected": ["IOS-005"],
        "description": "HTTP management enabled with password encryption disabled.",
        "content": BASE.format(hostname="ios005-violation")
        + """
no service password-encryption
ip http server
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios005-clean-encrypted-no-http.cfg",
        "expected": [],
        "description": "Password encryption enabled and HTTP server disabled.",
        "content": BASE.format(hostname="ios005-clean")
        + """
service password-encryption
no ip http server
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios006-violation-any-any-acl.cfg",
        "expected": ["IOS-006"],
        "description": "Extended ACL permits any/any after object-group resolution.",
        "content": BASE.format(hostname="ios006-violation")
        + """
object-group network OPEN-SOURCES
 group-object INTERNET-ANY
!
object-group network INTERNET-ANY
 network-object 0.0.0.0 255.255.255.255
!
ip access-list extended EDGE-IN
 10 permit ip object-group OPEN-SOURCES any
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios006-clean-scoped-acl.cfg",
        "expected": [],
        "description": "ACL permits only resolved RFC1918 sources to a fixed host.",
        "content": BASE.format(hostname="ios006-clean")
        + """
object-group network MGMT-JUMP
 network-object 10.50.0.0 0.0.0.255
!
ip access-list extended EDGE-IN
 10 permit tcp object-group MGMT-JUMP host 10.20.1.5 eq 443
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios007-violation-trunk-native-dtp.cfg",
        "expected": ["IOS-007"],
        "description": "Trunk uses native VLAN 1 and DTP desirable.",
        "content": BASE.format(hostname="ios007-violation")
        + """
interface GigabitEthernet1/0/1
 description uplink-to-distribution
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 1
 switchport mode dynamic desirable
 switchport trunk allowed vlan 10,20,30
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios007-clean-trunk-hardened.cfg",
        "expected": [],
        "description": "Trunk uses non-default native VLAN and DTP disabled.",
        "content": BASE.format(hostname="ios007-clean")
        + """
interface GigabitEthernet1/0/1
 description uplink-to-distribution
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 4094
 switchport nonegotiate
 switchport trunk allowed vlan 10,20,30
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios008-violation-vty-public-acl.cfg",
        "expected": ["IOS-008"],
        "description": "VTY access-class permits non-RFC1918 sources.",
        "content": BASE.format(hostname="ios008-violation")
        + """
ip access-list standard VTY-IN
 permit 203.0.113.0 0.0.0.255
 deny   any
!
line vty 0 4
 access-class VTY-IN in
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios008-clean-vty-rfc1918-acl.cfg",
        "expected": [],
        "description": "VTY access-class restricted to RFC1918 jump networks.",
        "content": BASE.format(hostname="ios008-clean")
        + """
ip access-list standard VTY-IN
 permit 10.50.0.0 0.0.0.255
 deny   any
!
line vty 0 4
 access-class VTY-IN in
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios003-violation-snmp-rw.cfg",
        "expected": ["IOS-003"],
        "description": "SNMP community grants read-write access.",
        "content": BASE.format(hostname="ios003-rw-violation")
        + """
snmp-server community ops-backup RW
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios002-violation-transport-all.cfg",
        "expected": ["IOS-002"],
        "description": "VTY transport input all includes telnet.",
        "content": BASE.format(hostname="ios002-all-violation")
        + """
line vty 0 15
 transport input all
 login local
!
""",
    },
    {
        "path": "cisco_ios_xe/ios009-violation-access-no-hardening.cfg",
        "expected": [],
        "description": "Disabled IOS-009: access port without BPDU guard or port-security.",
        "content": BASE.format(hostname="ios009-violation")
        + """
interface GigabitEthernet1/0/10
 switchport mode access
 switchport access vlan 50
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios009-clean-access-hardened.cfg",
        "expected": [],
        "description": "Disabled IOS-009: access port with BPDU guard and port-security.",
        "content": BASE.format(hostname="ios009-clean")
        + """
interface GigabitEthernet1/0/10
 switchport mode access
 switchport access vlan 50
 spanning-tree bpduguard enable
 switchport port-security
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios004-violation-enable-only.cfg",
        "expected": ["IOS-004"],
        "description": "Enable password without enable secret on legacy AAA.",
        "content": BASE.format(hostname="ios004-enable-violation")
        + """
enable password 7 12090404011C
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios005-violation-no-encryption-only.cfg",
        "expected": ["IOS-005"],
        "description": "Password encryption disabled without HTTP (single-vector IOS-005).",
        "content": BASE.format(hostname="ios005-enc-violation")
        + """
no service password-encryption
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios006-violation-literal-any-any.cfg",
        "expected": ["IOS-006"],
        "description": "Literal permit ip any any ACE.",
        "content": BASE.format(hostname="ios006-literal-violation")
        + """
ip access-list extended OPEN-EDGE
 10 permit ip any any
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios007-violation-dtp-auto.cfg",
        "expected": ["IOS-007"],
        "description": "Trunk negotiates DTP auto without native VLAN hardening.",
        "content": BASE.format(hostname="ios007-dtp-violation")
        + """
interface GigabitEthernet1/0/2
 switchport trunk encapsulation dot1q
 switchport mode dynamic auto
 switchport trunk allowed vlan 100,200
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/ios008-violation-vty-extended-public.cfg",
        "expected": ["IOS-008"],
        "description": "VTY access-class extended ACL permits vendor /24.",
        "content": BASE.format(hostname="ios008-ext-violation")
        + """
ip access-list extended VTY-IN
 10 permit tcp 198.51.100.0 0.0.0.255 any eq 22
!
line vty 0 4
 access-class VTY-IN in
 transport input ssh
 login local
""",
    },
]

HOLDOUT_ENTRIES: list[dict] = [
    {
        "path": "cisco_ios_xe/holdout-iosxe-cooccur-telnet-snmp.cfg",
        "expected": ["IOS-002", "IOS-003"],
        "description": "Co-occurring telnet VTY and default SNMP community.",
        "content": BASE.format(hostname="holdout-cooccur")
        + """
snmp-server community private RO
!
line con 0
 logging synchronous
line vty 0 4
 transport input telnet
 access-class VTY-IN in
 login local
!
ip access-list standard VTY-IN
 permit 10.0.0.0 0.255.255.255
""",
    },
    {
        "path": "cisco_ios_xe/holdout-iosxe-cooccur-trunk-any.cfg",
        "expected": ["IOS-006", "IOS-007"],
        "description": "Co-occurring permissive ACL and weak trunk posture.",
        "content": BASE.format(hostname="holdout-trunk-any")
        + """
ip access-list extended TRANSIT
 10 permit ip any any
!
interface TenGigabitEthernet1/1/1
 switchport mode trunk
 switchport trunk native vlan 1
 switchport mode dynamic auto
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/holdout-iosxe-tricky-telnet-comment.cfg",
        "expected": [],
        "description": "Clean bait: telnet mentioned only in comment, VTY is SSH-only.",
        "content": BASE.format(hostname="holdout-tricky-comment")
        + """
! legacy note: do not re-enable telnet on VTY lines
!
line vty 0 4
 transport input ssh
 login local
!
ip ssh version 2
""",
    },
    {
        "path": "cisco_ios_xe/holdout-iosxe-tricky-public-hostname.cfg",
        "expected": [],
        "description": "Clean bait: hostname contains 'public' but SNMP community is custom.",
        "content": BASE.format(hostname="branch-public-services-sw1")
        + """
snmp-server community campus-nms-44a1 RO
!
line vty 0 4
 transport input ssh
 login local
""",
    },
    {
        "path": "cisco_ios_xe/holdout-iosxe-clean-jump-host.cfg",
        "expected": [],
        "description": "Clean full config with hardened management and scoped ACLs.",
        "content": BASE.format(hostname="holdout-clean-jump")
        + """
service password-encryption
no ip http server
!
aaa new-model
aaa authentication login default local
!
enable secret 9 $14$k1gO$9m9m9m9m9m9m9m9m9m9m9m9m9m9m9m
!
snmp-server community nms-ro-9c2f RO
!
ip access-list standard VTY-IN
 permit 10.50.10.0 0.0.0.255
 deny   any
!
ip access-list extended EDGE-IN
 10 permit tcp 10.0.0.0 0.255.255.255 host 10.20.1.5 eq 443
!
interface GigabitEthernet1/0/24
 switchport mode access
 switchport access vlan 200
 spanning-tree bpduguard enable
 switchport port-security
!
line vty 0 4
 access-class VTY-IN in
 transport input ssh
 login authentication default
!
ip ssh version 2
""",
    },
]


def _write_entry(base_dir: Path, entry: dict) -> None:
    rel = entry["path"]
    config_path = base_dir.parent / rel if "holdout" in str(base_dir) else ROOT / "validation" / "corpus" / "config" / rel.split("/", 1)[1]
    if "holdout" in entry["path"]:
        config_path = HOLDOUT / Path(entry["path"]).name
    else:
        config_path = CORPUS / Path(entry["path"]).name
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(entry["content"].strip() + "\n")
    labels = {
        "target_type": "cisco_ios_xe",
        "virtual_path": f"switches/{config_path.name}",
        "expected_rule_ids": entry["expected"],
        "description": entry["description"],
    }
    labels_path = config_path.with_suffix(config_path.suffix + ".labels.json")
    labels_path.write_text(json.dumps(labels, indent=2) + "\n")


def main() -> None:
    for entry in ENTRIES:
        _write_entry(CORPUS, entry)
    HOLDOUT.mkdir(parents=True, exist_ok=True)
    for entry in HOLDOUT_ENTRIES:
        _write_entry(HOLDOUT, entry)
    print(f"Wrote {len(ENTRIES)} generated and {len(HOLDOUT_ENTRIES)} holdout IOS-XE fixtures")


if __name__ == "__main__":
    main()
