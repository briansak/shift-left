#!/usr/bin/env python3
"""Generate NX-OS handler evaluation corpus fixtures."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "validation" / "corpus" / "config" / "cisco_nx_os"

BASE = """\
! NX-OS baseline context for generated corpus fixtures
boot nxos
switchname {hostname}
feature ssh
no feature telnet
!
vrf context management
!
line vty
 transport input ssh
!
aaa authentication login default group radius
 radius-server key 7 094F471A1A0A
!
"""

ENTRIES: list[dict] = [
    {
        "path": "cisco_nx_os/nxos003-violation-feature-telnet.cfg",
        "expected": ["NXOS-003"],
        "description": "Cleartext telnet feature enabled.",
        "content": BASE.format(hostname="nxos003-violation")
        + """
feature telnet
!
""",
    },
    {
        "path": "cisco_nx_os/nxos003-violation-telnet-after-ssh.cfg",
        "expected": ["NXOS-003"],
        "description": "Telnet feature enabled after SSH baseline.",
        "content": BASE.format(hostname="nxos003-violation2")
        + """
feature telnet
feature interface-vlan
!
""",
    },
    {
        "path": "cisco_nx_os/nxos003-clean-no-telnet.cfg",
        "expected": [],
        "description": "Telnet feature absent and explicitly disabled.",
        "content": BASE.format(hostname="nxos003-clean")
        + """
no feature telnet
!
""",
    },
    {
        "path": "cisco_nx_os/nxos003-clean-ssh-only.cfg",
        "expected": [],
        "description": "SSH feature enabled without telnet.",
        "content": BASE.format(hostname="nxos003-clean2")
        + """
feature ssh
no feature telnet
!
""",
    },
    {
        "path": "cisco_nx_os/nxos004-violation-no-feature-ssh.cfg",
        "expected": ["NXOS-004"],
        "description": "SSH feature explicitly disabled with VTY lines present.",
        "content": """\
boot nxos
switchname nxos004-violation
no feature ssh
!
line vty
 transport input telnet
!
""",
    },
    {
        "path": "cisco_nx_os/nxos004-violation-missing-ssh.cfg",
        "expected": ["NXOS-004"],
        "description": "VTY configured without SSH feature enabled.",
        "content": """\
boot nxos
switchname nxos004-violation2
feature telnet
!
line vty
 transport input telnet
!
""",
    },
    {
        "path": "cisco_nx_os/nxos004-clean-feature-ssh.cfg",
        "expected": [],
        "description": "SSH feature enabled for VTY management.",
        "content": BASE.format(hostname="nxos004-clean"),
    },
    {
        "path": "cisco_nx_os/nxos004-clean-ssh-explicit.cfg",
        "expected": [],
        "description": "Explicit feature ssh with SSH-only VTY transport.",
        "content": BASE.format(hostname="nxos004-clean2")
        + """
feature ssh
line vty
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos005-violation-snmp-public.cfg",
        "expected": ["NXOS-005"],
        "description": "SNMP community uses default public string.",
        "content": BASE.format(hostname="nxos005-violation")
        + """
snmp-server community public RO
!
""",
    },
    {
        "path": "cisco_nx_os/nxos005-violation-snmp-rw.cfg",
        "expected": ["NXOS-005"],
        "description": "SNMP community grants read-write access.",
        "content": BASE.format(hostname="nxos005-violation2")
        + """
snmp-server community netops-rw-44a1 RW
!
""",
    },
    {
        "path": "cisco_nx_os/nxos005-clean-snmp-custom.cfg",
        "expected": [],
        "description": "SNMP community uses non-default read-only string.",
        "content": BASE.format(hostname="nxos005-clean")
        + """
snmp-server community netops-ro-7f3a RO
!
""",
    },
    {
        "path": "cisco_nx_os/nxos005-clean-snmp-scoped.cfg",
        "expected": [],
        "description": "SNMP read-only community with custom name.",
        "content": BASE.format(hostname="nxos005-clean2")
        + """
snmp-server community dc1-monitor RO
snmp-server location DC1-MDF
!
""",
    },
    {
        "path": "cisco_nx_os/nxos006-violation-no-aaa.cfg",
        "expected": ["NXOS-006"],
        "description": "VTY lines without AAA login authentication.",
        "content": """\
boot nxos
switchname nxos006-violation
feature ssh
!
line vty
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos006-violation-aaa-no-login.cfg",
        "expected": ["NXOS-006"],
        "description": "AAA lines present without login authentication.",
        "content": """\
boot nxos
switchname nxos006-violation2
feature ssh
!
aaa group server radius RADIUS
 server 10.10.10.10
!
line vty
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos006-clean-aaa-login.cfg",
        "expected": [],
        "description": "AAA login authentication configured.",
        "content": BASE.format(hostname="nxos006-clean"),
    },
    {
        "path": "cisco_nx_os/nxos006-clean-radius-login.cfg",
        "expected": [],
        "description": "AAA login via RADIUS group.",
        "content": BASE.format(hostname="nxos006-clean2")
        + """
aaa authentication login default group radius
aaa group server radius RADIUS
 server 10.10.10.10
!
""",
    },
    {
        "path": "cisco_nx_os/nxos007-violation-role-star.cfg",
        "expected": ["NXOS-007"],
        "description": "Role grants permit command *.",
        "content": BASE.format(hostname="nxos007-violation")
        + """
role name contractor
 rule 1 permit command *
!
""",
    },
    {
        "path": "cisco_nx_os/nxos007-violation-role-broad.cfg",
        "expected": ["NXOS-007"],
        "description": "Role grants broad permit command * privilege.",
        "content": BASE.format(hostname="nxos007-violation2")
        + """
role name backup-admin
 rule 10 permit command *
 rule 20 deny command configure terminal
!
""",
    },
    {
        "path": "cisco_nx_os/nxos007-clean-role-scoped.cfg",
        "expected": [],
        "description": "Role scoped to show commands only.",
        "content": BASE.format(hostname="nxos007-clean")
        + """
role name netops-read
 rule 1 permit command show interface
 rule 2 permit command show ip
!
""",
    },
    {
        "path": "cisco_nx_os/nxos007-clean-role-deny.cfg",
        "expected": [],
        "description": "Role denies configure while permitting show.",
        "content": BASE.format(hostname="nxos007-clean2")
        + """
role name operator
 rule 1 permit command show *
 rule 2 deny command configure terminal
!
""",
    },
    {
        "path": "cisco_nx_os/nxos008-violation-mgmt-public.cfg",
        "expected": ["NXOS-008"],
        "description": "Management VRF VTY ACL permits internet source.",
        "content": BASE.format(hostname="nxos008-violation")
        + """
ip access-list MGMT-IN
 10 permit ip 203.0.113.0/24 any
!
line vty
 access-class MGMT-IN in
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos008-violation-mgmt-any.cfg",
        "expected": ["NXOS-008"],
        "description": "Management VRF VTY ACL permits any source.",
        "content": BASE.format(hostname="nxos008-violation2")
        + """
ip access-list MGMT-JUMP
 10 permit ip any any
!
line vty
 access-class MGMT-JUMP in
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos008-clean-mgmt-rfc1918.cfg",
        "expected": [],
        "description": "Management VRF VTY ACL scoped to RFC1918 jump hosts.",
        "content": BASE.format(hostname="nxos008-clean")
        + """
ip access-list MGMT-JUMP
 10 permit ip 10.20.30.0/24 any
!
line vty
 access-class MGMT-JUMP in
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos008-clean-mgmt-deny.cfg",
        "expected": [],
        "description": "Management VRF VTY ACL denies non-jump sources.",
        "content": BASE.format(hostname="nxos008-clean2")
        + """
ip access-list MGMT-IN
 10 permit ip 192.168.100.0/24 any
 20 deny ip any any
!
line vty
 access-class MGMT-IN in
 transport input ssh
!
""",
    },
    {
        "path": "cisco_nx_os/nxos009-violation-any-any.cfg",
        "expected": ["NXOS-009"],
        "description": "ACL permit ACE allows any/any on resolved endpoints.",
        "content": BASE.format(hostname="nxos009-violation")
        + """
ip access-list DATA-IN
 10 permit ip any any
!
""",
    },
    {
        "path": "cisco_nx_os/nxos009-violation-any-any-tcp.cfg",
        "expected": ["NXOS-009"],
        "description": "ACL permit tcp any any.",
        "content": BASE.format(hostname="nxos009-violation2")
        + """
ip access-list EDGE-IN
 10 permit tcp any any
!
""",
    },
    {
        "path": "cisco_nx_os/nxos009-clean-scoped-acl.cfg",
        "expected": [],
        "description": "ACL permit ACE scoped to private networks.",
        "content": BASE.format(hostname="nxos009-clean")
        + """
ip access-list DATA-IN
 10 permit tcp 10.10.0.0/16 any eq 443
!
""",
    },
    {
        "path": "cisco_nx_os/nxos009-clean-deny-default.cfg",
        "expected": [],
        "description": "ACL ends with explicit deny.",
        "content": BASE.format(hostname="nxos009-clean2")
        + """
ip access-list EDGE-IN
 10 permit tcp 172.16.0.0/12 any eq 443
 20 deny ip any any
!
""",
    },
    {
        "path": "cisco_nx_os/nxos010-violation-feature-ftp.cfg",
        "expected": ["NXOS-010"],
        "description": "FTP file-transfer feature enabled.",
        "content": BASE.format(hostname="nxos010-violation")
        + """
feature ftp
!
""",
    },
    {
        "path": "cisco_nx_os/nxos010-violation-feature-tftp.cfg",
        "expected": ["NXOS-010"],
        "description": "TFTP file-transfer feature enabled.",
        "content": BASE.format(hostname="nxos010-violation2")
        + """
feature tftp
!
""",
    },
    {
        "path": "cisco_nx_os/nxos010-clean-no-transfer.cfg",
        "expected": [],
        "description": "No unencrypted file-transfer features enabled.",
        "content": BASE.format(hostname="nxos010-clean"),
    },
    {
        "path": "cisco_nx_os/nxos010-clean-scp-only.cfg",
        "expected": [],
        "description": "SCP-server disabled; only SSH management enabled.",
        "content": BASE.format(hostname="nxos010-clean2")
        + """
no feature scp-server
no feature ftp
no feature tftp
!
""",
    },
]


def _write_entry(entry: dict) -> None:
    rel = Path(entry["path"])
    cfg_path = ROOT / "validation" / "corpus" / "config" / rel
    label_path = cfg_path.with_suffix(cfg_path.suffix + ".labels.json")
    cfg_path.write_text(entry["content"])
    label_path.write_text(
        json.dumps(
            {
                "target_type": "cisco_nx_os",
                "virtual_path": f"switches/{rel.name.split('/')[-1]}",
                "expected_rule_ids": entry["expected"],
                "description": entry["description"],
            },
            indent=2,
        )
        + "\n"
    )


def main() -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    for entry in ENTRIES:
        _write_entry(entry)
    print(f"Wrote {len(ENTRIES)} generated NX-OS corpus fixtures to {CORPUS}")


if __name__ == "__main__":
    main()
