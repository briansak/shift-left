#!/usr/bin/env python3
"""Generate labeled handler evaluation corpus under validation/corpus/config/."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "validation" / "corpus" / "config"

ASA_HEADER = """\
! Generated handler corpus — edge firewall context
hostname edge-fw-01
domain-name corp.example
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address dhcp setroute
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.10.0.1 255.255.255.0
!
"""

ASA_FOOTER = """\
!
access-group OUTSIDE_IN in interface outside
access-group INSIDE_OUT out interface inside
!
logging enable
logging timestamp
"""

ENTRIES: list[dict] = [
    # --- cisco_secure_firewall violations (14) ---
    {
        "path": "cisco_secure_firewall/edge-perimeter-wide.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/edge-perimeter-wide.rules",
        "expected_rule_ids": ["ASA-001"],
        "description": "Internet edge ACL contains permit ip any any before explicit deny.",
        "content": ASA_HEADER
        + """
object network INSIDE_NET
 subnet 10.10.0.0 255.255.255.0
!
access-list OUTSIDE_IN extended permit tcp any object INSIDE_NET eq 443
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended deny ip any any log
"""
        + ASA_FOOTER,
    },
    {
        "path": "cisco_secure_firewall/guest-wifi-bypass.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "policy/guest-wifi-bypass.rules",
        "expected_rule_ids": ["ASA-001"],
        "description": "Guest VLAN policy includes temporary any-any permit.",
        "content": ASA_HEADER
        + """
object network GUEST_VLAN
 subnet 192.168.50.0 255.255.255.0
!
access-list GUEST_IN extended permit ip any any
access-list GUEST_IN extended permit udp any any eq domain
access-list GUEST_IN extended deny ip any any log
!
access-group GUEST_IN in interface outside
""",
    },
    {
        "path": "cisco_secure_firewall/lab-temp-open.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/lab-temp-open.rules",
        "expected_rule_ids": ["ASA-001"],
        "description": "Lab change ticket left a broad permit in OUT ACL.",
        "content": ASA_HEADER
        + """
access-list OUTSIDE_IN remark TEMP-LAB-4412
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended permit icmp any any
access-list OUTSIDE_IN extended deny ip any any
""",
    },
    {
        "path": "cisco_secure_firewall/partner-dmz-service-objects.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/partner-dmz-service-objects.rules",
        "expected_rule_ids": ["ASA-002"],
        "description": "Service objects include unconstrained TCP and IP protocol objects.",
        "content": ASA_HEADER
        + """
object service SVC-ANY-PROTO
 service protocol ip
!
object service SVC-TCP-WIDE
 service tcp
!
object service SVC-HTTPS
 service tcp destination eq 443
!
object network INSIDE_NET
 subnet 10.20.0.0 255.255.255.0
!
access-list PARTNER_IN extended permit object SVC-HTTPS any object INSIDE_NET
access-list PARTNER_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/shared-object-catalog.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "objects/shared-object-catalog.rules",
        "expected_rule_ids": ["ASA-002"],
        "description": "Shared catalog defines UDP service without port constraints.",
        "content": """\
hostname obj-catalog-01
!
object service APP-UDP-UNBOUNDED
 service udp
!
object service APP-DNS
 service udp destination eq 53
!
object network APP-SUBNET
 subnet 10.20.30.0 255.255.255.0
!
access-list APP_IN extended permit object APP-DNS any object APP-SUBNET
access-list APP_IN extended deny ip any any
""",
    },
    {
        "path": "cisco_secure_firewall/legacy-any-tcp-object.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/legacy-any-tcp-object.rules",
        "expected_rule_ids": ["ASA-002"],
        "description": "Legacy migration object uses bare service tcp.",
        "content": ASA_HEADER
        + """
object service MIGRATE-OLD-QUEUE
 service tcp
!
object network QUEUE_HOST
 host 10.10.0.50
!
access-list INSIDE_OUT extended permit object MIGRATE-OLD-QUEUE object QUEUE_HOST any
access-list INSIDE_OUT extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/branch-vpn-legacy-crypto.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "vpn/branch-vpn-legacy-crypto.rules",
        "expected_rule_ids": ["ASA-004"],
        "description": "Branch VPN still references weak IKEv2 and transform-set algorithms.",
        "content": ASA_HEADER
        + """
crypto ikev2 policy 10
 encryption des
 integrity md5
 group 2
 prf sha1
!
crypto ipsec transform-set BRANCH-LEGACY esp-3des esp-md5-hmac
!
crypto ipsec ikev2 ipsec-proposal BRANCH-OLD
 protocol esp encryption 3des
 protocol esp integrity md5
!
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/site-to-site-weak-phase1.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "vpn/site-to-site-weak-phase1.rules",
        "expected_rule_ids": ["ASA-004"],
        "description": "Site-to-site profile keeps SHA1 and DH group 5.",
        "content": """\
hostname vpn-concentrator-02
!
crypto isakmp policy 20
 authentication pre-share
 encryption 3des
 hash sha1
 group 5
 lifetime 86400
!
crypto ipsec transform-set PARTNER-OLD esp-3des esp-sha-hmac
!
access-list VPN_PEER extended permit ip 10.30.0.0 255.255.255.0 10.40.0.0 255.255.255.0
""",
    },
    {
        "path": "cisco_secure_firewall/mgmt-plane-exposure.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "mgmt/mgmt-plane-exposure.rules",
        "expected_rule_ids": ["ASA-005"],
        "description": "SSH and HTTP management allowed from any source on outside interface.",
        "content": ASA_HEADER
        + """
ssh 0.0.0.0 0.0.0.0 outside
http 0.0.0.0 0.0.0.0 outside
https 10.0.0.0 255.0.0.0 management
!
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/ops-jump-host-public.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "mgmt/ops-jump-host-public.rules",
        "expected_rule_ids": ["ASA-005"],
        "description": "Operations published SSH to a public /24 range.",
        "content": """\
hostname ops-fw-01
!
interface Management0/0
 nameif management
 security-level 100
 ip address 192.168.255.1 255.255.255.0
!
ssh 203.0.113.0 255.255.255.0 outside
telnet 203.0.113.10 255.255.255.255 outside
http 10.0.0.0 255.0.0.0 management
!
access-list MGMT extended deny ip any any
""",
    },
    {
        "path": "cisco_secure_firewall/acl-shadowed-permits.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/acl-shadowed-permits.rules",
        "expected_rule_ids": ["ASA-006"],
        "description": "Catch-all deny precedes several permit lines that can never match.",
        "content": ASA_HEADER
        + """
access-list OUTSIDE_IN extended deny ip any any log
access-list OUTSIDE_IN extended permit tcp 10.0.0.0 255.0.0.0 host 10.10.0.25 eq 443
access-list OUTSIDE_IN extended permit tcp 172.16.0.0 255.240.0.0 host 10.10.0.30 eq 80
access-list OUTSIDE_IN extended permit ip 10.0.0.0 255.255.255.0 any
!
access-group OUTSIDE_IN in interface outside
""",
    },
    {
        "path": "cisco_secure_firewall/dead-ace-cleanup.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/dead-ace-cleanup.rules",
        "expected_rule_ids": ["ASA-006"],
        "description": "Emergency deny-all was never followed by ACE reordering.",
        "content": ASA_HEADER
        + """
object service DMZ-HTTPS
 service tcp destination eq 443
!
object service DMZ-DNS
 service udp destination eq 53
!
object-group service DMZ-SERVICES
 service-object object DMZ-HTTPS
 service-object object DMZ-DNS
!
access-list INSIDE_OUT remark INC-8821 emergency block
access-list INSIDE_OUT extended deny ip any any
access-list INSIDE_OUT extended permit object-group DMZ-SERVICES 10.0.0.0 255.0.0.0 10.10.0.0 255.255.255.0
access-list INSIDE_OUT extended permit icmp 10.0.0.0 255.0.0.0 10.10.0.0 255.255.255.0
access-list INSIDE_OUT extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/undefined-network-group.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/undefined-network-group.rules",
        "expected_rule_ids": ["ASA-007"],
        "description": "ACE references undefined network object-group UNDEFINED-NET-GROUP.",
        "content": ASA_HEADER
        + """
access-list CORPUS_IN extended permit ip object-group UNDEFINED-NET-GROUP any any
access-list CORPUS_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/undefined-service-group.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/undefined-service-group.rules",
        "expected_rule_ids": ["ASA-007"],
        "description": "ACE references undefined service object-group UNDEFINED-SVC-GROUP.",
        "content": ASA_HEADER
        + """
access-list CORPUS_IN extended permit object-group UNDEFINED-SVC-GROUP 10.0.0.0 255.0.0.0 10.10.0.0 255.255.255.0
access-list CORPUS_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/scoped-network-group-clean.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/scoped-network-group-clean.rules",
        "expected_rule_ids": [],
        "description": "Network object-group resolves to narrow RFC1918 subnets; no ASA-007.",
        "content": ASA_HEADER
        + """
object-group network PARTNER-SUBNETS
 network-object 10.50.0.0 255.255.255.0
 network-object 10.51.0.0 255.255.255.0
!
access-list CORPUS_IN extended permit tcp object-group PARTNER-SUBNETS host 10.10.0.25 eq 443
access-list CORPUS_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/multi-violation-edge.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/multi-violation-edge.rules",
        "expected_rule_ids": ["ASA-001", "ASA-006"],
        "description": "Combines any-any permit with shadowed follow-on ACEs.",
        "content": ASA_HEADER
        + """
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended deny ip any any
access-list OUTSIDE_IN extended permit tcp any host 10.10.0.25 eq 22
access-list OUTSIDE_IN extended permit udp any any eq 53
""",
    },
    {
        "path": "cisco_secure_firewall/multi-object-and-mgmt.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/multi-object-and-mgmt.rules",
        "expected_rule_ids": ["ASA-001", "ASA-002", "ASA-005"],
        "description": "Permissive service object, any-any permit ACE, plus public SSH management.",
        "content": ASA_HEADER
        + """
object service MONITORING-ANY
 service protocol ip
!
ssh 198.51.100.0 255.255.255.0 outside
!
access-list OUTSIDE_IN extended permit object MONITORING-ANY any any
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    # --- cisco_secure_firewall clean (14) ---
    {
        "path": "cisco_secure_firewall/edge-scoped-production.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/edge-scoped-production.rules",
        "expected_rule_ids": [],
        "description": "Production edge ACL with scoped permits and explicit deny.",
        "content": ASA_HEADER
        + """
object network WEB_TIER
 subnet 10.10.10.0 255.255.255.0
!
access-list OUTSIDE_IN extended permit tcp any object WEB_TIER eq 443
access-list OUTSIDE_IN extended permit tcp 203.0.113.50 255.255.255.255 object WEB_TIER eq 443
access-list OUTSIDE_IN extended deny ip any any log
"""
        + ASA_FOOTER,
    },
    {
        "path": "cisco_secure_firewall/branch-office-outbound.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/branch-office-outbound.rules",
        "expected_rule_ids": [],
        "description": "Branch office outbound restrictions with deny default.",
        "content": """\
hostname branch-fw-12
!
object network BRANCH_LAN
 subnet 172.16.12.0 255.255.255.0
!
access-list INSIDE_OUT extended permit tcp object BRANCH_LAN any eq 443
access-list INSIDE_OUT extended permit udp object BRANCH_LAN any eq 53
access-list INSIDE_OUT extended deny ip any any log
!
access-group INSIDE_OUT out interface inside
""",
    },
    {
        "path": "cisco_secure_firewall/service-objects-scoped.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "objects/service-objects-scoped.rules",
        "expected_rule_ids": [],
        "description": "Service objects with explicit protocol and port constraints.",
        "content": ASA_HEADER
        + """
object service SVC-HTTPS
 service tcp destination eq 443
!
object service SVC-DNS
 service udp destination eq 53
!
object network APP_NET
 subnet 10.10.20.0 255.255.255.0
!
access-list INSIDE_OUT extended permit object SVC-HTTPS object APP_NET any
access-list INSIDE_OUT extended permit object SVC-DNS object APP_NET any
access-list INSIDE_OUT extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/vpn-strong-crypto.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "vpn/vpn-strong-crypto.rules",
        "expected_rule_ids": [],
        "description": "Modern IKEv2/IPsec proposals with strong algorithms.",
        "content": ASA_HEADER
        + """
crypto ikev2 policy 20
 encryption aes-256
 integrity sha256
 group 19
 prf sha256
!
crypto ipsec ikev2 ipsec-proposal STRONG
 protocol esp encryption aes-256
 protocol esp integrity sha-256
!
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/mgmt-rfc1918-only.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "mgmt/mgmt-rfc1918-only.rules",
        "expected_rule_ids": [],
        "description": "Management plane restricted to RFC1918 jump networks.",
        "content": ASA_HEADER
        + """
ssh 10.0.0.0 255.0.0.0 management
https 192.168.10.0 255.255.255.0 management
http 172.16.0.0 255.240.0.0 management
!
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/acl-order-correct.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/acl-order-correct.rules",
        "expected_rule_ids": [],
        "description": "Permits precede catch-all deny; no shadowed ACEs.",
        "content": ASA_HEADER
        + """
access-list OUTSIDE_IN extended permit tcp any host 10.10.0.40 eq 443
access-list OUTSIDE_IN extended permit tcp 203.0.113.0 255.255.255.0 host 10.10.0.40 eq 22
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/dmz-restricted-services.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/dmz-restricted-services.rules",
        "expected_rule_ids": [],
        "description": "DMZ ACL allows only specific services to app tier.",
        "content": ASA_HEADER
        + """
object network DMZ_NET
 subnet 10.20.0.0 255.255.255.0
!
access-list DMZ_IN extended permit tcp any object DMZ_NET eq 443
access-list DMZ_IN extended permit tcp 198.18.0.0 255.255.0.0 object DMZ_NET eq 22
access-list DMZ_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/inspection-defaults.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/inspection-defaults.rules",
        "expected_rule_ids": [],
        "description": "Baseline inspection policy without risky objects or ACEs.",
        "content": ASA_HEADER
        + """
policy-map global_policy
 class inspection_default
  inspect dns preset_dns_map
  inspect ftp
  inspect h323 h225
  inspect h323 ras
!
access-list OUTSIDE_IN extended permit tcp any 10.10.0.0 255.255.0.0 eq 443
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/partner-vpn-acl.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "vpn/partner-vpn-acl.rules",
        "expected_rule_ids": [],
        "description": "Partner VPN interesting traffic ACL is narrowly scoped.",
        "content": """\
hostname partner-vpn-01
!
access-list PARTNER_VPN extended permit ip 10.60.0.0 255.255.255.0 10.70.0.0 255.255.255.0
access-list PARTNER_VPN extended deny ip any any log
!
crypto ikev2 policy 30
 encryption aes-256
 integrity sha512
 group 21
""",
    },
    {
        "path": "cisco_secure_firewall/internal-segmentation.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/internal-segmentation.rules",
        "expected_rule_ids": [],
        "description": "East-west segmentation between internal VLANs.",
        "content": ASA_HEADER
        + """
object network USERS_VLAN
 subnet 10.10.30.0 255.255.255.0
object network SERVERS_VLAN
 subnet 10.10.40.0 255.255.255.0
!
access-list INSIDE_IN extended permit tcp object USERS_VLAN object SERVERS_VLAN eq 443
access-list INSIDE_IN extended permit udp object USERS_VLAN any eq 53
access-list INSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/logging-enabled-permits.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/logging-enabled-permits.rules",
        "expected_rule_ids": [],
        "description": "Permit ACEs include log keyword where required.",
        "content": ASA_HEADER
        + """
access-list OUTSIDE_IN extended permit tcp any host 10.10.0.15 eq 443 log
access-list OUTSIDE_IN extended permit icmp any host 10.10.0.15 log
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/legacy-transform-strong.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "vpn/legacy-transform-strong.rules",
        "expected_rule_ids": [],
        "description": "Transform-set uses AES256 and SHA256.",
        "content": """\
hostname crypto-fw-03
!
crypto ipsec transform-set MODERN esp-aes-256 esp-sha256-hmac
!
crypto ikev2 policy 40
 encryption aes-256
 integrity sha256
 group 19
""",
    },
    {
        "path": "cisco_secure_firewall/nat-and-acl-combo.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/nat-and-acl-combo.rules",
        "expected_rule_ids": [],
        "description": "NAT policies with matching scoped ACL entries.",
        "content": ASA_HEADER
        + """
object network WEB_HOST
 host 10.10.0.80
!
nat (inside,outside) static 203.0.113.80
!
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.80 eq 443
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    {
        "path": "cisco_secure_firewall/shadow-safe-deny-tcp.rules",
        "target_type": "cisco_secure_firewall",
        "virtual_path": "firewall/shadow-safe-deny-tcp.rules",
        "expected_rule_ids": [],
        "description": "Protocol-specific deny does not shadow later permit ip.",
        "content": ASA_HEADER
        + """
access-list OUTSIDE_IN extended deny tcp any any eq 80
access-list OUTSIDE_IN extended permit ip 10.0.0.0 255.0.0.0 any
access-list OUTSIDE_IN extended deny ip any any log
""",
    },
    # --- cisco_ftd violations (7) ---
    {
        "path": "cisco_ftd/branch-policy-insecure.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/branch-policy-insecure.tf",
        "expected_rule_ids": ["FTD-001", "FTD-002", "FTD-003", "FTD-005"],
        "description": "FMC policy with permissive port object, logging disabled, and public SSH.",
        "content": """\
terraform {
  required_providers {
    fmc = { source = "CiscoDevNet/fmc" }
  }
}

resource "fmc_access_policy" "branch" {
  name = "branch-edge"
}

resource "fmc_port" "svc_any_protocol" {
  name     = "SVC-ANY-PROTOCOL"
  protocol = "2048"
}

resource "fmc_access_rule" "mgmt_ssh_any" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "MGMT-SSH-FROM-ANY"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false

  source_network_literals {
    literal { value = "0.0.0.0/0" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "22" }
  }
}

resource "fmc_access_rule" "default_deny" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "DEFAULT-DENY"
  action           = "BLOCK"
  enabled          = true
  log_connection_begin = true
}
""",
    },
    {
        "path": "cisco_ftd/edge-unbounded-ports.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/edge-unbounded-ports.tf",
        "expected_rule_ids": ["FTD-002", "FTD-003"],
        "description": "Unbounded TCP port object and ALLOW without log_connection_begin.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_port" "svc_tcp_wide" {
  name     = "SVC-TCP-WIDE"
  protocol = "TCP"
}

resource "fmc_access_rule" "inside_https" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_port_literals { literal { protocol = "6" port = "443" } }
}
""",
    },
    {
        "path": "cisco_ftd/vpn-weak-ike.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/vpn/vpn-weak-ike.tf",
        "expected_rule_ids": ["FTD-004"],
        "description": "FMC IKEv2 policy with DES and low DH group.",
        "content": """\
resource "fmc_ikev2_policy" "legacy" {
  name                  = "IKEV2-LEGACY"
  encryption_algorithms = ["DES"]
  integrity_algorithms  = ["MD5"]
  dh_groups             = ["2"]
}

resource "fmc_access_policy" "vpn" { name = "vpn-policy" }
""",
    },
    {
        "path": "cisco_ftd/device-vpn-weak.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/vpn/device-vpn-weak.tf",
        "expected_rule_ids": ["FTD-004"],
        "description": "Bulk FMC IKEv2 policies with 3DES and SHA-1.",
        "content": """\
resource "fmc_ikev2_policies" "branch_weak" {
  items = {
    branch_weak = {
      encryption_algorithms = ["3DES"]
      integrity_algorithms  = ["SHA-1"]
      dh_groups             = ["5"]
    }
  }
}
""",
    },
    {
        "path": "cisco_ftd/mgmt-https-public.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/mgmt-https-public.tf",
        "expected_rule_ids": ["FTD-005"],
        "description": "HTTPS management allowed from public /24.",
        "content": """\
resource "fmc_access_policy" "mgmt" { name = "mgmt-policy" }

resource "fmc_access_rule" "mgmt_https_public" {
  access_control_policy_id = fmc_access_policy.mgmt.id
  name             = "MGMT-HTTPS-PUBLIC"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "203.0.113.0/24" } }
  destination_port_literals { literal { protocol = "6" port = "443" } }
}
""",
    },
    {
        "path": "cisco_ftd/shadowed-bulk-rules.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/shadowed-bulk-rules.tf",
        "expected_rule_ids": ["FTD-005", "FTD-006"],
        "description": "Shadowed mgmt ALLOW (FTD-005) co-occurring with catch-all BLOCK shadow (FTD-006).",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge-policy" }

resource "fmc_access_rules" "ordered" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "DENY-ALL"
      action  = "BLOCK"
      enabled = true
      source_network_literals      = [{ value = "0.0.0.0/0" }]
      destination_network_literals = [{ value = "any" }]
    },
    {
      name    = "ALLOW-HTTPS"
      action  = "ALLOW"
      enabled = true
      log_connection_begin = true
      destination_port_literals = [{ protocol = "6" port = "443" }]
    }
  ]
}
""",
    },
    {
        "path": "cisco_ftd/multi-violation-edge.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/multi-violation-edge.tf",
        "expected_rule_ids": ["FTD-003", "FTD-006"],
        "description": "Bulk rules shadow ALLOW while standalone rule disables logging.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "app_allow_no_log" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "APP-ALLOW"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false
  source_network_literals { literal { value = "10.0.0.0/8" } }
}

resource "fmc_access_rules" "ordered_shadow" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "BLOCK-ALL"
      action  = "BLOCK"
      enabled = true
      source_network_literals      = [{ value = "any" }]
      destination_network_literals = [{ value = "any" }]
    },
    {
      name    = "ALLOW-DNS"
      action  = "ALLOW"
      enabled = true
      destination_port_literals = [{ protocol = "17" port = "53" }]
    }
  ]
}
""",
    },
    # --- cisco_ftd clean (7) ---
    {
        "path": "cisco_ftd/dcloud-baseline.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/dcloud-baseline.tf",
        "expected_rule_ids": [],
        "description": "Scoped dCloud lab policy with logging enabled.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "inside_to_inside" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-TO-INSIDE"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "198.18.0.0/15" } }
  destination_network_literals { literal { value = "198.18.0.0/15" } }
}

resource "fmc_port" "svc_https" {
  name     = "SVC-HTTPS"
  protocol = "TCP"
  port     = "443"
}
""",
    },
    {
        "path": "cisco_ftd/strong-vpn-policy.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/vpn/strong-vpn-policy.tf",
        "expected_rule_ids": [],
        "description": "Strong FMC IKEv2 policy.",
        "content": """\
resource "fmc_ikev2_policy" "strong" {
  name                  = "IKEV2-STRONG"
  encryption_algorithms = ["AES-256"]
  integrity_algorithms  = ["SHA-256"]
  dh_groups             = ["19"]
}
""",
    },
    {
        "path": "cisco_ftd/private-mgmt-ssh.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/private-mgmt-ssh.tf",
        "expected_rule_ids": [],
        "description": "SSH management restricted to RFC1918.",
        "content": """\
resource "fmc_access_policy" "mgmt" { name = "mgmt" }

resource "fmc_access_rule" "mgmt_ssh_private" {
  access_control_policy_id = fmc_access_policy.mgmt.id
  name             = "MGMT-SSH-PRIVATE"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_port_literals { literal { protocol = "6" port = "22" } }
}
""",
    },
    {
        "path": "cisco_ftd/app-https-scoped.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/app-https-scoped.tf",
        "expected_rule_ids": [],
        "description": "Application HTTPS rule with private source.",
        "content": """\
resource "fmc_access_policy" "app" { name = "app" }

resource "fmc_access_rule" "app_https" {
  access_control_policy_id = fmc_access_policy.app.id
  name             = "APP-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_port_literals { literal { protocol = "6" port = "443" } }
}
""",
    },
    {
        "path": "cisco_ftd/separate-rules-no-shadow.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/separate-rules-no-shadow.tf",
        "expected_rule_ids": [],
        "description": "Separate fmc_access_rule resources; deny after permit.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "allow_https" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "ALLOW-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
}

resource "fmc_access_rule" "deny_rest" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "DENY-REST"
  action           = "BLOCK"
  enabled          = true
  source_network_literals { literal { value = "0.0.0.0/0" } }
}
""",
    },
    {
        "path": "cisco_ftd/bulk-safe-order.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/bulk-safe-order.tf",
        "expected_rule_ids": [],
        "description": "Bulk rules with port-specific BLOCK that does not shadow ALLOW ip.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rules" "ordered" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "BLOCK-TCP-80"
      action  = "BLOCK"
      enabled = true
      destination_port_literals = [{ protocol = "6" port = "80" }]
    },
    {
      name    = "ALLOW-IP"
      action  = "ALLOW"
      enabled = true
      log_connection_begin = true
      source_network_literals = [{ value = "10.0.0.0/8" }]
    }
  ]
}
""",
    },
    {
        "path": "cisco_ftd/port-catalog-clean.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/objects/port-catalog-clean.tf",
        "expected_rule_ids": [],
        "description": "Well-scoped FMC port objects.",
        "content": """\
resource "fmc_port" "svc_dns" {
  name     = "SVC-DNS"
  protocol = "UDP"
  port     = "53"
}

resource "fmc_ports" "catalog" {
  items = {
    web = {
      protocol = "TCP"
      port     = "443"
    }
  }
}
""",
    },
    # --- FTD-001 broad network literals (4) ---
    {
        "path": "cisco_ftd/broad-source-any.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/broad-source-any.tf",
        "expected_rule_ids": ["FTD-001"],
        "description": "ALLOW with 0.0.0.0/0 source literal.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "internet_ingress" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INTERNET-INGRESS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "0.0.0.0/0" } }
  destination_port_literals { literal { protocol = "6" port = "8080" } }
}
""",
    },
    {
        "path": "cisco_ftd/broad-dest-missing.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/broad-dest-missing.tf",
        "expected_rule_ids": ["FTD-001"],
        "description": "ALLOW with explicit any destination network literal.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "inside_any_dest" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-ANY-DEST"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_network_literals { literal { value = "any" } }
}
""",
    },
    {
        "path": "cisco_ftd/scoped-network-pair.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/scoped-network-pair.tf",
        "expected_rule_ids": [],
        "description": "ALLOW with scoped source and destination literals.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "inside_to_dmz" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-TO-DMZ"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_network_literals { literal { value = "10.20.0.0/24" } }
}
""",
    },
    {
        "path": "cisco_ftd/scoped-network-objects.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/scoped-network-objects.tf",
        "expected_rule_ids": [],
        "description": "ALLOW references in-module network objects instead of open literals.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_network" "inside" {
  name  = "INSIDE"
  prefix = "10.0.0.0/8"
}

resource "fmc_network" "dmz" {
  name  = "DMZ"
  prefix = "10.20.0.0/24"
}

resource "fmc_access_rule" "inside_to_dmz" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-TO-DMZ-OBJECTS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_objects {
    objects { id = fmc_network.inside.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.dmz.id type = "Network" }
  }
}
""",
    },
    # --- FTD-008 dangling network object refs (4) ---
    {
        "path": "cisco_ftd/dangling-source-network.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/dangling-source-network.tf",
        "expected_rule_ids": ["FTD-008"],
        "description": "Access rule references undefined fmc_network object.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "bad_source_ref" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "BAD-SOURCE-REF"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_objects {
    objects { id = fmc_network.missing_inside.id type = "Network" }
  }
  destination_network_literals { literal { value = "10.20.0.0/24" } }
}
""",
    },
    {
        "path": "cisco_ftd/dangling-dest-network.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/dangling-dest-network.tf",
        "expected_rule_ids": ["FTD-008"],
        "description": "Access rule references undefined destination network object.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_network" "inside" {
  name  = "INSIDE"
  prefix = "10.0.0.0/8"
}

resource "fmc_access_rule" "bad_dest_ref" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "BAD-DEST-REF"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_objects {
    objects { id = fmc_network.inside.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.missing_dmz.id type = "Network" }
  }
}
""",
    },
    {
        "path": "cisco_ftd/resolved-network-objects.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/resolved-network-objects.tf",
        "expected_rule_ids": [],
        "description": "In-module network object references resolve.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_network" "inside" {
  name  = "INSIDE"
  prefix = "10.0.0.0/8"
}

resource "fmc_network" "dmz" {
  name  = "DMZ"
  prefix = "10.20.0.0/24"
}

resource "fmc_access_rule" "resolved_refs" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "RESOLVED-REFS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_objects {
    objects { id = fmc_network.inside.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.dmz.id type = "Network" }
  }
}
""",
    },
    {
        "path": "cisco_ftd/literals-only-no-refs.tf",
        "target_type": "cisco_ftd",
        "virtual_path": "terraform/policies/literals-only-no-refs.tf",
        "expected_rule_ids": [],
        "description": "Scoped literals without network object references.",
        "content": """\
resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "literal_only" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "LITERAL-ONLY"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "10.10.0.0/24" } }
  destination_network_literals { literal { value = "10.20.0.0/24" } }
}
""",
    },
    # --- generic_terraform violations (7) ---
    {
        "path": "generic_terraform/aws-open-sg.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/aws-open-sg.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "AWS security group rule allows global ingress.",
        "content": """\
terraform {
  required_providers { aws = { source = "hashicorp/aws" } }
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application tier"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group_rule" "wide_ingress" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
""",
    },
    {
        "path": "generic_terraform/azure-nsg-open.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/azure-nsg-open.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "Azure NSG allows Internet inbound.",
        "content": """\
resource "azurerm_network_security_group" "edge" {
  name                = "edge-nsg"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name
}

resource "azurerm_network_security_rule" "allow_internet" {
  name                        = "AllowInternetInbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.core.name
  network_security_group_name = azurerm_network_security_group.edge.name
}
""",
    },
    {
        "path": "generic_terraform/gcp-firewall-open.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/gcp-firewall-open.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "GCP firewall allows 0.0.0.0/0 ingress.",
        "content": """\
resource "google_compute_firewall" "allow_public" {
  name    = "allow-public-ingress"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web"]
}
""",
    },
    {
        "path": "generic_terraform/fmc-inbound-open.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/fmc-inbound-open.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "FMC access rule in generic terraform corpus flags TF-001 via fmc parser path.",
        "content": """\
resource "fmc_access_policy" "branch" { name = "branch" }

resource "fmc_access_rule" "allow_internet_inbound" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "ALLOW-INTERNET-INBOUND"
  action           = "ALLOW"
  enabled          = true
  source_network_literals { literal { value = "0.0.0.0/0" } }
  destination_network_literals { literal { value = "any" } }
  destination_port_literals { literal { value = "any" } }
}
""",
    },
    {
        "path": "generic_terraform/aws-sg-ingress-block.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/aws-sg-ingress-block.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "AWS VPC security group ingress rule with ::/0.",
        "content": """\
resource "aws_vpc_security_group_ingress_rule" "ipv6_all" {
  security_group_id = aws_security_group.app.id
  ip_protocol       = "-1"
  cidr_ipv6         = "::/0"
}
""",
    },
    {
        "path": "generic_terraform/aws-sg-nested-ingress.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/aws-sg-nested-ingress.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "Nested ingress block on aws_security_group.",
        "content": """\
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
    },
    {
        "path": "generic_terraform/azure-nsg-group-rule.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/azure-nsg-group-rule.tf",
        "expected_rule_ids": ["TF-001"],
        "description": "Azure NSG embedded security_rule allows any source.",
        "content": """\
resource "azurerm_network_security_group" "app" {
  name                = "app-nsg"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name

  security_rule {
    name                       = "AllowAnyInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
""",
    },
    # --- generic_terraform clean (7) ---
    {
        "path": "generic_terraform/aws-scoped-sg.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/aws-scoped-sg.tf",
        "expected_rule_ids": [],
        "description": "AWS SG scoped to private CIDR.",
        "content": """\
resource "aws_security_group_rule" "app_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.app.id
}
""",
    },
    {
        "path": "generic_terraform/azure-scoped-nsg.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/azure-scoped-nsg.tf",
        "expected_rule_ids": [],
        "description": "Azure NSG scoped to VNet.",
        "content": """\
resource "azurerm_network_security_rule" "allow_vnet" {
  name                        = "AllowVnetInbound"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "VirtualNetwork"
  resource_group_name         = azurerm_resource_group.core.name
  network_security_group_name = azurerm_network_security_group.edge.name
}
""",
    },
    {
        "path": "generic_terraform/gcp-scoped-firewall.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/gcp-scoped-firewall.tf",
        "expected_rule_ids": [],
        "description": "GCP firewall limited to internal range.",
        "content": """\
resource "google_compute_firewall" "internal_https" {
  name    = "allow-internal-https"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["app"]
}
""",
    },
    {
        "path": "generic_terraform/aws-var-cidr.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/aws-var-cidr.tf",
        "expected_rule_ids": [],
        "description": "Interpolated CIDR should be unevaluated, not matched.",
        "content": """\
variable "admin_cidr" { type = string }

resource "aws_security_group_rule" "admin_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr]
  security_group_id = aws_security_group.app.id
}
""",
    },
    {
        "path": "generic_terraform/aws-egress-only.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/aws-egress-only.tf",
        "expected_rule_ids": [],
        "description": "Egress-only SG rule with public dest is not ingress violation.",
        "content": """\
resource "aws_security_group_rule" "egress_https" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
""",
    },
    {
        "path": "generic_terraform/gcp-egress.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/gcp-egress.tf",
        "expected_rule_ids": [],
        "description": "GCP egress firewall with public dest.",
        "content": """\
resource "google_compute_firewall" "egress_updates" {
  name      = "egress-updates"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"
  allow { protocol = "tcp" ports = ["443"] }
  destination_ranges = ["0.0.0.0/0"]
}
""",
    },
    {
        "path": "generic_terraform/fmc-scoped-allow.tf",
        "target_type": "generic_terraform",
        "virtual_path": "terraform/fmc-scoped-allow.tf",
        "expected_rule_ids": [],
        "description": "FMC rule with private source and specific port.",
        "content": """\
resource "fmc_access_policy" "app" { name = "app" }

resource "fmc_access_rule" "inside_https" {
  access_control_policy_id = fmc_access_policy.app.id
  name             = "INSIDE-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_port_literals { literal { protocol = "6" port = "443" } }
}
""",
    },
]


def main() -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    manifest = []
    for entry in ENTRIES:
        config_path = CORPUS / entry["path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(entry["content"])
        labels = {
            "target_type": entry["target_type"],
            "virtual_path": entry["virtual_path"],
            "expected_rule_ids": entry["expected_rule_ids"],
            "description": entry["description"],
        }
        labels_path = config_path.with_suffix(config_path.suffix + ".labels.json")
        labels_path.write_text(json.dumps(labels, indent=2) + "\n")
        manifest.append(
            {
                "path": entry["path"],
                "target_type": entry["target_type"],
                "expected_rule_ids": entry["expected_rule_ids"],
                "category": "clean" if not entry["expected_rule_ids"] else "violation",
            }
        )
    (CORPUS / "manifest.json").write_text(json.dumps({"entries": manifest}, indent=2) + "\n")
    clean = sum(1 for item in manifest if item["category"] == "clean")
    print(f"Wrote {len(manifest)} corpus files ({clean} clean, {len(manifest) - clean} violation)")


if __name__ == "__main__":
    main()
