"""Platform sniffing for IOS-XE vs NX-OS vs ASA CLI fragments."""

from __future__ import annotations

from enum import Enum


class SniffedPlatform(str, Enum):
    IOS_XE = "cisco_ios_xe"
    NX_OS = "cisco_nx_os"
    ASA = "cisco_secure_firewall"
    UNKNOWN = "unknown"


_IOS_XE_MARKERS = (
    "version ",
    "boot-start-marker",
    "boot-end-marker",
    "service timestamps",
    "ip access-list extended ",
    "ip access-list standard ",
    "object-group network ",
    "object-group service ",
    "spanning-tree ",
    "license udi pid",
)

_NX_OS_MARKERS = (
    "boot nxos",
    "switchname ",
    "feature ",
    "vrf context ",
    "object-group ip address ",
    "object-group ip port ",
    "role name ",
    "nv overlay evpn",
    "vpc domain",
    "interface nve",
)

_ASA_MARKERS = (
    "nameif ",
    "security-level ",
    "access-list ",
    "object network ",
    "object service ",
    "same-security-traffic ",
)

# ASA management-plane commands are `ssh|http|https|telnet <addr> <mask> <ifname>`.
# IOS-XE and NX-OS do not use that form. `crypto ikev2 policy` and
# `crypto ipsec transform-set` are shared with IOS-XE, so they are not markers.
_ASA_MGMT_SERVICES = frozenset({"ssh", "http", "https", "telnet"})


def _ipv4_token(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _has_asa_management_access(content: str) -> bool:
    """True when a line is an ASA ssh/http/https/telnet management-access command."""
    for raw in content.splitlines():
        command = raw.split("!", 1)[0].strip()
        parts = command.split()
        if len(parts) < 4:
            continue
        if parts[0].lower() not in _ASA_MGMT_SERVICES:
            continue
        if _ipv4_token(parts[1]) and _ipv4_token(parts[2]):
            return True
    return False


def sniff_platform(content: str) -> SniffedPlatform:
    """Return the most likely platform for a CLI config body (no regex on semantics)."""
    lowered = content.lower()
    scores = {
        SniffedPlatform.IOS_XE: 0,
        SniffedPlatform.NX_OS: 0,
        SniffedPlatform.ASA: 0,
    }
    for marker in _IOS_XE_MARKERS:
        if marker in lowered:
            scores[SniffedPlatform.IOS_XE] += 1
    for marker in _NX_OS_MARKERS:
        if marker in lowered:
            scores[SniffedPlatform.NX_OS] += 1
    for marker in _ASA_MARKERS:
        if marker in lowered:
            scores[SniffedPlatform.ASA] += 1
    if _has_asa_management_access(content):
        scores[SniffedPlatform.ASA] += 1

    if scores[SniffedPlatform.ASA] > 0 and "access-list " in lowered and " extended " in lowered:
        scores[SniffedPlatform.ASA] += 2
    if "nameif " in lowered and "security-level " in lowered:
        scores[SniffedPlatform.ASA] += 2
    if "ip access-list " in lowered and "boot-start-marker" in lowered:
        scores[SniffedPlatform.IOS_XE] += 2
    elif "ip access-list extended " in lowered or "ip access-list standard " in lowered:
        scores[SniffedPlatform.IOS_XE] += 2
    if "boot nxos" in lowered or "switchname " in lowered:
        scores[SniffedPlatform.NX_OS] += 2
    if "object-group ip address " in lowered or "object-group ip port " in lowered:
        scores[SniffedPlatform.NX_OS] += 2
    if "vrf context " in lowered and "feature " in lowered:
        scores[SniffedPlatform.NX_OS] += 1

    best = max(scores.items(), key=lambda item: item[1])
    if best[1] == 0:
        return SniffedPlatform.UNKNOWN
    tied = [platform for platform, score in scores.items() if score == best[1]]
    if len(tied) > 1:
        return SniffedPlatform.UNKNOWN
    return best[0]


def platform_mismatch_line(
    *,
    declared_target_type: str,
    content: str,
) -> str | None:
    """Human-readable mismatch reason when sniffed platform disagrees with declaration."""
    sniffed = sniff_platform(content)
    if sniffed == SniffedPlatform.UNKNOWN:
        return None
    if sniffed.value == declared_target_type:
        return None
    return (
        f"declared target_type={declared_target_type} but content markers match "
        f"{sniffed.value}"
    )
