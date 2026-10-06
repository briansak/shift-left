"""Pluggable config format handlers for Foundation-Sec prompts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ConfigFormatHandler:
    name: str
    globs: tuple[str, ...]
    prompt_context: str

    def matches(self, path: str) -> bool:
        from foundation_sec_server.globmatch import matches_any

        return matches_any(path, self.globs)


class HandlerRegistry:
    def __init__(self, handlers: list[ConfigFormatHandler]) -> None:
        self._handlers = handlers

    def resolve(self, path: str) -> ConfigFormatHandler:
        for handler in self._handlers:
            if handler.matches(path):
                return handler
        return self._handlers[-1]


TERRAFORM = ConfigFormatHandler(
    name="terraform",
    globs=("**/*.tf", "**/*.tfvars", "**/*.hcl"),
    prompt_context=(
        "This is Terraform / OpenTofu infrastructure-as-code. Evaluate resource "
        "blocks, security groups, IAM bindings, and network exposure in the PROPOSED "
        "change only (comment lines and inactive blocks are removed before evaluation). "
        "Flag internet-wide exposure (0.0.0.0/0, ::/0) and unrestricted ingress. "
        "RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are "
        "common intentional scoping — do not flag solely for being a /8 or /16 private "
        "supernet unless combined with public CIDRs or clearly excessive exposure."
    ),
)

KUBERNETES = ConfigFormatHandler(
    name="kubernetes",
    globs=(
        "**/deploy/**",
        "**/k8s/**",
        "**/kubernetes/**",
        "**/*netpol*.yaml",
        "**/*netpol*.yml",
    ),
    prompt_context=(
        "This is a Kubernetes manifest (YAML). Evaluate securityContext, "
        "privileged mode, hostNetwork, RBAC bindings, and exposed services in "
        "the PROPOSED change only."
    ),
)

ANSIBLE = ConfigFormatHandler(
    name="ansible",
    globs=(
        "**/playbooks/**",
        "**/roles/**/*.yml",
        "**/roles/**/*.yaml",
        "**/ansible/**",
        "ansible/**",
    ),
    prompt_context=(
        "This is Ansible YAML (playbooks, roles, or task lists). Evaluate tasks that "
        "weaken host security: passwordless sudo (NOPASSWD), wildcard sudoers entries "
        "(ALL ALL=(ALL) ...), hardcoded secrets, permissive firewall modules, and "
        "privilege escalation. Comment-only lines are removed before evaluation."
    ),
)

NGINX = ConfigFormatHandler(
    name="nginx",
    globs=("nginx/**", "**/nginx/**", "**/*nginx*.conf"),
    prompt_context=(
        "This is nginx configuration. Evaluate listener bindings: plain HTTP (listen 80 "
        "without ssl/tls) on sensitive hosts, missing TLS on public-facing server_name "
        "blocks, weak ssl_protocols, and proxy_pass to cleartext backends. Comment lines "
        "are removed before evaluation."
    ),
)

DEVICE_CONFIG = ConfigFormatHandler(
    name="device",
    globs=("**/*.rules", "**/firewall/**", "**/*.xml"),
    prompt_context=(
        "This is network device configuration (Cisco ASA/ACL, iptables-style, or "
        "similar rule text). Evaluate access-list / security rule changes for: "
        "'permit ip any any' or equivalent any-to-any ALLOW, source/destination any "
        "with permit/allow, 0.0.0.0/0 with permit, and management-plane exposure. "
        "Scoped permits to specific subnets with a trailing deny are often intentional."
    ),
)

GENERIC = ConfigFormatHandler(
    name="generic",
    globs=("**/*.conf", "**/*.cfg", "**/*"),
    prompt_context=(
        "This is generic structured or semi-structured configuration text. "
        "Evaluate the PROPOSED change for security posture regression."
    ),
)

DEFAULT_REGISTRY = HandlerRegistry([TERRAFORM, KUBERNETES, ANSIBLE, NGINX, DEVICE_CONFIG, GENERIC])
