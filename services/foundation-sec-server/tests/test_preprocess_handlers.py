"""Tests for config preprocessing and handler routing."""

from __future__ import annotations

from foundation_sec_server.handlers.registry import ANSIBLE, DEFAULT_REGISTRY, NGINX, TERRAFORM
from foundation_sec_server.preprocess import strip_inactive_lines


def test_ansible_path_resolves_to_ansible_handler() -> None:
    handler = DEFAULT_REGISTRY.resolve("ansible/wildcard-sudo.yml")
    assert handler.name == "ansible"


def test_nginx_path_resolves_to_nginx_handler() -> None:
    handler = DEFAULT_REGISTRY.resolve("nginx/payments.conf")
    assert handler.name == "nginx"


def test_strip_hash_comments_terraform() -> None:
    content = "# inactive wide rule\nresource \"x\" { cidr = \"0.0.0.0/0\" }\n"
    active, stripped = strip_inactive_lines(content, TERRAFORM)
    assert stripped == 1
    assert "# inactive" not in active
    assert "resource" in active


def test_strip_hash_comments_preserves_active_block() -> None:
    content = (
        "# Broad CIDR justified\n"
        'resource "aws_security_group_rule" "x" {\n'
        '  cidr_blocks = ["10.0.0.0/8"]\n'
        "}\n"
    )
    active, stripped = strip_inactive_lines(content, TERRAFORM)
    assert stripped == 1
    assert "10.0.0.0/8" in active


def test_nginx_comment_stripped() -> None:
    content = "# old tls config\nserver { listen 80; }\n"
    active, stripped = strip_inactive_lines(content, NGINX)
    assert stripped == 1
    assert "listen 80" in active
