"""Glob matching for config handler selection."""

from __future__ import annotations

from foundation_sec_server.globmatch import path_matches_glob


def test_root_deploy_path_matches_kubernetes_glob() -> None:
    assert path_matches_glob("deploy/k8s-hostnetwork.yaml", "**/deploy/**")


def test_root_k8s_path_matches_kubernetes_glob() -> None:
    assert path_matches_glob("k8s/manifest.yaml", "**/k8s/**")


def test_ansible_subdirectory_matches_glob() -> None:
    assert path_matches_glob("ansible/playbooks/site.yml", "**/ansible/**")
