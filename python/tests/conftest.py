"""Shared fixtures for ressrf tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "vectors"


@pytest.fixture
def cidr_vectors() -> list[dict]:
    with open(VECTORS_DIR / "cidr_containment.json") as f:
        data = json.load(f)
    return data["cases"]


@pytest.fixture
def policy_vectors() -> list[dict]:
    with open(VECTORS_DIR / "policy_decisions.json") as f:
        data = json.load(f)
    return data["cases"]


@pytest.fixture
def url_vectors() -> list[dict]:
    with open(VECTORS_DIR / "url_validation.json") as f:
        data = json.load(f)
    return data["cases"]


@pytest.fixture
def url_rules_vectors() -> list[dict]:
    with open(VECTORS_DIR / "url_rules.json") as f:
        data = json.load(f)
    return data["cases"]


@pytest.fixture
def ssrf_techniques_vectors() -> list[dict]:
    with open(VECTORS_DIR / "ssrf_techniques.json") as f:
        data = json.load(f)
    return data["cases"]


@pytest.fixture
def audit_event_vectors() -> list[dict]:
    with open(VECTORS_DIR / "audit_events.json") as f:
        data = json.load(f)
    return data["test_cases"]


@pytest.fixture
def redirect_chain_vectors() -> list[dict]:
    with open(VECTORS_DIR / "redirect_chains.json") as f:
        data = json.load(f)
    return data["test_cases"]


@pytest.fixture
def ipv4_ipv6_mapping_vectors() -> list[dict]:
    with open(VECTORS_DIR / "ipv4_ipv6_mapping.json") as f:
        data = json.load(f)
    return data["cases"]
