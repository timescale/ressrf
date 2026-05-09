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
