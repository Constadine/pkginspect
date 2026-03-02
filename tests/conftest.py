from __future__ import annotations

import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> list[str]:
    return (FIXTURES / name).read_text().splitlines()


@pytest.fixture
def clean_lines():
    return load_fixture("clean.PKGBUILD")


@pytest.fixture
def moderate_lines():
    return load_fixture("moderate.PKGBUILD")


@pytest.fixture
def malicious_lines():
    return load_fixture("malicious.PKGBUILD")
