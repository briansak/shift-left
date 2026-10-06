"""MITRE CWE export parsing helpers."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from cwe_mitre_export import applicable_languages


def test_applicable_languages_includes_language_class_when_name_absent() -> None:
    weakness = ET.fromstring(
        """
        <Weakness xmlns="http://cwe.mitre.org/cwe-7" ID="1004">
          <Applicable_Platforms>
            <Language Class="Not Language-Specific" Prevalence="Undetermined"/>
          </Applicable_Platforms>
        </Weakness>
        """
    )
    assert applicable_languages(weakness) == ["Not Language-Specific"]


def test_applicable_languages_includes_named_and_class_values() -> None:
    weakness = ET.fromstring(
        """
        <Weakness xmlns="http://cwe.mitre.org/cwe-7" ID="89">
          <Applicable_Platforms>
            <Language Class="Not Language-Specific" Prevalence="Undetermined"/>
            <Language Name="SQL" Prevalence="Often"/>
          </Applicable_Platforms>
        </Weakness>
        """
    )
    assert applicable_languages(weakness) == ["Not Language-Specific", "SQL"]
