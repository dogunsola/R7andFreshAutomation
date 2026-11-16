import csv
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from rapid7_freshservice_sync.models import (
    AffectedAsset,
    Finding,
)
from rapid7_freshservice_sync.transform import (
    build_catalog,
    transform_assets,
    write_findings_csv,
)


class TransformTests(unittest.TestCase):
    def test_build_catalog_maps_severity_and_remediation_details(
        self,
    ) -> None:
        catalog = build_catalog(
            [
                {
                    "id": "vuln-1",
                    "severity": "Critical",
                    "cves":
                        "CVE-2025-1234, cve-2025-56789",
                    "name": "Example Service",
                    "solution":
                        "Upgrade Example Service",
                    "fix":
                        "Install version 2.0",
                },
                {
                    "id": "vuln-2",
                    "severity": "Severe",
                    "cves": "CVE-2024-9999",
                    "name": "Example Service",
                    "solution":
                        "Apply vendor update",
                    "fix_details":
                        "Restart the service",
                },
                {
                    "id": "moderate",
                    "severity": "Moderate",
                    "cves": "CVE-2020-0001",
                },
            ]
        )

        self.assertEqual(
            catalog,
            {
                "vuln-1": (
                    "critical",
                    "Example Service",
                    "Upgrade Example Service",
                    "Install version 2.0",
                ),
                "vuln-2": (
                    "severe",
                    "Example Service",
                    "Apply vendor update",
                    "Restart the service",
                ),
            },
        )

    def test_transform_uses_active_findings_and_deduplicates(
        self,
    ) 