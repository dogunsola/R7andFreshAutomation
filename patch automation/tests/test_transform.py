import csv
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from rapid7_freshservice_sync.models import AffectedAsset, Finding
from rapid7_freshservice_sync.transform import (
    build_catalog,
    transform_assets,
    write_findings_csv,
)


class TransformTests(unittest.TestCase):
    def test_build_catalog_maps_severity_and_remediation_details(self) -> None:
        catalog = build_catalog(
            [
                {
                    "id": "vuln-1",
                    "severity": "Critical",
                    "cves": "CVE-2025-1234, cve-2025-56789",
                    "name": "Example Service",
                    "solution": "Upgrade Example Service",
                    "fix": "Install version 2.0",
                },
                {
                    "id": "vuln-2",
                    "severity": "Severe",
                    "cves": "CVE-2024-9999",
                    "name": "Example Service",
                    "solution": "Apply vendor update",
                    "fix_details": "Restart the service",
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

    def test_transform_uses_active_findings_and_deduplicates(self) -> None:
        catalog = {
            "vuln-1": (
                "critical",
                "Example Service",
                "Upgrade",
                "Install 2.0",
            ),
            "no-cve": (
                "severe",
                "Example Service",
                "Upgrade",
                "Install 2.0",
            ),
            "microsoft": (
                "critical",
                "Microsoft Windows Server",
                "Update Windows",
                "Install patch",
            ),
        }

        assets = [
            {
                "host_name": "host.example.com",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
                "same": [
                    {
                        "vulnerability_id": "vuln-1",
                    },
                    {
                        "vulnerability_id": "no-cve",
                    },
                    {
                        "vulnerability_id": "missing",
                    },
                ],
                "remediated": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            },
            {
                "host_name": "host2.example.com",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            },
            {
                "ip": "10.0.0.2",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            },
        ]

        findings, stats = transform_assets(
            assets,
            catalog,
        )

        self.assertEqual(
            findings,
            [
                Finding(
                    hosts=(
                        "host.example.com",
                        "host2.example.com",
                    ),
                    solution="Upgrade",
                    fix_details="Install 2.0",
                    vulnerability_count=2,
                    affected_assets=(
                        AffectedAsset(
                            "",
                            "host.example.com",
                            "",
                        ),
                        AffectedAsset(
                            "",
                            "host2.example.com",
                            "",
                        ),
                    ),
                )
            ],
        )

        self.assertEqual(
            stats.assets_seen,
            3,
        )

        self.assertEqual(
            stats.assets_without_host,
            1,
        )

        self.assertEqual(
            stats.vulnerability_ids_not_in_catalog,
            1,
        )

    def test_transform_falls_back_to_catalog_when_solution_lookup_is_empty(
        self,
    ) -> None:
        catalog = {
            "vuln-1": (
                "critical",
                "Example Service",
                "Upgrade Example Service",
                "Install version 2.0",
            )
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "ip": "10.0.0.10",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            }
        ]

        findings, stats = transform_assets(
            assets,
            catalog,
            solution_lookup=lambda _: [],
        )

        self.assertEqual(
            len(findings),
            1,
        )

        finding = findings[0]

        self.assertEqual(
            finding.hosts,
            ("host-a",),
        )

        self.assertEqual(
            finding.solution_id,
            "",
        )

        self.assertEqual(
            finding.solution,
            "Upgrade Example Service",
        )

        self.assertEqual(
            finding.fix_details,
            "Install version 2.0",
        )

        self.assertEqual(
            finding.vulnerability_count,
            1,
        )

        self.assertEqual(
            finding.affected_assets,
            (
                AffectedAsset(
                    "10",
                    "host-a",
                    "10.0.0.10",
                ),
            ),
        )

        self.assertEqual(
            stats.assets_seen,
            1,
        )

        self.assertEqual(
            stats.findings_written,
            1,
        )

        self.assertEqual(
            stats.assets_without_host,
            0,
        )

        self.assertEqual(
            stats.vulnerability_ids_not_in_catalog,
            0,
        )

    def test_transform_fetches_proof_per_asset_when_solution_has_at_most_five_vulnerabilities(
        self,
    ) -> None:
        catalog = {
            f"vuln-{index}": (
                "critical",
                "Example Service",
                "Upgrade",
                "Install 2.0",
            )
            for index in range(1, 6)
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "new": [
                    {
                        "vulnerability_id": vulnerability_id,
                    }
                    for vulnerability_id in catalog
                ],
            },
            {
                "id": 20,
                "host_name": "host-b",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    },
                ],
            },
        ]

        solution_lookup = lambda _vulnerability_id: [
            {
                "id": "solution-1",
                "summary": {
                    "text": "Upgrade",
                },
                "steps": {
                    "text": "Install 2.0",
                },
            },
        ]

        proof_lookup = Mock(
            side_effect=lambda asset_id, vulnerability_id: [
                {
                    "check_id": f"check-{vulnerability_id}",
                    "status": "vulnerable-version",
                    "proof": f"{asset_id}:{vulnerability_id}",
                }
            ]
        )

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=solution_lookup,
            proof_lookup=proof_lookup,
        )

        self.assertEqual(
            len(findings),
            1,
        )

        self.assertEqual(
            findings[0].solution_id,
            "solution-1",
        )

        self.assertEqual(
            findings[0].vulnerability_count,
            5,
        )

        self.assertEqual(
            {
                (
                    proof.asset_id,
                    proof.vulnerability_id,
                )
                for proof in findings[0].proofs
            },
            {
                (
                    asset_id,
                    vulnerability_id,
                )
                for asset_id, vulnerability_ids in (
                    (
                        "10",
                        catalog.keys(),
                    ),
                    (
                        "20",
                        ("vuln-1",),
                    ),
                )
                for vulnerability_id in vulnerability_ids
            },
        )

        self.assertEqual(
            proof_lookup.call_count,
            6,
        )

    def test_transform_skips_proof_lookup_for_solutions_with_more_than_five_vulnerabilities(
        self,
    ) -> None:
        catalog = {
            f"vuln-{index}": (
                "critical",
                "Example Service",
                "Upgrade",
                "Install 2.0",
            )
            for index in range(6)
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "new": [
                    {
                        "vulnerability_id": vulnerability_id,
                    }
                    for vulnerability_id in catalog
                ],
            }
        ]

        solution_lookup = lambda _vulnerability_id: [
            {
                "id": "solution-1",
                "summary": {
                    "text": "Upgrade",
                },
                "steps": {
                    "text": "Install 2.0",
                },
            },
        ]

        proof_lookup = Mock()

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=solution_lookup,
            proof_lookup=proof_lookup,
        )

        proof_lookup.assert_not_called()

        self.assertEqual(
            findings[0].vulnerability_count,
            6,
        )

        self.assertIn(
            "limit: 5",
            findings[0].proof_note,
        )

    def test_transform_keeps_asset_row_when_rapid7_returns_no_proof(
        self,
    ) -> None:
        catalog = {
            "vuln-1": (
                "critical",
                "Example Service",
                "Upgrade",
                "Install 2.0",
            )
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            }
        ]

        solution_lookup = lambda _vulnerability_id: [
            {
                "id": "solution-1",
                "summary": {
                    "text": "Upgrade",
                },
                "steps": {
                    "text": "Install 2.0",
                },
            },
        ]

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=solution_lookup,
            proof_lookup=lambda _asset_id, _vulnerability_id: [],
        )

        self.assertEqual(
            len(findings[0].proofs),
            1,
        )

        self.assertEqual(
            findings[0].proofs[0].asset_id,
            "10",
        )

        self.assertEqual(
            findings[0].proofs[0].proof,
            "No proof details returned by Rapid7.",
        )

    def test_transform_keeps_distinct_solution_ids_separate(
        self,
    ) -> None:
        catalog = {
            "vuln-1": (
                "critical",
                "Example Service",
                "Upgrade",
                "Install 2.0",
            )
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            }
        ]

        solutions = [
            {
                "id": "solution-a",
                "summary": {
                    "text": "Upgrade",
                },
                "steps": {
                    "text": "Install 2.0",
                },
            },
            {
                "id": "solution-b",
                "summary": {
                    "text": "Upgrade",
                },
                "steps": {
                    "text": "Install 2.0",
                },
            },
        ]

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=lambda _vulnerability_id: solutions,
        )

        self.assertEqual(
            [
                finding.solution_id
                for finding in findings
            ],
            [
                "solution-a",
                "solution-b",
            ],
        )

    def test_transform_prefers_latest_version_over_specific_updates(
        self,
    ) -> None:
        catalog = {
            "vuln-1": (
                "critical",
                "Example Service",
                "Upgrade",
                "",
            )
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "new": [
                    {
                        "vulnerability_id": "vuln-1",
                    }
                ],
            }
        ]

        solutions = [
            {
                "id": "latest",
                "summary": {
                    "text": "Upgrade to the latest version",
                },
                "steps": {
                    "text": "Use the vendor's current release.",
                },
            },
            {
                "id": "specific",
                "summary": {
                    "text": "Upgrade to version 4.2.1",
                },
                "steps": {
                    "text": "Install version 4.2.1.",
                },
            },
            {
                "id": "config",
                "summary": {
                    "text": "Disable the vulnerable feature",
                },
                "steps": {
                    "text": "Update the service configuration.",
                },
            },
        ]

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=lambda _vulnerability_id: solutions,
        )

        self.assertEqual(
            [
                finding.solution_id
                for finding in findings
            ],
            [
                "config",
                "latest",
            ],
        )

    def test_transform_consolidates_matching_family_across_cves(
        self,
    ) -> None:
        catalog = {
            "cve-a": (
                "critical",
                "Example Service",
                "Upgrade",
                "",
            ),
            "cve-b": (
                "critical",
                "Example Service - security update",
                "Upgrade",
                "",
            ),
        }

        assets = [
            {
                "id": 10,
                "host_name": "host-a",
                "new": [
                    {
                        "vulnerability_id": "cve-a",
                    },
                    {
                        "vulnerability_id": "cve-b",
                    },
                ],
            }
        ]

        solutions = {
            "cve-a": [
                {
                    "id": "latest",
                    "summary": {
                        "text": "Upgrade to the latest version",
                    },
                    "steps": {
                        "text": "Use the vendor's current release.",
                    },
                },
            ],
            "cve-b": [
                {
                    "id": "specific",
                    "summary": {
                        "text": "Upgrade to version 4.2.1",
                    },
                    "steps": {
                        "text": "Install version 4.2.1.",
                    },
                },
            ],
        }

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=lambda vulnerability_id: solutions[
                vulnerability_id
            ],
        )

        self.assertEqual(
            len(findings),
            1,
        )
        self.assertEqual(
            findings[0].solution_id,
            "latest",
        )
        self.assertEqual(
            findings[0].vulnerability_count,
            2,
        )

    def test_ip_fallback_and_csv_format(
        self,
    ) -> None:
        findings, _ = transform_assets(
            [
                {
                    "ip": "10.0.0.2",
                    "new": [
                        {
                            "vulnerability_id": "vuln-1",
                        }
                    ],
                }
            ],
            {
                "vuln-1": (
                    "critical",
                    "Example Service",
                    "Upgrade",
                    "Install 2.0",
                )
            },
            hostname_fallback="ip",
        )

        with tempfile.TemporaryDirectory() as directory:
            output = (
                Path(directory)
                / "findings.csv"
            )

            write_findings_csv(
                output,
                findings,
            )

            with output.open(
                newline="",
                encoding="utf-8",
            ) as file:
                rows = list(
                    csv.reader(file)
                )

        self.assertEqual(
            rows,
            [
                [
                    "Hosts",
                    "Solution",
                    "Fix details",
                    "Proof information",
                ],
                [
                    "10.0.0.2",
                    "Upgrade",
                    "Install 2.0",
                    "",
                ],
            ],
        )

    def test_csv_formula_cells_are_escaped_and_file_is_private(
        self,
    ) -> None:
        findings = [
            Finding(
                hosts=(
                    "host.example.com",
                ),
                solution="=cmd|calc",
                fix_details="Install 2.0",
            )
        ]

        with tempfile.TemporaryDirectory() as directory:
            output = (
                Path(directory)
                / "findings.csv"
            )

            write_findings_csv(
                output,
                findings,
            )

            with output.open(
                newline="",
                encoding="utf-8",
            ) as file:
                rows = list(
                    csv.reader(file)
                )

            mode = stat.S_IMODE(
                output.stat().st_mode
            )

        self.assertEqual(
            rows[1],
            [
                "host.example.com",
                "'=cmd|calc",
                "Install 2.0",
                "",
            ],
        )

        self.assertEqual(
            mode,
            0o600,
        )


if __name__ == "__main__":
    unittest.main()
