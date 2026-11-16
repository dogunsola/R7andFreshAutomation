import unittest
from unittest.mock import Mock

from rapid7_freshservice_sync.rapid7 import (
    Rapid7SolutionClient,
)
from rapid7_freshservice_sync.transform import (
    build_catalog,
    transform_assets,
)


class SolutionTests(unittest.TestCase):
    def test_solution_lookup_and_caching(
        self,
    ) -> None:
        http = Mock()

        record = {
            "summary": {
                "text": "Upgrade",
            },
            "steps": {
                "text": "Install update",
            },
        }

        http.request_json.side_effect = [
            {
                "resources": [
                    "fix/id",
                ]
            },
            record,
            {
                "resources": [
                    "fix/id",
                ]
            },
        ]

        client = Rapid7SolutionClient(
            "https://console:3780",
            "user",
            "password",
            http,
        )

        solution = {
            **record,
            "id": "fix/id",
        }

        self.assertEqual(
            client.get_vulnerability_solutions(
                "vuln/id"
            ),
            [
                solution,
            ],
        )

        self.assertEqual(
            client.get_vulnerability_solutions(
                "vuln/id"
            ),
            [
                solution,
            ],
        )

        self.assertEqual(
            client.get_vulnerability_solutions(
                "other"
            ),
            [
                solution,
            ],
        )

        self.assertEqual(
            http.request_json.call_count,
            3,
        )

        self.assertEqual(
            http.request_json.call_args_list[
                0
            ].args,
            (
                "GET",
                (
                    "https://console:3780/api/3/"
                    "vulnerabilities/"
                    "vuln%2Fid/solutions"
                ),
            ),
        )

        self.assertEqual(
            http.request_json.call_args_list[
                1
            ].args,
            (
                "GET",
                (
                    "https://console:3780/api/3/"
                    "solutions/fix%2Fid"
                ),
            ),
        )

    def test_solution_lookup_missing_resources_returns_empty_and_caches(
        self,
    ) -> None:
        http = Mock()

        http.request_json.return_value = {
            "links": [],
        }

        client = Rapid7SolutionClient(
            "https://console:3780",
            "user",
            "password",
            http,
        )

        self.assertEqual(
            client.get_vulnerability_solutions(
                "no-solution"
            ),
            [],
        )

        self.assertEqual(
            client.get_vulnerability_solutions(
                "no-solution"
            ),
            [],
        )

        self.assertEqual(
            http.request_json.call_count,
            1,
        )

        http.request_json.assert_called_once_with(
            "GET",
            (
                "https://console:3780/api/3/"
                "vulnerabilities/"
                "no-solution/solutions"
            ),
        )

    def test_vulnerability_detail_lookup_and_caching(
        self,
    ) -> None:
        http = Mock()

        http.request_json.return_value = {
            "id": "vuln/id",
            "severity": "Critical",
            "title": "Example vulnerability",
            "categories": [
                "Apache",
            ],
        }

        client = Rapid7SolutionClient(
            "https://console:3780",
            "user",
            "password",
            http,
        )

        expected = {
            "id": "vuln/id",
            "severity": "Critical",
            "title": "Example vulnerability",
            "categories": [
                "Apache",
            ],
        }

        self.assertEqual(
            client.get_vulnerability(
                "vuln/id"
            ),
            expected,
        )

        self.assertEqual(
            client.get_vulnerability(
                "vuln/id"
            ),
            expected,
        )

        http.request_json.assert_called_once_with(
            "GET",
            (
                "https://console:3780/api/3/"
                "vulnerabilities/vuln%2Fid"
            ),
            timeout=300,
        )

    def test_iter_vulnerabilities_filters_deduplicates_and_excludes_microsoft_patch(
        self,
    ) -> None:
        http = Mock()

        http.request_json.side_effect = [
            {
                "id": "critical",
                "severity": "Critical",
                "categories": [
                    "Apache",
                ],
            },
            {
                "id": "microsoft",
                "severity": "Severe",
                "categories": [
                    "Microsoft Patch",
                ],
            },
            {
                "id": "moderate",
                "severity": "Moderate",
                "categories": [
                    "Apache",
                ],
            },
        ]

        client = Rapid7SolutionClient(
            "https://console:3780",
            "user",
            "password",
            http,
        )

        results = list(
            client.iter_vulnerabilities(
                [
                    "moderate",
                    "critical",
                    "critical",
                    "microsoft",
                ]
            )
        )

        self.assertEqual(
            [
                result["id"]
                for result in results
            ],
            [
                "critical",
            ],
        )

        # The duplicate critical ID is requested only once.
        self.assertEqual(
            http.request_json.call_count,
            3,
        )

        requested_urls = {
            call.args[1]
            for call in (
                http.request_json.call_args_list
            )
        }

        self.assertEqual(
            requested_urls,
            {
                (
                    "https://console:3780/api/3/"
                    "vulnerabilities/critical"
                ),
                (
                    "https://console:3780/api/3/"
                    "vulnerabilities/microsoft"
                ),
                (
                    "https://console:3780/api/3/"
                    "vulnerabilities/moderate"
                ),
            },
        )

    def test_asset_vulnerability_proof_uses_v3_detail_endpoint_and_caches(
        self,
    ) -> None:
        http = Mock()

        http.request_json.return_value = {
            "results": [
                {
                    "checkId": "check-1",
                    "status": "vulnerable-version",
                    "proof": "<p>Version 1</p>",
                },
                {
                    "checkId": "check-2",
                    "status": "not-vulnerable",
                    "proof": "Not vulnerable",
                },
            ],
        }

        client = Rapid7SolutionClient(
            "https://console:3780",
            "user",
            "password",
            http,
        )

        proof = (
            client.get_asset_vulnerability_proof(
                "asset/id",
                "vuln/id",
            )
        )

        self.assertEqual(
            proof,
            [
                {
                    "check_id": "check-1",
                    "status": "vulnerable-version",
                    "proof": "<p>Version 1</p>",
                }
            ],
        )

        self.assertEqual(
            client.get_asset_vulnerability_proof(
                "asset/id",
                "vuln/id",
            ),
            proof,
        )

        http.request_json.assert_called_once_with(
            "GET",
            (
                "https://console:3780/api/3/"
                "assets/asset%2Fid/"
                "vulnerabilities/vuln%2Fid"
            ),
        )

    def test_console_url_and_auth(
        self,
    ) -> None:
        for url in [
            "http://console",
            "https://user:pass@console",
            "https://console/path",
            "https://console?x=1",
        ]:
            with self.assertRaises(
                ValueError
            ):
                Rapid7SolutionClient(
                    url,
                    "user",
                    "password",
                )

        client = Rapid7SolutionClient(
            "https://console:3780",
            "user",
            "password",
        )

        self.assertEqual(
            client.http.headers[
                "Authorization"
            ],
            "Basic dXNlcjpwYXNzd29yZA==",
        )

        self.assertNotIn(
            "X-Api-Key",
            client.http.headers,
        )

    def test_transform_uses_multiple_solution_records_and_catalog_fallback(
        self,
    ) -> None:
        catalog = build_catalog(
            [
                {
                    "id": "v",
                    "severity": "Severe",
                    "name": "Apache",
                    "solution": "old",
                }
            ]
        )

        assets = [
            {
                "host_name": host,
                "new": [
                    {
                        "vulnerability_id": "v",
                    }
                ],
            }
            for host in [
                "a",
                "b",
            ]
        ]

        lookup = Mock(
            return_value=[
                {
                    "summary": {
                        "text": "Upgrade",
                    },
                    "steps": {
                        "text": "Install 2",
                    },
                },
                {
                    "summary": {
                        "text": "Configure",
                    },
                    "steps": {
                        "text": "Disable feature",
                    },
                },
            ]
        )

        findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=lookup,
        )

        self.assertEqual(
            [
                (
                    finding.hosts,
                    finding.solution,
                    finding.fix_details,
                )
                for finding in findings
            ],
            [
                (
                    (
                        "a",
                        "b",
                    ),
                    "Configure",
                    "Disable feature",
                ),
                (
                    (
                        "a",
                        "b",
                    ),
                    "Upgrade",
                    "Install 2",
                ),
            ],
        )

        fallback_findings, _ = transform_assets(
            assets,
            catalog,
            solution_lookup=(
                lambda _vulnerability_id: []
            ),
        )

        self.assertEqual(
            len(fallback_findings),
            1,
        )

        self.assertEqual(
            fallback_findings[
                0
            ].hosts,
            (
                "a",
                "b",
            ),
        )

        self.assertEqual(
            fallback_findings[
                0
            ].solution_id,
            "",
        )

        self.assertEqual(
            fallback_findings[
                0
            ].solution,
            "old",
        )

        self.assertEqual(
            fallback_findings[
                0
            ].fix_details,
            "",
        )

        lookup.side_effect = RuntimeError(
            "API failure"
        )

        with self.assertRaises(
            RuntimeError
        ):
            transform_assets(
                assets,
                catalog,
                solution_lookup=lookup,
            )


if __name__ == "__main__":
    unittest.main()