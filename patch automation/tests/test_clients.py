import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from rapid7_freshservice_sync.freshservice import (
    FreshserviceClient,
    _ticket_description,
    finding_tag,
)
from rapid7_freshservice_sync.http import (
    ApiError,
    HttpClient,
)
from rapid7_freshservice_sync.models import Finding
from rapid7_freshservice_sync.rapid7 import Rapid7Client


class ClientTests(unittest.TestCase):
    def test_console_assets_pagination_membership_and_active_findings(
        self,
    ) -> None:
        recent_scan_date = datetime.now(
            timezone.utc
        ).isoformat()
        stale_scan_date = (
            datetime.now(
                timezone.utc
            )
            - timedelta(
                days=8
            )
        ).isoformat()

        def page(
            resources,
            total=1,
        ):
            return {
                "resources": resources,
                "page": {
                    "totalPages": total,
                },
            }

        http = Mock()

        http.request_json.side_effect = [
            # /asset_groups page 0
            page(
                [
                    {
                        "id": 1,
                        "name": (
                            "other workstations/laptops"
                        ),
                    }
                ],
                2,
            ),

            # /asset_groups page 1
            page(
                [
                    {
                        "id": 2,
                        "name": (
                            "workstations/laptops"
                        ),
                    }
                ],
                2,
            ),

            # /asset_groups/2/assets
            {
                "resources": [
                    10,
                    20,
                    30,
                ]
            },

            # /assets/search page 0
            page(
                [
                    {
                        "id": 99,
                    },
                    {
                        "id": 10,
                        "hostName": "host-a",
                        "ip": "10.0.0.1",
                        "lastScanDate": recent_scan_date,
                    },
                    {
                        "id": 30,
                        "hostName": "stale-host",
                        "lastScanDate": stale_scan_date,
                    },
                ],
                2,
            ),

            # /assets/search page 1
            page(
                [
                    {
                        "id": 20,
                        "ip": "10.0.0.2",
                        "lastScanDate": recent_scan_date,
                    }
                ],
                2,
            ),

            # Asset 10 vulnerabilities page 0
            page(
                [
                    {
                        "id": "v1",
                        "status": "vulnerable",
                    }
                ],
                2,
            ),

            # Asset 10 vulnerabilities page 1
            page(
                [
                    {
                        "id": "v2",
                        "status": "invulnerable",
                    },
                    {
                        "id": "v3",
                        "status": "no-results",
                    },
                ],
                2,
            ),

            # Asset 20 vulnerabilities
            page(
                [
                    {
                        "id": "v4",
                        "status": "vulnerable",
                    }
                ]
            ),
        ]

        client = Rapid7Client(
            "https://console.example:3780",
            "user",
            "password",
            http=http,
            page_size=100,
        )

        assets = list(
            client.iter_affected_assets()
        )

        self.assertEqual(
            assets,
            [
                {
                    "id": 10,
                    "host_name": "host-a",
                    "ip": "10.0.0.1",
                    "new": [
                        {
                            "vulnerability_id": "v1",
                        }
                    ],
                },
                {
                    "id": 20,
                    "host_name": "",
                    "ip": "10.0.0.2",
                    "new": [
                        {
                            "vulnerability_id": "v4",
                        }
                    ],
                },
            ],
        )

        calls = (
            http.request_json.call_args_list
        )

        self.assertEqual(
            len(
                calls
            ),
            8,
        )

        # ---------------------------------------------
        # Asset-group page 0
        # ---------------------------------------------
        self.assertEqual(
            calls[
                0
            ].args,
            (
                "GET",
                (
                    "https://console.example:3780/"
                    "api/3/asset_groups"
                ),
            ),
        )

        self.assertEqual(
            calls[
                0
            ].kwargs[
                "params"
            ][
                "page"
            ],
            0,
        )

        self.assertEqual(
            calls[
                0
            ].kwargs[
                "params"
            ][
                "size"
            ],
            100,
        )

        self.assertEqual(
            calls[
                0
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertNotIn(
            "retries",
            calls[
                0
            ].kwargs,
        )

        # ---------------------------------------------
        # Asset-group page 1
        # ---------------------------------------------
        self.assertEqual(
            calls[
                1
            ].kwargs[
                "params"
            ][
                "page"
            ],
            1,
        )

        self.assertEqual(
            calls[
                1
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertNotIn(
            "retries",
            calls[
                1
            ].kwargs,
        )

        # ---------------------------------------------
        # Exact asset-group membership request
        # ---------------------------------------------
        self.assertEqual(
            calls[
                2
            ].args,
            (
                "GET",
                (
                    "https://console.example:3780/"
                    "api/3/asset_groups/2/assets"
                ),
            ),
        )

        self.assertEqual(
            calls[
                2
            ].kwargs,
            {
                "timeout": 300,
            },
        )

        # ---------------------------------------------
        # Recent-asset search page 0
        # ---------------------------------------------
        self.assertEqual(
            calls[
                3
            ].args,
            (
                "POST",
                (
                    "https://console.example:3780/"
                    "api/3/assets/search"
                ),
            ),
        )

        self.assertEqual(
            calls[
                3
            ].kwargs[
                "json_body"
            ],
            {
                "match": "all",
                "filters": [
                    {
                        "field":
                            "last-scan-date",
                        "operator":
                            "is-within-the-last",
                        "value":
                            7,
                    }
                ],
            },
        )

        self.assertEqual(
            calls[
                3
            ].kwargs[
                "params"
            ],
            {
                "page": 0,
                "size": 100,
            },
        )

        self.assertEqual(
            calls[
                3
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertEqual(
            calls[
                3
            ].kwargs[
                "retries"
            ],
            2,
        )

        # ---------------------------------------------
        # Recent-asset search page 1
        # ---------------------------------------------
        self.assertEqual(
            calls[
                4
            ].args,
            (
                "POST",
                (
                    "https://console.example:3780/"
                    "api/3/assets/search"
                ),
            ),
        )

        self.assertEqual(
            calls[
                4
            ].kwargs[
                "params"
            ],
            {
                "page": 1,
                "size": 100,
            },
        )

        self.assertEqual(
            calls[
                4
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertEqual(
            calls[
                4
            ].kwargs[
                "retries"
            ],
            2,
        )

        self.assertEqual(
            calls[
                4
            ].kwargs[
                "json_body"
            ],
            {
                "match": "all",
                "filters": [
                    {
                        "field":
                            "last-scan-date",
                        "operator":
                            "is-within-the-last",
                        "value":
                            7,
                    }
                ],
            },
        )

        # ---------------------------------------------
        # Asset 10 vulnerability page 0
        # ---------------------------------------------
        self.assertEqual(
            calls[
                5
            ].args,
            (
                "GET",
                (
                    "https://console.example:3780/api/3/"
                    "assets/10/vulnerabilities"
                ),
            ),
        )

        self.assertEqual(
            calls[
                5
            ].kwargs[
                "params"
            ],
            {
                "page": 0,
                "size": 100,
            },
        )

        self.assertEqual(
            calls[
                5
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertNotIn(
            "retries",
            calls[
                5
            ].kwargs,
        )

        # ---------------------------------------------
        # Asset 10 vulnerability page 1
        # ---------------------------------------------
        self.assertEqual(
            calls[
                6
            ].args,
            (
                "GET",
                (
                    "https://console.example:3780/api/3/"
                    "assets/10/vulnerabilities"
                ),
            ),
        )

        self.assertEqual(
            calls[
                6
            ].kwargs[
                "params"
            ],
            {
                "page": 1,
                "size": 100,
            },
        )

        self.assertEqual(
            calls[
                6
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertNotIn(
            "retries",
            calls[
                6
            ].kwargs,
        )

        # ---------------------------------------------
        # Asset 20 vulnerability page
        # ---------------------------------------------
        self.assertEqual(
            calls[
                7
            ].args,
            (
                "GET",
                (
                    "https://console.example:3780/api/3/"
                    "assets/20/vulnerabilities"
                ),
            ),
        )

        self.assertEqual(
            calls[
                7
            ].kwargs[
                "params"
            ],
            {
                "page": 0,
                "size": 100,
            },
        )

        self.assertEqual(
            calls[
                7
            ].kwargs[
                "timeout"
            ],
            300,
        )

        self.assertNotIn(
            "retries",
            calls[
                7
            ].kwargs,
        )

    def test_console_catalog_filters_severity_and_category(
        self,
    ) -> None:
        http = Mock()

        http.request_json.side_effect = [
            {
                "resources": [
                    {
                        "id": "a",
                        "severity": "Critical",
                    },
                    {
                        "id": "b",
                        "severity": "Moderate",
                    },
                ],
                "page": {
                    "totalPages": 2,
                },
            },
            {
                "resources": [
                    {
                        "id": "c",
                        "severity": "Severe",
                        "categories": [
                            "Microsoft Patch",
                        ],
                    },
                    {
                        "id": "d",
                        "severity": "Severe",
                        "categories": [
                            "Apache",
                        ],
                    },
                ],
                "page": {
                    "totalPages": 2,
                },
            },
        ]

        client = Rapid7Client(
            "https://console:3780",
            "user",
            "password",
            http=http,
        )

        vulnerabilities = list(
            client.iter_vulnerability_catalog()
        )

        self.assertEqual(
            [
                vulnerability[
                    "id"
                ]
                for vulnerability
                in vulnerabilities
            ],
            [
                "a",
                "d",
            ],
        )

        self.assertEqual(
            http.request_json.call_count,
            2,
        )

        calls = (
            http.request_json.call_args_list
        )

        self.assertEqual(
            calls[
                0
            ].kwargs[
                "params"
            ][
                "page"
            ],
            0,
        )

        self.assertEqual(
            calls[
                1
            ].kwargs[
                "params"
            ][
                "page"
            ],
            1,
        )

        for call in calls:
            self.assertEqual(
                call.kwargs[
                    "timeout"
                ],
                300,
            )

            self.assertNotIn(
                "retries",
                call.kwargs,
            )

    def test_missing_group_fails_without_broadening_scope(
        self,
    ) -> None:
        http = Mock()

        http.request_json.return_value = {
            "resources": [],
            "page": {
                "totalPages": 0,
            },
        }

        client = Rapid7Client(
            "https://console:3780",
            "user",
            "password",
            http=http,
        )

        with self.assertRaisesRegex(
            ValueError,
            "exactly one",
        ):
            list(
                client.iter_affected_assets()
            )

        self.assertEqual(
            http.request_json.call_count,
            1,
        )

    def test_empty_group_has_no_assets(
        self,
    ) -> None:
        http = Mock()

        http.request_json.side_effect = [
            {
                "resources": [
                    {
                        "id": 2,
                        "name":
                            "workstations/laptops",
                    }
                ],
                "page": {
                    "totalPages": 1,
                },
            },
            {
                "resources": [],
            },
        ]

        client = Rapid7Client(
            "https://console:3780",
            "user",
            "password",
            http=http,
        )

        self.assertEqual(
            list(
                client.iter_affected_assets()
            ),
            [],
        )

        self.assertEqual(
            http.request_json.call_count,
            2,
        )

        self.assertEqual(
            http.request_json.call_args_list[
                1
            ].kwargs,
            {
                "timeout": 300,
            },
        )

    def test_freshservice_creates_tagged_ticket_when_no_open_duplicate_exists(
        self,
    ) -> None:
        http = Mock()

        http.request_json.side_effect = [
            {
                "tickets": [],
                "total": 0,
            },
            {
                "tickets": [],
                "total": 0,
            },
            {
                "ticket": {
                    "id": 123,
                }
            },
        ]

        client = FreshserviceClient(
            "https://alterna.freshservice.com",
            "api-key",
            "security@example.com",
            workspace_id=2,
            group_id=11000367285,
            http=http,
        )

        finding = Finding(
            (
                "host.example.com",
            ),
            "Upgrade",
            "Install 2.0",
        )

        result = (
            client.create_ticket_if_missing(
                finding
            )
        )

        self.assertEqual(
            result[
                "id"
            ],
            123,
        )

        calls = (
            http.request_json.call_args_list
        )

        expected_tag = finding_tag(
            finding
        )

        self.assertEqual(
            len(
                calls
            ),
            3,
        )

        self.assertEqual(
            calls[
                0
            ].args,
            (
                "GET",
                (
                    "https://alterna.freshservice.com/"
                    "api/v2/tickets/filter"
                ),
            ),
        )

        self.assertEqual(
            calls[
                0
            ].kwargs[
                "params"
            ],
            {
                "workspace_id": 2,
                "query": (
                    f"\"tag:'{expected_tag}' "
                    "AND status:2\""
                ),
            },
        )

        self.assertEqual(
            calls[
                1
            ].kwargs[
                "params"
            ],
            {
                "workspace_id": 2,
                "query": (
                    f"\"tag:'{expected_tag}' "
                    "AND status:3\""
                ),
            },
        )

        self.assertEqual(
            calls[
                2
            ].args,
            (
                "POST",
                (
                    "https://alterna.freshservice.com/"
                    "api/v2/tickets"
                ),
            ),
        )

        payload = calls[
            2
        ].kwargs[
            "json_body"
        ]

        self.assertEqual(
            payload[
                "email"
            ],
            "security@example.com",
        )

        self.assertEqual(
            payload[
                "subject"
            ],
            "Upgrade",
        )

        self.assertEqual(
            payload[
                "workspace_id"
            ],
            2,
        )

        self.assertEqual(
            payload[
                "group_id"
            ],
            11000367285,
        )

        self.assertEqual(
            payload[
                "status"
            ],
            2,
        )

        self.assertEqual(
            payload[
                "priority"
            ],
            2,
        )

        self.assertNotIn(
            "urgency",
            payload,
        )

        self.assertNotIn(
            "impact",
            payload,
        )

        self.assertEqual(
            payload[
                "category"
            ],
            "Digital Security",
        )

        self.assertEqual(
            payload[
                "sub_category"
            ],
            "Vulnerability Management",
        )

        self.assertIn(
            "rapid7-insightvm",
            payload[
                "tags"
            ],
        )

        self.assertIn(
            expected_tag,
            payload[
                "tags"
            ],
        )

        self.assertFalse(
            calls[
                2
            ].kwargs[
                "retryable"
            ]
        )

    def test_freshservice_skips_matching_open_ticket(
        self,
    ) -> None:
        http = Mock()

        http.request_json.return_value = {
            "tickets": [
                {
                    "id": 456,
                    "status": 2,
                }
            ],
            "total": 1,
        }

        client = FreshserviceClient(
            "https://alterna.freshservice.com",
            "api-key",
            "security@example.com",
            workspace_id=2,
            group_id=11000367285,
            http=http,
        )

        finding = Finding(
            (
                "host.example.com",
            ),
            "Upgrade",
            "Install 2.0",
        )

        result = (
            client.create_ticket_if_missing(
                finding
            )
        )

        self.assertIsNone(
            result
        )

        self.assertEqual(
            http.request_json.call_count,
            1,
        )

        self.assertEqual(
            http.request_json.call_args.kwargs[
                "params"
            ],
            {
                "workspace_id": 2,
                "query": (
                    f"\"tag:'{finding_tag(finding)}' "
                    "AND status:2\""
                ),
            },
        )

    def test_ticket_description_omits_proof_section_above_threshold(
        self,
    ) -> None:
        description = _ticket_description(
            Finding(
                (
                    "host.example.com",
                ),
                "Upgrade",
                "Install 2.0",
                vulnerability_count=6,
                proof_note=(
                    "Proof lookup skipped: over limit."
                ),
            )
        )

        self.assertIn(
            "<h2>Rapid7 Remediation Details</h2>",
            description,
        )

        self.assertIn(
            "host.example.com",
            description,
        )

        self.assertNotIn(
            "<h2>Rapid7 Proof by Asset</h2>",
            description,
        )

    def test_freshservice_configuration_is_validated(
        self,
    ) -> None:
        client = FreshserviceClient(
            "https://alterna.freshservice.com",
            "api-key",
            "security@example.com",
            workspace_id=2,
            group_id=11000367285,
        )

        self.assertEqual(
            client.base_url,
            (
                "https://alterna.freshservice.com/"
                "api/v2"
            ),
        )

        self.assertEqual(
            client.workspace_id,
            2,
        )

        self.assertEqual(
            client.group_id,
            11000367285,
        )

        for invalid_workspace_id in (
            0,
            -1,
            True,
        ):
            with (
                self.subTest(
                    workspace_id=invalid_workspace_id
                ),
                self.assertRaises(
                    ValueError
                ),
            ):
                FreshserviceClient(
                    "https://alterna.freshservice.com",
                    "api-key",
                    "security@example.com",
                    workspace_id=invalid_workspace_id,
                    group_id=11000367285,
                )

        for invalid_group_id in (
            0,
            -1,
            True,
        ):
            with (
                self.subTest(
                    group_id=invalid_group_id
                ),
                self.assertRaises(
                    ValueError
                ),
            ):
                FreshserviceClient(
                    "https://alterna.freshservice.com",
                    "api-key",
                    "security@example.com",
                    workspace_id=2,
                    group_id=invalid_group_id,
                )

        invalid_domains = (
            "http://alterna.freshservice.com",
            (
                "https://alterna.freshservice.com"
                ".evil.test"
            ),
            "https://custom.example.com",
            "https://support.alterna.ca",
            (
                "https://alterna.freshservice.com/"
                "api/v2"
            ),
        )

        for domain in invalid_domains:
            with (
                self.subTest(
                    domain=domain
                ),
                self.assertRaises(
                    ValueError
                ),
            ):
                FreshserviceClient(
                    domain,
                    "api-key",
                    "security@example.com",
                    workspace_id=2,
                    group_id=11000367285,
                )

    def test_http_client_rejects_unexpected_urls(
        self,
    ) -> None:
        http = HttpClient(
            allowed_hosts={
                "api.example.com",
            }
        )

        with self.assertRaises(
            ApiError
        ):
            http.request_json(
                "GET",
                "http://api.example.com/test",
            )

        with self.assertRaises(
            ApiError
        ):
            http.request_json(
                "GET",
                "https://evil.example.com/test",
            )


if __name__ == "__main__":
    unittest.main()
