import unittest
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
            page(
                [
                    {
                        "id": 1,
                        "name":
                            "other workstations/laptops",
                    }
                ],
                2,
            ),
            page(
                [
                    {
                        "id": 2,
                        "name":
                            "workstations/laptops",
                    }
                ],
                2,
            ),
            {
                "resources": [
                    10,
                    20,
                ]
            },
            page(
                [
                    {
                        "id": 99,
                    },
                    {
                        "id": 10,
                        "hostName": "host-a",
                        "ip": "10.0.0.1",
                    },
                ],
                2,
            ),
            page(
                [
                    {
                        "id": "v1",
                        "status": "vulnerable",
                    }
                ],
                2,
            ),
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
            page(
                [
                    {
                        "id": 20,
                        "ip": "10.0.0.2",
                    }
                ],
                2,
            ),
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

        self.assertEqual(
            list(
                client.iter_affected_assets()
            ),
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

        calls = http.request_json.call_args_list

        self.assertTrue(
            all(
                call.args[1].startswith(
                    "https://console.example:3780/api/3/"
                )
                for call in calls
            )
        )

        self.assertEqual(
            calls[1].kwargs[
                "params"
            ][
                "page"
            ],
            1,
        )

        self.assertEqual(
            calls[2].args[1],
            (
                "https://console.example:3780/api/3/"
                "asset_groups/2/assets"
            ),
        )

        self.assertEqual(
            calls[3].args[0],
            "POST",
        )

        self.assertEqual(
            calls[3].kwargs[
                "json_body"
            ],
            {
                "match": "all",
                "filters": [
                    {
                        "field": "last-scan-date",
                        "operator":
                            "is-within-the-last",
                        "value": 7,
                    }
                ],
            },
        )

        self.assertEqual(
            calls[5].kwargs[
                "params"
            ][
                "page"
            ],
            1,
        )

        self.assertEqual(
            calls[6].kwargs[
                "params"
            ][
                "page"
            ],
            1,
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

        self.assertEqual(
            [
                vulnerability[
                    "id"
                ]
                for vulnerability
                in client.iter_vulnerability_catalog()
            ],
            [
                "a",
                "d",
            ],
        )

        self.assertEqual(
            http.request_json.call_args.args,
            (
                "GET",
                (
                    "https://console:3780/api/3/"
                    "vulnerabilities"
                ),
            ),
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
                "workspaces": [
                    {
                        "id": 7,
                        "name": (
                            "IT, Banking Support & "
                            "Marketing"
                        ),
                    }
                ]
            },
            {
                "groups": [
                    {
                        "id": 12,
                        "name": "Service Desk",
                    }
                ]
            },
            {
                "ticket": {
                    "id": 123,
                    "status": 2,
                }
            },
        ]

        client = FreshserviceClient(
            "https://alterna.freshservice.com",
            "api-key",
            "security@example.com",
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
            result["id"],
            123,
        )

        calls = (
            http.request_json.call_args_list
        )

        expected_tag = finding_tag(
            finding
        )

        self.assertEqual(
            calls[0].args,
            (
                "GET",
                (
                    "https://alterna.freshservice.com/"
                    "api/v2/tickets/filter"
                ),
            ),
        )

        self.assertEqual(
            calls[0].kwargs[
                "params"
            ],
            {
                "workspace_id": 0,
                "query": (
                    f"\"tag:'{expected_tag}' "
                    "AND status:2\""
                ),
            },
        )

        self.assertEqual(
            calls[1].kwargs[
                "params"
            ],
            {
                "workspace_id": 0,
                "query": (
                    f"\"tag:'{expected_tag}' "
                    "AND status:3\""
                ),
            },
        )

        self.assertEqual(
            calls[2].args,
            (
                "GET",
                (
                    "https://alterna.freshservice.com/"
                    "api/v2/workspaces"
                ),
            ),
        )

        self.assertEqual(
            calls[2].kwargs[
                "params"
            ],
            {
                "page": 1,
                "per_page": 100,
            },
        )

        self.assertEqual(
            calls[3].args,
            (
                "GET",
                (
                    "https://alterna.freshservice.com/"
                    "api/v2/groups"
                ),
            ),
        )

        self.assertEqual(
            calls[3].kwargs[
                "params"
            ],
            {
                "workspace_id": 7,
                "page": 1,
                "per_page": 100,
            },
        )

        payload = calls[4].kwargs[
            "json_body"
        ]

        self.assertEqual(
            payload["email"],
            "security@example.com",
        )

        self.assertEqual(
            payload["subject"],
            "Upgrade",
        )

        self.assertEqual(
            payload["status"],
            2,
        )

        self.assertEqual(
            payload["urgency"],
            2,
        )

        self.assertEqual(
            payload["impact"],
            2,
        )

        self.assertEqual(
            payload["priority"],
            2,
        )

        self.assertEqual(
            payload["workspace_id"],
            7,
        )

        self.assertEqual(
            payload["group_id"],
            12,
        )

        self.assertEqual(
            payload["category"],
            "Digital Security",
        )

        self.assertEqual(
            payload["sub_category"],
            "Vulnerability Management",
        )

        self.assertIn(
            expected_tag,
            payload["tags"],
        )

        self.assertFalse(
            calls[4].kwargs[
                "retryable"
            ]
        )

        self.assertEqual(
            client.http,
            http,
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
            http=http,
        )

        finding = Finding(
            (
                "host.example.com",
            ),
            "Upgrade",
            "Install 2.0",
        )

        self.assertIsNone(
            client.create_ticket_if_missing(
                finding
            )
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
                "workspace_id": 0,
                "query": (
                    f"\"tag:'{finding_tag(finding)}' "
                    "AND status:2\""
                ),
            },
        )

    def test_freshservice_requires_the_configured_workspace(
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
                "workspaces": [],
            },
        ]

        client = FreshserviceClient(
            "https://alterna.freshservice.com",
            "api-key",
            "security@example.com",
            http=http,
        )

        with self.assertRaisesRegex(
            ApiError,
            "workspace named",
        ):
            client.create_ticket_if_missing(
                Finding(
                    (
                        "host.example.com",
                    ),
                    "Upgrade",
                    "Install 2.0",
                )
            )

        self.assertEqual(
            http.request_json.call_count,
            3,
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

    def test_freshservice_domain_and_credentials_are_validated(
        self,
    ) -> None:
        valid_client = FreshserviceClient(
            "https://alterna.freshservice.com",
            "api-key",
            "security@example.com",
        )

        self.assertEqual(
            valid_client.base_url,
            (
                "https://alterna.freshservice.com/"
                "api/v2"
            ),
        )

        for domain in (
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
        ):
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
                )

        with self.assertRaises(
            ValueError
        ):
            FreshserviceClient(
                "https://alterna.freshservice.com",
                "",
                "security@example.com",
            )

        with self.assertRaises(
            ValueError
        ):
            FreshserviceClient(
                "https://alterna.freshservice.com",
                "api-key",
                "",
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