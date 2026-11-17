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


class FreshserviceClientTests(unittest.TestCase):
    def test_creates_ticket_using_configured_workspace_and_group(
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

        result = client.create_ticket_if_missing(
            finding
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
            len(calls),
            3,
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
                "workspace_id": 2,
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
                "workspace_id": 2,
                "query": (
                    f"\"tag:'{expected_tag}' "
                    "AND status:3\""
                ),
            },
        )

        self.assertEqual(
            calls[2].args,
            (
                "POST",
                (
                    "https://alterna.freshservice.com/"
                    "api/v2/tickets"
                ),
            ),
        )

        payload = calls[2].kwargs[
            "json_body"
        ]

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
            expected_tag,
            payload[
                "tags"
            ],
        )

        self.assertFalse(
            calls[2].kwargs[
                "retryable"
            ]
        )

    def test_skips_matching_open_ticket(
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

        self.assertIsNone(
            client.create_ticket_if_missing(
                finding
            )
        )

        self.assertEqual(
            http.request_json.call_count,
            1,
        )

    def test_ticket_description_omits_proof_above_threshold(
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

    def test_configuration_is_validated(
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