import csv
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapid7_freshservice_sync.cli import main


class ConsoleExportTests(unittest.TestCase):
    def test_export_uses_scoped_vulnerability_details_and_creates_ticket(
        self,
    ) -> None:
        rapid7_origin = (
            "https://security-console.example:3780/api/3"
        )

        freshservice_origin = (
            "https://alterna.freshservice.com/api/v2"
        )

        def page(records):
            return {
                "resources": records,
                "page": {
                    "totalPages": 1,
                },
            }

        responses = {
            (
                "GET",
                "/asset_groups",
            ): page(
                [
                    {
                        "id": 8,
                        "name": "workstations/laptops",
                    }
                ]
            ),

            (
                "GET",
                "/asset_groups/8/assets",
            ): {
                "resources": [
                    42,
                ]
            },

            (
                "POST",
                "/assets/search",
            ): page(
                [
                    {
                        "id": 42,
                        "hostName": "laptop.example",
                        "ip": "192.0.2.10",
                    }
                ]
            ),

            (
                "GET",
                "/assets/42/vulnerabilities",
            ): page(
                [
                    {
                        "id": "apache-vuln",
                        "status": "vulnerable",
                    },
                    {
                        "id": "moderate",
                        "status": "vulnerable",
                    },
                    {
                        "id": "ms",
                        "status": "vulnerable",
                    },
                    {
                        "id": "exception",
                        "status": "invulnerable",
                    },
                ]
            ),

            (
                "GET",
                "/vulnerabilities/apache-vuln",
            ): {
                "id": "apache-vuln",
                "title": "Apache vulnerability",
                "severity": "Critical",
                "categories": [
                    "Apache",
                ],
                "solution": "Upgrade Apache",
                "fix": "Install latest release",
            },

            (
                "GET",
                "/vulnerabilities/moderate",
            ): {
                "id": "moderate",
                "title": "Apache issue",
                "severity": "Moderate",
                "categories": [
                    "Apache",
                ],
                "solution": "Upgrade Apache",
                "fix": "Install latest release",
            },

            (
                "GET",
                "/vulnerabilities/ms",
            ): {
                "id": "ms",
                "title": "Microsoft vulnerability",
                "severity": "Severe",
                "categories": [
                    "Microsoft Patch",
                ],
                "solution": "Install Microsoft update",
                "fix": "Install the applicable patch",
            },

            (
                "GET",
                "/vulnerabilities/apache-vuln/solutions",
            ): {
                "resources": [
                    "apache-upgrade",
                    "apache-configure",
                ],
            },

            (
                "GET",
                "/solutions/apache-upgrade",
            ): {
                "summary": {
                    "text": "Upgrade Apache",
                },
                "steps": {
                    "text": "Install latest release",
                },
            },

            (
                "GET",
                "/solutions/apache-configure",
            ): {
                "summary": {
                    "text": "Configure Apache",
                },
                "steps": {
                    "text": "Disable legacy module",
                },
            },

            (
                "GET",
                "/assets/42/vulnerabilities/apache-vuln",
            ): {
                "results": [
                    {
                        "checkId": "apache-check",
                        "status": "vulnerable-version",
                        "proof": (
                            "<p>Apache version 2.4.0</p>"
                        ),
                    }
                ]
            },

            (
                "POST",
                "/tickets",
            ): {
                "ticket": {
                    "id": 100,
                    "status": 2,
                }
            },
        }

        seen: list[
            tuple[str, str]
        ] = []

        filter_requests = 0
        ticket_bodies = []
        routing_requests = []

        def request(
            client,
            method,
            url,
            **kwargs,
        ):
            nonlocal filter_requests

            # -----------------------------
            # Rapid7 requests
            # -----------------------------
            if url.startswith(
                rapid7_origin + "/"
            ):
                self.assertEqual(
                    client.headers[
                        "Authorization"
                    ],
                    "Basic dXNlcjpwYXNzd29yZA==",
                )

                self.assertNotIn(
                    "X-Api-Key",
                    client.headers,
                )

                key = (
                    method,
                    url[
                        len(
                            rapid7_origin
                        ):
                    ].split("?")[0],
                )

                seen.append(
                    key
                )

                self.assertIn(
                    key,
                    responses,
                    f"Unexpected Rapid7 request: {key}",
                )

                return responses[key]

            # -----------------------------
            # Freshservice requests
            # -----------------------------
            self.assertTrue(
                url.startswith(
                    freshservice_origin + "/"
                ),
                url,
            )

            self.assertEqual(
                client.headers[
                    "Authorization"
                ],
                "Basic ZnJlc2gta2V5Olg=",
            )

            key = (
                method,
                url[
                    len(
                        freshservice_origin
                    ):
                ].split("?")[0],
            )

            # -----------------------------
            # Duplicate-ticket lookup
            # -----------------------------
            if key == (
                "GET",
                "/tickets/filter",
            ):
                filter_requests += 1

                params = kwargs[
                    "params"
                ]

                self.assertEqual(
                    params[
                        "workspace_id"
                    ],
                    0,
                )

                query = params[
                    "query"
                ]

                # Freshservice requires the entire filter expression
                # to be wrapped in double quotes.
                self.assertTrue(
                    query.startswith(
                        "\"tag:'rapid7-remediation-"
                    ),
                    query,
                )

                self.assertTrue(
                    query.endswith(
                        "\""
                    ),
                    query,
                )

                self.assertIn(
                    " AND status:",
                    query,
                )

                status = (
                    2
                    if filter_requests % 2 == 1
                    else 3
                )

                self.assertTrue(
                    query.endswith(
                        f"AND status:{status}\""
                    ),
                    query,
                )

                return {
                    "tickets": [],
                    "total": 0,
                }

            # -----------------------------
            # Workspace lookup
            # -----------------------------
            if key == (
                "GET",
                "/workspaces",
            ):
                routing_requests.append(
                    key
                )

                return {
                    "workspaces": [
                        {
                            "id": 42,
                            "name": (
                                "IT, Banking Support & "
                                "Marketing"
                            ),
                        }
                    ]
                }

            # -----------------------------
            # Service Desk group lookup
            # -----------------------------
            if key == (
                "GET",
                "/groups",
            ):
                self.assertEqual(
                    kwargs[
                        "params"
                    ][
                        "workspace_id"
                    ],
                    42,
                )

                routing_requests.append(
                    key
                )

                return {
                    "groups": [
                        {
                            "id": 84,
                            "name": "Service Desk",
                        }
                    ]
                }

            # -----------------------------
            # Ticket creation
            # -----------------------------
            if key == (
                "POST",
                "/tickets",
            ):
                seen.append(
                    key
                )

                payload = kwargs[
                    "json_body"
                ]

                self.assertEqual(
                    payload[
                        "email"
                    ],
                    "security@example.com",
                )

                self.assertNotIn("status", payload)
                self.assertNotIn("urgency", payload)
                self.assertNotIn("impact", payload)
                self.assertNotIn("priority", payload)

                self.assertEqual(
                    payload[
                        "workspace_id"
                    ],
                    42,
                )

                self.assertEqual(
                    payload[
                        "group_id"
                    ],
                    84,
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

                self.assertTrue(
                    any(
                        tag.startswith(
                            "rapid7-remediation-"
                        )
                        for tag
                        in payload[
                            "tags"
                        ]
                    )
                )

                description = payload[
                    "description"
                ]

                self.assertIn(
                    (
                        "<h2>"
                        "Rapid7 Remediation Details"
                        "</h2>"
                    ),
                    description,
                )

                self.assertIn(
                    (
                        "<th>Asset ID</th>"
                        "<th>Hostname</th>"
                    ),
                    description,
                )

                self.assertIn(
                    "laptop.example",
                    description,
                )

                self.assertIn(
                    "192.0.2.10",
                    description,
                )

                self.assertIn(
                    payload[
                        "subject"
                    ],
                    description,
                )

                self.assertIn(
                    (
                        "<h2>"
                        "Rapid7 Proof by Asset"
                        "</h2>"
                    ),
                    description,
                )

                # Rapid7 proof is intentionally HTML-escaped
                # inside a <pre> block.
                self.assertIn(
                    (
                        "<pre>"
                        "&lt;p&gt;"
                        "Apache version 2.4.0"
                        "&lt;/p&gt;"
                        "</pre>"
                    ),
                    description,
                )

                ticket_bodies.append(
                    payload
                )

                return responses[
                    key
                ]

            self.fail(
                "Unexpected Freshservice request: "
                f"{method} {url}"
            )

        with tempfile.TemporaryDirectory() as directory:
            output = (
                Path(directory)
                / "export.csv"
            )

            with (
                patch.dict(
                    os.environ,
                    {
                        "RAPID7_CONSOLE_URL": (
                            rapid7_origin.removesuffix(
                                "/api/3"
                            )
                        ),
                        "RAPID7_CONSOLE_USERNAME": (
                            "user"
                        ),
                        "RAPID7_CONSOLE_PASSWORD": (
                            "password"
                        ),
                        "FRESHSERVICE_DOMAIN": (
                            "https://alterna.freshservice.com"
                        ),
                        "FRESHSERVICE_API_KEY": (
                            "fresh-key"
                        ),
                        "FRESHSERVICE_REQUESTER_EMAIL": (
                            "security@example.com"
                        ),
                    },
                    clear=True,
                ),
                patch(
                    "sys.argv",
                    [
                        "sync",
                        "--output",
                        str(
                            output
                        ),
                        "--create-tickets",
                    ],
                ),
                patch(
                    (
                        "rapid7_freshservice_sync.http."
                        "HttpClient.request_json"
                    ),
                    new=request,
                ),
            ):
                main()

            # -----------------------------
            # Generated CSV
            # -----------------------------
            with output.open(
                newline="",
                encoding="utf-8",
            ) as file:
                self.assertEqual(
                    list(
                        csv.reader(
                            file
                        )
                    ),
                    [
                        [
                            "Hosts",
                            "Solution",
                            "Fix details",
                            "Proof information",
                        ],
                        [
                            "laptop.example",
                            "Configure Apache",
                            "Disable legacy module",
                            (
                                "Asset: laptop.example "
                                "(ID 42); "
                                "Vulnerability: apache-vuln; "
                                "Check: apache-check; "
                                "Status: vulnerable-version; "
                                "Proof: "
                                "<p>Apache version 2.4.0</p>"
                            ),
                        ],
                        [
                            "laptop.example",
                            "Upgrade Apache",
                            "Install latest release",
                            (
                                "Asset: laptop.example "
                                "(ID 42); "
                                "Vulnerability: apache-vuln; "
                                "Check: apache-check; "
                                "Status: vulnerable-version; "
                                "Proof: "
                                "<p>Apache version 2.4.0</p>"
                            ),
                        ],
                    ],
                )

        # -------------------------------------------------
        # Catalog optimization regression check
        # -------------------------------------------------

        # The optimized path must never download the full
        # paginated vulnerability catalog.
        self.assertNotIn(
            (
                "GET",
                "/vulnerabilities",
            ),
            seen,
        )

        # Moderate vulnerability details are retrieved so they
        # can be classified, but the vulnerability must not
        # proceed to solution lookup.
        self.assertNotIn(
            (
                "GET",
                "/vulnerabilities/moderate/solutions",
            ),
            seen,
        )

        # Microsoft Patch findings must also stop before
        # solution lookup.
        self.assertNotIn(
            (
                "GET",
                "/vulnerabilities/ms/solutions",
            ),
            seen,
        )

        expected_rapid7_requests = {
            (
                "GET",
                "/asset_groups",
            ),
            (
                "GET",
                "/asset_groups/8/assets",
            ),
            (
                "POST",
                "/assets/search",
            ),
            (
                "GET",
                "/assets/42/vulnerabilities",
            ),
            (
                "GET",
                "/vulnerabilities/apache-vuln",
            ),
            (
                "GET",
                "/vulnerabilities/moderate",
            ),
            (
                "GET",
                "/vulnerabilities/ms",
            ),
            (
                "GET",
                "/vulnerabilities/apache-vuln/solutions",
            ),
            (
                "GET",
                "/solutions/apache-upgrade",
            ),
            (
                "GET",
                "/solutions/apache-configure",
            ),
            (
                "GET",
                "/assets/42/vulnerabilities/apache-vuln",
            ),
        }

        actual_rapid7_requests = {
            key
            for key in seen
            if key
            != (
                "POST",
                "/tickets",
            )
        }

        self.assertEqual(
            actual_rapid7_requests,
            expected_rapid7_requests,
        )

        # Two findings, each checked against Open and Pending
        # Freshservice statuses.
        self.assertEqual(
            filter_requests,
            4,
        )

        # Two Rapid7 solutions should produce two ticket requests.
        self.assertEqual(
            len(
                ticket_bodies
            ),
            2,
        )

        self.assertEqual(
            {
                body[
                    "subject"
                ]
                for body
                in ticket_bodies
            },
            {
                "Configure Apache",
                "Upgrade Apache",
            },
        )

        # The two Rapid7 solutions have different stable
        # deduplication tags.
        self.assertNotEqual(
            ticket_bodies[
                0
            ][
                "tags"
            ],
            ticket_bodies[
                1
            ][
                "tags"
            ],
        )

        # Workspace and group are cached after the first lookup,
        # so these should occur only once despite two tickets.
        self.assertEqual(
            routing_requests,
            [
                (
                    "GET",
                    "/workspaces",
                ),
                (
                    "GET",
                    "/groups",
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()