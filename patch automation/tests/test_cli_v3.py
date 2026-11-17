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

        workspace_id = 2
        group_id = 11000367285

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
                "fix": "Install applicable patch",
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
        }

        rapid7_requests = []
        freshservice_requests = []
        filter_requests = []
        ticket_bodies = []

        def request(
            client,
            method,
            url,
            **kwargs,
        ):
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

                rapid7_requests.append(
                    key
                )

                self.assertIn(
                    key,
                    responses,
                    f"Unexpected Rapid7 request: {key}",
                )

                return responses[key]

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

            freshservice_requests.append(
                key
            )

            if key == (
                "GET",
                "/tickets/filter",
            ):
                params = kwargs[
                    "params"
                ]

                self.assertEqual(
                    params[
                        "workspace_id"
                    ],
                    workspace_id,
                )

                query = params[
                    "query"
                ]

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

                self.assertTrue(
                    (
                        "AND status:2\""
                        in query
                    )
                    or (
                        "AND status:3\""
                        in query
                    ),
                    query,
                )

                filter_requests.append(
                    {
                        "workspace_id":
                            params[
                                "workspace_id"
                            ],
                        "query":
                            query,
                    }
                )

                return {
                    "tickets": [],
                    "total": 0,
                }

            if key == (
                "POST",
                "/tickets",
            ):
                payload = kwargs[
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
                        "workspace_id"
                    ],
                    workspace_id,
                )

                self.assertEqual(
                    payload[
                        "group_id"
                    ],
                    group_id,
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

                remediation_tags = [
                    tag
                    for tag in payload[
                        "tags"
                    ]
                    if tag.startswith(
                        "rapid7-remediation-"
                    )
                ]

                self.assertEqual(
                    len(
                        remediation_tags
                    ),
                    1,
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

                return {
                    "ticket": {
                        "id": (
                            100
                            + len(
                                ticket_bodies
                            )
                        ),
                    }
                }

            if key in {
                (
                    "GET",
                    "/workspaces",
                ),
                (
                    "GET",
                    "/groups",
                ),
            }:
                self.fail(
                    "Freshservice workspace/group "
                    "enumeration must not occur"
                )

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
                        "RAPID7_CONSOLE_USERNAME":
                            "user",
                        "RAPID7_CONSOLE_PASSWORD":
                            "password",
                        "FRESHSERVICE_DOMAIN": (
                            "https://alterna."
                            "freshservice.com"
                        ),
                        "FRESHSERVICE_API_KEY":
                            "fresh-key",
                        "FRESHSERVICE_REQUESTER_EMAIL":
                            "security@example.com",
                        "FRESHSERVICE_WORKSPACE_ID":
                            str(
                                workspace_id
                            ),
                        "FRESHSERVICE_GROUP_ID":
                            str(
                                group_id
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
                        "rapid7_freshservice_sync."
                        "http.HttpClient.request_json"
                    ),
                    new=request,
                ),
            ):
                main()

            with output.open(
                newline="",
                encoding="utf-8",
            ) as file:
                rows = list(
                    csv.reader(
                        file
                    )
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

        self.assertNotIn(
            (
                "GET",
                "/vulnerabilities",
            ),
            rapid7_requests,
        )

        self.assertNotIn(
            (
                "GET",
                "/vulnerabilities/moderate/solutions",
            ),
            rapid7_requests,
        )

        self.assertNotIn(
            (
                "GET",
                "/vulnerabilities/ms/solutions",
            ),
            rapid7_requests,
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
                (
                    "/vulnerabilities/"
                    "apache-vuln/solutions"
                ),
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
                (
                    "/assets/42/vulnerabilities/"
                    "apache-vuln"
                ),
            ),
        }

        self.assertEqual(
            set(
                rapid7_requests
            ),
            expected_rapid7_requests,
        )

        self.assertNotIn(
            (
                "GET",
                "/workspaces",
            ),
            freshservice_requests,
        )

        self.assertNotIn(
            (
                "GET",
                "/groups",
            ),
            freshservice_requests,
        )

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
                for body in ticket_bodies
            },
            {
                "Configure Apache",
                "Upgrade Apache",
            },
        )

        for body in ticket_bodies:
            self.assertEqual(
                body[
                    "workspace_id"
                ],
                2,
            )

            self.assertEqual(
                body[
                    "group_id"
                ],
                11000367285,
            )

            self.assertEqual(
                body[
                    "status"
                ],
                2,
            )

            self.assertEqual(
                body[
                    "priority"
                ],
                2,
            )

            self.assertNotIn(
                "urgency",
                body,
            )

            self.assertNotIn(
                "impact",
                body,
            )

        self.assertEqual(
            len(
                filter_requests
            ),
            4,
        )

        for request_info in filter_requests:
            self.assertEqual(
                request_info[
                    "workspace_id"
                ],
                2,
            )

        first_tags = set(
            ticket_bodies[
                0
            ][
                "tags"
            ]
        )

        second_tags = set(
            ticket_bodies[
                1
            ][
                "tags"
            ]
        )

        self.assertNotEqual(
            first_tags,
            second_tags,
        )


if __name__ == "__main__":
    unittest.main()