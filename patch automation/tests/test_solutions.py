import unittest
from unittest.mock import Mock

from rapid7_freshservice_sync.rapid7 import Rapid7SolutionClient
from rapid7_freshservice_sync.transform import (
    build_catalog,
    transform_assets,
)


class SolutionTests(unittest.TestCase):
    def test_solution_lookup_and_caching(self):
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
            [solution],
        )

        # Cached vulnerability -> solution mapping.
        self.assertEqual(
            client.get_vulnerability_solutions(
                "vuln/id"
            ),
            [solution],
        )

        # Different vulnerability, same solution ID.
        # The solution details themselves should already
        # be cached.
        self.assertEqual(
            client.get_vulnerability_solutions(
                "other"
            ),
            [solution],
        )

        self.assertEqual(
            http.request_json.call_count,
            3,
        )

        self.assertEqual(
            http.request_json.call_args_list[0].args,
            (
                "GET",
                "https://console:3780/api/3/"
                "vulnerabilities/vuln%2Fid/solutions",
            ),
        )

        self.assertEqual(
            http.request_json.call_args_list[1].args,
            (
                "GET",
                "https://console:3780/api/3/"
                "solutions/fix%2Fid",
            ),
        )

    def test_solution_lookup_missing_resources_returns_empty_and_caches(
        self,
    ):
        http = Mock()

        # Reproduces the production condition that previously
        # resulted in:
        #
        # KeyError: 'resources'
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

        # The empty result must also be cached so we do not
        # repeatedly call the Rapid7 endpoint for the same
        # vulnerability.
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
            "https://console:3780/api/3/"
            "vulnerabilities/no-solution/solutions",
        )

    def test_asset_vulnerability_proof_uses_v3_detail_endpoint_and_caches(
        self,
    ):
        http = Mock()