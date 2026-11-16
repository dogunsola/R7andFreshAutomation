import base64
import logging
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import quote, urlparse

from .http import HttpClient


LOG = logging.getLogger(__name__)


class Rapid7SolutionClient:
    """Security Console v3 client using HTTPS and Basic authentication."""

    def __init__(
        self,
        console_url: str,
        username: str,
        password: str,
        http: HttpClient | None = None,
        *,
        page_size: int = 500,
        asset_group: str = "workstations/laptops",
    ) -> None:
        if not 1 <= page_size <= 500:
            raise ValueError(
                "Rapid7 page size must be between 1 and 500"
            )

        if not asset_group.strip():
            raise ValueError(
                "Rapid7 asset group must not be empty"
            )

        parsed = urlparse(console_url)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Rapid7 console URL must be an HTTPS origin, "
                "e.g. https://console:3780"
            )

        if (
            not username
            or ":" in username
            or not password
        ):
            raise ValueError(
                "Rapid7 console username and password are required; "
                "username cannot contain ':'"
            )

        self.page_size = page_size
        self.asset_group = asset_group
        self.base_url = console_url.rstrip("/") + "/api/3"

        token = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode("ascii")

        self.http = http or HttpClient(
            headers={
                "Authorization": f"Basic {token}",
                "Accept": "application/json",
            },
            allowed_hosts={
                parsed.hostname,
            },
        )

        self._solutions: dict[
            str,
            dict[str, Any],
        ] = {}

        self._vulnerabilities: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._vulnerability_details: dict[
            str,
            dict[str, Any],
        ] = {}

        self._asset_vulnerability_proofs: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = {}

    def get_vulnerability(
        self,
        vulnerability_id: str,
    ) -> dict[str, Any]:
        """
        Retrieve and cache one vulnerability definition.

        This avoids downloading the complete Rapid7 vulnerability catalog
        when only a smaller set of vulnerabilities is active on the scoped
        assets.
        """

        vulnerability_id = str(
            vulnerability_id
        ).strip()

        if not vulnerability_id:
            raise ValueError(
                "Rapid7 vulnerability ID must not be empty"
            )

        if vulnerability_id in self._vulnerability_details:
            return self._vulnerability_details[
                vulnerability_id
            ]

        encoded_vulnerability_id = quote(
            vulnerability_id,
            safe="",
        )

        payload = self.http.request_json(
            "GET",
            (
                f"{self.base_url}/vulnerabilities/"
                f"{encoded_vulnerability_id}"
            ),
            timeout=300,
        )

        if not isinstance(payload, dict):
            raise ValueError(
                "Rapid7 returned an invalid vulnerability response for "
                f"{vulnerability_id!r}; expected an object, received "
                f"{type(payload).__name__}"
            )

        vulnerability = {
            **payload,
            "id": str(
                payload.get("id")
                or vulnerability_id
            ),
        }

        self._vulnerability_details[
            vulnerability_id
        ] = vulnerability

        return vulnerability

    def iter_vulnerabilities(
        self,
        vulnerability_ids: Iterable[str],
    ) -> Iterator[dict[str, Any]]:
        """
        Retrieve only the requested vulnerability definitions.

        The method preserves the original filtering requirements:

        - Critical and Severe vulnerabilities only.
        - Exclude vulnerabilities categorized as Microsoft Patch.
        """

        normalized_ids = sorted(
            {
                str(vulnerability_id).strip()
                for vulnerability_id in vulnerability_ids
                if str(vulnerability_id).strip()
            }
        )

        total = len(normalized_ids)

        for index, vulnerability_id in enumerate(
            normalized_ids,
            start=1,
        ):
            if index == 1 or index % 100 == 0 or index == total:
                LOG.info(
                    "Downloading Rapid7 vulnerability details: %s/%s",
                    index,
                    total,
                )

            vulnerability = self.get_vulnerability(
                vulnerability_id
            )

            severity = str(
                vulnerability.get(
                    "severity",
                    "",
                )
            ).lower()

            if severity not in {
                "critical",
                "severe",
            }:
                continue

            categories = vulnerability.get(
                "categories",
                [],
            )

            if not isinstance(
                categories,
                (list, tuple),
            ):
                categories = []

            if any(
                str(category).strip().lower()
                == "microsoft patch"
                for category in categories
            ):
                continue

            yield vulnerability

    def get_vulnerability_solutions(
        self,
        vulnerability_id: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve and cache Rapid7 remediation solutions.

        If Rapid7 returns a valid response without a resources collection,
        return an empty list. The transformation layer can then fall back
        to remediation details in the vulnerability catalog.
        """

        if vulnerability_id in self._vulnerabilities:
            return self._vulnerabilities[
                vulnerability_id
            ]

        encoded_vulnerability_id = quote(
            vulnerability_id,
            safe="",
        )

        payload = self.http.request_json(
            "GET",
            (
                f"{self.base_url}/vulnerabilities/"
                f"{encoded_vulnerability_id}/solutions"
            ),
        )

        if not isinstance(payload, dict):
            raise ValueError(
                "Rapid7 returned an invalid vulnerability-solutions "
                f"response for vulnerability {vulnerability_id!r}; "
                f"expected an object, received {type(payload).__name__}"
            )

        resources = payload.get("resources")

        if resources is None:
            LOG.warning(
                "Rapid7 returned no 'resources' collection from the "
                "vulnerability-solutions endpoint for vulnerability %s. "
                "Response keys: %s. The catalog remediation will be used "
                "as a fallback.",
                vulnerability_id,
                sorted(
                    str(key)
                    for key in payload
                ),
            )

            self._vulnerabilities[
                vulnerability_id
            ] = []

            return []

        if not isinstance(resources, list):
            raise ValueError(
                "Rapid7 returned an invalid 'resources' value from the "
                "vulnerability-solutions endpoint for vulnerability "
                f"{vulnerability_id!r}; expected a list, received "
                f"{type(resources).__name__}"
            )

        solutions: list[
            dict[str, Any]
        ] = []

        for solution_id in resources:
            if (
                not isinstance(solution_id, str)
                or not solution_id.strip()
            ):
                raise ValueError(
                    "Rapid7 returned an invalid solution ID"
                )

            if solution_id not in self._solutions:
                encoded_solution_id = quote(
                    solution_id,
                    safe="",
                )

                solution = self.http.request_json(
                    "GET",
                    (
                        f"{self.base_url}/solutions/"
                        f"{encoded_solution_id}"
                    ),
                )

                if not isinstance(solution, dict):
                    raise ValueError(
                        "Rapid7 returned an invalid solution for "
                        f"solution ID {solution_id!r}; expected an "
                        f"object, received {type(solution).__name__}"
                    )

                self._solutions[
                    solution_id
                ] = {
                    **solution,
                    "id": solution_id,
                }

            solutions.append(
                self._solutions[
                    solution_id
                ]
            )

        self._vulnerabilities[
            vulnerability_id
        ] = solutions

        return solutions

    def get_asset_vulnerability_proof(
        self,
        asset_id: str,
        vulnerability_id: str,
    ) -> list[dict[str, Any]]:
        key = (
            str(asset_id),
            vulnerability_id,
        )

        if key not in self._asset_vulnerability_proofs:
            encoded_asset_id = quote(
                key[0],
                safe="",
            )

            encoded_vulnerability_id = quote(
                vulnerability_id,
                safe="",
            )

            payload = self.http.request_json(
                "GET",
                (
                    f"{self.base_url}/assets/"
                    f"{encoded_asset_id}/vulnerabilities/"
                    f"{encoded_vulnerability_id}"
                ),
            )

            if not isinstance(payload, dict):
                raise ValueError(
                    "Rapid7 returned an invalid asset vulnerability"
                )

            results = payload.get(
                "results",
                [],
            )

            if not isinstance(results, list):
                raise ValueError(
                    "Rapid7 returned invalid asset vulnerability results"
                )

            proofs: list[
                dict[str, Any]
            ] = []

            for result in results:
                if not isinstance(result, dict):
                    raise ValueError(
                        "Rapid7 returned an invalid vulnerability result"
                    )

                status = str(
                    result.get("status")
                    or ""
                )

                if not status.lower().startswith(
                    "vulnerable"
                ):
                    continue

                proof = (
                    result.get("proof")
                    or ""
                )

                if not isinstance(proof, str):
                    raise ValueError(
                        "Rapid7 returned invalid vulnerability proof text"
                    )

                if not proof.strip():
                    continue

                proofs.append(
                    {
                        "check_id": str(
                            result.get(
                                "checkId"
                            )
                            or ""
                        ),
                        "status": status,
                        "proof": proof,
                    }
                )

            self._asset_vulnerability_proofs[
                key
            ] = proofs

        return self._asset_vulnerability_proofs[
            key
        ]


class Rapid7Client(Rapid7SolutionClient):
    def _pages(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        page = 0

        while True:
            kwargs: dict[
                str,
                Any,
            ] = {
                "params": {
                    **(params or {}),
                    "page": page,
                    "size": self.page_size,
                },
                "timeout": 300,
            }

            if body is not None:
                kwargs[
                    "json_body"
                ] = body

            payload = self.http.request_json(
                method,
                f"{self.base_url}{path}",
                **kwargs,
            )

            if not isinstance(payload, dict):
                raise ValueError(
                    "Rapid7 returned an invalid paginated response for "
                    f"{path!r}"
                )

            resources = payload.get(
                "resources"
            )

            if not isinstance(resources, list):
                raise ValueError(
                    "Rapid7 returned an invalid resources collection for "
                    f"{path!r}"
                )

            for resource in resources:
                if not isinstance(resource, dict):
                    raise ValueError(
                        "Rapid7 returned an invalid resource for "
                        f"{path!r}"
                    )

                yield resource

            page_data = payload.get(
                "page"
            )

            if not isinstance(page_data, dict):
                raise ValueError(
                    "Rapid7 returned invalid pagination information for "
                    f"{path!r}"
                )

            total_pages = page_data.get(
                "totalPages"
            )

            try:
                total_pages_int = int(
                    total_pages
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise ValueError(
                    "Rapid7 returned an invalid totalPages value for "
                    f"{path!r}: {total_pages!r}"
                ) from exc

            if page + 1 >= total_pages_int:
                return

            page += 1

    def iter_vulnerability_catalog(
        self,
    ) -> Iterator[dict[str, Any]]:
        """
        Retained for compatibility and testing.

        The optimized production workflow uses iter_vulnerabilities()
        instead of downloading the complete catalog.
        """

        for vulnerability in self._pages(
            "/vulnerabilities"
        ):
            severity = str(
                vulnerability.get(
                    "severity",
                    "",
                )
            ).lower()

            if severity not in {
                "critical",
                "severe",
            }:
                continue

            categories = vulnerability.get(
                "categories",
                [],
            )

            if not isinstance(
                categories,
                (list, tuple),
            ):
                categories = []

            if any(
                str(category).strip().lower()
                == "microsoft patch"
                for category in categories
            ):
                continue

            yield vulnerability

    def iter_affected_assets(
        self,
    ) -> Iterator[dict[str, Any]]:
        groups = [
            group
            for group in self._pages(
                "/asset_groups",
                params={
                    "name": self.asset_group,
                },
            )
            if str(
                group.get(
                    "name",
                    "",
                )
            ).casefold()
            == self.asset_group.casefold()
        ]

        if len(groups) != 1:
            raise ValueError(
                "Expected exactly one accessible Rapid7 asset group "
                f"named {self.asset_group!r}; found {len(groups)}"
            )

        group_id = quote(
            str(
                groups[0][
                    "id"
                ]
            ),
            safe="",
        )

        membership = self.http.request_json(
            "GET",
            (
                f"{self.base_url}/asset_groups/"
                f"{group_id}/assets"
            ),
        )

        if not isinstance(membership, dict):
            raise ValueError(
                "Rapid7 returned invalid asset group membership data"
            )

        membership_resources = membership.get(
            "resources"
        )

        if not isinstance(
            membership_resources,
            list,
        ):
            raise ValueError(
                "Rapid7 returned an invalid asset group membership "
                "resources collection"
            )

        member_ids = {
            str(asset_id)
            for asset_id in membership_resources
        }

        if not member_ids:
            return

        criteria = {
            "match": "all",
            "filters": [
                {
                    "field": "last-scan-date",
                    "operator": "is-within-the-last",
                    "value": 7,
                },
            ],
        }

        for asset in self._pages(
            "/assets/search",
            method="POST",
            body=criteria,
        ):
            asset_id_value = asset.get(
                "id"
            )

            if str(
                asset_id_value
            ) not in member_ids:
                continue

            encoded_asset_id = quote(
                str(asset_id_value),
                safe="",
            )

            findings = [
                {
                    "vulnerability_id": str(
                        finding["id"]
                    ),
                }
                for finding in self._pages(
                    (
                        f"/assets/{encoded_asset_id}/"
                        "vulnerabilities"
                    )
                )
                if (
                    finding.get("status")
                    == "vulnerable"
                    and finding.get("id") is not None
                )
            ]

            yield {
                "id": asset_id_value,
                "host_name": asset.get(
                    "hostName",
                    "",
                ),
                "ip": asset.get(
                    "ip",
                    "",
                ),
                "new": findings,
            }