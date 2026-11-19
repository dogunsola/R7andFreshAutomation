import base64
import logging
import time
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlparse

from .http import HttpClient


LOG = logging.getLogger(__name__)

DEFAULT_RAPID7_TIMEOUT_SECONDS = 300
ASSET_SEARCH_TIMEOUT_SECONDS = 300
ASSET_SEARCH_RETRIES = 2
PROGRESS_INTERVAL = 100
RECENT_SCAN_DAYS = 7


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

        parsed = urlparse(
            console_url
        )

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
        self.base_url = (
            console_url.rstrip("/")
            + "/api/3"
        )

        token = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode(
            "ascii"
        )

        self.http = (
            http
            or HttpClient(
                headers={
                    "Authorization": f"Basic {token}",
                    "Accept": "application/json",
                },
                allowed_hosts={
                    parsed.hostname,
                },
            )
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
            timeout=DEFAULT_RAPID7_TIMEOUT_SECONDS,
        )

        if not isinstance(
            payload,
            dict,
        ):
            raise ValueError(
                "Rapid7 returned an invalid vulnerability "
                f"response for {vulnerability_id!r}; "
                "expected an object, received "
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
        normalized_ids = sorted(
            {
                str(
                    vulnerability_id
                ).strip()
                for vulnerability_id
                in vulnerability_ids
                if str(
                    vulnerability_id
                ).strip()
            }
        )

        total = len(
            normalized_ids
        )

        for index, vulnerability_id in enumerate(
            normalized_ids,
            start=1,
        ):
            if (
                index == 1
                or index % PROGRESS_INTERVAL == 0
                or index == total
            ):
                LOG.info(
                    "Downloading Rapid7 vulnerability "
                    "details: %s/%s",
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
                str(
                    category
                ).strip().lower()
                == "microsoft patch"
                for category
                in categories
            ):
                continue

            yield vulnerability

    def get_vulnerability_solutions(
        self,
        vulnerability_id: str,
    ) -> list[dict[str, Any]]:
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
            timeout=DEFAULT_RAPID7_TIMEOUT_SECONDS,
        )

        if not isinstance(
            payload,
            dict,
        ):
            raise ValueError(
                "Rapid7 returned an invalid vulnerability-solutions "
                f"response for vulnerability {vulnerability_id!r}; "
                "expected an object, received "
                f"{type(payload).__name__}"
            )

        resources = payload.get(
            "resources"
        )

        if resources is None:
            LOG.warning(
                "Rapid7 returned no 'resources' collection from the "
                "vulnerability-solutions endpoint for vulnerability %s. "
                "Response keys: %s. The catalog remediation will be used "
                "as a fallback.",
                vulnerability_id,
                sorted(
                    str(
                        key
                    )
                    for key
                    in payload
                ),
            )

            self._vulnerabilities[
                vulnerability_id
            ] = []

            return []

        if not isinstance(
            resources,
            list,
        ):
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
                not isinstance(
                    solution_id,
                    str,
                )
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
                    timeout=DEFAULT_RAPID7_TIMEOUT_SECONDS,
                )

                if not isinstance(
                    solution,
                    dict,
                ):
                    raise ValueError(
                        "Rapid7 returned an invalid solution for "
                        f"solution ID {solution_id!r}; "
                        "expected an object, received "
                        f"{type(solution).__name__}"
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
            str(
                asset_id
            ),
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
                timeout=DEFAULT_RAPID7_TIMEOUT_SECONDS,
            )

            if not isinstance(
                payload,
                dict,
            ):
                raise ValueError(
                    "Rapid7 returned an invalid asset vulnerability"
                )

            results = payload.get(
                "results",
                [],
            )

            if not isinstance(
                results,
                list,
            ):
                raise ValueError(
                    "Rapid7 returned invalid asset "
                    "vulnerability results"
                )

            proofs: list[
                dict[str, Any]
            ] = []

            for result in results:
                if not isinstance(
                    result,
                    dict,
                ):
                    raise ValueError(
                        "Rapid7 returned an invalid "
                        "vulnerability result"
                    )

                status = str(
                    result.get(
                        "status"
                    )
                    or ""
                )

                if not status.lower().startswith(
                    "vulnerable"
                ):
                    continue

                proof = (
                    result.get(
                        "proof"
                    )
                    or ""
                )

                if not isinstance(
                    proof,
                    str,
                ):
                    raise ValueError(
                        "Rapid7 returned invalid "
                        "vulnerability proof text"
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
    @staticmethod
    def _was_scanned_within(
        asset: dict[str, Any],
        *,
        days: int,
        now: datetime,
    ) -> bool:
        """Return whether an asset's latest scan is within ``days``.

        ``/assets/search`` normally applies this filter itself, but some
        Security Console versions can return assets outside the requested
        relative-date window.  Check the returned value as well so a stale
        asset cannot produce a ticket.
        """
        scanned_at = asset.get(
            "lastScanDate"
        )

        if not isinstance(
            scanned_at,
            str,
        ):
            LOG.warning(
                "Skipping Rapid7 asset %r because it has no lastScanDate",
                asset.get(
                    "id"
                ),
            )
            return False

        try:
            parsed_scan_time = datetime.fromisoformat(
                scanned_at.replace(
                    "Z",
                    "+00:00",
                )
            )
        except ValueError:
            LOG.warning(
                "Skipping Rapid7 asset %r with invalid lastScanDate %r",
                asset.get(
                    "id"
                ),
                scanned_at,
            )
            return False

        if parsed_scan_time.tzinfo is None:
            parsed_scan_time = parsed_scan_time.replace(
                tzinfo=timezone.utc
            )

        return (
            now - timedelta(
                days=days
            )
            <= parsed_scan_time.astimezone(
                timezone.utc
            )
            <= now
        )

    def _pages(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: int = DEFAULT_RAPID7_TIMEOUT_SECONDS,
        retries: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        page = 0

        while True:
            page_started = time.monotonic()

            LOG.info(
                "Requesting Rapid7 %s page %s",
                path,
                page + 1,
            )

            kwargs: dict[
                str,
                Any,
            ] = {
                "params": {
                    **(
                        params
                        or {}
                    ),
                    "page": page,
                    "size": self.page_size,
                },
                "timeout": timeout,
            }

            if retries is not None:
                kwargs[
                    "retries"
                ] = retries

            if body is not None:
                kwargs[
                    "json_body"
                ] = body

            payload = self.http.request_json(
                method,
                (
                    f"{self.base_url}"
                    f"{path}"
                ),
                **kwargs,
            )

            page_duration = (
                time.monotonic()
                - page_started
            )

            if not isinstance(
                payload,
                dict,
            ):
                raise ValueError(
                    "Rapid7 returned an invalid paginated response for "
                    f"{path!r}"
                )

            resources = payload.get(
                "resources"
            )

            if not isinstance(
                resources,
                list,
            ):
                raise ValueError(
                    "Rapid7 returned an invalid resources collection for "
                    f"{path!r}"
                )

            LOG.info(
                "Rapid7 %s page %s returned %s resources "
                "in %.2f seconds",
                path,
                page + 1,
                len(
                    resources
                ),
                page_duration,
            )

            for resource in resources:
                if not isinstance(
                    resource,
                    dict,
                ):
                    raise ValueError(
                        "Rapid7 returned an invalid resource for "
                        f"{path!r}"
                    )

                yield resource

            page_data = payload.get(
                "page"
            )

            if not isinstance(
                page_data,
                dict,
            ):
                raise ValueError(
                    "Rapid7 returned invalid pagination "
                    f"information for {path!r}"
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
                str(
                    category
                ).strip().lower()
                == "microsoft patch"
                for category
                in categories
            ):
                continue

            yield vulnerability

    def iter_affected_assets(
        self,
    ) -> Iterator[dict[str, Any]]:
        LOG.info(
            "Locating Rapid7 asset group %r",
            self.asset_group,
        )

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
            timeout=DEFAULT_RAPID7_TIMEOUT_SECONDS,
        )

        if not isinstance(
            membership,
            dict,
        ):
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
            str(
                asset_id
            )
            for asset_id
            in membership_resources
        }

        LOG.info(
            "Rapid7 asset group %r contains %s asset IDs",
            self.asset_group,
            len(
                member_ids
            ),
        )

        if not member_ids:
            return

        criteria = {
            "match": "all",
            "filters": [
                {
                    "field": "last-scan-date",
                    "operator": "is-within-the-last",
                    "value": RECENT_SCAN_DAYS,
                },
            ],
        }

        LOG.info(
            "Searching Rapid7 for assets scanned "
            "within the last %s days",
            RECENT_SCAN_DAYS,
        )

        recent_assets = list(
            self._pages(
                "/assets/search",
                method="POST",
                body=criteria,
                timeout=ASSET_SEARCH_TIMEOUT_SECONDS,
                retries=ASSET_SEARCH_RETRIES,
            )
        )

        LOG.info(
            "Rapid7 recent-asset search returned "
            "%s total assets",
            len(
                recent_assets
            ),
        )

        now = datetime.now(
            timezone.utc
        )

        scoped_assets = [
            asset
            for asset in recent_assets
            if str(
                asset.get(
                    "id"
                )
            )
            in member_ids
            and self._was_scanned_within(
                asset,
                days=RECENT_SCAN_DAYS,
                now=now,
            )
        ]

        LOG.info(
            "%s recently scanned assets belong to "
            "Rapid7 asset group %r",
            len(
                scoped_assets
            ),
            self.asset_group,
        )

        total_scoped_assets = len(
            scoped_assets
        )

        for asset_index, asset in enumerate(
            scoped_assets,
            start=1,
        ):
            if (
                asset_index == 1
                or asset_index % PROGRESS_INTERVAL == 0
                or asset_index == total_scoped_assets
            ):
                LOG.info(
                    "Downloading Rapid7 asset "
                    "vulnerabilities: %s/%s",
                    asset_index,
                    total_scoped_assets,
                )

            asset_id_value = asset.get(
                "id"
            )

            encoded_asset_id = quote(
                str(
                    asset_id_value
                ),
                safe="",
            )

            findings = [
                {
                    "vulnerability_id": str(
                        finding[
                            "id"
                        ]
                    ),
                }
                for finding in self._pages(
                    (
                        f"/assets/{encoded_asset_id}/"
                        "vulnerabilities"
                    )
                )
                if (
                    finding.get(
                        "status"
                    )
                    == "vulnerable"
                    and finding.get(
                        "id"
                    )
                    is not None
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
