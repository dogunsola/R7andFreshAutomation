import base64
import hashlib
import html
from typing import Any
from urllib.parse import urlparse

from .http import ApiError, HttpClient
from .models import (
    MAX_PROOF_VULNERABILITIES,
    AffectedAsset,
    Finding,
)


OPEN_STATUSES = (2, 3)

WORKSPACE_NAME = "IT, Banking Support & Marketing"
GROUP_NAME = "Service Desk"

TICKET_CATEGORY = "Digital Security"
TICKET_SUB_CATEGORY = "Vulnerability Management"

MEDIUM = 2
RESOURCE_PAGE_SIZE = 100


class FreshserviceClient:
    def __init__(
        self,
        domain: str,
        api_key: str,
        requester_email: str,
        http: HttpClient | None = None,
    ) -> None:
        normalized_domain = domain.strip().rstrip("/")
        parsed = urlparse(normalized_domain)

        if parsed.scheme != "https":
            raise ValueError(
                "Freshservice domain must use HTTPS"
            )

        if not parsed.hostname:
            raise ValueError(
                "Freshservice domain must contain a hostname"
            )

        hostname = parsed.hostname.lower()

        if not hostname.endswith(".freshservice.com"):
            raise ValueError(
                "Freshservice hostname must end with .freshservice.com"
            )

        if parsed.username or parsed.password:
            raise ValueError(
                "Freshservice domain must not contain credentials"
            )

        if parsed.path not in ("", "/"):
            raise ValueError(
                "Freshservice domain must contain only the HTTPS "
                "origin and must not include a path"
            )

        if (
            parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Freshservice domain must contain only the HTTPS origin"
            )

        if not api_key.strip():
            raise ValueError(
                "Freshservice API key is required"
            )

        if not requester_email.strip():
            raise ValueError(
                "Freshservice requester email is required"
            )

        self.base_url = (
            f"https://{parsed.netloc}/api/v2"
        )

        self.requester_email = (
            requester_email.strip()
        )

        token = base64.b64encode(
            f"{api_key.strip()}:X".encode()
        ).decode("ascii")

        self.http = (
            http
            or HttpClient(
                headers={
                    "Authorization": f"Basic {token}",
                    "Accept": "application/json",
                },
                allowed_hosts={
                    hostname,
                },
            )
        )

        self._workspace_id: int | None = None
        self._group_id: int | None = None

    def create_ticket_if_missing(
        self,
        finding: Finding,
    ) -> dict[str, Any] | None:
        """
        Create a Freshservice ticket unless a matching Open or
        Pending ticket already exists.

        The complete Freshservice filter expression must be enclosed
        in double quotes. String values inside the expression use
        single quotes.

        workspace_id=0 searches across all accessible workspaces.
        """

        tag = finding_tag(finding)

        for status in OPEN_STATUSES:
            query = (
                f"\"tag:'{tag}' "
                f"AND status:{status}\""
            )

            response = self.http.request_json(
                "GET",
                f"{self.base_url}/tickets/filter",
                params={
                    "workspace_id": 0,
                    "query": query,
                },
            )

            tickets = (
                response.get("tickets")
                if isinstance(response, dict)
                else None
            )

            if not isinstance(tickets, list):
                raise ApiError(
                    "Freshservice ticket filter returned "
                    "an invalid response"
                )

            if tickets:
                return None

        workspace_id, group_id = (
            self._ticket_routing_ids()
        )

        payload = {
            "email": self.requester_email,
            "subject": _ticket_subject(
                finding.solution
            ),
            "description": _ticket_description(
                finding
            ),
            "urgency": MEDIUM,
            "impact": MEDIUM,
            "priority": MEDIUM,
            "status": 2,
            "workspace_id": workspace_id,
            "group_id": group_id,
            "category": TICKET_CATEGORY,
            "sub_category": TICKET_SUB_CATEGORY,
            "tags": [
                "rapid7-insightvm",
                tag,
            ],
        }

        response = self.http.request_json(
            "POST",
            f"{self.base_url}/tickets",
            json_body=payload,
            retryable=False,
        )

        ticket = (
            response.get("ticket")
            if isinstance(response, dict)
            else None
        )

        if (
            not isinstance(ticket, dict)
            or "id" not in ticket
        ):
            raise ApiError(
                "Freshservice ticket creation returned "
                "an invalid response"
            )

        return ticket

    def _ticket_routing_ids(
        self,
    ) -> tuple[int, int]:
        if self._workspace_id is None:
            self._workspace_id = (
                self._find_resource_id(
                    "/workspaces",
                    "workspaces",
                    WORKSPACE_NAME,
                )
            )

        if self._group_id is None:
            self._group_id = (
                self._find_resource_id(
                    "/groups",
                    "groups",
                    GROUP_NAME,
                    params={
                        "workspace_id":
                            self._workspace_id,
                    },
                )
            )

        return (
            self._workspace_id,
            self._group_id,
        )

    def _find_resource_id(
        self,
        path: str,
        resource_key: str,
        name: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> int:
        resources = self._list_resources(
            path,
            resource_key,
            params=params,
        )

        matches = [
            resource
            for resource in resources
            if resource.get("name") == name
        ]

        if len(matches) != 1:
            raise ApiError(
                "Expected exactly one Freshservice "
                f"{resource_key[:-1]} named "
                f"{name!r}; found {len(matches)}"
            )

        resource_id = matches[0].get("id")

        if (
            isinstance(resource_id, bool)
            or not isinstance(
                resource_id,
                (int, str),
            )
        ):
            raise ApiError(
                f"Freshservice {resource_key[:-1]} "
                f"{name!r} has an invalid ID"
            )

        if (
            isinstance(resource_id, str)
            and not resource_id.isdecimal()
        ):
            raise ApiError(
                f"Freshservice {resource_key[:-1]} "
                f"{name!r} has an invalid ID"
            )

        parsed_id = int(resource_id)

        if parsed_id <= 0:
            raise ApiError(
                f"Freshservice {resource_key[:-1]} "
                f"{name!r} has an invalid ID"
            )

        return parsed_id

    def _list_resources(
        self,
        path: str,
        resource_key: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        page = 1
        resources: list[dict[str, Any]] = []

        while True:
            response = self.http.request_json(
                "GET",
                f"{self.base_url}{path}",
                params={
                    **(params or {}),
                    "page": page,
                    "per_page": RESOURCE_PAGE_SIZE,
                },
            )

            batch = (
                response.get(resource_key)
                if isinstance(response, dict)
                else None
            )

            if (
                not isinstance(batch, list)
                or any(
                    not isinstance(resource, dict)
                    for resource in batch
                )
            ):
                raise ApiError(
                    f"Freshservice {resource_key} list "
                    "returned an invalid response"
                )

            resources.extend(batch)

            if len(batch) < RESOURCE_PAGE_SIZE:
                return resources

            page += 1


def finding_tag(
    finding: Finding,
) -> str:
    """
    Build a stable tag for Freshservice duplicate detection.

    When a Rapid7 solution ID is available, it is included in
    the identity. Otherwise the solution text and fix details
    become the identity.
    """

    if finding.solution_id:
        identity = (
            f"{finding.solution_id}"
            "\0"
            f"{finding.solution}"
            "\0"
            f"{finding.fix_details}"
        )
    else:
        identity = (
            f"{finding.solution}"
            "\0"
            f"{finding.fix_details}"
        )

    stable_id = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:24]

    return (
        "rapid7-remediation-"
        f"{stable_id}"
    )


def _ticket_subject(
    solution: str,
) -> str:
    return (
        solution
        or "Review vulnerability findings"
    )[:250]


def _ticket_description(
    finding: Finding,
) -> str:
    """
    Build the Freshservice HTML ticket description.

    Rapid7-provided data is HTML-escaped before insertion.
    """

    assets = (
        finding.affected_assets
        or tuple(
            AffectedAsset(
                asset_id="",
                host=host,
                ip="",
            )
            for host in finding.hosts
        )
    )

    asset_rows = "".join(n(
        (
            "<tr>"
            f"<td>{html.escape(asset.asset_id)}</td>"
            f"<td>{html.escape(asset.host)}</td>"
          f"<td>{html.escape(asset.ip)}</td>"
            f"<td>{html.escape(finding.solution_id)}</td>"
            f"<td>{html.escape(finding.solution)}</td>"
            f"<td>{html.escape(finding.fix_details)}</td>"
            "</tr>"
        )
        for asset in assets
    )

    remediation_section = (
        "<h2>Rapid7 Remediation Details</h2>"
        "<table>"
        "<thead>"
        "<tr>"
        "<th>Asset ID</th>"
        "<th>Hostname</th>"
        "<th>IP Address</th>"
        "<th>Solution ID</th>"
        "<th>Solution</th>"
        "<th>Fix Details</th>"
        "</tr>"
        "</thead>"
        f"<tbody>{asset_rows}</tbody>"
        "</table>"
    )

    proof_section = ""

    if (
        finding.proofs
        or (
            0
            < finding.vulnerability_count
            <= MAX_PROOF_VULNERABILITIES
        )
    ):
        if finding.proofs:
            proof_rows = "".join(
                (
                    "<tr>"
                    f"<td>{html.escape(proof.asset_id)}</td>"
                    f"<td>{html.escape(proof.host)}</td>"
                    f"<td>{html.escape(proof.vulnerability_id)}</td>"
                    f"<td>{html.escape(proof.check_id)}</td>"
                    f"<td>{html.escape(proof.status)}</td>"
                    "<td><pre>"
                    f"{html.escape(proof.proof)}"
                    "</pre></td>"
                    "</tr>"
                )
                for proof in finding.proofs
            )

            proof_content = (
                "<table>"
                "<thead>"
                "<tr>"
                "<th>Asset ID</th>"
                "<th>Hostname</th>"
                "<th>Vulnerability ID</th>"
                "<th>Check ID</th>"
                "<th>Status</th>"
                "<th>Proof</th>"
                "</tr>"
                "</thead>"
                f"<tbody>{proof_rows}</tbody>"
                "</table>"
            )

        else:
            proof_content = (
                "<p>"
                "Rapid7 returned no proof details "
                "for this solution's findings."
                "</p>"
            )

        proof_section = (
            "<h2>Rapid7 Proof by Asset</h2>"
            f"{proof_content}"
        )

    return (
        remediation_section
        + proof_section
    )