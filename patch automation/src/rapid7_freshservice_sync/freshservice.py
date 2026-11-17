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

TICKET_CATEGORY = "Digital Security"
TICKET_SUB_CATEGORY = "Vulnerability Management"

# Required by the Freshservice ticket creation API.
DEFAULT_STATUS = 2
DEFAULT_PRIORITY = 2


class FreshserviceClient:
    def __init__(
        self,
        domain: str,
        api_key: str,
        requester_email: str,
        workspace_id: int,
        group_id: int,
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
                "Freshservice hostname must end with "
                ".freshservice.com"
            )

        if parsed.username or parsed.password:
            raise ValueError(
                "Freshservice domain must not contain credentials"
            )

        if parsed.path not in ("", "/"):
            raise ValueError(
                "Freshservice domain must contain only the "
                "HTTPS origin and must not include a path"
            )

        if (
            parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Freshservice domain must contain only the "
                "HTTPS origin"
            )

        if not api_key.strip():
            raise ValueError(
                "Freshservice API key is required"
            )

        if not requester_email.strip():
            raise ValueError(
                "Freshservice requester email is required"
            )

        if (
            isinstance(workspace_id, bool)
            or not isinstance(workspace_id, int)
            or workspace_id <= 0
        ):
            raise ValueError(
                "Freshservice workspace ID must be "
                "a positive integer"
            )

        if (
            isinstance(group_id, bool)
            or not isinstance(group_id, int)
            or group_id <= 0
        ):
            raise ValueError(
                "Freshservice group ID must be "
                "a positive integer"
            )

        self.base_url = (
            f"https://{parsed.netloc}/api/v2"
        )

        self.requester_email = (
            requester_email.strip()
        )

        self.workspace_id = workspace_id
        self.group_id = group_id

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

    def create_ticket_if_missing(
        self,
        finding: Finding,
    ) -> dict[str, Any] | None:
        """
        Create a ticket in the explicitly configured workspace and group.

        Duplicate detection is limited to the same workspace. The client
        does not enumerate Freshservice workspaces or groups.

        Freshservice requires status and priority during ticket creation.
        Urgency and impact are deliberately omitted so Freshservice
        defaults and workflow automations can manage them.
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
                    "workspace_id": self.workspace_id,
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

        payload = {
            "email": self.requester_email,
            "subject": _ticket_subject(
                finding.solution
            ),
            "description": _ticket_description(
                finding
            ),

            # Mandatory Freshservice create-ticket fields.
            "status": DEFAULT_STATUS,
            "priority": DEFAULT_PRIORITY,

            # Explicit routing.
            "workspace_id": self.workspace_id,
            "group_id": self.group_id,

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


def finding_tag(
    finding: Finding,
) -> str:
    """
    Generate a stable remediation tag for duplicate detection.

    Detailed Rapid7 solutions include the solution ID. Catalog fallback
    findings use the solution text and fix details.
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
    Build the Freshservice HTML description.

    All Rapid7-provided values are HTML escaped before insertion.
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

    asset_rows = "".join(
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