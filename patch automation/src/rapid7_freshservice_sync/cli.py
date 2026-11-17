import argparse
import logging
import os
import stat
from pathlib import Path

from .freshservice import FreshserviceClient
from .rapid7 import Rapid7Client
from .secrets import (
    AzureKeyVaultSecretProvider,
    EnvSecretProvider,
    default_secret_name,
)
from .transform import (
    build_catalog,
    transform_assets,
    write_findings_csv,
)


LOG = logging.getLogger(__name__)


def positive_int(
    value: str,
) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a positive integer"
        ) from exc

    if parsed <= 0:
        raise argparse.ArgumentTypeError(
            "must be a positive integer"
        )

    return parsed


def optional_env_positive_int(
    variable_name: str,
) -> int | None:
    value = os.environ.get(
        variable_name,
        "",
    ).strip()

    if not value:
        return None

    try:
        return positive_int(value)
    except argparse.ArgumentTypeError as exc:
        raise SystemExit(
            f"{variable_name} must be a positive integer"
        ) from exc


def safe_output_path(
    path: Path,
) -> Path:
    if path.exists() and path.is_symlink():
        raise SystemExit(
            "Refusing to write output through a symbolic link"
        )

    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export InsightVM findings and create "
            "Freshservice tickets."
        )
    )

    parser.add_argument(
        "--asset-group",
        default="workstations/laptops",
        help=(
            "Exact Security Console asset group name"
        ),
    )

    parser.add_argument(
        "--page-size",
        type=positive_int,
        default=500,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "rapid7-freshservice-findings.csv"
        ),
        help="CSV output path",
    )

    parser.add_argument(
        "--hostname-fallback",
        choices=(
            "skip",
            "ip",
        ),
        default="skip",
        help=(
            "Behavior when an InsightVM asset "
            "has no hostname"
        ),
    )

    parser.add_argument(
        "--create-tickets",
        action="store_true",
        help=(
            "Create Freshservice tickets for findings "
            "not already open"
        ),
    )

    parser.add_argument(
        "--secret-source",
        choices=(
            "env",
            "azure-keyvault",
        ),
        default=os.environ.get(
            "SECRET_SOURCE",
            "env",
        ),
        help=(
            "Secret source for credentials "
            "(default: SECRET_SOURCE or env)"
        ),
    )

    parser.add_argument(
        "--azure-key-vault-url",
        default=os.environ.get(
            "AZURE_KEY_VAULT_URL",
            "",
        ),
        help=(
            "Azure Key Vault URL when --secret-source "
            "azure-keyvault is used"
        ),
    )

    parser.add_argument(
        "--freshservice-api-key-secret",
        default=None,
        help=(
            "Secret name for the Freshservice API key"
        ),
    )

    parser.add_argument(
        "--freshservice-requester-email-secret",
        default=None,
        help=(
            "Secret name for the Freshservice requester email"
        ),
    )

    parser.add_argument(
        "--freshservice-domain",
        default=os.environ.get(
            "FRESHSERVICE_DOMAIN",
            "",
        ),
        help=(
            "Freshservice HTTPS origin, for example "
            "https://alterna.freshservice.com"
        ),
    )

    parser.add_argument(
        "--freshservice-workspace-id",
        type=positive_int,
        default=optional_env_positive_int(
            "FRESHSERVICE_WORKSPACE_ID"
        ),
        help=(
            "Numeric Freshservice workspace ID; defaults to "
            "FRESHSERVICE_WORKSPACE_ID"
        ),
    )

    parser.add_argument(
        "--freshservice-group-id",
        type=positive_int,
        default=optional_env_positive_int(
            "FRESHSERVICE_GROUP_ID"
        ),
        help=(
            "Numeric Freshservice group ID; defaults to "
            "FRESHSERVICE_GROUP_ID"
        ),
    )

    parser.add_argument(
        "--console-url",
        default=os.environ.get(
            "RAPID7_CONSOLE_URL",
            "",
        ),
        help=(
            "Security Console HTTPS origin, for example "
            "https://console:3780"
        ),
    )

    parser.add_argument(
        "--rapid7-console-username-secret",
        default=None,
    )

    parser.add_argument(
        "--rapid7-console-password-secret",
        default=None,
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
    )

    return parser.parse_args()


def build_secret_provider(
    args: argparse.Namespace,
) -> (
    EnvSecretProvider
    | AzureKeyVaultSecretProvider
):
    if args.secret_source == "env":
        return EnvSecretProvider()

    if not args.azure_key_vault_url:
        raise SystemExit(
            "--azure-key-vault-url or AZURE_KEY_VAULT_URL "
            "is required for Azure Key Vault"
        )

    return AzureKeyVaultSecretProvider(
        args.azure_key_vault_url
    )


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=(
            logging.DEBUG
            if args.verbose
            else logging.INFO
        ),
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    secrets = build_secret_provider(
        args
    )

    if not args.console_url:
        raise SystemExit(
            "--console-url or RAPID7_CONSOLE_URL "
            "is required for Rapid7 API access"
        )

    rapid7 = Rapid7Client(
        args.console_url,
        secrets.get_required(
            args.rapid7_console_username_secret
            or default_secret_name(
                args.secret_source,
                "RAPID7_CONSOLE_USERNAME",
                "rapid7-console-username",
            )
        ),
        secrets.get_required(
            args.rapid7_console_password_secret
            or default_secret_name(
                args.secret_source,
                "RAPID7_CONSOLE_PASSWORD",
                "rapid7-console-password",
            )
        ),
        page_size=args.page_size,
        asset_group=args.asset_group,
    )

    LOG.info(
        "Downloading in-scope Rapid7 assets and "
        "active vulnerability IDs"
    )

    assets = list(
        rapid7.iter_affected_assets()
    )

    vulnerability_ids = {
        str(
            item.get(
                "vulnerability_id",
                "",
            )
        ).strip()
        for asset in assets
        for field in (
            "new",
            "same",
        )
        for item in (
            asset.get(field)
            or []
        )
        if str(
            item.get(
                "vulnerability_id",
                "",
            )
        ).strip()
    }

    LOG.info(
        "Found %s in-scope assets with %s distinct "
        "active vulnerability IDs",
        len(assets),
        len(vulnerability_ids),
    )

    LOG.info(
        "Downloading catalog details only for "
        "in-scope vulnerability IDs"
    )

    catalog = build_catalog(
        rapid7.iter_vulnerabilities(
            vulnerability_ids
        )
    )

    LOG.info(
        "Catalog contains %s qualifying Critical/Severe "
        "non-Microsoft-Patch vulnerability IDs",
        len(catalog),
    )

    LOG.info(
        "Transforming affected Rapid7 assets and "
        "active findings"
    )

    findings, stats = transform_assets(
        assets,
        catalog,
        hostname_fallback=(
            args.hostname_fallback
        ),
        solution_lookup=(
            rapid7.get_vulnerability_solutions
        ),
        proof_lookup=(
            rapid7.get_asset_vulnerability_proof
        ),
    )

    args.output = safe_output_path(
        args.output
    )

    write_findings_csv(
        args.output,
        findings,
    )

    LOG.info(
        "Wrote %s unique findings to %s",
        len(findings),
        args.output,
    )

    LOG.info(
        "Summary: assets=%s, no-host=%s, "
        "unknown-vulnerability-id=%s",
        stats.assets_seen,
        stats.assets_without_host,
        stats.vulnerability_ids_not_in_catalog,
    )

    if args.create_tickets:
        if not args.freshservice_domain:
            raise SystemExit(
                "--freshservice-domain or FRESHSERVICE_DOMAIN "
                "is required to create tickets"
            )

        if args.freshservice_workspace_id is None:
            raise SystemExit(
                "--freshservice-workspace-id or "
                "FRESHSERVICE_WORKSPACE_ID is required "
                "to create tickets"
            )

        if args.freshservice_group_id is None:
            raise SystemExit(
                "--freshservice-group-id or "
                "FRESHSERVICE_GROUP_ID is required "
                "to create tickets"
            )

        freshservice = FreshserviceClient(
            domain=args.freshservice_domain,
            api_key=secrets.get_required(
                args.freshservice_api_key_secret
                or default_secret_name(
                    args.secret_source,
                    "FRESHSERVICE_API_KEY",
                    "freshservice-api-key",
                )
            ),
            requester_email=secrets.get_required(
                args.freshservice_requester_email_secret
                or default_secret_name(
                    args.secret_source,
                    "FRESHSERVICE_REQUESTER_EMAIL",
                    "freshservice-requester-email",
                )
            ),
            workspace_id=(
                args.freshservice_workspace_id
            ),
            group_id=(
                args.freshservice_group_id
            ),
        )

        created = 0
        skipped = 0

        for finding in findings:
            ticket = (
                freshservice.create_ticket_if_missing(
                    finding
                )
            )

            if ticket is None:
                skipped += 1

                LOG.info(
                    "Skipping existing open Freshservice ticket "
                    "for solution %s (%s)",
                    (
                        finding.solution_id
                        or finding.solution
                    ),
                    finding.solution,
                )
            else:
                created += 1

                LOG.info(
                    "Created Freshservice ticket id=%s "
                    "for solution %s",
                    ticket["id"],
                    (
                        finding.solution_id
                        or finding.solution
                    ),
                )

        LOG.info(
            "Freshservice tickets: created=%s, "
            "already-open=%s",
            created,
            skipped,
        )
    else:
        LOG.info(
            "Dry run complete; use --create-tickets "
            "to create Freshservice tickets"
        )

    try:
        mode = stat.S_IMODE(
            args.output.stat().st_mode
        )

        if mode & 0o077:
            LOG.warning(
                "%s is readable by group/other; "
                "consider chmod 600",
                args.output,
            )
    except OSError:
        pass


if __name__ == "__main__":
    main()