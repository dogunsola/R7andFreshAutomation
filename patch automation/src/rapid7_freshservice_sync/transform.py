import csv
import os
import re
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .models import (
    MAX_PROOF_VULNERABILITIES,
    AffectedAsset,
    AssetVulnerabilityProof,
    Finding,
    TransformStats,
)


QUALIFYING_SEVERITIES = {
    "critical",
    "severe",
}

ACTIVE_FINDING_FIELDS = (
    "new",
    "same",
)

CSV_FORMULA_PREFIXES = (
    "=",
    "+",
    "-",
    "@",
    "\t",
    "\r",
    "\n",
)

MICROSOFT_TOKENS = (
    "microsoft",
    "windows",
    "office",
    "azure",
    "sql server",
)

LATEST_VERSION_PATTERN = re.compile(
    r"\b(?:latest|newest|most\s+recent)\s+(?:available\s+)?version\b",
    re.IGNORECASE,
)

SPECIFIC_VERSION_PATTERN = re.compile(
    r"\b(?:version|v)\s*\d+(?:\.\d+)+\b"
    r"|\b(?:update|upgrade|install)\b.{0,80}?\b\d+(?:\.\d+)+\b",
    re.IGNORECASE,
)


def _exclude_redundant_version_remediations(
    remediations: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    """Prefer a latest-version remediation over specific version updates."""
    if not any(
        LATEST_VERSION_PATTERN.search(
            f"{solution} {fix_details}"
        )
        for _, solution, fix_details in remediations
    ):
        return remediations

    return [
        remediation
        for remediation in remediations
        if not SPECIFIC_VERSION_PATTERN.search(
            f"{remediation[1]} {remediation[2]}"
        )
        or LATEST_VERSION_PATTERN.search(
            f"{remediation[1]} {remediation[2]}"
        )
    ]


def _consolidate_product_family_rollups(
    findings: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    """Merge version-pinned findings into one latest-version rollup.

    This is deliberately conservative: different Rapid7 solution IDs are
    consolidated only when every vulnerability in each finding has the same
    normalized software family and that family has exactly one rollup.
    """
    rollups_by_family: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for entry in findings.values():
        families = entry["software_families"]

        if (
            len(families) != 1
            or not LATEST_VERSION_PATTERN.search(
                f"{entry['solution']} {entry['fix_details']}"
            )
        ):
            continue

        family = next(iter(families))
        rollups_by_family.setdefault(
            family,
            [],
        ).append(entry)

    for key, entry in list(findings.items()):
        families = entry["software_families"]

        if (
            len(families) != 1
            or LATEST_VERSION_PATTERN.search(
                f"{entry['solution']} {entry['fix_details']}"
            )
            or not SPECIFIC_VERSION_PATTERN.search(
                f"{entry['solution']} {entry['fix_details']}"
            )
        ):
            continue

        family = next(iter(families))
        rollups = rollups_by_family.get(
            family,
            [],
        )

        if len(rollups) != 1:
            continue

        rollup = rollups[0]
        rollup["hosts"].update(
            entry["hosts"]
        )
        rollup["assets"].update(
            entry["assets"]
        )

        for vulnerability_id, assets in entry[
            "vulnerabilities"
        ].items():
            rollup["vulnerabilities"].setdefault(
                vulnerability_id,
                set(),
            ).update(assets)

        del findings[key]


def build_catalog(
    vulnerabilities: Iterable[dict[str, Any]],
) -> dict[str, tuple[str, str, str, str]]:
    catalog: dict[
        str,
        tuple[str, str, str, str],
    ] = {}

    for vulnerability in vulnerabilities:
        vulnerability_id = str(
            vulnerability.get(
                "id",
                "",
            )
        ).strip()

        severity = str(
            vulnerability.get(
                "severity",
                "",
            )
        ).lower()

        if (
            not vulnerability_id
            or severity not in QUALIFYING_SEVERITIES
        ):
            continue

        software = str(
            vulnerability.get("name")
            or vulnerability.get("title")
            or "Unknown Service"
        )

        software = _normalize_software_name(
            software
        )

        solution = _clean_cell(
            _rapid7_text(
                vulnerability.get(
                    "solution"
                )
            )
        )

        fix_details = _clean_cell(
            _rapid7_text(
                vulnerability.get("fix_details")
                or vulnerability.get("fix")
            )
        )

        catalog[vulnerability_id] = (
            severity,
            software,
            solution,
            fix_details,
        )

    return catalog


def transform_assets(
    assets: Iterable[dict[str, Any]],
    catalog: dict[
        str,
        tuple[str, str, str, str],
    ],
    hostname_fallback: str = "skip",
    solution_lookup: Callable[
        [str],
        list[dict[str, Any]],
    ]
    | None = None,
    proof_lookup: Callable[
        [str, str],
        list[dict[str, Any]],
    ]
    | None = None,
) -> tuple[list[Finding], TransformStats]:
    findings: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}

    assets_seen = 0
    assets_without_host = 0
    unknown_ids = 0

    for asset in assets:
        assets_seen += 1

        host = _clean_cell(
            str(
                asset.get("host_name")
                or ""
            ).strip()
        )

        if (
            not host
            and hostname_fallback == "ip"
        ):
            host = _clean_cell(
                str(
                    asset.get("ip")
                    or ""
                ).strip()
            )

        if not host:
            assets_without_host += 1
            continue

        asset_id = str(
            asset.get("id")
            or ""
        ).strip()

        ip = _clean_cell(
            str(
                asset.get("ip")
                or ""
            ).strip()
        )

        affected_asset = AffectedAsset(
            asset_id=asset_id,
            host=host,
            ip=ip,
        )

        for field in ACTIVE_FINDING_FIELDS:
            for item in asset.get(field) or []:
                vulnerability_id = str(
                    item.get(
                        "vulnerability_id",
                        "",
                    )
                ).strip()

                catalog_entry = catalog.get(
                    vulnerability_id
                )

                if catalog_entry is None:
                    unknown_ids += 1
                    continue

                (
                    severity,
                    software,
                    catalog_solution,
                    catalog_fix_details,
                ) = catalog_entry

                if _is_microsoft_software(
                    software
                ):
                    continue

                # Begin with the remediation data available in the
                # vulnerability catalog. If Rapid7 returns detailed
                # solution records, those records replace this fallback.
                remediations: list[
                    tuple[str, str, str]
                ] = [
                    (
                        "",
                        catalog_solution,
                        catalog_fix_details,
                    )
                ]

                if solution_lookup is not None:
                    solution_records = solution_lookup(
                        vulnerability_id
                    )

                    if solution_records:
                        remediations = [
                            (
                                str(
                                    record.get("id")
                                    or ""
                                ),
                                _clean_cell(
                                    _rapid7_text(
                                        record.get(
                                            "summary"
                                        )
                                    )
                                ),
                                _clean_cell(
                                    _rapid7_text(
                                        record.get(
                                            "steps"
                                        )
                                    )
                                ),
                            )
                            for record in solution_records
                        ]

                remediations = _exclude_redundant_version_remediations(
                    remediations
                )

                for (
                    solution_id,
                    solution,
                    fix_details,
                ) in remediations:
                    key = (
                        solution_id,
                        solution,
                        fix_details,
                    )

                    group = findings.setdefault(
                        key,
                        {
                            "solution_id": solution_id,
                            "solution": solution,
                            "fix_details": fix_details,
                            "software_families": set(),
                            "hosts": set(),
                            "assets": {},
                            "vulnerabilities": {},
                        },
                    )

                    group["software_families"].add(
                        _normalize_software_name(
                            software
                        ).casefold()
                    )

                    group["hosts"].add(
                        host
                    )

                    group["assets"][
                        (
                            asset_id,
                            host,
                            ip,
                        )
                    ] = affected_asset

                    group[
                        "vulnerabilities"
                    ].setdefault(
                        vulnerability_id,
                        set(),
                    ).add(
                        (
                            asset_id,
                            host,
                        )
                    )

    _consolidate_product_family_rollups(
        findings
    )

    ordered: list[Finding] = []

    for entry in sorted(
        findings.values(),
        key=lambda item: (
            item["solution"],
            item["fix_details"],
            item["solution_id"],
        ),
    ):
        vulnerability_assets = entry[
            "vulnerabilities"
        ]

        vulnerability_count = len(
            vulnerability_assets
        )

        proofs: list[
            AssetVulnerabilityProof
        ] = []

        proof_note = ""

        if proof_lookup is not None:
            if (
                vulnerability_count
                > MAX_PROOF_VULNERABILITIES
            ):
                proof_note = (
                    "Proof lookup skipped: this remediation solution "
                    f"affects {vulnerability_count} distinct "
                    "vulnerabilities "
                    f"(limit: {MAX_PROOF_VULNERABILITIES})."
                )
            else:
                for (
                    vulnerability_id,
                    vulnerability_asset_records,
                ) in sorted(
                    vulnerability_assets.items()
                ):
                    for (
                        asset_id,
                        host,
                    ) in sorted(
                        vulnerability_asset_records
                    ):
                        if not asset_id:
                            raise ValueError(
                                "Rapid7 asset ID is required to retrieve "
                                "vulnerability proof"
                            )

                        results = proof_lookup(
                            asset_id,
                            vulnerability_id,
                        )

                        if not results:
                            proofs.append(
                                AssetVulnerabilityProof(
                                    asset_id=asset_id,
                                    host=host,
                                    vulnerability_id=(
                                        vulnerability_id
                                    ),
                                    check_id="",
                                    status="",
                                    proof=(
                                        "No proof details returned "
                                        "by Rapid7."
                                    ),
                                )
                            )

                            continue

                        for result in results:
                            proofs.append(
                                AssetVulnerabilityProof(
                                    asset_id=asset_id,
                                    host=host,
                                    vulnerability_id=(
                                        vulnerability_id
                                    ),
                                    check_id=_clean_cell(
                                        str(
                                            result.get(
                                                "check_id"
                                            )
                                            or ""
                                        )
                                    ),
                                    status=_clean_cell(
                                        str(
                                            result.get(
                                                "status"
                                            )
                                            or ""
                                        )
                                    ),
                                    proof=_clean_cell(
                                        str(
                                            result.get(
                                                "proof"
                                            )
                                            or ""
                                        )
                                    ),
                                )
                            )

                if not proofs:
                    proof_note = (
                        "Rapid7 returned no proof details for this "
                        "solution's findings."
                    )

        ordered.append(
            Finding(
                hosts=tuple(
                    sorted(
                        entry["hosts"]
                    )
                ),
                solution=entry[
                    "solution"
                ],
                fix_details=entry[
                    "fix_details"
                ],
                solution_id=entry[
                    "solution_id"
                ],
                proofs=tuple(
                    proofs
                ),
                proof_note=proof_note,
                vulnerability_count=(
                    vulnerability_count
                ),
                affected_assets=tuple(
                    sorted(
                        entry[
                            "assets"
                        ].values()
                    )
                ),
            )
        )

    return (
        ordered,
        TransformStats(
            assets_seen=assets_seen,
            findings_written=len(
                ordered
            ),
            assets_without_host=(
                assets_without_host
            ),
            vulnerability_ids_not_in_catalog=(
                unknown_ids
            ),
        ),
    )


def write_findings_csv(
    path: Path,
    findings: Iterable[Finding],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )

    os.chmod(
        temp_name,
        0o600,
    )

    try:
        with os.fdopen(
            fd,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.writer(
                file
            )

            writer.writerow(
                (
                    "Hosts",
                    "Solution",
                    "Fix details",
                    "Proof information",
                )
            )

            for item in findings:
                writer.writerow(
                    [
                        _clean_cell(
                            ";".join(
                                item.hosts
                            )
                        ),
                        _clean_cell(
                            item.solution
                        ),
                        _clean_cell(
                            item.fix_details
                        ),
                        _clean_cell(
                            _format_proof_information(
                                item
                            )
                        ),
                    ]
                )

        os.replace(
            temp_name,
            path,
        )

    except Exception:
        try:
            os.unlink(
                temp_name
            )
        except FileNotFoundError:
            pass

        raise


def _clean_cell(
    value: str,
) -> str:
    cleaned = value.replace(
        "\x00",
        "",
    ).strip()

    if cleaned.startswith(
        CSV_FORMULA_PREFIXES
    ):
        return f"'{cleaned}"

    return cleaned


def _format_proof_information(
    finding: Finding,
) -> str:
    if not finding.proofs:
        return finding.proof_note

    return "\n".join(
        (
            f"Asset: {proof.host} (ID {proof.asset_id}); "
            f"Vulnerability: {proof.vulnerability_id}; "
            f"Check: {proof.check_id}; "
            f"Status: {proof.status}; "
            f"Proof: {proof.proof}"
        )
        for proof in finding.proofs
    )


def _rapid7_text(
    value: Any,
) -> str:
    if value is None:
        return ""

    if isinstance(
        value,
        (list, tuple),
    ):
        return "; ".join(
            str(item)
            for item in value
        )

    if isinstance(
        value,
        dict,
    ):
        if "text" in value:
            return str(
                value["text"]
                or ""
            )

        return "; ".join(
            f"{key}: {item}"
            for key, item in value.items()
        )

    return str(
        value
    )


def _normalize_software_name(
    value: str,
) -> str:
    cleaned = re.sub(
        r"\s+",
        " ",
        value,
    ).strip()

    if not cleaned:
        return "Unknown Service"

    for marker in (
        " - ",
        " – ",
        ":",
        " for ",
        " on ",
        " with ",
        " related to ",
    ):
        cleaned_lower = cleaned.lower()

        if marker in cleaned_lower:
            idx = cleaned_lower.index(
                marker
            )

            cleaned = cleaned[
                :idx
            ].strip()

    cleaned = re.sub(
        r"\s*\(.*\)\s*$",
        "",
        cleaned,
    )

    cleaned = re.sub(
        (
            r"\s*(?:"
            r"cve-\d{4}-\d{4,}"
            r"|security update"
            r"|patch"
            r"|advisory"
            r"|vulnerability"
            r").*$"
        ),
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).strip()

    if not cleaned:
        return "Unknown Service"

    return cleaned


def _is_microsoft_software(
    software: str,
) -> bool:
    lowered = software.lower()

    return any(
        token in lowered
        for token in MICROSOFT_TOKENS
    )
