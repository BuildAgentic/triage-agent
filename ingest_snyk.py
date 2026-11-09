#!/usr/bin/env python3
"""Normalize `snyk test --json` output into one deduplicated findings list.

Usage:
    python3 ingest_snyk.py goof-snyk.json -o findings.json

Standard library only. Handles single-project output (a JSON object) and
multi-project output (a JSON list). Writes findings.json and prints a summary.

Snyk lists a vulnerability once per dependency path that reaches it, so the
same package and advisory can appear many times. This script collapses those
rows into one finding per (package, version, advisory id) and records how many
distinct dependency chains lead to each one.
"""
import argparse
import json
import sys

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1}


def version_key(version):
    """Turn '4.17.12' into (4, 17, 12) so versions compare numerically."""
    parts = []
    for piece in str(version).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def major(version):
    try:
        return version_key(version)[0]
    except (IndexError, ValueError):
        return None


def fix_target(current, fixed_in):
    """Lowest fixed version newer than the current one (falls back to lowest overall)."""
    newer = [f for f in fixed_in if version_key(f) > version_key(current)]
    pool = newer or fixed_in
    return min(pool, key=version_key) if pool else None


def top_level_upgrade(upgrade_path):
    """Snyk's suggested top-level dependency upgrade, if it has one.

    For transitive findings this is the direct dependency to upgrade, which is
    not the same as the vulnerable package's own fixed version.
    """
    for step in upgrade_path or []:
        if isinstance(step, str) and "@" in step:
            return step
    return None


def load_projects(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    projects = data if isinstance(data, list) else [data]
    for project in projects:
        if "error" in project:
            sys.exit(f"Snyk reported an error, so there is nothing to ingest:\n  {project['error']}")
    return projects


def ingest(projects):
    raw_rows = 0
    ignored = 0
    findings = {}

    for project in projects:
        for vuln in project.get("vulnerabilities", []):
            raw_rows += 1
            if vuln.get("ignored"):
                ignored += 1
                continue

            package = vuln.get("packageName")
            current = vuln.get("version", "")
            advisory = vuln.get("id")
            key = (package, current, advisory)

            if key not in findings:
                target = fix_target(current, vuln.get("fixedIn") or [])
                findings[key] = {
                    "id": advisory,
                    "title": vuln.get("title"),
                    "package": package,
                    "current_version": current,
                    "severity": (vuln.get("severity") or "unknown").lower(),
                    "cvss": vuln.get("cvssScore"),
                    "cves": (vuln.get("identifiers") or {}).get("CVE", []),
                    "exploit_maturity": vuln.get("exploitMaturity"),
                    "fix_available": target is not None,
                    "fix_version": target,
                    "major_bump": target is not None and major(current) != major(target),
                    "top_level_upgrade": top_level_upgrade(vuln.get("upgradePath")),
                    "_chains": set(),
                }

            chain = tuple(vuln.get("from") or [])
            if chain:
                findings[key]["_chains"].add(chain)

    results = []
    for finding in findings.values():
        chains = sorted(finding.pop("_chains"), key=len)
        finding["dependency_paths"] = len(chains)
        finding["direct"] = any(len(chain) == 2 for chain in chains)
        finding["example_paths"] = [" > ".join(chain) for chain in chains[:3]]
        results.append(finding)

    results.sort(
        key=lambda f: (SEVERITY_RANK.get(f["severity"], 0), f["cvss"] or 0),
        reverse=True,
    )
    return results, raw_rows, ignored


def print_summary(results, raw_rows, ignored, source):
    by_severity = {}
    for finding in results:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1

    print(f"Source: {source}")
    print(f"Raw rows in Snyk output: {raw_rows} (ignored by policy: {ignored})")
    print(f"Unique findings (package + version + advisory): {len(results)}")
    print("By severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items(), key=lambda kv: -SEVERITY_RANK.get(kv[0], 0))))
    print(f"Direct dependencies: {sum(1 for f in results if f['direct'])}")
    print(f"Transitive only: {sum(1 for f in results if not f['direct'])}")
    print(f"Fix available: {sum(1 for f in results if f['fix_available'])}")
    print(f"Major-version fixes (need human review): {sum(1 for f in results if f['major_bump'])}")
    print()
    print(f"{'severity':<9} {'package':<22} {'current':<10} {'fix':<10} {'direct':<7} {'paths':<6} id")
    for finding in results[:15]:
        print(
            f"{finding['severity']:<9} {str(finding['package'])[:21]:<22} "
            f"{str(finding['current_version'])[:9]:<10} {str(finding['fix_version'] or '-')[:9]:<10} "
            f"{str(finding['direct']):<7} {finding['dependency_paths']:<6} {finding['id']}"
        )
    if len(results) > 15:
        print(f"... and {len(results) - 15} more (see the output file)")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snyk_json", help="Output of `snyk test --json`")
    parser.add_argument("-o", "--output", default="findings.json", help="Where to write normalized findings")
    args = parser.parse_args()

    projects = load_projects(args.snyk_json)
    results, raw_rows, ignored = ingest(projects)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(
            {"source": args.snyk_json, "raw_rows": raw_rows, "ignored": ignored, "findings": results},
            handle,
            indent=2,
        )

    print_summary(results, raw_rows, ignored, args.snyk_json)
    print(f"\nWrote {len(results)} findings to {args.output}")


if __name__ == "__main__":
    main()
