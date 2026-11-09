#!/usr/bin/env python3
"""Open a fix PR for a group the triage agent bucketed as act_now.

The model decides WHICH group to act on. This script decides WHAT version to
move to, and it does that with rules, not a model. That split is deliberate:
a wrong bucket costs a review, a wrong version number ships broken code.

Usage:
    # see the plan, touch nothing
    python3 open_pr.py findings.json triage.json --repo ~/goof-pr

    # pick a specific group instead of the top-ranked one
    python3 open_pr.py findings.json triage.json --repo ~/goof-pr --group express@4.16.0

    # actually branch, commit, push, and open a draft PR
    python3 open_pr.py findings.json triage.json --repo ~/goof-pr \
        --gh-repo BuildAgentic/goof --push

After re-scanning the branch, post the proof back to the PR:

    python3 open_pr.py --verify 5 --repo ~/goof-pr \
        --baseline ~/goof-base/findings-base.json \
        --after ~/goof-pr/findings-lodash.json

    # same command with --gh-repo and --push actually posts the comment

Both the baseline and the branch must be scanned the same way: separate
checkouts, lockfiles regenerated with --lockfile-version 1, no node_modules
present. Mixing lockfile formats, or an installed tree against a lockfile,
produces findings that look new but are not.

Requires: git and gh on PATH, npm for the lockfile, and push access to the repo.
Nothing is written unless you pass --push.
"""
import argparse
import json
import os
import subprocess
import sys

from triage_cohere import build_groups, is_breaking, load_scopes, package_name, version_key

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run(cmd, cwd=None, check=True, capture=True):
    result = subprocess.run(
        cmd, cwd=cwd, check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )
    if check and result.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{result.stdout or ''}")
    return (result.stdout or "").strip()


def split_key(key):
    """'express@4.16.0' -> ('express', '4.16.0'); handles scoped names."""
    name, _, version = key.rpartition("@")
    return (name, version) if name else (key, "")


def latest_non_breaking(package, current):
    """Highest published version that is not a breaking move from current.

    Asks the npm registry rather than guessing. Returns None if npm is
    unreachable, in which case we fall back to the advisory's fix version.
    """
    try:
        raw = subprocess.run(
            ["npm", "view", package, "versions", "--json"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    versions = json.loads(raw)
    if isinstance(versions, str):
        versions = [versions]
    safe = [
        v for v in versions
        if not is_breaking(current, v)
        and version_key(v) > version_key(current)
        and not any(c.isalpha() for c in v)  # skip betas and release candidates
    ]
    return max(safe, key=version_key) if safe else None


def required_fix(group, package):
    """Highest fix version the advisories demand for the direct package itself."""
    wanted = [
        f["fix_version"] for f in group["findings"]
        if f["package"] == package and f.get("fix_version")
    ]
    return max(wanted, key=version_key) if wanted else None


def choose_target(group, package, current):
    """The version to move to, and how we got there."""
    required = required_fix(group, package)
    latest = latest_non_breaking(package, current)
    if latest and required:
        if version_key(latest) >= version_key(required):
            return latest, f"latest non-breaking {package} release (covers advisory floor {required})"
        return required, f"advisory floor (npm's latest non-breaking was {latest}, which is lower)"
    if latest:
        return latest, f"latest non-breaking {package} release"
    if required:
        return required, "advisory floor (npm registry unavailable)"
    return None, "no fix version available"


def rank(group):
    """Worst severity first, then most findings. Picks the group worth showing."""
    worst = min(SEVERITY_RANK.get(f["severity"], 9) for f in group["findings"])
    return (worst, -len(group["findings"]))


def severity_table(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    rows = [f"| {s} | {counts[s]} |" for s in ("critical", "high", "medium", "low") if s in counts]
    return "| severity | findings |\n|----------|----------|\n" + "\n".join(rows)


def pr_body(group, package, current, target, how, result):
    findings = group["findings"]
    bucket_line = f"Bucket: `{result.get('final_bucket', result.get('bucket'))}`"
    if result.get("overridden"):
        bucket_line += f" (guardrail override)\n\n> {result['override_note']}"
    return f"""## Bump {package} {current} → {target}

Opened by the triage agent against `{group['key']}`.

### Why this group

> {result.get('reason', '(no reason recorded)')}

{bucket_line}

### What this group covers

{severity_table(findings)}

Scope: **{group['scope']}** (from package.json)

### How the version was chosen

`{target}` — {how}.
Checked as non-breaking: below 1.0 a minor bump counts as breaking, at or
above 1.0 only a major does.

### Verify before merging

```bash
npm ci
snyk test --json > after.json
```

Compare against a baseline built the same way — regenerate both lockfiles with
`--lockfile-version 1`. Comparing across lockfile formats produces phantom
findings.

---

Grouping and bucketing: Cohere `command-a-03-2025`.
Version selection, breaking-change check, and this PR: deterministic code, no model involved.
"""


def finding_key(f):
    """Identity of a finding. Version is part of it: the same advisory against
    two installed versions of a package is two findings, not one."""
    return (f["package"], f["current_version"], f["id"])


def diff_findings(baseline, after):
    b = {finding_key(f): f for f in baseline}
    a = {finding_key(f): f for f in after}
    return (
        [b[k] for k in b if k not in a],   # fixed
        [a[k] for k in a if k not in b],   # new
        len(b), len(a),
    )


def verify_comment(fixed, new, before_count, after_count):
    def table(rows):
        counts = {}
        for f in rows:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        if not counts:
            return "_none_"
        body = "\n".join(f"| {s} | {counts[s]} |" for s in ("critical", "high", "medium", "low") if s in counts)
        return "| severity | count |\n|----------|-------|\n" + body

    plural = "finding" if len(new) == 1 else "findings"
    verdict = (
        "No new findings.\n\nThis check compares advisories before and after. It says "
        "nothing about whether the application still behaves correctly — that needs a "
        "test run, and this tool does not do one."
        if not new else
        f"**{len(new)} new {plural} introduced.** Review before merging."
    )
    listing = "\n".join(
        f"- `{f['severity']}` {f['package']} {f['current_version']} — {f['id']}"
        for f in sorted(new, key=lambda f: (f["severity"], f["package"]))
    )
    return f"""## Re-scan result

Snyk findings: **{before_count} → {after_count}** ({len(fixed)} fixed, {len(new)} new)

**Fixed**

{table(fixed)}

**New**

{table(new)}
{(chr(10) + listing) if new else ""}

{verdict}

### Method

Baseline and branch were scanned the same way: separate checkouts, lockfiles
regenerated with `--lockfile-version 1`, no `node_modules` present, findings
deduplicated on (package, version, advisory id). Comparing across lockfile
formats or across installed-vs-lockfile scans produces phantom findings.

---

Verification: deterministic diff, no model involved.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings", nargs="?", help="findings.json from ingest_snyk.py")
    parser.add_argument("triage", nargs="?", help="triage.json from triage_cohere.py")
    parser.add_argument("--repo", required=True, help="Path to a git checkout of the project")
    parser.add_argument("--gh-repo", help="owner/name on GitHub, e.g. BuildAgentic/goof")
    parser.add_argument("--group", help="Group id to act on; default is the worst act_now group")
    parser.add_argument("--base", default="master", help="Branch to open the PR against")
    parser.add_argument("--push", action="store_true", help="Actually write: open the PR, or post the comment")
    parser.add_argument("--verify", metavar="PR_NUMBER", help="Post a re-scan result to this PR instead of opening one")
    parser.add_argument("--baseline", help="findings.json for the unmodified project (with --verify)")
    parser.add_argument("--after", help="findings.json for the branch (with --verify)")
    args = parser.parse_args()

    repo = os.path.expanduser(args.repo)

    if args.verify:
        if not (args.baseline and args.after):
            sys.exit("--verify needs --baseline and --after")
        with open(os.path.expanduser(args.baseline), encoding="utf-8") as handle:
            baseline = json.load(handle)["findings"]
        with open(os.path.expanduser(args.after), encoding="utf-8") as handle:
            after = json.load(handle)["findings"]
        fixed, new, before_count, after_count = diff_findings(baseline, after)
        comment = verify_comment(fixed, new, before_count, after_count)
        print(f"PR #{args.verify}: {before_count} -> {after_count}, {len(fixed)} fixed, {len(new)} new\n")
        print("--- comment ---\n")
        print(comment)
        if not args.push:
            print("--- dry run: nothing posted. Pass --push to comment on the PR. ---")
            return
        if not args.gh_repo:
            sys.exit("--push needs --gh-repo owner/name")
        payload_path = os.path.join(repo, ".comment-payload.json")
        with open(payload_path, "w", encoding="utf-8") as handle:
            json.dump({"body": comment}, handle)
        out = run(["gh", "api", f"repos/{args.gh_repo}/issues/{args.verify}/comments",
                   "--input", payload_path, "--jq", ".html_url"], cwd=repo)
        os.remove(payload_path)
        print(f"\nposted: {out}")
        return

    if not (args.findings and args.triage):
        sys.exit("Opening a PR needs findings.json and triage.json")
    manifest_path = os.path.join(repo, "package.json")

    with open(args.findings, encoding="utf-8") as handle:
        findings = json.load(handle)["findings"]
    with open(args.triage, encoding="utf-8") as handle:
        results = json.load(handle)["results"]

    scopes = load_scopes(manifest_path)
    groups = {g["key"]: g for g in build_groups(findings, scopes)}

    actionable = [
        g for key, g in groups.items()
        if results.get(key, {}).get("final_bucket", results.get(key, {}).get("bucket")) == "act_now"
        and package_name(key) in scopes
    ]
    if not actionable:
        sys.exit("No act_now group maps to a package in package.json. Run triage first.")

    if args.group:
        group = groups.get(args.group)
        if group is None:
            sys.exit(f"No group named {args.group}. Available act_now groups:\n  " +
                     "\n  ".join(g["key"] for g in sorted(actionable, key=rank)))
    else:
        group = sorted(actionable, key=rank)[0]

    result = results[group["key"]]
    package, current_from_key = split_key(group["key"])

    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    current = manifest.get("dependencies", {}).get(package) or manifest.get("devDependencies", {}).get(package)
    if not current:
        sys.exit(f"{package} is not a direct dependency in {manifest_path}")
    current = current.lstrip("^~") or current_from_key

    target, how = choose_target(group, package, current)
    if not target:
        sys.exit(f"No usable fix version for {package}. This group needs a human.")
    if is_breaking(current, target):
        sys.exit(f"{package} {current} -> {target} is a breaking move. Not opening a PR.")

    branch = f"fix/{package.replace('/', '-')}-{target}"
    body = pr_body(group, package, current, target, how, result)

    print(f"group       {group['key']}  ({len(group['findings'])} findings, scope {group['scope']})")
    print(f"bucket      {result.get('final_bucket', result.get('bucket'))}")
    print(f"bump        {package} {current} -> {target}")
    print(f"chosen as   {how}")
    print(f"branch      {branch}")
    print("\n--- PR body ---\n")
    print(body)

    if not args.push:
        print("--- dry run: nothing written. Pass --push to open the PR. ---")
        return
    if not args.gh_repo:
        sys.exit("--push needs --gh-repo owner/name")

    run(["git", "fetch", "origin"], cwd=repo)
    run(["git", "checkout", "-B", branch, f"origin/{args.base}"], cwd=repo)

    manifest_section = "dependencies" if package in manifest.get("dependencies", {}) else "devDependencies"
    with open(manifest_path, encoding="utf-8") as handle:
        fresh = json.load(handle)
    fresh[manifest_section][package] = target
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(fresh, handle, indent=2)
        handle.write("\n")

    print("\nregenerating lockfile...")
    run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--lockfile-version", "1"], cwd=repo)

    run(["git", "add", "package.json", "package-lock.json"], cwd=repo)
    run(["git", "commit", "-m", f"Bump {package} {current} -> {target}\n\n"
         f"Triaged as act_now by Cohere command-a-03-2025.\n"
         f"Version chosen by rule: {how}."], cwd=repo)
    run(["git", "push", "-u", "origin", branch, "--force-with-lease"], cwd=repo)

    payload = {
        "title": f"Bump {package} {current} -> {target}",
        "head": branch,
        "base": args.base,
        "body": body,
        "draft": True,
    }
    payload_path = os.path.join(repo, ".pr-payload.json")
    with open(payload_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    out = run(["gh", "api", f"repos/{args.gh_repo}/pulls", "--input", payload_path,
               "--jq", ".html_url"], cwd=repo)
    os.remove(payload_path)
    print(f"\nopened: {out}")


if __name__ == "__main__":
    main()
